// .zsb 加密封包导入（与 zcode-switch 互通，格式见 docs/development/03-data-formats.md §4）。
// CLI 与 Web 后台共用：IsSealedBundle 判定 → OpenZsbBundle 解封 → ZsbToProviders 转换
// → DefaultStore.ImportAccounts 入池。
//
// 外层 envelope：PBKDF2-HMAC-SHA256(password, salt, 100000, 32B) → AES-256-GCM
// （data‖tag），base64 为标准字母表 + padding；`kdf` 与 `cipher` 字段同时存在即视为
// 已加密信封（is_sealed）。内层明文：{"format":"zcode-accounts-bundle","version":2,
// "accounts":[{name,createdAt,credentials,config}]}，credentials 敏感值可能是 ZCode
// 客户端的 enc:v1 密文（key = SHA256(secret)，无 KDF 迭代）。
package app

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// IsSealedBundle payload 是否为 .zsb 加密封包（is_sealed：kdf + cipher 同时存在）。
func IsSealedBundle(payload map[string]any) bool {
	if _, ok := payload["kdf"]; !ok {
		return false
	}
	_, ok := payload["cipher"]
	return ok
}

// OpenZsbBundle 解开 .zsb 信封，返回内层明文 payload。
func OpenZsbBundle(payload map[string]any, password string) (map[string]any, error) {
	kdf, _ := payload["kdf"].(map[string]any)
	ciph, _ := payload["cipher"].(map[string]any)
	if kdf == nil || ciph == nil {
		return nil, errors.New("缺少 kdf/cipher 字段，不是有效的 .zsb 信封")
	}
	if algo, _ := kdf["algo"].(string); algo != "" && algo != "pbkdf2-hmac-sha256" {
		return nil, fmt.Errorf("不支持的 KDF 算法: %v", algo)
	}
	if algo, _ := ciph["algo"].(string); algo != "" && algo != "aes-256-gcm" {
		return nil, fmt.Errorf("不支持的加密算法: %v", algo)
	}
	iters := 0
	if v, ok := kdf["iters"].(float64); ok && v > 0 {
		iters = int(v)
	}
	if iters <= 0 {
		iters = 100000
	}
	salt, err := base64.StdEncoding.DecodeString(dictStr(kdf, "salt"))
	if err != nil {
		return nil, fmt.Errorf("salt 解码失败: %v", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(dictStr(ciph, "nonce"))
	if err != nil {
		return nil, fmt.Errorf("nonce 解码失败: %v", err)
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("nonce 长度必须为 12 字节，实际 %d", len(nonce))
	}
	tag, err := base64.StdEncoding.DecodeString(dictStr(ciph, "tag"))
	if err != nil {
		return nil, fmt.Errorf("tag 解码失败: %v", err)
	}
	data, err := base64.StdEncoding.DecodeString(dictStr(ciph, "data"))
	if err != nil {
		return nil, fmt.Errorf("data 解码失败: %v", err)
	}
	key := pbkdf2SHA256([]byte(password), salt, iters, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, nonce, append(data, tag...), nil)
	if err != nil {
		return nil, errors.New("解密失败（wrong_password：口令不正确或包已损坏）")
	}
	var inner map[string]any
	if err := json.Unmarshal(plain, &inner); err != nil {
		return nil, fmt.Errorf("内层明文不是有效 JSON: %v", err)
	}
	if format, _ := inner["format"].(string); format != "" && format != "zcode-accounts-bundle" {
		return nil, fmt.Errorf("内层 format=%q，无法识别（仅接受 zcode-accounts-bundle）", format)
	}
	return inner, nil
}

// ZsbToProviders 把内层 payload 转成 ImportAccounts 的 providers 形态。
// 对齐 zsw 语义：只取可解字段（name/jwt/apiKey），多余字段忽略；解不开的 enc:v1 直接跳过。
//
// provider 判定（对齐 zsw 双通道模型）：oauth:active_provider 可解密时以其为准；
// 否则按标记——只有 bigmodel 凭证/密钥而无任何 zai 配置 → bigmodel（额度与网关
// 都走 open.bigmodel.cn，凭证取 builtin:bigmodel(-coding-plan) 的 API Key）；
// 其余 → zai（zcodejwttoken + zai-coding-plan 回退 Key）。
func ZsbToProviders(payload map[string]any) map[string]any {
	providers := map[string]any{}
	addItem := func(provider string, item map[string]any) {
		items, _ := providers[provider].([]any)
		providers[provider] = append(items, any(item))
	}
	accounts, _ := payload["accounts"].([]any)
	for _, raw := range accounts {
		acc, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		name, _ := acc["name"].(string)
		creds, _ := acc["credentials"].(map[string]any)
		cfgProvider := map[string]any{}
		if cfg, ok := acc["config"].(map[string]any); ok {
			cfgProvider, _ = cfg["provider"].(map[string]any)
		}
		// provider 标记
		active := ""
		if v, ok := creds["oauth:active_provider"].(string); ok && v != "" {
			if plain, ok := resolveCred(v); ok {
				active = strings.ToLower(strings.TrimSpace(plain))
			}
		}
		hasZaiCfg, hasBigCred := false, false
		bigKey := ""
		for k := range creds {
			if strings.Contains(strings.ToLower(k), "bigmodel") {
				hasBigCred = true
			}
		}
		for id, pvRaw := range cfgProvider {
			idl := strings.ToLower(id)
			if strings.Contains(idl, "zai") {
				hasZaiCfg = true
			}
			if opts, ok := pvRaw.(map[string]any)["options"].(map[string]any); ok {
				if key, _ := opts["apiKey"].(string); key != "" && !strings.HasPrefix(key, "eyJ") {
					if strings.Contains(idl, "bigmodel-coding-plan") || idl == "builtin:bigmodel" {
						if bigKey == "" {
							bigKey = key
						}
					}
				}
			}
		}
		// BigModel live key：credentials 里的 coding-plan api-key（每次轮换后是最新的，
		// config 里的可能是旧值）——enc:v1 密文按本机派生密钥解出
		liveBigKey := ""
		for k, v := range creds {
			kl := strings.ToLower(k)
			if strings.Contains(kl, "coding-plan") && strings.HasSuffix(kl, ":api-key") {
				if sv, ok := v.(string); ok && sv != "" {
					if plain, ok := resolveCred(sv); ok && plain != "" {
						liveBigKey = plain
						break
					}
				}
			}
		}
		provider := "zai"
		if active == "bigmodel" || (!hasZaiCfg && (hasBigCred || bigKey != "" || liveBigKey != "")) {
			provider = "bigmodel"
		}
		// 双 token（重置卡计数 /reset/status 需要）：
		//   zcodeToken = zcodejwttoken；platformToken = oauth:{active}:access_token
		zcodeJWT := ""
		if v, ok := creds["zcodejwttoken"].(string); ok && v != "" {
			if plain, ok := resolveCred(v); ok {
				zcodeJWT = plain
			}
		}
		platformToken := ""
		for _, pk := range []string{"oauth:" + provider + ":access_token", "oauth:bigmodel:access_token", "oauth:zai:access_token"} {
			if v, ok := creds[pk].(string); ok && v != "" {
				if plain, ok := resolveCred(v); ok && plain != "" {
					platformToken = plain
					break
				}
			}
		}
		if provider == "bigmodel" {
			// BigModel 账号：API Key 即凭证（monitor 额度与网关 open.bigmodel.cn 都用它）；
			// live key 优先，config key 兜底
			key := liveBigKey
			if key == "" {
				key = bigKey
			}
			if key == "" {
				continue
			}
			item := map[string]any{"name": name, "apiKey": key}
			if zcodeJWT != "" {
				item["zcode_jwt"] = zcodeJWT
			}
			if platformToken != "" {
				item["platform_token"] = platformToken
			}
			addItem("bigmodel", item)
			continue
		}
		// zai 账号：zcodejwttoken 优先，回落 oauth:zai:access_token
		jwt := ""
		for _, key := range []string{"zcodejwttoken", "oauth:zai:access_token"} {
			if v, ok := creds[key].(string); ok && v != "" {
				if plain, ok := resolveCred(v); ok {
					jwt = plain
					break
				}
			}
		}
		// API Key 回退凭证：config.provider["builtin:zai-coding-plan"].options.apiKey
		apiKey := ""
		if zcp, ok := cfgProvider["builtin:zai-coding-plan"].(map[string]any); ok {
			if opts, ok := zcp["options"].(map[string]any); ok {
				apiKey, _ = opts["apiKey"].(string)
			}
		}
		if jwt == "" && apiKey == "" {
			continue
		}
		item := map[string]any{"name": name}
		if jwt != "" {
			item["secret"] = jwt
		}
		if apiKey != "" && apiKey != jwt {
			item["apiKey"] = apiKey
		}
		if zcodeJWT != "" {
			item["zcode_jwt"] = zcodeJWT
		}
		if platformToken != "" {
			item["platform_token"] = platformToken
		}
		addItem("zai", item)
	}
	return map[string]any{"providers": providers}
}

// resolveCred 解析凭证字符串：明文原样返回；enc:v1 密文尝试本机派生密钥解密，失败返回 false。
func resolveCred(v string) (string, bool) {
	const prefix = "enc:v1:"
	if !strings.HasPrefix(v, prefix) {
		return v, true
	}
	parts := strings.Split(strings.TrimPrefix(v, prefix), ".")
	if len(parts) != 3 {
		return "", false
	}
	nonce, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	tag, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	ct, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil || len(nonce) != 12 {
		return "", false
	}
	for _, secret := range encV1Secrets() {
		sum := sha256.Sum256([]byte(secret))
		block, err := aes.NewCipher(sum[:])
		if err != nil {
			continue
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			continue
		}
		if plain, err := gcm.Open(nil, nonce, append(ct, tag...), nil); err == nil {
			return string(plain), true
		}
	}
	return "", false
}

// encV1Secrets 与 zsw/ZCode 客户端一致的候选 secret 列表：
// env 覆盖优先，其次本机默认派生 zcode-credential-fallback:{platform}:{home}:{username}。
func encV1Secrets() []string {
	var out []string
	if v := os.Getenv("ZCODE_CREDENTIAL_SECRET"); v != "" {
		out = append(out, v)
	}
	platform := "unknown"
	switch runtime.GOOS {
	case "darwin":
		platform = "darwin"
	case "windows":
		platform = "win32"
	case "linux":
		platform = "linux"
	}
	home, _ := os.UserHomeDir()
	user := os.Getenv("USERNAME")
	if user == "" && runtime.GOOS != "windows" {
		if b, err := exec.Command("id", "-un").Output(); err == nil {
			user = strings.TrimSpace(string(b))
		}
	}
	if user == "" {
		user = os.Getenv("USER")
	}
	if user == "" {
		user = os.Getenv("LOGNAME")
	}
	if user == "" {
		user = "unknown"
	}
	out = append(out, fmt.Sprintf("zcode-credential-fallback:%s:%s:%s", platform, home, user))
	return out
}

// pbkdf2SHA256 标准 PBKDF2（RFC 2898），避免为导入路径引入 golang.org/x/crypto 依赖。
func pbkdf2SHA256(password, salt []byte, iterations, keyLen int) []byte {
	hashLen := sha256.Size
	numBlocks := (keyLen + hashLen - 1) / hashLen
	dk := make([]byte, 0, numBlocks*hashLen)
	buf := make([]byte, 4)
	for block := 1; block <= numBlocks; block++ {
		binary.BigEndian.PutUint32(buf, uint32(block))
		mac := hmac.New(sha256.New, password)
		mac.Write(salt)
		mac.Write(buf)
		u := mac.Sum(nil)
		t := make([]byte, len(u))
		copy(t, u)
		for n := 1; n < iterations; n++ {
			mac.Reset()
			mac.Write(u)
			u = mac.Sum(nil)
			for i := range t {
				t[i] ^= u[i]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

func dictStr(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

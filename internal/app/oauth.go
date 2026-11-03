// Z.AI OAuth 登录流程。
//
// 主要供 CLI `login zai` 使用：发起 OAuth → 轮询 → 兑换 API Key。
//
// 对齐 Python app/oauth.py。
package app

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ZaiAuthFlow api_base / exchange_origin 可注入（测试指向 Mock 上游）；
// 默认值来自 settings（其缺省又来自 constants 收口）。
//
// 官方 CLI 规范（对齐 zcode.cjs createZaiCliOAuthClient）：
//   - init 仅带 Authorization: Bearer <pollToken> 与 Content-Type: application/json
//   - poll 仅带 Authorization: Bearer <pollToken>
//
// 不携带额外伪装头，避免上游服务端对 OAuth 会话产生异常的设备/上下文绑定限制。
//
// 2026-09 起官方协议跟进（zcode-switch oauth.rs 同形）：init 响应 data.poll_token
// 由服务端下发，后续 poll 必须采用该值；仅当服务端未返回时回落自造 token
//（保留旧协议兼容）。
type ZaiAuthFlow struct {
	APIBase        string
	ExchangeOrigin string
	PollToken      string
}

// NewZaiAuthFlow 构造（对齐 __init__ 默认参数）。
func NewZaiAuthFlow(apiBase, exchangeOrigin string) *ZaiAuthFlow {
	if apiBase == "" {
		apiBase = OAUTH_API_BASE
	}
	if exchangeOrigin == "" {
		exchangeOrigin = ZAI_EXCHANGE_ORIGIN
	}
	// poll_token = secrets.token_hex(32)
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return &ZaiAuthFlow{
		APIBase:        apiBase,
		ExchangeOrigin: exchangeOrigin,
		PollToken:      hex.EncodeToString(b),
	}
}

// oauthRequest httpx.AsyncClient(timeout=30) 等价（跟随 env 代理，trust_env 默认 true）。
func oauthRequest(method, url string, headers map[string]string, body map[string]any) (*http.Response, string, error) {
	var reader io.Reader
	if body != nil {
		b, err := JSONMarshalCompact(body)
		if err != nil {
			return nil, "", err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return nil, "", err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := &http.Client{Timeout: 30 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer res.Body.Close()
	buf := &strings.Builder{}
	tmp := make([]byte, 32*1024)
	for {
		n, readErr := res.Body.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if readErr != nil {
			break
		}
	}
	text := buf.String()
	// raise_for_status 提前内联：读净 body 后错误里保留文本（对齐 err.response 可再 .json()）
	if res.StatusCode >= 400 {
		return res, text, &oauthHTTPStatusError{code: res.StatusCode, status: res.Status, body: text}
	}
	return res, text, nil
}

type oauthHTTPStatusError struct {
	code   int
	status string
	body   string // 已读净的响应体（对齐 err.response 语义，供 body code 解析）
}

func (e *oauthHTTPStatusError) Error() string { return e.status }

// HTTPStatusCode 供调用方区分 4xx/5xx（对齐 err.response.status_code）。
func (e *oauthHTTPStatusError) HTTPStatusCode() int { return e.code }

// ResponseJSONBody 返回响应体文本（对齐 err.response.json() 的数据来源）。
func (e *oauthHTTPStatusError) ResponseJSONBody() string { return e.body }

// IsOAuthStatusError 判断错误是否带 HTTP 状态（对齐 except httpx.HTTPStatusError）。
func IsOAuthStatusError(err error) (*oauthHTTPStatusError, bool) {
	if e, ok := err.(*oauthHTTPStatusError); ok {
		return e, true
	}
	return nil, false
}

// Init 对齐 async init()：返回 (flow_id, authorize_url)。
func (f *ZaiAuthFlow) Init() (string, string, error) {
	_, text, err := oauthRequest(http.MethodPost,
		f.APIBase+"/oauth/cli/init",
		map[string]string{
			"Authorization": "Bearer " + f.PollToken,
			"Content-Type":  "application/json",
		},
		map[string]any{"provider": "zai"})
	if err != nil {
		return "", "", err
	}
	if err != nil {
		return "", "", err
	}
	v, err := JSONDecode(text)
	if err != nil {
		return "", "", err
	}
	body, _ := v.(map[string]any)
	if body == nil {
		return "", "", fmt.Errorf("OAuth init 响应非对象")
	}
	if code, has := body["code"]; has && code != nil {
		if n, ok := AsInt(code); ok && n != 0 {
			return "", "", fmt.Errorf("OAuth init 被上游拒绝（code=%d）", n)
		}
	}
	data, _ := body["data"].(map[string]any)
	if data == nil {
		data = map[string]any{}
	}
	flowID := DictGetStr(data, "flow_id", "")
	authorizeURL := DictGetStr(data, "authorize_url", "")
	if flowID == "" || authorizeURL == "" {
		return "", "", fmt.Errorf("返回的 OAuth 流程数据不完整")
	}
	serverPollToken := strings.TrimSpace(DictGetStr(data, "poll_token", ""))
	if serverPollToken != "" {
		f.PollToken = serverPollToken
	}
	return flowID, authorizeURL, nil
}

// Poll 对齐 async poll(flow_id)。
func (f *ZaiAuthFlow) Poll(flowID string) (map[string]any, error) {
	_, text, err := oauthRequest(http.MethodGet,
		fmt.Sprintf("%s/oauth/cli/poll/%s", f.APIBase, flowID),
		map[string]string{"Authorization": "Bearer " + f.PollToken},
		nil)
	if err != nil {
		return nil, err
	}
	v, err := JSONDecode(text)
	if err != nil {
		return nil, err
	}
	body, _ := v.(map[string]any)
	if body == nil {
		return map[string]any{}, nil
	}
	data, _ := body["data"].(map[string]any)
	if data == nil {
		data = map[string]any{}
	}
	return data, nil
}

// ExchangeAPIKey OAuth access_token → 业务 token → 机构/项目 → API Key。
func (f *ZaiAuthFlow) ExchangeAPIKey(accessToken string) (string, error) {
	// POST /api/auth/z/login
	_, text, err := oauthRequest(http.MethodPost,
		f.ExchangeOrigin+"/api/auth/z/login",
		map[string]string{"Content-Type": "application/json"},
		map[string]any{"token": accessToken})
	if err != nil {
		return "", err
	}
v, err := JSONDecode(text)
	if err != nil {
		return "", err
	}
	loginBody, _ := v.(map[string]any)
	data, _ := loginBody["data"].(map[string]any)
	if data == nil {
		data = map[string]any{}
	}
	bizToken := DictGetStr(data, "access_token", "")
	if bizToken == "" {
		bizToken = DictGetStr(data, "accessToken", "")
	}
	if bizToken == "" {
		return "", fmt.Errorf("返回数据中不含业务凭证")
	}

	// GET /api/biz/customer/getCustomerInfo
	_, text, err = oauthRequest(http.MethodGet,
		f.ExchangeOrigin+"/api/biz/customer/getCustomerInfo",
		map[string]string{"Authorization": "Bearer " + bizToken},
		nil)
	if err != nil {
		return "", err
	}
v, err = JSONDecode(text)
	if err != nil {
		return "", err
	}
	infoBody, _ := v.(map[string]any)
	infoData, _ := infoBody["data"].(map[string]any)
	orgsRaw, _ := infoData["organizations"].([]any)

	// 默认机构优先，其次第一个；无机构报错
	var org map[string]any
	for _, rawOrg := range orgsRaw {
		o, ok := rawOrg.(map[string]any)
		if !ok {
			continue
		}
		if strings.Contains(DictGetStr(o, "organizationName", ""), "默认机构") {
			org = o
			break
		}
	}
	if org == nil && len(orgsRaw) > 0 {
		org, _ = orgsRaw[0].(map[string]any)
	}
	if org == nil {
		return "", fmt.Errorf("找不到可用的机构")
	}
	projectsRaw, _ := org["projects"].([]any)

	var proj map[string]any
	for _, rawProj := range projectsRaw {
		p, ok := rawProj.(map[string]any)
		if !ok {
			continue
		}
		if strings.Contains(DictGetStr(p, "projectName", ""), "默认项目") {
			proj = p
			break
		}
	}
	if proj == nil && len(projectsRaw) > 0 {
		proj, _ = projectsRaw[0].(map[string]any)
	}
	if proj == nil {
		return "", fmt.Errorf("找不到可用的项目")
	}

	orgID := DictGetStr(org, "organizationId", "")
	projID := DictGetStr(proj, "projectId", "")
	keyURL := fmt.Sprintf("%s/api/biz/v1/organization/%s/projects/%s/api_keys",
		f.ExchangeOrigin, orgID, projID)

	// GET api_keys 列表
	_, text, err = oauthRequest(http.MethodGet, keyURL,
		map[string]string{"Authorization": "Bearer " + bizToken}, nil)
	if err != nil {
		return "", err
	}
v, err = JSONDecode(text)
	if err != nil {
		return "", err
	}
	keysBody, _ := v.(map[string]any)
	keysRaw, _ := keysBody["data"].([]any)

	var keyObj map[string]any
	for _, rawKey := range keysRaw {
		k, ok := rawKey.(map[string]any)
		if ok && DictGetStr(k, "name", "") == "zcode-api-key" {
			keyObj = k
			break
		}
	}
	if keyObj == nil {
		// POST 创建
		_, text, err = oauthRequest(http.MethodPost, keyURL,
			map[string]string{"Authorization": "Bearer " + bizToken, "Content-Type": "application/json"},
			map[string]any{"name": "zcode-api-key"})
		if err != nil {
			return "", err
		}
				v, err = JSONDecode(text)
		if err != nil {
			return "", err
		}
		createBody, _ := v.(map[string]any)
		keyObj, _ = createBody["data"].(map[string]any)
	}

	apiKey := DictGetStr(keyObj, "apiKey", "")
	if apiKey == "" {
		return "", fmt.Errorf("获取 API Key 失败")
	}

	// GET copy/{api_key} 解密 Secret Key
	_, text, err = oauthRequest(http.MethodGet, keyURL+"/copy/"+apiKey,
		map[string]string{"Authorization": "Bearer " + bizToken}, nil)
	if err != nil {
		return "", err
	}
v, err = JSONDecode(text)
	if err != nil {
		return "", err
	}
	copyBody, _ := v.(map[string]any)
	copyData, _ := copyBody["data"].(map[string]any)
	secretKey := DictGetStr(copyData, "secretKey", "")
	if secretKey == "" {
		return "", fmt.Errorf("未能解密 Secret Key")
	}
	return apiKey + "." + secretKey, nil
}

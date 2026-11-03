// 上游请求构建。
//
// 负责根据账号凭证选择端点、组装请求头、应用 body 变换。
// 实际发送与流式透传在 routes/gateway.go。
//
// 对齐 Python app/agent.py：_DROP_HEADERS / _DROP_HEADER_PREFIXES / build_request。
package app

import (
	"strings"

	"github.com/zhaoboy9692/zcode2api-go/internal/uuidx"
)

// dropHeaders 透传客户端 header 时需要剔除的字段（对齐 _DROP_HEADERS）。
var dropHeaders = map[string]bool{
	"host":           true,
	"content-length": true,
	"x-api-key":      true,
	"authorization":  true,
	"user-agent":     true,
	"http-referer":   true,
	"referer":        true,
	"origin":         true,
	"cookie":         true,
	"accept":         true,
	"accept-language": true,
	"accept-encoding": true,
	"connection":      true,
	"true-client-ip":  true,
	"x-original-forwarded-for": true,
	// 身份/追踪头由本服务仿真生成，禁止客户端透传覆盖（指纹一致性）
	"x-device-mid":       true,
	"x-request-id":       true,
	"x-zcode-trace-id":   true,
	"x-zcode-session-type": true,
	"x-query-id":         true,
	"x-session-id":       true,
	"x-title":            true,
	"x-platform":         true,
	"x-release-channel":  true,
	"x-client-language":  true,
	"x-client-timezone":  true,
	"x-os-category":      true,
	"x-os-version":       true,
}

// dropHeaderPrefixes 前缀剔除：本服务仿真的头族 + 客户端 SDK 特征头族。
//
// x-stainless-* 是 Anthropic SDK 自动附加的运行环境指纹（lang/runtime/package 版本），
// 值来自真实调用客户端而非官方 ZCode 桌面端 —— 与 ZCode/3.10.2 的 UA 组成矛盾信号，
// 且 zapi（Node fetch 直发、无 stainless 头）长期被上游正常接受，剔除后同为已验证形状。
// x-forwarded-*/forwarded/x-real-ip/via/cf-*/cdn-loop 是反代与 CDN 隧道注入的
// 基础设施头（2026-09 review）：官方客户端永不携带，透传泄露部署拓扑并构成指纹矛盾。
var dropHeaderPrefixes = []string{"x-zcode", "x-stainless", "x-forwarded", "forwarded",
	"x-real-ip", "via", "cf-", "cdn-loop"}

// BuildRequestResult 构建结果：(目标 URL, 请求头, 序列化后的请求体)。
type BuildRequestResult struct {
	URL     string
	Headers map[string]string
	Body    []byte
}

// BuildRequest 对齐 build_request(account, body, verify_param, incoming_headers,
// verify_region, force_fallback)。
//
// body 变换（cache_control / metadata.user_id）在此统一应用：变换幂等，
// 网关验证码重试时用同一 body 重建请求，重复调用安全。
//
// forceFallback：强制走 API Key 回退通道（Plan 通道瞬态失败如 429 时，
// 账号 status 保持 ACTIVE，不能靠状态推导路由，须显式指定）。
func BuildRequest(account *Account, body map[string]any, verifyParam string,
	incomingHeaders map[string]string, verifyRegion string, forceFallback bool) (*BuildRequestResult, error) {
	provider := account.Provider
	var targetURL string
	auth := map[string]string{}

	if provider == "zai" {
		if account.UsesPlanChannel() && !forceFallback {
			targetURL = UPSTREAM["zai"]
			auth["Authorization"] = "Bearer " + account.JWTToken
		} else if account.APIKey != "" {
			targetURL = UPSTREAM["zai_fallback"]
			auth["x-api-key"] = account.APIKey
		} else {
			return nil, &runtimeError{msg: "账号缺少有效凭证"}
		}
	} else if provider == "bigmodel" {
		targetURL = UPSTREAM["bigmodel"]
		if account.APIKey == "" {
			return nil, &runtimeError{msg: "BigModel 账号缺少 API Key"}
		}
		auth["x-api-key"] = account.APIKey
	} else {
		return nil, &runtimeError{msg: "未知提供商: " + provider}
	}

	headers := map[string]string{}
	isPlanChannel := provider == "zai" && account.UsesPlanChannel() && !forceFallback
	if isPlanChannel {
		// JWT 通道：全量身份头 + 追踪头（对齐官方客户端 pio + trace 头序）
		profile := ProfileFor(account)
		// 会话粘性：同首轮文本 → 同 session_id（官方会话内稳定，cache 依赖它）。
		// 必须在 TransformBody 之前算——日期轮会被插到 messages[0]。
		sessionID := ConversationSessionID(body, account.ID)
		if sessionID == "" {
			sessionID = uuidx.New4()
		}
		userID := BodyTransformJWTUserID(account.JWTToken)
		model := ""
		if m, ok := body["model"].(string); ok {
			model = m
		}
		body = TransformBody(body, userID, model, profile.DeviceMid, sessionID)
		headers["content-type"] = "application/json"
		for k, v := range auth {
			headers[k] = v
		}
		headers["anthropic-version"] = ANTHROPIC_VERSION
		// start-plan 网关的 harness 要求：mid-conversation system 能力位，
		// 官方客户端 LLM 调用恒带（vlelyanin / TriDefender 双源一致）。
		headers["anthropic-beta"] = "mid-conversation-system-2026-04-07"
		for k, v := range BuildIdentityHeaders(account) {
			headers[k] = v
		}
		for k, v := range BuildTraceHeaders(sessionID) {
			headers[k] = v
		}
		// 官方 anthropic SDK 同时下发 x-api-key（与 Bearer 同值）；
		// 缺失会被 start-plan 网关视为非客户端流量（vlelyanin 实证）。
		if account.JWTToken != "" {
			headers["x-api-key"] = account.JWTToken
		}
	} else {
		// API Key 通道（回退 / bigmodel）：保持原有最小头集
		headers["content-type"] = "application/json"
		for k, v := range auth {
			headers[k] = v
		}
		headers["anthropic-version"] = ANTHROPIC_VERSION
		headers["User-Agent"] = SettingsUserAgent()
		headers["X-ZCode-App-Version"] = XZcodeAppVersion()
		headers["X-ZCode-Agent"] = X_ZCODE_AGENT
		headers["HTTP-Referer"] = HTTP_REFERER
	}
	if verifyParam != "" {
		headers[CAPTCHA_HEADER] = verifyParam
	}
	if verifyRegion != "" {
		headers[CAPTCHA_REGION_HEADER] = verifyRegion
	}

	for key, value := range incomingHeaders {
		lower := strings.ToLower(key)
		if dropHeaders[lower] {
			continue
		}
		dropped := false
		for _, prefix := range dropHeaderPrefixes {
			if strings.HasPrefix(lower, prefix) {
				dropped = true
				break
			}
		}
		if dropped {
			continue
		}
		headers[key] = value
	}

	payload, err := JSONMarshalCompact(body)
	if err != nil {
		return nil, &runtimeError{msg: "请求体序列化失败"}
	}
	// 对齐 json.dumps(body, ensure_ascii=False).encode("utf-8")——再补一个空格
	// 分隔符差异无业务影响，此处保持紧凑形态（FastAPI 风格 separators）
	return &BuildRequestResult{URL: targetURL, Headers: headers, Body: payload}, nil
}

// runtimeError 对齐 RuntimeError（凭证缺失等构建失败）。
type runtimeError struct{ msg string }

func (e *runtimeError) Error() string { return e.msg }

// IsRuntimeError 判断是否 RuntimeError 等价。
func IsRuntimeError(err error) bool {
	_, ok := err.(*runtimeError)
	return ok
}

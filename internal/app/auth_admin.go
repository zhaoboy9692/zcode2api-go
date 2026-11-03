// 鉴权依赖：后台管理密钥 + 可选的网关 API Key。
//
// 对齐 Python app/auth_admin.py：verify_admin_key（Bearer 头或 ?app_key= 查询
// 参数，失败限次 + 临时锁死）与 verify_gateway_key（未配置则放行）。
package app

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"
	"sync"
)

const (
	AdminFailLimit   = 8
	AdminLockSeconds = 300
)

type adminFailureRec struct {
	count       int
	lockedUntil float64
}

var (
	adminFailuresMu sync.Mutex
	adminFailures   = map[string]*adminFailureRec{}
)

// ResetAdminFailures 测试夹具：清空登录失败计数。
func ResetAdminFailures() {
	adminFailuresMu.Lock()
	adminFailures = map[string]*adminFailureRec{}
	adminFailuresMu.Unlock()
}

// clientIP 对齐 _client_ip(request)。
func clientIP(r *http.Request) string {
	for _, header := range []string{"cf-connecting-ip", "x-real-ip"} {
		val := strings.TrimSpace(r.Header.Get(header))
		if val != "" {
			return strings.TrimSpace(strings.Split(val, ",")[0])
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if host != "" {
		return host
	}
	return "unknown"
}

func isAdminLocked(ip string) bool {
	adminFailuresMu.Lock()
	defer adminFailuresMu.Unlock()
	rec, ok := adminFailures[ip]
	if !ok {
		return false
	}
	until := rec.lockedUntil
	if until != 0 && NowFloat() < until {
		return true
	}
	if until != 0 && NowFloat() >= until {
		delete(adminFailures, ip)
	}
	return false
}

func recordAdminFailure(ip string) {
	adminFailuresMu.Lock()
	defer adminFailuresMu.Unlock()
	rec, ok := adminFailures[ip]
	if !ok {
		rec = &adminFailureRec{}
		adminFailures[ip] = rec
	}
	rec.count++
	if rec.count >= AdminFailLimit {
		rec.lockedUntil = NowFloat() + AdminLockSeconds
	}
}

func clearAdminFailures(ip string) {
	adminFailuresMu.Lock()
	delete(adminFailures, ip)
	adminFailuresMu.Unlock()
}

// extractBearer 对齐 _extract_bearer。
func extractBearer(authorization string) string {
	if authorization == "" {
		return ""
	}
	scheme, token, _ := strings.Cut(authorization, " ")
	if !strings.EqualFold(scheme, "bearer") || token == "" {
		return ""
	}
	return token
}

// AdminAuthError 管理鉴权失败（携带 HTTP 状态码，routes 层直接回 JSON）。
type AdminAuthError struct {
	Code    int
	Message string
}

func (e *AdminAuthError) Error() string { return e.Message }

// VerifyAdminKey 校验后台管理密钥。
//
// 支持 `Authorization: Bearer <key>` 头或 `?app_key=<key>` 查询参数
//（后者用于 EventSource 等无法发送自定义头的场景）。
// 同一客户端连续失败达到上限后临时锁死，正确密码也要等锁过期。
func VerifyAdminKey(r *http.Request) *AdminAuthError {
	ip := clientIP(r)
	if isAdminLocked(ip) {
		return &AdminAuthError{Code: http.StatusTooManyRequests, Message: "登录失败次数过多，请稍后再试"}
	}
	key := DefaultStore.AdminKey()
	if key == "" {
		return &AdminAuthError{Code: http.StatusUnauthorized, Message: "未配置后台密钥"}
	}
	token := extractBearer(r.Header.Get("Authorization"))
	if token == "" {
		token = r.URL.Query().Get("app_key")
	}
	if token == "" {
		recordAdminFailure(ip)
		return &AdminAuthError{Code: http.StatusUnauthorized, Message: "缺少鉴权凭证"}
	}
	// 对齐 hmac.compare_digest：常数时间比较
	if !secureEqual(token, key) {
		recordAdminFailure(ip)
		return &AdminAuthError{Code: http.StatusUnauthorized, Message: "鉴权凭证无效"}
	}
	clearAdminFailures(ip)
	return nil
}

func secureEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// VerifyGatewayKey 校验 /v1/messages 网关访问密钥（未配置则放行）。
// 返回 nil 表示通过。
func VerifyGatewayKey(r *http.Request) *AdminAuthError {
	key := DefaultStore.GatewayKey()
	if key == "" {
		return nil
	}
	token := extractBearer(r.Header.Get("Authorization"))
	if token == "" {
		token = r.Header.Get("x-api-key")
	}
	if token == "" {
		return &AdminAuthError{Code: http.StatusUnauthorized, Message: "缺少 API Key"}
	}
	if !secureEqual(token, key) {
		return &AdminAuthError{Code: http.StatusForbidden, Message: "API Key 无效"}
	}
	return nil
}

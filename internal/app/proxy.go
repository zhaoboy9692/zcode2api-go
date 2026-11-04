// 显式上游代理（ZCODE_UPSTREAM_PROXY）。
//
// 与 egress.go 的 env 代理（trust_env 语义）不同，这是**显式**配置：设置后全部
// 上游官方端点（网关 /v1/messages、quota、claim、telemetry、install、version、
// 验证码 configs 与验证码浏览器子进程）统一走它，保证「验证码 token 出口 ==
// 真实请求出口」（见 egress.go 头注历史教训）。NO_PROXY 依旧生效。
//
// 形态：http://user:pass@host:port、https://…、socks5://user:pass@host:port、
// socks5h://…（socks5h 与 socks5 同义——Go 的 socks5 拨号本就把域名交给代理
// 远端解析）。裸 host:port 按 http 代理处理（对齐 proxyMap 的补全规则）。
//
// 浏览器形态（BrowserProxyRaw）：Chromium 的 --proxy-server 不支持鉴权——
//   - http(s) 代理：剥离 userinfo，凭据由 solver_pw.js 用 page.authenticate 回填；
//   - socks5 代理：Chromium 不支持 SOCKS 用户名/密码认证（Chromium 多年未实现），
//     有凭据时起一个本地免鉴权中继（proxyrelay.go），浏览器连中继、中继带凭据
//     连真代理——网关侧不受此限制（Go 原生支持带鉴权 socks5）。
package app

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
)

var (
	upstreamProxyOnce sync.Once
	upstreamProxyAddr *url.URL
	upstreamProxyErr  error
)

// NormalizeProxyRaw 校验并规范化代理字符串：socks5h→socks5、裸 host:port 补 http://。
// 返回规范化后的字符串（含凭据，勿直接打日志）；空串合法（= 清除/未配置）。
func NormalizeProxyRaw(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("代理地址解析失败: %v", err)
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "socks5h":
		// socks5h：域名由代理远端解析；Go/Chromium 的 socks5 即此语义
		scheme = "socks5"
	case "http", "https", "socks5":
	default:
		return "", fmt.Errorf("代理协议 %q 不支持（仅 http/https/socks5/socks5h）", u.Scheme)
	}
	if u.Host == "" {
		return "", errors.New("代理缺少 host:port")
	}
	u.Scheme = scheme
	return u.String(), nil
}

// loadUpstreamProxy 解析并规范化 ZCODE_UPSTREAM_PROXY（进程生命周期内只解析一次）。
func loadUpstreamProxy() {
	raw, err := NormalizeProxyRaw(os.Getenv("ZCODE_UPSTREAM_PROXY"))
	if err != nil {
		upstreamProxyErr = fmt.Errorf("ZCODE_UPSTREAM_PROXY: %v", err)
		return
	}
	if raw == "" {
		return
	}
	u, _ := url.Parse(raw)
	upstreamProxyAddr = u
}

// UpstreamProxy 显式上游代理（规范化后）；未配置返回 nil。
func UpstreamProxy() *url.URL {
	upstreamProxyOnce.Do(loadUpstreamProxy)
	if upstreamProxyErr != nil {
		return nil
	}
	return upstreamProxyAddr
}

// UpstreamProxyRaw 显式上游代理的规范化字符串（含凭据，勿直接打日志）；未配置返回 ""。
func UpstreamProxyRaw() string {
	u := UpstreamProxy()
	if u == nil {
		return ""
	}
	cp := *u
	return cp.String()
}

// ProxyFuncFor 显式代理的 http.Transport.Proxy 函数：NO_PROXY 命中 → 直连。
func ProxyFuncFor() func(*http.Request) (*url.URL, error) {
	return ProxyFuncForRaw(UpstreamProxyRaw())
}

// ProxyFuncForRaw 固定代理字符串的 http.Transport.Proxy 函数：NO_PROXY 命中 → 直连。
func ProxyFuncForRaw(raw string) func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		if NoProxyCovers(req.URL.String()) {
			return nil, nil
		}
		cp, err := url.Parse(raw)
		if err != nil {
			return nil, nil
		}
		return cp, nil
	}
}

// ProxyRawForAccount 该账号实际生效的显式代理：账号级 > 全局；"" = 无显式代理（env/直连）。
func ProxyRawForAccount(account *Account) string {
	if account != nil {
		if p, err := NormalizeProxyRaw(account.Proxy); err == nil && p != "" {
			return p
		}
	}
	return UpstreamProxyRaw()
}

// EgressTagForAccount 该账号上游请求的出口标签。
// 显式代理 → 规范化代理 URL 作为标签身份（验证码池按其隔离，勿外泄日志）；
// 无显式代理 → 沿用 env 语义（"direct" / "proxy"）。
func EgressTagForAccount(account *Account) string {
	if raw := ProxyRawForAccount(account); raw != "" {
		return raw
	}
	return EgressFor(UPSTREAM["zai"])
}

// BrowserProxyRaw 验证码浏览器子进程用的代理形态（--proxy-server 兼容，无凭据）。
// 未配置返回 ""；socks5+凭据 → 本地免鉴权中继地址；其余 → 剥离 userinfo。
func BrowserProxyRaw() string {
	raw := UpstreamProxyRaw()
	if raw == "" {
		return ""
	}
	return BrowserFormForRaw(raw)
}

// BrowserFormForRaw 任意代理字符串 → 浏览器形态（无凭据 --proxy-server 值）。
// socks5+凭据 → 本地免鉴权中继地址；其余 → 剥离 userinfo（凭据由 solver
// 用 page.authenticate 回填）。
func BrowserFormForRaw(raw string) string {
	normalized, err := NormalizeProxyRaw(raw)
	if err != nil || normalized == "" {
		return ""
	}
	u, _ := url.Parse(normalized)
	if u.Scheme == "socks5" && u.User != nil {
		local, err := ensureSocksAuthRelay(u)
		if err != nil {
			LogWarn("proxy", fmt.Sprintf("SOCKS 免鉴权中继启动失败，浏览器将无法走带鉴权 SOCKS 代理: %v", err))
			cp := *u
			cp.User = nil
			return cp.String()
		}
		return local
	}
	cp := *u
	cp.User = nil
	return cp.String()
}

// MaskProxySecret 代理地址脱敏（日志回显用）：userinfo 的密码替换为 ***。
func MaskProxySecret(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	if u.User == nil {
		return raw
	}
	user := u.User.Username()
	if user == "" {
		user = "***"
	}
	u.User = url.UserPassword(user, "***")
	return u.String()
}

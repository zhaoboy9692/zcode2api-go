// 出口一致性：验证码 token 的签发出口必须等于真实请求的出口。
//
// 阿里云无痕验证把 `verifyParam` 绑定到签发它的那次浏览会话（含出口 IP）。
// 官方 ZCode 客户端天然满足——SDK 在同一个 renderer 里跑、请求从同一个 socket
// 发出；本服务把两件事拆在不同进程，必须显式对齐，否则上游判
// 「unusual activity」（3012）。
//
// 历史教训（2026-10-01 claim 排障）：token 直连解、claim 走 US 代理 → 恒被拒；
// 两者都直连才过。当时的结论被表述成「claim 必须直连」，更准确的表述是
// 「token 出口必须等于请求出口」——直连只是碰巧让两边一致。
//
// 本模块只回答一个问题：某个上游 URL 的请求实际从哪个出口出去。答案必须与
// Python 版 httpx 的判定**逐字一致**（网关的 httpx 客户端是 trust_env=True），
// 所以这里复刻 httpx._utils.get_environment_proxies + URLPattern 的匹配语义，
// 而不是凭直觉写一套「NO_PROXY 像 curl」的规则——两者差异很大：
//
//   - `NO_PROXY=zcode.z.ai`    → 命中该 host 及其子域（httpx 键 all://*zcode.z.ai）
//   - `NO_PROXY=.zcode.z.ai`   → 只命中子域，**不命中** zcode.z.ai 本身
//   - `NO_PROXY=*.zcode.z.ai`  → 通配符被 re.escape 成字面量 `*`，**什么都不命中**
//   - `NO_PROXY=zcode.z.ai:443`→ 仅在端口为 443 时命中
//   - `NO_PROXY=*`             → 全部直连（httpx 直接返回空 proxy 表）
//   - `192.168.0.0/16` 这类 CIDR 同样按字面量处理，不展开
//
// 代理来源对齐 `urllib.request.getproxies()`（httpx 用的就是它）：环境变量
// `*_proxy`（no_proxy 同源采集，键名 "no"）。Python 版在 Windows/macOS 还会
// 读系统代理；Go 服务以 Linux 容器部署为主，本实现对齐 getproxies_environment
// 语义（env 即全部真相），系统代理场景需显式 export 环境变量。
//
// 误判的代价不对称：把 proxy 判成 direct 会让 token 与请求换出口用（3012），
// 所以宁可复刻这份语义，也不要「更宽松地认为某 host 直连」。
//
// 对齐 Python app/egress.py。
package app

import (
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

const (
	EgressDirect = "direct"
	EgressProxy  = "proxy"
)

// getproxies 对齐 urllib.request.getproxies_environment()：
// 遍历环境变量，`name_proxy` → 键 name（统一小写；同键后出现者覆盖先出现者，
// 与 Python dict 迭代覆盖顺序一致）。CGI 场景（REQUEST_METHOD 存在）剔除
// http_proxy（CVE-2016-1000110）。no_proxy → 键 "no"。
func getproxies() map[string]string {
	out := map[string]string{}
	for _, kv := range os.Environ() {
		eq := strings.Index(kv, "=")
		if eq <= 0 {
			continue
		}
		name := strings.ToLower(kv[:eq])
		value := kv[eq+1:]
		if value != "" && strings.HasSuffix(name, "_proxy") {
			out[name[:len(name)-6]] = value
		}
	}
	if _, has := os.LookupEnv("REQUEST_METHOD"); has {
		delete(out, "http")
	}
	return out
}

// proxyMap httpx `_get_proxy_map` 的 scheme → 代理 子集（all/http/https）。
func proxyMap() map[string]string {
	info := getproxies()
	out := map[string]string{}
	for _, scheme := range []string{"http", "https", "all"} {
		host := strings.TrimSpace(info[scheme])
		if host != "" {
			if strings.Contains(host, "://") {
				out[scheme] = host
			} else {
				out[scheme] = "http://" + host
			}
		}
	}
	return out
}

// ProxyURL 该目标会用的代理地址；`""` 表示无代理可走。
//
// 显式配置 ZCODE_UPSTREAM_PROXY 时优先返回它（NO_PROXY 的命中判定在
// EgressFor/ProxyFuncFor 里做）。否则对齐 httpx：按 (端口, host 长度,
// scheme 长度) 排序取最具体的一条，scheme 专属条目优先于 `ALL_PROXY`。
// 不传目标时按 https 取。
func ProxyURL(urlOrHost string) string {
	if raw := UpstreamProxyRaw(); raw != "" {
		return raw
	}
	hosts := proxyMap()
	scheme := "https"
	if urlOrHost != "" {
		if strings.Contains(urlOrHost, "//") {
			scheme = urlSchemeOf(urlOrHost)
		} else {
			scheme = ""
		}
		if scheme != "http" && scheme != "https" {
			scheme = ""
		}
	}
	keys := []string{}
	if scheme != "" {
		keys = append(keys, scheme)
	}
	keys = append(keys, "all")
	for _, key := range keys {
		if v, ok := hosts[key]; ok {
			return v
		}
	}
	// 目标 scheme 无专属代理时，httpx 没有可匹配的 mount → 直连
	return ""
}

func urlSchemeOf(raw string) string {
	// 对齐 urllib.parse.urlsplit(...).scheme：截到第一个 ':'
	i := strings.Index(raw, ":")
	if i < 0 {
		return ""
	}
	return strings.ToLower(raw[:i])
}

// noProxyEntries 对齐 _no_proxy_entries。
func noProxyEntries() []string {
	var out []string
	for _, item := range strings.Split(getproxies()["no"], ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

// hostPattern httpx URLPattern 的 host 匹配（nil 表示不限 host）。
func hostPattern(hostPatternStr string) *regexp.Regexp {
	if hostPatternStr == "" || hostPatternStr == "*" {
		return nil
	}
	if strings.HasPrefix(hostPatternStr, "*.") {
		// *.example.com：只匹配子域，不匹配 example.com 本身
		return regexp.MustCompile(`^.+\.` + regexp.QuoteMeta(hostPatternStr[2:]) + `$`)
	}
	if strings.HasPrefix(hostPatternStr, "*") {
		// *example.com：example.com 与任意子域
		return regexp.MustCompile(`^(.+\.)?` + regexp.QuoteMeta(hostPatternStr[1:]) + `$`)
	}
	return regexp.MustCompile("^" + regexp.QuoteMeta(hostPatternStr) + "$")
}

// isBareHost httpx 对 IPv4/IPv6/localhost 不加 `*` 前缀（按精确 host 匹配）。
func isBareHost(entry string) bool {
	if strings.ToLower(entry) == "localhost" {
		return true
	}
	hostPart := strings.Split(entry, "/")[0]
	if ip := net.ParseIP(hostPart); ip != nil {
		return true
	}
	return false
}

// mountKey NO_PROXY 条目 → (host 正则, 端口, scheme)。
//
// 与 httpx 相同：条目补成 `all://*{entry}`（IP/localhost 不加 `*`，IPv6 加
// 方括号），再交给 URL 解析取 host/port——所以 `host:443` 会带上端口约束。
// 条目自带 `://` 时按完整 URL 模式处理。
func mountKey(entry string) (*regexp.Regexp, int, string) {
	var raw string
	switch {
	case strings.Contains(entry, "://"):
		raw = entry
	case isBareHost(entry):
		if strings.Contains(entry, ":") && !strings.Contains(entry, "]") {
			raw = "all://[" + entry + "]"
		} else {
			raw = "all://" + entry
		}
	default:
		raw = "all://*" + entry
	}
	host, port := urlHostPort(raw)
	scheme := urlSchemeOf(raw)
	if scheme == "all" {
		scheme = ""
	}
	return hostPattern(host), port, scheme
}

// urlHostPort 从 URL 字符串提取 hostname 与显式端口（不补默认端口）。
// 对齐 httpx.URL.port 语义：只有显式写出才有值；IPv6 剥方括号。
func urlHostPort(raw string) (string, int) {
	rest := raw
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	// 截断 path/query
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	// 拆 userinfo
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		rest = rest[i+1:]
	}
	host := rest
	port := 0
	if strings.HasPrefix(rest, "[") {
		// IPv6 字面量
		if j := strings.Index(rest, "]"); j > 0 {
			host = rest[1:j]
			rest2 := rest[j+1:]
			if strings.HasPrefix(rest2, ":") {
				if p, err := strconv.Atoi(rest2[1:]); err == nil {
					port = p
				}
			}
		}
	} else if i := strings.LastIndex(rest, ":"); i >= 0 {
		if p, err := strconv.Atoi(rest[i+1:]); err == nil {
			host = rest[:i]
			port = p
		}
	}
	host = strings.ToLower(host)
	return host, port
}

// NoProxyCovers NO_PROXY 是否让该目标绕过代理（语义与 httpx 一致）。
//
// 端口只认 URL 里**显式写出**的：`https://zcode.z.ai` 的 port 是 None
//（httpx.URL.port 不补默认端口），所以 `NO_PROXY=zcode.z.ai:443` 不命中它。
// 传裸 host 时同理没有端口可比。
func NoProxyCovers(urlOrHost string) bool {
	var scheme, host string
	var port int
	if strings.Contains(urlOrHost, "//") {
		scheme = urlSchemeOf(urlOrHost)
		host, port = urlHostPort(urlOrHost)
	} else {
		host = urlOrHost
	}
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	for _, entry := range noProxyEntries() {
		if entry == "*" {
			return true
		}
		pattern, entryPort, entryScheme := mountKey(entry)
		if entryScheme != "" && scheme != "" && entryScheme != scheme {
			continue
		}
		if pattern != nil && !pattern.MatchString(host) {
			continue
		}
		if entryPort != 0 && entryPort != port {
			continue
		}
		return true
	}
	return false
}

// EgressFor 该目标实际使用的出口：`proxy`（走 env/系统代理）或 `direct`。
//
// 与 httpx `trust_env=True` 的判定一致：NO_PROXY 命中 → 直连；
// 否则配了代理就走代理；都没有则直连。
func EgressFor(urlOrHost string) string {
	if ProxyURL(urlOrHost) == "" {
		return EgressDirect
	}
	if NoProxyCovers(urlOrHost) {
		return EgressDirect
	}
	return EgressProxy
}

// EgressForUpstream messages 上游端点的出口标签（热路径常用）。
func EgressForUpstream() string { return EgressFor(UPSTREAM["zai"]) }

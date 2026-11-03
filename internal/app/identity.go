// 上游身份头仿真 —— 对齐 zapi identity.ts 镜像的官方 ZCode 客户端 `pio` 头集合。
//
// 官方客户端对上游发的每个请求都携带这组 companion 头（指纹层），缺失或形状
// 不对都会提高 WAF 关注度。此处逐字段、按序复刻：
//
//	HTTP-Referer, User-Agent, X-ZCode-App-Version, X-Title, X-ZCode-Agent,
//	X-Platform, X-Release-Channel, X-Client-Language, X-Client-Timezone,
//	X-Os-Category, X-Os-Version, X-Device-Mid
//
// 有账号时 X-Device-Mid / 平台 / 语言 / 时区取自该号 DeviceProfile（一号一台
// 生成的桌面设备）。无账号时回退全局伪装常量 + quota.device_mid()。
//
// 另含追踪头（attribution 六件，2026-10-29 对齐官方 3.16.3 构造器）：
// x-request-id / x-zcode-session-type / x-zcode-trace-id / x-query-id /
// x-zcode-query-source / x-session-id，每请求重新生成；分级语义已随
// 官方客户端升级废除（详见 BuildTraceHeaders 注释）。
//
// 平台/语言/时区/设备 ID 取自账号指纹（fingerprint.ProfileFor）：每账号独立
// 设备档案，消灭「多账号同一设备」的关联信号。account 为 nil（CLI 自检等）
// 时回退全局伪装常量 + 本机 device_mid。
//
// 对齐 Python app/identity.py。
package app

import (
	"regexp"
	"strings"

	"github.com/zhaoboy9692/zcode2api-go/internal/uuidx"
)

// 打印可见 ASCII 门（ZCode bundle fio 助手）；任何头值不含此形态即丢弃该头
var asciiPrintable = regexp.MustCompile(`^[\x20-\x7e]+$`)

// cleanHeader 对齐 _clean：strip 后非空且全打印 ASCII 才收。
func cleanHeader(value string) string {
	v := strings.TrimSpace(value)
	if v != "" && asciiPrintable.MatchString(v) {
		return v
	}
	return ""
}

// osCategoryOf 对齐 _os_category(sys_platform)。
func osCategoryOf(sysPlatform string) string {
	// 兼容两种形态：platform.system() 产出 darwin/windows/linux，伪装平台用 win32
	switch sysPlatform {
	case "darwin", "macos":
		return "macos"
	case "win32", "windows":
		return "windows"
	default:
		return "linux"
	}
}

// BuildIdentityHeaders 构建完整身份头（保持 pio 的字段顺序；条件性缺失语义同样镜像）。
//
// 有 account 时按其指纹档案出值（每账号独立设备形态，见 fingerprint.go）；
// 无 account 时回退全局伪装常量（constants.CLIENT_PLATFORM 等，与 zapi
// identity.ts 同策略：服务端部署在 Linux 时 platform.* 会暴露云服务器特征，
// 与官方桌面端形状不符）。env 覆盖仅用于无 account 路径的指纹实验。
func BuildIdentityHeaders(account *Account) map[string]string {
	appVersion := cleanHeader(ClientAppVersion())
	var plat, arch, release, language, timezone, deviceMidVal string
	var channel string
	var hasChannel, hasLanguage, hasTimezone, hasRelease bool
	if account != nil {
		profile := ProfileFor(account)
		plat, arch = profile.Platform, profile.Arch
		release = profile.OSVersion
		channel = BILLING_RELEASE_CHANNEL
		hasChannel = true
		language, timezone = profile.Language, profile.Timezone
		hasLanguage, hasTimezone = true, true
		deviceMidVal = profile.DeviceMid
	} else {
		platArch := strings.SplitN(CLIENT_PLATFORM, "-", 2) // "darwin-arm64"
		plat = cleanHeader(envOr("ZCODE_IDENTITY_PLATFORM", platArch[0]))
		if plat == "" {
			plat = "darwin"
		}
		defArch := "arm64"
		if len(platArch) > 1 {
			defArch = platArch[1]
		}
		arch = cleanHeader(envOr("ZCODE_IDENTITY_ARCH", defArch))
		if arch == "" {
			arch = "arm64"
		}
		release = cleanHeader(envOr("ZCODE_IDENTITY_RELEASE", IDENTITY_OS_VERSION))
		hasRelease = release != ""
		channel = cleanHeader(envOr("ZCODE_IDENTITY_RELEASE_CHANNEL", IDENTITY_RELEASE_CHANNEL))
		hasChannel = channel != ""
		language = cleanHeader(envOr("ZCODE_IDENTITY_CLIENT_LANGUAGE", IDENTITY_CLIENT_LANGUAGE))
		hasLanguage = language != ""
		timezone = cleanHeader(envOr("ZCODE_IDENTITY_CLIENT_TIMEZONE", IDENTITY_CLIENT_TIMEZONE))
		hasTimezone = timezone != ""
		deviceMidVal = cleanHeader(envOr("ZCODE_IDENTITY_DEVICE_MID", DeviceMid()))
	}

	headers := map[string]string{
		"HTTP-Referer": HTTP_REFERER,
		"User-Agent":   SettingsUserAgent(),
	}
	if appVersion != "" {
		headers["X-ZCode-App-Version"] = appVersion
	}
	if account != nil {
		headers["X-Title"] = BILLING_TITLE
	} else {
		headers["X-Title"] = IDENTITY_TITLE
	}
	headers["X-ZCode-Agent"] = X_ZCODE_AGENT
	headers["X-Platform"] = plat + "-" + arch
	if hasChannel {
		headers["X-Release-Channel"] = channel
	}
	if hasLanguage {
		headers["X-Client-Language"] = language
	}
	if hasTimezone {
		headers["X-Client-Timezone"] = timezone
	}
	if plat != "" {
		headers["X-Os-Category"] = osCategoryOf(plat)
	}
	if hasRelease {
		headers["X-Os-Version"] = release
	}
	if deviceMidVal != "" {
		headers["X-Device-Mid"] = deviceMidVal
	}
	return headers
}

// BuildTraceHeaders 追踪头：每请求全新 UUID（对齐官方 3.16.3 attribution 构造器）。
//
// session_id 传入时复用为 x-session-id —— 官方同一会话内 x-session-id 与
// metadata.user_id blob 的 session_id 是同值，二者必须一致（不一致会构成
// 指纹矛盾）。未传入则新生成。
//
// 历史注记：旧实现按 zapi（3.10.2 时代）静态分析做 start-plan/coding-plan
// 分级——start-plan 只发 request-id/session-type/trace-id 三件，理由是
// 「误发 query-id/session-id 触发 3012」。该结论产生于 2026-09-05 事件，
// 事后已被修正为高频测试触发的临时风控，分级假设从未单独验证过。
//
// 2026-10-29 对 3.16.3 bundle 静态核对（createModelRequestAttributionHeaders）：
// 六件头**无任何按套餐/通道的分级**，数据存在即发；同日 mitm 实抓真实
// 请求头六件俱全（x-zcode-query-source=main_turn）。故全量对齐：
//
//	x-request-id / x-zcode-session-type / x-zcode-trace-id /
//	x-query-id / x-zcode-query-source / x-session-id
//
//（x-opencode-session 仅对 opencode.ai 域名生效，与本服务无关。）
//
// 与官方的已知残留差异：官方 session-id/query-id 在会话/查询内稳定，
// hub 无会话态、每请求全新——形状一致、生命周期更短，属可接受漂移。
func BuildTraceHeaders(sessionID string) map[string]string {
	if sessionID == "" {
		sessionID = uuidx.New4()
	}
	return map[string]string{
		"x-request-id":         uuidx.New4(),
		"x-zcode-session-type": "main",
		"x-zcode-trace-id":     uuidx.New4(),
		"x-query-id":           uuidx.New4(),
		"x-zcode-query-source": "main_turn",
		"x-session-id":         sessionID,
	}
}

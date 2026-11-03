// 宿主机真实指纹采集 —— 诊断/测试用，不是账号入池默认源。
//
// 账号身份走 fingerprint.RandomProfile 的成套桌面 SKU（一号一台生成设备）。
// 本模块只描述部署机事实（Linux 云内核、无显示器 1920x1080 等），供
// host_profile / 运维对照，禁止再当作多账号共用的上游身份。
//
// 采集项 ↔ DeviceProfile 字段：
//   platform    platform.system()   → darwin / win32 / linux（官方 process.platform 语义）
//   arch        platform.machine()  → arm64 / x64（官方 process.arch 语义）
//   os_version  _host_os_version() → os.release() 同源，官方 X-Os-Version 直接用它
//               （Windows 上 release() 只给 marketing 版 "10"/"11"，归一为
//                内核形态 "10.0.xxxxx"）
//   timezone    /etc/localtime → IANA 名：符号链接反解；实体文件则与
//               /usr/share/zoneinfo 字节比对；都失败退 UTC
//   language    $LANG（zh_CN.UTF-8 → zh-CN；缺失退 en-US）
//   screen      本机无显示器（服务器形态）→ 官方桌面端必有屏幕，取 HOST_FALLBACK
//   device_mid  本模块不生成 —— DeviceProfile 缺省工厂给每次采集全新 UUID；
//               MID 归属（全局持久化 / 每账号新装）由调用方决定
//               （见 fingerprint.HostProfile 的两种传参语义）
//
// 所有值仍过 fingerprint.Validate 合规门：真机数据天然合规（Linux 内核版本
// 不在预置池时，Validate 按「版本形态」放行本机采集值，见 fingerprint 备注）。
//
// 对齐 Python app/hostinfo.py。平台判定走 runtime.GOOS（darwin/linux/windows），
// arch 走 runtime.GOARCH（Go 值 arm64/amd64 → arm64/x64 对齐 process.arch）。
package app

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// FallbackScreen 服务器无显示器时的兜底分辨率（官方桌面端激活事件必有 screen_resolution）
const FallbackScreen = "1920x1080"

// resolveTimezone IANA 时区名：官方客户端读系统时区（Intl.resolvedOptions().timeZone）。
//
// 解析顺序：
//  1. /etc/localtime 符号链接路径反解（darwin 通常如此）
//  2. /etc/localtime 为实体文件时（部分 Linux 发行版是拷贝而非链接，
//     如 pxed），与 /usr/share/zoneinfo 逐文件字节比对取唯一匹配
//  3. 都失败退 UTC
func resolveTimezone() string {
	const path = "/etc/localtime"
	if target, err := filepath.EvalSymlinks(path); err == nil {
		parts := strings.Split(filepath.ToSlash(target), "/")
		for i, seg := range parts {
			if seg == "zoneinfo" && i+2 < len(parts) {
				return parts[i+1] + "/" + parts[i+2]
			}
		}
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "UTC"
	}
	zoneinfoDir := "/usr/share/zoneinfo"
	if st, err := os.Stat(zoneinfoDir); err != nil || !st.IsDir() {
		return "UTC"
	}
	var candidates []string
	_ = filepath.Walk(zoneinfoDir, func(f string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		rel, relErr := filepath.Rel(zoneinfoDir, f)
		if relErr != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil // 跳过链接（posix/RIGHT 别名）
		}
		if strings.Contains(rel, "/") == false {
			// 顶层单段文件（CST 等）不作候选：真实地名以大写开头的两段式优先
			// Python 源：rel[0].isupper() 且两段式不强制——保留单段大写候选
			if len(rel) > 0 && !(rel[0] >= 'A' && rel[0] <= 'Z') {
				return nil
			}
		} else if len(rel) > 0 && !(rel[0] >= 'A' && rel[0] <= 'Z') {
			return nil
		}
		if strings.HasPrefix(rel, "Etc/") || strings.HasPrefix(rel, "posix/") ||
			strings.HasPrefix(rel, "right/") || rel == "posixrules" || rel == "leapseconds" {
			return nil
		}
		if filepath.Ext(f) != "" {
			return nil // 二进制 TZif 无后缀；跳过非数据文件
		}
		data, rerr := os.ReadFile(f)
		if rerr != nil {
			return nil
		}
		if bytes.Equal(data, content) {
			candidates = append(candidates, rel)
		}
		return nil
	})
	if len(candidates) == 0 {
		return "UTC"
	}
	// Area/City 两段式优先于单段，字典序稳定输出
	sortCandidates(candidates)
	return candidates[0]
}

func sortCandidates(candidates []string) {
	// 简单插入排序：(0 if "/" in r else 1, r)
	for i := 1; i < len(candidates); i++ {
		for j := i; j > 0; j-- {
			ki, kj := 0, 0
			if !strings.Contains(candidates[j-1], "/") {
				ki = 1
			}
			if !strings.Contains(candidates[j], "/") {
				kj = 1
			}
			if kj < ki || (kj == ki && candidates[j] < candidates[j-1]) {
				candidates[j-1], candidates[j] = candidates[j], candidates[j-1]
			} else {
				break
			}
		}
	}
}

// resolveLanguage 语言标签：$LANG 的 zh_CN.UTF-8 形态转 zh-CN；无 Locale 环境退 en-US。
//
// 官方桌面端 locale 来自系统偏好；Linux 容器常为 C/C.UTF-8（无语言信息），
// 此时与官方常见默认 en-US 对齐（真实安装于裸 Locale 主机时同样如此）。
func resolveLanguage() string {
	raw := strings.TrimSpace(os.Getenv("LC_ALL"))
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("LANG"))
	}
	m := langRe.FindStringSubmatch(raw)
	if m == nil {
		return "en-US"
	}
	lang, region := m[1], m[2]
	if region == "" {
		switch lang {
		case "zh":
			return "zh-CN"
		case "en":
			return "en-US"
		case "ja":
			return "ja-JP"
		case "ko":
			return "ko-KR"
		case "de":
			return "de-DE"
		case "fr":
			return "fr-FR"
		default:
			return "en-US"
		}
	}
	return lang + "-" + strings.ToUpper(region)
}

// windowsKernelVersion Windows 内核形态 os_version（"10.0.22000"）。非 Windows 返回 ""。
//
// platform.release() 在 Windows 只给 marketing 版本号（"10"/"11"），通不过
// fingerprint releaseShape 的 X.Y 内核形态门；RtlGetVersion 的 major.minor.build
// 与官方客户端 Windows 档案（10.0.xxxxx）同形。
func windowsKernelVersion() string {
	major, minor, build, ok := rtlGetVersion()
	if !ok {
		return ""
	}
	return itoa(int(major)) + "." + itoa(int(minor)) + "." + itoa(int(build))
}

// hostOSVersion os_version（os.release() 同源语义，供 X-Os-Version）。
//
// Windows 走内核 build 形态；其余平台读内核 release（Linux /proc/sys/kernel/osrelease
// ≙ platform.release()；darwin 为 Darwin 版本，天然符合形态门）。
func hostOSVersion() string {
	if runtime.GOOS == "windows" {
		if kernel := windowsKernelVersion(); kernel != "" {
			return kernel
		}
		return "0.0"
	}
	if data, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		v := strings.TrimSpace(string(data))
		if v != "" {
			return v
		}
	}
	if out, err := runCmd("uname", "-r"); err == nil {
		return strings.TrimSpace(out)
	}
	return "0.0"
}

// normalizeArch process.arch 语义：arm64 / x64（官方取值）；其余按 64 位推断为 x64。
func normalizeArch(machine string) string {
	m := strings.ToLower(machine)
	if strings.Contains(m, "arm") || strings.Contains(m, "aarch") {
		return "arm64"
	}
	return "x64"
}

// normalizePlatform platform.system() → 官方 process.platform 语义。
func normalizePlatform(system string) string {
	switch strings.ToLower(system) {
	case "darwin":
		return "darwin"
	case "windows":
		return "win32"
	default:
		return "linux"
	}
}

// CollectHostProfile 采集本机真实设备档案（每次调用重采，落库由调用方负责）。
func CollectHostProfile() DeviceProfile {
	arch := normalizeArch(runtime.GOARCH)
	if runtime.GOOS == "windows" {
		arch = normalizeArch(windowsMachine())
	}
	return DeviceProfile{
		Platform:  normalizePlatform(runtime.GOOS),
		Arch:      arch,
		OSVersion: hostOSVersion(),
		Language:  resolveLanguage(),
		Timezone:  resolveTimezone(),
		Screen:    FallbackScreen,
	}
}

//go:build windows

// Windows 平台探测：RtlGetVersion（major.minor.build，对齐 sys.getwindowsversion）。
package app

import (
	"runtime"

	"golang.org/x/sys/windows"
)

func rtlGetVersion() (major, minor, build uint32, ok bool) {
	// RtlGetVersion 直读内核版本（GetVersionEx 在 manifest 不足时谎报兼容版本，
	// 对齐 Python sys.getwindowsversion 的真实内核语义）。
	v := windows.RtlGetVersion()
	if v == nil {
		return 0, 0, 0, false
	}
	return v.MajorVersion, v.MinorVersion, v.BuildNumber, true
}

func windowsMachine() string {
	// platform.machine() 只被 normalizeArch 按 arm/aarch 关键字归类；
	// Go runtime 的 GOARCH 已等价承载该信息（amd64→x64, arm64→arm64）。
	return runtime.GOARCH
}

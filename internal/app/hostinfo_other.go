//go:build !windows

// 非 Windows 平台：Windows 专属探测不可用（hostinfo 采集走 runtime.GOOS 分支）。
package app

func rtlGetVersion() (major, minor, build uint32, ok bool) { return 0, 0, 0, false }

func windowsMachine() string { return "" }

func machineArch() (string, error) { return "", nil }

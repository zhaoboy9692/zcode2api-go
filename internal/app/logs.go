// 日志工具 — ANSI 彩色终端输出 (Windows GBK 兼容)。
//
// 对齐 Python app/logs.py：ok/step/info/warn/err/header/req/req_ok/req_err/banner。
package app

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

const (
	logR   = "\033[0m"
	logG   = "\033[32m"
	logC   = "\033[36m"
	logY   = "\033[33m"
	logRed = "\033[31m"
	logDim = "\033[90m"
	logB   = "\033[1m"
	logMag = "\033[35m"
	logW   = "\033[37m"
)

func logPrint(format string, args ...any) {
	fmt.Fprintf(os.Stdout, format, args...)
}

// LogOK 对齐 logs.ok
func LogOK(module, msg string) {
	logPrint("  %s[+]%s %s%s%s %s\n", logG, logR, logDim, module, logR, msg)
}

// LogStep 对齐 logs.step
func LogStep(module, msg string) {
	logPrint("  %s[>]%s %s%s%s %s\n", logC, logR, logDim, module, logR, msg)
}

// LogInfo 对齐 logs.info
func LogInfo(module, msg string) {
	logPrint("  %s[-] %s %s%s\n", logDim, module, msg, logR)
}

// LogWarn 对齐 logs.warn
func LogWarn(module, msg string) {
	logPrint("  %s[~]%s %s%s%s %s\n", logY, logR, logDim, module, logR, msg)
}

// LogErr 对齐 logs.err
func LogErr(module, msg string) {
	logPrint("  %s[!]%s %s%s%s %s\n", logRed, logR, logDim, module, logR, msg)
}

// LogHeader 对齐 logs.header
func LogHeader(module, msg string) {
	logPrint("  %s%s%s%s %s\n", logB, logMag, module, logR, msg)
}

// LogReq 请求日志 — 一行显示关键信息（对齐 logs.req）
func LogReq(reqID, model string, stream bool, lastMsg string) {
	s := "sync"
	if stream {
		s = "stream"
	}
	msgPreview := lastMsg
	if runes := []rune(msgPreview); len(runes) > 40 {
		// Python last_msg[:40] 按码点截断，对齐避免切坏 UTF-8
		msgPreview = string(runes[:40]) + "..."
	}
	logPrint("  %s>>>%s %s%s%s  %s%s%s  %s%s%s  %s\"%s\"%s\n",
		logC, logR, logDim, reqID, logR, logW, model, logR, logDim, s, logR, logDim, msgPreview, logR)
}

// LogReqOK 请求完成（对齐 logs.req_ok）
func LogReqOK(reqID string, tokens int) {
	t := ""
	if tokens != 0 {
		t = fmt.Sprintf("  %s%dtok%s", logDim, tokens, logR)
	}
	logPrint("  %s<<<%s %s%s%s%s\n", logG, logR, logDim, reqID, logR, t)
}

// LogReqErr 请求错误 — 只显示 req_id + 简短原因，不泄露上游（对齐 logs.req_err）
func LogReqErr(reqID, msg string) {
	logPrint("  %s<!>%s %s%s%s  %s\n", logRed, logR, logDim, reqID, logR, msg)
}

var stripANSIRe = regexp.MustCompile(`\033\[[0-9;]*m`)

// LogBanner 对齐 logs.banner：计算去 ANSI 后的最大宽度，画等号边框。
func LogBanner(lines []string) {
	w := 0
	for _, line := range lines {
		if n := len([]rune(stripANSIRe.ReplaceAllString(line, ""))); n > w {
			w = n
		}
	}
	w += 4
	border := logDim + strings.Repeat("=", w) + logR
	logPrint("\n%s\n", border)
	for _, line := range lines {
		logPrint("  %s\n", line)
	}
	logPrint("%s\n\n", border)
}

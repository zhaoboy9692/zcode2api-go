// hostinfo 辅助实现（正则/子进程/格式化）。
package app

import (
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// langRe $LANG 形态解析：语言主码（2-3 位小写）+ 可选地区码（对齐 _LANG_RE）
var langRe = regexp.MustCompile(`^([a-z]{2,3})(?:[_-]([A-Za-z]{2,4}))?`)

// runCmd 运行外部命令取 stdout（uname 等探测用）。
func runCmd(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

func itoa(n int) string { return strconv.Itoa(n) }

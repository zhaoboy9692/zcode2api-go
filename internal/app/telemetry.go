// 激活遥测上报 —— 官方 event/report 端点的单一事实源。
//
// 事件体 16 字段与 app.asar 逆向的 telemetry-core sendReport 逐字段一致
//（commit 65a547b 三源实证：首启日志 / asar 逆向 / pxed 实装模仿）。字段集、
// URL、业务码判定只在本模块维护：
//
//   - claim.report_activation_events（登录态激活上报，preview 前）
//   - install.run_install_sequence（首启安装序）
//
// 端点走 settings.ZCODE_EVENT_REPORT_URL（env 可覆盖，测试注入 mock 上游）。
//
// 对齐 Python app/telemetry.py。
package app

import (
	"bytes"
	"fmt"
	"net/http"
	"time"

	"github.com/zhaoboy9692/zcode2api-go/internal/uuidx"
)

const telemetryTimeout = 10 // 秒

// BuildActivationEventBody 激活事件体（官方 sendReport 字段集固定为这 16 个）。
func BuildActivationEventBody(element string, profile DeviceProfile, userID string) map[string]any {
	return map[string]any{
		"event_id":           uuidx.New4(),
		"client_timezone":    profile.Timezone,
		"client_language":    profile.Language,
		"element_name":       element,
		"event_region":       "app",
		"event_type":         "view",
		"event_text":         "",
		"event_extra_detail": map[string]any{},
		"user_id":            userID,
		"screen_resolution":  profile.Screen,
		"app_version":        BillingAppVersion(),
		"device_os_category": profile.OsCategory(),
		"device_os_version":  profile.OSVersion,
		"device_mid":         profile.DeviceMid,
		"mac_id":             "",
		"marketing_params":   "{}",
	}
}

// TelemetryBusinessCode 上游业务码；非对象 JSON / 缺 code / 非数字 → -1（视为失败）。
func TelemetryBusinessCode(body any) int {
	dict, ok := body.(map[string]any)
	if !ok {
		return -1
	}
	v, has := dict["code"]
	if !has {
		return -1
	}
	if n, ok := AsInt(v); ok {
		return n
	}
	return -1
}

// telemetryHTTPClient trust_env=False 直连（与 Python 注释同语义：不用环境代理）。
func telemetryHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// trust_env=False：直连，忽略 HTTP_PROXY 等环境变量
			Proxy: nil,
		},
	}
}

// PostActivationEvent 单条激活事件上报（无 Authorization，官方端点不校验登录态）。
//
// HTTP >= 400 或业务码非 0 抛错误，文案含定位信息（"HTTP 500" / "业务码异常"）；
// 网络错误原样上抛 —— 容错策略（中止/继续）由调用方定。
//
// trust_env=False 直连（2.7.16，2026-11-04 线上实锤）：激活上报是领取链路的
// 资格信号，必须与 billing/claim 同出口——claim.py 实测「claim 直连 code:0、
// 走美国出口被拒 unusual activity」，且 hub 进程 env 代理（127.0.0.1:10822）
// 当晚完全超时（curl 15s HTTP 000），激活上报逐轮 ConnectTimeout/ReadTimeout
// → 上游收不到当日活跃信号 → marketing/touch 恒空 → 自动领取全天空转。
func PostActivationEvent(profile DeviceProfile, userID, element string, timeout time.Duration) error {
	if timeout == 0 {
		timeout = telemetryTimeout * time.Second
	}
	bodyBytes, err := JSONMarshalCompact(BuildActivationEventBody(element, profile, userID))
	if err != nil {
		return err
	}
	client := telemetryHTTPClient(timeout)
	resp, err := client.Post(ZCODE_EVENT_REPORT_URL, "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	buf := new(bytes.Buffer)
	_, _ = buf.ReadFrom(resp.Body)
	text := buf.String()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("event/report %s HTTP %d: %s", element, resp.StatusCode, truncateStr(text, 120))
	}
	body, err := JSONDecode(text)
	if err != nil {
		body = nil
	}
	code := TelemetryBusinessCode(body)
	if code != 0 {
		return fmt.Errorf("event/report %s 业务码异常(%d): %s", element, code, truncateStr(text, 120))
	}
	return nil
}

func truncateStr(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

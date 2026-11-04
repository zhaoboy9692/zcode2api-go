// ZCode 首次安装初始化仿真 —— 按官方客户端真实首启顺序请求一遍。
//
// 官方桌面端首启实测序（本机 ZCode 首启日志 2026-09-02 + app.asar 逆向
// + pxed AppImage 实装模仿，三源交叉确认）：
//  1. GET  /api/v1/client/configs?app_version=…   免鉴权拉取运行配置
//    （验证码 scene/region 开关、startPlanPreview 等功能开关）
//  2. POST /api/v1/event/report                   激活遥测（无 Authorization）
//     element = app_launch → app_daily_active（日活去重由上游按 device_mid+日期算）
//  3. （用户登录后）OAuth CLI 流程 → 业务凭证 —— oauth.ZaiAuthFlow 已覆盖；
//     登录态的激活上报由 claim.ReportActivationEvents 承担，不在此处
//
// 安装语义要点（对齐官方客户端）：
//   - client/configs 不带 Authorization（免鉴权端点），带 app_version 查询参数；
//     实测带 platform 参数会被拒（3001），故只带 app_version。
//   - event/report 的 device_mid + 当日日期构成日活去重键；重复上报同日
//     app_daily_active 无副作用（官方客户端每次启动都发）。
//   - 全程不需要账号凭证 —— 「安装」先于「登录」，未登录设备同样上报
//     app_launch（user_id 为空串），登录后才带 user_id。
//
// 对外入口 RunInstallSequence()：Server 生命周期每次启动后台执行一次
//（官方客户端每次启动都拉 configs + 发 app_launch）。任何失败都不抛出，
// errors 列表留痕（安装仿真不影响主服务，与官方「配置拉取失败继续启动」一致）。
//
// 对齐 Python app/install.py。
package app

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// syncWaitGroup 别名（保持文件自洽）
type syncWaitGroup = sync.WaitGroup

const installClientTimeout = 15 // 秒

// installFetchClientConfigs 第 1 步：client/configs（免鉴权）。HTTP / 业务码任一失败返回错误。
//
// trust_env=False 直连（2.7.16）：安装序与激活上报（telemetry 直连）/billing
//（claim 直连）同属一条官方首启模拟链路，必须同出口——hub env 代理
//（127.0.0.1:10822）2026-11-04 实测完全超时，走代理即「All connection
// attempts failed」，且出口分裂本身是指纹矛盾信号。
func installFetchClientConfigs(account *Account) (map[string]any, error) {
	fullURL := fmt.Sprintf("%s?app_version=%s", CLIENT_CONFIGS_URL, BillingAppVersion())
	client := &http.Client{
		Timeout:   installClientTimeout * time.Second,
		Transport: upstreamTransportFor(account),
	}
	req, err := http.NewRequest(http.MethodGet, fullURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ZCode/"+BillingAppVersion())
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	buf := &strings.Builder{}
	tmp := make([]byte, 32*1024)
	for {
		n, readErr := res.Body.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if readErr != nil {
			break
		}
	}
	if res.StatusCode >= 400 {
		// 对齐 res.raise_for_status()
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	v, err := JSONDecode(buf.String())
	if err != nil {
		// 非 JSON 由调用方按 ValueError 容错
		return nil, fmt.Errorf("响应非 JSON: %v", err)
	}
	body, _ := v.(map[string]any)
	if body == nil {
		body = map[string]any{}
	}
	if TelemetryBusinessCode(body) != 0 {
		return nil, fmt.Errorf("client/configs 业务码异常: %s", truncateStr(DumpJSONText(body), 120))
	}
	data, _ := body["data"].(map[string]any)
	if data == nil {
		data = map[string]any{}
	}
	return data, nil
}

// installCaptchaEnabled 对齐 _captcha_enabled(configs)。
func installCaptchaEnabled(configs map[string]any) bool {
	cfg, _ := configs["configs"].(map[string]any)
	if cfg == nil {
		return false
	}
	captcha, _ := cfg["captcha"].(map[string]any)
	if captcha == nil {
		return false
	}
	enabled, _ := captcha["enabled"].(bool)
	return enabled
}

// RunInstallSequenceForAccount 按账号安装序：client/configs + 激活事件，绑定该账号的安装身份。
//
// 与 RunInstallSequence 的差别：
//   - 设备档案 = 账号自身指纹（ProfileFor → 每账号独立 device_mid，
//     官方语义「每台安装一台设备」），而非全局 device_mid；
//   - user_id 从账号 JWT 解出（登录态安装）；无 JWT（apiKey 账号）退回空串
//     —— 官方未登录安装形态；
//   - 幂等：account.installed_at 非空直接跳过（skipped=true，零上游请求），
//     完成后落 installed_at 并持久化。
//
// 任何失败都不抛出，errors 留痕（同 RunInstallSequence 约定）。
func RunInstallSequenceForAccount(account *Account) map[string]any {
	result := map[string]any{
		"configs_fetched": false,
		"events_reported": []any{},
		"errors":          []any{},
		"installed":       false,
		"skipped":         false,
	}
	errs := func() []any { return result["errors"].([]any) }
	appendErr := func(msg string) { result["errors"] = append(errs(), msg) }
	if account.InstalledAt != nil {
		result["skipped"] = true
		return result
	}

	profile := ProfileFor(account)
	userID := ClaimJWTUserID(account)

	if _, err := installFetchClientConfigs(account); err != nil {
		appendErr(fmt.Sprintf("client/configs 失败: %v", err))
	} else {
		result["configs_fetched"] = true
	}

	for _, element := range ActivationElements() {
		if err := PostActivationEvent(account, profile, userID, element, installClientTimeout*time.Second); err != nil {
			appendErr(err.Error())
		} else {
			result["events_reported"] = append(result["events_reported"].([]any), element)
		}
	}

	if len(errs()) == 0 {
		live := DefaultStore.Find(account.Provider, account.ID)
		if live == nil {
			appendErr("账号已删除，跳过安装落库")
			LogWarn("install", fmt.Sprintf("账号 %s 安装序完成前已被删除", account.Name))
			return result
		}
		now := NowFloat()
		live.InstalledAt = &now
		DefaultStore.UpdateAccount(live)
		account.InstalledAt = live.InstalledAt
		result["installed"] = true
		LogOK("install", fmt.Sprintf("账号 %s 安装序完成（install_id=%s）", account.Name, account.InstallID))
	} else {
		LogWarn("install", fmt.Sprintf("账号 %s 安装序部分失败: %s", account.Name, strings.Join(errorsToStrings(errs()), "; ")))
	}
	return result
}

func errorsToStrings(list []any) []string {
	out := make([]string, 0, len(list))
	for _, v := range list {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// RunInstallSequence 按官方首启顺序执行一次安装初始化，返回各步结果（含失败文案）。
//
// 设备身份 = 官方桌面常量档案 + 全局持久化 device_mid（quota.DeviceMid）。
// 进程级安装序只拉 configs / 报日活，不得把部署机云内核上报成用户设备；
// 每账号安装序才使用该号自己的生成 SKU。任何失败都不抛出。
func RunInstallSequence() map[string]any {
	result := map[string]any{
		"configs_fetched": false,
		"events_reported": []any{},
		"errors":          []any{},
	}
	errs := func() []any { return result["errors"].([]any) }
	appendErr := func(msg string) { result["errors"] = append(errs(), msg) }

	parts := strings.SplitN(CLIENT_PLATFORM, "-", 2)
	plat, arch := parts[0], "arm64"
	if plat == "" {
		plat = "darwin"
	}
	if len(parts) > 1 && parts[1] != "" {
		arch = parts[1]
	}
	profile := DeviceProfile{
		Platform:  plat,
		Arch:      arch,
		OSVersion: IDENTITY_OS_VERSION,
		Language:  IDENTITY_CLIENT_LANGUAGE,
		Timezone:  IDENTITY_CLIENT_TIMEZONE,
		Screen:    ACTIVATION_SCREEN_RESOLUTION,
		DeviceMid: DeviceMid(),
	}

	if configs, err := installFetchClientConfigs(nil); err != nil {
		appendErr(fmt.Sprintf("client/configs 失败: %v", err))
	} else {
		result["configs_fetched"] = true
		result["captcha_enabled"] = installCaptchaEnabled(configs)
	}

	for _, element := range ActivationElements() {
		if err := PostActivationEvent(nil, profile, "", element, installClientTimeout*time.Second); err != nil {
			appendErr(err.Error())
		} else {
			result["events_reported"] = append(result["events_reported"].([]any), element)
		}
	}

	if len(errs()) > 0 {
		LogWarn("install", fmt.Sprintf("安装初始化部分失败: %s", strings.Join(errorsToStrings(errs()), "; ")))
	} else {
		events := strings.Join(errorsToStrings(result["events_reported"].([]any)), ",")
		if events == "" {
			events = "无"
		}
		fetched := "×"
		if result["configs_fetched"].(bool) {
			fetched = "√"
		}
		LogOK("install", fmt.Sprintf("安装初始化完成（configs=%s，events=%s）", fetched, events))
	}
	return result
}

// ── 后台安装任务调度（对齐 schedule_install + _install_tasks 强引用集合）────

var installWG syncWaitGroup

// ScheduleInstall 后台调度按账号安装序（configs + 激活事件，幂等）。
//
// 入池、指纹换发、风控禁用换设备等场景共用：不阻塞调用方；任何账号模式
// 都跑；重复调用安全（installed_at 幂等跳过）；异常全部兜住不冒泡。
func ScheduleInstall(account *Account) {
	installWG.Add(1)
	go func() {
		defer installWG.Done()
		defer func() {
			if r := recover(); r != nil {
				LogWarn("install", fmt.Sprintf("账号 %s 安装序任务异常: %v", account.Name, r))
			}
		}()
		live := DefaultStore.Find(account.Provider, account.ID)
		if live == nil {
			return
		}
		RunInstallSequenceForAccount(live)
	}()
}

// WaitInstallTasks 等待后台安装任务收尾（lifespan 关闭路径可用）。
func WaitInstallTasks() { installWG.Wait() }

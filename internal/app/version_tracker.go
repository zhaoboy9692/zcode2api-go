// ZCode 官方版本自动感知与同步管理器（Dynamic Version Tracker）。
//
// 数据源：官方原生 Electron 更新清单接口（GET /api/v1/releases/electron/manifest）。
// 实证（2026-11-03 官方桌面端逆向）：
//   - 官方桌面端检查更新直连此端点；
//   - 返回 YAML 格式，包含最新版本（version）、发布日期（releaseDate）、
//     官方原生 Markdown 更新日志（releaseNotes，含中英文双语）；
//   - 免鉴权公开只读端点。
//
// 工作机制：
//   - 启动时恢复历史缓存的最新版本（若开启自动同步，立即对齐伪装指纹）；
//   - 异步向上游拉取最新 electron manifest；
//   - 若 upstream version > 当前本地 version，且开启 auto_sync：
//     动态调用 SetActiveVersion 对齐指纹，落库并记录日志；
//   - 定时轮询（默认每 12 小时），并在管理后台提供手动触发检查与日志展示。
//
// 对齐 Python app/version_tracker.py。
package app

import (
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// ParseSemver 提取版本数字用于大小比较，如 '3.17.2' -> (3, 17, 2)。
func ParseSemver(v string) []int {
	nums := []int{}
	for _, m := range regexp.MustCompile(`\d+`).FindAllString(StrValue(v), -1) {
		if n, err := strconv.Atoi(m); err == nil {
			nums = append(nums, n)
		}
	}
	if len(nums) == 0 {
		return []int{0}
	}
	return nums
}

// IsNewerVersion candidate 是否比 baseline 更新（纯数字分量比较）。
func IsNewerVersion(candidate, baseline string) bool {
	c := ParseSemver(candidate)
	b := ParseSemver(baseline)
	maxLen := len(c)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	for len(c) < maxLen {
		c = append(c, 0)
	}
	for len(b) < maxLen {
		b = append(b, 0)
	}
	for i := 0; i < maxLen; i++ {
		if c[i] != b[i] {
			return c[i] > b[i]
		}
	}
	return false
}

// VersionInfo 版本探测结果（对齐 dataclass VersionInfo）。
type VersionInfo struct {
	Version      string  `json:"version"`
	ReleaseDate  string  `json:"release_date"`
	ReleaseName  string  `json:"release_name"`
	ReleaseNotes string  `json:"release_notes"`
	CheckedAt    float64 `json:"checked_at"`
}

// VersionInfoFromDict 对齐 VersionInfo.from_dict。
func VersionInfoFromDict(data map[string]any) VersionInfo {
	info := VersionInfo{}
	if v, ok := data["version"].(string); ok {
		info.Version = v
	}
	if v, ok := data["release_date"].(string); ok {
		info.ReleaseDate = v
	}
	if v, ok := data["release_name"].(string); ok {
		info.ReleaseName = v
	}
	if v, ok := data["release_notes"].(string); ok {
		info.ReleaseNotes = v
	}
	if f, ok := AsFloat(data["checked_at"]); ok {
		info.CheckedAt = f
	}
	return info
}

// ToDict 对齐 to_dict。
func (v VersionInfo) ToDict() map[string]any {
	return map[string]any{
		"version":       v.Version,
		"release_date":  v.ReleaseDate,
		"release_name":  v.ReleaseName,
		"release_notes": v.ReleaseNotes,
		"checked_at":    v.CheckedAt,
	}
}

// ParseManifest 解析官方 electron manifest (YAML) 内容。
//
// YAML 1.1 陷阱：`version: 3.10` 会被解析成 float 3.1，str() 后
// 版本号被截断（3.10 → "3.1"，比较时 (3,1) < (3,17,1) 永远判旧）。解析结果
// 非字符串时回退用正则从原始文本提取字面量（2026-11-04 review 实证）。
// Go yaml.v3（YAML 1.2 core schema）对 `3.10` 同样解出 float64(3.1)，陷阱保留。
func ParseManifest(text string) *VersionInfo {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	var data map[string]any
	if err := yaml.Unmarshal([]byte(text), &data); err != nil {
		return nil
	}
	if data == nil {
		return nil
	}
	verRaw := data["version"]
	ver := strings.TrimSpace(StrValue(verRaw))
	if ver == "" {
		return nil
	}
	if _, isStr := verRaw.(string); !isStr {
		// 回退正则提取字面量
		re := regexp.MustCompile(`(?m)^version:\s*['"]?([0-9A-Za.\-+]+)`)
		if m := re.FindStringSubmatch(text); m != nil {
			ver = strings.TrimSpace(m[1])
		}
	}

	releaseDate := strings.TrimSpace(StrValue(data["releaseDate"]))
	releaseName := strings.TrimSpace(StrValue(data["releaseName"]))
	if releaseName == "" {
		releaseName = "Release v" + ver
	}

	// 优先抽取中文更新日志，其次 fallback 主 releaseNotes 或英文
	locales, _ := data["releaseNotesByLocale"].(map[string]any)
	notes := ""
	if locales != nil {
		zh, _ := locales["zh-CN"].(map[string]any)
		if zh != nil {
			if md, ok := zh["markdown"].(string); ok && md != "" {
				notes = strings.TrimSpace(md)
			}
		} else if zhStr, ok := locales["zh-CN"].(string); ok {
			notes = strings.TrimSpace(zhStr)
		}
	}
	if notes == "" {
		if rn, ok := data["releaseNotes"].(string); ok && strings.TrimSpace(rn) != "" {
			notes = strings.TrimSpace(rn)
		}
	}
	if notes == "" && locales != nil {
		if en, ok := locales["en-US"].(map[string]any); ok {
			if md, ok := en["markdown"].(string); ok && md != "" {
				notes = strings.TrimSpace(md)
			}
		}
	}
	return &VersionInfo{
		Version:      ver,
		ReleaseDate:  releaseDate,
		ReleaseName:  releaseName,
		ReleaseNotes: notes,
		CheckedAt:    NowFloat(),
	}
}

// VersionTracker 版本追踪器（对齐 class VersionTracker）。
//
// 结果新鲜窗口（秒）：窗口内复用上次核验结果，避免领套餐前置核验、
// 后台 12h 轮、管理后台手动核验三个触发源并发时重复打上游。
const versionFreshWindow = 300

type VersionTracker struct {
	mu          sync.Mutex
	LatestInfo  *VersionInfo
	stopCh      chan struct{}
	done        chan struct{}
	lastResult  map[string]any
	lastChecked float64
	checkLock   sync.Mutex
}

// DefaultVersionTracker 全局单例（对齐 version_tracker = VersionTracker()）。
var DefaultVersionTracker = &VersionTracker{}

// InitFromStore 启动阶段从 store 恢复之前探测到的最新版本。
func (t *VersionTracker) InitFromStore() {
	t.mu.Lock()
	defer t.mu.Unlock()
	storedVer := strings.TrimSpace(fmt.Sprintf("%v", DefaultStore.GetSetting("zcode_latest_version", "")))
	rawInfo := strings.TrimSpace(fmt.Sprintf("%v", DefaultStore.GetSetting("zcode_latest_info", "")))
	if rawInfo == "<nil>" {
		rawInfo = ""
	}
	if rawInfo != "" {
		if v, err := JSONDecode(rawInfo); err == nil {
			if dict, ok := v.(map[string]any); ok {
				info := VersionInfoFromDict(dict)
				t.LatestInfo = &info
			}
		}
	}
	autoSyncRaw := fmt.Sprintf("%v", DefaultStore.GetSetting("auto_sync_client_version",
		strings.ToLower(strconv.FormatBool(AUTO_SYNC_CLIENT_VERSION))))
	autoSync := autoSyncRaw == "true"
	if autoSync && storedVer != "" && storedVer != "<nil>" &&
		IsNewerVersion(storedVer, ClientAppVersion()) {
		SetActiveVersion(storedVer)
		LogInfo("version", fmt.Sprintf("恢复已同步的 ZCode 官方版本: v%s", storedVer))
	}
}

// FetchRemoteManifest 向上游请求最新 manifest。
//
// trust_env=False 直连 + 官方同形 UA（2.7.16 review 修复）：自定义 UA
//（原 ZCode-Hub-Tracker）等于向上游 WAF 自报非官方代理身份；且 hub 进程
// env 代理（127.0.0.1:10822）2026-11-04 实测完全超时（15s HTTP 000），
// 直连才是可用出口——与 claim/billing 链路同出口策略。
func (t *VersionTracker) FetchRemoteManifest() *VersionInfo {
	client := &http.Client{Timeout: 15 * time.Second, Transport: directTransport()}
	req, err := http.NewRequest(http.MethodGet, ZCODE_MANIFEST_URL, nil)
	if err != nil {
		LogWarn("version", fmt.Sprintf("查询官方版本 manifest 异常: %v", err))
		return nil
	}
	req.Header.Set("User-Agent", SettingsUserAgent())
	req.Header.Set("Accept", "application/x-yaml,text/yaml,text/plain,*/*")
	res, err := client.Do(req)
	if err != nil {
		LogWarn("version", fmt.Sprintf("查询官方版本 manifest 异常: %v", err))
		return nil
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		LogWarn("version", fmt.Sprintf("查询官方版本 manifest 失败: HTTP %d", res.StatusCode))
		return nil
	}
	body, _ := io.ReadAll(res.Body)
	return ParseManifest(string(body))
}

// freshResult 新鲜窗口内的缓存结果；过期/从未核验返回 nil。
func (t *VersionTracker) freshResult() map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.lastResult != nil && NowFloat()-t.lastChecked < versionFreshWindow {
		return t.lastResult
	}
	return nil
}

// CheckAndSync 执行一次版本探测与同步。
//
// force=false 默认带新鲜度防抖（_FRESH_WINDOW 内直接复用上次结果）；
// force=true 跳过缓存强制拉取（管理后台「立即核验」语义）。并发调用
// 由锁串行化，锁内二次校验新鲜度（double-checked）。
func (t *VersionTracker) CheckAndSync(force bool) error {
	if !force {
		if cached := t.freshResult(); cached != nil {
			return nil
		}
	}
	t.checkLock.Lock()
	defer t.checkLock.Unlock()
	if !force {
		if cached := t.freshResult(); cached != nil {
			return nil
		}
	}
	result := t.checkOnce()
	t.mu.Lock()
	t.lastResult = result
	t.lastChecked = NowFloat()
	t.mu.Unlock()
	return nil
}

// checkOnce 真正的探测与同步（调用方须持锁）。
func (t *VersionTracker) checkOnce() map[string]any {
	info := t.FetchRemoteManifest()
	if info == nil {
		currentVer := ClientAppVersion()
		latestVer := currentVer
		releaseDate, releaseName, releaseNotes := "", "", ""
		var checkedAt float64
		t.mu.Lock()
		if t.LatestInfo != nil {
			latestVer = t.LatestInfo.Version
			releaseDate = t.LatestInfo.ReleaseDate
			releaseName = t.LatestInfo.ReleaseName
			releaseNotes = t.LatestInfo.ReleaseNotes
			checkedAt = t.LatestInfo.CheckedAt
		}
		t.mu.Unlock()
		return map[string]any{
			"ok":              false,
			"current_version": currentVer,
			"latest_version":  latestVer,
			"has_update":      IsNewerVersion(latestVer, currentVer),
			"updated":         false,
			"release_date":    releaseDate,
			"release_name":    releaseName,
			"release_notes":   releaseNotes,
			"checked_at":      checkedAt,
		}
	}

	t.mu.Lock()
	t.LatestInfo = info
	t.mu.Unlock()
	DefaultStore.SetSetting("zcode_latest_version", info.Version)
	if raw, err := JSONMarshalCompact(info.ToDict()); err == nil {
		DefaultStore.SetSetting("zcode_latest_info", string(raw))
	}

	currentVer := ClientAppVersion()
	autoSyncRaw := fmt.Sprintf("%v", DefaultStore.GetSetting("auto_sync_client_version",
		strings.ToLower(strconv.FormatBool(AUTO_SYNC_CLIENT_VERSION))))
	autoSync := autoSyncRaw == "true"
	hasNew := IsNewerVersion(info.Version, currentVer)
	updated := false

	if hasNew {
		if autoSync {
			SetActiveVersion(info.Version)
			updated = true
			LogOK("version", fmt.Sprintf("检测到 ZCode 官方发版 %s（当前 %s），已自动对齐伪装指纹",
				info.Version, currentVer))
		} else {
			LogInfo("version", fmt.Sprintf("检测到 ZCode 官方新版 %s（当前 %s，未开启自动对齐）",
				info.Version, currentVer))
		}
	} else {
		LogInfo("version", fmt.Sprintf("ZCode 官方版本核验: 当前 v%s，最新 v%s（已是对齐状态）",
			currentVer, info.Version))
	}

	return map[string]any{
		"ok":              true,
		"current_version": ClientAppVersion(),
		"latest_version":  info.Version,
		"has_update":      hasNew,
		"updated":         updated,
		"release_date":    info.ReleaseDate,
		"release_name":    info.ReleaseName,
		"release_notes":   info.ReleaseNotes,
		"checked_at":      info.CheckedAt,
	}
}

// Start 对齐 version_tracker.start()。
func (t *VersionTracker) Start() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopCh != nil {
		return
	}
	t.stopCh = make(chan struct{})
	t.done = make(chan struct{})
	go t.loop()
}

func (t *VersionTracker) loop() {
	defer close(t.done)
	// 启动后先等待 5 秒，避开其他模块初始启动流量
	select {
	case <-t.stopCh:
		return
	case <-time.After(5 * time.Second):
	}
	for {
		// 常驻任务必须自兜：单次探测异常（SQLite 抖动/持久化失败等）不得
		// 杀死轮询协程，否则自动感知静默失效直到重启（对齐 claim/quota 轮）
		func() {
			defer func() {
				if r := recover(); r != nil {
					LogErr("version", fmt.Sprintf("版本检测循环异常（下轮自动重试）: %v", r))
				}
			}()
			if err := t.CheckAndSync(false); err != nil {
				LogErr("version", fmt.Sprintf("版本检测循环异常（下轮自动重试）: %v", err))
			}
		}()
		interval := VERSION_CHECK_INTERVAL
		if interval < 60 {
			interval = 60
		}
		select {
		case <-t.stopCh:
			return
		case <-time.After(time.Duration(interval) * time.Second):
		}
	}
}

// Stop 对齐 async stop()。
func (t *VersionTracker) Stop() {
	t.mu.Lock()
	if t.stopCh == nil {
		t.mu.Unlock()
		return
	}
	stop := t.stopCh
	done := t.done
	t.stopCh = nil
	t.mu.Unlock()
	close(stop)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}

// LatestVersionSnapshot 供管理后台读取（admin_api GET /settings 用）。
func (t *VersionTracker) LatestVersionSnapshot() *VersionInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.LatestInfo
}

// LastResult 返回最近一次 CheckAndSync 的结果（对齐 Python check_and_sync 直接返回 dict；
// Go 版把结果缓存于此供路由层取用）。
func (t *VersionTracker) LastResult() map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.lastResult != nil {
		out := map[string]any{}
		for k, v := range t.lastResult {
			out[k] = v
		}
		return out
	}
	// 从未核验过：返回与 _check_once 无 info 相同的兜底形态
	currentVer := ClientAppVersion()
	latestVer := currentVer
	releaseDate, releaseName, releaseNotes := "", "", ""
	var checkedAt float64
	if t.LatestInfo != nil {
		latestVer = t.LatestInfo.Version
		releaseDate = t.LatestInfo.ReleaseDate
		releaseName = t.LatestInfo.ReleaseName
		releaseNotes = t.LatestInfo.ReleaseNotes
		checkedAt = t.LatestInfo.CheckedAt
	}
	return map[string]any{
		"ok":              false,
		"current_version": currentVer,
		"latest_version":  latestVer,
		"has_update":      IsNewerVersion(latestVer, currentVer),
		"updated":         false,
		"release_date":    releaseDate,
		"release_name":    releaseName,
		"release_notes":   releaseNotes,
		"checked_at":      checkedAt,
	}
}

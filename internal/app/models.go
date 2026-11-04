// 账号数据模型与状态枚举。
//
// 对齐 Python app/models.py：dataclass Account → Go struct（JSON 字段名逐一对齐，
// 保证 data/accounts.db 的 data 列与 Python 版互相兼容）；全部判定方法
// （uses_plan_channel / allows_billing / quota_expired / is_selectable / is_cooling /
// risk_penalty / plan_kind / public_view / effective_status …）逐个移植。
package app

import (
	"encoding/json"
	"strings"
	"time"
	"unicode"

	"github.com/zhaoboy9692/zcode2api-go/internal/uuidx"
)

// Providers 对齐 PROVIDERS = ("zai", "bigmodel")。
func Providers() []string { return []string{"zai", "bigmodel"} }

// IsProvider 判断 provider 是否在 PROVIDERS 内。
func IsProvider(p string) bool { return p == "zai" || p == "bigmodel" }

// 账号运行状态（对齐 class Status）。
const (
	StatusActive    = "active"    // 正常，可参与轮询
	StatusExhausted = "exhausted" // 额度用完
	StatusCooling   = "cooling"   // 临时限流（冷却中）
	StatusInvalid   = "invalid"   // 凭证失效 / 鉴权失败
	StatusDisabled  = "disabled"  // 手动禁用
)

// ExpiresEpoch 把上游 `expires_at` 归一成 epoch 秒。
//
// 两种形态都出现过：线上 accounts.db 里是 **epoch 秒**（如 1793375999），
// mock 与部分快照里是 **ISO8601 字符串**（`"2026-01-01T00:00:00Z"`）。原实现
// 从不解析该字段（只看 remaining），所以「过期」从未被判过；写入归一函数后
// 两种形态都能安全比较。兼容：epoch 秒、epoch 毫秒、ISO8601（带 Z / 偏移 /
// 无时区按 UTC / 纯日期）、空值。
//
// Go 返回 (epoch, ok)；ok=false 对齐 Python None。
func ExpiresEpoch(value any) (float64, bool) {
	switch v := value.(type) {
	case nil, bool:
		return 0, false
	case int:
		return normalizeEpoch(float64(v)), true
	case int64:
		return normalizeEpoch(float64(v)), true
	case float64:
		return normalizeEpoch(v), true
	case jsonNum:
		f, err := v.Float64()
		if err != nil {
			return 0, false
		}
		return normalizeEpoch(f), true
	case string:
		text := strings.TrimSpace(v)
		if text == "" {
			return 0, false
		}
		// 纯数字字符串（含小数）
		if f, err := parsePyFloat(text); err == nil {
			return normalizeEpoch(f), true
		}
		// ISO8601：Python datetime.fromisoformat(text.replace("Z", "+00:00"))
		parsed, err := parseISO8601(text)
		if err != nil {
			return 0, false
		}
		return float64(parsed.Unix()) + float64(parsed.Nanosecond())/1e9, true
	default:
		return 0, false
	}
}

func normalizeEpoch(number float64) float64 {
	if number <= 0 {
		return 0
	}
	if number > 1e11 {
		return number / 1000.0 // 毫秒时间戳
	}
	return number
}

// jsonNum 是 encoding/json json.Number 的别名（UseNumber 解析产物）。
type jsonNum = json.Number

// parsePyFloat 对齐 float(text)（十进制，可带指数）。
func parsePyFloat(text string) (float64, error) {
	return strconvParseFloat(text)
}

// WindowUsable 额度窗口是否还有效：剩余 > 0 **且**未过期。
//
// `remaining` 缺失视为「未知但有量」（上游有的窗口只给 total/used）；
// `expires_at` 缺失/无法解析视为不过期（一次性/永久池）。
func WindowUsable(window map[string]any, now float64) bool {
	if window == nil || len(window) == 0 {
		return false
	}
	if remaining, has := window["remaining"]; has && remaining != nil {
		// Python: remaining is not None and (remaining or 0) <= 0
		if f, ok := AsFloat(remaining); ok && f <= 0 {
			return false
		}
	}
	expiresAt, ok := ExpiresEpoch(window["expires_at"])
	return !ok || expiresAt > now
}

// WindowExpired 窗口是否已过有效期（只看 expires_at；无/不可解析 = 不过期）。
func WindowExpired(window map[string]any, now float64) bool {
	if window == nil {
		return false
	}
	expiresAt, ok := ExpiresEpoch(window["expires_at"])
	return ok && expiresAt <= now
}

// accountID 对齐 _account_id(name)。
func accountID(name string) string {
	src := name
	if src == "" {
		src = "account"
	}
	var b strings.Builder
	for _, c := range strings.ToLower(src) {
		if unicode.IsLetter(c) || unicode.IsDigit(c) {
			b.WriteRune(c)
		} else {
			b.WriteByte('-')
		}
	}
	safe := strings.Trim(b.String(), "-")
	if len(safe) > 32 {
		// Python safe[:32] 按码点；此时 safe 全是 ASCII alnum 与 '-'，按字节即按码点
		safe = safe[:32]
	}
	if safe == "" {
		safe = "account"
	}
	return safe + "-" + uuidx.HexToken(4)
}

// Account 单个可轮询的账号凭证 + 运行时状态。
//
// JSON 标签逐字段对齐 Python dataclass 字段名（asdict 落库形态）。
type Account struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
	Mode     string `json:"mode"` // "jwt" | "apiKey"

	JWTToken string `json:"jwt_token"`
	APIKey   string `json:"api_key"`
	Enabled  bool   `json:"enabled"`
	Status   string `json:"status"`

	// 额度快照：{ model_show_name: {total, used, remaining, expires_at} }
	Quota map[string]any `json:"quota"`
	Plan  map[string]any `json:"plan"`  // 当前激活方案（billing/current plans[0]，兼容保留）
	Plans []any          `json:"plans"` // 全部方案（上游 plans 数组；多套餐时 entitlements 不丢）
	Usage map[string]any `json:"usage"` // 近期用量原始数据

	UseCount      int      `json:"use_count"`
	FailCount     int      `json:"fail_count"`
	RiskStrikes   int      `json:"risk_strikes"`   // 当前风控退避周期内累计命中次数；成功或跨衰减窗口即清零
	LastRiskAt    *float64 `json:"last_risk_at"`   // 最近一次风控命中时间（strikes 衰减窗口基准）
	RecentResults []any    `json:"recent_results"` // 最近请求结果 tick（True 成功/False 失败），最新在末尾
	LastUsedAt    *float64 `json:"last_used_at"`
	LastCheckedAt *float64 `json:"last_checked_at"`
	// 额度快照的「可信时间」：只在 billing/balance **成功取到数据**、quota 被真正
	// 写过的那一刻更新。与 last_checked_at（含失败/去抖，仅用于节流）区分开——
	// 过期判定只认这个（见 quota_expired：过期后还没成功查过 = 未知，不封号）。
	QuotaVerifiedAt *float64 `json:"quota_verified_at"`
	CoolingUntil    *float64 `json:"cooling_until"`
	LastError       string   `json:"last_error"`
	CreatedAt       float64  `json:"created_at"`
	// 每账号客户端指纹（fingerprint.DeviceProfile；落库为 dict，取用时还原）
	Fingerprint map[string]any `json:"fingerprint"`
	// 安装身份：入池分配的稳定安装令牌（hub 内部，跨账号不重复，导出时剥离）
	InstallID   string   `json:"install_id"`
	InstalledAt *float64 `json:"installed_at"` // 按账号安装序完成时间；nil = 未安装
	// 出站代理（账号级）：空 = 跟随全局 ZCODE_UPSTREAM_PROXY，再退 env/直连。
	// 形态 http(s)://user:pass@host:port / socks5(h)://user:pass@host:port；
	// 验证码 token 按此代理的出口隔离签发（见 captcha.go 出口标签）。
	Proxy string `json:"proxy"`
	// Coding 平面额度快照（monitor 端点，见 quota.go FetchCodingLimits）：
	// {items:[{name,window,total,used,remaining,pct,reset}], tier, expire, refreshed_at}
	CodingLimits map[string]any `json:"coding_limits"`
	// 平台 OAuth token（oauth:{provider}:access_token 的解密形态）：仅用于
	// /coding-plan/reset/status 的 X-Bigmodel-Authorization 头；不对外回显
	PlatformToken string `json:"platform_token"`
	// 网关并发上限（账号级，可单独设置）：≥1 = 上限；0 = 不限；缺省 1
	Concurrency int `json:"concurrency"`
}

// AccountCreate 对齐 Account.create(provider, name, secret)。
func AccountCreate(provider, name, secret string) *Account {
	secret = strings.TrimSpace(secret)
	isJWT := strings.Count(secret, ".") == 2 && provider == "zai"
	acc := &Account{
		ID:            accountID(name),
		Provider:      provider,
		Mode:          "apiKey",
		Enabled:       true,
		Status:        StatusActive,
		Concurrency:   1,
		Quota:         map[string]any{},
		Plan:          map[string]any{},
		Plans:         []any{},
		Usage:         map[string]any{},
		RecentResults: []any{},
		CreatedAt:     NowFloat(),
	}
	if name != "" {
		acc.Name = name
	} else {
		acc.Name = provider + "-account"
	}
	if isJWT {
		acc.Mode = "jwt"
		acc.JWTToken = secret
	} else {
		acc.APIKey = secret
	}
	return acc
}

// Secret 对齐 .secret 属性。
func (a *Account) Secret() string {
	if a.Mode == "jwt" {
		return a.JWTToken
	}
	return a.APIKey
}

// RiskPenalty 命中风控（3012/405「unusual activity」）：指数退避冷却，累计
// ban_strikes 次才升级为禁用（人工确认恢复）。
//
// 实测（2026-10-01）上游对 messages 端点的 3012 是频道级瞬时频控：
// 同号同刻 billing 全部正常、数小时自愈——硬禁用会让健康的 billing/claim
// 陪葬（领取轮两度因此停摆）。冷却自动恢复且冷却期零上游流量
// （is_cooling 全通道门禁），既避免对真封禁账号持续施压，也不拖死领取轮。
//
// strikes 仅在 decay_seconds 窗口内累计：距上次命中超过窗口视为无关的
// 新事件，重新起算——避免跨月偶发命中累积成禁用。Plan 通道成功（gateway
// 成功分支）或窗口衰减都会清零。
func (a *Account) RiskPenalty(base, cap float64, banStrikes int, decaySeconds float64) {
	now := NowFloat()
	if a.LastRiskAt != nil && now-*a.LastRiskAt > decaySeconds {
		a.RiskStrikes = 0
	}
	a.RiskStrikes++
	last := now
	a.LastRiskAt = &last
	if a.RiskStrikes >= banStrikes {
		a.Status = StatusDisabled
		a.CoolingUntil = nil
		return
	}
	a.Status = StatusCooling
	until := now + minFloat(base*pow2(a.RiskStrikes-1), cap)
	a.CoolingUntil = &until
}

// pow2 对齐 2 ** n（n ≥ 0）。
func pow2(n int) float64 {
	r := 1.0
	for i := 0; i < n; i++ {
		r *= 2
	}
	return r
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// HasApikeyFallback 同账号是否持有可走 api.z.ai 的 API Key（JWT 死后的对话回退）。
//
// 仅 JWT 账号的附加 Key 算回退；纯 apiKey 账号的主键不是 fallback，
// 风控/失效后不得靠这把 Key 继续被选中。
func (a *Account) HasApikeyFallback() bool {
	return a.Mode == "jwt" && strings.TrimSpace(a.APIKey) != ""
}

// UsesPlanChannel 当前是否允许走 Coding Plan JWT 通道（messages + billing）。
//
// invalid / 风控 disabled / 手动停用 都视为 JWT 不可用；有 Key 时对话
// 走回退通道，但 billing/claim 仍必须停（Key 通道没有套餐领取）。
func (a *Account) UsesPlanChannel() bool {
	if a.Mode != "jwt" || strings.TrimSpace(a.JWTToken) == "" {
		return false
	}
	if !a.Enabled {
		return false
	}
	return a.Status != StatusInvalid && a.Status != StatusDisabled
}

// AllowsBilling 是否允许打 billing 全家桶（preview/claim/current/balance/usage）。
func (a *Account) AllowsBilling(now float64) bool {
	return a.UsesPlanChannel() && !a.IsCooling(now)
}

// QuotaExpired 权益是否已全部失效（每个额度窗口都「过期」或「剩余为 0」）。
//
// 2026-10-31 线上实证：老号 `GLM-5.3-Flash` 本地记录 `remaining=1e8` 但
// `expires_at=10-03`（28 天前），上游一律回 `{"code":1005,"msg":"exceed
// quota limit"}` —— 只看 remaining 会把过期窗口当可用，等于让每个请求都
// 先撞一次必然失败的 1005。
//
// 口径：`quota` 为空 = **未知**（新号/尚未刷新），不判过期，否则会把可用
// 账号挡在门外；只有取到记录且**每一个**窗口都不可用时才判 true。
//
// 追加口径（2026-11-03）：额度窗口是**滚动日窗**，快照天然会过时——快照若
// 取自最新到期时间**之前**，它没有资格判死。「有余额但全部过期」必须由
// **过期之后的一次成功查询**确认（`quota_verified_at > 最新 expires_at`），
// 否则按未知处理、继续让账号参与轮询。实证：trial 号日窗
// `expires_at=11-02 23:59:59`，11-03 00:39 上游照回 200（新窗到 11-03
// 23:59:59），而本地因 `quota_refresh_interval=0` 永不刷新，旧逻辑把能用的号
// 永久封成 503。反例（要保住的行为）：老号 `expires_at` 在 28 天前、且过期后
// 成功查过 → 仍判过期，不会每次请求先撞一次必然失败的 1005。
func (a *Account) QuotaExpired(now float64) bool {
	if len(a.Quota) == 0 {
		return false
	}
	if now == 0 {
		now = NowFloat()
	}
	anyUsable := false
	for _, w := range a.Quota {
		if wm, ok := w.(map[string]any); ok && WindowUsable(wm, now) {
			anyUsable = true
			break
		}
	}
	if anyUsable {
		return false
	}
	// 余额本身已归零 = 确定耗尽，与快照新旧无关（赠送池由调用方另判）
	anyPositive := false
	for _, w := range a.Quota {
		wm, ok := w.(map[string]any)
		if !ok {
			continue
		}
		if f, ok := AsFloat(wm["remaining"]); ok && f > 0 {
			anyPositive = true
			break
		}
	}
	if !anyPositive {
		return true
	}
	// 有余额、但每个窗口都过了期：可能只是快照停在上一轮日窗 → 需确认
	var ends []float64
	for _, w := range a.Quota {
		wm, ok := w.(map[string]any)
		if !ok {
			continue
		}
		if e, ok := ExpiresEpoch(wm["expires_at"]); ok {
			ends = append(ends, e)
		}
	}
	if len(ends) == 0 {
		return true
	}
	maxEnd := ends[0]
	for _, e := range ends[1:] {
		if e > maxEnd {
			maxEnd = e
		}
	}
	return a.QuotaVerifiedAt != nil && *a.QuotaVerifiedAt > maxEnd
}

// RecordResult 记录单次请求结果明细（后台「最近请求」tick 悬停展示），只保留最近 keep 条。
//
// 条目形如 {"ok": bool, "at": epoch 秒, "detail": 文案}；历史遗留的纯布尔条目
// 由前端兼容渲染。
func (a *Account) RecordResult(ok bool, detail string, keep int) {
	if keep <= 0 {
		keep = 20
	}
	d := detail
	if d == "" {
		if ok {
			d = "成功"
		} else {
			d = "失败"
		}
	}
	entry := map[string]any{"ok": ok, "at": NowFloat(), "detail": d}
	a.RecentResults = append(a.RecentResults, entry)
	if len(a.RecentResults) > keep {
		a.RecentResults = a.RecentResults[len(a.RecentResults)-keep:]
	}
}

// IsSelectable 是否可被轮询选中。
//
// JWT 失效 / 风控禁用后，若同账号有 API Key，仍可选中并走回退通道；
// 手动 enabled=false 永远不选。
//
// 额度快照已判「全部窗口过期/为零」时也不选：这类账号本地看着有余额、
// 上游只会回 1005，选中它等于每次请求都先烧一次必然失败的调用（且会
// 挤掉真正可用的账号的轮询位）。额度未知（空快照）不在此列。
func (a *Account) IsSelectable(now float64) bool {
	if !a.Enabled {
		return false
	}
	if a.Status == StatusInvalid || a.Status == StatusDisabled {
		// 回退通道（api.z.ai + API Key）花的是 Key 自己的额度，与套餐快照无关
		return a.HasApikeyFallback()
	}
	if a.Status == StatusExhausted || a.QuotaExpired(now) {
		return false
	}
	if a.Status == StatusCooling {
		if now == 0 {
			now = NowFloat()
		}
		return a.CoolingUntil != nil && now >= *a.CoolingUntil
	}
	return true
}

// IsCooling 冷却是否仍在生效（含风控指数退避）。冷却期内不应产生任何上游流量。
func (a *Account) IsCooling(now float64) bool {
	if a.Status != StatusCooling {
		return false
	}
	if now == 0 {
		now = NowFloat()
	}
	return a.CoolingUntil != nil && now < *a.CoolingUntil
}

// PlanKind 当前套餐类型：start-plan（体验/免费档）/ coding-plan / ""（未知）。
//
// 上游 plan_id 形如 `zcode-v3-start-plan-0817` / `zcode-v3-coding-plan-…`，
// 取自 billing 的 plans[]（`quota.fetch_quota` 落库到 account.plans）。
// 后台据此区分体验号与付费号；路由/限流如需按套餐分流也从这里取。
func (a *Account) PlanKind() string {
	candidates := []any{a.Plan}
	candidates = append(candidates, a.Plans...)
	for _, c := range candidates {
		plan, ok := c.(map[string]any)
		if !ok {
			continue
		}
		parts := []string{}
		for _, k := range []string{"plan_id", "name", "description"} {
			v := plan[k]
			// Python: str(plan.get(k) or "") —— None 归空串
			s := ""
			if v != nil {
				s = StrValue(v)
			}
			parts = append(parts, strings.ToLower(s))
		}
		blob := strings.Join(parts, " ")
		if strings.Contains(blob, "start-plan") || strings.Contains(blob, "start plan") {
			return "start-plan"
		}
		if strings.Contains(blob, "coding-plan") || strings.Contains(blob, "coding plan") {
			return "coding-plan"
		}
	}
	return ""
}

// ToDict 对齐 asdict(self)：全部字段的 map 形态（落库/返回前端用）。
// 数值统一 float64/int；None 字段以 nil 表达（*float64 nil → nil）。
func (a *Account) ToDict() map[string]any {
	return map[string]any{
		"id":                a.ID,
		"name":              a.Name,
		"provider":          a.Provider,
		"mode":              a.Mode,
		"jwt_token":         strOrNil(a.JWTToken),
		"api_key":           strOrNil(a.APIKey),
		"enabled":           a.Enabled,
		"status":            a.Status,
		"quota":             dictOrNil(a.Quota),
		"plan":              dictOrNil(a.Plan),
		"plans":             listOrNil(a.Plans),
		"usage":             dictOrNil(a.Usage),
		"use_count":         a.UseCount,
		"fail_count":        a.FailCount,
		"risk_strikes":      a.RiskStrikes,
		"last_risk_at":      fOrNil(a.LastRiskAt),
		"recent_results":    listOrNil(a.RecentResults),
		"last_used_at":      fOrNil(a.LastUsedAt),
		"last_checked_at":   fOrNil(a.LastCheckedAt),
		"quota_verified_at": fOrNil(a.QuotaVerifiedAt),
		"cooling_until":     fOrNil(a.CoolingUntil),
		"last_error":        strOrNil(a.LastError),
		"created_at":        a.CreatedAt,
		"fingerprint":       dictOrNil(a.Fingerprint),
		"install_id":        strOrNil(a.InstallID),
		"installed_at":      fOrNil(a.InstalledAt),
		"proxy":             strOrNil(a.Proxy),
		"coding_limits":     dictOrNil(a.CodingLimits),
		"platform_token":    strOrNil(a.PlatformToken),
		"concurrency":       a.Concurrency,
	}
}

func strOrNil(s string) any {
	if s == "" {
		return nil // 对齐 Python None
	}
	return s
}

func dictOrNil(m map[string]any) any {
	if m == nil {
		return nil
	}
	return m
}

func listOrNil(l []any) any {
	if l == nil {
		return nil
	}
	return l
}

func fOrNil(p *float64) any {
	if p == nil {
		return nil
	}
	return *p
}

// AccountFromDict 对齐 Account.from_dict(data)：仅取已知字段，未知字段忽略。
// 输入为 UseNumber 解析产物；None/缺失字段保持零值。
func AccountFromDict(data map[string]any) *Account {
	a := &Account{
		Quota:         map[string]any{},
		Plan:          map[string]any{},
		Plans:         []any{},
		Usage:         map[string]any{},
		RecentResults: []any{},
	}
	if v, ok := data["id"].(string); ok {
		a.ID = v
	}
	if v, ok := data["name"].(string); ok {
		a.Name = v
	}
	if v, ok := data["provider"].(string); ok {
		a.Provider = v
	}
	if v, ok := data["mode"].(string); ok {
		a.Mode = v
	}
	if v, ok := data["jwt_token"].(string); ok {
		a.JWTToken = v
	}
	if v, ok := data["api_key"].(string); ok {
		a.APIKey = v
	}
	if v, ok := data["enabled"].(bool); ok {
		a.Enabled = v
	} else {
		a.Enabled = true
	}
	if v, ok := data["status"].(string); ok {
		a.Status = v
	} else {
		a.Status = StatusActive
	}
	if v, ok := data["quota"].(map[string]any); ok && v != nil {
		a.Quota = v
	}
	if v, ok := data["plan"].(map[string]any); ok && v != nil {
		a.Plan = v
	}
	if v, ok := data["plans"].([]any); ok && v != nil {
		a.Plans = v
	}
	if v, ok := data["usage"].(map[string]any); ok && v != nil {
		a.Usage = v
	}
	if v, ok := AsInt(data["use_count"]); ok {
		a.UseCount = v
	}
	if v, ok := AsInt(data["fail_count"]); ok {
		a.FailCount = v
	}
	if v, ok := AsInt(data["risk_strikes"]); ok {
		a.RiskStrikes = v
	}
	a.LastRiskAt = floatPtr(data["last_risk_at"])
	if v, ok := data["recent_results"].([]any); ok && v != nil {
		a.RecentResults = v
	}
	a.LastUsedAt = floatPtr(data["last_used_at"])
	a.LastCheckedAt = floatPtr(data["last_checked_at"])
	a.QuotaVerifiedAt = floatPtr(data["quota_verified_at"])
	a.CoolingUntil = floatPtr(data["cooling_until"])
	if v, ok := data["last_error"].(string); ok {
		a.LastError = v
	}
	if v, ok := AsFloat(data["created_at"]); ok {
		a.CreatedAt = v
	} else {
		a.CreatedAt = NowFloat()
	}
	if v, ok := data["fingerprint"].(map[string]any); ok && v != nil {
		a.Fingerprint = v
	}
	if v, ok := data["install_id"].(string); ok {
		a.InstallID = v
	}
	a.InstalledAt = floatPtr(data["installed_at"])
	if v, ok := data["proxy"].(string); ok {
		a.Proxy = strings.TrimSpace(v)
	}
	if v, ok := data["coding_limits"].(map[string]any); ok && v != nil {
		a.CodingLimits = v
	}
	if v, ok := data["platform_token"].(string); ok {
		a.PlatformToken = v
	}
	// 并发上限：旧数据缺字段 → 默认 1；显式 0 = 不限
	if v, ok := AsInt(data["concurrency"]); ok {
		a.Concurrency = v
	} else {
		a.Concurrency = 1
	}
	return a
}

func floatPtr(v any) *float64 {
	if v == nil {
		return nil
	}
	if f, ok := AsFloat(v); ok {
		return &f
	}
	return nil
}

// FingerprintView 指纹的对外形态（dict）；未分配/半初始化返回 nil。
func (a *Account) FingerprintView() map[string]any {
	fp := a.Fingerprint
	if fp != nil {
		if _, has := fp["device_mid"]; has {
			return fp
		}
	}
	return nil
}

// PublicView 返回给前端的视图（脱敏 token）。
func (a *Account) PublicView() map[string]any {
	secret := a.Secret()
	masked := secret
	if len(secret) > 16 {
		masked = secret[:8] + "…" + secret[len(secret)-6:]
	}
	return map[string]any{
		"id":                a.ID,
		"name":              a.Name,
		"provider":          a.Provider,
		"mode":              a.Mode,
		"token_masked":      masked,
		"enabled":           a.Enabled,
		"status":            a.EffectiveStatus(0),
		"quota":             dictOrNil(a.Quota),
		"plan":              dictOrNil(a.Plan),
		"plans":             listOrNil(a.Plans),
		"plan_kind":         a.PlanKind(),
		"use_count":         a.UseCount,
		"fail_count":        a.FailCount,
		"risk_strikes":      a.RiskStrikes,
		"recent_results":    listOrNil(a.RecentResults),
		"last_used_at":      fOrNil(a.LastUsedAt),
		"last_checked_at":   fOrNil(a.LastCheckedAt),
		"quota_verified_at": fOrNil(a.QuotaVerifiedAt),
		// 轮询是否会选中它（额度判死/冷却/停用都在这里体现）：后台排障时
		// 「状态 active 但不发请求」最常见的原因就是这一项为 false
		"selectable":    a.IsSelectable(0),
		"cooling_until": fOrNil(a.CoolingUntil),
		"last_error":    strOrNil(a.LastError),
		"created_at":    a.CreatedAt,
		"fingerprint": func() any {
			if v := a.FingerprintView(); v != nil {
				return v
			}
			return nil
		}(),
		"install_id":   strOrNil(a.InstallID),
		"installed_at": fOrNil(a.InstalledAt),
		// 出站代理回显（用户自填配置，非上游凭证，不脱敏；前端折叠框编辑用）
		"proxy": strOrNil(a.Proxy),
		// Coding 平面额度快照（monitor 端点；bigmodel 账号的主账本）
		"coding":      dictOrNil(a.CodingLimits),
		"concurrency": a.Concurrency,
	}
}

// EffectiveStatus 考虑冷却到期后的实时状态。
func (a *Account) EffectiveStatus(now float64) string {
	if a.Status == StatusCooling {
		if now == 0 {
			now = NowFloat()
		}
		if a.CoolingUntil != nil && now >= *a.CoolingUntil {
			return StatusActive
		}
	}
	return a.Status
}

// NowFloat time.time() 等价（epoch 秒，含小数）。
func NowFloat() float64 {
	return float64(time.Now().UnixNano()) / 1e9
}

// TimeNowPtr 当前 epoch 秒指针。
func TimeNowPtr() *float64 {
	v := NowFloat()
	return &v
}

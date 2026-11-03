// 套餐领取（Z.AI billing/preview + billing/claim）。
//
// 链路与 zcode-switch claim.rs 同形：
//  1. GET  {BILLING_BASE}/billing/preview?app_version=&platform= → data.plans[]
//  2. 领取需阿里云无痕验证码：CaptchaManager 服务端求解 → X-Aliyun-Captcha-Verify-Param
//  3. POST {BILLING_BASE}/billing/claim  body {"plan_id":...}（+ 可选 Verify-Region 头）
//
// 上游业务码语义（沿用 zcode-switch 映射）：1001 套餐不存在 / 1002 活动结束 /
// 1003 已领取过 / 1004 不符合条件 / 1005 今日名额用完 / 3001 参数错误 /
// 3007 验证码失败（换验证码重试一次）/ 401 未登录。
//
// 对齐 Python app/claim.py。
package app

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ClaimError 业务失败（含上游 code 语义），message 面向用户。
//
// NextAt 仅 1005（名额用完）携带：上游 data.plan.ends_at（秒 → 毫秒），
// 即名额恢复时间（zcode-switch claim.rs claim_error 同形）。
type ClaimError struct {
	Message string
	Code    int
	NextAt  *int64
}

func (e *ClaimError) Error() string { return e.Message }

// AuthExpiredMessage 对齐 AUTH_EXPIRED_MESSAGE。
const AuthExpiredMessage = "凭证失效，请重新授权"

var claimFailText = map[int]string{
	1001: "套餐不存在",
	1002: "活动已结束或套餐暂不可领取",
	1003: "该套餐已经领取过",
	1004: "不符合领取条件",
	1005: "今日领取名额已用完",
	3001: "领取参数错误，请刷新后重试",
	3007: "验证码校验失败，请重试",
	401:  "请先登录后再领取",
}

// BillingBlockReason JWT 不可打 billing 时的用户文案；可打则返回 ""。
func BillingBlockReason(account *Account, action string) string {
	if account.IsCooling(0) {
		return fmt.Sprintf("账号冷却中（风控/限流），已跳过%s", action)
	}
	if account.Mode != "jwt" || strings.TrimSpace(account.JWTToken) == "" {
		return fmt.Sprintf("非 Coding Plan 账号，已跳过%s", action)
	}
	if !account.Enabled {
		return fmt.Sprintf("账号已停用，已跳过%s", action)
	}
	if account.Status == StatusDisabled {
		return "账号风控封禁，已跳过" + action
	}
	if account.Status == StatusInvalid || !account.UsesPlanChannel() {
		return AuthExpiredMessage
	}
	return ""
}

// markAuthFailure 对齐 _mark_auth_failure。
func markAuthFailure(account *Account) {
	live := DefaultStore.Find(account.Provider, account.ID)
	if live == nil {
		return
	}
	live.Status = StatusInvalid
	live.LastError = AuthExpiredMessage
	DefaultStore.UpdateAccount(live)
	account.Status = live.Status
	account.LastError = live.LastError
}

// failError 业务码 → ClaimError；1005 附带名额恢复时间（data.plan.ends_at 秒 → 毫秒）。
func failError(code int, body map[string]any) *ClaimError {
	base, ok := claimFailText[code]
	if !ok {
		base = "领取失败"
	}
	server := DictGetStr(body, "msg", "")
	if server == "" {
		server = DictGetStr(body, "message", "")
	}
	message := base
	if server != "" {
		message = fmt.Sprintf("%s（%s）", base, server)
	}
	var nextAt *int64
	if code == 1005 {
		data, _ := body["data"].(map[string]any)
		if data != nil {
			plan, _ := data["plan"].(map[string]any)
			if plan != nil {
				if ends, ok := AsFloat(plan["ends_at"]); ok && ends > 0 {
					v := int64(ends * 1000)
					nextAt = &v
				}
			}
		}
	}
	return &ClaimError{Message: message, Code: code, NextAt: nextAt}
}

// claimBusinessCode 对齐 _business_code(body)。
func claimBusinessCode(body map[string]any) int {
	v, has := body["code"]
	if !has || v == nil {
		return -1
	}
	if n, ok := AsInt(v); ok {
		return n
	}
	return -1
}

// ParsePlan 提取可领取套餐（plan_id/name/描述/优先级 + model_usage token 授权项）。
// 返回 nil 表示不可领取。
func ParsePlan(raw map[string]any) map[string]any {
	planID := strings.TrimSpace(firstNonEmptyStr(raw["plan_id"], raw["planId"]))
	if planID == "" {
		return nil
	}
	grants := []any{}
	rawEnts, _ := raw["entitlements"].([]any)
	for _, rawEnt := range rawEnts {
		ent, ok := rawEnt.(map[string]any)
		if !ok {
			continue
		}
		if DictGetStr(ent, "meter", "") != "model_usage" || DictGetStr(ent, "unit_type", "") != "token" {
			continue
		}
		name := strings.TrimSpace(firstNonEmptyStr(ent["show_name"], ent["showName"]))
		if name == "" {
			continue
		}
		// units = ent.get("grant_units", ent.get("grantUnits")) or 0
		unitsAny, hasUnits := ent["grant_units"]
		if !hasUnits || unitsAny == nil {
			unitsAny = ent["grantUnits"]
		}
		units := 0.0
		if f, ok := AsFloat(unitsAny); ok {
			units = f
		}
		period := DictGetStr(ent, "period", "one_time")
		if period == "" {
			period = "one_time"
		}
		grants = append(grants, map[string]any{
			"name":   name,
			"units":  units,
			"period": period,
		})
	}
	priority := 0
	if f, ok := AsFloat(raw["priority"]); ok {
		priority = int(f)
	}
	return map[string]any{
		"plan_id":     planID,
		"name":        strings.TrimSpace(StrValue(raw["name"])),
		"description": strings.TrimSpace(StrValue(raw["description"])),
		"priority":    priority,
		"grants":      grants,
	}
}

func firstNonEmptyStr(vals ...any) string {
	for _, v := range vals {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// ExtractPlansFromMarketingDeliveries 从 marketing/touch 的 deliveries 载荷中提取待领取套餐。
//
// 官方客户端结构实证（2026-11-03 逆向 + 线上实测）：
//
//	delivery.banner.buttons[].action: {"type": "claim_zcode_plan", "args": {"plan_id": "..."}}
//	delivery.banner.args.zcode_plan: {"plan_id": "...", "name": "...", "priority": ..., "entitlements": [...]}
func ExtractPlansFromMarketingDeliveries(deliveries []any) []any {
	var plans []any
	seenIDs := map[string]bool{}

	var scan func(obj any)
	scan = func(obj any) {
		if dict, ok := obj.(map[string]any); ok {
			// 1. 优先提取挂在 args 里的完整 zcode_plan
			zpRaw := firstPresent(dict, "zcode_plan", "zcodePlan")
			if zp, ok := zpRaw.(map[string]any); ok && zp != nil {
				if parsed := ParsePlan(zp); parsed != nil {
					pid := parsed["plan_id"].(string)
					existing := findPlanByID(plans, pid)
					if existing != nil {
						// 对齐 Python existing.update(parsed)：逐键覆盖
						for k, v := range parsed {
							existing[k] = v
						}
					} else {
						plans = append(plans, parsed)
						seenIDs[pid] = true
					}
				}
			}
			// 2. 检查 claim_zcode_plan 按钮动作
			if action, ok := dict["action"].(map[string]any); ok && action != nil {
				if DictGetStr(action, "type", "") == "claim_zcode_plan" {
					args, _ := action["args"].(map[string]any)
					if args == nil {
						args = map[string]any{}
					}
					pid := strings.TrimSpace(firstNonEmptyStr(args["plan_id"], args["planId"]))
					if pid != "" && !seenIDs[pid] {
						plans = append(plans, map[string]any{
							"plan_id":     pid,
							"name":        pid,
							"description": "活动投放套餐",
							"priority":    100,
							"grants":      []any{},
						})
						seenIDs[pid] = true
					}
				}
			}
			for _, v := range dict {
				scan(v)
			}
		} else if list, ok := obj.([]any); ok {
			for _, item := range list {
				scan(item)
			}
		}
	}
	for _, delivery := range deliveries {
		scan(delivery)
	}
	return plans
}

func firstPresent(m map[string]any, keys ...string) any {
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			return v
		}
	}
	return nil
}

func findPlanByID(plans []any, pid string) map[string]any {
	for _, p := range plans {
		if pm, ok := p.(map[string]any); ok && pm["plan_id"] == pid {
			return pm
		}
	}
	return nil
}

// FetchMarketingTouchPlans 拉取 marketing/touch 接口下发的活动套餐（2026-11 官方实证）。
//
// 失败时仅记录并返回空列表，不阻断主流程。
func FetchMarketingTouchPlans(account *Account) ([]any, error) {
	body, err := billingRequest(account, "GET", ZCODE_MARKETING_TOUCH_URL,
		&billingReqOpts{headers: authHeaders(account), query: url.Values{"seq": {"0"}}})
	if err != nil {
		LogInfo("claim", fmt.Sprintf("账号 %s marketing/touch 查询跳过（%v）", account.Name, err))
		return nil, err
	}
	if claimBusinessCode(body) != 0 {
		return nil, nil
	}
	data, _ := body["data"].(map[string]any)
	var deliveries []any
	if data != nil {
		deliveries, _ = data["deliveries"].([]any)
	}
	return ExtractPlansFromMarketingDeliveries(deliveries), nil
}

// billingReqOpts 对齐 Python **kwargs（headers / params / json）。
type billingReqOpts struct {
	headers map[string]string
	query   url.Values
	jsonBody map[string]any
}

// billingRequest 对齐 _billing_request：billing 全家桶统一 HTTP 入口。
//
// trust_env=False：billing 全家桶直连。实测「解码直连 + claim 直连」才能过
// 上游风控（claim 走 US 出口被拒「unusual activity」，直连 code:0）；
// messages 端点与此相反（直连曾被 3012 风控），仍走 env 的 US 代理。
func billingRequest(account *Account, method, path string, opts *billingReqOpts) (map[string]any, error) {
	if opts == nil {
		opts = &billingReqOpts{}
	}
	fullURL := path
	if !strings.HasPrefix(path, "http") {
		fullURL = ZCODE_BILLING_BASE + path
	}
	if len(opts.query) > 0 {
		fullURL += "?" + opts.query.Encode()
	}
	var bodyReader io.Reader
	if opts.jsonBody != nil {
		b, err := JSONMarshalCompact(opts.jsonBody)
		if err != nil {
			return nil, &ClaimError{Message: fmt.Sprintf("请求体序列化失败: %v", err)}
		}
		bodyReader = strings.NewReader(string(b))
	}
	req, err := http.NewRequest(method, fullURL, bodyReader)
	if err != nil {
		return nil, &ClaimError{Message: fmt.Sprintf("上游网络错误: %v", err)}
	}
	for k, v := range opts.headers {
		req.Header.Set(k, v)
	}
	// trust_env=False 直连（对齐 httpx.AsyncClient(trust_env=False)）
	client := &http.Client{Timeout: 25 * time.Second, Transport: directTransport()}
	res, err := client.Do(req)
	if err != nil {
		// 连接/超时等网络故障统一转业务错误：路由层只需面对 ClaimError 一种失败
		return nil, &ClaimError{Message: fmt.Sprintf("上游网络错误: %v", err)}
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
	text := buf.String()
	if res.StatusCode == 401 || res.StatusCode == 403 {
		low := strings.ToLower(text)
		if !strings.Contains(low, "captcha") && !strings.Contains(low, "verify") {
			markAuthFailure(account)
			return nil, &ClaimError{Message: AuthExpiredMessage}
		}
	}
	v, err := JSONDecode(text)
	if err != nil {
		return nil, &ClaimError{Message: fmt.Sprintf("上游响应非 JSON HTTP %d", res.StatusCode)}
	}
	dict, _ := v.(map[string]any)
	if dict == nil {
		dict = map[string]any{}
	}
	return dict, nil
}

// ClaimJWTUserID JWT payload 的 user_id（zcode-switch telemetry_user_id 同源语义）。
//
// 官方客户端事件上报以 user_id 标识用户；hub 不存 user_info，直接从 JWT
// 解出（user_id 优先，sub 兜底，两者同为 36 位 uuid）。
func ClaimJWTUserID(account *Account) string {
	token := strings.TrimSpace(account.JWTToken)
	if token == "" {
		return ""
	}
	return BodyTransformJWTUserID(token)
}

// ReportActivationEvents 上报官方客户端激活事件（app_launch + app_daily_active），返回错误或 ""。
//
// zcode-switch claim_refresh 同形：preview 前模拟桌面端当日活跃（疑似活动
// 套餐投放资格信号）。事件体/端点/业务码判定收敛在 telemetry 单一事实源；
// 请求无 Authorization（上游事件端点不校验）；任何失败仅返回文案，不阻断
// preview，首个失败即中止（日活键在上游按 device_mid+日期去重，重试无意义）。
func ReportActivationEvents(account *Account) string {
	profile := ProfileFor(account)
	userID := ClaimJWTUserID(account)
	if userID == "" {
		return "JWT 无 user_id，跳过激活上报"
	}
	for _, element := range ActivationElements() {
		if err := PostActivationEvent(profile, userID, element, 0); err != nil {
			return activationErrText(element, err)
		}
	}
	return ""
}

// activationErrText 激活失败文案。Go error 的 Error() 恒非空——此处保留
// Python「空串时回退异常类名」的语义对应（网络错误已带类型信息）。
func activationErrText(element string, err error) string {
	detail := strings.TrimSpace(err.Error())
	if detail == "" {
		detail = fmt.Sprintf("%T", err)
	}
	return fmt.Sprintf("激活事件 %s 上报失败: %s", element, detail)
}

// 激活上报每日去重门：账号 id → 最近一次**成功**上报的本地日期。
// 自动路径（领取轮/入池）每号每天最多成功上报一次（官方客户端 app_launch
// 语义 = 每次启动一次；日活键上游本就按 device_mid+日期去重）。上报失败不
// 记账，下一轮自然重试（轮间隔 3600s，故障期上限 24 次/天，自愈）。手动
// preview 端点不走此门（用户触发 = zcode-switch claim_refresh 语义）。
var (
	activationReportedMu sync.Mutex
	activationReported   = map[string]string{}
)

func todayKey() string {
	return time.Now().Format("2006-01-02")
}

// AutoClaimAllPlans 新账号入池自动领取：每日一次激活上报（preview 之前）→ preview → 逐个领取。
//
// 入池链路的 fire-and-forget 收尾：任何失败只记日志/返回 outcome，绝不抛出
//（入池流程不受影响）。重复执行安全（上游 1003 已领取过幂等）。
// skipPlanIDs：本轮跳过领取的套餐 id（1005 名额等待期由 ClaimRoundManager
// 记忆传入）；preview 仍照常执行，新套餐发现不受影响。
//
// 激活上报时序（2.6.6 根因修复）：上报必须先于 preview——活动投放疑似以
// 当日激活信号为资格（constants.ACTIVATION_ELEMENTS 注释、09-06 实证），
// 「先 preview 后补上报」会在新的一天形成 preview 恒空 → 永不激活的死锁。
// 频率由每日去重门控制（每号每天 1 次，官方节奏），不再每轮空发。
func AutoClaimAllPlans(account *Account, skipPlanIDs map[string]bool) []any {
	if !(account.Mode == "jwt" && account.JWTToken != "") {
		return []any{}
	}
	outcomes := []any{}

	activationReportedMu.Lock()
	reported := activationReported[account.ID]
	activationReportedMu.Unlock()
	if reported != todayKey() {
		if err := ReportActivationEvents(account); err != "" {
			LogWarn("claim", fmt.Sprintf("账号 %s 激活上报失败: %s", account.Name, err))
		} else {
			activationReportedMu.Lock()
			activationReported[account.ID] = todayKey()
			activationReportedMu.Unlock()
		}
	}

	plans, err := PreviewPlans(account)
	if err != nil {
		if _, isClaim := err.(*ClaimError); isClaim {
			LogInfo("claim", fmt.Sprintf("账号 %s 无可领套餐（%v）", account.Name, err))
		} else {
			LogWarn("claim", fmt.Sprintf("账号 %s preview 异常: %v", account.Name, err))
		}
		return outcomes
	}
	if len(plans) == 0 {
		LogInfo("claim", fmt.Sprintf("账号 %s 上游无投放套餐，跳过领取", account.Name))
		return outcomes
	}

	skip := skipPlanIDs
	if skip == nil {
		skip = map[string]bool{}
	}
	skipped := 0
	for _, rawPlan := range plans {
		plan, _ := rawPlan.(map[string]any)
		if plan == nil {
			continue
		}
		planID := plan["plan_id"].(string)
		if skip[planID] {
			skipped++
			continue
		}
		result, err := ClaimPlan(account, planID)
		if err != nil {
			outcome := map[string]any{
				"account_id":   account.ID,
				"account_name": account.Name,
				"ok":           false,
				"plan_id":      planID,
				"message":      err.Error(),
			}
			if ce, isClaim := err.(*ClaimError); isClaim {
				if ce.Code != -1 {
					outcome["code"] = ce.Code
				}
				if ce.NextAt != nil {
					outcome["next_at"] = *ce.NextAt
				}
			}
			outcomes = append(outcomes, outcome)
			if ce, isClaim := err.(*ClaimError); isClaim {
				LogWarn("claim", fmt.Sprintf("账号 %s 自动领取 %s 失败: %s", account.Name, planID, ce.Message))
			} else {
				LogWarn("claim", fmt.Sprintf("账号 %s 自动领取异常: %v", account.Name, err))
			}
			continue
		}
		merged := map[string]any{
			"account_id":   account.ID,
			"account_name": account.Name,
			"ok":           true,
		}
		for k, v := range result {
			merged[k] = v
		}
		outcomes = append(outcomes, merged)
		planName := ""
		if v, ok := result["plan_name"].(string); ok {
			planName = v
		}
		if planName == "" {
			planName = planID
		}
		LogOK("claim", fmt.Sprintf("账号 %s 自动领取成功: %s", account.Name, planName))
	}
	if skipped > 0 {
		LogInfo("claim", fmt.Sprintf("账号 %s %d 个套餐名额等待期，本轮跳过领取", account.Name, skipped))
	}
	return outcomes
}

// PreviewPlans 拉取账号当前可领取套餐，按优先级降序。
//
// 双通道发现：
//  1. /billing/preview（常规预览端点）
//  2. /api/v1/marketing/touch（活动投放端点，2026-11 官方实证）
//
// 两者套餐按 plan_id 去重合并并按优先级降序排列。
func PreviewPlans(account *Account) ([]any, error) {
	if blocked := BillingBlockReason(account, "上游查询"); blocked != "" {
		return nil, &ClaimError{Message: blocked}
	}
	// platform 跟账号档案走（官方 TH() = process.platform-arch）；
	// 实测 client/configs 才拒 platform 参数，preview 宽容。
	body, err := billingRequest(account, "GET", "/billing/preview", &billingReqOpts{
		headers: authHeaders(account),
		query: url.Values{
			"app_version": {BillingAppVersion()},
			"platform":    {ProfileFor(account).PlatformFull()},
		},
	})
	if err != nil {
		return nil, err
	}
	if code := claimBusinessCode(body); code != 0 {
		return nil, failError(code, body)
	}
	data, _ := body["data"].(map[string]any)
	var rawPlans []any
	if data != nil {
		rawPlans, _ = data["plans"].([]any)
	}
	var plans []any
	for _, p := range rawPlans {
		if pm, ok := p.(map[string]any); ok {
			if parsed := ParsePlan(pm); parsed != nil {
				plans = append(plans, parsed)
			}
		}
	}

	// 合并 marketing/touch 活动投放通道（官方客户端实证：活动套餐由此下发）
	if marketingPlans, err := FetchMarketingTouchPlans(account); err != nil {
		LogWarn("claim", fmt.Sprintf("账号 %s marketing/touch 套餐合并异常: %v", account.Name, err))
	} else {
		seen := map[string]bool{}
		for _, p := range plans {
			if pm, ok := p.(map[string]any); ok {
				seen[pm["plan_id"].(string)] = true
			}
		}
		for _, mp := range marketingPlans {
			if pm, ok := mp.(map[string]any); ok {
				if pid, ok := pm["plan_id"].(string); ok && !seen[pid] {
					plans = append(plans, pm)
					seen[pid] = true
				}
			}
		}
	}

	sortPlans(plans)
	return plans, nil
}

// sortPlans 对齐 plans.sort(key=lambda p: (-p["priority"], p["plan_id"]))。
func sortPlans(plans []any) {
	// 稳定排序：优先级降序，plan_id 升序
	for i := 1; i < len(plans); i++ {
		for j := i; j > 0; j-- {
			a, _ := plans[j-1].(map[string]any)
			b, _ := plans[j].(map[string]any)
			if a == nil || b == nil {
				break
			}
			pa, pb := planPriority(a), planPriority(b)
			ida, _ := a["plan_id"].(string)
			idb, _ := b["plan_id"].(string)
			// (-priority, plan_id) 字典序比较
			if pb < pa || (pb == pa && idb < ida) {
				plans[j-1], plans[j] = plans[j], plans[j-1]
			} else {
				break
			}
		}
	}
}

func planPriority(p map[string]any) int {
	if f, ok := AsFloat(p["priority"]); ok {
		return int(f)
	}
	return 0
}

// autoPickPlan plan_id 为空时 preview 自动选优先级最高套餐。返回 (plan_id, plan_name, grants)。
func autoPickPlan(account *Account, planID string) (string, string, []any, error) {
	if planID != "" {
		return planID, "", nil, nil
	}
	plans, err := PreviewPlans(account)
	if err != nil {
		return "", "", nil, err
	}
	if len(plans) == 0 {
		return "", "", nil, &ClaimError{Message: "没有待领取的套餐"}
	}
	best, _ := plans[0].(map[string]any)
	name, _ := best["name"].(string)
	grants, _ := best["grants"].([]any)
	if name == "" {
		name = best["plan_id"].(string)
	}
	return best["plan_id"].(string), name, grants, nil
}

// claimHeaders billing/claim 客户端请求头形态（asar claimManualPlan）。
//
// 实测缺版本/平台头时即使验证码有效也 3007；X-Device-Mid 由 authHeaders 提供。
func claimHeaders(account *Account, verifyParam string, region string) map[string]string {
	headers := authHeaders(account)
	headers[CAPTCHA_HEADER] = verifyParam
	if strings.TrimSpace(region) != "" {
		headers["X-Aliyun-Captcha-Verify-Region"] = strings.TrimSpace(region)
	}
	// 实测缺版本/平台头时即使验证码有效也 3007（authHeaders 已带，此处显式
	// 兜底防止基座头漂移）。平台必须跟账号档案走，禁止再盖成全局 darwin-arm64。
	headers["X-ZCode-App-Version"] = BillingAppVersion()
	return headers
}

// postClaim 提交 billing/claim 并翻译业务码。
func postClaim(account *Account, headers map[string]string, planID string) (map[string]any, error) {
	body, err := billingRequest(account, "POST", "/billing/claim", &billingReqOpts{
		headers:  headers,
		jsonBody: map[string]any{"plan_id": planID},
	})
	if err != nil {
		return nil, err
	}
	if code := claimBusinessCode(body); code != 0 {
		return nil, failError(code, body)
	}
	return body, nil
}

// claimOutcome 领取成功返回集；server_time/starts_at/ends_at 为上游秒值 → 毫秒
//（zcode-switch 3.11.2 领取语义：服务端时钟随成功载荷下发，供前端
// 区分本机时钟漂移）。缺失字段保持 nil，不造数。
func claimOutcome(body map[string]any, planID, planName string, grants []any) map[string]any {
	data, _ := body["data"].(map[string]any)
	if data == nil {
		data = map[string]any{}
	}
	plan, _ := data["plan"].(map[string]any)
	if plan == nil {
		plan = map[string]any{}
	}

	ms := func(key string) any {
		if f, ok := AsFloat(plan[key]); ok && f > 0 {
			return int64(f * 1000)
		}
		return nil
	}

	respName := strings.TrimSpace(StrValue(plan["name"]))
	parsedGrants := grants
	if len(parsedGrants) == 0 {
		if parsed := ParsePlan(plan); parsed != nil {
			if g, ok := parsed["grants"].([]any); ok {
				parsedGrants = g
			}
		}
	}
	outName := respName
	if outName == "" {
		outName = planName
	}
	if outName == "" {
		outName = planID
	}
	var serverTime any
	if f, ok := AsFloat(data["server_time"]); ok && f > 0 {
		serverTime = int64(f * 1000)
	}
	return map[string]any{
		"plan_id":     planID,
		"plan_name":   outName,
		"grants":      parsedGrants,
		"starts_at":   ms("starts_at"),
		"ends_at":     ms("ends_at"),
		"server_time": serverTime,
	}
}

// ClaimWithCaptcha 手动领取：verify_param 由用户浏览器内阿里 SDK 滑块产生，本端只做转发。
//
// plan_id 缺省时先 preview 自动选优先级最高套餐（无需验证码）。
func ClaimWithCaptcha(account *Account, verifyParam, region, planID string) (map[string]any, error) {
	if !(account.Mode == "jwt" && account.JWTToken != "") {
		return nil, &ClaimError{Message: "仅 Coding Plan (JWT) 账号支持领取"}
	}
	if blocked := BillingBlockReason(account, "领取"); blocked != "" {
		return nil, &ClaimError{Message: blocked}
	}
	if strings.TrimSpace(verifyParam) == "" {
		return nil, &ClaimError{Message: "缺少验证码参数，请先完成人机验证"}
	}

	pid, planName, grants, err := autoPickPlan(account, firstNonEmpty(planID))
	if err != nil {
		return nil, err
	}
	headers := claimHeaders(account, strings.TrimSpace(verifyParam), region)
	body, err := postClaim(account, headers, pid)
	if err != nil {
		return nil, err
	}
	return claimOutcome(body, pid, planName, grants), nil
}

func firstNonEmpty(s string) string { return s }

// ClaimPlan 领取套餐。plan_id 缺省时自动选优先级最高的可领套餐。
//
// 返回 claimOutcome 形态（含 server_time/starts_at/ends_at，可能为 nil）；
// 1005 携带 next_at（名额恢复时间）。验证码被拒（3007）单次即止（2.6.5 整改）：
// 拒码本身就是上游风险信号，换码连打只会加剧——拒码出池，下一轮自然重试。
func ClaimPlan(account *Account, planID string) (map[string]any, error) {
	if !(account.Mode == "jwt" && account.JWTToken != "") {
		return nil, &ClaimError{Message: "仅 Coding Plan (JWT) 账号支持领取"}
	}
	if blocked := BillingBlockReason(account, "领取"); blocked != "" {
		return nil, &ClaimError{Message: blocked}
	}

	pid, planName, grants, err := autoPickPlan(account, planID)
	if err != nil {
		return nil, err
	}
	// claim 的 billing 请求走 trust_env=False 直连，验证码必须同样直连解，
	// 否则 token 的出口与请求出口不一致，上游判 unusual activity。
	verifyParam, verifyRegion, cerr := DefaultCaptchaManager.GetVerifyParam(EgressDirect)
	if cerr != nil {
		return nil, cerr
	}
	config, _ := DefaultCaptchaManager.FetchConfig(EgressDirect)
	region := verifyRegion
	if region == "" {
		region = DictGetStr(config, "region", "")
	}
	headers := claimHeaders(account, verifyParam, region)

	body, err := billingRequest(account, "POST", "/billing/claim", &billingReqOpts{
		headers:  headers,
		jsonBody: map[string]any{"plan_id": pid},
	})
	if err != nil {
		return nil, err
	}
	code := claimBusinessCode(body)
	if code == 0 {
		return claimOutcome(body, pid, planName, grants), nil
	}
	if code == 3007 {
		DefaultCaptchaManager.Invalidate(EgressDirect) // 被拒的码出池，避免下轮复用
	}
	return nil, failError(code, body)
}

// ── 后台周期自动领取轮（ClaimRoundManager）──────────────────────────────────

// ClaimRoundManager 后台周期自动领取轮（默认 1 小时，2.6.5 整改；对齐 zcode-switch 用户触发语义）。
//
// 每轮对全部可打 billing 的 JWT 账号执行 AutoClaimAllPlans（每日一次激活
// 上报先于 preview + 逐个领取可领套餐）；冷却/停用/风控禁用/失效账号由
// AllowsBilling() 先行过滤，保证「冷却期零上游 billing 流量」不变量。
// 1005（今日名额用完）按服务端 next_at 退避：等待期该套餐不打 claim
//（省 captcha 求解与上游写流量），preview 照常保留新套餐发现
//（docs/development/05「按服务端 next window 退避」语义落地）。
// 轮间隔与**领取窗口**（claim_round_hours，北京时间小时）运行期读 meta 设置
//（interval 0 = 关闭；窗口外只睡不跑、到点准时醒来；空窗口 = 全天）；
// 单账号异常不中断整轮，后台任务异常全部自兜。
type ClaimRoundManager struct {
	// 停服截止：轮内长尾（验证码求解重试可达分钟级）超时即放弃等待，
	// lifespan 关闭保持有界，不被半途的求解卡成脏停机
	stopGraceSeconds int

	mu         sync.Mutex
	stopCh     chan struct{}
	done       chan struct{}
	claimHolds map[string]map[string]int64 // 账号 → {plan_id: 名额恢复时间(ms)}：1005 退避记忆
	emptyWarned bool
}

// ClaimRound 全局单例（对齐 claim_round = ClaimRoundManager()）。
var ClaimRound = newClaimRoundManager()

func newClaimRoundManager() *ClaimRoundManager {
	return &ClaimRoundManager{stopGraceSeconds: 10, claimHolds: map[string]map[string]int64{}}
}

func (m *ClaimRoundManager) round() {
	accounts := []*Account{}
	for _, a := range DefaultStore.ListAccounts("zai") {
		if a.Mode == "jwt" && a.AllowsBilling(0) {
			accounts = append(accounts, a)
		}
	}
	if len(accounts) == 0 {
		m.mu.Lock()
		if !m.emptyWarned {
			LogWarn("claim", "无可服务账号（全部禁用/冷却/失效），本轮跳过")
			m.emptyWarned = true
		}
		m.mu.Unlock()
		return
	}
	m.mu.Lock()
	m.emptyWarned = false
	m.mu.Unlock()
	// 轮次执行前先轻量核验官方最新版本（若有新版本且开启 auto_sync，自动对齐指纹）
	if err := DefaultVersionTracker.CheckAndSync(false); err != nil {
		LogInfo("claim", fmt.Sprintf("轮次前官方版本核验跳过（%v）", err))
	}

	nowMs := NowFloat() * 1000
	// 退避表先清过期项（next_at 已过的恢复本轮重试）
	m.mu.Lock()
	holds := map[string]map[string]int64{}
	for aid, pl := range m.claimHolds {
		filtered := map[string]int64{}
		for pid, at := range pl {
			if at > int64(nowMs) {
				filtered[pid] = at
			}
		}
		if len(filtered) > 0 {
			holds[aid] = filtered
		}
	}
	m.claimHolds = holds
	m.mu.Unlock()

	claimed := 0
	for _, acc := range accounts {
		accHolds := holds[acc.ID]
		if len(accHolds) > 0 {
			minAt := int64(-1)
			for _, at := range accHolds {
				if minAt < 0 || at < minAt {
					minAt = at
				}
			}
			soon := int64(0)
			if d := minAt - int64(nowMs); d > 0 {
				soon = d / 1000
			}
			LogInfo("claim", fmt.Sprintf("账号 %s %d 个套餐名额等待中（约 %ds 后恢复重试）",
				acc.Name, len(accHolds), soon))
		}
		skip := map[string]bool{}
		for pid := range accHolds {
			skip[pid] = true
		}
		outcomes := AutoClaimAllPlans(acc, skip)
		// 按本轮实绩更新退避表：1005+next_at 记忆；成功/其余失败清除
		//（被跳过的套餐无 outcome，等待自然延续到 next_at）
		updated := map[string]int64{}
		for pid, at := range accHolds {
			updated[pid] = at
		}
		for _, o := range outcomes {
			om, ok := o.(map[string]any)
			if !ok {
				continue
			}
			pid, _ := om["plan_id"].(string)
			if pid == "" {
				continue
			}
			code, _ := AsInt(om["code"])
			if code == 1005 {
				if f, ok := AsFloat(om["next_at"]); ok {
					updated[pid] = int64(f)
					continue
				}
			}
			delete(updated, pid)
		}
		m.mu.Lock()
		if len(updated) > 0 {
			holds[acc.ID] = updated
			m.claimHolds[acc.ID] = updated
		} else {
			delete(holds, acc.ID)
			delete(m.claimHolds, acc.ID)
		}
		m.mu.Unlock()
		anyOK := false
		for _, o := range outcomes {
			if om, ok := o.(map[string]any); ok {
				if b, ok := om["ok"].(bool); ok && b {
					anyOK = true
					break
				}
			}
		}
		if !anyOK {
			continue
		}
		claimed++
		live := DefaultStore.Find("zai", acc.ID)
		if live != nil {
			// 领到额度立即反映到 UI
			RefreshAccounts([]*Account{live})
		}
	}
	if claimed > 0 {
		LogOK("claim", fmt.Sprintf("自动领取轮完成: %d 个账号有新套餐入账", claimed))
	}
}

func (m *ClaimRoundManager) loop() {
	defer close(m.done)
	// 启动先等一段（避开启动安装序 / 入池自动领取的首次流量高峰）
	select {
	case <-m.stopCh:
		return
	case <-time.After(30 * time.Second):
	}
	for {
		interval := DefaultStore.ClaimRoundInterval() // 实时读取设置，改后即生效
		hours := DefaultStore.ClaimRoundHours()
		if m.shouldRun(interval, hours, 0) {
			m.round()
		}
		// interval<=0 视为关闭：仍周期性回看设置，便于随时启用
		select {
		case <-m.stopCh:
			return
		case <-time.After(time.Duration(m.nextWait(interval, hours, 0)) * time.Second):
		}
	}
}

// shouldRun 本轮是否执行：轮次启用（interval>0）且（无窗口限制 或 当前在窗口内）。
func (m *ClaimRoundManager) shouldRun(interval int, hours []int, now float64) bool {
	return interval > 0 && m.inWindow(hours, now)
}

// ── 领取窗口调度（北京时间）─────────────────────────────────────────────
// 上游套餐按天投放，用户侧实证每天 19:00 放量。窗口锚定北京时钟而非 host
// 时区（host 换成 UTC 也不漂）；中国无夏令时，固定 +8 即精确，无 tzdata 依赖。

// beijingHourFrac 当前北京时间的小时（含小数，19.5 = 19:30）。
func (m *ClaimRoundManager) beijingHourFrac(now float64) float64 {
	if now == 0 {
		now = NowFloat()
	}
	lt := time.Unix(int64(now), 0).UTC().Add(8 * time.Hour)
	return float64(lt.Hour()) + float64(lt.Minute())/60 + float64(lt.Second())/3600
}

// inWindow 当前北京时间小时是否在领取窗口内（空窗口 = 全天不限时）。
func (m *ClaimRoundManager) inWindow(hours []int, now float64) bool {
	if len(hours) == 0 {
		return true
	}
	h := int(m.beijingHourFrac(now))
	return containsInt(hours, h)
}

// secondsUntilWindow 距下一个窗口起点（北京时间整点）的秒数；已在窗口内返回 0。
func (m *ClaimRoundManager) secondsUntilWindow(hours []int, now float64) float64 {
	frac := m.beijingHourFrac(now)
	if containsInt(hours, int(frac)) {
		return 0.0 // 恰逢整点（frac == hour）也属于窗口内，不能落进「今天已过」
	}
	sorted := append([]int{}, hours...)
	sortInts(sorted)
	for _, hour := range sorted {
		if frac < float64(hour) {
			return (float64(hour) - frac) * 3600
		}
	}
	return (24 - frac + float64(sorted[0])) * 3600 // 今天窗口已过 → 明天第一个窗口
}

func sortInts(list []int) {
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && list[j] < list[j-1]; j-- {
			list[j-1], list[j] = list[j], list[j-1]
		}
	}
}

// nextWait 下一次唤醒秒数。
//
// interval<=0：关闭态 30s 回看设置（随时可启用）；
// 无窗口：interval 节拍；有窗口：窗口内 interval 节拍，窗口外最迟 30min
// 回看一次设置、并在窗口开始时准时醒来（19:00 放量即领，不空转一天）。
func (m *ClaimRoundManager) nextWait(interval int, hours []int, now float64) float64 {
	if interval <= 0 {
		return 30.0
	}
	if len(hours) == 0 {
		return float64(interval)
	}
	if now == 0 {
		now = NowFloat()
	}
	if m.inWindow(hours, now) {
		return float64(interval)
	}
	w := m.secondsUntilWindow(hours, now)
	if w > 1800.0 {
		w = 1800.0
	}
	if w < 30.0 {
		w = 30.0
	}
	return w
}

// Start 对齐 claim_round.start()。
func (m *ClaimRoundManager) Start() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopCh != nil {
		return
	}
	m.stopCh = make(chan struct{})
	m.done = make(chan struct{})
	go m.loop()
}

// Stop 停止后台轮：事件置位后有截止地等待；超时即放弃等待。
//
// 轮内正在跑的验证码求解/上游请求长尾（求解重试可达分钟级）不允许
// 卡住 lifespan 关闭——到期返回（goroutine 随 HTTP 超时自然收尾）。
func (m *ClaimRoundManager) Stop() {
	m.mu.Lock()
	if m.stopCh == nil {
		m.mu.Unlock()
		return
	}
	stop := m.stopCh
	done := m.done
	m.stopCh = nil
	m.mu.Unlock()
	close(stop)
	select {
	case <-done:
	case <-time.After(time.Duration(m.stopGraceSeconds) * time.Second):
	}
}

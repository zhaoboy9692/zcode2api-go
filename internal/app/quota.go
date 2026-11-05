// ZCode 额度 / 余额 / 用量查询，以及账号状态判定。
//
// 在查询基础上提供「额度用完自动标记 exhausted」的监控能力。
//
// 对齐 Python app/quota.py：device_mid 持久化、billing 三路并发查询、
// 业务错误识别、窗口合并、耗尽/复活判定、Coding 平面额度、并发刷新与
// 后台 QuotaMonitor 轮询。
package app

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/zhaoboy9692/zcode2api-go/internal/uuidx"
)

var (
	deviceMidMu  sync.Mutex
	deviceMidVal string
)

// DeviceMid 本机设备 ID（ZCode 客户端 telemetry 同款语义）。
//
// billing 全家桶（current/balance/usage/preview/claim）必需 X-Device-Mid，
// 缺失时上游返回 code=3001 parameter error。首次生成后持久化到 data 目录。
func DeviceMid() string {
	deviceMidMu.Lock()
	defer deviceMidMu.Unlock()
	if deviceMidVal != "" {
		return deviceMidVal
	}
	path := filepath.Join(DATA_DIR, "device_mid")
	if data, err := os.ReadFile(path); err == nil {
		v := strings.TrimSpace(string(data))
		if v != "" {
			deviceMidVal = v
			return v
		}
	}
	deviceMidVal = uuidx.New4()
	if err := os.MkdirAll(DATA_DIR, 0o755); err == nil {
		// Python: open(path, "x") 独占创建——已存在则不覆盖
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err == nil {
			_, _ = f.WriteString(deviceMidVal)
			_ = f.Close()
		}
	} else {
		LogWarn("quota", fmt.Sprintf("device_mid 持久化失败（仅进程内生效）: %v", err))
	}
	return deviceMidVal
}

// authHeaders billing 族请求头（对齐 zcode-switch zai_billing_headers 实证形态）。
//
// UA/版本走 BILLING_APP_VERSION（官方桌面端现行版，与 messages 指纹刻意
// 分离）；平台/os/语言/时区/设备 ID 按账号指纹档案出值（每账号独立设备，
// 见 fingerprint.go）；每请求全新 x-request-id。
func authHeaders(account *Account) map[string]string {
	profile := ProfileFor(account)
	headers := map[string]string{
		"Content-Type":        "application/json",
		"User-Agent":          "ZCode/" + BillingAppVersion(),
		"HTTP-Referer":        ZCODE_ORIGIN,
		"X-Title":             BILLING_TITLE,
		"X-ZCode-App-Version": BillingAppVersion(),
		"X-Platform":          profile.PlatformFull(),
		"X-Release-Channel":   BILLING_RELEASE_CHANNEL,
		"X-Client-Language":   profile.Language,
		"X-Client-Timezone":   profile.Timezone,
		"X-Os-Category":       profile.OsCategory(),
		"X-Os-Version":        profile.OSVersion,
		"X-Device-Mid":        profile.DeviceMid,
		"x-request-id":        uuidx.New4(),
	}
	if account.Mode == "jwt" && account.JWTToken != "" {
		headers["Authorization"] = "Bearer " + account.JWTToken
	} else if account.APIKey != "" {
		headers["x-api-key"] = account.APIKey
	}
	return headers
}

// bonusActive plan 是否带有已生效的一次性赠送授权（balance 不含这类额度）。
//
// 用于额度耗尽判定：日窗口用完但赠送池有效时，账号仍有真实可用额度。
func bonusActive(plan map[string]any, now float64) bool {
	if plan == nil {
		return false
	}
	rawEnts, _ := plan["entitlements"].([]any)
	for _, rawEnt := range rawEnts {
		e, ok := rawEnt.(map[string]any)
		if !ok {
			continue
		}
		if DictGetStr(e, "period", "") != "one_time" {
			continue
		}
		eff, _ := AsFloat(e["effective_at"])
		if eff == 0 {
			eff = 0
		}
		ends, hasEnds := AsFloat(e["ends_at"])
		if !hasEnds || ends == 0 {
			ends, hasEnds = AsFloat(e["expires_at"])
			if !hasEnds {
				ends = 0
			}
		}
		if eff != 0 && eff <= now && (ends == 0 || now <= ends) {
			return true
		}
	}
	return false
}

// FetchQuota 拉取单个账号的 方案 / 余额 / 用量，写回账号状态并持久化。
//
// 返回结构: {"billing":..., "balance":..., "usage":..., "error":...}
func FetchQuota(account *Account) map[string]any {
	live := DefaultStore.Find(account.Provider, account.ID)
	if live == nil {
		return map[string]any{"error": "账号已删除"}
	}
	if live != account {
		account = live
	}
	if !account.AllowsBilling(0) && !account.IsCooling(0) {
		// 与 admin/monitor 同一扇门。冷却账号仍允许查询（测试与兜底约定：
		// 拿额度不得提前解除冷却）；废 JWT / 风控 / 手动停用一律不打 billing。
		if account.LastError != "" {
			return map[string]any{"error": account.LastError}
		}
		if reason := BillingBlockReason(account, "上游查询"); reason != "" {
			return map[string]any{"error": reason}
		}
		return map[string]any{"error": AuthExpiredMessage}
	}
	headers := authHeaders(account)
	base := ZCODE_BILLING_BASE
	result := map[string]any{}

	type respErr struct {
		resp *http.Response
		text string
		err  error
	}
	getPath := func(path string, ch chan respErr) {
		client := &http.Client{Timeout: 20 * time.Second, Transport: upstreamTransportFor(account)}
		req, err := http.NewRequest(http.MethodGet, base+path, nil)
		if err != nil {
			ch <- respErr{err: err}
			return
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		res, err := client.Do(req)
		if err != nil {
			ch <- respErr{err: err}
			return
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
		ch <- respErr{resp: res, text: buf.String()}
	}
	chCurrent := make(chan respErr, 1)
	chBalance := make(chan respErr, 1)
	chUsage := make(chan respErr, 1)
	go getPath("/billing/current", chCurrent)
	go getPath("/billing/balance", chBalance)
	go getPath("/usage", chUsage)
	billingRes := <-chCurrent
	balanceRes := <-chBalance
	usageRes := <-chUsage

	live = DefaultStore.Find(account.Provider, account.ID)
	if live == nil {
		return map[string]any{"error": "账号已删除"}
	}
	if live != account {
		account = live
	}

	now := NowFloat()
	account.LastCheckedAt = &now

	// 鉴权失败 → 标记 invalid
	if billingRes.resp != nil && (billingRes.resp.StatusCode == 401 || billingRes.resp.StatusCode == 403) {
		body := strings.ToLower(billingRes.text)
		if !strings.Contains(body, "captcha") && !strings.Contains(body, "verify") {
			account.Status = StatusInvalid
			account.LastError = AuthExpiredMessage
			// Coding 平面快照：有 API Key 的账号顺带拉一次 monitor（bigmodel 账号的主账本）
			if account.APIKey != "" {
				if res := FetchCodingLimits(account); res["error"] == nil {
					// snapshot 已写入 account.CodingLimits
				}
			}

			DefaultStore.UpdateAccount(account)
			return map[string]any{"error": account.LastError}
		}
	}

	// HTTP 200 承载的业务错误（Plan 通道实测：额度/风控类拒绝常是 200 +
	// {"code":1005,...}）。三条 billing 请求各自判：命中业务错误的**不得写库**，
	// 否则会把 quota 快照 / plans 洗空，看起来像「上游没投放、额度未知」。
	errors := map[string]int{}
	var billingPlans []any // 本次 billing/current 实际解析到的 plans

	if billingRes.resp != nil && billingRes.resp.StatusCode == 200 {
		if data, err := JSONDecode(billingRes.text); err == nil {
			if dict, ok := data.(map[string]any); ok {
				result["billing"] = dict
				if code, isErr := BusinessCode(dict); isErr {
					errors["current"] = code
				} else {
					dataDict, _ := dict["data"].(map[string]any)
					var plans []any
					if dataDict != nil {
						plans, _ = dataDict["plans"].([]any)
					}
					if plans == nil {
						plans = []any{}
					}
					billingPlans = plans
					// 全量保留（多套餐时 entitlements 不丢）；plan 兼容保留首个
					account.Plans = plans
					if len(plans) > 0 {
						if p0, ok := plans[0].(map[string]any); ok {
							account.Plan = p0
						}
					} else {
						account.Plan = map[string]any{}
					}
				}
			}
		}
	}

	quotaMap := map[string]any{}
	if balanceRes.resp != nil && balanceRes.resp.StatusCode == 200 {
		if data, err := JSONDecode(balanceRes.text); err == nil {
			if dict, ok := data.(map[string]any); ok {
				result["balance"] = dict
				code, isErr := BusinessCode(dict)
				if isErr {
					errors["balance"] = code
				} else {
					// balance 也带 plans[]（含 plan_id）。`/billing/current` 偶发失败时
					// 这里就是套餐类型的唯一来源——少了它 trial 号会退化成「未知套餐」，
					// 拿不到体验档的并发收紧（见 models.Account.plan_kind）。
					dataDict, _ := dict["data"].(map[string]any)
					var balPlans []any
					if dataDict != nil {
						balPlans, _ = dataDict["plans"].([]any)
					}
					if len(balPlans) > 0 && len(account.Plans) == 0 {
						account.Plans = balPlans
						if p0, ok := balPlans[0].(map[string]any); ok {
							account.Plan = p0
						}
					}
					// 注意：quota_verified_at **不在这里**打点。balance 200 但 balances
					// 为空（新号 billing 全空形态，见下方注释）时什么也没确认——此时
					// 打点会把旧的过期快照误升格为「过期后实查确认」，正好把 2.7.8
					// 要救的号从另一扇门判死。打点在下方 quota_map 非空分支。
					var balances []any
					if dataDict != nil {
						balances, _ = dataDict["balances"].([]any)
					}
					if !isErr { // 对齐 Python: for bal in [...] if code is None
						for _, rawBal := range balances {
							bal, ok := rawBal.(map[string]any)
							if !ok {
								continue
							}
							name := DictGetStr(bal, "show_name", "")
							if name == "" {
								name = DictGetStr(bal, "model", "")
							}
							if name == "" {
								name = "model"
							}
							window := map[string]any{
								"total":      bal["total_units"],
								"used":       bal["used_units"],
								"remaining":  bal["remaining_units"],
								"expires_at": bal["expires_at"],
							}
							if prev, exists := quotaMap[name]; exists {
								// 防御：同模型多窗口（如日窗 + 一次性）合并，避免后者覆盖前者
								prevDict, _ := prev.(map[string]any)
								for _, k := range []string{"total", "used", "remaining"} {
									sum := 0.0
									if f, ok := AsFloat(prevDict[k]); ok {
										sum += f
									}
									if f, ok := AsFloat(window[k]); ok {
										sum += f
									}
									if sum != 0 || prevDict[k] != nil || window[k] != nil {
										prevDict[k] = sum
									}
								}
								// expires_at 保留**更晚**的那个。该字段线上是 epoch 秒、
								// 快照里也出现过 ISO8601 字符串，直接 max() 会按字典序比
								//（str 与 int 混型甚至 TypeError），必须先归一成 epoch 再挑。
								prevEnd, hasPrev := ExpiresEpoch(prevDict["expires_at"])
								newEnd, hasNew := ExpiresEpoch(window["expires_at"])
								if hasNew && (!hasPrev || newEnd > prevEnd) {
									prevDict["expires_at"] = window["expires_at"]
								}
								LogWarn("quota", fmt.Sprintf("balance 同名窗口 %s 已合并", name))
							} else {
								quotaMap[name] = window
							}
						}
					}
				}
			}
		}
	}

	if usageRes.resp != nil && usageRes.resp.StatusCode == 200 {
		if data, err := JSONDecode(usageRes.text); err == nil {
			if dict, ok := data.(map[string]any); ok {
				if code, isErr := BusinessCode(dict); isErr {
					errors["usage"] = code
				} else {
					dataDict, _ := dict["data"].(map[string]any)
					if dataDict == nil {
						dataDict = map[string]any{}
					}
					account.Usage = dataDict
					result["usage"] = account.Usage
				}
			}
		}
	}

	if len(quotaMap) > 0 {
		account.Quota = quotaMap
		// 快照真实写库的时刻 = 「过期后实查」的证据点（见 models.Account.quota_expired）。
		// 绑在 quota_map 非空上：只有真的取到窗口，才谈得上「确认」它们的状态。
		account.QuotaVerifiedAt = &now
		// 额度耗尽判定：逐窗口算「有效余量」（remaining > 0 且未过期）。
		// 原实现只看 remaining <= 0，把**已过期窗口**当可用 —— 2026-10-31 实证：
		// 老号 GLM-5.3-Flash 本地 remaining=1e8、expires_at 在 28 天前，上游对
		// 每个 messages 一律回 {"code":1005}。只看余额会让这类号长期占着轮询位。
		// 注意 balance 不含一次性赠送池：赠送池有效时不判耗尽。
		now2 := NowFloat()
		hasUsable := false
		allExpired := true
		for _, w := range quotaMap {
			wm, _ := w.(map[string]any)
			if wm == nil {
				continue
			}
			if WindowUsable(wm, now2) {
				hasUsable = true
			}
			if !WindowExpired(wm, now2) {
				allExpired = false
			}
		}
		hasBonus := bonusActive(account.Plan, now2)
		for _, p := range account.Plans {
			pm, ok := p.(map[string]any)
			if ok && bonusActive(pm, now2) {
				hasBonus = true
			}
		}
		if !hasUsable && !hasBonus {
			account.Status = StatusExhausted
			if allExpired {
				account.LastError = "额度已过期"
			} else {
				account.LastError = "额度已用完"
			}
		} else if (account.Status == StatusExhausted || account.Status == StatusCooling) &&
			(hasUsable || hasBonus) {
			// 额度恢复（窗口重置 / 赠送池生效）→ 重新激活。冷却期内不提前解除；
			// 废 JWT / 风控禁用绝不能因额度数字复活 Plan 通道。
			if !account.IsCooling(0) {
				account.Status = StatusActive
				account.LastError = ""
				account.CoolingUntil = nil
			}
		}
	} else if len(errors) > 0 {
		// billing 回了业务错误、但没拿到任何窗口：**不据此判死**。
		// 上游对「体验套餐/新号」的 billing 支持并不一致（老实证：billing 全空
		// 仍有 100% 可用的试用额度），拿不到账面数据 ≠ 没额度。真正的判定只有
		// 两处：balance 窗口全部失效（上面分支）、messages 真实回 1005（gateway）。
		// 这里只留痕，让一次真实请求去定生死——否则新号会被永久挡在门外。
		detail := ""
		for k, v := range errors {
			if detail != "" {
				detail += "，"
			}
			detail += fmt.Sprintf("%s=code%d", k, v)
		}
		LogWarn("quota", fmt.Sprintf("账号 %s billing 业务错误但保留可选（%s）", account.Name, detail))
	} else if len(quotaMap) == 0 && len(billingPlans) == 0 && result["usage"] == nil {
		// 新号体验额度：上游对新注册账号可能 **billing 全空/全拒**，但 messages 仍能
		// 正常服务（2026-09-06 实测：空 billing 的 oauth-login 100% 成功服务请求；
		// 2026-11-01 复核：billing/preview、balance 均空/1005，新号照样有体验套餐）。
		// 只凭 billing 就判死会把真能用的号挡在门外。这里**只给 ACTIVE 且零成功请求
		// 的号**一条提示，绝不复活已判死的号——否则「首探 1005 → 判死 → 下次刷新又
		// 拉活 → 再撞 1005」会无限循环，每圈烧一次真实请求（比误判更贵）。
		if account.UseCount == 0 && account.Status == StatusActive {
			account.LastError = "billing 为空，待首次请求验证（疑似新号体验额度）"
		}
		// 上游账本成功返回但已空（套餐结束/窗口整体消失）：清掉本地已过期的旧
		// 窗口快照 —— 否则 UI 永远显示早已到期的窗口（如「至 11/05 09:00」挂
		// 一整天）。只清全部过期的（留 10 分钟时钟余量），活性窗口不动；
		// 不改 status/LastError，账号生死判定仍走原路径。
		if len(account.Quota) > 0 {
			nowF := NowFloat()
			allExpired := true
			for _, w := range account.Quota {
				wm, ok := w.(map[string]any)
				if !ok {
					continue
				}
				exp, _ := AsFloat(wm["expires_at"])
				if exp == 0 || exp > nowF-600 {
					allExpired = false
					break
				}
			}
			if allExpired {
				account.Quota = map[string]any{}
				account.Plans = []any{}
				account.Plan = map[string]any{}
			}
		}
	}

	DefaultStore.UpdateAccount(account)
	// 「三路全业务错误」才整体报失败（调用方据此区分「上游拒绝」与「上游确实
	// 什么都没有」）。一路成功就照常返回，错误只记日志——避免把「部分可用」
	// 误报成刷新失败。
	if len(errors) > 0 {
		if _, hasCurrent := errors["current"]; hasCurrent && len(quotaMap) == 0 && result["usage"] == nil {
			detail := ""
			for k, v := range errors {
				if detail != "" {
					detail += "，"
				}
				detail += fmt.Sprintf("%s=code%d", k, v)
			}
			LogWarn("quota", fmt.Sprintf("账号 %s billing 全业务错误（%s）", account.Name, detail))
			return map[string]any{"error": fmt.Sprintf("上游业务错误（%s）", detail)}
		}
	}
	if len(result) == 0 {
		return map[string]any{"error": "无法获取额度数据"}
	}
	return result
}

// normalizeLimits `data.limits[]` → 紧凑快照（TOKENS_LIMIT / TIME_LIMIT 两类窗口混排）。
func normalizeLimits(data map[string]any) []any {
	out := []any{}
	dataDict, _ := data["data"].(map[string]any)
	var limits []any
	if dataDict != nil {
		limits, _ = dataDict["limits"].([]any)
	}
	for _, rawItem := range limits {
		item, ok := rawItem.(map[string]any)
		if !ok {
			continue
		}
		out = append(out, map[string]any{
			"type":            item["type"],
			"unit":            item["unit"],
			"number":          item["number"],
			"usage":           item["usage"],
			"remaining":       item["remaining"],
			"percentage":      item["percentage"],
			"next_reset_time": item["next_reset_time"],
		})
	}
	return out
}

// FetchCodingLimits 拉取 Coding 平面额度（api.z.ai monitor 端点）。
//
// 与 `FetchQuota` 是**两套独立账本**：Plan 通道额度来自 zcode.z.ai 的
// billing 族；Coding 平面（API Key 直连 api.z.ai）的额度完全不在那套账里。
// 体验套餐号在 billing 侧常全空/全拒，但这里能给出真实上限表——作为第二
// 额度源补盲，只读、不写账号状态（避免与 billing 判定打架）。
//
// 返回 {"limits": [...], "raw": {...}} 或 {"error": ...}
// FetchCodingLimits 拉取 Coding 平面额度（monitor 端点，API Key 鉴权）。
//
// 与 `FetchQuota` 是**两套独立账本**：Plan 通道额度来自 zcode.z.ai 的 billing 族；
// Coding 平面的额度完全不在那套账里。端点按 provider 分流（对齐 zcode-switch 的
// Monitor 通道）：bigmodel 账号走 open.bigmodel.cn（并带 subscription/list 取
// 套餐档位与有效期），zai 账号走 api.z.ai。
//
// 成功时把快照写入 account.CodingLimits（调用方负责持久化）。
//
// 返回 {"limits": [...], "tier": "...", "expire": "..."} 或 {"error": ...}
func FetchCodingLimits(account *Account) map[string]any {
	apiKey := strings.TrimSpace(account.APIKey)
	if apiKey == "" {
		return map[string]any{"error": "该账号没有 API Key，无法查询 Coding 平面额度"}
	}
	origin := ZAI_API_ORIGIN
	if account.Provider == "bigmodel" {
		origin = BIGMODEL_ORIGIN
	}
	get := func(path string) (map[string]any, int, error) {
		client := &http.Client{Timeout: 20 * time.Second, Transport: upstreamTransportFor(account)}
		req, err := http.NewRequest(http.MethodGet, origin+path, nil)
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("authorization", apiKey)
		req.Header.Set("accept", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()
		buf := &strings.Builder{}
		tmp := make([]byte, 32*1024)
		for {
			n, readErr := resp.Body.Read(tmp)
			if n > 0 {
				buf.Write(tmp[:n])
			}
			if readErr != nil {
				break
			}
		}
		data, err := JSONDecode(buf.String())
		if err != nil {
			return nil, resp.StatusCode, fmt.Errorf("上游返回非 JSON（HTTP %d）", resp.StatusCode)
		}
		dict, ok := data.(map[string]any)
		if !ok {
			return nil, resp.StatusCode, fmt.Errorf("上游返回结构异常")
		}
		return dict, resp.StatusCode, nil
	}

	dict, status, err := get("/api/monitor/usage/quota/limit")
	if err != nil {
		return map[string]any{"error": fmt.Sprintf("请求上游失败: %v", err)}
	}
	if code, isErr := BusinessCode(dict); isErr {
		msg := DictGetStr(dict, "msg", "")
		if msg == "" {
			msg = fmt.Sprintf("业务错误 code=%d", code)
		}
		return map[string]any{"error": msg, "code": code}
	}
	if status >= 400 {
		return map[string]any{"error": fmt.Sprintf("HTTP %d", status)}
	}

	items := normalizeCodingItems(dict)
	// 套餐档位：monitor data.level；bigmodel 再补 subscription/list（档位名 + 有效期）
	dataDict := dictDict(dict, "data")
	tier := codingTier(DictGetStr(dataDict, "level", ""))
	expire := ""
	if account.Provider == "bigmodel" {
		if sub, _, subErr := get("/api/biz/subscription/list"); subErr == nil {
			if arr, ok := sub["data"].([]any); ok {
				for _, rawSub := range arr {
					sm, ok := rawSub.(map[string]any)
					if !ok {
						continue
					}
					st := strings.ToUpper(DictGetStr(sm, "status", ""))
					if st != "" && st != "VALID" && st != "ACTIVE" {
						continue
					}
					if pn := DictGetStr(sm, "productName", ""); pn != "" {
						tier = codingTier(pn)
					}
					expire = codingExpire(sm)
					break
				}
			}
		}
	}
	// 套餐固定规格（GLM Coding Plan 公开售卖页口径）：档位 → 每周重置卡张数 / 并发数。
	// 上游接口不返回这两个数，按 tier 映射；未知档位不给，前端回落到窗口数计数。
	weeklyCards, concurrency := 0, 0
	switch strings.ToLower(tier) {
	case "max":
		weeklyCards, concurrency = 3, 4
	case "pro":
		weeklyCards, concurrency = 2, 2
	}
	snapshot := map[string]any{
		"items":        items,
		"tier":         strOrNil(tier),
		"expire":       strOrNil(expire),
		"weekly_cards": weeklyCards,
		"concurrency":  concurrency,
		"refreshed_at": NowFloat(),
	}
	// 真实重置卡计数（官方 /coding-plan/reset/status，双 token 鉴权）：
	// available_five_hour_resets / available_week_resets，每张卡自带 expire_at（ms）。
	// 有即覆盖规格映射的 weekly_cards —— 这是「N 张每周重置卡」的权威数据源。
	if account.JWTToken != "" && account.PlatformToken != "" {
		if rc := fetchResetCredits(account); rc != nil {
			snapshot["reset_credits"] = rc
			if nw, ok := rc["weekly"].(int); ok && nw > 0 {
				snapshot["weekly_cards"] = nw
			}
		}
	}
	account.CodingLimits = snapshot
	return snapshot
}

// fetchResetCredits 官方重置卡计数：GET /coding-plan/reset/status。
// 头位与 jusage 同款：ZCode JWT（Bearer）+ 平台 OAuth token（X-Bigmodel-Authorization）。
func fetchResetCredits(account *Account) map[string]any {
	client := &http.Client{Timeout: 20 * time.Second, Transport: upstreamTransportFor(account)}
	req, err := http.NewRequest(http.MethodGet, ZCODE_ORIGIN+"/api/v1/coding-plan/reset/status", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+account.JWTToken)
	req.Header.Set("X-Bigmodel-Authorization", account.PlatformToken)
	req.Header.Set("Bigmodel-Target-Type", "PERSONAL")
	req.Header.Set("Accept", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer res.Body.Close()
	data, err := JSONDecode(readAllHTTP(res))
	if err != nil {
		return nil
	}
	dict, ok := data.(map[string]any)
	if !ok {
		return nil
	}
	if code, isErr := BusinessCode(dict); isErr && code != 0 {
		return nil
	}
	root := dictDict(dict, "data")
	if root == nil {
		return nil
	}
	count := func(key string) (int, float64) {
		arr, _ := root[key].([]any)
		n, earliest := 0, 0.0
		for _, raw := range arr {
			item, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			ms, ok := AsFloat(item["expire_at"])
			if !ok || ms <= 0 {
				continue
			}
			n++
			if earliest == 0 || ms < earliest {
				earliest = ms
			}
		}
		return n, earliest
	}
	n5, e5 := count("available_five_hour_resets")
	nw, ew := count("available_week_resets")
	return map[string]any{"five_hour": n5, "weekly": nw, "five_hour_next": e5, "weekly_next": ew}
}

// readAllHTTP 读完响应体。
func readAllHTTP(res *http.Response) string {
	buf := &strings.Builder{}
	tmp := make([]byte, 32*1024)
	for {
		n, err := res.Body.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			break
		}
	}
	return buf.String()
}

// dictDict 取 map 里嵌套 map（nil 安全）。
func dictDict(m map[string]any, key string) map[string]any {
	v, _ := m[key].(map[string]any)
	return v
}

// codingTier 套餐档位名归一（对齐 zsw tier_from_level）。
func codingTier(level string) string {
	l := strings.ToLower(level)
	switch {
	case strings.Contains(l, "max"):
		return "Max"
	case strings.Contains(l, "pro"):
		return "Pro"
	case strings.Contains(l, "lite"):
		return "Lite"
	}
	return level
}

// codingExpire 从订阅条目提取有效期（候选键对齐 zsw extract_expire）。
func codingExpire(obj map[string]any) string {
	keys := []string{"nextRenewTime", "expireTime", "expire_time", "endTime", "end_time",
		"expireAt", "expiredTime", "validEndTime", "expires_at", "expiresAt", "expired_at",
		"period_end", "valid"}
	for _, k := range keys {
		v, ok := obj[k]
		if !ok || v == nil {
			continue
		}
		if f, ok := AsFloat(v); ok {
			if f > 1e12 { // 毫秒时间戳
				return time.Unix(int64(f)/1000, 0).Format("2006-01-02")
			}
			if f > 1e9 { // 秒时间戳
				return time.Unix(int64(f), 0).Format("2006-01-02")
			}
			continue
		}
		if sv, ok := v.(string); ok { // "2027-09-28 10:07:00" 等日期字符串
			sv = strings.TrimSpace(sv)
			if strings.HasPrefix(sv, "20") && len(sv) >= 10 {
				return sv[:10]
			}
		}
	}
	return ""
}

// normalizeCodingItems monitor limits → 展示条目（字段映射对齐 zsw normalize_quota_limit：
// total=usage、used=currentValue、重置=nextResetTime(ms)、周期=unit×number）。
func normalizeCodingItems(data map[string]any) []any {
	out := []any{}
	dataDict := dictDict(data, "data")
	var limits []any
	if dataDict != nil {
		limits, _ = dataDict["limits"].([]any)
	}
	for _, rawItem := range limits {
		item, ok := rawItem.(map[string]any)
		if !ok {
			continue
		}
		typ := DictGetStr(item, "type", "")
		unit, _ := AsFloat(item["unit"])
		number, _ := AsFloat(item["number"])
		total, _ := AsFloat(item["usage"])
		used, _ := AsFloat(item["currentValue"])
		remaining, _ := AsFloat(item["remaining"])
		pct, hasPct := AsFloat(item["percentage"])
		if !hasPct && total > 0 {
			pct = used / total * 100
		}
		window := "每周期"
		switch int(unit) {
		case 3:
			window = fmt.Sprintf("每 %g 小时", number)
		case 4:
			window = "每天"
		case 5:
			window = "每月"
		case 6:
			window = "每周"
		}
		name := typ
		switch typ {
		case "CREDIT_LIMIT":
			name = "Credits（" + window + "）"
		case "TOKENS_LIMIT":
			name = "Tokens（" + window + "）"
		case "TIME_LIMIT":
			name = "使用时长（" + window + "）"
		case "PROMPT_LIMIT":
			name = "提示次数（" + window + "）"
		}
		reset := ""
		resetMs, _ := AsFloat(item["nextResetTime"])
		if resetMs > 0 {
			reset = time.Unix(int64(resetMs)/1000, 0).Format("01-02 15:04")
		}
		out = append(out, map[string]any{
			"name":      name,
			"window":    window,
			"total":     total,
			"used":      used,
			"remaining": remaining,
			"pct":       pct,
			"reset":     reset,
			"reset_ms":  resetMs,
		})
	}
	return out
}

// RefreshAccounts 并发刷新一批账号，返回汇总。
func RefreshAccounts(accounts []*Account) map[string]any {
	if len(accounts) == 0 {
		return map[string]any{"ok": 0, "fail": 0}
	}
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var mu sync.Mutex
	okCount := 0
	for _, acc := range accounts {
		wg.Add(1)
		go func(a *Account) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res := FetchQuota(a)
			_, hasErr := res["error"]
			mu.Lock()
			if !hasErr {
				okCount++
			}
			mu.Unlock()
		}(acc)
	}
	wg.Wait()
	return map[string]any{"ok": okCount, "fail": len(accounts) - okCount}
}

// ── 后台监控轮询（QuotaMonitor）─────────────────────────────────────────────

// QuotaMonitor 后台周期性刷新可管理账号的额度，实现实时用量监控。
type QuotaMonitor struct {
	mu     sync.Mutex
	stopCh chan struct{}
	done   chan struct{}
}

// QuotaMonitor 全局单例（对齐 monitor = QuotaMonitor()）。
var Monitor = &QuotaMonitor{}

// Start 对齐 monitor.start()。
func (m *QuotaMonitor) Start() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stopCh != nil {
		return
	}
	m.stopCh = make(chan struct{})
	m.done = make(chan struct{})
	go m.loop()
}

// Stop 对齐 async monitor.stop()。
func (m *QuotaMonitor) Stop() {
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
	<-done
}

func (m *QuotaMonitor) loop() {
	defer close(m.done)
	// 启动后先等几秒，避免与服务启动争抢
	select {
	case <-m.stopCh:
		return
	case <-time.After(5 * time.Second):
	}
	for {
		interval := DefaultStore.QuotaRefreshInterval() // 实时读取设置，改后即生效
		if interval > 0 {
			var accounts []*Account
			for _, a := range DefaultStore.ListAccounts("zai") {
				if a.Mode == "jwt" && a.AllowsBilling(0) {
					accounts = append(accounts, a)
				}
			}
			if len(accounts) > 0 {
				RefreshAccounts(accounts)
			}
		}
		// interval<=0 视为关闭：仍周期性回看设置，便于随时启用
		wait := time.Duration(interval) * time.Second
		if interval <= 0 {
			wait = 30 * time.Second
		}
		select {
		case <-m.stopCh:
			return
		case <-time.After(wait):
		}
	}
}

// upstreamTransportFor 上游官方端点统一 Transport：该账号生效的显式代理
// （账号级 > 全局 ZCODE_UPSTREAM_PROXY，见 proxy.go），保持「验证码出口 ==
// 请求出口」；未配置保持 trust_env=False 直连。
func upstreamTransportFor(account *Account) *http.Transport {
	t := &http.Transport{
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	if raw := ProxyRawForAccount(account); raw != "" {
		t.Proxy = ProxyFuncForRaw(raw)
	}
	return t
}

// upstreamTransport 无账号上下文（版本清单等全局请求）的 Transport。
func upstreamTransport() *http.Transport { return upstreamTransportFor(nil) }

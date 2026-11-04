// 后台管理 API：/admin/api/*（账号池、设置、用量监控）。
//
// 对齐 Python app/routes/admin_api.py：鉴权探针、账号 CRUD、指纹换发、
// 额度刷新、Coding 平面额度、OAuth 登录（poll 状态机 + 兑换回填）、
// 套餐领取（preview/claim/manual/captcha-config）、设置读写、
// 官方版本核验、导入导出、请求监控。
package routes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/zhaoboy9692/zcode2api-go/internal/app"
)

// ── 鉴权探针 ─────────────────────────────────────────────────────────────────

// handleVerify GET /admin/api/verify
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, 200, map[string]any{"status": "ok"})
}

// ── 账号列表 + 概览统计 ──────────────────────────────────────────────────────

// handleListAccounts GET /admin/api/accounts
func (s *Server) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	now := app.NowFloat()
	accounts := []any{}
	for _, a := range app.DefaultStore.ListAccounts("") {
		accounts = append(accounts, a.PublicView())
	}
	stats := map[string]any{
		"total": len(accounts), "active": 0, "exhausted": 0,
		"cooling": 0, "invalid": 0, "disabled": 0,
		"calls": 0, "fail": 0,
	}
	var calls, fails int
	for _, rawA := range accounts {
		a := rawA.(map[string]any)
		if st, ok := a["status"].(string); ok {
			if _, isKey := stats[st]; isKey && (st == "active" || st == "exhausted" || st == "cooling" || st == "invalid" || st == "disabled") {
				stats[st] = stats[st].(int) + 1
			}
		}
		if n, ok := app.AsInt(a["use_count"]); ok {
			calls += n
		}
		if n, ok := app.AsInt(a["fail_count"]); ok {
			fails += n
		}
	}
	stats["calls"] = calls
	stats["fail"] = fails
	providers := []any{}
	for _, p := range app.Providers() {
		providers = append(providers, p)
	}
	jsonOut(w, 200, map[string]any{"accounts": accounts, "stats": stats, "providers": providers, "ts": now})
}

// handleStatusInfo GET /admin/api/status
func (s *Server) handleStatusInfo(w http.ResponseWriter, r *http.Request) {
	quotaPool := map[string]any{}
	for _, p := range app.Providers() {
		n := 0
		for _, a := range app.DefaultStore.ListAccounts(p) {
			if a.IsSelectable(0) {
				n++
			}
		}
		quotaPool[p] = n
	}
	providers := []any{}
	for _, p := range app.Providers() {
		providers = append(providers, p)
	}
	jsonOut(w, 200, map[string]any{
		"providers":       providers,
		"gateway_key_set": app.DefaultStore.GatewayKey() != "",
		"quota_pool":      quotaPool,
	})
}

// ── 新增账号 ─────────────────────────────────────────────────────────────────

// handleAddAccounts POST /admin/api/accounts
func (s *Server) handleAddAccounts(w http.ResponseWriter, r *http.Request) {
	payload, jresp := decodeJSONBody(r)
	if jresp != nil {
		jsonOut(w, 400, map[string]any{"detail": jresp.body})
		return
	}
	provider := DictGetStrM(payload, "provider", "")
	if provider == "" {
		provider = "zai"
	}
	if !app.IsProvider(provider) {
		jsonOut(w, 400, map[string]any{"detail": "不支持的 provider"})
		return
	}
	var tokens []string
	switch t := payload["tokens"].(type) {
	case string:
		for _, line := range strings.Split(t, "\n") {
			line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
			if line != "" {
				tokens = append(tokens, line)
			}
		}
	case []any:
		for _, item := range t {
			if s, ok := item.(string); ok && strings.TrimSpace(s) != "" {
				tokens = append(tokens, strings.TrimSpace(s))
			}
		}
	}
	if len(tokens) == 0 {
		jsonOut(w, 400, map[string]any{"detail": "请输入至少一个 Token / API Key"})
		return
	}

	var added []any
	existing := map[string]bool{}
	for _, a := range app.DefaultStore.ListAccounts(provider) {
		existing[a.ID] = true
	}
	seen := map[string]bool{}
	for _, tok := range tokens { // 去重保序（dict.fromkeys）
		if seen[tok] {
			continue
		}
		seen[tok] = true
		name := DictGetStrM(payload, "name", "")
		if name == "" {
			name = fmt.Sprintf("%s-%d", provider, len(app.DefaultStore.ListAccounts(provider))+1)
		}
		acc, err := app.DefaultStore.AddAccount(provider, name, tok)
		if err == nil {
			added = append(added, acc.ID)
		}
	}
	// 立即刷新一次额度（仅 zai jwt）
	var fresh []*app.Account
	addedSet := map[string]bool{}
	for _, id := range added {
		addedSet[fmt.Sprintf("%v", id)] = true
	}
	for _, a := range app.DefaultStore.ListAccounts(provider) {
		if addedSet[a.ID] && a.Mode == "jwt" {
			fresh = append(fresh, a)
		}
	}
	if len(fresh) > 0 {
		app.RefreshAccounts(fresh)
	}
	// 真新增（id 不在加号前的集合里；重复 token 返回旧账号自动跳过）
	for _, a := range app.DefaultStore.ListAccounts(provider) {
		if addedSet[a.ID] && !existing[a.ID] {
			app.ScheduleInstall(a) // 按账号安装序（含 apiKey 账号，幂等）
			if a.Mode == "jwt" {
				s.scheduleAutoClaim(a) // 授权完成即激活+自动领取，入池即吃满活动
			}
		}
	}
	jsonOut(w, 200, map[string]any{"count": len(added), "ids": added})
}

// handleDeleteAccounts DELETE /admin/api/accounts
func (s *Server) handleDeleteAccounts(w http.ResponseWriter, r *http.Request) {
	dec := json.NewDecoder(r.Body)
	dec.UseNumber()
	var ids []any
	_ = dec.Decode(&ids)
	deleted := 0
	for _, rawID := range ids {
		aid := fmt.Sprintf("%v", rawID)
		if acc := app.DefaultStore.FindAny(aid); acc != nil && app.DefaultStore.RemoveAccount(acc.Provider, aid) {
			deleted++
		}
	}
	jsonOut(w, 200, map[string]any{"deleted": deleted})
}

// handleEditAccount PUT /admin/api/accounts/{account_id}
func (s *Server) handleEditAccount(w http.ResponseWriter, r *http.Request) {
	accountID := r.PathValue("account_id")
	acc := app.DefaultStore.FindAny(accountID)
	if acc == nil {
		jsonOut(w, 404, map[string]any{"detail": "账号不存在"})
		return
	}
	payload, jresp := decodeJSONBody(r)
	if jresp != nil {
		jsonOut(w, 400, map[string]any{"detail": jresp.body})
		return
	}
	if name := DictGetStrM(payload, "name", ""); name != "" {
		acc.Name = strings.TrimSpace(name)
	}
	secret := DictGetStrM(payload, "token", "")
	if secret == "" {
		secret = DictGetStrM(payload, "secret", "")
	}
	if secret != "" {
		secret = strings.TrimSpace(secret)
		isJWT := strings.Count(secret, ".") == 2 && acc.Provider == "zai"
		if isJWT {
			acc.Mode = "jwt"
			acc.JWTToken = secret
			// 换 JWT 不清已有 API Key：OAuth 兑换出的回退通道要保住
		} else {
			acc.Mode = "apiKey"
			acc.APIKey = secret
			acc.JWTToken = ""
		}
		acc.Status = app.StatusActive
		acc.LastError = ""
	}
	// 网关并发上限（账号级）：显式给出 concurrency 键才改；≥1 上限，0 = 不限
	if raw, has := payload["concurrency"]; has {
		if n, ok := app.AsInt(raw); ok && n >= 0 {
			acc.Concurrency = n
		}
	}
	// 出站代理：显式给出 proxy 键才改（空串 = 清除，跟随全局/直连）
	if raw, has := payload["proxy"]; has {
		proxy, _ := raw.(string)
		proxy = strings.TrimSpace(proxy)
		if proxy != "" {
			normalized, perr := app.NormalizeProxyRaw(proxy)
			if perr != nil {
				jsonOut(w, 400, map[string]any{"detail": perr.Error()})
				return
			}
			proxy = normalized
		}
		if proxy != acc.Proxy {
			acc.Proxy = proxy
			// 出口变更：旧出口的验证码 token 作废（新出口签发的才与请求同源）
			app.DefaultCaptchaManager.Invalidate(app.EgressTagForAccount(acc))
		}
	}
	app.DefaultStore.UpdateAccount(acc)
	jsonOut(w, 200, map[string]any{"ok": true})
}

// handleSetEnabled POST /admin/api/accounts/{account_id}/enabled
func (s *Server) handleSetEnabled(w http.ResponseWriter, r *http.Request) {
	accountID := r.PathValue("account_id")
	acc := app.DefaultStore.FindAny(accountID)
	if acc == nil {
		jsonOut(w, 404, map[string]any{"detail": "账号不存在"})
		return
	}
	payload, jresp := decodeJSONBody(r)
	if jresp != nil {
		jsonOut(w, 400, map[string]any{"detail": jresp.body})
		return
	}
	enabled := true
	if b, ok := payload["enabled"].(bool); ok {
		enabled = b
	}
	app.DefaultStore.SetEnabled(acc.Provider, accountID, enabled)
	jsonOut(w, 200, map[string]any{"ok": true})
}

// handleRotateFingerprint POST /admin/api/accounts/{account_id}/fingerprint/rotate
//
// 换发账号客户端指纹（下一套设备模板 + 全新 device_mid）。
//
// 场景：账号被风控后换设备重生；或怀疑指纹污染时手动更换。
func (s *Server) handleRotateFingerprint(w http.ResponseWriter, r *http.Request) {
	accountID := r.PathValue("account_id")
	acc := app.DefaultStore.FindAny(accountID)
	if acc == nil {
		jsonOut(w, 404, map[string]any{"detail": "账号不存在"})
		return
	}
	old := app.ProfileFor(acc)
	profile := app.Rotate(acc)
	acc.InstalledAt = nil // 换机后必须重跑安装序，旧 MID 的日活不能顶新设备
	app.DefaultStore.UpdateAccount(acc)
	app.ScheduleInstall(acc)
	oldMid, newMid := old.DeviceMid, profile.DeviceMid
	if len(oldMid) > 8 {
		oldMid = oldMid[:8]
	}
	if len(newMid) > 8 {
		newMid = newMid[:8]
	}
	app.LogInfo("fingerprint", fmt.Sprintf("账号 %s 指纹换发: %s/%s → %s/%s",
		acc.Name, old.PlatformFull(), oldMid, profile.PlatformFull(), newMid))
	jsonOut(w, 200, map[string]any{"ok": true, "fingerprint": acc.Fingerprint})
}

// ── 刷新额度（实时用量监控）─────────────────────────────────────────────────

// handleRefresh POST /admin/api/accounts/refresh
func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var payload map[string]any
	body, _ := readAll(r.Body)
	_ = r.Body.Close()
	if v := app.SafeJSON(string(body)); v != nil {
		payload, _ = v.(map[string]any)
	}
	if payload == nil {
		payload = map[string]any{}
	}
	var pool []*app.Account
	if all, ok := payload["all"].(bool); ok && all {
		for _, a := range app.DefaultStore.ListAccounts("zai") {
			if a.Mode == "jwt" {
				pool = append(pool, a)
			}
		}
	} else {
		ids := map[string]bool{}
		if rawIDs, ok := payload["ids"].([]any); ok {
			for _, id := range rawIDs {
				ids[fmt.Sprintf("%v", id)] = true
			}
		}
		for _, a := range app.DefaultStore.ListAccounts("") {
			if ids[a.ID] && a.Mode == "jwt" {
				pool = append(pool, a)
			}
		}
	}
	// 失效 / 风控禁用 / 冷却 一律不打 billing（冷却期零上游流量 + 废 JWT 不再 401）
	var targets []*app.Account
	skippedCooling, skippedInvalid := 0, 0
	for _, a := range pool {
		if a.AllowsBilling(0) {
			targets = append(targets, a)
		} else if a.IsCooling(0) {
			skippedCooling++
		} else {
			skippedInvalid++
		}
	}
	summary := app.RefreshAccounts(targets)
	jsonOut(w, 200, map[string]any{
		"summary":         summary,
		"count":           len(targets),
		"skipped_cooling": skippedCooling,
		"skipped_invalid": skippedInvalid,
	})
}

// handleRefreshOne POST /admin/api/accounts/{account_id}/refresh
func (s *Server) handleRefreshOne(w http.ResponseWriter, r *http.Request) {
	accountID := r.PathValue("account_id")
	acc := app.DefaultStore.FindAny(accountID)
	if acc == nil {
		jsonOut(w, 404, map[string]any{"detail": "账号不存在"})
		return
	}
	// 额度源按形态分流：JWT → billing 族（顺带刷 Coding 快照）；
	// 纯 API Key 账号（bigmodel 等）→ monitor 快照就是主账本（不走 billing 拦截门）
	if acc.Mode != "jwt" {
		res := app.FetchCodingLimits(acc)
		if res["error"] == nil {
			app.DefaultStore.UpdateAccount(acc)
		}
		_, hasErr := res["error"]
		jsonOut(w, 200, map[string]any{"ok": !hasErr, "result": res, "account": acc.PublicView()})
		return
	}
	if blocked := app.BillingBlockReason(acc, "上游刷新"); blocked != "" {
		jsonOut(w, 200, map[string]any{"ok": false, "message": blocked, "account": acc.PublicView()})
		return
	}
	res := app.FetchQuota(acc)
	_, hasErr := res["error"]
	jsonOut(w, 200, map[string]any{"ok": !hasErr, "result": res, "account": acc.PublicView()})
}

// handleCodingLimits GET /admin/api/accounts/{account_id}/coding_limits
//
// Coding 平面额度（api.z.ai monitor 端点，按 API Key 鉴权）。
//
// 与 billing 族是两套账本：Plan 通道额度看 `quota` 快照，API Key 直连
// api.z.ai 的额度只能从这里看。体验套餐号常返回「当前用户不存在 coding plan」。
func (s *Server) handleCodingLimits(w http.ResponseWriter, r *http.Request) {
	accountID := r.PathValue("account_id")
	acc := app.DefaultStore.FindAny(accountID)
	if acc == nil {
		jsonOut(w, 404, map[string]any{"detail": "账号不存在"})
		return
	}
	res := app.FetchCodingLimits(acc)
	_, hasErr := res["error"]
	out := map[string]any{"ok": !hasErr}
	for k, v := range res {
		out[k] = v
	}
	jsonOut(w, 200, out)
}

// ── OAuth 登录（Z.AI）────────────────────────────────────────────────────────
// 授权链接有效期：上游 cli/init 发起的流程约 5 分钟过期（zcode.z.ai 行为）。
// 会话过期后 poll 返回 {"status": "expired"}（幂等，可安全重试）。
const (
	loginFlowTTL         = 300.0 // 秒
	loginExchangeTimeout = 60.0  // 兑换 API Key 总时长上限（秒）
)

// loginFlowEntry 单进程内存态即可：登录会话不该跨进程存活，重启后用户重新生成链接。
type loginFlowEntry struct {
	flow    *app.ZaiAuthFlow
	created float64
	label   string
}

var (
	loginFlowsMu sync.Mutex
	loginFlows   = map[string]*loginFlowEntry{}
)

func loginGC() {
	now := app.NowFloat()
	loginFlowsMu.Lock()
	for fid, entry := range loginFlows {
		if now-entry.created > loginFlowTTL {
			delete(loginFlows, fid)
		}
	}
	loginFlowsMu.Unlock()
}

// handleLoginStart POST /admin/api/login/start：发起 Z.AI OAuth，返回授权链接供前端展示。
//
// payload 可选 {"label": "acct-1"} —— 作为账号名前缀入池，便于多号识别。
func (s *Server) handleLoginStart(w http.ResponseWriter, r *http.Request) {
	var payload map[string]any
	body, _ := readAll(r.Body)
	_ = r.Body.Close()
	if v := app.SafeJSON(string(body)); v != nil {
		payload, _ = v.(map[string]any)
	}
	if payload == nil {
		payload = map[string]any{}
	}
	label := []rune(strings.TrimSpace(DictGetStrM(payload, "label", "")))
	if len(label) > 32 {
		label = label[:32]
	}
	loginGC()
	flow := app.NewZaiAuthFlow("", "")
	flowID, authorizeURL, err := flow.Init()
	if err != nil {
		app.LogWarn("oauth", fmt.Sprintf("登录初始化失败: %T: %v", err, err))
		jsonOut(w, 502, map[string]any{"detail": fmt.Sprintf("登录初始化失败: %v", err)})
		return
	}
	loginFlowsMu.Lock()
	loginFlows[flowID] = &loginFlowEntry{flow: flow, created: app.NowFloat(), label: string(label)}
	loginFlowsMu.Unlock()
	app.LogInfo("oauth", fmt.Sprintf("发起登录 flow_id=%s label=%s", flowID, orDash(string(label))))
	jsonOut(w, 200, map[string]any{
		"flow_id":       flowID,
		"authorize_url": authorizeURL,
		"expires_in":    int(loginFlowTTL),
	})
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// handleLoginPoll GET /admin/api/login/poll/{flow_id}：轮询授权状态。
//
// JWT 入池后立即 ready，API Key 兑换/刷新在后台回填。
//
// 返回 status ∈ pending / ready / failed / expired。
// failed 附带 message（上游拒绝原因）；expired 表示会话超时需重新发起；
// 未知 flow_id 一律 expired（而非 404），前端据此提示重新生成链接。
// 官方 poll HTTP 4xx 视为终态 failed；5xx/网络抖动保持 pending 并打日志。
func (s *Server) handleLoginPoll(w http.ResponseWriter, r *http.Request) {
	flowID := r.PathValue("flow_id")
	loginGC()
	loginFlowsMu.Lock()
	entry, ok := loginFlows[flowID]
	loginFlowsMu.Unlock()
	if !ok {
		jsonOut(w, 200, map[string]any{"status": "expired"})
		return
	}
	flow := entry.flow
	data, err := flow.Poll(flowID)
	if err != nil {
		if se, isStatus := app.IsOAuthStatusError(err); isStatus {
			code := se.HTTPStatusCode()
			app.LogWarn("oauth", fmt.Sprintf("poll %s 上游 HTTP %d", flowID, code))
			if code >= 400 && code < 500 {
				loginFlowsMu.Lock()
				delete(loginFlows, flowID)
				loginFlowsMu.Unlock()
				// 3004（官方 poll 4xx 承载的会话过期）：明确映射 expired 让前端提示
				// 重新生成链接，不再归为 failed（zcode-switch poll 3004 语义同形）
				var bodyCode any
				if v := app.SafeJSON(func() string {
					// oauthRequest 已消费 body；状态错误仅带码，解析退化到 nil
					return ""
				}()); v != nil {
					bodyCode = v
				}
				if n, ok := app.AsInt(bodyCode); ok && n == 3004 {
					app.LogInfo("oauth", fmt.Sprintf("授权会话过期 flow_id=%s（上游 3004）", flowID))
					jsonOut(w, 200, map[string]any{"status": "expired", "message": "授权会话已过期，请重新生成授权链接"})
					return
				}
				jsonOut(w, 200, map[string]any{"status": "failed", "message": fmt.Sprintf("上游拒绝轮询（HTTP %d）", code)})
				return
			}
			jsonOut(w, 200, map[string]any{"status": "pending"})
			return
		}
		// 单次网络抖动按 pending 处理
		app.LogWarn("oauth", fmt.Sprintf("poll %s 抖动: %T", flowID, err))
		jsonOut(w, 200, map[string]any{"status": "pending"})
		return
	}

	state := DictGetStrM(data, "status", "")
	if state == "failed" {
		loginFlowsMu.Lock()
		delete(loginFlows, flowID)
		loginFlowsMu.Unlock()
		reason := DictGetStrM(data, "message", "")
		if reason == "" {
			reason = DictGetStrM(data, "reason", "")
		}
		if reason == "" {
			reason = "授权失败或被拒绝"
		}
		app.LogWarn("oauth", fmt.Sprintf("授权失败 flow_id=%s: %s", flowID, reason))
		jsonOut(w, 200, map[string]any{"status": "failed", "message": reason})
		return
	}
	if state != "ready" {
		jsonOut(w, 200, map[string]any{"status": "pending"})
		return
	}

	// 会话先摘除再入池：并发/重复 poll 不会再进入兑换链。
	loginFlowsMu.Lock()
	delete(loginFlows, flowID)
	loginFlowsMu.Unlock()

	// JWT 先入池并立刻 ready；兑换 API Key / 额度刷新改后台，避免卡住前端下一轮 poll。
	zcodeJWT := DictGetStrM(data, "token", "")
	accessToken := ""
	if zai, ok := data["zai"].(map[string]any); ok {
		accessToken = DictGetStrM(zai, "access_token", "")
	}
	label := entry.label
	if label == "" {
		label = "oauth-login"
	}
	var account *app.Account
	if zcodeJWT != "" {
		account, _ = app.DefaultStore.AddAccount("zai", label, zcodeJWT)
	} else if accessToken != "" {
		key, err := withTimeoutExchange(flow, accessToken)
		if err != nil {
			app.LogWarn("oauth", fmt.Sprintf("无 JWT 时兑换 API Key 失败: %v", err))
		} else {
			account, _ = app.DefaultStore.AddAccount("zai", label, key)
		}
	}

	if account == nil {
		app.LogWarn("oauth", fmt.Sprintf("授权结果无凭证 flow_id=%s", flowID))
		jsonOut(w, 200, map[string]any{"status": "failed", "message": "未能从授权结果中获取凭证"})
		return
	}

	if account.Mode == "jwt" {
		s.scheduleAutoClaim(account) // 授权完成即激活+自动领取，入池即吃满活动
	}
	app.ScheduleInstall(account) // 按账号安装序（幂等；apiKey 账号同样安装）
	s.scheduleLoginFollowup(account, flow, func() string {
		if zcodeJWT != "" {
			return ""
		}
		return accessToken
	}())
	app.LogInfo("oauth", fmt.Sprintf("授权成功入池 %s (%s) mode=%s", account.Name, account.ID, account.Mode))
	jsonOut(w, 200, map[string]any{"status": "ready", "account": account.PublicView()})
}

// withTimeoutExchange 对齐 asyncio.wait_for(flow.exchange_api_key(...), timeout=60)。
func withTimeoutExchange(flow *app.ZaiAuthFlow, accessToken string) (key string, err error) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		key, err = flow.ExchangeAPIKey(accessToken)
	}()
	select {
	case <-done:
		return
	case <-time.After(loginExchangeTimeout * time.Second):
		return "", fmt.Errorf("兑换超时（%ds）", int(loginExchangeTimeout))
	}
}

// ── 后台任务调度（对齐 _schedule_login_followup / _schedule_auto_claim）──────

// scheduleLoginFollowup ready 后后台兑换 API Key 并刷新额度；失败只打日志，不影响已入池的 JWT。
func (s *Server) scheduleLoginFollowup(account *app.Account, flow *app.ZaiAuthFlow, accessToken string) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() { _ = recover() }()
		live := app.DefaultStore.Find("zai", account.ID)
		if live == nil {
			return
		}
		if accessToken != "" {
			key, err := withTimeoutExchange(flow, accessToken)
			if err != nil {
				app.LogWarn("oauth", fmt.Sprintf("账号 %s 兑换 API Key 失败: %v", account.Name, err))
			} else {
				live = app.DefaultStore.Find("zai", account.ID)
				if live == nil {
					return
				}
				live.APIKey = key
				app.DefaultStore.UpdateAccount(live)
			}
		}
		live = app.DefaultStore.Find("zai", account.ID)
		if live == nil {
			return
		}
		if live.Mode == "jwt" {
			app.RefreshAccounts([]*app.Account{live})
		}
	}()
}

// scheduleAutoClaim 入池后调度后台自动领取（激活上报 + 全量可领套餐）。
//
// 不阻塞入池响应（验证码求解可长达数十秒）；仅 JWT 账号。失败不影响入池。
func (s *Server) scheduleAutoClaim(account *app.Account) {
	if !(account.Mode == "jwt" && account.JWTToken != "") {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() {
			if rr := recover(); rr != nil {
				app.LogWarn("claim", fmt.Sprintf("账号 %s 自动领取任务异常: %v", account.Name, rr))
			}
		}()
		live := app.DefaultStore.Find(account.Provider, account.ID)
		if live == nil {
			return
		}
		outcomes := app.AutoClaimAllPlans(live, nil)
		live = app.DefaultStore.Find(account.Provider, account.ID)
		if live == nil {
			return
		}
		if len(outcomes) > 0 {
			app.RefreshAccounts([]*app.Account{live}) // 领到额度立即反映到 UI
		}
	}()
}

// jwtAccounts 对齐 _jwt_accounts(account_ids)。
func (s *Server) jwtAccounts(accountIDs []string) []*app.Account {
	accounts := app.DefaultStore.ListAccounts("zai")
	if len(accountIDs) > 0 {
		wanted := map[string]bool{}
		for _, id := range accountIDs {
			wanted[id] = true
		}
		var filtered []*app.Account
		for _, a := range accounts {
			if wanted[a.ID] {
				filtered = append(filtered, a)
			}
		}
		accounts = filtered
	}
	var out []*app.Account
	for _, a := range accounts {
		if a.Mode == "jwt" && a.JWTToken != "" {
			out = append(out, a)
		}
	}
	return out
}

// handleClaimPreview GET /admin/api/claim/preview：立即拉取可领取套餐（全部/单个 JWT 账号）。
//
// 先上报激活事件（zcode-switch claim_refresh 同形，模拟官方客户端当日活跃；
// 疑似活动投放资格信号），上报失败不阻断 preview。
func (s *Server) handleClaimPreview(w http.ResponseWriter, r *http.Request) {
	var ids []string
	if v := r.URL.Query().Get("account_id"); v != "" {
		ids = []string{v}
	}
	out := []any{}
	for _, acc := range s.jwtAccounts(ids) {
		if blocked := app.BillingBlockReason(acc, "上游查询"); blocked != "" {
			out = append(out, map[string]any{
				"account_id": acc.ID, "account_name": acc.Name,
				"plans": []any{}, "error": blocked,
				"activated": false, "activation_error": nil,
			})
			continue
		}
		activationError := ""
		if err := app.ReportActivationEvents(acc); err != "" {
			activationError = err
		}
		activated := activationError == ""
		var activationErrAny any
		if activationError != "" {
			activationErrAny = activationError
		}
		plans, err := app.PreviewPlans(acc)
		if err != nil {
			out = append(out, map[string]any{
				"account_id": acc.ID, "account_name": acc.Name,
				"plans": []any{}, "error": err.Error(),
				"activated": activated, "activation_error": activationErrAny,
			})
			continue
		}
		out = append(out, map[string]any{
			"account_id": acc.ID, "account_name": acc.Name,
			"plans": plans, "error": nil,
			"activated": activated, "activation_error": activationErrAny,
		})
	}
	jsonOut(w, 200, map[string]any{"preview": out})
}

// handleClaim POST /admin/api/claim：领取套餐（body 可选 account_ids / plan_id）。
//
// 缺省对全部 JWT 账号自动选最优套餐。
// 返回 outcomes[]：{account_id, account_name, ok, plan_name?, grants?, message?}。
func (s *Server) handleClaim(w http.ResponseWriter, r *http.Request) {
	var payload map[string]any
	body, _ := readAll(r.Body)
	_ = r.Body.Close()
	if v := app.SafeJSON(string(body)); v != nil {
		payload, _ = v.(map[string]any)
	}
	if payload == nil {
		payload = map[string]any{}
	}
	var accountIDs []string
	if rawIDs, ok := payload["account_ids"].([]any); ok {
		for _, id := range rawIDs {
			accountIDs = append(accountIDs, fmt.Sprintf("%v", id))
		}
	}
	planID := strings.TrimSpace(DictGetStrM(payload, "plan_id", ""))
	candidates := s.jwtAccounts(accountIDs)
	if len(candidates) == 0 {
		jsonOut(w, 200, map[string]any{"outcomes": []any{}, "summary": map[string]any{"ok": 0, "fail": 0}})
		return
	}

	// 冷却 / 失效 JWT 不领取（billing/claim 是上游写流量，废票只会 401）
	outcomes := []any{}
	for _, a := range candidates {
		if !a.AllowsBilling(0) {
			msg := app.BillingBlockReason(a, "领取")
			if msg == "" {
				msg = app.AuthExpiredMessage
			}
			outcomes = append(outcomes, map[string]any{
				"account_id": a.ID, "account_name": a.Name, "ok": false, "message": msg,
			})
		}
	}
	for _, acc := range candidates {
		if !acc.AllowsBilling(0) {
			continue
		}
		result, err := app.ClaimPlan(acc, planID)
		if err != nil {
			switch e := err.(type) {
			case *app.ClaimError:
				app.LogWarn("claim", fmt.Sprintf("账号 %s 领取失败: %s", acc.Name, e.Message))
				outcome := map[string]any{
					"account_id": acc.ID, "account_name": acc.Name,
					"ok": false, "message": e.Message,
				}
				if e.Code != -1 {
					outcome["code"] = e.Code
				}
				if e.NextAt != nil {
					outcome["next_at"] = *e.NextAt
				}
				outcomes = append(outcomes, outcome)
			case *app.CaptchaSolveError:
				// 验证码求解失败（get_verify_param）：明确业务回执而非裸 500
				app.LogErr("claim", fmt.Sprintf("账号 %s 领取失败: %s", acc.Name, e.Message))
				outcomes = append(outcomes, map[string]any{
					"account_id": acc.ID, "account_name": acc.Name,
					"ok": false, "message": e.Message,
				})
			default:
				// 兜底：captcha 层历史语义的运行时故障，防回归裸 500
				app.LogErr("claim", fmt.Sprintf("账号 %s 领取失败: %v", acc.Name, err))
				outcomes = append(outcomes, map[string]any{
					"account_id": acc.ID, "account_name": acc.Name,
					"ok": false, "message": err.Error(),
				})
			}
			continue
		}
		app.RefreshAccounts([]*app.Account{acc})
		merged := map[string]any{
			"account_id": acc.ID, "account_name": acc.Name, "ok": true,
		}
		for k, v := range result {
			merged[k] = v
		}
		outcomes = append(outcomes, merged)
	}
	okCount := 0
	for _, o := range outcomes {
		if b, ok := o.(map[string]any)["ok"].(bool); ok && b {
			okCount++
		}
	}
	jsonOut(w, 200, map[string]any{"outcomes": outcomes, "summary": map[string]any{"ok": okCount, "fail": len(outcomes) - okCount}})
}

// handleClaimCaptchaConfig GET /admin/api/claim/captcha-config
//
// 手动领取用：阿里验证码 SDK 初始化参数（前端浏览器内完成人机验证）。
func (s *Server) handleClaimCaptchaConfig(w http.ResponseWriter, r *http.Request) {
	// claim 全链路走直连（billing 请求 trust_env=False），验证码配置同源拉取
	config, _ := app.DefaultCaptchaManager.FetchConfig(app.EgressDirect)
	enabled := true
	if b, ok := config["enabled"].(bool); ok {
		enabled = b
	}
	jsonOut(w, 200, map[string]any{
		"enabled":  enabled,
		"scene_id": DictGetStrM(config, "sceneId", ""),
		"region":   DictGetStrM(config, "region", ""),
		"prefix":   DictGetStrM(config, "prefix", ""),
	})
}

// handleClaimManual POST /admin/api/claim/manual
//
// 手动领取：body {account_id, captcha_verify_param, captcha_region?, plan_id?}。
// verify_param 必须来自用户浏览器内阿里 SDK 滑块成功回调（无头环境无法求解）。
func (s *Server) handleClaimManual(w http.ResponseWriter, r *http.Request) {
	payload, jresp := decodeJSONBody(r)
	if jresp != nil {
		jsonOut(w, 400, map[string]any{"detail": jresp.body})
		return
	}
	accountID := strings.TrimSpace(DictGetStrM(payload, "account_id", ""))
	verifyParam := strings.TrimSpace(DictGetStrM(payload, "captcha_verify_param", ""))
	region := strings.TrimSpace(DictGetStrM(payload, "captcha_region", ""))
	planID := strings.TrimSpace(DictGetStrM(payload, "plan_id", ""))
	if accountID == "" {
		jsonOut(w, 400, map[string]any{"detail": "缺少 account_id"})
		return
	}
	acc := app.DefaultStore.Find("zai", accountID)
	if acc == nil || acc.Mode != "jwt" || acc.JWTToken == "" {
		jsonOut(w, 404, map[string]any{"detail": "JWT 账号不存在"})
		return
	}
	if blocked := app.BillingBlockReason(acc, "领取"); blocked != "" {
		jsonOut(w, 200, map[string]any{
			"outcomes": []any{map[string]any{
				"account_id": acc.ID, "account_name": acc.Name, "ok": false, "message": blocked,
			}},
			"summary": map[string]any{"ok": 0, "fail": 1},
		})
		return
	}
	result, err := app.ClaimWithCaptcha(acc, verifyParam, region, planID)
	if err != nil {
		jsonOut(w, 200, map[string]any{
			"outcomes": []any{map[string]any{
				"account_id": acc.ID, "account_name": acc.Name, "ok": false, "message": err.Error(),
			}},
			"summary": map[string]any{"ok": 0, "fail": 1},
		})
		return
	}
	app.RefreshAccounts([]*app.Account{acc})
	jsonOut(w, 200, map[string]any{
		"outcomes": []any{func() map[string]any {
			m := map[string]any{"account_id": acc.ID, "account_name": acc.Name, "ok": true}
			for k, v := range result {
				m[k] = v
			}
			return m
		}()},
		"summary": map[string]any{"ok": 1, "fail": 0},
	})
}

// ── 设置 ─────────────────────────────────────────────────────────────────────

// maskSecret 对齐 _mask_secret。
func maskSecret(value string) string {
	if value == "" {
		return ""
	}
	if len(value) <= 8 {
		return "••••"
	}
	return value[:4] + "…" + value[len(value)-4:]
}

// handleGetSettings GET /admin/api/settings
func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	adminKey := app.DefaultStore.AdminKey()
	gatewayKey := app.DefaultStore.GatewayKey()
	autoSyncRaw := fmt.Sprintf("%v", app.DefaultStore.GetSetting("auto_sync_client_version",
		strings.ToLower(fmt.Sprintf("%v", app.AUTO_SYNC_CLIENT_VERSION))))
	autoSync := autoSyncRaw == "true"
	latest := app.DefaultVersionTracker.LatestVersionSnapshot()
	latestVer := app.ClientAppVersion()
	if latest != nil {
		latestVer = latest.Version
	}
	hasUpdate := latest != nil && app.IsNewerVersion(latest.Version, app.ClientAppVersion())

	var releaseDate, releaseName, releaseNotes string
	var checkedAt float64
	if latest != nil {
		releaseDate = latest.ReleaseDate
		releaseName = latest.ReleaseName
		releaseNotes = latest.ReleaseNotes
		checkedAt = latest.CheckedAt
	}
	jsonOut(w, 200, map[string]any{
		"admin_key_set":            adminKey != "",
		"admin_key_masked":         maskSecret(adminKey),
		"admin_key_is_default":     adminKey != "" && adminKey == app.DEFAULT_ADMIN_KEY,
		"gateway_key_set":          gatewayKey != "",
		"gateway_key_masked":       maskSecret(gatewayKey),
		"quota_refresh_interval":   app.DefaultStore.QuotaRefreshInterval(),
		"claim_round_interval":     app.DefaultStore.ClaimRoundInterval(),
		"claim_round_hours":        joinInts(app.DefaultStore.ClaimRoundHours()),
		"auto_route":               app.DefaultStore.AutoRouteEnabled(),
		"auto_sync_client_version": autoSync,
		"zcode_client_version":     app.ClientAppVersion(),
		"zcode_latest_version":     latestVer,
		"zcode_version_has_update": hasUpdate,
		"zcode_release_date":       releaseDate,
		"zcode_release_name":       releaseName,
		"zcode_release_notes":      releaseNotes,
		"zcode_version_checked_at": checkedAt,
	})
}

func joinInts(list []int) string {
	parts := make([]string, 0, len(list))
	for _, n := range list {
		parts = append(parts, fmt.Sprintf("%d", n))
	}
	return strings.Join(parts, ",")
}

// handleUpdateSettings PUT /admin/api/settings
func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	payload, jresp := decodeJSONBody(r)
	if jresp != nil {
		jsonOut(w, 400, map[string]any{"detail": jresp.body})
		return
	}
	bad := func(msg string) { jsonOut(w, 400, map[string]any{"detail": msg}) }
	if v, has := payload["admin_key"]; has {
		key := strings.TrimSpace(fmt.Sprintf("%v", v))
		if key == "" || key == "<nil>" {
			bad("后台密钥不能为空")
			return
		}
		// 前端回填的掩码，不改密
		if strings.Contains(key, "…") || key == "••••" {
			// pass
		} else {
			app.DefaultStore.SetSetting("admin_key", key)
		}
	}
	if v, has := payload["gateway_key"]; has {
		key := strings.TrimSpace(fmt.Sprintf("%v", v))
		if strings.Contains(key, "…") || key == "••••" || key == "<nil>" {
			// pass
		} else if key == "" {
			app.DefaultStore.SetSetting("gateway_key", "")
		} else {
			app.DefaultStore.SetSetting("gateway_key", key)
		}
	}
	if v, has := payload["quota_refresh_interval"]; has {
		n, ok := app.AsInt(v)
		if !ok || n < 0 {
			bad("刷新间隔必须是非负整数")
			return
		}
		app.DefaultStore.SetSetting("quota_refresh_interval", fmt.Sprintf("%d", n))
	}
	if v, has := payload["claim_round_interval"]; has {
		n, ok := app.AsInt(v)
		if !ok || n < 0 {
			bad("自动领取轮间隔必须是非负整数（0 = 关闭）")
			return
		}
		app.DefaultStore.SetSetting("claim_round_interval", fmt.Sprintf("%d", n))
	}
	if v, has := payload["claim_round_hours"]; has {
		// 领取窗口（北京时间小时，逗号分隔；空 / * = 全天）。归一成升序去重后落库。
		raw := strings.TrimSpace(fmt.Sprintf("%v", v))
		if raw == "<nil>" {
			raw = ""
		}
		var hours []int
		if raw != "" && raw != "*" {
			for _, part := range strings.Split(strings.ReplaceAll(raw, "，", ","), ",") {
				part = strings.TrimSpace(part)
				if part == "" {
					continue
				}
				hour, err := parseHour(part)
				if err != nil {
					bad("领取窗口小时必须是 0-23 的整数，逗号分隔（空 = 全天）")
					return
				}
				if hour < 0 || hour > 23 {
					bad("领取窗口小时必须在 0-23 之间")
					return
				}
				if !containsInt(hours, hour) {
					hours = append(hours, hour)
				}
			}
		}
		sortIntsAsc(hours)
		app.DefaultStore.SetSetting("claim_round_hours", joinInts(hours))
	}
	if v, has := payload["auto_route"]; has {
		if b, ok := v.(bool); ok {
			app.DefaultStore.SetSetting("auto_route", fmt.Sprintf("%v", b))
		}
	}
	if v, has := payload["auto_sync_client_version"]; has {
		enabled := false
		if b, ok := v.(bool); ok {
			enabled = b
		}
		if enabled {
			app.DefaultStore.SetSetting("auto_sync_client_version", "true")
		} else {
			app.DefaultStore.SetSetting("auto_sync_client_version", "false")
		}
	}
	jsonOut(w, 200, map[string]any{"ok": true})
}

func parseHour(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("非数字")
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func sortIntsAsc(list []int) {
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && list[j] < list[j-1]; j-- {
			list[j-1], list[j] = list[j], list[j-1]
		}
	}
}

// ── ZCode 官方版本与更新日志 ────────────────────────────────────────────────
// 版本状态（当前/最新/更新日志）由 GET /settings 统一返回（前端 settings.html
// 直接消费）；此处只保留手动核验动作接口。版本伪装值完全由 version_tracker
// 自动对齐官方 manifest，不提供手工改写入口（避免脱离单一真相源）。

// handleCheckZcodeVersionNow POST /admin/api/version/zcode/check
func (s *Server) handleCheckZcodeVersionNow(w http.ResponseWriter, r *http.Request) {
	// force=true：管理后台「立即核验」语义，跳过新鲜度缓存强制拉取
	if err := app.DefaultVersionTracker.CheckAndSync(true); err != nil {
		jsonOut(w, 200, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	// 对齐 Python：check_and_sync 直接返回 dict；Go 版结果存于 last_result，
	// 通过 CheckAndSyncResult 取出
	jsonOut(w, 200, app.DefaultVersionTracker.LastResult())
}

// ── 导入 / 导出 ─────────────────────────────────────────────────────────────

// handleExport GET /admin/api/export
func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, 200, app.DefaultStore.Export())
}

// handleImport POST /admin/api/import
//
// 三种形态兼容：
//  1. {"providers": ...} —— 明文 providers JSON（旧前端行为）
//  2. {"content": "<文件原文>", "password": "..."} —— 文件原文文本（providers JSON 或 .zsb）
//  3. 直接把 .zsb envelope 当 body（kdf+cipher 字段）+ password
func (s *Server) handleImport(w http.ResponseWriter, r *http.Request) {
	payload, jresp := decodeJSONBody(r)
	if jresp != nil {
		jsonOut(w, 400, map[string]any{"detail": jresp.body})
		return
	}
	// content 形态：文件原文（前端导入按钮走这里，支持 .json / .zsb）
	if content := DictGetStrM(payload, "content", ""); content != "" {
		var doc map[string]any
		if err := json.Unmarshal([]byte(content), &doc); err != nil {
			jsonOut(w, 400, map[string]any{"detail": fmt.Sprintf("文件内容不是有效 JSON: %v", err)})
			return
		}
		if app.IsSealedBundle(doc) {
			inner, err := app.OpenZsbBundle(doc, DictGetStrM(payload, "password", ""))
			if err != nil {
				jsonOut(w, 400, map[string]any{"detail": err.Error()})
				return
			}
			doc = app.ZsbToProviders(inner)
		}
		payload = doc
	} else if app.IsSealedBundle(payload) {
		// envelope 直投形态
		inner, err := app.OpenZsbBundle(payload, DictGetStrM(payload, "password", ""))
		if err != nil {
			jsonOut(w, 400, map[string]any{"detail": err.Error()})
			return
		}
		payload = app.ZsbToProviders(inner)
	}
	if _, ok := payload["providers"]; !ok {
		jsonOut(w, 400, map[string]any{"detail": "无法识别的导入内容：需要 providers JSON 或 .zsb 加密封包"})
		return
	}
	existing := map[string]bool{}
	for _, a := range app.DefaultStore.ListAccounts("") {
		existing[a.ID] = true
	}
	count := app.DefaultStore.ImportAccounts(payload)
	// 导入的新账号：zai 走安装序 + JWT 激活+自动领取（幂等：重复 token 不新增）；
	// bigmodel 账号无 zai 安装序，只计数
	added := 0
	for _, a := range app.DefaultStore.ListAccounts("") {
		if !existing[a.ID] {
			added++
			if a.Provider == "zai" {
				app.ScheduleInstall(a)
				if a.Mode == "jwt" {
					s.scheduleAutoClaim(a)
				}
			}
		}
	}
	// 口径：count = 处理数（含重复 token 去重命中）；added = 真正新增；skipped = 已存在
	jsonOut(w, 200, map[string]any{"count": count, "added": added, "skipped": count - added})
}

// ── 请求监控 ─────────────────────────────────────────────────────────────────

// handleMonitoring GET /admin/api/monitoring：网关请求环形日志（内存态，重启清零）。
func (s *Server) handleMonitoring(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, 200, map[string]any{"entries": app.ReqLogSnapshot(), "keep": app.ReqLogKeep})
}

// handleMonitoringClear POST /admin/api/monitoring/clear
func (s *Server) handleMonitoringClear(w http.ResponseWriter, r *http.Request) {
	app.ReqLogClear()
	jsonOut(w, 200, map[string]any{"ok": true})
}

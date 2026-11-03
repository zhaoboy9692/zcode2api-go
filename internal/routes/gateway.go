// Package routes — 核心网关：/v1/messages（Anthropic 风格）与
// /v1/chat/completions（OpenAI 风格）。
//
// 共用多账号轮询 + 额度用完自动换号 + 阿里无痕验证自动续期；OpenAI 端点由
// openai_compat 做双向格式转换，调度与错误处理策略完全一致。
//
// 对齐 Python app/routes/gateway.py（1053 行）：调度器、单账号并发限制、
// 验证码三形态挑战、风控指数退避、429/5xx 重试策略、API Key 回退、
// HTTP 200 业务错误识别、SSE 三路流式透传/转换。
package routes

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zhaoboy9692/zcode2api-go/internal/app"
)

const (
	maxCaptchaRetries   = 3
	maxAccountAttempts  = 5
)

// jsonOut 把响应写成 FastAPI JSONResponse 等价形态（紧凑、无 HTML 转义）。
func jsonOut(w http.ResponseWriter, status int, body any) {
	b, err := app.JSONMarshalCompact(body)
	if err != nil {
		b = []byte(`{"error":{"message":"响应序列化失败","type":"internal_error"}}`)
		status = http.StatusInternalServerError
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// JSONResponse 内部错误响应载体（对齐 JSONResponse(status_code=..., body=...)）。
type JSONResponse struct {
	status int
	body   any
}

// upstreamOrResult 调度结果：_Upstream（成功）或 JSONResponse（错误）。
// Python 以对象类型区分；Go 以 kind 字段区分。
type dispatchResult struct {
	kind resultKind // 0=upstream, 1=json, 2=next account
	up   *Upstream
	json *JSONResponse
}

type resultKind int

const (
	kindUpstream resultKind = iota
	kindJSON
	kindNextAccount
)

// detectProvider 对齐 _detect_provider(body, headers)。
func detectProvider(body map[string]any, headerFn func(string) string) string {
	model := ""
	if m, ok := body["model"].(string); ok {
		model = m
	}
	if strings.HasPrefix(model, "bigmodel/") || headerFn("x-provider") == "bigmodel" {
		return "bigmodel"
	}
	return "zai"
}

// normalizeBody 对齐 _normalize_body：模型别名改写 / max_tokens 钳制 / content 字符串桥接。
func normalizeBody(body map[string]any) map[string]any {
	if model, ok := body["model"].(string); ok && strings.Contains(model, "/") {
		parts := strings.Split(model, "/")
		body["model"] = strings.Join(parts[1:], "/")
	}
	if model, ok := body["model"].(string); ok {
		// 先按大小写别名改写，再兜底「已退役型号」→ 当前主力型号。上游对退役名
		// 一律 3006（model not allowed），原样透传只会让客户端拿必然失败的结果。
		mapped, ok := app.MODEL_NAME_MAP[strings.ToLower(model)]
		if !ok {
			mapped = model
		}
		if alias, ok := app.RETIRED_MODEL_ALIASES[mapped]; ok {
			mapped = alias
		}
		if mapped != model {
			app.LogWarn("gateway", fmt.Sprintf("模型 %s → %s（别名/退役型号改写）", model, mapped))
			body["model"] = mapped
		}
	}

	// 上游对 max_tokens 有硬校验（400 code 1210），钳制到合法区间并记录钳制动作
	if raw := body["max_tokens"]; raw != nil {
		if _, isBool := raw.(bool); !isBool { // Python: not isinstance(raw, bool)
			if f, ok := app.AsFloat(raw); ok { // int(float(raw))
				mt := int(f)
				clamped := mt
				if clamped < 1 {
					clamped = 1
				}
				if clamped > app.MAX_TOKENS_LIMIT {
					clamped = app.MAX_TOKENS_LIMIT
				}
				if clamped != mt {
					app.LogWarn("gateway", fmt.Sprintf("max_tokens %d 超出上游范围 [1,%d]，钳制为 %d",
						mt, app.MAX_TOKENS_LIMIT, clamped))
				}
				body["max_tokens"] = clamped
			}
		}
	}

	if messages, ok := body["messages"].([]any); ok {
		var bridged []any
		for _, rawMsg := range messages {
			if msg, ok := rawMsg.(map[string]any); ok {
				if content, ok := msg["content"].(string); ok {
					m := map[string]any{}
					for k, v := range msg {
						m[k] = v
					}
					m["content"] = []any{map[string]any{"type": "text", "text": content}}
					bridged = append(bridged, m)
					continue
				}
			}
			bridged = append(bridged, rawMsg)
		}
		body["messages"] = bridged
	}
	return body
}

func isStr(v any) bool {
	_, ok := v.(string)
	return ok
}

// isCaptchaError 对齐 _is_captcha_error(text)。
func isCaptchaError(text string) bool {
	low := strings.ToLower(text)
	return strings.Contains(low, "captcha") || strings.Contains(low, "verify token") || strings.Contains(low, "verify failed")
}

// detectCaptchaChallenge 验证码挑战双检测（对齐 zapi handler.ts / gateway._detect_captcha_challenge）。
//
// 三种形态：
//  1. 响应头 x-aliyun-captcha-verify-param 存在（官方挑战信号）
//  2. HTTP 400/403 + body {"code":3007}（2026-08 观测的 body 内挑战）
//  3. HTTP 403 + 文案 captcha/verify（老检测，保留兼容）
//
// 返回挑战标记（非 "" 即挑战），否则 ""。
func detectCaptchaChallenge(headerFn func(string) string, statusCode int, text *string) string {
	// 1) challenge 响应头
	headerVal := headerFn(app.CAPTCHA_HEADER)
	if strings.TrimSpace(headerVal) != "" {
		return "header"
	}
	if text == nil {
		return ""
	}
	low := strings.ToLower(*text)
	// 2) body code 3007（400/403 任意状态）
	if statusCode == 400 || statusCode == 403 {
		for _, m := range app.CAPTCHA_BODY_MARKERS {
			if strings.Contains(*text, m) {
				return "in-body-3007"
			}
		}
	}
	// 3) 403 + 挑战文案
	if statusCode == 403 && isCaptchaError(low) {
		return "text"
	}
	return ""
}

// isExhausted 对齐 _is_exhausted(status_code, text)。
func isExhausted(statusCode int, text string) bool {
	// 429 是频控信号，优先于一切 body 关键词：429 body 带额度文案时
	//（api.z.ai 实测形态）必须走频控重试，不得判成额度耗尽踢号。
	if statusCode == 429 {
		return false
	}
	for _, s := range app.EXHAUST_HTTP_STATUSES {
		if s == statusCode {
			return true
		}
	}
	// 业务码优先：Plan 通道 1005/1113 实测形态 {"code":1005,"msg":"exceed quota limit"}
	if data, ok := app.SafeJSON(text).(map[string]any); ok {
		if code, has := data["code"]; has {
			if n, ok := app.AsInt(code); ok {
				for _, c := range app.EXHAUST_BUSINESS_CODES {
					if n == c {
						return true
					}
				}
			}
		}
	}
	low := strings.ToLower(text)
	for _, k := range app.EXHAUST_KEYWORDS {
		if strings.Contains(low, strings.ToLower(k)) {
			return true
		}
	}
	return false
}

// isRiskControl 风控信号判定（3012「unusual activity」/ messages 端点 405）。
//
// 与验证码挑战互斥：调用点已先排除 challenge 形态。命中即账号级风控，
// 需指数退避冷却，而非直接回传客户端错误（会导致下次立刻重打、加剧风控）。
func isRiskControl(statusCode int, text string) bool {
	for _, s := range app.RISK_CONTROL_HTTP_STATUSES {
		if s == statusCode {
			return true
		}
	}
	low := strings.ToLower(text)
	for _, m := range app.RISK_CONTROL_MARKERS {
		if strings.Contains(low, strings.ToLower(m)) {
			return true
		}
	}
	return false
}

// isConcurrencyHit 429 body 是否为 3009「模型并发已满」（区别于真频控，等待策略不同）。
//
// 业务码必须解析后精确比较：logid 是 20 位随机数字，裸子串 "3009" 会撞车
//（constants.CONCURRENCY_BUSINESS_CODE 注记的同款教训）；非 JSON 形态退回
// 文案匹配兜底。
func isConcurrencyHit(text string) bool {
	code, ok := app.BusinessCode(app.SafeJSON(text))
	if ok && code == app.CONCURRENCY_BUSINESS_CODE {
		return true
	}
	return strings.Contains(strings.ToLower(text), "concurrency limit")
}

// parseRetryAfter 解析 Retry-After（仅秒数形态；HTTP-date 形态少见，放弃即用默认重试等待）。
//
// 非正数不采信；超长值封顶采信 —— 尊重上游意图的同时防止把客户端吊死。
func parseRetryAfter(value string) (int, bool) {
	if value == "" {
		return 0, false
	}
	f, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return 0, false
	}
	secs := int(f)
	if secs <= 0 {
		return 0, false
	}
	if secs > app.RETRY_429_WAIT_MAX {
		secs = app.RETRY_429_WAIT_MAX
	}
	return secs, true
}

// markAccount 对齐 _mark(account, status, error)。
func markAccount(account *app.Account, statusValue string, errMsg string) {
	account.Status = statusValue
	account.LastError = errMsg
	if statusValue == app.StatusCooling {
		until := app.NowFloat() + float64(app.COOLING_SECONDS)
		account.CoolingUntil = &until
	}
	app.DefaultStore.UpdateAccount(account)
}

// lastUserText 对齐 _last_user_text(body)。
func lastUserText(body map[string]any) string {
	messages, ok := body["messages"].([]any)
	if !ok {
		return ""
	}
	for i := len(messages) - 1; i >= 0; i-- {
		msg, ok := messages[i].(map[string]any)
		if !ok || msg["role"] != "user" {
			continue
		}
		switch content := msg["content"].(type) {
		case string:
			return content
		case []any:
			for _, part := range content {
				if p, ok := part.(map[string]any); ok && p["type"] == "text" {
					if t, ok := p["text"].(string); ok {
						return t
					}
					return ""
				}
			}
		}
	}
	return ""
}

// Upstream 已建立的上游成功流：由调用方消费并负责关闭（对齐 _Upstream）。
type Upstream struct {
	resp        *http.Response
	client      *http.Client
	tFirst      *float64
	accountName string
	mode        string
	onClose     func()
	mu          interface{}
	closed      bool
}

// Close 幂等关闭：释放上游流与并发槽位（on_close），重复调用安全。
//
// resp/client 可能为 nil（200 业务错误的正文已读净并包成内存响应），
// 只释放仍然存在的部分。
func (u *Upstream) Close() {
	if u.closed {
		return
	}
	u.closed = true
	if u.resp != nil && u.resp.Body != nil {
		_ = u.resp.Body.Close()
	}
	if u.client != nil {
		if tr, ok := u.client.Transport.(*http.Transport); ok {
			tr.CloseIdleConnections()
		}
	}
	if u.onClose != nil {
		func() {
			defer func() { _ = recover() }() // 槽位释放失败不掩盖主流程
			u.onClose()
		}()
	}
}

// StatusCode 上游响应状态码。
func (u *Upstream) StatusCode() int {
	if u.resp == nil {
		return 200
	}
	return u.resp.StatusCode
}

// streamRaw 原样透传（/v1/messages 直通路径，对齐 to_streaming）。
func (u *Upstream) streamRaw(w http.ResponseWriter, r *http.Request, reqID string) {
	defer u.Close()
	w.Header().Set("Content-Type", headerGet(u.resp, "Content-Type", "application/json"))
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(u.resp.StatusCode)
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		select {
		case <-r.Context().Done():
			// 客户端断开 → 499 收口
			app.ReqLogFinishError(reqID, "客户端断开", app.IntPtr(499), u.tFirst)
			return
		default:
		}
		n, err := u.resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				app.ReqLogFinishError(reqID, "客户端断开", app.IntPtr(499), u.tFirst)
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			if err.Error() == "EOF" || n == 0 {
				app.LogReqOK(reqID, 0)
				app.ReqLogFinishOK(reqID, u.tFirst, nil, nil, app.IntPtr(u.resp.StatusCode))
			} else {
				app.LogReqErr(reqID, fmt.Sprintf("流传输中断: %v", err))
				app.ReqLogFinishError(reqID, fmt.Sprintf("流传输中断: %v", err), nil, u.tFirst)
			}
			return
		}
	}
}

func headerGet(resp *http.Response, key, def string) string {
	if v := resp.Header.Get(key); v != "" {
		return v
	}
	return def
}

// ── 账号并发限制 ─────────────────────────────────────────────────────────────

var (
	inflightMu sync.Mutex
	inflight   = map[string]int{} // account_id → 在飞请求数
)

func inflightGet(id string) int {
	inflightMu.Lock()
	defer inflightMu.Unlock()
	return inflight[id]
}

func inflightInc(id string) {
	inflightMu.Lock()
	inflight[id]++
	inflightMu.Unlock()
}

// releaseSlot 对齐 _release_slot。
func releaseSlot(accountID string) {
	inflightMu.Lock()
	n := inflight[accountID] - 1
	if n <= 0 {
		delete(inflight, accountID)
	} else {
		inflight[accountID] = n
	}
	inflightMu.Unlock()
}

// parkSlot 等待（429/验证码/5xx）前释放并发槽，避免把账号冻住数分钟。
func parkSlot(slotBox *string) {
	if slotBox != nil && *slotBox != "" {
		releaseSlot(*slotBox)
		*slotBox = ""
	}
}

// reacquireSlot 等待结束后重新占槽；占不到则让调用方换号。
func reacquireSlot(account *app.Account, slotBox *string) bool {
	if slotBox == nil {
		return true
	}
	limit := app.DefaultStore.AccountConcurrency()
	if limit <= 0 {
		return true
	}
	if inflightGet(account.ID) >= limit {
		return false
	}
	inflightInc(account.ID)
	*slotBox = account.ID
	return true
}

// limit 当前并发上限（0 = 不限），实时读取设置（后台改后即生效）。
func limit() int { return app.DefaultStore.AccountConcurrency() }

// ── 后台任务（对齐 _spawn_bg / _safe_refresh）───────────────────────────────

func spawnBg(f func()) {
	go func() {
		defer func() { _ = recover() }()
		f()
	}()
}

// safeRefresh 对齐 _safe_refresh(account)。
func safeRefresh(account *app.Account) {
	defer func() { _ = recover() }()
	live := app.DefaultStore.Find(account.Provider, account.ID)
	if live == nil {
		return
	}
	if live.Provider == "zai" && live.AllowsBilling(0) {
		// 去抖：每条消息都刷 billing 是流量放大器（会加剧风控），与 monitor 共享
		// last_checked_at，最小间隔内的刷新直接跳过
		last := live.LastCheckedAt
		if last != nil && app.NowFloat()-*last < float64(app.BILLING_REFRESH_MIN_INTERVAL) {
			return
		}
		app.FetchQuota(live)
	}
}

// handleListModels GET /v1/models（Anthropic /v1/models 风格）。
func (s *Server) handleListModels(w http.ResponseWriter, r *http.Request) {
	data := make([]any, 0, len(app.AVAILABLE_MODELS))
	for _, m := range app.AVAILABLE_MODELS {
		data = append(data, map[string]any{
			"id":           m,
			"type":         "model",
			"display_name": m,
			"created_at":   "2025-01-01T00:00:00Z",
		})
	}
	jsonOut(w, 200, map[string]any{"object": "list", "data": data})
}

// decodeJSONBody 对齐 `await request.json()`：ClientDisconnect / 非法 JSON 统一报 400。
func decodeJSONBody(r *http.Request) (map[string]any, *JSONResponse) {
	dec := json.NewDecoder(r.Body)
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, &JSONResponse{status: 400, body: map[string]any{
			"error": map[string]any{"message": "请求体不是合法 JSON", "type": "invalid_request"},
		}}
	}
	dict, ok := v.(map[string]any)
	if !ok {
		return nil, &JSONResponse{status: 400, body: map[string]any{
			"error": map[string]any{"message": "请求体必须是 JSON 对象", "type": "invalid_request_error"},
		}}
	}
	return dict, nil
}

// handleMessages POST /v1/messages。
func (s *Server) handleMessages(w http.ResponseWriter, r *http.Request) {
	body, jresp := decodeJSONBody(r)
	if jresp != nil {
		jsonOut(w, jresp.status, jresp.body)
		return
	}

	incomingHeaders := incomingHeaderMap(r)
	provider := detectProvider(body, func(k string) string { return r.Header.Get(k) })
	body = normalizeBody(body)

	reqID := randHex(8)
	model := "-"
	if m, ok := body["model"].(string); ok && m != "" {
		model = m
	}
	stream := false
	if b, ok := body["stream"].(bool); ok {
		stream = b
	}
	app.LogReq(reqID, model, stream, lastUserText(body))
	app.ReqLogBegin(reqID, "messages", model, stream, lastUserText(body))

	result := s.dispatch(reqID, body, incomingHeaders, provider, r)
	if result.kind == kindNextAccount { // 不应发生（dispatch 收尾自兜）
		app.ReqLogFinishError(reqID, "无可用账号 / 额度均已耗尽 / 并发已满", app.IntPtr(503), nil)
		jsonOut(w, 503, noAvailableAccountBody())
		return
	}
	if result.kind == kindJSON {
		jsonOut(w, result.json.status, result.json.body)
		return
	}
	// 流式透传
	result.up.streamRaw(w, r, reqID)
}

func noAvailableAccountBody() map[string]any {
	return map[string]any{
		"error": map[string]any{
			"message": "所有账号均不可用、额度已用完或并发已满，请在后台检查账号状态",
			"type":    "no_available_account",
		},
	}
}

// incomingHeaderMap 对齐 dict(request.headers)：小写键 → 值（多值取首个）。
func incomingHeaderMap(r *http.Request) map[string]string {
	out := map[string]string{}
	for k, vs := range r.Header {
		if len(vs) > 0 {
			out[strings.ToLower(k)] = vs[0]
		}
	}
	if h := r.Host; h != "" {
		out["host"] = h
	}
	return out
}

func randHex(n int) string {
	return randHexImpl(n)
}

// ── OpenAI 风格端点公共骨架（/v1/chat/completions 与 /v1/responses 共用）─────
//
// 流程：解析 JSON → translate(payload) 得 anthropic body → 归一 → 调度
//（多账号/重试/验证码与 /v1/messages 同一条路径）→ 按客户端要求走流式或
// 非流式消费。三方差异全部参数化：
//
//	translate(payload) -> (anthropic_body, err)
//	streamHook(up, model, req_id) -> 流式写出
//	finalize(data, model) -> 非流式：anthropic message → 客户端格式
func (s *Server) runCompatEndpoint(w http.ResponseWriter, r *http.Request, kind string,
	translate func(map[string]any) (map[string]any, string),
	streamHook func(*Upstream, string, string, http.ResponseWriter, *http.Request),
	finalize func(map[string]any, string) map[string]any) {

	payload, jresp := decodeJSONBody(r)
	if jresp != nil {
		jsonOut(w, jresp.status, jresp.body)
		return
	}
	body, terr := translate(payload)
	if terr != "" || body == nil {
		jsonOut(w, 400, map[string]any{
			"error": map[string]any{"message": func() string {
				if terr != "" {
					return terr
				}
				return "请求体不合法"
			}(), "type": "invalid_request_error"},
		})
		return
	}

	incomingHeaders := incomingHeaderMap(r)
	provider := detectProvider(body, func(k string) string { return r.Header.Get(k) })
	body = normalizeBody(body)

	reqID := randHex(8)
	model := "-"
	if m, ok := body["model"].(string); ok && m != "" {
		model = m
	}
	stream := false
	if b, ok := payload["stream"].(bool); ok {
		stream = b
	}
	app.LogReq(reqID, model, stream, lastUserText(body))
	app.ReqLogBegin(reqID, kind, model, stream, lastUserText(body))

	result := s.dispatch(reqID, body, incomingHeaders, provider, r)
	if result.kind == kindNextAccount {
		app.ReqLogFinishError(reqID, "无可用账号 / 额度均已耗尽 / 并发已满", app.IntPtr(503), nil)
		jsonOut(w, 503, noAvailableAccountBody())
		return
	}
	if result.kind == kindJSON {
		jsonOut(w, result.json.status, result.json.body)
		return
	}

	modelName := ""
	if m, ok := body["model"].(string); ok {
		modelName = m
	}
	if stream {
		streamHook(result.up, modelName, reqID, w, r)
		return
	}

	// 非流式：读净上游响应
	up := result.up
	defer up.Close()
	raw, err := readAll(up.resp.Body)
	if err != nil {
		app.LogReqErr(reqID, fmt.Sprintf("读取上游响应失败: %v", err))
		app.ReqLogFinishError(reqID, fmt.Sprintf("读取上游响应失败: %v", err), app.IntPtr(502), up.tFirst)
		jsonOut(w, 502, map[string]any{
			"error": map[string]any{"message": fmt.Sprintf("读取上游响应失败: %v", err), "type": "upstream_error"},
		})
		return
	}
	app.LogReqOK(reqID, 0)
	data, ok := app.SafeJSON(string(raw)).(map[string]any)
	if !ok || DictGetStrM(data, "type", "") != "message" {
		app.ReqLogFinishError(reqID, "上游响应格式异常", app.IntPtr(502), up.tFirst)
		jsonOut(w, 502, map[string]any{
			"error": map[string]any{"message": "上游响应格式异常", "type": "upstream_error"},
		})
		return
	}
	inputTokens, outputTokens := usageTokens(data)
	app.ReqLogFinishOK(reqID, up.tFirst, &inputTokens, &outputTokens, app.IntPtr(up.resp.StatusCode))
	jsonOut(w, 200, finalize(data, modelName))
}

func DictGetStrM(m map[string]any, key, def string) string {
	if m == nil {
		return def
	}
	if s, ok := m[key].(string); ok {
		return s
	}
	return def
}

func usageTokens(data map[string]any) (int, int) {
	inTok, outTok := 0, 0
	if usage, ok := data["usage"].(map[string]any); ok {
		if n, ok := app.AsInt(usage["input_tokens"]); ok {
			inTok = n
		}
		if n, ok := app.AsInt(usage["output_tokens"]); ok {
			outTok = n
		}
	}
	return inTok, outTok
}

// handleChatCompletions POST /v1/chat/completions（OpenAI Chat Completions 兼容端点）。
func (s *Server) handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	s.runCompatEndpoint(w, r, "chat",
		app.OpenAIToAnthropic,
		openaiStreamResponse,
		app.AnthropicToOpenAI,
	)
}

// translateResponses Responses → Chat Completions → Anthropic 两跳翻译。
func translateResponses(payload map[string]any) (map[string]any, string) {
	chat, err := app.ResponsesToChat(payload)
	if err != "" || chat == nil {
		return nil, err
	}
	return app.OpenAIToAnthropic(chat)
}

// handleResponses POST /v1/responses（OpenAI Responses API 兼容端点，入站 Responses → chat → anthropic，出站反向）。
func (s *Server) handleResponses(w http.ResponseWriter, r *http.Request) {
	s.runCompatEndpoint(w, r, "responses",
		translateResponses,
		responsesStreamResponse,
		func(data map[string]any, model string) map[string]any {
			return app.ChatToResponse(app.AnthropicToOpenAI(data, model), model)
		},
	)
}

// handleCountTokens POST /v1/messages/count_tokens：本地确定性估算。
//
// 上游（Plan 通道与 api.z.ai）**没有**这个端点（2026-11-02 实测 404），但
// Anthropic SDK / Claude Code 会先调它做上下文预算，缺了会直接中断会话。
// 这里只做估算：不占账号额度、不打上游、不需要可用账号（池空也能回）。
//
// 估算对象是 **transform 之后**的形状（含官方 system 三块 + 日期轮，
// 线上标定固定开销 ≈400 tok）——2026-11-03 实测：只算客户端原始 body 时
// 6 tok 的请求实际计费 341，预算严重失真。
func (s *Server) handleCountTokens(w http.ResponseWriter, r *http.Request) {
	body, jresp := decodeJSONBody(r)
	if jresp != nil {
		jsonOut(w, jresp.status, jresp.body)
		return
	}
	model, ok := body["model"].(string)
	if !ok || strings.TrimSpace(model) == "" {
		jsonOut(w, 400, map[string]any{
			"error": map[string]any{"message": "必须提供 model 参数", "type": "invalid_request_error"},
		})
		return
	}
	jsonOut(w, 200, map[string]any{
		"input_tokens": app.EstimateInputTokensAfterTransform(normalizeBody(body), model),
	})
}

// ── 流式转换端点（openai / responses）───────────────────────────────────────

// openaiStreamResponse 把上游 Anthropic SSE 事件流转换为 OpenAI chunk 流。
func openaiStreamResponse(up *Upstream, model, reqID string, w http.ResponseWriter, r *http.Request) {
	conv := app.NewStreamConverter(model)
	defer up.Close()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(200)
	flusher, _ := w.(http.Flusher)

	writeOut := func(lines []string) bool {
		for _, line := range lines {
			if _, err := w.Write([]byte(line)); err != nil {
				return false
			}
		}
		if flusher != nil {
			flusher.Flush()
		}
		return true
	}
	if !writeOut([]string{conv.Start()}) {
		return
	}
	err := scanSSE(up.resp.Body, r, func(evt map[string]any) bool {
		for _, out := range conv.Feed(evt) {
			if _, werr := w.Write([]byte(out)); werr != nil {
				return false
			}
		}
		if flusher != nil {
			flusher.Flush()
		}
		return true
	})
	if err != nil && r.Context().Err() != nil {
		app.ReqLogFinishError(reqID, "客户端断开", app.IntPtr(499), up.tFirst)
		return
	}
	if err != nil {
		app.LogReqErr(reqID, fmt.Sprintf("流传输中断: %v", err))
		app.ReqLogFinishError(reqID, fmt.Sprintf("流传输中断: %v", err), nil, up.tFirst)
		return
	}
	_, _ = w.Write([]byte(conv.Done()))
	if flusher != nil {
		flusher.Flush()
	}
	app.LogReqOK(reqID, 0)
	promptTokens := asIntAny(conv.Usage["prompt_tokens"])
	completionTokens := asIntAny(conv.Usage["completion_tokens"])
	app.ReqLogFinishOK(reqID, up.tFirst, promptTokens, completionTokens, app.IntPtr(up.resp.StatusCode))
}

// responsesStreamResponse 上游 Anthropic SSE → Responses 事件族（经 chat chunk 中转，复用两套转换器）。
func responsesStreamResponse(up *Upstream, model, reqID string, w http.ResponseWriter, r *http.Request) {
	chatConv := app.NewStreamConverter(model)
	respConv := app.NewResponsesStreamConverter(model)
	defer up.Close()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(200)
	flusher, _ := w.(http.Flusher)

	writeOut := func(lines []string) bool {
		for _, line := range lines {
			if _, err := w.Write([]byte(line)); err != nil {
				return false
			}
		}
		if flusher != nil {
			flusher.Flush()
		}
		return true
	}
	if !writeOut(respConv.Start()) {
		return
	}
	err := scanSSE(up.resp.Body, r, func(evt map[string]any) bool {
		for _, chunk := range chatConv.FeedEvents(evt) {
			if !writeOut(respConv.FeedChunk(chunk)) {
				return false
			}
		}
		return true
	})
	if err != nil && r.Context().Err() != nil {
		app.ReqLogFinishError(reqID, "客户端断开", app.IntPtr(499), up.tFirst)
		return
	}
	if err != nil {
		app.LogReqErr(reqID, fmt.Sprintf("流传输中断: %v", err))
		app.ReqLogFinishError(reqID, fmt.Sprintf("流传输中断: %v", err), nil, up.tFirst)
		return
	}
	writeOut(respConv.Done())
	app.LogReqOK(reqID, 0)
	promptTokens := asIntAny(chatConv.Usage["prompt_tokens"])
	completionTokens := asIntAny(chatConv.Usage["completion_tokens"])
	app.ReqLogFinishOK(reqID, up.tFirst, promptTokens, completionTokens, app.IntPtr(up.resp.StatusCode))
}

func asIntAny(v any) *int {
	if v == nil {
		return nil
	}
	if f, ok := app.AsFloat(v); ok {
		n := int(f)
		return &n
	}
	return nil
}

// scanSSE 逐行扫描 SSE 流（`data:` 行 → JSON 回调）；ctx 取消时返回错误。
func scanSSE(body ioReadCloser, r *http.Request, onEvent func(map[string]any) bool) error {
	scanner := bufio.NewScanner(body)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		if r != nil && r.Context().Err() != nil {
			return fmt.Errorf("客户端断开")
		}
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		dataStr := strings.TrimSpace(line[5:])
		if dataStr == "" {
			continue
		}
		if evt, ok := app.SafeJSON(dataStr).(map[string]any); ok {
			if !onEvent(evt) {
				return nil
			}
		}
	}
	return scanner.Err()
}

// ── 多账号轮询调度（对齐 _dispatch）─────────────────────────────────────────
//
// 单账号并发限制：选号后若该账号在飞请求已达上限（store.account_concurrency，
// 0 = 不限），跳过换下一个账号——不排队（流式请求可占槽位数分钟，排队会
// 放大延迟甚至吊死客户端）。满号跳过不计入 MAX_ACCOUNT_ATTEMPTS（只计真正
// 进入 _try_account 的次数）。全满/无号 → 503。
func (s *Server) dispatch(reqID string, body map[string]any, incomingHeaders map[string]string, provider string, r *http.Request) *dispatchResult {
	tried := map[string]bool{}
	limitVal := limit()
	attempts := 0

	for attempts < maxAccountAttempts {
		account := app.DefaultStore.Select(provider, tried)
		if account == nil {
			break
		}
		tried[account.ID] = true
		if limitVal > 0 && inflightGet(account.ID) >= limitVal {
			app.LogWarn(reqID, fmt.Sprintf("账号 %s 并发已满（%d/%d），切换下一个", account.Name, inflightGet(account.ID), limitVal))
			continue
		}
		attempts++
		// 结构上能否用到验证码（Plan 通道）；是否**真的带**由上游 captcha 配置决定：
		// 线上 skip_model_request=true ⇒ 官方客户端模型请求不带验证码头，hub 也必须不带
		//（带了就是「官方不会干的事」，3012 的结构性嫌疑）。上游若仍回 3007 要码，
		// _try_account 会补码重试。
		planChannel := provider == "zai" && account.UsesPlanChannel()
		needsCaptcha := false
		if planChannel {
			needsCaptcha = app.DefaultCaptchaManager.ModelRequestsNeedCaptcha(app.EgressFor(app.UPSTREAM["zai"]))
		}

		slotBox := ""
		if limitVal > 0 {
			inflightInc(account.ID)
			slotBox = account.ID
		}
		result := s.tryAccount(reqID, account, body, incomingHeaders, planChannel, needsCaptcha, &slotBox, r)
		if slotBox != "" {
			switch result.kind {
			case kindNextAccount:
				releaseSlot(slotBox)
			case kindUpstream:
				// 槽位随上游流关闭释放
				held := slotBox
				result.up.onClose = func() { releaseSlot(held) }
			case kindJSON:
				releaseSlot(slotBox)
			}
		}
		if result.kind == kindNextAccount {
			continue
		}
		return result
	}

	app.LogReqErr(reqID, "无可用账号 / 额度均已耗尽 / 并发已满")
	app.ReqLogFinishError(reqID, "无可用账号 / 额度均已耗尽 / 并发已满", app.IntPtr(503), nil)
	return &dispatchResult{kind: kindJSON, json: &JSONResponse{status: 503, body: noAvailableAccountBody()}}
}

// statusForBusinessCode 业务码 → 等价 HTTP 状态（复用已有错误分支，不另起一套处置）。
//
// 这里**不写死映射表**：风控码与额度码都取自 constants，改常量即同步生效，
// 不会出现「常量加了 1113、映射忘了」这类静默漂移（单测把两边对齐钉住）。
func statusForBusinessCode(code int) int {
	if code == app.RISK_BUSINESS_CODE {
		return app.RISK_CONTROL_HTTP_STATUSES[0]
	}
	for _, c := range app.EXHAUST_BUSINESS_CODES {
		if c == code {
			return app.EXHAUST_HTTP_STATUSES[0]
		}
	}
	return 400
}

// bufferedResponse 把已读净的正文包成内存响应，供下游按原语义消费。
//
// 去掉 content-encoding/content-length/transfer-encoding：正文已是解码后的
// 字节，保留这些头会让下游再解一次（httpx 对内存响应仍会解 content-encoding）。
// Go 版：http.ReadResponse 于内存 buffer 重放（保留原状态码与非剔除头）。
func bufferedResponse(resp *http.Response, raw []byte) *http.Response {
	drop := map[string]bool{"content-encoding": true, "content-length": true, "transfer-encoding": true}
	h := resp.Header.Clone()
	for k := range h {
		if drop[strings.ToLower(k)] {
			h.Del(k)
		}
	}
	cloned := *resp
	cloned.Header = h
	cloned.Body = newByteBody(raw)
	cloned.ContentLength = int64(len(raw))
	return &cloned
}

func newByteBody(b []byte) ioReadCloser {
	return &byteBody{data: b}
}

type byteBody struct {
	data []byte
	off  int
}

func (b *byteBody) Read(p []byte) (int, error) {
	if b.off >= len(b.data) {
		return 0, ioEOF
	}
	n := copy(p, b.data[b.off:])
	b.off += n
	return n, nil
}

func (b *byteBody) Close() error { return nil }

// tryAccount 尝试用单个账号转发，含验证码续期与可配置重试（对齐 _try_account）。
//
// 错误处理策略（参数见 settings，均可用环境变量调整）：
//   - 验证码挑战：清池换码重建请求，最多 MAX_CAPTCHA_RETRIES 次
//   - 429 频控：**不冷却账号**，按上游 Retry-After（封顶 RETRY_429_WAIT_MAX）
//     或 RETRY_429_WAIT 等待后原地重试，最多 RETRY_429_TIMES 次；
//     耗尽后换下一个账号，账号保持可用。Plan 通道耗尽且有 API Key 时切
//     回退通道重试（force_fallback 显式路由——429 不改账号状态，不能靠
//     status 推导通道；回退通道自己的 429 重试预算独立计满后再换号）
//   - 5xx 等一般错误：重试最多 RETRY_5XX_TIMES 次；耗尽后账号冷却
//     COOLING_SECONDS 并换下一个账号
//   - 风控（3012/405「unusual activity」）：指数退避冷却（base 900s 起，封顶
//     24h），累计 RISK_BAN_STRIKES 次升级禁用（UI 展示），人工确认恢复
func (s *Server) tryAccount(reqID string, account *app.Account, body map[string]any,
	incomingHeaders map[string]string, planChannel, needsCaptcha bool, slotBox *string, r *http.Request) *dispatchResult {

	captchaRetries := 0
	retries429 := 0
	retries5xx := 0
	forceFallback := false // 本请求瞬态走 Key 回退（不改账号持久化状态）
	modelName := "-"
	if m, ok := body["model"].(string); ok && m != "" {
		modelName = m
	}
	// 结构上是否 Plan 通道（决定「能不能用验证码」）；needs_captcha 只表示「这一趟带不带」
	// 验证码必须与本次 Plan 请求同出口（见 app/egress.go）；记下来供失败日志佐证
	captchaEgress := ""
	if planChannel {
		captchaEgress = app.EgressFor(app.UPSTREAM["zai"])
	}
	for {
		attemptT0 := app.NowFloat()
		app.ReqLogMarkAccount(reqID, account.Name, account.Mode)
		verifyParam := ""
		verifyRegion := ""
		if needsCaptcha {
			parkSlot(slotBox)
			// 验证码必须与本次 Plan 请求同出口：token 由某出口签发后，
			// 换出口使用会被上游判 unusual activity（3012）。
			vp, vr, err := app.DefaultCaptchaManager.GetVerifyParam(app.EgressFor(app.UPSTREAM["zai"]))
			if err != nil {
				app.LogReqErr(reqID, fmt.Sprintf("人机校验失败: %v", err))
				app.ReqLogFinishError(reqID, fmt.Sprintf("人机校验失败: %v", err), app.IntPtr(500), nil)
				return &dispatchResult{kind: kindJSON, json: &JSONResponse{
					status: 500,
					body: map[string]any{"error": map[string]any{
						"message": fmt.Sprintf("无法完成人机校验: %v", err), "type": "captcha_error"}},
				}}
			}
			verifyParam, verifyRegion = vp, vr
			if !reacquireSlot(account, slotBox) {
				app.LogWarn(reqID, fmt.Sprintf("账号 %s 验证码等待后并发已满，切换下一个", account.Name))
				return &dispatchResult{kind: kindNextAccount}
			}
		}

		build, err := app.BuildRequest(account, body, verifyParam, incomingHeaders, verifyRegion, forceFallback)
		if err != nil {
			account.RecordResult(false, fmt.Sprintf("凭证无效: %v", err), 20)
			markAccount(account, app.StatusInvalid, err.Error())
			app.LogWarn(reqID, fmt.Sprintf("账号 %s 凭证无效，切换下一个", account.Name))
			return &dispatchResult{kind: kindNextAccount}
		}

		client := &http.Client{Transport: gatewayTransport()}
		req, err := http.NewRequest(http.MethodPost, build.URL, newByteBody(build.Body))
		if err != nil {
			client.CloseIdleConnections()
			account.RecordResult(false, fmt.Sprintf("连接失败: %v", err), 20)
			if account.Status == app.StatusInvalid || account.Status == app.StatusDisabled {
				app.DefaultStore.UpdateAccount(account)
			} else {
				markAccount(account, app.StatusCooling, fmt.Sprintf("连接失败: %v", err))
			}
			app.LogWarn(reqID, fmt.Sprintf("账号 %s 连接失败，切换下一个", account.Name))
			return &dispatchResult{kind: kindNextAccount}
		}
		for k, v := range build.Headers {
			req.Header[k] = []string{v}
		}
		resp, err := client.Do(req)
		if err != nil {
			client.CloseIdleConnections()
			account.RecordResult(false, fmt.Sprintf("连接失败: %v", err), 20)
			// 废 JWT / 风控禁用走 Key 回退失败时不得洗成 cooling，否则冷却结束会重开 Plan
			if account.Status == app.StatusInvalid || account.Status == app.StatusDisabled {
				app.DefaultStore.UpdateAccount(account)
			} else {
				markAccount(account, app.StatusCooling, fmt.Sprintf("连接失败: %v", err))
			}
			app.LogWarn(reqID, fmt.Sprintf("账号 %s 连接失败，切换下一个", account.Name))
			return &dispatchResult{kind: kindNextAccount}
		}

		statusCode := resp.StatusCode
		var text *string

		// 200 承载业务错误：Plan 通道对额度/风控类拒绝直接回 HTTP 200 +
		// {"code":1005|3012,"msg":...}（2026-10-30 实测，content-type application/json）。
		// 不识别有两个后果：① 当成成功洗掉 risk_strikes / 冷却 / last_error，把仍在
		// 标记期的账号拉回 ACTIVE（「冷却期零上游流量」不变量被绕开）；② 错误体当正文
		// 透传，客户端拿到「200 但没有 message」。JSON 正文一次读净：合法响应改走内存
		// 流（下游消费逻辑不变），业务错误码映射成等价 HTTP 状态走下面统一分支。
		if statusCode < 400 && strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
			raw, _ := readAll(resp.Body)
			_ = resp.Body.Close()
			decoded := string(raw)
			data := app.SafeJSON(decoded)
			var code int
			var hasCode bool
			if dict, ok := data.(map[string]any); ok {
				code, hasCode = app.BusinessCode(dict)
			}
			if !hasCode {
				resp = bufferedResponse(resp, raw)
			} else {
				text = &decoded
				statusCode = statusForBusinessCode(code)
				app.LogWarn(reqID, fmt.Sprintf("账号 %s HTTP 200 承载业务错误 code=%d（按 %d 处置）：%s",
					account.Name, code, statusCode, truncateRuns(collapseSpace(decoded), 160)))
			}
		}

		if statusCode >= 400 {
			if text == nil {
				raw, _ := readAll(resp.Body)
				_ = resp.Body.Close()
				decoded := string(raw)
				text = &decoded
			}

			// 验证码挑战：三形态任一命中即清池重试（不改账号状态）。Plan 通道上
			// 即使这一趟没带码也要探测——若上游仍要求验证码，下一趟补码重试。
			challenge := ""
			if planChannel && !forceFallback {
				challenge = detectCaptchaChallenge(func(k string) string { return resp.Header.Get(k) }, statusCode, text)
			}
			if challenge != "" {
				app.DefaultCaptchaManager.Invalidate(app.EgressFor(app.UPSTREAM["zai"]))
				captchaRetries++
				if captchaRetries >= maxCaptchaRetries {
					account.RecordResult(false, "验证码挑战连续失败", 20)
					app.LogWarn(reqID, fmt.Sprintf("账号 %s 验证码连续失败，切换下一个", account.Name))
					return &dispatchResult{kind: kindNextAccount}
				}
				if !needsCaptcha {
					// 按配置本不该带码，但上游明确要码 → 下一趟补码
					needsCaptcha = true
					app.LogWarn(reqID, fmt.Sprintf("账号 %s 验证码挑战（%s），补码重试", account.Name, challenge))
				} else {
					app.LogWarn(reqID, fmt.Sprintf("账号 %s 验证码挑战（%s），刷新重试", account.Name, challenge))
				}
				continue // 同账号重建请求重试
			}

			// 风控（3012「unusual activity」/ 405）：指数退避冷却自动恢复，累计
			// RISK_BAN_STRIKES 次升级禁用（人工恢复）。不立即重试（避免对风控
			// 账号持续施压）；冷却期零上游流量（is_cooling 全通道门禁）。
			if isRiskControl(statusCode, *text) {
				// 405 一律按风控计（RISK_CONTROL_HTTP_STATUSES），所以必须把上游
				// body 留一段在日志里——否则分不清是 3012 标记、验证码挑战还是
				// WAF/签名拒绝，strikes 花完了仍不知道上游在拒什么。
				snippet := truncateRuns(collapseSpace(*text), 200)
				account.RecordResult(false, fmt.Sprintf("风控 HTTP %d（3012/unusual activity）", statusCode), 20)
				account.RiskPenalty(float64(app.RISK_COOLDOWN_BASE), float64(app.RISK_COOLDOWN_MAX),
					app.RISK_BAN_STRIKES, float64(app.RISK_STRIKE_DECAY_SECONDS))
				var penaltyNote string
				if account.Status == app.StatusDisabled {
					account.LastError = fmt.Sprintf(
						"风控封禁 (3012/unusual activity) HTTP %d，确认恢复后请在后台手动启用（第 %d 次）",
						statusCode, account.RiskStrikes)
					penaltyNote = fmt.Sprintf("已升级禁用（第 %d 次）", account.RiskStrikes)
					if app.RISK_AUTO_ROTATE {
						// 「风控后换设备重生」自动化：升级禁用即换发全新设备
						//（新 SKU + 新 device_mid），后台补跑安装序；账号重新
						// 启用时已是全新身份（billing/claim 头同源跟随档案）
						oldMid := app.ProfileFor(account).DeviceMid
						if len(oldMid) > 8 {
							oldMid = oldMid[:8]
						}
						app.Rotate(account)
						account.InstalledAt = nil
						app.ScheduleInstall(account)
						app.LogWarn(reqID, fmt.Sprintf("账号 %s 风控禁用，已自动换发设备指纹（旧 mid %s）",
							account.Name, oldMid))
					}
				} else {
					coolUntil := "?"
					if account.CoolingUntil != nil {
						coolUntil = time.Unix(int64(*account.CoolingUntil), 0).Format("15:04")
					}
					account.LastError = fmt.Sprintf(
						"命中风控 (3012/unusual activity) HTTP %d，指数退避冷却至 %s（第 %d 次）",
						statusCode, coolUntil, account.RiskStrikes)
					penaltyNote = fmt.Sprintf("冷却至 %s（第 %d 次）", coolUntil, account.RiskStrikes)
				}
				app.DefaultStore.UpdateAccount(account)
				if planChannel && !forceFallback && account.HasApikeyFallback() {
					app.LogWarn(reqID, fmt.Sprintf("账号 %s 命中风控 HTTP %d（出口=%s），%s，切 API Key 回退；上游body=%q",
						account.Name, statusCode, captchaEgress, penaltyNote, snippet))
					needsCaptcha = false
					forceFallback = true
					continue
				}
				app.LogWarn(reqID, fmt.Sprintf("账号 %s 命中风控 HTTP %d（出口=%s），%s，切换下一个；上游body=%q",
					account.Name, statusCode, captchaEgress, penaltyNote, snippet))
				return &dispatchResult{kind: kindNextAccount}
			}

			if isExhausted(statusCode, *text) {
				account.RecordResult(false, fmt.Sprintf("额度用完 HTTP %d", statusCode), 20)
				if account.Status == app.StatusInvalid || account.Status == app.StatusDisabled {
					app.DefaultStore.UpdateAccount(account)
				} else {
					markAccount(account, app.StatusExhausted, "额度已用完")
					acc := account
					spawnBg(func() { safeRefresh(acc) })
				}
				app.LogWarn(reqID, fmt.Sprintf("账号 %s 额度用完，切换下一个", account.Name))
				return &dispatchResult{kind: kindNextAccount}
			}

			if statusCode == 401 {
				account.RecordResult(false, "鉴权失败 HTTP 401", 20)
				markAccount(account, app.StatusInvalid, "鉴权失败 HTTP 401")
				if planChannel && !forceFallback && account.HasApikeyFallback() {
					app.LogWarn(reqID, fmt.Sprintf("账号 %s 鉴权失败 401，切 API Key 回退", account.Name))
					needsCaptcha = false
					forceFallback = true
					continue
				}
				app.LogWarn(reqID, fmt.Sprintf("账号 %s 鉴权失败 401，切换下一个", account.Name))
				return &dispatchResult{kind: kindNextAccount}
			}

			if statusCode == 403 {
				// 403 已排除挑战形态（上方 challenge 分支），此处为真实鉴权拒绝
				account.RecordResult(false, "鉴权失败 HTTP 403", 20)
				markAccount(account, app.StatusInvalid, "鉴权失败 HTTP 403")
				if planChannel && !forceFallback && account.HasApikeyFallback() {
					app.LogWarn(reqID, fmt.Sprintf("账号 %s 鉴权失败 403，切 API Key 回退", account.Name))
					needsCaptcha = false
					forceFallback = true
					continue
				}
				app.LogWarn(reqID, fmt.Sprintf("账号 %s 鉴权失败 403，切换下一个", account.Name))
				return &dispatchResult{kind: kindNextAccount}
			}

			if statusCode == 429 {
				// 1113「无余额/无资源包」是 Key 的永久状态（api.z.ai 实测秒回），
				// 原地等待重试毫无意义，只会把客户端吊死在 RETRY_429_TIMES×WAIT 里
				// ——快速换号/失败。
				lowText := strings.ToLower(*text)
				if strings.Contains(*text, "1113") || strings.Contains(lowText, "insufficient balance") {
					account.RecordResult(false, "429 1113 无余额（Key 无资源包，永久态）", 20)
					app.LogWarn(reqID, fmt.Sprintf("账号 %s 429 为 1113 无余额，跳过等待重试", account.Name))
					if planChannel && !forceFallback && account.HasApikeyFallback() {
						needsCaptcha = false
						forceFallback = true
						retries429 = 0
						continue
					}
					return &dispatchResult{kind: kindNextAccount}
				}
				// 频控不是账号故障：不冷却，原地等一等再试，耗尽后换号且账号保持可用。
				// Plan 通道耗尽 ≠ Key 回退也耗尽：同账号切回退并归还该通道的重试预算
				//（与上方 3012/401/403 切回退同一语义）
				if retries429 < app.RETRY_429_TIMES {
					retries429++
					// 3009「model concurrency limit exceeded」= 并发争用，不是频控：
					// 上游不给 Retry-After，槽位通常几秒内释放。等默认 60s 会把
					// 客户端白白吊死。短退避 + 抖动打散重试。
					concurrencyHit := isConcurrencyHit(*text)
					wait, ok := parseRetryAfter(resp.Header.Get("Retry-After"))
					if !ok {
						if concurrencyHit {
							wait = app.RETRY_429_CONCURRENCY_WAIT + rand.Intn(3)
						} else {
							wait = app.RETRY_429_WAIT
						}
					}
					if concurrencyHit {
						app.LogWarn(reqID, fmt.Sprintf("账号 %s 模型并发已满（3009），%ds 后重试（%d/%d）",
							account.Name, wait, retries429, app.RETRY_429_TIMES))
					} else {
						app.LogWarn(reqID, fmt.Sprintf("账号 %s 被限流 429，%ds 后重试（%d/%d）",
							account.Name, wait, retries429, app.RETRY_429_TIMES))
					}
					parkSlot(slotBox)
					time.Sleep(time.Duration(wait) * time.Second)
					if !reacquireSlot(account, slotBox) {
						app.LogWarn(reqID, fmt.Sprintf("账号 %s 429 等待后并发已满，切换下一个", account.Name))
						return &dispatchResult{kind: kindNextAccount}
					}
					continue
				}
				if planChannel && !forceFallback && account.HasApikeyFallback() {
					account.RecordResult(false, "Plan 通道 429 耗尽，切 API Key 回退", 20)
					app.LogWarn(reqID, fmt.Sprintf("账号 %s Plan 通道 429 耗尽，切 API Key 回退", account.Name))
					needsCaptcha = false
					forceFallback = true
					retries429 = 0
					continue
				}
				account.RecordResult(false, fmt.Sprintf("429 重试 %d 次耗尽", app.RETRY_429_TIMES), 20)
				app.DefaultStore.UpdateAccount(account)
				app.LogWarn(reqID, fmt.Sprintf("账号 %s 429 重试 %d 次耗尽，切换下一个（账号保持可用）",
					account.Name, app.RETRY_429_TIMES))
				return &dispatchResult{kind: kindNextAccount}
			}

			if statusCode >= 500 {
				// 一般性上游错误：重试，耗尽才冷却账号并换号
				if retries5xx < app.RETRY_5XX_TIMES {
					retries5xx++
					app.LogWarn(reqID, fmt.Sprintf("账号 %s 上游 HTTP %d，%ds 后重试（%d/%d）",
						account.Name, statusCode, app.RETRY_5XX_WAIT, retries5xx, app.RETRY_5XX_TIMES))
					parkSlot(slotBox)
					time.Sleep(time.Duration(app.RETRY_5XX_WAIT) * time.Second)
					if !reacquireSlot(account, slotBox) {
						app.LogWarn(reqID, fmt.Sprintf("账号 %s 5xx 等待后并发已满，切换下一个", account.Name))
						return &dispatchResult{kind: kindNextAccount}
					}
					continue
				}
				account.RecordResult(false, fmt.Sprintf("HTTP %d 重试 %d 次耗尽，冷却", statusCode, app.RETRY_5XX_TIMES), 20)
				if account.Status == app.StatusInvalid || account.Status == app.StatusDisabled || account.IsCooling(0) {
					// Key 回退 5xx 不得覆盖废 JWT / 风控禁用，否则冷却结束会重开 Plan；
					// 风控冷却同理（冷却期不覆盖，避免缩短风控退避）
					app.DefaultStore.UpdateAccount(account)
					app.LogWarn(reqID, fmt.Sprintf("账号 %s 上游 %d 重试耗尽，Plan 已停用，切换下一个", account.Name, statusCode))
				} else {
					cool := app.COOLING_SECONDS
					account.Status = app.StatusCooling
					until := app.NowFloat() + float64(cool)
					account.CoolingUntil = &until
					account.LastError = fmt.Sprintf("上游 HTTP %d 重试 %d 次耗尽，冷却", statusCode, app.RETRY_5XX_TIMES)
					app.DefaultStore.UpdateAccount(account)
					app.LogWarn(reqID, fmt.Sprintf("账号 %s 上游 %d 重试耗尽，冷却 %ds，切换下一个", account.Name, statusCode, cool))
				}
				return &dispatchResult{kind: kindNextAccount}
			}

			// 其它 4xx：直接回传客户端；响应体全量落日志供排查
			//（错误 JSON 通常很小；防御性上限 4KB，超长按 HTML 类 WAF 页处理只留头部）
			account.FailCount++
			account.RecordResult(false, truncateRuns(strings.ReplaceAll(fmt.Sprintf("HTTP %d: %s", statusCode, *text), "\n", " "), 120), 20)
			app.DefaultStore.UpdateAccount(account)
			app.LogReqErr(reqID, fmt.Sprintf("上游错误 HTTP %d（账号 %s）", statusCode, account.Name))
			bodyLog := *text
			if len(bodyLog) > 4000 {
				bodyLog = fmt.Sprintf("%s...(共 %d 字节，疑似 WAF 页)", bodyLog[:4000], len(bodyLog))
			}
			app.LogWarn(reqID, fmt.Sprintf("上游 %d 完整响应体: %s", statusCode, bodyLog))
			tFirst := app.NowFloat() - attemptT0
			app.ReqLogFinishError(reqID,
				truncateRuns(strings.ReplaceAll(fmt.Sprintf("HTTP %d: %s", statusCode, *text), "\n", " "), 120),
				app.IntPtr(statusCode), &tFirst)
			// 对齐 _safe_json(text) or {"error": ...}
			var outBody any
			if v := app.SafeJSON(*text); v != nil {
				outBody = v
			} else {
				outBody = map[string]any{"error": map[string]any{
					"message": truncateRuns(*text, 500), "type": "upstream_error"}}
			}
			return &dispatchResult{kind: kindJSON, json: &JSONResponse{status: statusCode, body: outBody}}
		}

		// 成功：记录用量并把打开的上游流交给调用方
		account.UseCount++
		lastUsed := app.NowFloat()
		account.LastUsedAt = &lastUsed
		account.RecordResult(true, fmt.Sprintf("HTTP 200 · %s · %.1fs", modelName, app.NowFloat()-attemptT0), 20)
		// API Key 回退成功不得把废 JWT / 风控禁用洗成 active，也不得清风控计数；
		// 风控冷却未到期同样不洗（上游风控标记为小时级粘性，回退通道成功不代表
		// Plan 通道已解除，洗掉会立刻重打 Plan 并累加计数）。冷却已过期后的
		// Plan 通道成功即证明恢复，全量清理（清风控计数）。
		if account.Status != app.StatusInvalid && account.Status != app.StatusDisabled && !account.IsCooling(0) {
			account.RiskStrikes = 0
			account.LastRiskAt = nil
			account.LastError = ""
			account.CoolingUntil = nil
			if account.Status == app.StatusCooling || account.Status == app.StatusExhausted {
				account.Status = app.StatusActive
			}
		}
		app.DefaultStore.UpdateAccount(account)
		acc := account
		spawnBg(func() { safeRefresh(acc) })

		tFirst := app.NowFloat() - attemptT0
		return &dispatchResult{
			kind: kindUpstream,
			up: &Upstream{
				resp:        resp,
				client:      client,
				tFirst:      &tFirst,
				accountName: account.Name,
				mode:        account.Mode,
			},
		}
	}
}

// gatewayTransport 对齐 httpx.Timeout(connect=30, read=None, write=120, pool=30)：
// 拨号/握手 30s，读不设超时（流式长连接），连接池空闲回收。
func gatewayTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment, // httpx trust_env=True
		DialContext:           dialerWithTimeout(30 * time.Second),
		TLSHandshakeTimeout:   30 * time.Second,
		ResponseHeaderTimeout: 0, // read=None
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   8,
	}
}

func collapseSpace(s string) string { return strings.Join(strings.Fields(s), " ") }

func truncateRuns(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// sort 包引用保留（未来排序扩展）
var _ = sort.Ints

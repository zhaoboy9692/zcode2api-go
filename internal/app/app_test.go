// 单元测试 — 对齐 Python tests/unit 高价值断言（回归基线）。
//
// 覆盖：constants 常量钉扎 / models 状态判定 / body_transform 幂等与结构 /
// token_estimate 口径 / openai_compat 与 responses_compat 双向转换 /
// version_tracker YAML 陷阱 / store.parse_hours / egress 语义 / claim 解析。
package app

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	// 测试数据隔离：数据目录指向临时目录（避免污染仓库）
	if os.Getenv("ZCODE_DATA_DIR") == "" {
		dir, _ := os.MkdirTemp("", "zcode2api-test-*")
		os.Setenv("ZCODE_DATA_DIR", dir)
		// settings 在包 init 已定型，仅影响 Store 创建路径 —— 重开数据目录
		DATA_DIR = dir
		DB_PATH = DATA_DIR + "/accounts.db"
	}
	InitStore()
	os.Exit(m.Run())
}

// ── constants（对齐 tests/unit/test_constants.py）────────────────────────────

func TestConstantsModelMap(t *testing.T) {
	if MODEL_NAME_MAP["glm-5.3-flash"] != "GLM-5.3-Flash" {
		t.Fatalf("glm-5.3-flash 映射错误: %v", MODEL_NAME_MAP["glm-5.3-flash"])
	}
	if MODEL_NAME_MAP["glm-5.2"] != "GLM-5.3" {
		t.Fatalf("退役别名 glm-5.2 应映射 GLM-5.3")
	}
	if RETIRED_MODEL_ALIASES["GLM-4.7"] != "GLM-5.3" {
		t.Fatalf("GLM-4.7 应映射 GLM-5.3")
	}
	if len(AVAILABLE_MODELS) != 2 {
		t.Fatalf("/v1/models 应只公布 2 个模型: %v", AVAILABLE_MODELS)
	}
}

func TestConstantsExhaustSignals(t *testing.T) {
	if len(EXHAUST_BUSINESS_CODES) != 2 { // 1005 + 1113
		t.Fatalf("EXHAUST_BUSINESS_CODES 应为 1005/1113: %v", EXHAUST_BUSINESS_CODES)
	}
	found := false
	for _, k := range EXHAUST_KEYWORDS {
		if k == "exceed quota" {
			found = true
		}
		if strings.Contains(k, "quota") && strings.Contains(k, "exceed") {
			// 定量短语而非裸词
			if k == "quota" {
				t.Fatalf("不应有裸词 quota 关键字")
			}
		}
	}
	if !found {
		t.Fatalf("缺少 'exceed quota' 关键字")
	}
	if CONCURRENCY_BUSINESS_CODE != 3009 || RISK_BUSINESS_CODE != 3012 {
		t.Fatalf("业务码常量漂移: 3009=%d 3012=%d", CONCURRENCY_BUSINESS_CODE, RISK_BUSINESS_CODE)
	}
	if MAX_TOKENS_LIMIT != 131072 {
		t.Fatalf("max_tokens 上限漂移")
	}
}

func TestSetActiveVersion(t *testing.T) {
	defer SetActiveVersion(DEFAULT_CLIENT_APP_VERSION)
	SetActiveVersion(" v3.17.2 ") // 剥 v 前缀与空白
	if ClientAppVersion() != "3.17.2" {
		t.Fatalf("SetActiveVersion 未剥离 v 前缀: %s", ClientAppVersion())
	}
	if UserAgent() != "ZCode/3.17.2" {
		t.Fatalf("UA 应为 ZCode/3.17.2: %s", UserAgent())
	}
	if ClientConfigsQuery() != "app_version=3.17.2" {
		t.Fatalf("configs query 未同步: %s", ClientConfigsQuery())
	}
}

// ── models（对齐 models 状态机）──────────────────────────────────────────────

func TestExpiresEpoch(t *testing.T) {
	if _, ok := ExpiresEpoch(nil); ok {
		t.Fatal("nil 应无效")
	}
	if _, ok := ExpiresEpoch(true); ok {
		t.Fatal("bool 应无效")
	}
	// epoch 秒
	v, ok := ExpiresEpoch(1793375999)
	if !ok || v != 1793375999 {
		t.Fatalf("epoch 秒解析错误: %v %v", v, ok)
	}
	// epoch 毫秒（> 1e11）
	v, _ = ExpiresEpoch(1793375999000.0)
	if v != 1793375999 {
		t.Fatalf("毫秒应除以 1000: %v", v)
	}
	// ISO8601 字符串
	v, ok = ExpiresEpoch("2026-01-01T00:00:00Z")
	if !ok || v <= 0 {
		t.Fatalf("ISO8601 解析失败: %v %v", v, ok)
	}
	expect := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	if int64(v) != expect {
		t.Fatalf("ISO8601 值不符: %v != %d", v, expect)
	}
	// 数字字符串
	v, _ = ExpiresEpoch("100.5")
	if v != 100.5 {
		t.Fatalf("数字字符串解析错误: %v", v)
	}
	// 非法
	if _, ok := ExpiresEpoch("garbage"); ok {
		t.Fatal("垃圾串应无效")
	}
}

func TestWindowUsableExpired(t *testing.T) {
	now := 1000.0
	if WindowUsable(nil, now) {
		t.Fatal("nil 窗口不可用")
	}
	// remaining > 0 且未过期
	if !WindowUsable(map[string]any{"remaining": 5.0, "expires_at": 2000.0}, now) {
		t.Fatal("有效窗口应可用")
	}
	// remaining = 0
	if WindowUsable(map[string]any{"remaining": 0.0, "expires_at": 2000.0}, now) {
		t.Fatal("零余额窗口不可用")
	}
	// remaining 缺失 = 未知但有量
	if !WindowUsable(map[string]any{"total": 10.0}, now) {
		t.Fatal("无 remaining 应视为有量")
	}
	// 已过期
	if WindowUsable(map[string]any{"remaining": 5.0, "expires_at": 500.0}, now) {
		t.Fatal("过期窗口不可用")
	}
	if !WindowExpired(map[string]any{"expires_at": 500.0}, now) {
		t.Fatal("应判过期")
	}
	if WindowExpired(map[string]any{"expires_at": "bad"}, now) {
		t.Fatal("不可解析的 expires_at = 不过期")
	}
}

func TestAccountQuotaExpired(t *testing.T) {
	// 空 quota = 未知，不判过期
	acc := AccountCreate("zai", "t", "a.b.c")
	if acc.QuotaExpired(0) {
		t.Fatal("空 quota 不判过期")
	}
	// 有余额且未过期 → 可用
	acc.Quota = map[string]any{"GLM-5.3-Flash": map[string]any{"remaining": 100.0, "expires_at": NowFloat() + 3600}}
	if acc.QuotaExpired(0) {
		t.Fatal("有有效窗口不判过期")
	}
	// 全部过期 + 过期后成功查过 → 判死
	past := NowFloat() - 86400*28
	verified := NowFloat() - 100
	acc.Quota = map[string]any{"GLM-5.3-Flash": map[string]any{"remaining": 1e8, "expires_at": past}}
	acc.QuotaVerifiedAt = &verified
	if !acc.QuotaExpired(0) {
		t.Fatal("过期后实查确认应判死（2.7.8 反例行为）")
	}
	// 全部过期但 verified_at 早于 expires_at → 快照过期，不判死
	olderVerified := past - 100
	acc.QuotaVerifiedAt = &olderVerified
	if acc.QuotaExpired(0) {
		t.Fatal("快照早于到期时间无资格判死（滚动日窗口径）")
	}
	// 余额归零 = 确定耗尽
	acc.Quota = map[string]any{"GLM-5.3-Flash": map[string]any{"remaining": 0.0, "expires_at": past}}
	acc.QuotaVerifiedAt = nil
	if !acc.QuotaExpired(0) {
		t.Fatal("余额归零应判耗尽")
	}
}

func TestAccountSelectableAndChannels(t *testing.T) {
	acc := AccountCreate("zai", "t", "a.b.c")
	if !acc.IsSelectable(0) {
		t.Fatal("新号应可选")
	}
	if !acc.UsesPlanChannel() {
		t.Fatal("JWT 账号应走 Plan 通道")
	}
	if acc.HasApikeyFallback() {
		t.Fatal("纯 JWT 无回退")
	}
	// apiKey 账号
	acc2 := AccountCreate("zai", "t2", "sk-key")
	if acc2.Mode != "apiKey" {
		t.Fatal("非 JWT 形态应识别为 apiKey")
	}
	if acc2.UsesPlanChannel() {
		t.Fatal("apiKey 账号不走 Plan 通道")
	}
	// disabled 不可选
	acc.Status = StatusDisabled
	if acc.IsSelectable(0) {
		t.Fatal("禁用不可选")
	}
	// disabled + API Key → 回退可选
	acc.APIKey = "sk-x"
	if !acc.IsSelectable(0) {
		t.Fatal("废 JWT + Key 应回退可选")
	}
}

func TestAccountRiskPenalty(t *testing.T) {
	acc := AccountCreate("zai", "t", "a.b.c")
	base, cap := 900.0, 86400.0
	acc.RiskPenalty(base, cap, 4, 7*86400)
	if acc.Status != StatusCooling || acc.RiskStrikes != 1 {
		t.Fatalf("第一次风控应 cooling: %s", acc.Status)
	}
	if acc.CoolingUntil == nil || *acc.CoolingUntil-NowFloat() < 899 {
		t.Fatal("第一次冷却应 ≈900s")
	}
	// 第二次 → 1800s
	acc.RiskPenalty(base, cap, 4, 7*86400)
	if acc.RiskStrikes != 2 {
		t.Fatal("strikes 应累计")
	}
	// 第四次 → 禁用
	acc.RiskPenalty(base, cap, 4, 7*86400)
	acc.RiskPenalty(base, cap, 4, 7*86400)
	if acc.Status != StatusDisabled {
		t.Fatalf("累计 4 次应禁用: %s", acc.Status)
	}
	if acc.CoolingUntil != nil {
		t.Fatal("禁用时清冷却")
	}
	// 跨衰减窗口清零重算
	old := NowFloat() - 8*86400
	acc2 := AccountCreate("zai", "t2", "a.b.c")
	acc2.LastRiskAt = &old
	acc2.RiskStrikes = 3
	acc2.RiskPenalty(base, cap, 4, 7*86400)
	if acc2.RiskStrikes != 1 {
		t.Fatal("超窗口应重新起算")
	}
}

func TestAccountPlanKind(t *testing.T) {
	acc := AccountCreate("zai", "t", "a.b.c")
	acc.Plan = map[string]any{"plan_id": "zcode-v3-start-plan-0817"}
	if acc.PlanKind() != "start-plan" {
		t.Fatalf("应识别 start-plan: %q", acc.PlanKind())
	}
	acc.Plans = []any{map[string]any{"plan_id": "zcode-v3-coding-plan-x"}}
	if acc.PlanKind() != "start-plan" {
		t.Fatal("plan 优先于 plans")
	}
	acc.Plan = map[string]any{}
	if acc.PlanKind() != "coding-plan" {
		t.Fatalf("应从 plans 识别 coding-plan: %q", acc.PlanKind())
	}
}

// ── body_transform（对齐 tests/unit 断言）────────────────────────────────────

func TestApplyStartPlanSystemStrict(t *testing.T) {
	body := map[string]any{"messages": []any{}, "system": "You are helpful."}
	changed := ApplyStartPlanSystem(body, "GLM-5.3", "zai-api", "", "", "", "")
	if !changed {
		t.Fatal("首次注入应生效")
	}
	sys, _ := body["system"].([]any)
	if len(sys) != 3 {
		t.Fatalf("必须严格三块: %d", len(sys))
	}
	// 幂等：首块已是官方标识
	if ApplyStartPlanSystem(body, "GLM-5.3", "zai-api", "", "", "", "") {
		t.Fatal("重复注入应 no-op")
	}
}

func TestTransformBodyFull(t *testing.T) {
	body := map[string]any{
		"model": "GLM-5.3",
		"messages": []any{
			map[string]any{"role": "user", "content": "hello"},
		},
	}
	TransformBody(body, "sub-user", "GLM-5.3", "mid-32-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "sess-uuid", "zai-api", "", "")
	// system 三块
	if sys, ok := body["system"].([]any); !ok || len(sys) != 3 {
		t.Fatal("system 三块缺失")
	}
	// cache_control 注入到原首条消息（ApplyCacheControl 先于日期轮前插）
	msgs, _ := body["messages"].([]any)
	if len(msgs) < 2 {
		t.Fatal("应含日期轮 + 原消息")
	}
	// 日期轮：首条消息现在是日期轮
	dateMsg := msgs[0].(map[string]any)
	if !isDateTurnText(func() any {
		content, _ := dateMsg["content"].([]any)
		block, _ := content[0].(map[string]any)
		return block["text"]
	}()) {
		t.Fatal("日期轮应插入 messages[0] 之前")
	}
	// cache_control 注入在原 "hello" 消息的 content block 内（对齐 Python msg["content"]=[{...cache_control...}]）
	helloMsg := msgs[1].(map[string]any)
	helloContent, _ := helloMsg["content"].([]any)
	if len(helloContent) == 0 {
		t.Fatal("hello content 应转为 block 数组")
	}
	helloBlock, _ := helloContent[0].(map[string]any)
	if _, ok := helloBlock["cache_control"]; !ok {
		t.Fatal("cache_control 未注入")
	}
	// metadata.user_id attribution blob
	meta, ok := body["metadata"].(map[string]any)
	if !ok {
		t.Fatal("metadata 缺失")
	}
	if !strings.Contains(meta["user_id"].(string), `"device_id"`) {
		t.Fatalf("attribution blob 形态错误: %v", meta["user_id"])
	}
}

func TestConversationSessionID(t *testing.T) {
	b1 := map[string]any{"messages": []any{map[string]any{"role": "user", "content": "hi there"}}}
	b2 := map[string]any{"messages": []any{map[string]any{"role": "user", "content": "hi there"}}}
	s1 := ConversationSessionID(b1, "acc1")
	s2 := ConversationSessionID(b2, "acc1")
	if s1 == "" || s1 != s2 {
		t.Fatal("同首轮文本应得同 session_id")
	}
	s3 := ConversationSessionID(b1, "acc2")
	if s3 == s1 {
		t.Fatal("不同账号应隔离命名空间")
	}
	// 日期轮应被跳过
	b3 := map[string]any{"messages": []any{
		map[string]any{"role": "user", "content": []any{
			map[string]any{"type": "text", "text": "<system-reminder>\nToday's date is 2026-11-04.\n</system-reminder>"},
		}},
		map[string]any{"role": "user", "content": "hi there"},
	}}
	if ConversationSessionID(b3, "acc1") != s1 {
		t.Fatal("前插日期轮不应改变会话指纹")
	}
}

func TestJWTUserID(t *testing.T) {
	// 构造 payload {"user_id":"u-1","sub":"s-1"}
	payload := `{"user_id":"u-1","sub":"s-1"}`
	b64 := base64RawURL(payload)
	token := "hdr." + b64 + ".sig"
	if BodyTransformJWTUserID(token) != "u-1" {
		t.Fatal("user_id 优先")
	}
	payload2 := `{"sub":"s-2"}`
	token2 := "h." + base64RawURL(payload2) + ".s"
	if BodyTransformJWTUserID(token2) != "s-2" {
		t.Fatal("sub 兜底")
	}
	if BodyTransformJWTUserID("not-a-jwt") != "" {
		t.Fatal("畸形 token 返回空")
	}
}

func base64RawURL(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	out := []byte{}
	data := []byte(s)
	for i := 0; i < len(data); i += 3 {
		var chunk [3]byte
		n := copy(chunk[:], data[i:])
		b0, b1, b2 := chunk[0], chunk[1], chunk[2]
		out = append(out, alphabet[b0>>2])
		out = append(out, alphabet[(b0&0x3)<<4|b1>>4])
		if n > 1 {
			out = append(out, alphabet[(b1&0xf)<<2|b2>>6])
		}
		if n > 2 {
			out = append(out, alphabet[b2&0x3f])
		}
	}
	return string(out)
}

// ── token_estimate（对齐估算口径）────────────────────────────────────────────

func TestTokenEstimate(t *testing.T) {
	body := map[string]any{
		"model": "GLM-5.3",
		"messages": []any{
			map[string]any{"role": "user", "content": "abcdefgh"}, // 8 ascii → 2 tok
		},
	}
	n := EstimateInputTokens(body)
	// 8/4=2 + 消息开销 4 + 下限 1 → ≥ 5
	if n < 5 {
		t.Fatalf("估算过低: %d", n)
	}
	// CJK 每字 1 token
	body2 := map[string]any{"messages": []any{map[string]any{"role": "user", "content": "你好世界"}}}
	n2 := EstimateInputTokens(body2)
	if n2 < 4 {
		t.Fatalf("CJK 估算过低: %d", n2)
	}
	// 图片 +1600
	body3 := map[string]any{"messages": []any{map[string]any{"role": "user", "content": []any{
		map[string]any{"type": "image", "source": map[string]any{}},
	}}}}
	if got := EstimateInputTokens(body3); got < 1600 {
		t.Fatalf("图片应 +1600: %d", got)
	}
	// transform 后估算 > 原始估算（官方 system 块开销）
	raw := EstimateInputTokens(map[string]any{"model": "GLM-5.3", "messages": []any{map[string]any{"role": "user", "content": "hi"}}})
	after := EstimateInputTokensAfterTransform(map[string]any{"model": "GLM-5.3", "messages": []any{map[string]any{"role": "user", "content": "hi"}}}, "GLM-5.3")
	if after <= raw {
		t.Fatalf("transform 后应更大: raw=%d after=%d", raw, after)
	}
}

// ── openai_compat ────────────────────────────────────────────────────────────

func TestOpenAIToAnthropic(t *testing.T) {
	payload := map[string]any{
		"model": "glm-5.3",
		"messages": []any{
			map[string]any{"role": "system", "content": "be nice"},
			map[string]any{"role": "user", "content": "hello"},
			map[string]any{"role": "tool", "tool_call_id": "call-1", "content": "42"},
			map[string]any{"role": "assistant", "content": "", "tool_calls": []any{
				map[string]any{"id": "call-1", "type": "function",
					"function": map[string]any{"name": "calc", "arguments": `{"x":1}`}},
			}},
		},
		"max_tokens": 100.0,
	}
	body, err := OpenAIToAnthropic(payload)
	if err != "" {
		t.Fatalf("转换失败: %s", err)
	}
	if body["system"] != "be nice" {
		t.Fatalf("system 提取错误: %v", body["system"])
	}
	if body["max_tokens"] != 100 {
		t.Fatalf("max_tokens: %v", body["max_tokens"])
	}
	msgs := body["messages"].([]any)
	if len(msgs) != 3 { // user + tool→user + assistant
		t.Fatalf("消息数: %d", len(msgs))
	}
	toolMsg := msgs[1].(map[string]any)
	if toolMsg["role"] != "user" {
		t.Fatal("tool 角色映射为 user")
	}
	// 缺 model 报错
	_, err2 := OpenAIToAnthropic(map[string]any{})
	if err2 != "必须提供 model 参数" {
		t.Fatalf("错误文案: %s", err2)
	}
}

func TestAnthropicToOpenAIAndStream(t *testing.T) {
	data := map[string]any{
		"id": "msg_1", "model": "GLM-5.3", "stop_reason": "max_tokens",
		"content": []any{map[string]any{"type": "text", "text": "hi"}},
		"usage":   map[string]any{"input_tokens": 3, "output_tokens": 5},
	}
	out := AnthropicToOpenAI(data, "glm")
	if out["object"] != "chat.completion" {
		t.Fatal("object 形态错误")
	}
	choices := out["choices"].([]any)
	finish := choices[0].(map[string]any)["finish_reason"]
	if finish != "length" {
		t.Fatalf("max_tokens → length: %v", finish)
	}
	usage := out["usage"].(map[string]any)
	if usage["total_tokens"] != 8 {
		t.Fatalf("total: %v", usage["total_tokens"])
	}

	// 流转换
	conv := NewStreamConverter("GLM-5.3")
	first := conv.Start()
	if !strings.HasPrefix(first, "data: ") {
		t.Fatal("SSE 行形态错误")
	}
	chunks := conv.Feed(map[string]any{"type": "content_block_delta",
		"delta": map[string]any{"type": "text_delta", "text": "yo"}})
	if len(chunks) != 1 || !strings.Contains(chunks[0], `"content":"yo"`) {
		t.Fatalf("text delta 转换错误: %v", chunks)
	}
	_ = conv.Done()
}

// ── responses_compat ─────────────────────────────────────────────────────────

func TestResponsesToChat(t *testing.T) {
	payload := map[string]any{
		"model": "glm-5.3",
		"input": []any{
			map[string]any{"type": "message", "role": "user", "content": "hi"},
		},
		"max_output_tokens": 256.0,
	}
	chat, err := ResponsesToChat(payload)
	if err != "" {
		t.Fatalf("转换失败: %s", err)
	}
	if chat["max_tokens"] != 256 {
		t.Fatalf("max_output_tokens → max_tokens: %v", chat["max_tokens"])
	}
	// previous_response_id 拒绝
	payload["previous_response_id"] = "resp_x"
	_, err = ResponsesToChat(payload)
	if !strings.Contains(err, "previous_response_id") {
		t.Fatalf("应拒绝会话态: %s", err)
	}
}

func TestResponsesStreamConverter(t *testing.T) {
	conv := NewResponsesStreamConverter("GLM-5.3")
	start := conv.Start()
	if len(start) != 2 || !strings.HasPrefix(start[0], "event: response.created") {
		t.Fatalf("start 事件: %v", start)
	}
	chunk := map[string]any{
		"choices": []any{map[string]any{"delta": map[string]any{"content": "hi"}}},
	}
	out := conv.FeedChunk(chunk)
	found := false
	for _, line := range out {
		if strings.Contains(line, "response.output_text.delta") {
			found = true
		}
	}
	if !found {
		t.Fatal("缺 output_text.delta")
	}
	done := conv.Done()
	if !strings.Contains(done[len(done)-1], "response.completed") {
		t.Fatal("结尾应为 response.completed")
	}
}

// ── version_tracker ──────────────────────────────────────────────────────────

func TestVersionCompare(t *testing.T) {
	if !IsNewerVersion("3.17.2", "3.17.1") {
		t.Fatal("3.17.2 > 3.17.1")
	}
	if IsNewerVersion("3.17.1", "3.17.1") {
		t.Fatal("相等不算更新")
	}
	if !IsNewerVersion("3.18", "3.17.1") {
		t.Fatal("3.18 > 3.17.1")
	}
	if !IsNewerVersion("4.0", "3.99.99") {
		t.Fatal("主版本优先")
	}
}

func TestParseManifestYAMLTrap(t *testing.T) {
	// YAML 1.1/1.2 陷阱：3.10 会被解析成 float 3.1 → 必须回退正则提取字面量
	text := "version: 3.10\nreleaseDate: 2026-11-03\nreleaseName: v3.10\n"
	info := ParseManifest(text)
	if info == nil {
		t.Fatal("解析失败")
	}
	if info.Version != "3.10" {
		t.Fatalf("版本号被截断: %q", info.Version)
	}
	if info.ReleaseName != "v3.10" {
		t.Fatalf("releaseName: %q", info.ReleaseName)
	}
	// 中文日志优先
	text2 := "version: 3.17.1\nreleaseNotesByLocale:\n  zh-CN:\n    markdown: 中文日志\n  en-US:\n    markdown: english\n"
	info2 := ParseManifest(text2)
	if info2 == nil || info2.ReleaseNotes != "中文日志" {
		t.Fatalf("中文日志优先: %+v", info2)
	}
	if ParseManifest("") != nil {
		t.Fatal("空文本 → nil")
	}
}

// ── store.parse_hours（对齐 test_claim_window 等）────────────────────────────

func TestParseHours(t *testing.T) {
	if len(ParseHours("")) != 0 || len(ParseHours("*")) != 0 {
		t.Fatal("空/* = 全天")
	}
	h := ParseHours("19")
	if len(h) != 1 || h[0] != 19 {
		t.Fatalf("单小时: %v", h)
	}
	h = ParseHours("21, 9 ,9，23")
	if len(h) != 3 || h[0] != 9 || h[1] != 21 || h[2] != 23 {
		t.Fatalf("升序去重+全角逗号: %v", h)
	}
	h = ParseHours("24,abc,-1")
	if len(h) != 0 {
		t.Fatalf("脏值跳过: %v", h)
	}
}

// ── egress（对齐 httpx NO_PROXY 语义文档）────────────────────────────────────

func TestEgressNoProxySemantics(t *testing.T) {
	if NoProxyCovers("") {
		t.Fatal("空 host 不命中")
	}
	// entry="*" 全直连
	if !noProxyEntryCoversForTest("*", "zcode.z.ai", 0) {
		t.Fatal("* 应全命中")
	}
	// zcode.z.ai 命中自身与子域
	if !noProxyEntryCoversForTest("zcode.z.ai", "zcode.z.ai", 0) {
		t.Fatal("裸条目命中自身")
	}
	if !noProxyEntryCoversForTest("zcode.z.ai", "api.zcode.z.ai", 0) {
		t.Fatal("裸条目命中子域")
	}
	// .zcode.z.ai 只命中子域
	if noProxyEntryCoversForTest(".zcode.z.ai", "zcode.z.ai", 0) {
		t.Fatal("点前缀不应命中自身")
	}
	if !noProxyEntryCoversForTest(".zcode.z.ai", "api.zcode.z.ai", 0) {
		t.Fatal("点前缀命中子域")
	}
	// *.zcode.z.ai 被 re.escape → 什么都不命中
	if noProxyEntryCoversForTest("*.zcode.z.ai", "api.zcode.z.ai", 0) {
		t.Fatal("星号前缀应不命中任何 host")
	}
	// 端口约束：显式端口才可比
	if !noProxyEntryCoversForTest("zcode.z.ai:443", "zcode.z.ai", 443) {
		t.Fatal("显式端口命中")
	}
	if noProxyEntryCoversForTest("zcode.z.ai:443", "zcode.z.ai", 0) {
		t.Fatal("无端口 URL 不应命中带端口条目")
	}
}

func noProxyEntryCoversForTest(entry, host string, port int) bool {
	// 对齐 NoProxyCovers：entry=="*" 特判全直连（不走 mountKey）
	if entry == "*" {
		return true
	}
	// 直接驱动 mountKey 判定（与 NoProxyCovers 相同的匹配逻辑）
	pattern, entryPort, entryScheme := mountKey(entry)
	if entryScheme != "" && entryScheme != "https" && entryScheme != "http" {
		// 仅 all 或显式 scheme；测试按 https
		if entryScheme != "all" && entryScheme != "" {
			return false
		}
	}
	if pattern != nil && !pattern.MatchString(host) {
		return false
	}
	if entryPort != 0 && entryPort != port {
		return false
	}
	return true
}

// ── claim（对齐 parse_plan / marketing 提取）─────────────────────────────────

func TestParsePlan(t *testing.T) {
	raw := map[string]any{
		"plan_id": "zcode-v3-start-plan-0817",
		"name":    "Start Plan",
		"priority": 10.0,
		"entitlements": []any{
			map[string]any{"meter": "model_usage", "unit_type": "token",
				"show_name": "GLM-5.3-Flash", "grant_units": 300000000.0, "period": "one_time"},
			map[string]any{"meter": "other", "unit_type": "token", "show_name": "x"},
		},
	}
	p := ParsePlan(raw)
	if p == nil || p["plan_id"] != "zcode-v3-start-plan-0817" {
		t.Fatalf("plan_id 提取失败: %v", p)
	}
	grants := p["grants"].([]any)
	if len(grants) != 1 {
		t.Fatalf("只收 model_usage/token 项: %d", len(grants))
	}
	if ParsePlan(map[string]any{"name": "no-id"}) != nil {
		t.Fatal("无 plan_id 返回 nil")
	}
}

func TestExtractMarketingDeliveries(t *testing.T) {
	deliveries := []any{
		map[string]any{
			"banner": map[string]any{
				"args": map[string]any{
					"zcode_plan": map[string]any{"plan_id": "zcode-v3-start-plan-1104", "name": "活动套餐", "priority": 50.0},
				},
				"buttons": []any{
					map[string]any{"action": map[string]any{"type": "claim_zcode_plan",
						"args": map[string]any{"plan_id": "zcode-v3-start-plan-1104"}}},
				},
			},
		},
	}
	plans := ExtractPlansFromMarketingDeliveries(deliveries)
	if len(plans) != 1 {
		t.Fatalf("按 plan_id 去重应得 1 个: %d", len(plans))
	}
	if plans[0].(map[string]any)["plan_id"] != "zcode-v3-start-plan-1104" {
		t.Fatalf("plan_id: %v", plans[0])
	}
	// 纯按钮动作 → 兜底形态
	deliveries2 := []any{map[string]any{"action": map[string]any{"type": "claim_zcode_plan", "args": map[string]any{"plan_id": "p-1"}}}}
	plans2 := ExtractPlansFromMarketingDeliveries(deliveries2)
	if len(plans2) != 1 || plans2[0].(map[string]any)["priority"] != 100 {
		t.Fatalf("按钮兜底形态: %v", plans2)
	}
}

// ── store 轮询选择 ───────────────────────────────────────────────────────────

func TestStoreSelectRoundRobin(t *testing.T) {
	s := NewStore()
	a1, _ := s.AddAccount("zai", "rr-1", "tok.aaa.bbb")
	a2, _ := s.AddAccount("zai", "rr-2", "tok.ccc.ddd")
	seen := map[string]int{}
	for i := 0; i < 4; i++ {
		sel := s.Select("zai", nil)
		if sel != nil {
			seen[sel.ID]++
		}
	}
	if seen[a1.ID] != 2 || seen[a2.ID] != 2 {
		t.Fatalf("round-robin 应均分: %v", seen)
	}
	// skip 后不选中被 skip 的账号（注意：NewStore 加载同一 DB，含 s1 的账号）
	s2 := NewStore()
	only, _ := s2.AddAccount("zai", "only", "tok.only.a")
	if sel := s2.Select("zai", map[string]bool{only.ID: true}); sel != nil && sel.ID == only.ID {
		t.Fatal("被 skip 的账号不应被选中")
	}
}

// ── claim 窗口调度（北京时间）────────────────────────────────────────────────

func TestClaimWindowBeijing(t *testing.T) {
	m := newClaimRoundManager()
	// 窗口语义：int(frac) in hours —— 仅整点命中窗口（19 窗口 = 北京 19:00–19:59）
	// 2026-11-04 12:00 UTC = 20:00 北京 → 不在 19 点窗口
	now := time.Date(2026, 11, 4, 12, 0, 0, 0, time.UTC).Unix()
	if m.inWindow([]int{19}, float64(now)) {
		t.Fatal("北京 20 点不在 19 点窗口")
	}
	// 11:00 UTC = 19:00 北京 → 窗口内
	now11 := time.Date(2026, 11, 4, 11, 0, 0, 0, time.UTC).Unix()
	if !m.inWindow([]int{19}, float64(now11)) {
		t.Fatal("北京 19 点整应在窗口内")
	}
	// 11:30 UTC = 19:30 北京 → 仍在窗口内（frac=19.5，int=19）
	now1130 := time.Date(2026, 11, 4, 11, 30, 0, 0, time.UTC).Unix()
	if !m.inWindow([]int{19}, float64(now1130)) {
		t.Fatal("北京 19:30 应在窗口内")
	}
	// 10:00 UTC = 18:00 北京 → 窗口外，距 19:00 整 1 小时
	now10 := time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC).Unix()
	if m.inWindow([]int{19}, float64(now10)) {
		t.Fatal("北京 18 点应在窗口外")
	}
	wait := m.secondsUntilWindow([]int{19}, float64(now10))
	if wait < 3599 || wait > 3601 {
		t.Fatalf("距窗口应约 3600s: %v", wait)
	}
	// 空窗口 = 全天
	if !m.inWindow(nil, float64(now10)) {
		t.Fatal("空窗口应全天")
	}
	if m.nextWait(0, []int{19}, 0) != 30.0 {
		t.Fatal("关闭态 30s 回看")
	}
}

// ── 附加：jsonutil ───────────────────────────────────────────────────────────

func TestJSONRoundTrip(t *testing.T) {
	v := SafeJSON(`{"code":1005,"msg":"exceed quota limit","n":12345678901234}`)
	dict := v.(map[string]any)
	if code, ok := BusinessCode(dict); !ok || code != 1005 {
		t.Fatalf("业务码识别失败: %v %v", code, ok)
	}
	if code, ok := BusinessCode(map[string]any{"code": 0}); ok {
		t.Fatalf("code=0 不是业务错误: %d", code)
	}
	if code, ok := BusinessCode(map[string]any{"code": 200}); ok {
		t.Fatalf("code=200 不是业务错误: %d", code)
	}
	if _, ok := BusinessCode(map[string]any{"type": "message", "code": 5}); ok {
		t.Fatal("带 type 的正常响应不判业务错误")
	}
	if code, ok := BusinessCode(map[string]any{"code": true}); ok {
		t.Fatalf("bool code 不判: %v", code)
	}
}

// 请求体变换 —— 对齐 zapi body-transformer.ts 在 anthropic 通道上的变换集。
//
// coding-plan 通道（本服务 JWT 通道）应用三项：
//  1. system 身份块：前置 ZCode 官方 system 块（CLI Prefix / Agent Identity /
//     Environment Info）+ 动态 currentModel 块。网关做内容审查，请求缺这些
//     身份块会被拒为 3012 "method not allowed"（镜像 zapi buildStartPlanSystem）。
//  2. cache_control：最后一条非 system 消息的最后一个 content block 追加
//     `cache_control: {"type": "ephemeral"}`（镜像 ZCode bundle 的 HLr，
//     "finalizeLatestNonSystemCacheControl"）。Anthropic API 对低于缓存门槛的
//     请求静默忽略 cache_control，因此无条件追加是安全的。
//  3. metadata.user_id：JWT 账号存在 user_id 时注入（镜像 bundle 的
//     `user_id: B.metadata.userId`）。user_id 每次从 JWT payload（sub / user_id
//     字段）实时解出，token 刷新后自动跟随。
//
// 所有变换对畸形输入保持 no-op：解析失败返回原样，坏 body 永远不会被这里放大。
//
// 对齐 Python app/body_transform.py。zcode_system.json 经 go:embed 内嵌
//（对齐 Python 读取包内同目录文件的语义，单二进制部署同样可用）。
package app

import (
	_ "embed"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/zhaoboy9692/zcode2api-go/internal/uuidx"
)

//go:embed zcode_system.json
var zcodeSystemJSON []byte

// zcodeSystemBlocks 对齐 _ZCODE_SYSTEM_BLOCKS（解析失败 → 空表）。
var zcodeSystemBlocks = func() []map[string]any {
	v, err := JSONDecode(string(zcodeSystemJSON))
	if err != nil {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []map[string]any
	for _, item := range list {
		if m, ok := item.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}()

// isPlainDict 对齐 _is_plain_dict。
func isPlainDict(v any) bool {
	_, ok := v.(map[string]any)
	return ok
}

// normalizeUserSystem 把客户端原有 system 归一为 text block 列表（镜像 zapi normalizeUserSystem）。
func normalizeUserSystem(system any) []map[string]any {
	if system == nil {
		return nil
	}
	if s, ok := system.(string); ok {
		if strings.TrimSpace(s) != "" {
			return []map[string]any{{"type": "text", "text": s}}
		}
		return nil
	}
	list, ok := system.([]any)
	if !ok {
		return nil
	}
	var out []map[string]any
	for _, item := range list {
		if s, ok := item.(string); ok {
			if strings.TrimSpace(s) != "" {
				out = append(out, map[string]any{"type": "text", "text": s})
			}
			continue
		}
		if m, ok := item.(map[string]any); ok {
			if m["type"] == "text" {
				if text, ok := m["text"].(string); ok && strings.TrimSpace(text) != "" {
					block := map[string]any{"type": "text", "text": text}
					if cc, ok := m["cache_control"].(map[string]any); ok {
						block["cache_control"] = cc
					}
					out = append(out, block)
				}
			}
		}
	}
	return out
}

// ApplyStartPlanSystem 前置 ZCode 官方 system 身份块，并把 powered-by / 客户端 system 并入最后一块。幂等。
//
// **严格三块**（2026-11-02 修正，此前为四块+，全池 3012）：
//   - 网关校验的是 system 的**块结构**（cli_prefix 必须独立成首块），
//     而非逐字内容——实测末块内容可任意（空串 / 仅前缀 / 无前缀均 200）。
//   - 官方 harness 的 system 恰好 3 块，trial/start-plan 下外来 system 文本
//     **只许并入末块内部**；追加成第 4 块、或把客户端 system 另起成独立块，
//     都会破坏形态 → 405 3012 "unusual activity"。
func ApplyStartPlanSystem(body map[string]any, model string) bool {
	if len(zcodeSystemBlocks) == 0 {
		return false
	}
	existing := body["system"]
	// 幂等：首块已是官方标识则视为已注入
	if list, ok := existing.([]any); ok && len(list) > 0 {
		if first, ok := list[0].(map[string]any); ok {
			if t, _ := first["text"].(string); t == StrValue(zcodeSystemBlocks[0]["text"]) {
				return false
			}
		}
	}

	// 第 1、2 块原样；其余一切文本合并进第 3 块
	var official []any
	for i := 0; i < 2 && i < len(zcodeSystemBlocks); i++ {
		official = append(official, deepCopyDict(zcodeSystemBlocks[i]))
	}
	var tail []string
	for i := 2; i < len(zcodeSystemBlocks); i++ {
		text, _ := zcodeSystemBlocks[i]["text"].(string)
		if strings.TrimSpace(text) != "" {
			tail = append(tail, text)
		}
	}
	if strings.TrimSpace(model) != "" {
		tail = append(tail, fmt.Sprintf("- You are powered by the model named %s.", model))
	}
	var userParts []string
	for _, b := range normalizeUserSystem(existing) {
		if t, ok := b["text"].(string); ok && strings.TrimSpace(t) != "" {
			userParts = append(userParts, t)
		}
	}
	if len(userParts) > 0 {
		tail = append(tail, strings.Join(userParts, "\n\n"))
	}

	official = append(official, map[string]any{
		"type":          "text",
		"text":          strings.Join(tail, "\n\n"),
		"cache_control": map[string]any{"type": "ephemeral"},
	})
	body["system"] = official
	return true
}

// deepCopyDict 对齐 copy.deepcopy（JSON 值域内递归）。
func deepCopyDict(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = deepCopyDict(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = deepCopyDict(val)
		}
		return out
	default:
		return v
	}
}

// isDateTurnText 注入的「当前日期」user 轮的标记（幂等判定与会话指纹共用同一真相源）。
func isDateTurnText(text any) bool {
	s, ok := text.(string)
	return ok && strings.Contains(s, "<system-reminder>") && strings.Contains(s, "Today's date is")
}

// ApplyCurrentDateTurn 把官方 meta_user 的「当前日期」附件补进首条 user 轮（3.17.1 起不在 system 块里）。
//
// 形态：`<system-reminder>\nToday's date is YYYY-MM-DD.\n</system-reminder>` 的独立 user 轮。
// 幂等：首条消息已是该形态则跳过。
func ApplyCurrentDateTurn(body map[string]any) bool {
	messages, ok := body["messages"].([]any)
	if !ok || len(messages) == 0 {
		return false
	}
	if first, ok := messages[0].(map[string]any); ok && first["role"] == "user" {
		if content, ok := first["content"].([]any); ok && len(content) > 0 {
			if block, ok := content[0].(map[string]any); ok {
				if isDateTurnText(block["text"]) {
					return false
				}
			}
		}
	}
	dateText := fmt.Sprintf("<system-reminder>\nToday's date is %s.\n</system-reminder>", time.Now().Format("2006-01-02"))
	dateTurn := map[string]any{
		"role": "user",
		"content": []any{
			map[string]any{"type": "text", "text": dateText},
		},
	}
	newMessages := []any{dateTurn}
	newMessages = append(newMessages, messages...)
	body["messages"] = newMessages
	return true
}

// ApplyCacheControl 最后一条非 system 消息的最后一个 block 加 ephemeral 缓存标记。幂等。
func ApplyCacheControl(body map[string]any) bool {
	messages, ok := body["messages"].([]any)
	if !ok || len(messages) == 0 {
		return false
	}
	for i := len(messages) - 1; i >= 0; i-- {
		msg, ok := messages[i].(map[string]any)
		if !ok {
			continue
		}
		if msg["role"] == "system" {
			continue
		}
		if content, ok := msg["content"].(string); ok {
			msg["content"] = []any{
				map[string]any{
					"type":          "text",
					"text":          content,
					"cache_control": map[string]any{"type": "ephemeral"},
				},
			}
			return true
		}
		if content, ok := msg["content"].([]any); ok && len(content) > 0 {
			if lastBlock, ok := content[len(content)-1].(map[string]any); ok {
				if _, has := lastBlock["cache_control"]; !has {
					lastBlock["cache_control"] = map[string]any{"type": "ephemeral"}
					return true
				}
			}
		}
		return false
	}
	return false
}

// ApplyUserID 注入 metadata.user_id（保留已有 metadata 其它字段）。幂等。
func ApplyUserID(body map[string]any, userID string) bool {
	existing := body["metadata"]
	if isPlainDict(existing) {
		if m, _ := existing.(map[string]any); m["user_id"] == userID {
			return false
		}
	}
	merged := map[string]any{}
	if isPlainDict(existing) {
		for k, v := range existing.(map[string]any) {
			merged[k] = v
		}
	}
	merged["user_id"] = userID
	body["metadata"] = merged
	return true
}

// AttributionUserID 官方 attribution 的 metadata.user_id 形态：JSON 字符串 blob。
//
// bundle `Bdt` / vlelyanin transform.js 实证：
//
//	{"device_id": <mid>, "account_uuid": "", "session_id": <sid>}
//
//（旧版直塞 JWT sub 是错误形态）
func AttributionUserID(deviceMid, sessionID string) string {
	blob := map[string]any{
		"device_id":    deviceMid,
		"account_uuid": "",
		"session_id":   sessionID,
	}
	out, _ := JSONMarshalCompact(blob)
	return string(out)
}

// ConversationSessionID 同一会话的稳定 session_id（同首轮 → 同 id），无首轮文本返回 ""。
//
// 官方客户端的 `x-session-id` 与 metadata blob 的 `session_id` 在会话内
// 稳定，prompt cache 的命中依赖它。hub 无会话态，用「会话首条 user 文本」
// 做指纹：多轮请求里首轮文本不变，因此同一会话自然拿到同一 id。
//
// 加入 account_id 隔离命名空间，避免不同账号/不同租户撞同一个 id
//（id 会随请求上报给上游，跨号相同是额外的关联信号）。
//
// ⚠️ 必须跳过注入的日期轮（2026-11-03 复现的缺陷）：`TransformBody` 会把
// 日期轮插到 messages[0] 且**原地**改写 body，而重试/换号路径会对同一个
// body 对象再次调用 `BuildRequest`——不跳过的话，第二次起指纹就落在日期
// 文本上，同一账号同一天所有会话撞成同一个 id（跨会话关联信号 + cache 键
// 漂移）。跳过规则对「前插任意个匹配轮」幂等，指纹与首次调用一致。
func ConversationSessionID(body map[string]any, accountID string) string {
	messages, ok := body["messages"].([]any)
	if !ok {
		return ""
	}
	text := ""
	for _, rawMsg := range messages {
		msg, ok := rawMsg.(map[string]any)
		if !ok || msg["role"] != "user" {
			continue
		}
		var candidate string
		switch content := msg["content"].(type) {
		case string:
			candidate = content
		case []any:
			candidate = ""
			for _, rawBlock := range content {
				block, ok := rawBlock.(map[string]any)
				if !ok {
					continue
				}
				if block["type"] == "text" {
					if t, ok := block["text"].(string); ok {
						candidate = t
						break
					}
				}
			}
		default:
			candidate = ""
		}
		if isDateTurnText(candidate) {
			continue // 日期轮（自己的或同形前插轮）：不是会话内容
		}
		text = candidate
		break
	}
	if strings.TrimSpace(text) == "" {
		return ""
	}
	digest := sha256Hex32(strings.TrimSpace(text))
	// 对齐 uuid.uuid5(uuid.NAMESPACE_URL, f"zcode-hub:{account_id}:{digest}")
	return uuidx.New5(uuidx.NamespaceURL, fmt.Sprintf("zcode-hub:%s:%s", accountID, digest))
}

// BodyTransformJWTUserID 从 JWT payload 解 user_id（sub / user_id 字段），失败返回 ""。
//
// JWT 是账号凭证（短期有效），user_id 跟随 token 变化，因此不跨进程缓存。
func BodyTransformJWTUserID(jwtToken string) string {
	if jwtToken == "" || strings.Count(jwtToken, ".") != 2 {
		return ""
	}
	seg := strings.Split(jwtToken, ".")[1]
	// 对齐 Python payload_b64 += "=" * (-len(payload_b64) % 4)：
	// Python 取模恒非负（结果 0..3），Go 需换算为 (4 - n%4) % 4
	if pad := (4 - len(seg)%4) % 4; pad != 0 {
		seg += strings.Repeat("=", pad)
	}
	payloadRaw, err := base64.URLEncoding.DecodeString(seg)
	if err != nil {
		return ""
	}
	v, err := JSONDecode(string(payloadRaw))
	if err != nil {
		return ""
	}
	payload, ok := v.(map[string]any)
	if !ok {
		return ""
	}
	uid := firstNonEmptyStr(payload["user_id"], payload["sub"])
	if uid == "" {
		return ""
	}
	return uid
}

// TransformBody 按 anthropic 通道变换 body（原地修改并返回）。变换失败静默保持原样。
//
// user_id 为 JWT sub（仅用于兜底）；attribution 优先用 device_mid/session_id 组 blob。
func TransformBody(body map[string]any, userID, model string, deviceMid, sessionID string) map[string]any {
	func() {
		defer func() {
			// 对齐 except Exception: pass —— 变换永不放大请求失败
			_ = recover()
		}()
		ApplyStartPlanSystem(body, model)
		ApplyCacheControl(body)
		ApplyCurrentDateTurn(body)
		if deviceMid != "" || sessionID != "" {
			ApplyUserID(body, AttributionUserID(deviceMid, sessionID))
		} else if userID != "" {
			ApplyUserID(body, userID)
		}
	}()
	return body
}

// OpenAI Chat Completions 兼容层 —— /v1/chat/completions ↔ Anthropic Messages 双向转换。
//
// 入站：OpenAI 请求体 → Anthropic messages 体（system/developer 提取为 system 参数、
// content 分块、tool_calls / tool_result / 图片(data URL) best-effort 映射）。
// 出站：Anthropic 响应（JSON 或 SSE 事件流）→ OpenAI 格式。
//
// 与 body_transform 同一原则：对畸形输入保持宽容，映射不了的部件安静跳过，
// 绝不放大请求失败。
//
// 对齐 Python app/openai_compat.py。
package app

import (
	"fmt"
	"strings"
	"time"

	"github.com/zhaoboy9692/zcode2api-go/internal/uuidx"
)

// stopReasonMap Anthropic stop_reason → OpenAI finish_reason。
var stopReasonMap = map[string]string{
	"end_turn":      "stop",
	"stop_sequence": "stop",
	"max_tokens":    "length",
	"tool_use":      "tool_calls",
}

// OpenAIAsInt 对齐 _as_int（Python int(value)）。
func OpenAIAsInt(value any) (int, bool) {
	switch v := value.(type) {
	case nil, bool:
		return 0, false
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	case jsonNum:
		if i, err := v.Int64(); err == nil {
			return int(i), true
		}
		if f, err := v.Float64(); err == nil {
			return int(f), true
		}
		return 0, false
	case string:
		// Python int("42") 成功、int("4.2") 失败——保持一致
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(v), "%d", &n); err == nil {
			return n, true
		}
		return 0, false
	default:
		return 0, false
	}
}

// textFromContent OpenAI content（str | 分块数组）→ 纯文本。
func textFromContent(content any) string {
	if s, ok := content.(string); ok {
		return s
	}
	list, ok := content.([]any)
	if !ok {
		return ""
	}
	var parts []string
	for _, item := range list {
		if m, ok := item.(map[string]any); ok && m["type"] == "text" {
			if t, ok := m["text"].(string); ok {
				parts = append(parts, t)
			}
		}
	}
	var nonEmpty []string
	for _, p := range parts {
		if p != "" {
			nonEmpty = append(nonEmpty, p)
		}
	}
	return strings.Join(nonEmpty, "\n")
}

// imageBlock data:image/...;base64,xxx → Anthropic image block；外链 URL 无法回填，跳过。
func imageBlock(rawURL string) map[string]any {
	if !strings.HasPrefix(rawURL, "data:") {
		return nil
	}
	head, b64, _ := strings.Cut(rawURL, ",")
	mediaType := "image/png"
	if len(head) > 5 {
		mediaType = strings.Split(head[5:], ";")[0]
	}
	if mediaType == "" {
		mediaType = "image/png"
	}
	if b64 == "" {
		return nil
	}
	return map[string]any{
		"type": "image",
		"source": map[string]any{
			"type":       "base64",
			"media_type": mediaType,
			"data":       b64,
		},
	}
}

// blocksFromUserContent 对齐 _blocks_from_user_content。
func blocksFromUserContent(content any) []any {
	if s, ok := content.(string); ok {
		if s != "" {
			return []any{map[string]any{"type": "text", "text": s}}
		}
		return []any{map[string]any{"type": "text", "text": ""}}
	}
	list, ok := content.([]any)
	if !ok {
		return []any{map[string]any{"type": "text", "text": ""}}
	}
	var blocks []any
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if m["type"] == "text" {
			if t, ok := m["text"].(string); ok {
				blocks = append(blocks, map[string]any{"type": "text", "text": t})
			}
		} else if m["type"] == "image_url" {
			rawURL := ""
			if urlDict, ok := m["image_url"].(map[string]any); ok {
				rawURL = DictGetStr(urlDict, "url", "")
			}
			if block := imageBlock(rawURL); block != nil {
				blocks = append(blocks, block)
			}
		}
	}
	if len(blocks) == 0 {
		return []any{map[string]any{"type": "text", "text": ""}}
	}
	return blocks
}

// OpenAIToAnthropic OpenAI 请求体 → Anthropic messages 体。
// 非法时返回 (nil, 错误信息)。
func OpenAIToAnthropic(payload map[string]any) (map[string]any, string) {
	model, ok := payload["model"].(string)
	if !ok || strings.TrimSpace(model) == "" {
		return nil, "必须提供 model 参数"
	}
	rawMessages, ok := payload["messages"].([]any)
	if !ok || len(rawMessages) == 0 {
		return nil, "必须提供 messages 数组"
	}

	var systemParts []string
	var outMsgs []any
	for _, rawMsg := range rawMessages {
		msg, ok := rawMsg.(map[string]any)
		if !ok {
			continue
		}
		role := DictGetStr(msg, "role", "")
		content := msg["content"]
		if role == "system" || role == "developer" {
			if text := textFromContent(content); text != "" {
				systemParts = append(systemParts, text)
			}
		} else if role == "tool" {
			outMsgs = append(outMsgs, map[string]any{
				"role": "user",
				"content": []any{
					map[string]any{
						"type":        "tool_result",
						"tool_use_id": DictGetStr(msg, "tool_call_id", ""),
						"content":     textFromContent(content),
					},
				},
			})
		} else if role == "assistant" {
			var blocks []any
			if text := textFromContent(content); text != "" {
				blocks = append(blocks, map[string]any{"type": "text", "text": text})
			}
			if toolCalls, ok := msg["tool_calls"].([]any); ok {
				for _, rawTC := range toolCalls {
					tc, ok := rawTC.(map[string]any)
					if !ok {
						continue
					}
					fn, ok := tc["function"].(map[string]any)
					if !ok {
						continue
					}
					args := fn["arguments"]
					if s, isStr := args.(string); isStr {
						if v, err := JSONDecode(s); err == nil {
							args = v
						} else {
							args = map[string]any{"_raw": s}
						}
					}
					if !isPlainDict(args) {
						args = map[string]any{}
					}
					blocks = append(blocks, map[string]any{
						"type":  "tool_use",
						"id":    DictGetStr(tc, "id", ""),
						"name":  DictGetStr(fn, "name", ""),
						"input": args,
					})
				}
			}
			if len(blocks) == 0 {
				blocks = []any{map[string]any{"type": "text", "text": ""}}
			}
			outMsgs = append(outMsgs, map[string]any{"role": "assistant", "content": blocks})
		} else {
			// user 及未知角色一律按 user 处理
			outMsgs = append(outMsgs, map[string]any{"role": "user", "content": blocksFromUserContent(content)})
		}
	}

	// 结构化输出：anthropic wire 没有 response_format，用 system 指令逼近。
	// 只对显式要求 JSON 的调用生效；不改变普通对话的提示词。
	if fmtDict, ok := payload["response_format"].(map[string]any); ok {
		ftype := DictGetStr(fmtDict, "type", "")
		if ftype == "json_object" {
			systemParts = append(systemParts, "Respond with a single valid JSON object and nothing else.")
		} else if ftype == "json_schema" {
			js, _ := fmtDict["json_schema"].(map[string]any)
			directive := "Respond with a single JSON value conforming to this JSON Schema and nothing else."
			if js != nil {
				if schema, ok := js["schema"].(map[string]any); ok {
					if s, err := JSONMarshalCompact(schema); err == nil {
						directive += " Schema: " + string(s)
					}
				}
			}
			systemParts = append(systemParts, directive)
		}
	}

	maxTokens := 4096
	if n, ok := OpenAIAsInt(payload["max_tokens"]); ok {
		maxTokens = n
	} else if n, ok := OpenAIAsInt(payload["max_completion_tokens"]); ok {
		maxTokens = n
	}
	if maxTokens == 0 {
		maxTokens = 4096
	}
	body := map[string]any{
		"model":      model,
		"messages":   outMsgs,
		"max_tokens": maxTokens,
	}
	if len(systemParts) > 0 {
		body["system"] = strings.Join(systemParts, "\n\n")
	}

	// 思考强度：OpenAI `reasoning_effort` / Responses `reasoning.effort`
	// → anthropic wire 的 `output_config.effort`（官方客户端同形态）。
	effort, effortIsStr := payload["reasoning_effort"].(string)
	if !effortIsStr {
		if reasoning, ok := payload["reasoning"].(map[string]any); ok {
			effort, effortIsStr = reasoning["effort"].(string)
		}
	}
	if effortIsStr {
		low := strings.ToLower(effort)
		if low == "low" || low == "medium" || low == "high" || low == "max" {
			body["output_config"] = map[string]any{"effort": low}
		}
	}
	// temperature/top_p：Python float(v)，None 跳过；失败 pass
	if v := payload["temperature"]; v != nil {
		if f, ok := AsFloat(v); ok {
			body["temperature"] = f
		}
	}
	if v := payload["top_p"]; v != nil {
		if f, ok := AsFloat(v); ok {
			body["top_p"] = f
		}
	}
	stop := payload["stop"]
	if s, isStr := stop.(string); isStr && s != "" {
		body["stop_sequences"] = []any{s}
	} else if list, isList := stop.([]any); isList && len(list) > 0 {
		var seqs []any
		for _, s := range list {
			seqs = append(seqs, StrValue(s))
		}
		body["stop_sequences"] = seqs
	}
	if stream, ok := payload["stream"].(bool); ok && stream {
		body["stream"] = true
	}

	if tools, ok := payload["tools"].([]any); ok && len(tools) > 0 {
		var mapped []any
		for _, rawT := range tools {
			t, ok := rawT.(map[string]any)
			if !ok {
				continue
			}
			fn, ok := t["function"].(map[string]any)
			if !ok || DictGetStr(fn, "name", "") == "" {
				continue
			}
			params := fn["parameters"]
			if !isPlainDict(params) {
				params = map[string]any{"type": "object"}
			}
			mapped = append(mapped, map[string]any{
				"name":         DictGetStr(fn, "name", ""),
				"description":  DictGetStr(fn, "description", ""),
				"input_schema": params,
			})
		}
		if len(mapped) > 0 {
			body["tools"] = mapped
		}
	}

	choice := payload["tool_choice"]
	switch c := choice.(type) {
	case string:
		if c == "none" {
			delete(body, "tools")
		} else if c == "required" {
			body["tool_choice"] = map[string]any{"type": "any"}
		}
	case map[string]any:
		if DictGetStr(c, "type", "") == "function" {
			fn, _ := c["function"].(map[string]any)
			name := DictGetStr(fn, "name", "")
			if name != "" {
				body["tool_choice"] = map[string]any{"type": "tool", "name": name}
			}
		}
	}
	// "auto"/缺省：Anthropic 默认即 auto，无需显式映射
	return body, ""
}

// AnthropicToOpenAI Anthropic message 响应 → OpenAI chat.completion。
func AnthropicToOpenAI(data map[string]any, model string) map[string]any {
	var textParts []string
	var toolCalls []any
	if content, ok := data["content"].([]any); ok {
		for _, rawBlock := range content {
			block, ok := rawBlock.(map[string]any)
			if !ok {
				continue
			}
			if block["type"] == "text" {
				if t, ok := block["text"].(string); ok {
					textParts = append(textParts, t)
				}
			} else if block["type"] == "tool_use" {
				input := block["input"]
				if input == nil {
					input = map[string]any{}
				}
				args, _ := JSONMarshalCompact(input)
				toolCalls = append(toolCalls, map[string]any{
					"id":   DictGetStr(block, "id", ""),
					"type": "function",
					"function": map[string]any{
						"name":      DictGetStr(block, "name", ""),
						"arguments": string(args),
					},
				})
			}
		}
	}
	inTok, outTok := 0, 0
	if usage, ok := data["usage"].(map[string]any); ok {
		if n, ok := OpenAIAsInt(usage["input_tokens"]); ok {
			inTok = n
		}
		if n, ok := OpenAIAsInt(usage["output_tokens"]); ok {
			outTok = n
		}
	}
	contentValue := any(strings.Join(textParts, ""))
	if contentValue.(string) == "" {
		contentValue = nil
	}
	message := map[string]any{"role": "assistant", "content": contentValue}
	if len(toolCalls) > 0 {
		message["tool_calls"] = toolCalls
	}
	id := DictGetStr(data, "id", "")
	if id == "" {
		id = "chatcmpl-" + uuidx.New4()[:24]
	}
	m := model
	if v, ok := data["model"].(string); ok && v != "" {
		m = v
	}
	finish := "stop"
	if sr, ok := data["stop_reason"].(string); ok {
		if mapped, ok := stopReasonMap[sr]; ok {
			finish = mapped
		}
	}
	return map[string]any{
		"id":      id,
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   m,
		"choices": []any{
			map[string]any{
				"index":         0,
				"message":       message,
				"finish_reason": finish,
			},
		},
		"usage": map[string]any{
			"prompt_tokens":     inTok,
			"completion_tokens": outTok,
			"total_tokens":      inTok + outTok,
		},
	}
}

// ── StreamConverter：Anthropic SSE 事件流 → OpenAI chunk 流（有状态转换器）────
//
// 用法：先 Start() 产出 role 首 chunk，逐条 Feed(eventDict) 收输出行，
// 流结束后追加 Done()（"data: [DONE]"）。
//
// `FeedEvents` / `StartEvent` 返回 **chunk dict**：`/v1/responses` 需要把
// chunk 再翻译成 Responses 事件，不能只拿到已经序列化的 SSE 行。
type StreamConverter struct {
	Model        string
	chunkID      string
	created      int64
	FinishReason *string
	// nil = 上游未上报（未知），0 = 真实为零；两者语义不同
	Usage    map[string]any // {"prompt_tokens": any, "completion_tokens": any, "total_tokens": any}
	toolSeq  int
}

// NewStreamConverter 构造（对齐 __init__）。
func NewStreamConverter(model string) *StreamConverter {
	return &StreamConverter{
		Model:   model,
		chunkID: "chatcmpl-" + uuidx.New4()[:24],
		created: time.Now().Unix(),
		Usage:   map[string]any{"prompt_tokens": nil, "completion_tokens": nil, "total_tokens": nil},
	}
}

func (s *StreamConverter) syncUsageTotal() {
	p, pOK := s.Usage["prompt_tokens"]
	c, cOK := s.Usage["completion_tokens"]
	if !pOK && !cOK {
		s.Usage["total_tokens"] = nil
		return
	}
	total := 0
	if p != nil {
		if f, ok := AsFloat(p); ok {
			total += int(f)
		}
	}
	if c != nil {
		if f, ok := AsFloat(c); ok {
			total += int(f)
		}
	}
	if p == nil && c == nil {
		s.Usage["total_tokens"] = nil
		return
	}
	s.Usage["total_tokens"] = total
}

// StartEvent 对齐 start_event()。
func (s *StreamConverter) StartEvent() map[string]any {
	return s.chunkEvent(map[string]any{"role": "assistant", "content": ""}, nil)
}

// Start 对齐 start()：返回首个 SSE 行。
func (s *StreamConverter) Start() string {
	return sseLine(s.StartEvent())
}

// Done 对齐 done()。
func (s *StreamConverter) Done() string { return "data: [DONE]\n\n" }

// Feed 对齐 feed()：返回 SSE 行列表。
func (s *StreamConverter) Feed(evt map[string]any) []string {
	var out []string
	for _, c := range s.FeedEvents(evt) {
		out = append(out, sseLine(c))
	}
	return out
}

// FeedEvents 对齐 feed_events(evt)。
func (s *StreamConverter) FeedEvents(evt map[string]any) []map[string]any {
	etype := DictGetStr(evt, "type", "")
	switch etype {
	case "message_start":
		msg, _ := evt["message"].(map[string]any)
		if msg != nil {
			if id, ok := msg["id"].(string); ok && id != "" {
				s.chunkID = id
			}
			if u, ok := msg["usage"].(map[string]any); ok {
				if prompt, ok := OpenAIAsInt(u["input_tokens"]); ok {
					s.Usage["prompt_tokens"] = prompt
					s.syncUsageTotal()
				}
			}
		}
		return nil
	case "content_block_start":
		block, _ := evt["content_block"].(map[string]any)
		if block != nil && block["type"] == "tool_use" {
			idx := s.toolSeq
			s.toolSeq++
			return []map[string]any{
				s.chunkEvent(map[string]any{"tool_calls": []any{
					map[string]any{
						"index": idx,
						"id":    DictGetStr(block, "id", ""),
						"type":  "function",
						"function": map[string]any{
							"name":      DictGetStr(block, "name", ""),
							"arguments": "",
						},
					},
				}}, nil),
			}
		}
		return nil
	case "content_block_delta":
		delta, _ := evt["delta"].(map[string]any)
		if delta != nil {
			if delta["type"] == "text_delta" {
				if t, ok := delta["text"].(string); ok {
					return []map[string]any{s.chunkEvent(map[string]any{"content": t}, nil)}
				}
			}
			if delta["type"] == "input_json_delta" {
				if p, ok := delta["partial_json"].(string); ok {
					idx := s.toolSeq - 1
					if idx < 0 {
						idx = 0
					}
					return []map[string]any{
						s.chunkEvent(map[string]any{"tool_calls": []any{
							map[string]any{
								"index":    idx,
								"function": map[string]any{"arguments": p},
							},
						}}, nil),
					}
				}
			}
		}
		return nil
	case "message_delta":
		delta, _ := evt["delta"].(map[string]any)
		if delta == nil {
			delta = map[string]any{}
		}
		finish := "stop"
		if sr, ok := delta["stop_reason"].(string); ok {
			if mapped, ok := stopReasonMap[sr]; ok {
				finish = mapped
			}
		}
		s.FinishReason = &finish
		if u, ok := evt["usage"].(map[string]any); ok {
			if out, ok := OpenAIAsInt(u["output_tokens"]); ok {
				s.Usage["completion_tokens"] = out
				s.syncUsageTotal()
			}
		}
		return []map[string]any{s.chunkEvent(map[string]any{}, &finish)}
	default:
		// content_block_stop / message_stop / ping / error 等无需产出
		return nil
	}
}

func (s *StreamConverter) chunkEvent(delta map[string]any, finishReason *string) map[string]any {
	payload := map[string]any{
		"id":      s.chunkID,
		"object":  "chat.completion.chunk",
		"created": s.created,
		"model":   s.Model,
		"choices": []any{
			map[string]any{"index": 0, "delta": delta, "finish_reason": finishReason},
		},
	}
	if finishReason != nil {
		usageCopy := map[string]any{}
		for k, v := range s.Usage {
			usageCopy[k] = v
		}
		payload["usage"] = usageCopy
	}
	return payload
}

// sseLine 对齐 _sse(payload)：`data: <json>\n\n`（ensure_ascii=False）。
func sseLine(payload map[string]any) string {
	b, err := JSONMarshalCompact(payload)
	if err != nil {
		b = []byte("{}")
	}
	return "data: " + string(b) + "\n\n"
}

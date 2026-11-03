// OpenAI Responses API 兼容层 —— /v1/responses ↔ Chat Completions ↔ Anthropic。
//
// 官方 Responses 协议与 Chat Completions 的差异集中在三处：入站用 `input` 而不是
// `messages`、出站是 `output[]` 条目数组、流式是 `response.*` 事件族。这里先把
// Responses 请求翻译成 Chat Completions（复用既有的 chat→anthropic 与 anthropic→chat
// 双向层），再把 chat 结果/流翻译回 Responses 形态。
//
// 设计取舍（对齐 TriDefender 的 responses-handler）：
//   - **无状态**：不实现 `previous_response_id`/`store` 的服务端会话（hub 本身无会话态）。
//     带 `previous_response_id` 的请求直接 400，避免静默丢上下文。
//   - 只做形状翻译，不做内容改写：映射不了的部件安静跳过（与 openai_compat 同原则）。
//
// 对齐 Python app/responses_compat.py。
package app

import (
	"sort"
	"strings"
	"time"

	"github.com/zhaoboy9692/zcode2api-go/internal/uuidx"
)

const maxOutputDefault = 4096

// textFromResponsesContent Responses content（str | [{type:input_text|output_text|text,...}]）→ 纯文本。
func textFromResponsesContent(content any) string {
	if s, ok := content.(string); ok {
		return s
	}
	list, ok := content.([]any)
	if !ok {
		return ""
	}
	var parts []string
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		t := DictGetStr(m, "type", "")
		if (t == "input_text" || t == "output_text" || t == "text") {
			if text, ok := m["text"].(string); ok {
				parts = append(parts, text)
			}
		}
	}
	return strings.Join(parts, "\n")
}

// responsesUserBlocks Responses 用户内容 → anthropic 风格 content 分块（文本 + 图片）。
func responsesUserBlocks(content any) []any {
	if s, ok := content.(string); ok {
		return []any{map[string]any{"type": "text", "text": s}}
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
		t := DictGetStr(m, "type", "")
		if t == "input_text" || t == "output_text" || t == "text" {
			if text, ok := m["text"].(string); ok {
				blocks = append(blocks, map[string]any{"type": "text", "text": text})
			}
		} else if t == "input_image" {
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

// ResponsesToChat Responses 请求体 → Chat Completions 请求体。非法时返回 (nil, 错误)。
func ResponsesToChat(payload map[string]any) (map[string]any, string) {
	model, ok := payload["model"].(string)
	if !ok || strings.TrimSpace(model) == "" {
		return nil, "必须提供 model 参数"
	}
	if prev := DictGetStr(payload, "previous_response_id", ""); prev != "" {
		return nil, "不支持 previous_response_id：本网关无服务端会话状态，请把历史放进 input"
	}

	var chatMessages []any
	if instructions, ok := payload["instructions"].(string); ok && strings.TrimSpace(instructions) != "" {
		chatMessages = append(chatMessages, map[string]any{"role": "system", "content": instructions})
	}

	inp, hasInp := payload["input"]
	if s, isStr := inp.(string); isStr {
		chatMessages = append(chatMessages, map[string]any{"role": "user", "content": s})
	} else if list, isList := inp.([]any); isList {
		for _, rawItem := range list {
			item, ok := rawItem.(map[string]any)
			if !ok {
				continue
			}
			itype := item["type"]
			if itype == "function_call" {
				// arguments 是字符串原样；否则 JSON 序列化
				var argsStr string
				if s, isStr := item["arguments"].(string); isStr {
					argsStr = s
				} else {
					b, _ := JSONMarshalCompact(func() any {
						if v, ok := item["arguments"]; ok && v != nil {
							return v
						}
						return map[string]any{}
					}())
					argsStr = string(b)
				}
				chatMessages = append(chatMessages, map[string]any{
					"role":    "assistant",
					"content": nil,
					"tool_calls": []any{
						map[string]any{
							"id":    firstNonEmptyStr(item["call_id"], item["id"]),
							"type":  "function",
							"function": map[string]any{
								"name":      DictGetStr(item, "name", ""),
								"arguments": argsStr,
							},
						},
					},
				})
			} else if itype == "function_call_output" {
				content := textFromResponsesContent(item["output"])
				if content == "" {
					content = StrValue(item["output"])
				}
				chatMessages = append(chatMessages, map[string]any{
					"role":         "tool",
					"tool_call_id": DictGetStr(item, "call_id", ""),
					"content":      content,
				})
			} else if itype == nil || itype == "message" {
				role := DictGetStr(item, "role", "user")
				if role == "" {
					role = "user"
				}
				content := item["content"]
				if role == "system" || role == "developer" {
					if text := textFromResponsesContent(content); text != "" {
						chatMessages = append(chatMessages, map[string]any{"role": "system", "content": text})
					}
				} else if role == "assistant" {
					chatMessages = append(chatMessages, map[string]any{
						"role":    "assistant",
						"content": textFromResponsesContent(content),
					})
				} else {
					chatMessages = append(chatMessages, map[string]any{"role": "user", "content": responsesUserBlocks(content)})
				}
			}
			// 其它条目（reasoning / item_reference 等）无对应语义，跳过
		}
	} else if !hasInp || inp == nil {
		return nil, "必须提供 input（string 或条目数组）"
	} else {
		return nil, "input 必须是字符串或数组"
	}

	maxTokens := maxOutputDefault
	if n, ok := OpenAIAsInt(payload["max_output_tokens"]); ok && n != 0 {
		maxTokens = n
	}
	chat := map[string]any{
		"model":      model,
		"messages":   chatMessages,
		"max_tokens": maxTokens,
	}
	for _, key := range []string{"temperature", "top_p"} {
		if v, ok := payload[key]; ok && v != nil {
			chat[key] = v
		}
	}
	if stream, ok := payload["stream"].(bool); ok && stream {
		chat["stream"] = true
	}

	if tools, ok := payload["tools"].([]any); ok {
		var mapped []any
		for _, rawT := range tools {
			t, ok := rawT.(map[string]any)
			if !ok || DictGetStr(t, "type", "") != "function" || DictGetStr(t, "name", "") == "" {
				continue
			}
			params := t["parameters"]
			if !isPlainDict(params) {
				params = map[string]any{"type": "object"}
			}
			mapped = append(mapped, map[string]any{
				"type": "function",
				"function": map[string]any{
					"name":        DictGetStr(t, "name", ""),
					"description": DictGetStr(t, "description", ""),
					"parameters":  params,
				},
			})
		}
		if len(mapped) > 0 {
			chat["tools"] = mapped
		}
	}

	switch choice := payload["tool_choice"].(type) {
	case string:
		chat["tool_choice"] = choice
	case map[string]any:
		if DictGetStr(choice, "type", "") == "function" && DictGetStr(choice, "name", "") != "" {
			chat["tool_choice"] = map[string]any{
				"type":     "function",
				"function": map[string]any{"name": DictGetStr(choice, "name", "")},
			}
		}
	}

	if reasoning, ok := payload["reasoning"].(map[string]any); ok {
		if effort, ok := reasoning["effort"].(string); ok {
			chat["reasoning_effort"] = effort
		}
	}

	if textCfg, ok := payload["text"].(map[string]any); ok {
		if fmtDict, ok := textCfg["format"].(map[string]any); ok {
			ft := DictGetStr(fmtDict, "type", "")
			if ft == "json_object" || ft == "json_schema" {
				chat["response_format"] = fmtDict
			}
		}
	}

	return chat, ""
}

func respID() string    { return "resp_" + uuidx.New4()[:24] }
func itemID(prefix string) string {
	return prefix + "_" + uuidx.New4()[:24]
}

// ChatToResponse Chat Completions 响应 → Responses 响应对象。
func ChatToResponse(chat map[string]any, model string) map[string]any {
	var choice map[string]any
	if choices, ok := chat["choices"].([]any); ok && len(choices) > 0 {
		choice, _ = choices[0].(map[string]any)
	}
	if choice == nil {
		choice = map[string]any{}
	}
	msg, _ := choice["message"].(map[string]any)
	if msg == nil {
		msg = map[string]any{}
	}
	var output []any
	var outputTextParts []string

	if text, ok := msg["content"].(string); ok && text != "" {
		outputTextParts = append(outputTextParts, text)
		output = append(output, map[string]any{
			"type":    "message",
			"id":      itemID("msg"),
			"status":  "completed",
			"role":    "assistant",
			"content": []any{map[string]any{"type": "output_text", "text": text, "annotations": []any{}}},
		})
	}
	if toolCalls, ok := msg["tool_calls"].([]any); ok {
		for _, rawTC := range toolCalls {
			tc, ok := rawTC.(map[string]any)
			if !ok {
				continue
			}
			fn, _ := tc["function"].(map[string]any)
			output = append(output, map[string]any{
				"type":      "function_call",
				"id":        itemID("fc"),
				"call_id":   DictGetStr(tc, "id", ""),
				"name":      DictGetStr(fn, "name", ""),
				"arguments": DictGetStr(fn, "arguments", "{}"),
				"status":    "completed",
			})
		}
	}

	inTok, outTok := 0, 0
	if usage, ok := chat["usage"].(map[string]any); ok {
		if n, ok := OpenAIAsInt(usage["prompt_tokens"]); ok {
			inTok = n
		}
		if n, ok := OpenAIAsInt(usage["completion_tokens"]); ok {
			outTok = n
		}
	}
	finish := DictGetStr(choice, "finish_reason", "")
	status := "completed"
	if finish == "length" {
		status = "incomplete"
	}
	m := model
	if v, ok := chat["model"].(string); ok && v != "" {
		m = v
	}
	var incompleteDetails any
	if finish == "length" {
		incompleteDetails = map[string]any{"reason": "max_output_tokens"}
	}
	return map[string]any{
		"id":         respID(),
		"object":     "response",
		"created_at": time.Now().Unix(),
		"status":     status,
		"model":      m,
		"output":     output,
		"output_text": strings.Join(outputTextParts, ""),
		"usage": map[string]any{
			"input_tokens":          inTok,
			"output_tokens":         outTok,
			"total_tokens":          inTok + outTok,
			"input_tokens_details":  map[string]any{"cached_tokens": 0},
			"output_tokens_details": map[string]any{"reasoning_tokens": 0},
		},
		"error":              nil,
		"incomplete_details": incompleteDetails,
		"tools":              []any{},
		"tool_choice":        "auto",
		"parallel_tool_calls": true,
	}
}

// ── ResponsesStreamConverter：Chat chunk 流 → Responses SSE 事件族 ────────────
//
// 输入是 `StreamConverter.FeedEvents()` 产出的 chunk dict；输出是
// `event: <type>\ndata: <json>\n\n` 行（Responses 协议要求带 event 名）。
//
// 不变量（对齐 OpenAI Responses SSE）：
//   - `sequence_number` 从 **0** 起单调递增；
//   - `output_index` 按 item **创建顺序**分配（message 与 function_call 一视
//     同仁）——added/delta/done 三处同值，且与最终 `response.output` 数组
//     顺序一致。不能对 message 写死 0、对 tool 写死 idx+1：上游块序若为
//     tool→text，那样会产出乱序编号。
type ResponsesStreamConverter struct {
	Model      string
	responseID string
	createdAt  int64
	messageItemID string
	messageOpen   bool
	textParts     []string
	toolItems     map[int]map[string]any
	finishReason  *string
	usage         map[string]any // {"prompt_tokens": any, "completion_tokens": any}
	sequence      int
	nextOutput    int
	messageOutputIndex *int
	toolOutputIndex    map[int]int
}

// NewResponsesStreamConverter 构造（对齐 __init__）。
func NewResponsesStreamConverter(model string) *ResponsesStreamConverter {
	return &ResponsesStreamConverter{
		Model:         model,
		responseID:    respID(),
		createdAt:     time.Now().Unix(),
		messageItemID: itemID("msg"),
		toolItems:     map[int]map[string]any{},
		usage:         map[string]any{"prompt_tokens": nil, "completion_tokens": nil},
		sequence:      -1, // 首个 event() 自增后为 0
		nextOutput:    0,
		toolOutputIndex: map[int]int{},
	}
}

func (r *ResponsesStreamConverter) event(etype string, payload map[string]any) string {
	r.sequence++
	full := map[string]any{"type": etype, "sequence_number": r.sequence}
	for k, v := range payload {
		full[k] = v
	}
	b, _ := JSONMarshalCompact(full)
	return "event: " + etype + "\ndata: " + string(b) + "\n\n"
}

func (r *ResponsesStreamConverter) responseSkeleton(status string, output []any) map[string]any {
	inTok, outTok := 0, 0
	if f, ok := AsFloat(r.usage["prompt_tokens"]); ok {
		inTok = int(f)
	}
	if f, ok := AsFloat(r.usage["completion_tokens"]); ok {
		outTok = int(f)
	}
	return map[string]any{
		"id":         r.responseID,
		"object":     "response",
		"created_at": r.createdAt,
		"status":     status,
		"model":      r.Model,
		"output":     output,
		"output_text": strings.Join(r.textParts, ""),
		"usage": map[string]any{
			"input_tokens":          inTok,
			"output_tokens":         outTok,
			"total_tokens":          inTok + outTok,
			"input_tokens_details":  map[string]any{"cached_tokens": 0},
			"output_tokens_details": map[string]any{"reasoning_tokens": 0},
		},
		"error":              nil,
		"incomplete_details": nil,
		"tools":              []any{},
		"tool_choice":        "auto",
		"parallel_tool_calls": true,
	}
}

// Start 对齐 start()。
func (r *ResponsesStreamConverter) Start() []string {
	return []string{
		r.event("response.created", map[string]any{"response": r.responseSkeleton("in_progress", []any{})}),
		r.event("response.in_progress", map[string]any{"response": r.responseSkeleton("in_progress", []any{})}),
	}
}

func (r *ResponsesStreamConverter) openMessage() []string {
	if r.messageOpen {
		return nil
	}
	r.messageOpen = true
	idx := r.nextOutput
	r.nextOutput++
	r.messageOutputIndex = &idx
	item := map[string]any{
		"type":    "message",
		"id":      r.messageItemID,
		"status":  "in_progress",
		"role":    "assistant",
		"content": []any{},
	}
	return []string{
		r.event("response.output_item.added", map[string]any{
			"output_index": idx, "item": item}),
		r.event("response.content_part.added", map[string]any{
			"item_id":      r.messageItemID,
			"output_index": idx,
			"content_index": 0,
			"part":         map[string]any{"type": "output_text", "text": "", "annotations": []any{}},
		}),
	}
}

// FeedChunk 对齐 feed_chunk(chunk)。
func (r *ResponsesStreamConverter) FeedChunk(chunk map[string]any) []string {
	var out []string
	var choice map[string]any
	if choices, ok := chunk["choices"].([]any); ok && len(choices) > 0 {
		choice, _ = choices[0].(map[string]any)
	}
	if choice == nil {
		choice = map[string]any{}
	}
	delta, _ := choice["delta"].(map[string]any)
	if delta == nil {
		delta = map[string]any{}
	}
	if usage, ok := chunk["usage"].(map[string]any); ok && len(usage) > 0 {
		r.usage["prompt_tokens"] = usage["prompt_tokens"]
		r.usage["completion_tokens"] = usage["completion_tokens"]
	}

	if text, ok := delta["content"].(string); ok && text != "" {
		out = append(out, r.openMessage()...)
		r.textParts = append(r.textParts, text)
		out = append(out, r.event("response.output_text.delta", map[string]any{
			"item_id":       r.messageItemID,
			"output_index":  *r.messageOutputIndex,
			"content_index": 0,
			"delta":         text,
		}))
	}
	if toolCalls, ok := delta["tool_calls"].([]any); ok {
		for _, rawTC := range toolCalls {
			tc, ok := rawTC.(map[string]any)
			if !ok {
				continue
			}
			idx := 0
			if n, ok := OpenAIAsInt(tc["index"]); ok {
				idx = n
			}
			fn, _ := tc["function"].(map[string]any)
			if fn == nil {
				fn = map[string]any{}
			}
			if _, exists := r.toolItems[idx]; !exists {
				item := map[string]any{
					"type":      "function_call",
					"id":        itemID("fc"),
					"call_id":   DictGetStr(tc, "id", ""),
					"name":      DictGetStr(fn, "name", ""),
					"arguments": "",
					"status":    "in_progress",
				}
				r.toolItems[idx] = item
				outIdx := r.nextOutput
				r.nextOutput++
				r.toolOutputIndex[idx] = outIdx
				out = append(out, r.event("response.output_item.added", map[string]any{
					"output_index": outIdx, "item": deepCopyDict(item),
				}))
			}
			if args, ok := fn["arguments"].(string); ok && args != "" {
				item := r.toolItems[idx]
				item["arguments"] = item["arguments"].(string) + args
				out = append(out, r.event("response.function_call_arguments.delta", map[string]any{
					"item_id":      item["id"],
					"output_index": r.toolOutputIndex[idx],
					"delta":        args,
				}))
			}
		}
	}
	if fr, ok := choice["finish_reason"].(string); ok && fr != "" {
		f := fr
		r.finishReason = &f
	} else if choice["finish_reason"] != nil {
		// finish_reason 非 string（异常形状）时对齐 Python 真值判断——非空即记录
		if s := StrValue(choice["finish_reason"]); s != "" {
			f := s
			r.finishReason = &f
		}
	}
	return out
}

// Done 对齐 done()。
func (r *ResponsesStreamConverter) Done() []string {
	var out []string
	text := strings.Join(r.textParts, "")
	type idxItem struct {
		idx  int
		item map[string]any
	}
	var finalItems []idxItem
	if r.messageOpen {
		out = append(out, r.event("response.output_text.done", map[string]any{
			"item_id":       r.messageItemID,
			"output_index":  *r.messageOutputIndex,
			"content_index": 0,
			"text":          text,
		}))
		out = append(out, r.event("response.content_part.done", map[string]any{
			"item_id":       r.messageItemID,
			"output_index":  *r.messageOutputIndex,
			"content_index": 0,
			"part":          map[string]any{"type": "output_text", "text": text, "annotations": []any{}},
		}))
		messageItem := map[string]any{
			"type":    "message",
			"id":      r.messageItemID,
			"status":  "completed",
			"role":    "assistant",
			"content": []any{map[string]any{"type": "output_text", "text": text, "annotations": []any{}}},
		}
		out = append(out, r.event("response.output_item.done", map[string]any{
			"output_index": *r.messageOutputIndex, "item": messageItem,
		}))
		finalItems = append(finalItems, idxItem{*r.messageOutputIndex, messageItem})
	}
	// 对齐 sorted(self.tool_items.items())：按 idx 升序
	idxs := make([]int, 0, len(r.toolItems))
	for idx := range r.toolItems {
		idxs = append(idxs, idx)
	}
	sort.Ints(idxs)
	for _, idx := range idxs {
		item := r.toolItems[idx]
		out = append(out, r.event("response.function_call_arguments.done", map[string]any{
			"item_id":      item["id"],
			"output_index": r.toolOutputIndex[idx],
			"arguments":    item["arguments"],
		}))
		item["status"] = "completed"
		finalItems = append(finalItems, idxItem{r.toolOutputIndex[idx], deepCopyDict(item).(map[string]any)})
		out = append(out, r.event("response.output_item.done", map[string]any{
			"output_index": r.toolOutputIndex[idx], "item": deepCopyDict(item),
		}))
	}

	// 最终 output 数组按 output_index 排序（= item 创建顺序）
	sort.Slice(finalItems, func(i, j int) bool { return finalItems[i].idx < finalItems[j].idx })
	outputItems := make([]any, 0, len(finalItems))
	for _, pair := range finalItems {
		outputItems = append(outputItems, pair.item)
	}
	status := "completed"
	if r.finishReason != nil && *r.finishReason == "length" {
		status = "incomplete"
	}
	final := r.responseSkeleton(status, outputItems)
	if status == "incomplete" {
		final["incomplete_details"] = map[string]any{"reason": "max_output_tokens"}
	}
	out = append(out, r.event("response.completed", map[string]any{"response": final}))
	return out
}

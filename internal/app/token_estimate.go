// token 估算 —— `/v1/messages/count_tokens` 的本地实现。
//
// 上游（zcode-plan anthropic 网关与 api.z.ai）**没有** count_tokens 端点
//（2026-11-02 实测 404），但 Anthropic SDK 客户端会先调它做预算。这里给一个
// 确定性估算器：不追求与 GLM 分词器逐 token 对齐，目标是「量级正确、单调、
// 不把客户端吓退」。
//
// 口径：
//   - ASCII/拉丁字符按 4 字符 ≈ 1 token；
//   - CJK 等非拉丁字符按 1 字符 ≈ 1 token；
//   - 每条消息 +4（role/分隔符开销），图片 +1600（anthropic 的图片计价口径）；
//   - tools 的 JSON Schema 按文本估算。
//
// 对齐 Python app/token_estimate.py。
package app

import (
	"math"
	"strings"
)

// strings_repeat0_32 / strings_repeat0_36 对齐 Python "0"*32 与 "0"*36
//（attribution 定长代表值）。
var (
	strings_repeat0_32 = strings.Repeat("0", 32)
	strings_repeat0_36 = strings.Repeat("0", 36)
)

func textTokens(text string) int {
	if text == "" {
		return 0
	}
	asciiChars := 0
	wideChars := 0
	for _, ch := range text {
		if ch < 128 {
			asciiChars++
		} else {
			wideChars++
		}
	}
	return int(math.Ceil(float64(asciiChars)/4.0)) + wideChars
}

func contentTokens(content any) int {
	if s, ok := content.(string); ok {
		return textTokens(s)
	}
	list, ok := content.([]any)
	if !ok {
		return 0
	}
	total := 0
	for _, rawBlock := range list {
		block, ok := rawBlock.(map[string]any)
		if !ok {
			continue
		}
		btype := block["type"]
		switch btype {
		case "text":
			if t, ok := block["text"].(string); ok {
				total += textTokens(t)
			}
		case "image":
			total += 1600
		case "tool_use":
			total += textTokens(StrValue(block["name"]))
			in := block["input"]
			if in == nil {
				in = map[string]any{}
			}
			if s, err := JSONMarshalCompact(in); err == nil {
				total += textTokens(string(s))
			}
		case "tool_result":
			total += contentTokens(block["content"])
		case "thinking":
			if t, ok := block["thinking"].(string); ok {
				total += textTokens(t)
			}
		}
	}
	return total
}

// EstimateInputTokens 估算 anthropic messages 请求体的 input tokens（含 system / messages / tools）。
func EstimateInputTokens(body map[string]any) int {
	total := 0
	if system, ok := body["system"].(string); ok {
		total += textTokens(system)
	} else if systemList, ok := body["system"].([]any); ok {
		total += contentTokens(systemList)
	}
	if messages, ok := body["messages"].([]any); ok {
		for _, rawMsg := range messages {
			msg, ok := rawMsg.(map[string]any)
			if !ok {
				continue
			}
			total += 4
			total += contentTokens(msg["content"])
		}
	}
	if tools, ok := body["tools"].([]any); ok {
		for _, rawTool := range tools {
			if _, ok := rawTool.(map[string]any); ok {
				if s, err := JSONMarshalCompact(rawTool); err == nil {
					total += textTokens(string(s))
				}
			}
		}
	}
	if total < 1 {
		total = 1
	}
	return total
}

// EstimateInputTokensAfterTransform 估算 **transform 之后**（上游实际计费形状）的 input tokens。
//
// Plan 通道的请求会被 `body_transform` 注入官方 system 三块 + 日期轮 +
// attribution blob——2026-11-03 线上标定：这笔固定开销 ≈400 tok，count_tokens
// 若只算客户端原始 body，对小请求低估近百倍（6 tok 的请求实际 341）。
// attribution 用定长代表值（实际 device_mid/session_id 同量级，差 <1 tok）。
// Key 回退通道不做 transform，此估算对其略偏高——预算场景偏高是安全方向。
func EstimateInputTokensAfterTransform(body map[string]any, model string) int {
	transformed := deepCopyDict(body).(map[string]any)
	TransformBody(transformed, "", model, strings_repeat0_32, strings_repeat0_36)
	return EstimateInputTokens(transformed)
}

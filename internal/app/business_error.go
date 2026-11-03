// 上游「HTTP 200 承载业务错误」的统一识别。
//
// 2026-10-30/31 线上实证（Plan 通道）：额度与风控类拒绝经常**不是** 4xx，而是
// HTTP 200 + `application/json` + `{"code":1005,"msg":"exceed quota limit"}`。
// 不识别有三个后果：
//
//  1. messages：错误体当正文透传给客户端（「200 但没有 message」），成功分支还会
//     洗掉 risk_strikes / 冷却 / last_error，把仍在标记期的号拉回 ACTIVE；
//  2. billing 全家桶：业务失败被当成空数据写库，把 quota 快照 / plans 洗空；
//  3. 告警与指标全绿，问题只能靠人肉盯。
//
// 判定口径（唯一一处）：合法响应一定带业务形状（messages 有 `type`/`content`，
// billing 有 `data` 或 `code` 为 0/200）；因此「无业务形状 + code 是非 0/200 的
// 整数」即业务错误。带 type/content 的一律不判错，避免误杀正常响应。
//
// 对齐 Python app/business_error.py。
package app

// BusinessCode 返回 HTTP 200 响应里承载的业务错误码；不是业务错误则返回 false。
//
// Python 返回 int | None；Go 以 (code, ok) 表达 None 语义。
// 本服务所有 JSON 解析统一走 UseNumber()（见 jsonutil.go），数字形态为 json.Number；
// int/float64 分支仅兜底手工构造的值。
func BusinessCode(payload any) (int, bool) {
	data, ok := payload.(map[string]any)
	if !ok {
		return 0, false
	}
	if _, has := data["type"]; has {
		return 0, false // messages 正常响应形状
	}
	if _, has := data["content"]; has {
		return 0, false // messages 正常响应形状
	}
	rawCode, has := data["code"]
	if !has {
		return 0, false
	}
	// Python: bool 是 int 子类需显式排除；JSON 解析不出 bool/int 混淆，但保持对齐
	if _, isBool := rawCode.(bool); isBool {
		return 0, false
	}
	switch c := rawCode.(type) {
	case int:
		if c == 0 || c == 200 {
			return 0, false
		}
		return c, true
	case float64:
		// encoding/json 默认把数字解成 float64；仅整数值视为业务码（对齐 isinstance(code, int)）
		if c == float64(int(c)) {
			ic := int(c)
			if ic == 0 || ic == 200 {
				return 0, false
			}
			return ic, true
		}
		return 0, false
	case jsonNum:
		if ic, err := c.Int64(); err == nil {
			iv := int(ic)
			if iv == 0 || iv == 200 {
				return 0, false
			}
			return iv, true
		}
		return 0, false
	default:
		return 0, false
	}
}

// IsQuotaError 业务码是否属于「额度/余额耗尽」一类。
func IsQuotaError(code int, ok bool) bool {
	if !ok {
		return false
	}
	for _, c := range EXHAUST_BUSINESS_CODES {
		if c == code {
			return true
		}
	}
	return false
}

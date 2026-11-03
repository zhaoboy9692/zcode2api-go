// JSON 工具 — 对齐 Python json.loads / json.dumps 在本服务中的使用口径。
//
// 关键口径：
//   - 解析一律 UseNumber()：Python json.loads 把整数字面量解成 int、小数解成
//     float；Go encoding/json 默认把一切数字解成 float64，会在 epoch 秒、token
//     计数等大整数上丢精度（>2^53 才丢，但 expires_at 毫秒值已接近）。统一
//     json.Number 保留字面量，数值读取走 helper（AsInt/AsFloat）。
//   - 序列化 ensure_ascii=False（Go 默认即不转义非 ASCII）+ 关闭 HTML 转义
//     （Python 不转义 <>&；FastAPI JSONResponse 分隔符为 (",", ":")）。
package app

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// JSONDecode 对齐 json.loads(text)：UseNumber 保留数字字面量。
func JSONDecode(text string) (any, error) {
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// SafeJSON 对齐 gateway._safe_json：解析失败返回 nil（不区分错误）。
func SafeJSON(text string) any {
	v, err := JSONDecode(text)
	if err != nil {
		return nil
	}
	return v
}

// JSONMarshalCompact 序列化为紧凑 JSON（ensure_ascii=False，无 HTML 转义）。
// 对齐 json.dumps(v, ensure_ascii=False, separators=(",", ":"))。
func JSONMarshalCompact(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	// Encode 追加 '\n'，与 json.dumps 输出形态对齐则去掉
	out := buf.Bytes()
	if len(out) > 0 && out[len(out)-1] == '\n' {
		out = out[:len(out)-1]
	}
	return out, nil
}

// JSONMarshalIndent 缩进序列化（对齐 json.dump(..., indent=2, ensure_ascii=False)）。
func JSONMarshalIndent(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	out := buf.Bytes()
	if len(out) > 0 && out[len(out)-1] == '\n' {
		out = out[:len(out)-1]
	}
	return out, nil
}

// AsFloat 从 JSON 值取 float（int/float64/json.Number 皆可；失败 ok=false）。
func AsFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(n), 64)
		return f, err == nil
	default:
		return 0, false
	}
}

// AsInt 从 JSON 值取 int（含截断语义，对齐 Python int(value)）。
func AsInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	case json.Number:
		// Python int("3.7") 会抛 ValueError，但 int(3.7)==3；json.Number 优先按整数字面量
		if i, err := n.Int64(); err == nil {
			return int(i), true
		}
		if f, err := n.Float64(); err == nil {
			return int(f), true
		}
		return 0, false
	default:
		return 0, false
	}
}

// AsString 从 JSON 值取字符串（仅 string 形态返回 true，对齐 isinstance(x, str)）。
func AsString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

// AsDict 断言 map 形态。
func AsDict(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

// AsList 断言数组形态。
func AsList(v any) ([]any, bool) {
	l, ok := v.([]any)
	return l, ok
}

// DictGetStr 取字符串字段，缺失/非串返回 def。
func DictGetStr(m map[string]any, key, def string) string {
	if m == nil {
		return def
	}
	if s, ok := m[key].(string); ok {
		return s
	}
	return def
}

// DumpJSONText 调试输出（截断用）：等价 str(body) 的紧凑形态。
func DumpJSONText(v any) string {
	b, err := JSONMarshalCompact(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

// StrValue 对齐 Python str(v)（本服务涉及的标量子集）：string 原样，
// 数字字面量化，bool → "True"/"False"，nil → ""。
// Python str(True)=="True"；JSON 场景经 str() 后仅做 contains 判定，
// 大小写不影响结果，此处统一小写化调用方处理。
func StrValue(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case json.Number:
		return t.String()
	default:
		return DumpJSONText(v)
	}
}

// parseISO8601 对齐 datetime.fromisoformat(text.replace("Z", "+00:00"))：
// 支持带 Z/偏移/无时区（按 UTC）/纯日期；解析失败返回错误。
// time.Parse 对无时区布局本就按 UTC 解析（「无时区按 UTC」天然满足），
// 带偏移布局的 Unix 秒与原时区一致。
func parseISO8601(text string) (time.Time, error) {
	normalized := strings.Replace(text, "Z", "+00:00", 1)
	normalized = strings.Replace(normalized, "z", "+00:00", 1)
	layouts := []string{
		"2006-01-02T15:04:05.999999999-07:00",
		"2006-01-02T15:04:05.999999999",
		"2006-01-02T15:04",
		"2006-01-02",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, normalized); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("无法解析 ISO8601: %s", text)
}

// strconvParseFloat 对齐 float(text)（含前后空白）。
func strconvParseFloat(text string) (float64, error) {
	return strconv.ParseFloat(strings.TrimSpace(text), 64)
}

// sha256Hex32 对齐 hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]。
func sha256Hex32(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])[:32]
}

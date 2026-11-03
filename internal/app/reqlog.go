// 请求监控 —— 网关请求的内存环形日志（管理端「请求监控」页数据源）。
//
// 设计要点：
//   - 仅内存（上限 500 条），重启即清零：定位是运维实时观测而非审计，
//     避免每请求写库的 IO 放大（与 billing 刷新去抖同一节流思路）
//   - 粒度：一次客户端请求一条；多账号重试不分裂，账号字段记录最终归宿
//   - ok 三态：nil=在途/未知，true=成功，false=失败（含客户端断开 status=499）
//   - 纯观测：不触碰账号状态与调度逻辑
//
// 对齐 Python app/reqlog.py。
package app

import (
	"sync"

	"github.com/zhaoboy9692/zcode2api-go/internal/uuidx"
)

// ReqLogKeep 环形日志容量（对齐 KEEP = 500）。
const ReqLogKeep = 500

type reqLogEntry struct {
	mu          sync.Mutex
	reqID       string
	ts          float64
	endpoint    string
	model       string
	stream      bool
	preview     string
	account     string
	mode        string
	ok          *bool // nil=在途/未知
	status      *int
	error       string
	tFirst      *float64
	tTotal      *float64
	inputTokens  *int
	outputTokens *int
}

func (e *reqLogEntry) toDict() map[string]any {
	e.mu.Lock()
	defer e.mu.Unlock()
	var ok any
	if e.ok != nil {
		ok = *e.ok
	}
	var status any
	if e.status != nil {
		status = *e.status
	}
	var tFirst any
	if e.tFirst != nil {
		tFirst = *e.tFirst
	}
	var tTotal any
	if e.tTotal != nil {
		tTotal = *e.tTotal
	}
	var inTok any
	if e.inputTokens != nil {
		inTok = *e.inputTokens
	}
	var outTok any
	if e.outputTokens != nil {
		outTok = *e.outputTokens
	}
	return map[string]any{
		"req_id":        e.reqID,
		"ts":            e.ts,
		"endpoint":      e.endpoint,
		"model":         e.model,
		"stream":        e.stream,
		"preview":       e.preview,
		"account":       e.account,
		"mode":          e.mode,
		"ok":            ok,
		"status":        status,
		"error":         e.error,
		"t_first":       tFirst,
		"t_total":       tTotal,
		"input_tokens":  inTok,
		"output_tokens": outTok,
	}
}

var (
	reqLogMu       sync.Mutex
	reqLogEntries  []*reqLogEntry
	reqLogInflight = map[string]*reqLogEntry{}
)

// ReqLogBegin 请求进入网关（鉴权通过、body 解析成功后）。
func ReqLogBegin(reqID, endpoint, model string, stream bool, preview string) {
	p := preview
	if r := []rune(p); len(r) > 80 {
		p = string(r[:80])
	}
	entry := &reqLogEntry{
		reqID:    reqID,
		ts:       NowFloat(),
		endpoint: endpoint,
		model:    model,
		stream:   stream,
		preview:  p,
	}
	reqLogMu.Lock()
	defer reqLogMu.Unlock()
	reqLogEntries = append(reqLogEntries, entry)
	if len(reqLogEntries) > ReqLogKeep {
		// deque(maxlen) 语义：容量超限从头弹出
		reqLogEntries = reqLogEntries[len(reqLogEntries)-ReqLogKeep:]
	}
	reqLogInflight[reqID] = entry
}

// ReqLogMarkAccount 记录实际服务该请求的账号（多账号重试时最后一次生效）。
func ReqLogMarkAccount(reqID, accountName, mode string) {
	reqLogMu.Lock()
	defer reqLogMu.Unlock()
	if entry, ok := reqLogInflight[reqID]; ok {
		entry.mu.Lock()
		entry.account = accountName
		entry.mode = mode
		entry.mu.Unlock()
	}
}

// ReqLogFinishOK 对齐 finish_ok。
func ReqLogFinishOK(reqID string, tFirst *float64, inputTokens, outputTokens *int, status *int) {
	reqLogMu.Lock()
	defer reqLogMu.Unlock()
	entry, ok := reqLogInflight[reqID]
	if !ok {
		return
	}
	delete(reqLogInflight, reqID)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	okVal := true
	entry.ok = &okVal
	st := 200
	if status != nil {
		st = *status
	}
	entry.status = &st
	entry.tFirst = tFirst
	total := NowFloat() - entry.ts
	entry.tTotal = &total
	entry.inputTokens = inputTokens
	entry.outputTokens = outputTokens
}

// ReqLogFinishError 对齐 finish_error。
func ReqLogFinishError(reqID, errMsg string, status *int, tFirst *float64) {
	reqLogMu.Lock()
	defer reqLogMu.Unlock()
	entry, ok := reqLogInflight[reqID]
	if !ok {
		return
	}
	delete(reqLogInflight, reqID)
	entry.mu.Lock()
	defer entry.mu.Unlock()
	okVal := false
	entry.ok = &okVal
	entry.status = status
	if r := []rune(errMsg); len(r) > 200 {
		errMsg = string(r[:200])
	}
	entry.error = errMsg
	entry.tFirst = tFirst
	total := NowFloat() - entry.ts
	entry.tTotal = &total
}

// ReqLogSnapshot 全部条目，最新在前（含在途）。
func ReqLogSnapshot() []any {
	reqLogMu.Lock()
	defer reqLogMu.Unlock()
	out := make([]any, 0, len(reqLogEntries))
	for i := len(reqLogEntries) - 1; i >= 0; i-- {
		out = append(out, reqLogEntries[i].toDict())
	}
	return out
}

// ReqLogClear 对齐 clear()。
func ReqLogClear() {
	reqLogMu.Lock()
	defer reqLogMu.Unlock()
	reqLogEntries = nil
	reqLogInflight = map[string]*reqLogEntry{}
}

// IntPtr / FloatPtr 便捷指针构造（reqlog/gateway 共用）。
func IntPtr(v int) *int           { return &v }
func FloatPtr(v float64) *float64 { return &v }

// NewUUID4 转发 uuidx.New4（app 包外快捷访问，backfill_install_ids 等用）。
func NewUUID4() string { return uuidx.New4() }

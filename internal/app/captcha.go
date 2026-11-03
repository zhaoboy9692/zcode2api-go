// 验证码求解 + 预解 token 池。
//
// 主求解器 solver_pw.js：真浏览器（puppeteer-core + 系统 Chromium）运行阿里云
// 官方无痕 SDK 求 verifyParam（X-Aliyun-Captcha-Verify-Param）——阿里云无痕
// 验证信任真实浏览器环境，happy-dom 伪造路线 2026-09 起被风控「unusual
// activity」全拒（solver.js 仅作 ZCODE_CAPTCHA_SOLVER=legacy 回滚）。
//
// 架构对齐 zapi captcha.ts 的预解池设计：
//   - 热路径永不等待：请求到来时直接从池里取一枚已解好的 token（亚毫秒），
//     后台任务持续补充库存（目标 min，上限 max）。
//   - token 时效：verifyParam 实际 TTL ~2 分钟，池内按 FIFO + 年龄淘汰，
//     超过 token_ttl 的直接丢弃重解。
//   - 挑战失效：上游返回挑战时 Invalidate() 清空整池（该批指纹可能已被
//     风控盯上，继续复用只会连环 3007）。
//
// 对齐 Python app/captcha.py：asyncio.Queue → mutex 保护的双端切片；
// 后台补充循环 → goroutine。
package app

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// httpTimeoutClient 构造 httpx.AsyncClient(timeout, trust_env) 等价客户端。
func httpTimeoutClient(timeout time.Duration, trustEnv bool) *http.Client {
	t := &http.Transport{}
	if trustEnv {
		// trust_env=True：跟随 HTTP_PROXY/NO_PROXY 环境变量
		t.Proxy = http.ProxyFromEnvironment
	}
	return &http.Client{Timeout: timeout, Transport: t}
}

// 池参数：真浏览器求解重（10–40s/枚），默认 min1/max2 见 settings 注释
var (
	captchaPoolMin    = CAPTCHA_POOL_MIN
	captchaPoolMax    = CAPTCHA_POOL_MAX
	captchaTokenTTLMS = CAPTCHA_TOKEN_TTL // 单枚 token 的最大可用时长（ms）
)

// CaptchaSolveError 验证码求解最终失败（重试耗尽/求解器不可用）。
//
// 独立于 ClaimError 体系（验证码先于领域层使用），路由层按兜底回执处理。
type CaptchaSolveError struct{ Message string }

func (e *CaptchaSolveError) Error() string { return e.Message }

type captchaToken struct {
	param   string
	region  string
	bornAt  time.Time // monotonic 语义（Go time.Time 包含 monotonic 读数）
	egress  string
}

func (t *captchaToken) expired() bool {
	return time.Since(t.bornAt).Milliseconds() >= int64(captchaTokenTTLMS)
}

// CaptchaManager 预解池管理器。
type CaptchaManager struct {
	mu            sync.Mutex
	pools         map[string][]*captchaToken // 按出口分池（队列：FIFO）
	refillWG      sync.WaitGroup
	refillStop    chan struct{}
	refillStarted bool
	refilling     bool
	configMu      sync.Mutex
	// 配置按出口缓存：上游按出口 IP 给不同的 captcha 配置（实测直连 region=cn、
	// 走 US 代理 region=sgp），混用会把错地区的 token 配到请求上。
	configCache   map[string]map[string]any
	configCacheAt map[string]float64
	lastError     string
	bgWG          sync.WaitGroup
}

// DefaultCaptchaManager 全局单例（对齐 captcha_manager = CaptchaManager()）。
// Python 里模块单例名 captcha_manager 与类名不冲突；Go 同包需改名对齐。
var DefaultCaptchaManager = newCaptchaManager()

func newCaptchaManager() *CaptchaManager {
	return &CaptchaManager{
		pools:         map[string][]*captchaToken{},
		configCache:   map[string]map[string]any{},
		configCacheAt: map[string]float64{},
	}
}

// ── 出口 ─────────────────────────────────────────────────────────────────────

// HotEgress 预热哪个出口的池：默认跟随 messages 上游的实际出口。
//
// 只有 messages 是热路径（每次请求都要验证码）；claim 一小时一轮，
// 按需现解即可，不必占第二个池的内存。
func (m *CaptchaManager) HotEgress() string {
	forced := CAPTCHA_POOL_EGRESS
	if forced != "" {
		return forced
	}
	return EgressFor(UPSTREAM["zai"])
}

func (m *CaptchaManager) size(tag string) int {
	return len(m.pools[tag])
}

// ── 配置 ─────────────────────────────────────────────────────────────────────

// FetchConfig 取 captcha 配置（按出口缓存）。`egressTag` 决定拉取走哪条出口。
func (m *CaptchaManager) FetchConfig(egressTag string) (map[string]any, error) {
	tag := egressTag
	if tag == "" {
		tag = m.HotEgress()
	}
	ttl := float64(CAPTCHA_CONFIG_CACHE_TTL)
	m.mu.Lock()
	if cfg, ok := m.configCache[tag]; ok && NowFloat()*1000-m.configCacheAt[tag] < ttl {
		m.mu.Unlock()
		return cfg, nil
	}
	m.mu.Unlock()

	m.configMu.Lock()
	defer m.configMu.Unlock()
	// 双检：等锁期间可能已被其他请求填充
	m.mu.Lock()
	if cfg, ok := m.configCache[tag]; ok && NowFloat()*1000-m.configCacheAt[tag] < ttl {
		m.mu.Unlock()
		return cfg, nil
	}
	m.mu.Unlock()

	var err error
	for attempt := 0; attempt < 2; attempt++ { // 15s 走 US 代理偶发 ReadTimeout，重试一次
		cfg, fetchErr := fetchCaptchaConfigHTTP(tag)
		if fetchErr == nil && len(cfg) > 0 {
			m.mu.Lock()
			m.configCache[tag] = cfg
			m.configCacheAt[tag] = NowFloat() * 1000
			m.mu.Unlock()
			return cfg, nil
		}
		err = fetchErr
	}
	errType := "无响应"
	if err != nil {
		errType = fmt.Sprintf("%T", err)
	}
	LogWarn("captcha", fmt.Sprintf("获取配置失败（出口=%s），使用默认: %s: %v", tag, errType, err))
	return CaptchaDefaults(), nil
}

// fetchCaptchaConfigHTTP httpx (timeout=30, trust_env=tag==PROXY) 拉取 configs。
func fetchCaptchaConfigHTTP(tag string) (map[string]any, error) {
	client := httpTimeoutClient(30*time.Second, tag == EgressProxy)
	res, err := client.Get(CLIENT_CONFIGS_URL + "?" + ClientConfigsQuery())
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d", res.StatusCode)
	}
	buf := &strings.Builder{}
	tmp := make([]byte, 32*1024)
	for {
		n, readErr := res.Body.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if readErr != nil {
			break
		}
	}
	v, err := JSONDecode(buf.String())
	if err != nil {
		return nil, err
	}
	dict, _ := v.(map[string]any)
	if dict == nil {
		return nil, nil
	}
	data, _ := dict["data"].(map[string]any)
	cfgs, _ := data["configs"].(map[string]any)
	if cfgs == nil {
		return nil, nil
	}
	captcha, _ := cfgs["captcha"].(map[string]any)
	if captcha == nil {
		return nil, nil
	}
	return captcha, nil
}

// ModelRequestsNeedCaptcha 模型请求是否该带验证码——官方 `requiresRequestVerification` 的等价物。
//
// bundle 原文：`mode==="start-plan" && enabled!==false && skipModelRequest!==true`。
// 线上配置 `skip_model_request:true` ⇒ 官方客户端在模型请求上**不带**
// `X-Aliyun-Captcha-Verify-Param`；hub 长期无条件带，这正是「官方不会干的
// 事」，也是 3012 的结构性嫌疑。无配置时官方仍要求验证码，故默认 false。
func (m *CaptchaManager) ModelRequestsNeedCaptcha(egressTag string) bool {
	config, _ := m.FetchConfig(egressTag)
	// enabled is not False（缺省视为 true）
	enabledOK := true
	if v, has := config["enabled"]; has {
		if b, ok := v.(bool); ok && !b {
			enabledOK = false
		}
	}
	// skip_model_request is not True
	skipOK := true
	if v, has := config["skip_model_request"]; has {
		if b, ok := v.(bool); ok && b {
			skipOK = false
		}
	}
	return enabledOK && skipOK
}

// ── 预解池 ───────────────────────────────────────────────────────────────────

// Start 启动后台补充循环（生命周期启动调用）。
func (m *CaptchaManager) Start() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.refillStarted {
		return
	}
	m.refillStarted = true
	m.refillStop = make(chan struct{})
	m.refillWG.Add(1)
	go m.refillLoop()
}

// Close 停止后台补充循环（生命周期关闭调用）。
func (m *CaptchaManager) Close() {
	m.mu.Lock()
	if !m.refillStarted || m.refillStop == nil {
		m.mu.Unlock()
		return
	}
	stop := m.refillStop
	m.refillStop = nil
	m.mu.Unlock()
	close(stop)
	m.refillWG.Wait()
	m.mu.Lock()
	m.refillStarted = false
	m.mu.Unlock()
}

// gateOpen 是否允许预热：存在可走 Plan 对话的 jwt 账号才预热。
//
// apiKey 回退 / 废 JWT / 风控禁用 / 额度用完 / 冷却 都不需要验证码。
// 账号冷却状态随 store 落库，重启后全冷却期间此门保持关闭。
func (m *CaptchaManager) gateOpen() bool {
	for _, a := range DefaultStore.ListAccounts("zai") {
		if a.AllowsBilling(0) && a.IsSelectable(0) {
			return true
		}
	}
	return false
}

func (m *CaptchaManager) refillLoop() {
	defer m.refillWG.Done()
	stop := func() chan struct{} {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.refillStop
	}
	for {
		ch := stop()
		if ch == nil {
			return
		}
		exit := false
		func() {
			defer func() {
				if r := recover(); r != nil {
					m.mu.Lock()
					m.lastError = fmt.Sprintf("%v", r)
					m.mu.Unlock()
					LogWarn("captcha", fmt.Sprintf("补充循环异常: %v", r))
					time.Sleep(5 * time.Second)
				}
			}()
			tag := m.HotEgress()
			// 无可服务账号（全冷却/禁用/无号）：只淘汰过期 token，不解新码（不产生上游流量）
			if !m.gateOpen() {
				m.evictExpired(tag)
				if sleepStop(stop(), 3*time.Second) {
					exit = true
				}
				return
			}
			// 上游对模型请求免验证码（skip_model_request）时池无人取用，
			// 继续预热只是白烧阿里云求解流量与 chrome 内存
			if !m.ModelRequestsNeedCaptcha(tag) {
				m.evictExpired(tag)
				if sleepStop(stop(), 30*time.Second) {
					exit = true
				}
				return
			}
			need := captchaPoolMin - m.size(tag)
			if need > 0 {
				m.refillBatch(need, tag)
			} else {
				m.evictExpired(tag)
			}
			if sleepStop(stop(), 3*time.Second) {
				exit = true
			}
		}()
		if exit {
			return
		}
	}
}

func sleepStop(stop chan struct{}, d time.Duration) bool {
	select {
	case <-stop:
		return true
	case <-time.After(d):
		return false
	}
}

// refillBatch 串行补充（求解有 CPU 开销，避免并发爆 Node 进程）。
func (m *CaptchaManager) refillBatch(need int, tag string) {
	m.mu.Lock()
	if m.refilling {
		m.mu.Unlock()
		return
	}
	m.refilling = true
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		m.refilling = false
		m.mu.Unlock()
	}()
	if tag == "" {
		tag = m.HotEgress()
	}
	config, _ := m.FetchConfig(tag)
	for i := 0; i < need; i++ {
		if m.size(tag) >= captchaPoolMax {
			break
		}
		token, err := m.solveOne(config, tag)
		if err != nil || token == nil {
			break
		}
		m.put(token, tag)
	}
}

func (m *CaptchaManager) put(token *captchaToken, tag string) {
	if tag == "" {
		tag = token.egress
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.pools[tag]) < captchaPoolMax {
		m.pools[tag] = append(m.pools[tag], token)
	}
	// asyncio.QueueFull → 丢弃（put_nowait 容忍满池）
}

func (m *CaptchaManager) evictExpired(tag string) {
	tags := []string{tag}
	if tag == "" {
		m.mu.Lock()
		for k := range m.pools {
			tags = append(tags, k)
		}
		m.mu.Unlock()
	}
	for _, one := range tags {
		m.mu.Lock()
		pool := m.pools[one]
		var kept []*captchaToken
		for _, token := range pool {
			if !token.expired() && len(kept) < captchaPoolMax {
				kept = append(kept, token)
			}
		}
		m.pools[one] = kept
		m.mu.Unlock()
	}
}

// GetVerifyParam 取一枚可用 token：优先池内现成的（跳过过期），池空才同步现解。
//
// `egressTag` 必须是本次请求真实使用的出口（`proxy` / `direct`），
// 否则拿到的 token 与请求 IP 不一致，上游会判 unusual activity。
// 只有热路径出口有池；其它出口现解。
//
// 返回 (verify_param, region)。region 可为 ""（旧求解器无 region 概念）。
func (m *CaptchaManager) GetVerifyParam(egressTag string) (string, string, error) {
	tag := egressTag
	if tag == "" {
		tag = m.HotEgress()
	}
	pooled := tag == m.HotEgress()

	// 1) 池内直取（仅热路径出口有池）
	for pooled {
		m.mu.Lock()
		pool := m.pools[tag]
		if len(pool) == 0 {
			m.mu.Unlock()
			break
		}
		token := pool[0]
		m.pools[tag] = pool[1:]
		m.mu.Unlock()
		if token.egress == tag && !token.expired() {
			// 触发后台补货（fire-and-forget；refilling 防重入，WaitGroup 强引用防泄漏）
			m.bgWG.Add(1)
			go func() {
				defer m.bgWG.Done()
				m.refillBatch(1, tag)
			}()
			return token.param, token.region, nil
		}
	}

	// 2) 池空/全过期/非热路径出口：同步现解一次
	config, _ := m.FetchConfig(tag)
	token, err := m.solveOne(config, tag)
	if err != nil || token == nil {
		m.mu.Lock()
		last := m.lastError
		m.mu.Unlock()
		if last == "" {
			last = "多次重试无结果"
		}
		return "", "", &CaptchaSolveError{Message: fmt.Sprintf("验证码求解失败: %s", last)}
	}
	return token.param, token.region, nil
}

// ── 求解 ─────────────────────────────────────────────────────────────────────

func (m *CaptchaManager) solveOne(config map[string]any, tag string) (*captchaToken, error) {
	scene := DictGetStr(config, "sceneId", "")
	if scene == "" {
		scene = DictGetStr(CaptchaDefaults(), "sceneId", "")
	}
	region := DictGetStr(config, "region", "")
	if region == "" {
		region = DictGetStr(CaptchaDefaults(), "region", "")
	}
	prefix := DictGetStr(config, "prefix", "")
	if prefix == "" {
		prefix = DictGetStr(CaptchaDefaults(), "prefix", "")
	}

	var lastErr error
	for attempt := 1; attempt <= CAPTCHA_SOLVE_RETRIES; attempt++ {
		param, err := m.runSolver(scene, region, prefix, tag)
		lastErr = err
		if param != "" {
			if attempt > 1 {
				LogOK("captcha", fmt.Sprintf("求解成功（第 %d 次尝试，出口=%s）", attempt, tag))
			}
			return &captchaToken{param: param, region: region, bornAt: time.Now(), egress: tag}, nil
		}
		m.mu.Lock()
		if lastErr != nil {
			m.lastError = lastErr.Error()
		}
		m.mu.Unlock()
		LogWarn("captcha", fmt.Sprintf("第 %d/%d 次求解未果，重试…", attempt, CAPTCHA_SOLVE_RETRIES))
	}
	LogWarn("captcha", fmt.Sprintf("求解失败: %v", lastErr))
	return nil, lastErr
}

// runSolver 子进程调用 node solver（对齐 asyncio.create_subprocess_exec）。
//
// 出口必须与取用该 token 的请求一致（见 egress.go）：
//
//	direct → 剥掉代理变量，chrome 不带 --proxy-server
//	proxy  → 注入代理变量，solver 用它作 --proxy-server
func (m *CaptchaManager) runSolver(scene, region, prefix, tag string) (string, error) {
	solver := CAPTCHA_SOLVER_JS
	if _, err := os.Stat(solver); err != nil {
		return "", fmt.Errorf("未找到求解器 %s，请先在 captcha_node 下执行 npm install", solver)
	}
	solverEnv := os.Environ()
	solverEnv = append(solverEnv, "ZCODE_CHROMIUM_PATH="+CHROMIUM_PATH)
	proxyKeys := []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY", "all_proxy"}
	var cleaned []string
	for _, kv := range solverEnv {
		eq := strings.Index(kv, "=")
		if eq <= 0 {
			cleaned = append(cleaned, kv)
			continue
		}
		key := kv[:eq]
		drop := false
		for _, pk := range proxyKeys {
			if key == pk {
				drop = true
				break
			}
		}
		if !drop {
			cleaned = append(cleaned, kv)
		}
	}
	if tag == EgressProxy {
		proxy := ProxyURL("")
		if proxy == "" {
			return "", fmt.Errorf("请求走代理但 env 未配置代理地址，无法对齐验证码出口")
		}
		cleaned = append(cleaned, "HTTP_PROXY="+proxy, "HTTPS_PROXY="+proxy)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(CAPTCHA_SOLVE_TIMEOUT)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, NODE_PATH, solver, scene, region, prefix)
	cmd.Dir = CAPTCHA_SOLVER_DIR
	cmd.Env = cleaned
	stdout, err := cmd.Output()
	if ctx.Err() == context.DeadlineExceeded {
		// 对齐 TimeoutError → kill → return None
		return "", nil
	}
	if err != nil {
		// FileNotFoundError（node 不存在）等启动失败
		if isExecNotFound(err) {
			return "", fmt.Errorf("无法启动 Node（%s）: %v", NODE_PATH, err)
		}
		return "", nil
	}
	param := ""
	for _, line := range strings.Split(string(stdout), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if strings.HasPrefix(line, "VERIFY_PARAM=") {
			param = strings.TrimSpace(line[len("VERIFY_PARAM="):])
		}
	}
	return param, nil
}

func isExecNotFound(err error) bool {
	if _, ok := err.(*exec.Error); ok {
		return true
	}
	return false
}

// ── 失效 ─────────────────────────────────────────────────────────────────────

// Invalidate 上游返回验证码挑战时清空该出口的池（该批 token/指纹已不可信）。
//
// 默认只清热路径出口：只按出口清，避免把另一条通道（如 claim 的直连池）
// 一起废掉。传空 tag 时清热路径；需要全清时用 InvalidateAll()。
func (m *CaptchaManager) Invalidate(tag string) {
	if tag == "" {
		tag = m.HotEgress()
	}
	m.drain(tag)
}

// InvalidateAll 全出口清池。
func (m *CaptchaManager) InvalidateAll() {
	m.mu.Lock()
	tags := make([]string, 0, len(m.pools))
	for tag := range m.pools {
		tags = append(tags, tag)
	}
	m.mu.Unlock()
	for _, tag := range tags {
		m.drain(tag)
	}
}

func (m *CaptchaManager) drain(tag string) {
	m.mu.Lock()
	pool := m.pools[tag]
	if pool == nil {
		m.mu.Unlock()
		return
	}
	drained := len(pool)
	m.pools[tag] = nil
	m.mu.Unlock()
	if drained > 0 {
		LogWarn("captcha", fmt.Sprintf("验证码失效（%s 出口），清空池 %d 枚", tag, drained))
	}
}

// WaitBackground 等待热路径触发的补货任务收尾（关闭路径）。
func (m *CaptchaManager) WaitBackground() { m.bgWG.Wait() }

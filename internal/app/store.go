// 账号与设置的持久化存储（SQLite）。
//
// 数据保存在项目本目录下的 data/accounts.db，采用 WAL 模式，
// 与 grok2api 的本地 (local) 账号后端保持一致。
//
// 运行期账号对象常驻内存（保证轮询游标与状态实时性），
// 每次变更同步落库；进程启动时从 SQLite 读取快照。
//
// 对齐 Python app/store.py。驱动用 modernc.org/sqlite（纯 Go，无 CGO），
// PRAGMA（journal_mode=WAL / synchronous=NORMAL / busy_timeout=5000）与
// 表结构、meta 初始值逐条对齐。
package app

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	_ "modernc.org/sqlite"

	"github.com/zhaoboy9692/zcode2api-go/internal/uuidx"
)

const (
	tblAccounts = "accounts"
	tblMeta     = "meta"
)

// ParseHours 解析领取窗口（北京时间小时，逗号分隔；空/* = 全天 → []）。升序去重，脏值跳过。
func ParseHours(raw string) []int {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "*" {
		return []int{}
	}
	var hours []int
	for _, part := range strings.Split(strings.ReplaceAll(raw, "，", ","), ",") {
		part = strings.TrimSpace(part)
		hour, err := strconv.Atoi(part)
		if err != nil {
			continue // 脏值跳过，不让一个坏配置挂掉领取轮
		}
		if hour >= 0 && hour <= 23 && !containsInt(hours, hour) {
			hours = append(hours, hour)
		}
	}
	sort.Ints(hours)
	return hours
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// hoursWarned 已告警过的坏配置值（解析发生在每次循环唤醒/设置读取，去重避免刷屏）
var (
	hoursWarnedMu sync.Mutex
	hoursWarned   = map[string]bool{}
)

// Store 线程安全的账号 / 设置存储，含轮询游标。
type Store struct {
	mu       sync.Mutex
	db       *sql.DB
	accounts map[string][]*Account
	settings map[string]string
	rotation map[string]int
}

// NewStore 打开数据库、建表、加载快照。
func NewStore() *Store {
	s := &Store{
		accounts: map[string][]*Account{},
		settings: map[string]string{},
		rotation: map[string]int{},
	}
	for _, p := range Providers() {
		s.accounts[p] = []*Account{}
		s.rotation[p] = 0
	}
	s.initDB()
	s.load()
	return s
}

func dsn(dbPath string) string {
	// 对齐 Python _connect() 的三条 PRAGMA（每连接生效 → DSN 逐连接注入）
	q := url.Values{}
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "busy_timeout(5000)")
	return "file:" + filepath.ToSlash(dbPath) + "?" + q.Encode()
}

func (s *Store) initDB() {
	if err := os.MkdirAll(DATA_DIR, 0o755); err != nil {
		panic(fmt.Sprintf("创建数据目录失败: %v", err))
	}
	db, err := sql.Open("sqlite", dsn(DB_PATH))
	if err != nil {
		panic(fmt.Sprintf("打开 SQLite 失败: %v", err))
	}
	s.db = db
	script := fmt.Sprintf(`
                CREATE TABLE IF NOT EXISTS %s (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS %s (
                    id          TEXT PRIMARY KEY,
                    provider    TEXT NOT NULL,
                    name        TEXT,
                    mode        TEXT,
                    status      TEXT,
                    enabled     INTEGER NOT NULL DEFAULT 1,
                    created_at  REAL,
                    data        TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_acc_provider ON %s (provider);
                CREATE INDEX IF NOT EXISTS idx_acc_status   ON %s (status);
                `, tblMeta, tblAccounts, tblAccounts, tblAccounts)
	if _, err := s.db.Exec(script); err != nil {
		panic(fmt.Sprintf("初始化表失败: %v", err))
	}
	mustExec := func(q string, args ...any) {
		if _, err := s.db.Exec(q, args...); err != nil {
			panic(fmt.Sprintf("初始化 meta 失败: %v", err))
		}
	}
	mustExec(fmt.Sprintf("INSERT OR IGNORE INTO %s (key, value) VALUES ('admin_key', ?)", tblMeta), DEFAULT_ADMIN_KEY)
	mustExec(fmt.Sprintf("INSERT OR IGNORE INTO %s (key, value) VALUES ('gateway_key', '')", tblMeta))
	mustExec(fmt.Sprintf("INSERT OR IGNORE INTO %s (key, value) VALUES ('quota_refresh_interval', ?)", tblMeta), strconv.Itoa(QUOTA_REFRESH_INTERVAL))
	mustExec(fmt.Sprintf("INSERT OR IGNORE INTO %s (key, value) VALUES ('account_concurrency', ?)", tblMeta), strconv.Itoa(ACCOUNT_CONCURRENCY))
	mustExec(fmt.Sprintf("INSERT OR IGNORE INTO %s (key, value) VALUES ('claim_round_interval', ?)", tblMeta), strconv.Itoa(CLAIM_ROUND_INTERVAL))
}

func (s *Store) load() {
	rows, err := s.db.Query(fmt.Sprintf("SELECT key, value FROM %s", tblMeta))
	if err != nil {
		panic(fmt.Sprintf("读取 meta 失败: %v", err))
	}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err == nil {
			s.settings[k] = v
		}
	}
	rows.Close()
	setDefault := func(k, v string) {
		if _, ok := s.settings[k]; !ok {
			s.settings[k] = v
		}
	}
	setDefault("admin_key", DEFAULT_ADMIN_KEY)
	setDefault("gateway_key", "")
	setDefault("quota_refresh_interval", strconv.Itoa(QUOTA_REFRESH_INTERVAL))
	setDefault("account_concurrency", strconv.Itoa(ACCOUNT_CONCURRENCY))
	setDefault("claim_round_interval", strconv.Itoa(CLAIM_ROUND_INTERVAL))

	s.accounts = map[string][]*Account{}
	for _, p := range Providers() {
		s.accounts[p] = []*Account{}
	}
	rows2, err := s.db.Query(fmt.Sprintf("SELECT data FROM %s ORDER BY created_at ASC", tblAccounts))
	if err != nil {
		panic(fmt.Sprintf("读取账号失败: %v", err))
	}
	defer rows2.Close()
	for rows2.Next() {
		var data string
		if err := rows2.Scan(&data); err != nil {
			continue
		}
		v, err := JSONDecode(data)
		if err != nil {
			continue
		}
		dict, ok := v.(map[string]any)
		if !ok {
			continue
		}
		account := AccountFromDict(dict)
		if list, ok := s.accounts[account.Provider]; ok {
			s.accounts[account.Provider] = append(list, account)
		}
	}
}

func (s *Store) persistAccount(a *Account) {
	data, err := JSONMarshalCompact(a.ToDict())
	if err != nil {
		return
	}
	_, _ = s.db.Exec(
		fmt.Sprintf(`INSERT OR REPLACE INTO %s
                    (id, provider, name, mode, status, enabled, created_at, data)
                    VALUES (?,?,?,?,?,?,?,?)`, tblAccounts),
		a.ID, a.Provider, a.Name, a.Mode, a.Status, boolToInt(a.Enabled), a.CreatedAt, string(data),
	)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (s *Store) deleteAccount(accountID string) {
	_, _ = s.db.Exec(fmt.Sprintf("DELETE FROM %s WHERE id = ?", tblAccounts), accountID)
}

func (s *Store) setMeta(key, value string) {
	_, _ = s.db.Exec(
		fmt.Sprintf("INSERT OR REPLACE INTO %s (key, value) VALUES (?, ?)", tblMeta), key, value)
}

// Save 全量落库（兜底接口）。
func (s *Store) Save() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, accounts := range s.accounts {
		for _, a := range accounts {
			s.persistAccount(a)
		}
	}
}

// ── 设置 ─────────────────────────────────────────────────────────────────────

// GetSetting 对齐 get_setting(key, default=None)。
func (s *Store) GetSetting(key string, def any) any {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v, ok := s.settings[key]; ok {
		return v
	}
	return def
}

// SetSetting 对齐 set_setting：内存 + meta 表。
func (s *Store) SetSetting(key string, value any) {
	v := fmt.Sprintf("%v", value)
	s.mu.Lock()
	s.settings[key] = v
	s.mu.Unlock()
	s.setMeta(key, v)
}

func (s *Store) AdminKey() string {
	v := s.GetSetting("admin_key", DEFAULT_ADMIN_KEY)
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func (s *Store) GatewayKey() string {
	v := s.GetSetting("gateway_key", "")
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

func (s *Store) QuotaRefreshInterval() int {
	v, ok := AsInt(s.GetSetting("quota_refresh_interval", QUOTA_REFRESH_INTERVAL))
	if !ok {
		return QUOTA_REFRESH_INTERVAL
	}
	if v < 0 {
		v = 0
	}
	return v
}

// AccountConcurrency 单账号并发上限（0 = 不限）。运行时可改（meta 表），改后即生效。
func (s *Store) AccountConcurrency() int {
	v, ok := AsInt(s.GetSetting("account_concurrency", ACCOUNT_CONCURRENCY))
	if !ok {
		return ACCOUNT_CONCURRENCY
	}
	if v < 0 {
		v = 0
	}
	return v
}

// ClaimRoundInterval 套餐自动领取轮间隔（0 = 关闭）。运行时可改（meta 表），改后即生效。
func (s *Store) ClaimRoundInterval() int {
	v, ok := AsInt(s.GetSetting("claim_round_interval", CLAIM_ROUND_INTERVAL))
	if !ok {
		return CLAIM_ROUND_INTERVAL
	}
	if v < 0 {
		v = 0
	}
	return v
}

// ClaimRoundHours 自动领取窗口：北京时间小时升序列表；空 = 全天（不限时）。运行时可改。
//
// 上游套餐按天投放（用户侧实证：每天 19:00 放量），窗口外轮询只会空转
// preview。窗口锚定**北京时钟**而非 host 时区（host 换成 UTC 也不漂）；
// 中国无夏令时，固定 +8 即精确。
func (s *Store) ClaimRoundHours() []int {
	raw := strings.TrimSpace(fmt.Sprintf("%v", s.GetSetting("claim_round_hours", CLAIM_ROUND_HOURS)))
	if raw == "<nil>" {
		raw = ""
	}
	hours := ParseHours(raw)
	if len(hours) == 0 && raw != "" && raw != "*" {
		// 配置写了但一个有效小时都没有（env 笔误 / 手改 DB——管理端 PUT 有校验
		// 不会产生这种值）：**不允许坏配置静默升级成「全天轮询」**，回落默认并留痕。
		fallback := ParseHours(CLAIM_ROUND_HOURS)
		hoursWarnedMu.Lock()
		_, warned := hoursWarned[raw]
		if !warned {
			hoursWarned[raw] = true
		}
		hoursWarnedMu.Unlock()
		if !warned {
			fb := "全天"
			if len(fallback) > 0 {
				fb = fmt.Sprintf("%v", fallback)
			}
			LogWarn("store", fmt.Sprintf("claim_round_hours=%q 无有效小时，按默认处理 → %s", raw, fb))
		}
		return fallback
	}
	return hours
}

// ── 账号读取 ─────────────────────────────────────────────────────────────────

// ListAccounts 对齐 list_accounts(provider=None)：返回切片浅拷贝（对象引用共享）。
func (s *Store) ListAccounts(provider string) []*Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	if provider != "" {
		list, ok := s.accounts[provider]
		if !ok {
			return []*Account{}
		}
		out := make([]*Account, len(list))
		copy(out, list)
		return out
	}
	var out []*Account
	for _, p := range Providers() {
		out = append(out, s.accounts[p]...)
	}
	return out
}

// Find 对齐 find(provider, id_or_name)。
func (s *Store) Find(provider, idOrName string) *Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.findLocked(provider, idOrName)
}

// FindAny 对齐 find_any(id_or_name)。
func (s *Store) FindAny(idOrName string) *Account {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range Providers() {
		for _, a := range s.accounts[p] {
			if a.ID == idOrName {
				return a
			}
		}
	}
	return nil
}

func (s *Store) findLocked(provider, idOrName string) *Account {
	for _, a := range s.accounts[provider] {
		if a.ID == idOrName || a.Name == idOrName {
			return a
		}
	}
	return nil
}

// ── 账号增删改 ───────────────────────────────────────────────────────────────

// AddAccount 对齐 add_account：重复 token 跳过；入池即分配独立设备指纹 + 安装身份。
func (s *Store) AddAccount(provider, name, secret string) (*Account, error) {
	if !IsProvider(provider) {
		return nil, fmt.Errorf("不支持的 provider: %s", provider)
	}
	account := AccountCreate(provider, name, secret)
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range s.accounts[provider] {
		if a.Secret() != "" && a.Secret() == account.Secret() {
			return a, nil // 跳过重复 token
		}
	}
	assignFingerprint(account)                        // 入池即分配独立设备指纹
	account.InstallID = uuidx.New4()                  // 安装身份：稳定安装令牌
	s.accounts[provider] = append(s.accounts[provider], account)
	s.persistAccount(account)
	return account, nil
}

// assignFingerprint 对齐 DefaultStore._assign_fingerprint：给账号分配客户端指纹并固化为 dict。
func assignFingerprint(a *Account) {
	profile := ProfileFor(a)
	a.Fingerprint = map[string]any{
		"platform":   profile.Platform,
		"arch":       profile.Arch,
		"os_version": profile.OSVersion,
		"language":   profile.Language,
		"timezone":   profile.Timezone,
		"screen":     profile.Screen,
		"device_mid": profile.DeviceMid,
	}
}

// RemoveAccount 对齐 remove_account(provider, id_or_name)。
func (s *Store) RemoveAccount(provider, idOrName string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := s.accounts[provider]
	var target *Account
	for _, a := range items {
		if a.ID == idOrName || a.Name == idOrName {
			target = a
			break
		}
	}
	if target == nil {
		return false
	}
	filtered := items[:0]
	for _, a := range items {
		if a.ID != target.ID {
			filtered = append(filtered, a)
		}
	}
	s.accounts[provider] = filtered
	s.deleteAccount(target.ID)
	return true
}

// UpdateAccount 持久化某个账号的当前状态。
//
// 账号已从内存池删除时拒绝写回，避免后台任务 INSERT OR REPLACE 把已删行救活。
func (s *Store) UpdateAccount(a *Account) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.findLocked(a.Provider, a.ID) == nil {
		return false
	}
	s.persistAccount(a)
	return true
}

// SetEnabled 对齐 set_enabled：人工启用 = 确认恢复（禁用洗回 active / 跳过冷却等待）。
func (s *Store) SetEnabled(provider, idOrName string, enabled bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	account := s.findLocked(provider, idOrName)
	if account == nil {
		return false
	}
	account.Enabled = enabled
	if !enabled {
		account.Status = StatusDisabled
	} else if account.Status == StatusDisabled || account.Status == StatusCooling {
		// 人工启用 = 确认恢复：禁用洗回 active；冷却中启用视为跳过等待
		//（风控退避本就是自动恢复语义，人工提前放行同样成立）
		account.Status = StatusActive
		account.CoolingUntil = nil
	}
	s.persistAccount(account)
	return true
}

// ── 轮询选择 ─────────────────────────────────────────────────────────────────

// Select 按 round-robin 选择下一个可用账号。用完 / 失效的自动跳过。
func (s *Store) Select(provider string, skipIDs map[string]bool) *Account {
	if skipIDs == nil {
		skipIDs = map[string]bool{}
	}
	now := NowFloat()
	s.mu.Lock()
	defer s.mu.Unlock()
	var pool []*Account
	for _, a := range s.accounts[provider] {
		if a.IsSelectable(now) && !skipIDs[a.ID] {
			pool = append(pool, a)
		}
	}
	if len(pool) == 0 {
		return nil
	}
	idx := s.rotation[provider] % len(pool)
	account := pool[idx]
	s.rotation[provider] = (idx + 1) % len(pool)
	return account
}

// ── 导入 / 导出 ─────────────────────────────────────────────────────────────

// Export 对齐 export()。
func (s *Store) Export() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	providers := map[string]any{}
	for _, p := range Providers() {
		items := []any{}
		for _, a := range s.accounts[p] {
			items = append(items, map[string]any{
				"name":   a.Name,
				"mode":   a.Mode,
				"secret": a.Secret(),
			})
		}
		providers[p] = items
	}
	return map[string]any{
		"version":     1,
		"exported_at": NowFloat(),
		"providers":   providers,
	}
}

// ImportAccounts 对齐 import_accounts(payload)。
func (s *Store) ImportAccounts(payload map[string]any) int {
	providers, _ := payload["providers"].(map[string]any)
	count := 0
	for provider, rawItems := range providers {
		if !IsProvider(provider) {
			continue
		}
		items, ok := rawItems.([]any)
		if !ok {
			continue
		}
		for _, rawItem := range items {
			it, ok := rawItem.(map[string]any)
			if !ok {
				continue
			}
			secret := ""
			for _, k := range []string{"secret", "token", "jwtToken", "apiKey"} {
				if v, ok := it[k].(string); ok && v != "" {
					secret = v
					break
				}
			}
			if secret == "" {
				continue
			}
			name := DictGetStr(it, "name", provider)
			if _, err := s.AddAccount(provider, name, secret); err == nil {
				count++
			}
		}
	}
	return count
}

// DefaultStore 全局单例（对齐 Python `store = Store()`）。由 InitStore 显式初始化
//（Go 包级变量初始化顺序不保证 settings.init 先行，显式化避免隐式时序坑；
// 命名对齐 http.DefaultXxx 惯例——类型 Store 与单例同名会破坏方法表达式调用）。
var DefaultStore *Store

// InitStore 初始化全局存储（幂等）。main 与 Server 启动路径必须先调用。
func InitStore() {
	if DefaultStore == nil {
		DefaultStore = NewStore()
	}
}

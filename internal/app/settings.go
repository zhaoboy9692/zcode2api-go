// 运行期配置：环境变量 + 默认值。
//
// 所有可调参数集中在此。账号与凭证不在此处，而是持久化到 data/ 目录（见 store.go）。
//
// 对齐 Python app/settings.py：
//   - load_dotenv() → init() 内加载 .env（不覆盖已有环境变量）；
//   - 模块级常量 → 包级变量（env 覆盖逻辑一致）；
//   - USER_AGENT 与 constants 联动（SetActiveVersion 无 env 覆盖时回写），
//     以原子值存放，读走 UserAgent()。
package app

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
)

// ── .env 加载（对齐 python-dotenv load_dotenv 的子集语义）────────────────────
// 只补缺：已存在的环境变量不覆盖；支持 KEY=VALUE、# 注释、成对引号剥离。
func loadDotenv() {
	candidates := []string{}
	if root, err := projectRoot(); err == nil {
		candidates = append(candidates, filepath.Join(root, ".env"))
	}
	candidates = append(candidates, ".env")
	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			line = strings.TrimPrefix(line, "export ")
			eq := strings.Index(line, "=")
			if eq <= 0 {
				continue
			}
			key := strings.TrimSpace(line[:eq])
			val := strings.TrimSpace(line[eq+1:])
			if len(val) >= 2 && (val[0] == '"' && val[len(val)-1] == '"' || val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
			if _, exists := os.LookupEnv(key); !exists {
				_ = os.Setenv(key, val)
			}
		}
		// Python load_dotenv 默认只命中第一个找到的 .env
		break
	}
}

// projectRoot 对齐 Python ROOT_DIR = Path(__file__).parents[1]（仓库根）。
// Go 编译后无源码路径：取可执行文件所在目录（部署形态 = 与 frontend/、data/
// 同级的根目录），不可得时退当前工作目录。
func projectRoot() (string, error) {
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe), nil
	}
	return os.Getwd()
}

func resolvePath(envName, def string) string {
	raw := strings.TrimSpace(envOr(envName, def))
	if raw == "" {
		raw = def
	}
	if filepath.IsAbs(raw) {
		return raw
	}
	root, err := projectRoot()
	if err != nil {
		return raw
	}
	return filepath.Join(root, filepath.FromSlash(raw))
}

func envOr(name, def string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return def
}

func intEnv(name string, def int) int {
	raw, ok := os.LookupEnv(name)
	if !ok {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return def
	}
	return n
}

func boolEnv(name string, def bool) bool {
	raw := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	if raw == "" {
		return def
	}
	switch raw {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

// ── 目录 ─────────────────────────────────────────────────────────────────────
var (
	DATA_DIR string // 账号与设置持久化目录（ZCODE_DATA_DIR，默认 data/）
	DB_PATH  string // SQLite 数据库（data/accounts.db，与 grok2api 的 local 后端一致）
	// 前端目录（前后端分离）：默认仓库根 frontend/，可用 ZCODE_FRONTEND_DIR 指向
	// 独立部署目录（线上 /data/zcode-hub/frontend）；包内 statics 仅作兜底
	FRONTEND_DIR string
)

// ── 服务 ─────────────────────────────────────────────────────────────────────
var (
	PORT int    // 默认 3000
	HOST string // 默认 0.0.0.0
)

// ── 鉴权 ─────────────────────────────────────────────────────────────────────
// 后台管理密码默认值，首次启动写入 data/accounts.db，之后以数据库（meta 表）为准。
var DEFAULT_ADMIN_KEY string

// ── 验证码 ───────────────────────────────────────────────────────────────────
// 预解 token 池。真浏览器求解重（单枚 10–40s、Chromium 数百 MB），池收敛为 1/2
//（TTL 95s → 稳态约 95s 解一枚，Chromium 占空比 ~10–40%）；回滚 legacy 可调大。
var (
	CAPTCHA_POOL_MIN          int    // 目标库存（低于则补）
	CAPTCHA_POOL_MAX          int    // 池上限
	CAPTCHA_TOKEN_TTL         int    // 单枚 token 最大可用时长（ms；上游实际 ~2min）
	CAPTCHA_CONFIG_CACHE_TTL  int    // ms
	NODE_PATH                 string // 验证码求解 Node 可执行
	CAPTCHA_SOLVER_DIR        string
	CAPTCHA_SOLVER_MODE       string // "pw"（默认）或 "legacy"
	CAPTCHA_SOLVER_JS         string
	CHROMIUM_PATH             string // solver_pw 用；env 可覆盖，缺省按常见路径探测
	CAPTCHA_SOLVE_RETRIES     int
	CAPTCHA_SOLVE_TIMEOUT     int // 每次求解超时（秒）
	CAPTCHA_POOL_EGRESS       string
)

// ── 用量监控 ─────────────────────────────────────────────────────────────────
var (
	// 后台自动刷新账号额度的间隔（秒）。0 表示关闭后台轮询，仅按需刷新。
	// 默认 1800（2.6.5 整改）：zcode-switch 参照系下额度查询是用户开界面才触发
	//（人节奏，日均几十次）；60s 轮询 ≈ 每号每天 4300+ billing 请求，是风控
	//「unusual activity」的主信号源（vault「billing 连续查询易触发拦截」落地）。
	QUOTA_REFRESH_INTERVAL int
	// 成功对话后计费刷新的最小间隔（秒）：billing/* 连续查询易触发上游拦截，
	// 每条消息都刷是流量放大器，与 monitor 轮询共享 last_checked_at 去抖。
	BILLING_REFRESH_MIN_INTERVAL int
	// ── 上游错误重试 / 冷却（参数可设定）─────────────────────────────────────────
	// 429 频控：账号不冷却，原地等待后重试，耗尽后换下一个账号（账号保持可用）
	RETRY_429_TIMES     int // 429 重试次数
	RETRY_429_WAIT      int // 429 重试等待秒数（上游 Retry-After 优先）
	RETRY_429_WAIT_MAX  int // Retry-After 采信上限（防吊死客户端）
	// 429/code 3009「model concurrency limit exceeded」是并发争用而非频控：上游没有
	// Retry-After，等 60s 纯属浪费（槽位早空了）。这类回短退避，配 jitter 打散重试。
	RETRY_429_CONCURRENCY_WAIT int
	// 5xx 等一般错误：重试，耗尽后账号冷却 COOLING_SECONDS 并换下一个账号
	RETRY_5XX_TIMES int // 5xx 重试次数
	RETRY_5XX_WAIT  int // 5xx 重试等待秒数
	// 限流（cooling）冷却时长（秒）——仅 5xx 重试耗尽 / 连接失败使用
	COOLING_SECONDS int
	// 风控（3012/405「unusual activity」）指数退避冷却：实测为频道级瞬时频控
	//（同号同刻 billing 正常、数小时自愈），冷却自动恢复；累计 RISK_BAN_STRIKES
	// 次才升级为禁用（人工恢复）。冷却期零上游流量（is_cooling 全通道门禁）。
	RISK_COOLDOWN_BASE       int  // 首次冷却秒数
	RISK_COOLDOWN_MAX        int  // 冷却上限（24h）
	RISK_BAN_STRIKES         int  // 窗口内累计命中达到即禁用
	RISK_STRIKE_DECAY_SECONDS int // 距上次风控命中超过该窗口则 strikes 重新起算
	RISK_AUTO_ROTATE         bool // 风控升级禁用时自动换发设备指纹并后台补跑安装序
	// 套餐自动领取轮间隔（秒）：周期对全部可打 billing 的 JWT 账号轮一遍
	// preview + 领取（有可领套餐才补激活上报，见 claim.auto_claim_all_plans）。
	// 默认 3600（2.6.5 整改）。0 = 关闭轮次，仅入池/手动触发。
	CLAIM_ROUND_INTERVAL int
	// 领取窗口（北京时间小时，逗号分隔；空/"*" = 全天）。上游套餐按天投放，
	// 用户侧实证每天 19:00 放量——窗口外轮询只会空转 preview。
	CLAIM_ROUND_HOURS string
)

// ── 上游端点 ─────────────────────────────────────────────────────────────────
var (
	// 上游端点：默认值统一收口在 constants，环境变量仅作覆盖
	UPSTREAM map[string]string
	// ZCode 计费 / 额度查询端点
	ZCODE_BILLING_BASE string
	// 官方更新清单端点（测试时指向 Mock 上游）
	ZCODE_MANIFEST_URL string
	// 官方版本自动探测间隔（秒，默认 12 小时）
	VERSION_CHECK_INTERVAL int
	// 是否自动将客户端伪装对齐至官方最新版本
	AUTO_SYNC_CLIENT_VERSION bool
	// 营销触达 / 活动投放查询端点（测试时指向 Mock 上游）
	ZCODE_MARKETING_TOUCH_URL string
	// 激活事件上报（测试时指向 Mock 上游）
	ZCODE_EVENT_REPORT_URL string
	// OAuth 与兑换链 origin（测试时指向 Mock 上游）
	OAUTH_API_BASE     string
	ZAI_EXCHANGE_ORIGIN string

	APP_VERSION = "2.7.16"
)

// userAgentVal 对齐 Python settings.USER_AGENT 模块变量（可被 SetActiveVersion 回写）。
// 注意与 constants.UserAgent() 区分：Python 里两个模块各有一个 USER_AGENT，
// settings 层可被 UPSTREAM_USER_AGENT env 覆盖、又被 SetActiveVersion 回写。
var userAgentVal atomic.Value // string

// SettingsUserAgent 返回 settings 层 USER_AGENT（上游请求 UA）。
func SettingsUserAgent() string {
	if v, ok := userAgentVal.Load().(string); ok && v != "" {
		return v
	}
	return UserAgent()
}

// settingsSyncUserAgent 由 SetActiveVersion 调用（无 UPSTREAM_USER_AGENT 覆盖时），
// 对齐 Python `settings.USER_AGENT = constants.USER_AGENT`。
func settingsSyncUserAgent(v string) { userAgentVal.Store(v) }

func init() {
	loadDotenv()

	// ── 目录 ─────────────────────────────────────────────────────────────────
	DATA_DIR = resolvePath("ZCODE_DATA_DIR", "data")
	DB_PATH = filepath.Join(DATA_DIR, "accounts.db")
	frontendDefault := "frontend"
	// Python: (ROOT_DIR / "frontend").is_dir() ? "frontend" : <app 包>/statics
	if root, err := projectRoot(); err == nil {
		if st, err := os.Stat(filepath.Join(root, "frontend")); err == nil && st.IsDir() {
			frontendDefault = "frontend"
		} else {
			frontendDefault = filepath.Join("internal", "app", "statics")
		}
	}
	FRONTEND_DIR = resolvePath("ZCODE_FRONTEND_DIR", frontendDefault)

	// ── 服务 ─────────────────────────────────────────────────────────────────
	PORT = intEnv("ZCODE_PORT", 3000)
	HOST = envOr("ZCODE_HOST", "0.0.0.0")

	// ── 鉴权 ─────────────────────────────────────────────────────────────────
	DEFAULT_ADMIN_KEY = envOr("ZCODE_ADMIN_KEY", "zcode")

	// ── 验证码 ───────────────────────────────────────────────────────────────
	CAPTCHA_POOL_MIN = intEnv("CAPTCHA_POOL_MIN", 1)
	CAPTCHA_POOL_MAX = intEnv("CAPTCHA_POOL_MAX", 2)
	CAPTCHA_TOKEN_TTL = intEnv("CAPTCHA_TOKEN_TTL", 95_000)
	CAPTCHA_CONFIG_CACHE_TTL = intEnv("CAPTCHA_CONFIG_CACHE_TTL", 600_000)

	NODE_PATH = envOr("ZCODE_NODE_PATH", "node")
	// snap Chromium 沙箱只读 $HOME:部署在 /opt 等路径时,可用 env 把求解器目录
	// 指到 $HOME 下(含 page.html,snap 才能加载)
	CAPTCHA_SOLVER_DIR = envOr("ZCODE_CAPTCHA_SOLVER_DIR", filepath.Join(mustRoot(), "captcha_node"))
	CAPTCHA_SOLVER_MODE = strings.ToLower(strings.TrimSpace(envOr("ZCODE_CAPTCHA_SOLVER", "pw")))
	if CAPTCHA_SOLVER_MODE == "" {
		CAPTCHA_SOLVER_MODE = "pw"
	}
	if CAPTCHA_SOLVER_MODE == "legacy" {
		CAPTCHA_SOLVER_JS = filepath.Join(CAPTCHA_SOLVER_DIR, "solver.js")
	} else {
		CAPTCHA_SOLVER_JS = filepath.Join(CAPTCHA_SOLVER_DIR, "solver_pw.js")
	}
	CHROMIUM_PATH = envOr("ZCODE_CHROMIUM_PATH", "/usr/local/bin/chromium")
	CAPTCHA_SOLVE_RETRIES = intEnv("ZCODE_CAPTCHA_RETRIES", 4)
	CAPTCHA_SOLVE_TIMEOUT = intEnv("ZCODE_CAPTCHA_TIMEOUT", 240)
	CAPTCHA_POOL_EGRESS = strings.ToLower(strings.TrimSpace(os.Getenv("ZCODE_CAPTCHA_POOL_EGRESS")))

	// ── 用量监控 ─────────────────────────────────────────────────────────────
	QUOTA_REFRESH_INTERVAL = intEnv("ZCODE_QUOTA_REFRESH_INTERVAL", 1800)
	BILLING_REFRESH_MIN_INTERVAL = intEnv("ZCODE_BILLING_REFRESH_MIN_INTERVAL", 60)
	RETRY_429_TIMES = intEnv("ZCODE_RETRY_429_TIMES", 5)
	RETRY_429_WAIT = intEnv("ZCODE_RETRY_429_WAIT", 60)
	RETRY_429_WAIT_MAX = intEnv("ZCODE_RETRY_429_WAIT_MAX", 120)
	RETRY_429_CONCURRENCY_WAIT = intEnv("ZCODE_RETRY_429_CONCURRENCY_WAIT", 3)
	RETRY_5XX_TIMES = intEnv("ZCODE_RETRY_5XX_TIMES", 3)
	RETRY_5XX_WAIT = intEnv("ZCODE_RETRY_5XX_WAIT", 5)
	COOLING_SECONDS = intEnv("ZCODE_COOLING_SECONDS", 300)
	RISK_COOLDOWN_BASE = intEnv("ZCODE_RISK_COOLDOWN_BASE", 900)
	RISK_COOLDOWN_MAX = intEnv("ZCODE_RISK_COOLDOWN_MAX", 86400)
	RISK_BAN_STRIKES = intEnv("ZCODE_RISK_BAN_STRIKES", 4)
	RISK_STRIKE_DECAY_SECONDS = intEnv("ZCODE_RISK_STRIKE_DECAY_SECONDS", 7*86400)
	RISK_AUTO_ROTATE = boolEnv("ZCODE_RISK_AUTO_ROTATE", true)
	CLAIM_ROUND_INTERVAL = intEnv("ZCODE_CLAIM_ROUND_INTERVAL", 3600)
	CLAIM_ROUND_HOURS = os.Getenv("ZCODE_CLAIM_ROUND_HOURS")
	if CLAIM_ROUND_HOURS == "" {
		CLAIM_ROUND_HOURS = "19"
	}

	// ── 上游端点 ─────────────────────────────────────────────────────────────
	UPSTREAM = map[string]string{
		"zai":         envOr("ZAI_UPSTREAM_URL", MESSAGES_URLS["zai"]),
		"zai_fallback": envOr("ZAI_FALLBACK_URL", MESSAGES_URLS["zai_fallback"]),
		"bigmodel":    envOr("BIGMODEL_UPSTREAM_URL", MESSAGES_URLS["bigmodel"]),
	}
	ZCODE_BILLING_BASE = BILLING_BASE
	ZCODE_MANIFEST_URL = envOr("ZCODE_MANIFEST_URL", ELECTRON_MANIFEST_URL)
	VERSION_CHECK_INTERVAL = intEnv("ZCODE_VERSION_CHECK_INTERVAL", 43200)
	AUTO_SYNC_CLIENT_VERSION = boolEnv("ZCODE_AUTO_SYNC_CLIENT_VERSION", true)
	ZCODE_MARKETING_TOUCH_URL = envOr("ZCODE_MARKETING_TOUCH_URL", MARKETING_TOUCH_URL)
	ZCODE_EVENT_REPORT_URL = envOr("ZCODE_EVENT_REPORT_URL", EVENT_REPORT_URL)
	OAUTH_API_BASE = envOr("ZCODE_OAUTH_API_BASE", ZCODE_ORIGIN+"/api/v1")
	ZAI_EXCHANGE_ORIGIN = envOr("ZCODE_EXCHANGE_ORIGIN", ZAI_API_ORIGIN)

	ua := os.Getenv("UPSTREAM_USER_AGENT")
	if ua == "" {
		ua = UserAgent() // constants 层初始值 "ZCode/<DEFAULT_CLIENT_APP_VERSION>"
	}
	userAgentVal.Store(ua)
}

func mustRoot() string {
	root, err := projectRoot()
	if err != nil {
		return "."
	}
	return root
}

var frontendVersionFile = func() string { return filepath.Join(FRONTEND_DIR, "version") }

// FrontendVersion 前端版本号（frontend/version 文件，每次读取 → 前端独立发版即生效）。
//
// 文件缺失/为空时回退 APP_VERSION，保证本地开发与旧部署不破。
func FrontendVersion() string {
	data, err := os.ReadFile(frontendVersionFile())
	if err != nil {
		return APP_VERSION
	}
	v := strings.TrimSpace(string(data))
	if v == "" {
		return APP_VERSION
	}
	return v
}

// DBPathString 数据库路径（CLI status 输出用，对齐 str(settings.DB_PATH)）。
func DBPathString() string { return DB_PATH }

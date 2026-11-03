// FastAPI 应用工厂 + 生命周期（对齐 Python app/main.py）。
//
// lifespan 语义映射：
//   - create_app() → NewServer()（路由挂载 / 静态文件）
//   - lifespan startup → Server.Start()（指纹回填 / 安装身份补配 /
//     monitor+captcha+claim+version_tracker 后台轮 / 启动安装序 / banner）
//   - lifespan shutdown → Server.Shutdown()（逆序停止各后台任务）
package routes

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/zhaoboy9692/zcode2api-go/internal/app"
)

// Server zcode-hub 应用实例（对齐 FastAPI app 对象）。
type Server struct {
	mux  *http.ServeMux
	http *http.Server
	wg   sync.WaitGroup // 后台任务收尾（login followup / auto claim 等）
}

// NewServer 对齐 create_app()：路由挂载 + /static 静态文件。
func NewServer() *Server {
	s := &Server{mux: http.NewServeMux()}

	// app.mount("/static", StaticFiles(directory=FRONTEND_DIR))
	fs := http.FileServer(http.Dir(app.FRONTEND_DIR))
	s.mux.Handle("GET /static/", http.StripPrefix("/static/", noDirFS{http.FileServer(http.Dir(app.FRONTEND_DIR))}))
	_ = fs // FileServer 已由 noDirFS 包装，占位引用防误删

	// pages.router（include_in_schema=False）
	s.mux.HandleFunc("GET /{$}", s.handleRoot)
	s.mux.HandleFunc("GET /admin", s.handleAdminRoot)
	s.mux.HandleFunc("GET /admin/login", s.handleAdminLogin)
	s.mux.HandleFunc("GET /admin/accounts", s.handleAdminAccounts)
	s.mux.HandleFunc("GET /admin/monitoring", s.handleAdminMonitoring)
	s.mux.HandleFunc("GET /admin/settings", s.handleAdminSettings)
	s.mux.HandleFunc("GET /meta", s.handleMeta)

	// admin_api.router（prefix=/admin/api, dependencies=[verify_admin_key]）
	adminAuth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if err := app.VerifyAdminKey(r); err != nil {
				jsonOut(w, err.Code, map[string]any{"detail": err.Message})
				return
			}
			h(w, r)
		}
	}
	s.mux.HandleFunc("GET /admin/api/verify", adminAuth(s.handleVerify))
	s.mux.HandleFunc("GET /admin/api/accounts", adminAuth(s.handleListAccounts))
	s.mux.HandleFunc("POST /admin/api/accounts", adminAuth(s.handleAddAccounts))
	s.mux.HandleFunc("DELETE /admin/api/accounts", adminAuth(s.handleDeleteAccounts))
	s.mux.HandleFunc("PUT /admin/api/accounts/{account_id}", adminAuth(s.handleEditAccount))
	s.mux.HandleFunc("POST /admin/api/accounts/{account_id}/enabled", adminAuth(s.handleSetEnabled))
	s.mux.HandleFunc("POST /admin/api/accounts/{account_id}/fingerprint/rotate", adminAuth(s.handleRotateFingerprint))
	s.mux.HandleFunc("POST /admin/api/accounts/refresh", adminAuth(s.handleRefresh))
	s.mux.HandleFunc("POST /admin/api/accounts/{account_id}/refresh", adminAuth(s.handleRefreshOne))
	s.mux.HandleFunc("GET /admin/api/accounts/{account_id}/coding_limits", adminAuth(s.handleCodingLimits))
	s.mux.HandleFunc("POST /admin/api/login/start", adminAuth(s.handleLoginStart))
	s.mux.HandleFunc("GET /admin/api/login/poll/{flow_id}", adminAuth(s.handleLoginPoll))
	s.mux.HandleFunc("GET /admin/api/claim/preview", adminAuth(s.handleClaimPreview))
	s.mux.HandleFunc("POST /admin/api/claim", adminAuth(s.handleClaim))
	s.mux.HandleFunc("GET /admin/api/claim/captcha-config", adminAuth(s.handleClaimCaptchaConfig))
	s.mux.HandleFunc("POST /admin/api/claim/manual", adminAuth(s.handleClaimManual))
	s.mux.HandleFunc("GET /admin/api/settings", adminAuth(s.handleGetSettings))
	s.mux.HandleFunc("PUT /admin/api/settings", adminAuth(s.handleUpdateSettings))
	s.mux.HandleFunc("POST /admin/api/version/zcode/check", adminAuth(s.handleCheckZcodeVersionNow))
	s.mux.HandleFunc("GET /admin/api/export", adminAuth(s.handleExport))
	s.mux.HandleFunc("POST /admin/api/import", adminAuth(s.handleImport))
	s.mux.HandleFunc("GET /admin/api/monitoring", adminAuth(s.handleMonitoring))
	s.mux.HandleFunc("POST /admin/api/monitoring/clear", adminAuth(s.handleMonitoringClear))

	// gateway.router（dependencies=[verify_gateway_key]）
	gwAuth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if err := app.VerifyGatewayKey(r); err != nil {
				jsonOut(w, err.Code, map[string]any{"detail": err.Message})
				return
			}
			h(w, r)
		}
	}
	s.mux.HandleFunc("GET /v1/models", gwAuth(s.handleListModels))
	s.mux.HandleFunc("POST /v1/messages", gwAuth(s.handleMessages))
	s.mux.HandleFunc("POST /v1/messages/count_tokens", gwAuth(s.handleCountTokens))
	s.mux.HandleFunc("POST /v1/chat/completions", gwAuth(s.handleChatCompletions))
	s.mux.HandleFunc("POST /v1/responses", gwAuth(s.handleResponses))

	// FastAPI 未命中路径返回 {"detail":"Not Found"}（对齐 starlette 404 形态）
	s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		jsonOut(w, 404, map[string]any{"detail": "Not Found"})
	})

	return s
}

// noDirFS 禁目录列表的静态文件服务（StaticFiles(directory=...) 的 html=False 语义）。
type noDirFS struct{ h http.Handler }

func (f noDirFS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/") {
		jsonOut(w, 404, map[string]any{"detail": "Not Found"})
		return
	}
	f.h.ServeHTTP(w, r)
}

// ServeHTTP 实现 http.Handler。
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

// displayHost 对齐 _display_host：0.0.0.0 / 空地址在浏览器中不可直接访问，展示为 127.0.0.1。
func displayHost() string {
	host := strings.TrimSpace(app.HOST)
	if host == "" || host == "0.0.0.0" || host == "::" {
		return "127.0.0.1"
	}
	return host
}

// backfillFingerprints 启动时给无指纹或非桌面 SKU（旧版宿主机克隆）的存量账号换发生成档案。
//
// 换机后清 installed_at，由 lifespan 补跑按账号安装序（新 device_mid 需要
// 自己的 app_launch / app_daily_active）。返回被替换的账号列表。
func backfillFingerprints() []*app.Account {
	var replaced []*app.Account
	for _, account := range app.DefaultStore.ListAccounts("") {
		fp := account.Fingerprint
		needs := false
		mid := ""
		if fp == nil {
			needs = true
		} else {
			mid, _ = fp["device_mid"].(string)
			if mid == "" {
				needs = true
			} else {
				// DeviceProfile 结构完整性 → is_generated_sku 判定
				profile := app.DeviceProfile{
					Platform:  app.StrValue(fp["platform"]),
					Arch:      app.StrValue(fp["arch"]),
					OSVersion: app.StrValue(fp["os_version"]),
					Language:  app.StrValue(fp["language"]),
					Timezone:  app.StrValue(fp["timezone"]),
					Screen:    app.StrValue(fp["screen"]),
					DeviceMid: mid,
				}
				needs = !app.IsGeneratedSku(profile)
			}
		}
		if needs {
			account.Fingerprint = nil
			account.InstalledAt = nil
			app.ProfileFor(account)
			app.DefaultStore.UpdateAccount(account)
			replaced = append(replaced, account)
		}
	}
	return replaced
}

// backfillInstallIDs 启动时给无 install_id 的存量账号补配安装身份（纯本地，无网络）并落库。
func backfillInstallIDs() int {
	backfilled := 0
	for _, account := range app.DefaultStore.ListAccounts("") {
		if strings.TrimSpace(account.InstallID) == "" {
			account.InstallID = app.NewUUID4()
			app.DefaultStore.UpdateAccount(account)
			backfilled++
		}
	}
	return backfilled
}

// runInstallSequenceOnStart 启动后台执行一次安装序（官方客户端每次启动都拉 configs + 发
// app_launch，日活去重在上游按 device_mid+日期）。失败只留痕，绝不影响启动。
func runInstallSequenceOnStart(wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() {
			// 后台任务异常无人接收，必须自兜
			_ = recover()
		}()
		app.RunInstallSequence()
	}()
}

// Start 对齐 lifespan startup 段（不含监听本身）。
func (s *Server) Start() {
	replaced := backfillFingerprints()
	if len(replaced) > 0 {
		app.LogOK("fingerprint", fmt.Sprintf("存量账号补配独立设备指纹 ×%d", len(replaced)))
		for _, acc := range replaced {
			app.ScheduleInstall(acc)
		}
	}
	installed := backfillInstallIDs()
	if installed > 0 {
		app.LogOK("install", fmt.Sprintf("存量账号补配安装身份 ×%d", installed))
	}
	app.Monitor.Start()
	app.DefaultCaptchaManager.Start() // 验证码预解池后台补充
	app.ClaimRound.Start()            // 套餐自动领取轮（间隔 0 = 关闭）
	app.DefaultVersionTracker.InitFromStore()
	app.DefaultVersionTracker.Start() // 官方版本自动探测与同步
	runInstallSequenceOnStart(&s.wg)
	base := fmt.Sprintf("http://%s:%d", displayHost(), app.PORT)
	app.LogBanner([]string{
		fmt.Sprintf("%szcode-hub%s %sv%s · Go%s", mag(), reset(), dim(), app.APP_VERSION, reset()),
		fmt.Sprintf("%s后台管理%s  %s%s/admin/login%s", dim(), reset(), cyan(), base, reset()),
		fmt.Sprintf("%s对话端点%s  %s%s/v1/messages%s", dim(), reset(), cyan(), base, reset()),
	})
}

// mag/cyan/dim/reset ANSI 助手（对齐 logs._MAG 等）。
func mag() string    { return "\033[35m" }
func cyan() string   { return "\033[36m" }
func dim() string    { return "\033[90m" }
func reset() string  { return "\033[0m" }
func boldM() string  { return "\033[1m" }

// ListenAndServe 监听并服务（对齐 uvicorn.run 的 server 段）。
func (s *Server) ListenAndServe() error {
	addr := fmt.Sprintf("%s:%d", app.HOST, app.PORT)
	s.http = &http.Server{Addr: addr, Handler: s}
	err := s.http.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// Shutdown 对齐 lifespan shutdown 段（finally）：
//
//	await monitor.stop() / claim_round.stop() / version_tracker.stop() /
//	captcha_manager.close()
//
// ctx 用于 HTTP 优雅关闭（uvicorn 语义）。
func (s *Server) Shutdown(ctx context.Context) {
	if s.http != nil {
		_ = s.http.Shutdown(ctx)
	}
	app.Monitor.Stop()
	app.ClaimRound.Stop()
	app.DefaultVersionTracker.Stop()
	app.DefaultCaptchaManager.Close()
	app.DefaultCaptchaManager.WaitBackground()
	// 等待 login followup / auto claim / install 等短任务收尾（有界）
	done := make(chan struct{})
	go func() { s.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
	}
}

// ShutdownWithDefaultContext Shutdown 的默认上下文入口（CLI serve 收尾用）。
func (s *Server) ShutdownWithDefaultContext() {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	s.Shutdown(ctx)
}

// 保留 os/boldM 引用（启动环境判断扩展）
var _ = os.Getenv
var _ = boldM

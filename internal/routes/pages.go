// 页面路由：登录、账号管理、设置。
//
// 前端文件来自独立部署目录（app.FRONTEND_DIR，前后端分离）——
// 改前端只需 rsync 该目录，无需重启后端。
//
// 对齐 Python app/routes/pages.py。
package routes

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/zhaoboy9692/zcode2api-go/internal/app"
)

const appVersionToken = "{{APP_VERSION}}"

// htmlPage 对齐 _html(name)：读前端页面并替换版本占位（no-store）。
func htmlPage(w http.ResponseWriter, name string) {
	path := filepath.Join(app.FRONTEND_DIR, "admin", name)
	data, err := os.ReadFile(path)
	if err != nil {
		jsonOut(w, 404, map[string]any{"detail": "页面不存在"})
		return
	}
	body := strings.ReplaceAll(string(data), appVersionToken, app.FrontendVersion())
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(body))
}

// handleRoot GET /（include_in_schema=False）
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/admin", http.StatusTemporaryRedirect)
}

// handleAdminRoot GET /admin
func (s *Server) handleAdminRoot(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/admin/login", http.StatusTemporaryRedirect)
}

// handleAdminLogin GET /admin/login
func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	htmlPage(w, "login.html")
}

// handleAdminAccounts GET /admin/accounts
func (s *Server) handleAdminAccounts(w http.ResponseWriter, r *http.Request) {
	htmlPage(w, "accounts.html")
}

// handleAdminMonitoring GET /admin/monitoring
func (s *Server) handleAdminMonitoring(w http.ResponseWriter, r *http.Request) {
	htmlPage(w, "monitoring.html")
}

// handleAdminSettings GET /admin/settings
func (s *Server) handleAdminSettings(w http.ResponseWriter, r *http.Request) {
	htmlPage(w, "settings.html")
}

// handleMeta GET /meta
func (s *Server) handleMeta(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, 200, map[string]any{"version": app.APP_VERSION})
}

// ZCode Hub（zcode2api-go）
//
// 用法:
//
//	zcode2api-go serve [--port 3000]        启动网关 + 后台 UI
//	zcode2api-go login zai [--no-browser]   通过 OAuth 登录 Z.AI 并自动加入账号池
//	zcode2api-go add-account zai <name> <jwt|key>   添加轮询账号
//	zcode2api-go accounts [zai|bigmodel]    查看账号列表
//	zcode2api-go remove-account <provider> <id|name>
//	zcode2api-go quota                      查看各账号实时额度
//	zcode2api-go status                     查看配置概览
//	zcode2api-go set-admin-key <key>        设置后台密码
//	zcode2api-go export [file]              导出账号
//	zcode2api-go import <file>              导入账号
//
// 对齐 Python cli.py：子命令分发与输出文案逐条对齐。
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/zhaoboy9692/zcode2api-go/internal/app"
	"github.com/zhaoboy9692/zcode2api-go/internal/routes"
)

const cliUsage = `ZCode Hub

用法:
  zcode2api-go serve [--port 3000]        启动网关 + 后台 UI
  zcode2api-go login zai [--no-browser]   通过 OAuth 登录 Z.AI 并自动加入账号池
  zcode2api-go add-account zai <name> <jwt|key>   添加轮询账号
  zcode2api-go accounts [zai|bigmodel]    查看账号列表
  zcode2api-go remove-account <provider> <id|name>
  zcode2api-go quota                      查看各账号实时额度
  zcode2api-go status                     查看配置概览
  zcode2api-go set-admin-key <key>        设置后台密码
  zcode2api-go export [file]              导出账号
  zcode2api-go import <file> [--password <pw>]   导入账号（明文 JSON 或 .zsb 加密封包）
`

// C 对齐 CLI 色表
var C = map[string]string{
	"reset": "\033[0m", "green": "\033[32m", "yellow": "\033[33m",
	"blue": "\033[34m", "red": "\033[31m", "cyan": "\033[36m", "bold": "\033[1m",
}

func c(text, color string) string {
	return C[color] + text + C["reset"]
}

func usage() {
	fmt.Print(cliUsage)
}

// ── serve ────────────────────────────────────────────────────────────────────

func cmdServe(args []string) {
	port := app.PORT
	for i, a := range args {
		if a == "--port" && i+1 < len(args) {
			fmt.Sscanf(args[i+1], "%d", &port)
		}
	}
	app.PORT = port

	app.InitStore()
	server := routes.NewServer()
	// 修正 Windows 中文控制台可能出现的乱码（对齐 Python main.py 的 reconfigure）
	// Go 直接以 UTF-8 输出，现代 Windows Terminal 默认支持；此处保留注释语义。
	server.Start()
	app.LogStep("uvicorn", fmt.Sprintf("Uvicorn running on http://%s:%d", app.HOST, app.PORT))
	if err := server.ListenAndServe(); err != nil {
		app.LogErr("serve", fmt.Sprintf("服务退出: %v", err))
		os.Exit(1)
	}
	// 对齐 lifespan finally：监听结束后执行 shutdown 链
	server.ShutdownWithDefaultContext()
}

// ── login ────────────────────────────────────────────────────────────────────

func cmdLogin(args []string) {
	if len(args) == 0 || args[0] != "zai" {
		fmt.Println(c("目前仅支持: zcode2api-go login zai", "red"))
		return
	}
	flow := app.NewZaiAuthFlow("", "")
	flowID, authorizeURL, err := flow.Init()
	if err != nil {
		fmt.Println(c(fmt.Sprintf("❌ 登录初始化失败: %v", err), "red"))
		return
	}

	fmt.Println(c("\n✔ OAuth 初始化成功！请在浏览器中打开下面链接完成授权：", "green"))
	fmt.Println(c(authorizeURL, "blue"))

	noBrowser := false
	for _, a := range args {
		if a == "--no-browser" {
			noBrowser = true
		}
	}
	if !noBrowser {
		openBrowser(authorizeURL)
	}

	fmt.Println("正在等待授权...")
	for i := 0; i < 100; i++ {
		time.Sleep(2 * time.Second)
		data, err := flow.Poll(flowID)
		if err != nil {
			continue
		}
		status := app.DictGetStr(data, "status", "")
		if status == "ready" {
			accessToken := ""
			if zai, ok := data["zai"].(map[string]any); ok {
				accessToken = app.DictGetStr(zai, "access_token", "")
			}
			zcodeJWT := app.DictGetStr(data, "token", "")
			if zcodeJWT != "" {
				acc, _ := app.DefaultStore.AddAccount("zai", "oauth-login", zcodeJWT)
				if acc != nil {
					fmt.Println(c(fmt.Sprintf("\n✔ 已保存 Coding Plan JWT 账号: %s (%s)", acc.Name, acc.ID), "green"))
					cliIngestFollowup(acc)
				}
			}
			if accessToken != "" {
				key, err := flow.ExchangeAPIKey(accessToken)
				if err != nil {
					fmt.Println(c(fmt.Sprintf("⚠️ 兑换 API Key 失败: %v", err), "yellow"))
				} else {
					accKey, _ := app.DefaultStore.AddAccount("zai", "oauth-apikey", key)
					if accKey != nil {
						preview := key
						if len(preview) > 8 {
							preview = preview[:8]
						}
						fmt.Println(c(fmt.Sprintf("✔ 已兑换并保存 API Key: %s...", preview), "green"))
						cliIngestFollowup(accKey)
					}
				}
			}
			return
		}
		if status == "failed" {
			fmt.Println(c("❌ 授权失败或被拒绝。", "red"))
			return
		}
	}
	fmt.Println(c("❌ 登录超时，请重试。", "red"))
}

// openBrowser 对齐 webbrowser.open(authorize_url)（尽力而为）。
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

// cliIngestFollowup CLI 入池与 Web 入池对齐：按账号安装序 + JWT 自动领取。
func cliIngestFollowup(acc *app.Account) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println(c(fmt.Sprintf("⚠️ 安装序异常: %v", r), "yellow"))
		}
	}()
	app.RunInstallSequenceForAccount(acc)
	if acc.Mode == "jwt" && acc.JWTToken != "" {
		cliAutoClaim(acc)
	}
}

// cliAutoClaim 入池自动领取（激活上报 + 全量可领套餐），失败仅提示不阻断。
func cliAutoClaim(acc *app.Account) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println(c(fmt.Sprintf("⚠️ 自动领取异常: %v", r), "yellow"))
		}
	}()
	outcomes := app.AutoClaimAllPlans(acc, nil)
	for _, o := range outcomes {
		om, ok := o.(map[string]any)
		if !ok {
			continue
		}
		if okFlag, _ := om["ok"].(bool); okFlag {
			name := app.DictGetStr(om, "plan_name", "")
			if name == "" {
				name = app.DictGetStr(om, "plan_id", "")
			}
			fmt.Println(c(fmt.Sprintf("🎁 自动领取成功: %s", name), "green"))
		} else {
			fmt.Println(c(fmt.Sprintf("⚠️ 自动领取失败: %s", app.DictGetStr(om, "message", "")), "yellow"))
		}
	}
}

// ── 账号管理 ─────────────────────────────────────────────────────────────────

func cmdAddAccount(args []string) {
	if len(args) < 3 {
		fmt.Println(c("格式: zcode2api-go add-account <zai|bigmodel> <name> <jwt|key>", "red"))
		return
	}
	provider, name, secret := args[0], args[1], args[2]
	acc, err := app.DefaultStore.AddAccount(provider, name, secret)
	if err != nil {
		fmt.Println(c(fmt.Sprintf("%v", err), "red"))
		return
	}
	fmt.Println(c(fmt.Sprintf("✔ 已添加账号 %s (%s) 模式=%s", acc.Name, acc.ID, acc.Mode), "green"))
	cliIngestFollowup(acc)
}

func cmdAccounts(args []string) {
	provider := ""
	if len(args) > 0 && (args[0] == "zai" || args[0] == "bigmodel") {
		provider = args[0]
	}
	accounts := app.DefaultStore.ListAccounts(provider)
	if len(accounts) == 0 {
		fmt.Println("无账号")
		return
	}
	label := provider
	if label == "" {
		label = "全部"
	}
	fmt.Println(c(fmt.Sprintf("\n--- 账号列表 (%s) ---", label), "cyan"))
	for _, a := range accounts {
		st := a.EffectiveStatus(0)
		fmt.Printf("%s  %s  %s  %s  %s\n", a.ID, a.Provider, a.Mode, st, a.Name)
	}
}

func cmdRemoveAccount(args []string) {
	if len(args) < 2 {
		fmt.Println(c("格式: zcode2api-go remove-account <provider> <id|name>", "red"))
		return
	}
	if app.DefaultStore.RemoveAccount(args[0], args[1]) {
		fmt.Println(c(fmt.Sprintf("✔ 已删除账号 %s", args[1]), "green"))
	} else {
		fmt.Println(c("⚠️ 未找到指定账号", "yellow"))
	}
}

func cmdSetAdminKey(args []string) {
	if len(args) == 0 {
		fmt.Println(c("格式: zcode2api-go set-admin-key <key>", "red"))
		return
	}
	app.DefaultStore.SetSetting("admin_key", args[0])
	fmt.Println(c("✔ 已更新后台密码", "green"))
}

func cmdStatus() {
	fmt.Println(c("\n--- zcode-hub 状态 ---", "cyan"))
	fmt.Printf("数据库      : %s\n", c(app.DBPathString(), "blue"))
	fmt.Printf("默认端口    : %s\n", c(fmt.Sprintf("%d", app.PORT), "blue"))
	adminKey := app.DefaultStore.AdminKey()
	if adminKey != "" {
		fmt.Println("后台密码    : 已设置")
	} else {
		fmt.Printf("后台密码    : %s\n", c("未设置", "yellow"))
	}
	gatewayKey := app.DefaultStore.GatewayKey()
	if gatewayKey != "" {
		fmt.Println("网关 API Key: 已设置")
	} else {
		fmt.Println("网关 API Key: 未设置（不校验）")
	}
	for _, p := range []string{"zai", "bigmodel"} {
		accounts := app.DefaultStore.ListAccounts(p)
		active := 0
		for _, a := range accounts {
			if a.IsSelectable(0) {
				active++
			}
		}
		fmt.Printf("%-9s  : %d 个账号，%d 个可用\n", p, len(accounts), active)
	}
}

func cmdQuota() {
	var accounts []*app.Account
	for _, a := range app.DefaultStore.ListAccounts("zai") {
		if a.Mode == "jwt" {
			accounts = append(accounts, a)
		}
	}
	if len(accounts) == 0 {
		fmt.Println(c("无 Coding Plan (JWT) 账号可查询额度。", "yellow"))
		return
	}
	fmt.Println(c("\n正在拉取各账号实时额度...", "cyan"))
	for _, a := range accounts {
		app.FetchQuota(a)
		fmt.Println(c(fmt.Sprintf("\n账号: %s (%s)", a.Name, a.EffectiveStatus(0)), "bold"))
		if len(a.Quota) == 0 {
			fmt.Println("  无额度数据")
			continue
		}
		// 对齐 Python 字典序：quota.items() 保持插入序；Go map 无序 → 按 key 排序输出
		keys := make([]string, 0, len(a.Quota))
		for k := range a.Quota {
			keys = append(keys, k)
		}
		sortStrings(keys)
		for _, model := range keys {
			q, _ := a.Quota[model].(map[string]any)
			rem, tot := 0.0, 0.0
			if q != nil {
				if f, ok := app.AsFloat(q["remaining"]); ok {
					rem = f
				}
				if f, ok := app.AsFloat(q["total"]); ok {
					tot = f
				}
			}
			fmt.Printf("  %s: 剩余 %s / 总额 %s\n",
				c(model, "cyan"), commaInt(rem), commaInt(tot))
		}
	}
}

func commaInt(v float64) string {
	// 对齐 Python f"{rem:,}"
	s := fmt.Sprintf("%.0f", v)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var parts []string
	for len(s) > 3 {
		parts = append([]string{s[len(s)-3:]}, parts...)
		s = s[:len(s)-3]
	}
	parts = append([]string{s}, parts...)
	out := strings.Join(parts, ",")
	if neg {
		out = "-" + out
	}
	return out
}

func sortStrings(list []string) {
	for i := 1; i < len(list); i++ {
		for j := i; j > 0 && list[j] < list[j-1]; j-- {
			list[j-1], list[j] = list[j], list[j-1]
		}
	}
}

func cmdExport(args []string) {
	out := "zcode-accounts.json"
	if len(args) > 0 {
		out = args[0]
	}
	data := app.DefaultStore.Export()
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Println(c(fmt.Sprintf("导出失败: %v", err), "red"))
		return
	}
	if err := os.WriteFile(out, raw, 0o644); err != nil {
		fmt.Println(c(fmt.Sprintf("导出失败: %v", err), "red"))
		return
	}
	fmt.Println(c(fmt.Sprintf("✔ 已导出到 %s", out), "green"))
}

func cmdImport(args []string) {
	// --password <pw>：仅 .zsb 加密封包需要；回落环境变量 ZSW_PASSWORD / ZCODE_BUNDLE_PASSWORD
	password := ""
	files := []string{}
	for i := 0; i < len(args); i++ {
		if args[i] == "--password" && i+1 < len(args) {
			password = args[i+1]
			i++
			continue
		}
		files = append(files, args[i])
	}
	if len(files) == 0 {
		fmt.Println(c("格式: zcode2api-go import <file> [--password <pw>]", "red"))
		return
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		fmt.Println(c(fmt.Sprintf("读取失败: %v", err), "red"))
		return
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		fmt.Println(c(fmt.Sprintf("解析失败: %v", err), "red"))
		return
	}
	// .zsb 加密封包（is_sealed：kdf + cipher 同时存在）：解封后转成 providers 形态再入池
	if app.IsSealedBundle(payload) {
		if password == "" {
			password = os.Getenv("ZSW_PASSWORD")
		}
		if password == "" {
			password = os.Getenv("ZCODE_BUNDLE_PASSWORD")
		}
		if strings.TrimSpace(password) == "" {
			fmt.Println(c("该文件是 .zsb 加密封包：请加 --password <pw>，或设置环境变量 ZSW_PASSWORD", "red"))
			return
		}
		inner, err := app.OpenZsbBundle(payload, password)
		if err != nil {
			fmt.Println(c(fmt.Sprintf("解封失败: %v", err), "red"))
			return
		}
		total := 0
		if accs, ok := inner["accounts"].([]any); ok {
			total = len(accs)
		}
		payload = app.ZsbToProviders(inner)
		fmt.Println(c(fmt.Sprintf("✔ .zsb 已解封（%d 个账号）", total), "green"))
	}
	existing := map[string]bool{}
	for _, a := range app.DefaultStore.ListAccounts("") {
		existing[a.ID] = true
	}
	count := app.DefaultStore.ImportAccounts(payload)
	added := 0
	for _, a := range app.DefaultStore.ListAccounts("") {
		if !existing[a.ID] {
			added++
			if a.Provider == "zai" {
				cliIngestFollowup(a)
			}
		}
	}
	// 口径：count = 处理数（含重复 token 去重命中）；重复的不会重复入池
	if added < count {
		fmt.Println(c(fmt.Sprintf("✔ 已导入 %d 个账号（新增 %d，重复跳过 %d）", count, added, count-added), "green"))
	} else {
		fmt.Println(c(fmt.Sprintf("✔ 已导入 %d 个账号", count), "green"))
	}
}

// ── 分发 ─────────────────────────────────────────────────────────────────────

func main() {
	// 对齐 Python：store 单例在 import 时创建；Go 入口先初始化存储
	app.InitStore()

	argv := os.Args[1:]
	if len(argv) == 0 {
		usage()
		return
	}
	cmd, rest := argv[0], argv[1:]

	switch cmd {
	case "help", "-h", "--help":
		usage()
	case "serve":
		cmdServe(rest)
	case "login":
		cmdLogin(rest)
	case "add-account":
		cmdAddAccount(rest)
	case "accounts":
		cmdAccounts(rest)
	case "remove-account":
		cmdRemoveAccount(rest)
	case "set-admin-key":
		cmdSetAdminKey(rest)
	case "status":
		cmdStatus()
	case "quota":
		cmdQuota()
	case "export":
		cmdExport(rest)
	case "import":
		cmdImport(rest)
	default:
		fmt.Println(c(fmt.Sprintf("未知命令: %s", cmd), "red"))
		usage()
	}
}

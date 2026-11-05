# zcode2api-go (zcode-hub)

**ZCode 账号运营 + 双协议网关一体机（Go 版）**：把池内 ZCode Coding Plan / Start Plan / API Key 账号额度，统一转换为标准的
**Anthropic Messages API**（`/v1/messages`）与 **OpenAI Chat Completions API**（`/v1/chat/completions`），向 Claude Code、Cline、Codex CLI、Chatbox、NextChat 等各类 Agent 与客户端提供高可用 API 服务。

> 本项目是 [dengyie/zcode2api](https://github.com/dengyie/zcode2api)（Python · FastAPI）的 **1:1 Go 语言移植版**：
> 逐模块、逐函数、逐注释对齐改写，功能面、端点、错误语义、默认值与判定口径全部保持一致。
> 前端控制台（`frontend/`）、验证码求解器（`captcha_node/`）、文档（`docs/`）与数据格式（`data/accounts.db`）
> 与原版完全兼容，可直接替换部署。

## 来源项目

本仓库在原版移植之外，还复刻 / 参考了以下开源项目的实现与实证结论（在此致谢）：

| 项目 | 复刻 / 参考内容 |
|------|----------------|
| [dengyie/zcode2api](https://github.com/dengyie/zcode2api) | **1:1 移植源**（Python 原版）：全部网关 / 账号池 / 验证码 / 领取 / 后台功能 |
| [magpie-community/plugins · packages/zcode](https://github.com/magpie-community/plugins/tree/main/packages/zcode) | ZCode **3.17.2 官方提示词资产与 dress 形态**（`zcode_prompt_3172.json` 的出处；2026-11-03 上游按提示词版本指纹判 405/3012 的实证与修复）、`startHeaders` 请求头形态、coding-plan 通道 `x-api-key` + `Bearer` 双头与 `metadata.user_id` 形态 |
| [yetone/magpie](https://github.com/yetone/magpie) | 喜鹊应用本体：zcode 插件承载形态、账号路由与 usage 卡片交互参考 |
| [Arimayuki03/magpie-zcode-switch-auth](https://github.com/Arimayuki03/magpie-zcode-switch-auth) | zsw 账号导入 / 活动领取流程参考 |
| [wjsqqj/zcode-switch](https://github.com/wjsqqj/zcode-switch)（zsw） | **`.zsb` 加密封包格式**（PBKDF2 + AES-256-GCM envelope，见 `docs/development/03-data-formats.md`）与互通语义 |
| [@juejin-opensource/jusage-core](https://github.com/juejin-cn/juejin-usage)（掘金开源） | `coding-plan/reset/status` 官方重置卡端点（双 token 头）与 monitor 额度窗口的字段映射 |
| [liu5269/zcode2api](https://github.com/liu5269/zcode2api) | 早期简化形态对照（3.0.1 时代最小头集基线） |

自带一套完整的账号运营控制台：多账号池轮询、高可信成套桌面指纹仿真、官方首启安装序仿真、单账号并发控制、429/5xx/3012 阶梯容灾、请求全景监控、限时套餐自动与手动领取、OAuth 免密登录入池，以及免浏览器的阿里云无痕验证求解——开箱即用，自托管部署。

---

## 核心能力

- **双协议兼容网关**：原生支持 `POST /v1/messages`（Anthropic Messages 协议，支持流式 SSE）、`POST /v1/chat/completions`（OpenAI 格式双向翻译，支持流式与非流式）、`POST /v1/responses`（OpenAI Responses API 双跳翻译）与 `POST /v1/messages/count_tokens`（本地确定性估算，估算对象为 transform 后形状）、`GET /v1/models` 模型列表。
- **高可信桌面指纹池（一号一台）**：入池自动生成加权桌面成套 SKU（Mac Sequoia/Tahoe、Win11 主流分辨率等），每账号独立全新 UUIDv4 `device_mid`，杜绝宿主机云 Linux 内核共享导致的账号集群关联风险。
- **官方首启安装序仿真**：入池与指纹轮换自动执行 `client/configs` 与激活事件上报（`app_launch` / `app_daily_active`），持久化 `install_id` 与 `installed_at`。
- **反代与 CDN 基础设施头深度清洗**：自动剔除 `x-forwarded-*`、`forwarded`、`cf-*`、`cdn-loop`、`x-real-ip`、`via`、`cookie`、`referer`、`origin`、`accept-language` 等网络中间件头部，杜绝部署网络拓扑泄露与客户端伪装冲突。
- **单账号精细化并发控制**：支持单账号并发上限（默认 2，可在后台运行时热改，0 不限）。满并发账号智能跳过，不计入重试轮数；客户端断开、异常与等待期间即时释放并发槽位。
- **阶梯式故障转移与容灾策略**：
  - **429 智能退避重试**：优先根据上游 `Retry-After` 原地等待重试（等待期间释放并发槽位，防止阻塞）；重试耗尽无损换号且**不冷却账号**；Plan 通道 429 耗尽且同账号有 API Key 时自动切 `api.z.ai` 回退通道；code 3009「模型并发已满」短退避 + 抖动。
  - **5xx 熔断冷却**：重试 3 次后进入 300s 冷却，自动切下一个可用账号。
  - **3012/405 真风控隔离**：识别 "unusual activity" 按指数退避冷却（首冷 900s、封顶 24h），累计 4 次升级 `DISABLED`（可配置自动换发设备指纹重生的安装序），需后台人工确认恢复。
  - **401/403 鉴权失效标记**：非验证码的凭证失效直接标 `INVALID`。
- **HTTP 200 业务错误识别**：Plan 通道 `{"code":1005|3012,...}` 形态按等价 HTTP 状态走统一处置分支，不洗状态、不透传错误体。
- **全景请求监控与安全防护**：
  - 请求监控面板（`/admin/monitoring`）：实时展示在飞请求、历史请求耗时、状态码、模型、账号及错误信息（内存环形 500 条）。
  - 后台暴力破解防护：客户端 IP 连续登录失败达 8 次自动锁定 5 分钟。
  - 设置密钥脱敏回显：GET 设置接口密钥自动打码，保障安全性。
- **限时套餐领取（双轨机制）**：
  - 自动领取：入池即自动领取全部可领套餐（激活上报先于 preview），并有可配置的周期自动领取轮（默认 3600 秒，后台设置页可改，0 = 关闭），持续盯当期活动赠送。
  - 领取语义对齐官方 3.11.2：成功回执携带上游 `server_time` 与套餐窗口；1005「名额用完」附带名额恢复时间 `next_at`，领取轮按其退避（等待期不重试领取、不耗验证码，`next_at` 过后自动恢复）。
  - 北京时间领取窗口：`claim_round_hours` 按北京时钟锚定（host 换成 UTC 也不漂），窗口外不空转。
  - 浏览器过码：支持在前端调起阿里云滑块验证码进行手动领取，应对极严风控环境。
- **OAuth CLI 免密登录**：
  - 严格遵循官方 CLI 的干净请求头规范，JWT 授权入池秒级完成，API Key 兑换异步后台回填。
  - 跟进官方新协议：采用 init 响应服务端下发的 `poll_token` 轮询（未下发时回落自造，兼容旧协议）；poll 4xx 承载的 `code=3004` 明确映射为会话过期。
- **官方版本自动感知**：轮询官方 Electron manifest（YAML，含 YAML 1.1 float 版本号陷阱的回退解析），自动对齐客户端伪装版本与 UA，管理后台支持手动核验。

## 支持的账号类型

| Provider | 模式 | 说明 |
|----------|------|------|
| `zai` | `jwt` | Coding Plan 额度（Plan 通道，需无痕验证码），自动续领活动套餐 |
| `zai` | `apiKey` | Z.AI API Key（回退通道，免验证码） |
| `bigmodel` | `apiKey` | 智谱开放平台（Anthropic 兼容端点） |

> 一个 Z.AI 账号可同时持有 JWT 与 API Key：OAuth 登录后会一并入池，JWT 额度告罄或 429 耗尽时自动无缝走 API Key 回退通道。

## 快速开始

```bash
# 需要 Go 1.27+ 与 Node.js（JWT 模式求解验证码用）
go build -o zcode2api-go .
cp .env.example .env            # 按需修改密钥、端口等
cd captcha_node && npm install  # 首次使用 JWT 模式前执行
cd ..
./zcode2api-go serve            # 启动网关 + 后台 UI（默认 http://0.0.0.0:3000）
```

- 后台管理：`http://127.0.0.1:3000/admin/login`（初始密码见 `.env` 的 `ZCODE_ADMIN_KEY`，默认 `zcode`）
- 对话端点：
  - Anthropic 协议：`POST http://127.0.0.1:3000/v1/messages`（兼容 Claude Code、Cline）
  - OpenAI 协议：`POST http://127.0.0.1:3000/v1/chat/completions`（兼容 OpenAI 客户端）
  - Responses 协议：`POST http://127.0.0.1:3000/v1/responses`
  - 模型列表：`GET http://127.0.0.1:3000/v1/models`
  - 探活端点：`GET http://127.0.0.1:3000/meta`

## 快速上手一个账号

```bash
# 方式一：OAuth 登录（免密，自动入池 + 自动兑换回退 Key）
./zcode2api-go login zai

# 方式二：手动加入现成凭证（JWT 三段点分 或 API Key）
./zcode2api-go add-account zai 名称 <jwt|key>
```

## 命令行

```bash
zcode2api-go serve [--port 3000]    启动网关 + 后台 UI
zcode2api-go login zai              通过 OAuth 登录 Z.AI 并自动入池
zcode2api-go add-account <zai|bigmodel> <name> <jwt|key>   添加账号
zcode2api-go accounts [zai|bigmodel]  查看账号列表
zcode2api-go remove-account <provider> <id|name>  删除账号
zcode2api-go quota                  查看各账号实时额度
zcode2api-go status                 查看配置概览
zcode2api-go set-admin-key <key>    设置后台密码
zcode2api-go export [file]          导出全部账号
zcode2api-go import <file>          导入账号
```

## 后台 UI

| 页面 | 说明 |
|------|------|
| `/admin/login` | 后台登录（Bearer 密钥鉴权，连续失败 IP 锁定防护，凭证加密存于浏览器 localStorage）|
| `/admin/accounts` | 账号池：新增/导入/导出、启用禁用、指纹换发、**实时额度与状态监控**、套餐领取（自动/手动）|
| `/admin/settings` | 后台密码、网关 API Key（GET 脱敏掩码）、额度刷新间隔、单账号并发上限、领取轮间隔与窗口 |
| `/admin/monitoring` | 请求监控中心：实时请求耗时、状态码、上游模型、使用账号、失败原因 |

账号池页实时展示每个账号的**状态（正常 / 额度用完 / 限流 / 异常 / 禁用）**、各模型剩余额度、
调用与失败次数；并提供「手动刷新额度」与「批量领取套餐」入口。

## 多账号轮询与故障转移

- 在账号池粘贴 Coding Plan JWT（3 段点分）或 API Key，每行一个即可加入轮询。
- 网关每次请求选择下一个「可用」账号，跳过用完 / 限流 / 异常 / 禁用的账号。
- **单账号并发限制**：所选账号在飞并发达上限时智能跳过，不排队、不计入 `MAX_ACCOUNT_ATTEMPTS` 计数。
- **额度用完**（余额为 0 / 上游 402 / 业务码 1005·1113 / 错误体含 quota、余额不足等定量关键词）→ 标记 `exhausted`，换下一个账号。
- **上游 429** → **不冷却账号**，按 Retry-After（封顶）原地等待重试；等待期间释放该账号并发槽。耗尽后换号，账号保持可用。Plan 通道 429 耗尽且同账号有 API Key 时切回退通道。
- **上游 5xx** → 重试 3 次后标记 `cooling` 冷却 300 秒，自动换下一个账号。
- **真风控（3012 / 405 unusual activity）** → 指数退避冷却，累计 4 次升级 `disabled` 并熔断停用（默认自动换发设备指纹），需在后台手动恢复。
- **鉴权失败 401/403（非验证码）** → 标记 `invalid`，需重新登录。
- **验证码过期（403 / code 3007）** → 清池换码对同一账号重试（最多 3 次）。
- 达到请求上限仍无可用账号 → 返回 `503 no_available_account`。

账号状态机：

```
            ┌─────────┐   额度用完(定期自动再探)    ┌──────────┐
  登录 ────▶│ ACTIVE  │◀─────────────────────────│ EXHAUSTED│
            │         │   5xx 重试耗尽(冷却 N 秒) └──────────┘
            │         │◀───────┐      ┌─────────┐
            │         │        ├──────│ COOLING │
            │         │        └─────▶└─────────┘
            │         │ 401/403(非验证码)
            │         │──────────────────────▶ INVALID（凭证失效，重新授权）
            │         │ 3012/405(真风控)
            │         │──────────────────────▶ DISABLED（风控保护，后台手动恢复）
            └─────────┘
```

> 成功响应可清除 `COOLING` / `EXHAUSTED`；额度恢复时后台监控也会自动回 `ACTIVE`。

## 无痕验证（免浏览器）

JWT 账号调用上游时需携带阿里云无痕验证参数（请求头 `X-Aliyun-Captcha-Verify-Param`）。
本项目的求解器以子进程方式运行 **Node + 阿里云官方无痕 SDK**（`solver_pw.js` 真浏览器路线 / `solver.js` legacy 路线）直接求解该参数。

- 求解器位于 `captcha_node/`，首次使用前执行 `cd captcha_node && npm install`。
- `internal/app/captcha.go` 以子进程方式调用，内置**按出口分池**的预热池（token 与请求出口一致性由 `egress.go` 保证，否则上游判 unusual activity）、FIFO 年龄淘汰（默认 TTL 95s）、并发去重与失败重试。
- 出口对齐语义完整复刻 httpx 代理判定（`NO_PROXY` 通配符/点前缀/显式端口等差异，见 `internal/app/egress.go` 文档注释）。
- 配置与会话缓存兜底：`client/configs` 拉取失败时回落内置默认参数。

## 鉴权

- **后台鉴权**：所有 `/admin/api/*` 需 `Authorization: Bearer <后台密码>`（也支持 `?app_key=`），内置 IP 失败节流保护。
- **网关鉴权（可选）**：在「设置」配置「网关 API Key」后，`/v1/*` 各端点须携带
  `Authorization: Bearer <key>` 或 `x-api-key: <key>`；留空则不校验。

## 环境变量

`cp .env.example .env` 后按需修改（.env 永不入库）：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `ZCODE_PORT` | 3000 | 服务端口 |
| `ZCODE_HOST` | 0.0.0.0 | 监听地址 |
| `ZCODE_ADMIN_KEY` | zcode | 后台密码初始值（之后写库，以库为准）|
| `ZCODE_DATA_DIR` | data | 数据目录（SQLite 存放处）|
| `ZCODE_FRONTEND_DIR` | frontend | 前端静态目录 |
| `ZCODE_QUOTA_REFRESH_INTERVAL` | 1800 | 后台刷新额度间隔（秒），0 关闭 |
| `ZCODE_BILLING_REFRESH_MIN_INTERVAL` | 60 | 成功对话后计费刷新最小间隔（秒）|
| `ZCODE_COOLING_SECONDS` | 300 | 限流冷却时长（秒）|
| `ZCODE_CLAIM_ROUND_INTERVAL` | 3600 | 套餐自动领取轮间隔（秒），0 关闭（运行时可在后台设置改，以库为准）|
| `ZCODE_CLAIM_ROUND_HOURS` | 19 | 领取窗口（北京时间小时，逗号分隔；空/* = 全天）|
| `ZCODE_RISK_COOLDOWN_BASE` / `_MAX` | 900 / 86400 | 风控指数退避首冷 / 上限（秒）|
| `ZCODE_RISK_BAN_STRIKES` | 4 | 风控累计命中升级禁用阈值 |
| `ZCODE_RISK_AUTO_ROTATE` | true | 风控禁用时自动换发设备指纹 |
| `ZCODE_NODE_PATH` | node | 验证码求解所用 Node 可执行文件 |
| `ZCODE_CAPTCHA_RETRIES` | 4 | 单次求解失败重试次数 |
| `ZCODE_CAPTCHA_TIMEOUT` | 240 | 单次求解超时（秒）|
| `CAPTCHA_POOL_MIN` / `CAPTCHA_POOL_MAX` | 1 / 2 | 验证码预解池目标库存 / 上限 |
| `CAPTCHA_TOKEN_TTL` | 95000 | 单枚 token 最大可用时长（ms）|
| `ZAI_UPSTREAM_URL` / `ZAI_FALLBACK_URL` / `BIGMODEL_UPSTREAM_URL` | — | 上游端点覆盖 |
| `UPSTREAM_USER_AGENT` | — | 上游 UA 覆盖（默认跟随官方版本对齐）|

## 开发与测试

```bash
go build ./...        # 编译
go vet ./...          # 静态检查
go test ./...         # 全量单元测试（无真实网络）
```

单元测试对齐原版 `tests/unit` 的高价值断言：常量钉扎、模型状态机、body_transform
幂等与三块结构、token 估算口径、OpenAI/Responses 双向转换、YAML 版本号陷阱、
NO_PROXY 匹配语义、领取窗口（北京时钟）、风控指数退避等。

## Go 版移植对照

| Python（原版） | Go（本仓库） |
|----------------|--------------|
| `app/constants.py` | `internal/app/constants.go` |
| `app/settings.py` | `internal/app/settings.go` |
| `app/models.py` / `app/store.py` | `internal/app/models.go` / `internal/app/store.go` |
| `app/fingerprint.py` / `app/hostinfo.py` | 同名 `.go` |
| `app/identity.py` / `app/egress.go` / `app/telemetry.py` / `app/install.py` | 同名 `.go` |
| `app/quota.py` / `app/claim.py` / `app/captcha.py` / `app/version_tracker.py` / `app/oauth.py` | 同名 `.go` |
| `app/body_transform.py` / `app/openai_compat.py` / `app/responses_compat.py` / `app/token_estimate.py` / `app/agent.py` | 同名 `.go` |
| `app/auth_admin.py` / `app/reqlog.py` / `app/business_error.py` / `app/logs.py` | 同名 `.go` |
| `app/routes/gateway.py` / `admin_api.py` / `pages.py` | `internal/routes/*.go` |
| `app/main.py`（FastAPI 工厂 + lifespan） | `internal/routes/server.go` |
| `cli.py` | `main.go` |

- HTTP 服务：Python FastAPI/Uvicorn → Go `net/http`（1.22+ 方法/路径路由）；asyncio → goroutine。
- SQLite：语义一致（WAL / synchronous=NORMAL / busy_timeout=5000），驱动为纯 Go 的 `modernc.org/sqlite`，**数据库文件与 Python 版互通**。
- 运行期配置、meta 表、账号 JSON 序列化字段名与 Python 版逐字段一致。

## 文档

完整文档见 [`docs/README.md`](docs/README.md)（与原版一致）：

- **开发**：架构 · 数据格式 · API 规范 · 上游协议 · 开发指南 · 路线图
- **测试**：测试策略 · 单元用例 · 互通向量 · 集成 E2E · 验收标准

## 技术栈

- Go 1.27+ · `net/http`（零框架）
- SQLite（账号 / 设置持久化，WAL 模式，`modernc.org/sqlite` 纯 Go 驱动）
- `gopkg.in/yaml.v3`（官方 Electron manifest 解析）
- Node.js（免浏览器求解阿里云无痕验证，复用原版 `captcha_node/`）

## 许可证

本项目采用 [AGPL-3.0](LICENSE) 许可证（继承自原版 dengyie/zcode2api）。

## 免责声明

本仓库仅供学习、研究、个人实验与内部验证使用，不提供任何形式的商业授权、适用性保证或结果保证。

作者不因使用、修改、分发、部署或依赖本项目产生的任何直接或间接损失、账号封禁、数据丢失、
法律风险或第三方索赔负责。请勿将本项目用于违反服务条款、协议、法律或平台规则的场景；商业前请自行确认许可证与相关协议。

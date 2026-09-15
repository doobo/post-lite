# PostLite（postlite）设计说明

本文面向**改这个项目的开发者**：解释各模块的设计取舍与约束，也就是「为什么这么写」。
安装、启动参数、接口清单等使用说明见 [`../README.md`](../README.md)。

> 命名约定：产品名与 Web UI 标题是 `PostLite`，Go 模块名 / 二进制名 / import 前缀是 `postlite`
> （Go 标识符不能带连字符），数据库文件名 `postlite.db`，导出格式标识 `postlite/v1`。

---

## 1. 目标与约束

| 目标 | 落地方式 |
| --- | --- |
| 单文件部署 | 单个 Go 二进制，前端用 `go:embed` 编进去，拷一个文件就能在内网跑 |
| 不依赖外部服务 | 不用 CDN、不用外部数据库/缓存，出站请求由服务端代发 |
| 密钥只写不读 | Secret 用 AES-256-GCM 加密入库，服务端**不提供任何读取明文的接口** |
| 资源隔离 | `admin` / `user` 两种角色，数据按 `owner_id` 隔离 |
| 依赖极少 | 直接依赖只有 `modernc.org/sqlite`（纯 Go、无 cgo）与 `golang.org/x/crypto`（scrypt） |

最核心的一条约束：**浏览器不直接访问目标 API**。原因有两点——避免 CORS，以及避免把内网拓扑暴露给浏览器。
所以执行统一走 `POST /api/execute`，由服务端代发请求、脱敏后返回。

## 2. 架构

```
┌─────────────────────┐
│      Browser        │
│   Web UI / SPA      │
└──────────┬──────────┘
           │ HTTPS（PostLite 自身）
           ▼
┌────────────────────────────────────────────────────────┐
│                       PostLite                         │
│                                                        │
│  Auth(RBAC)   Collections   Environments               │
│  Sessions     Requests      Secret Vault (AES-256-GCM) │
│                                                        │
│  Executor（HTTP Client / 代理执行 / SSRF 校验 / 脱敏） │
│                                                        │
│  SQLite（业务数据 + 密钥密文，WAL）                    │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
                     内网业务 API
```

## 3. 技术选型（按实际实现）

| 层 | 选型 | 说明 |
| --- | --- | --- |
| 语言 | Go 1.27（见 `go.mod`） | 只用标准库 + 两个直接依赖 |
| HTTP | `net/http`（`ServeMux` 的 method+pattern 路由） | 无第三方框架，路由集中注册在 `cmd/postlite/main.go` |
| 存储 | SQLite（`modernc.org/sqlite`，纯 Go） | WAL 模式，文件单库 |
| 迁移 | `internal/db/migrations.go` 内嵌版本化 SQL | 按 `PRAGMA user_version` 顺序执行 |
| 口令 | `golang.org/x/crypto/scrypt`（N=16384, r=8, p=1, len=64, salt 16B） | 校验用 `subtle.ConstantTimeCompare` |
| 加密 | `crypto/aes` + `cipher.NewGCM`（AES-256-GCM） | 主密钥与库分离 |
| TLS | `crypto/tls` + 自签证书 | 证书不存在时自动生成 ECDSA P-256（CN=postlite，SAN 含 localhost/127.0.0.1/::1） |
| 前端 | **普通静态文件，零构建步骤** | `internal/web/static/{index.html,app.js,app.css}`，改完重新 `go build` 即生效 |
| 日志 | `log/slog`（TextHandler → stderr） | 审计日志另写入 `settings` 表 |

设计上放弃了「前端 Vite 构建」的早期方案：没有构建步骤后，内网离线环境也能直接改前端，
代价是前端保持 vanilla JS（无组件框架、无模块打包）。

## 4. 数据模型

以 `internal/db/migrations.go` 中的 migration V1 为准（此处同步展示，方便对照）：

```sql
CREATE TABLE users (
  id            INTEGER PRIMARY KEY,
  username      TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,       -- scrypt(N=16384,r=8,p=1,len=64) hex
  salt          TEXT NOT NULL,       -- 16B hex
  enabled       INTEGER NOT NULL DEFAULT 1,
  role          TEXT NOT NULL CHECK(role IN ('admin','user')),
  created_at    TEXT NOT NULL
);

CREATE TABLE sessions (
  id         TEXT PRIMARY KEY,       -- sha256(token) hex，不存明文 token
  user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL           -- RFC3339，默认 +24h
);

CREATE TABLE collections (
  id         INTEGER PRIMARY KEY,
  name       TEXT NOT NULL,
  owner_id   INTEGER REFERENCES users(id) ON DELETE SET NULL,  -- NULL = 全局（admin 建）
  created_at TEXT NOT NULL
);

CREATE TABLE folders (
  id            INTEGER PRIMARY KEY,
  collection_id INTEGER NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
  parent_id     INTEGER REFERENCES folders(id) ON DELETE CASCADE,  -- 支持嵌套
  name          TEXT NOT NULL
);

CREATE TABLE requests (
  id            INTEGER PRIMARY KEY,
  collection_id INTEGER NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
  folder_id     INTEGER REFERENCES folders(id) ON DELETE SET NULL,
  owner_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
  name          TEXT NOT NULL,
  method        TEXT NOT NULL CHECK(method IN ('GET','POST','PUT','PATCH','DELETE')),
  url           TEXT NOT NULL,       -- 支持 {{VAR}}
  headers       TEXT,                -- JSON
  query         TEXT,                -- JSON
  body_type     TEXT NOT NULL DEFAULT 'none',   -- none | json | raw
  body          TEXT,
  updated_at    TEXT NOT NULL
);

CREATE TABLE environments (
  id       INTEGER PRIMARY KEY,
  name     TEXT NOT NULL,
  scope    TEXT NOT NULL CHECK(scope IN ('global','user')),
  owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  vars     TEXT NOT NULL,            -- JSON: {"host":"10.0.0.1:8080"}
  UNIQUE(scope, owner_id, name)
);

CREATE TABLE secrets (
  id         INTEGER PRIMARY KEY,
  name       TEXT UNIQUE NOT NULL,   -- 占位符名，如 {{sec.api_key}} 里的 api_key
  ciphertext BLOB NOT NULL,          -- AES-256-GCM: nonce(12) || ciphertext || tag(16)
  created_by INTEGER NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
  -- 没有“解密值”列，也没有对应的读值接口
);

CREATE TABLE history (
  id           INTEGER PRIMARY KEY,
  request_id   INTEGER,
  user_id      INTEGER NOT NULL,
  method       TEXT NOT NULL,
  url          TEXT NOT NULL,
  status       INTEGER NOT NULL,
  duration_ms  INTEGER NOT NULL,
  req_redacted TEXT,                 -- 脱敏后的请求快照
  res_redacted TEXT,                 -- 脱敏后的响应体（截断 1MB）
  created_at   TEXT NOT NULL
);

CREATE TABLE settings (
  key   TEXT PRIMARY KEY,            -- 含 active_global_env / active_env_user_<uid> / audit_log 等
  value TEXT NOT NULL
);
```

设计要点：

- 时间统一存 `TEXT`（RFC3339 UTC），读写时显式解析，避免 SQLite 的日期类型歧义。
- `owner_id IS NULL` 表示全局资源（只有 admin 能建），权限判定因此只有两档：自己的 or 全局的。
- 外键用 `ON DELETE CASCADE` / `SET NULL` 表达归属关系，删用户后其私有数据不残留。
- 环境「当前激活」状态存在 `settings` 里（而不是进程内存），所以重启后仍按用户生效。

## 5. 认证、会话与 RBAC

- 登录：`POST /api/auth/login` 校验 scrypt 口令，通过后生成 32B 随机 token（`crypto/rand`）。
  Cookie `session=<token>`，`HttpOnly; SameSite=Lax`，TLS 下附加 `Secure`，`MaxAge=24h`。
- 会话：服务端只存 `sha256(token)`；24h **硬过期、无滑动续期**——宁可让用户重新登录，
  也不让一个会话无限延长。过期行在登录时顺带 `PurgeExpired`。
- 限流：同一 IP 登录失败 5 次锁定 15 分钟，进程内存计数（重启即清零，内网部署可接受）。
- 中间件：`auth.Middleware` 只负责「解析 cookie → 注入 user 上下文」，不做拒绝；
  需要鉴权的 handler 用 `requireUser` / `RequireRole("admin")` 显式声明，
  未登录路径（登录页、静态资源）才能安全穿过。
- 越权防护放在 **repository 层**：`CanView` / `CanManage` / `CanUseRequest` 统一按 `owner_id` 过滤，
  这样 handler 漏写检查也不会越权读别人数据。

| 能力 | admin | user |
| --- | --- | --- |
| 用户增删 / 禁用 / 重置密码 | ✅ | ❌ |
| 列出 / 写入 / 删除 Secret | ✅ | ❌ |
| 创建与管理全局 Environment、全局 Collection | ✅ | ❌ |
| 查看全局 Collection / Environment | ✅ | ✅ |
| 管理自己的 Collection / Folder / Request / Environment | ✅ | ✅ |
| 执行可见 Collection 中的全局请求 | ✅ | ✅ |
| 执行自己的请求、引用 `{{sec.NAME}}` 注入密钥 | ✅ | ✅（看不到 Secret 名与值） |
| 查看 / 删除自己的 History | ✅ | ✅ |

## 6. Secret Vault（核心安全设计）

- **主密钥**：32B 随机数，优先级 `-master-key` > `POSTLITE_MASTER_KEY` > `-master-key-file`（默认 `data/master.key`，
  首启生成，权限 0600，文件内容为 base64）。**永不写入 SQLite**，Vault 与业务库分离，
  启动日志打印 `key_fingerprint`（sha256 前 4 字节）便于人工核对。
- **加密**：AES-256-GCM，每次写入生成 12B 随机 nonce，存储 `nonce(12) || ciphertext || tag(16)`
  （Go 的 `AEAD.Seal` 把 tag 追加在密文之后）。
- **只写不读**：
  - `POST /api/secrets` 响应只回 `id` + `name`，不回显 value；
  - 没有读值接口；`GET /api/secrets`（仅 admin）只返回 `id` + `name` + `updated_at`；
  - 重名返回 `409`，改用 `PUT /api/secrets/{name}` 覆盖（旧密文直接替换）。
  - 明文只出现在两个地方：执行引擎内存中注入出站请求，以及（比对后）被脱敏掉的位置。
- **缓存**：解密结果进程内缓存 5 分钟，任何写入都会 `Invalidate()` 并递增 `gen`，
  跨 goroutine 用 `RWMutex` 保护，避免「覆盖了密钥但执行还在用旧值」。
- **脱敏**：出站请求快照 / 响应 / history / 审计日志统一走 `executor/redact.go`，
  凡是等于某密文解密结果的字符串都替换为 `***`。

## 7. 变量解析与注入

占位符语法 `{{name}}`，正则 `\{\{([\w.]+)\}\}`，URL / Headers / Query / Body 共用同一个 `resolve()`。

优先级（高 → 低）：

1. 请求级临时变量（执行时由 UI 传入）
2. 已激活的 user Environment
3. 已激活的 global Environment
4. `secrets` 表（占位符写作 `{{sec.NAME}}`，命中才解密）

未命中的占位符**原样保留**，并出现在执行结果的 `warnings` 里（去重、按名排序）；
但若 URL 解析后仍含 `{{`，直接返回 `400 unresolved_variable` —— 避免把带占位符的地址发到真实网络。

## 8. 执行引擎与 SSRF

- 服务端 `http.Client`：`ForceAttemptHTTP2`，禁用自动 gzip；默认超时取 `-timeout`（60s），
  可被 `settings.exec_timeout` 覆盖；每次执行可带请求级超时。
- 重定向：默认**不跟随**（3xx 原样回给 UI），请求级 `follow_redirects` 可开，最多 5 跳。
- 响应体截断 10MB 供 UI 展示；history 只存脱敏后的 1MB，避免库被大响应撑爆。
- **SSRF 防护**：白名单是 `settings.ssrf_whitelist` 里的 CIDR 列表
  （默认 `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8`）。
  执行前解析目标 host，要求**所有** A/AAAA 结果都落在白名单内才放行；跟随重定向时每一跳重新校验。
  拦截返回 `451` 并写审计日志。
- 通用约定：请求体上限 4MB；`method` 只允许 `GET/POST/PUT/PATCH/DELETE`，服务端校验。

## 9. REST API

除集合导出（直接返回原始 JSON 附件、不套信封）外，统一信封：
`{"ok":true,"data":...}` / `{"ok":false,"error":{"code","message"}}`。
鉴权失败 `401`、越权 `403`、SSRF 拦截 `451`。

```
Auth          POST /api/auth/login      POST /api/auth/logout        GET /api/auth/me
Users(admin)  GET/POST /api/users       DELETE /api/users/{id}
              POST /api/users/{id}/disable   POST /api/users/{id}/enable
              POST /api/users/{id}/reset-password
Collections   GET/POST /api/collections GET/PUT/DELETE /api/collections/{id}
              POST /api/collections/{id}/export
              POST /api/collections/import      # {json, global}，global=true 仅 admin
              GET/POST /api/collections/{id}/folders
Requests      GET/POST /api/requests    GET/PUT/DELETE /api/requests/{id}
Environments  GET/POST /api/environments  GET/PUT/DELETE /api/environments/{id}
              POST /api/environments/activate
Secrets       POST /api/secrets         PUT /api/secrets/{name}
(admin)       GET /api/secrets          DELETE /api/secrets/{id}
Execute       POST /api/execute         # { request_id | ad_hoc{...}, vars, active_env, follow_redirects }
History       GET /api/history?request_id=&limit=   GET/DELETE /api/history/{id}
Settings      GET/PUT /api/settings     # ssrf_whitelist / exec_timeout / max_history
```

`PUT /api/settings` 在写入前统一校验所有字段，避免「改一半」的半应用状态。

## 10. 前端

```
internal/web/static/
├── index.html   # 登录页 + 应用外壳（内联模板，无构建）
├── app.js       # 全部状态与视图渲染（vanilla JS，无依赖、无 CDN）
└── app.css
```

- `internal/web/web.go` 用 `//go:embed all:static` 打包，`Handler()` 提供 SPA 回退：
  命中静态文件就直接服务，否则回 `index.html`。
- 视图：登录页 → Collections 树 / Environments / History / Secrets(admin) / Users(admin) / Settings(admin)，
  加请求编辑器（method、url、headers/query 表格、body、Send → 结果面板）。
- `api()` 统一处理信封与 `401`：任何非登录接口返回 401 就回到登录页，
  这样服务端删了会话（例如被禁用）时前端不会卡在假登录态。
- 安全性：所有插值都经过 `esc()` / `escAttr()`，避免把响应内容当 HTML 渲染。

## 11. 项目结构

```
postlite/
├── cmd/postlite/
│   ├── main.go              # flag 解析、TLS、路由挂载、优雅退出
│   ├── helpers.go           # 首启建 admin、自签证书生成、panic 恢复
│   └── *_test.go            # 端到端 handler / 安全测试
├── internal/
│   ├── auth/                # password.go / session.go / middleware.go / ratelimit.go
│   ├── config/              # 运行配置（Config 结构体）
│   ├── crypto/              # Secret Vault：Seal/Open、主密钥加载、缓存
│   ├── db/                  # SQLite 打开（WAL）+ 版本化迁移
│   ├── models/              # 表结构体
│   ├── repository/          # 各实体 repo，统一 owner 过滤（store.go 聚合）
│   ├── httpapi/             # REST handler：auth/users/collections/requests/
│   │                        #   environments/secrets/execute/history/settings/server
│   ├── executor/            # http.go（出站执行 + SSRF）/ resolve.go / redact.go
│   └── web/
│       ├── web.go           # go:embed + SPA 回退
│       └── static/          # 前端静态文件（无构建步骤）
├── docs/DESIGN.md           # 本文
├── go.mod
└── Makefile
```

## 12. 构建与部署

```bash
make build      # go build -ldflags="-s -w" -o bin/postlite ./cmd/postlite
make run        # HTTPS，:5680，数据目录 ./data
make run-plain  # http://127.0.0.1:5681（仅开发）
make vet        # go vet ./...
make test       # go test ./...
```

首启自动建库、生成 `master.key` 与自签证书，并创建 `admin` 账号，**一次性密码打印到 stderr**
（与启动日志同一输出流），必须登录后到 Users 里重置。

两个注意点：

- 端口约定：TLS 默认 `:5680`，本地明文调试用 `127.0.0.1:5681`（两个模式互相独立，可以同时起）。
- `-plain` 模式下 `SecureCookie=false`（明文 HTTP 下 `Secure` cookie 会被浏览器丢弃）。
- `-data` 目录决定「身份」：换一个数据目录 = 换一套用户、密钥与历史。

## 13. 安全清单

- [x] 主密钥不落 SQLite，文件 0600，启动打印指纹便于核对
- [x] Secret 无读值接口；请求快照 / 响应 / history / 审计日志全链路脱敏
- [x] 登录限流（5 次 / 15 分钟）；会话 24h 硬过期；Cookie `HttpOnly` + `SameSite=Lax`（TLS 下 `Secure`）
- [x] SSRF CIDR 白名单，DNS 全部解析结果校验，重定向逐跳再校验
- [x] repository 层统一 `owner_id` 过滤，防越权
- [x] 请求体 / 响应体 / history 大小上限（4MB / 10MB / 1MB）
- [x] 管理操作（用户、Secret、设置、全局 Collection/Environment、SSRF 拦截）写审计日志
- [x] handler 外层 `withRecover`：panic 变 500 并记日志，不拖垮进程

## 14. 里程碑

**V0.1（已完成）**

单 Go 二进制 + 内嵌 UI；SQLite(WAL) + 自动迁移；登录 / 会话 / admin 用户管理；
RBAC 数据隔离；Collection / Folder / Request CRUD；Environment（global + user，激活持久化）；
Secret 加密入库、只写不读；执行 GET/POST/PUT/PATCH/DELETE + Headers/Query/Body；
`{{VAR}}` + `{{sec.NAME}}` 注入与全链路脱敏；SSRF 白名单；History 脱敏快照；集合导入 / 导出。

**V0.2（规划）**

WebSocket 代理、form-data / 文件上传、SSE 流式响应、请求前置后置脚本（JS 沙箱）、
团队空间、导出 OpenAPI。

WebSocket 的实现路线：V0.2 引入最小 ws 客户端（RFC6455 握手 + 帧编解码，约 200 行标准库代码），
保持零依赖，服务端逐帧中转（1MB/帧，300s 空闲断开）。

## 15. 与原计划的差异

早期设计草稿（本地未入库的 `Task.md`）里有几处后来改了，记录在此避免误解：

| 早期计划 | 实际实现 | 原因 |
| --- | --- | --- |
| 前端用 Vite 构建后 embed | 纯静态文件 + `go:embed`，零构建 | 内网离线也要能改前端，省掉 node 工具链 |
| Go 1.22+ | `go 1.27.0` | 用 `ServeMux` 的 method+pattern 路由 |
| Secret 存 `nonce \|\| tag \|\| ciphertext` | `nonce \|\| ciphertext \|\| tag` | 直接用 `AEAD.Seal` 的输出布局，不改写 |
| 一次性密码打印到 stdout | 打印到 stderr | 与启动日志同一输出流，便于重定向收集 |
| `POST /api/collections/{id}/import` | `POST /api/collections/import`（body 带集合 JSON） | 导入的是「外部文件」，不属于任何已存在集合 |
| 审计日志写 stdout | stderr + `settings.audit_log`（最多 500 条） | 内网无日志系统时也要能在 UI 里翻 |
| 后端叫 `apibox`，只有 UI 叫 PostLite | 模块 / 二进制 / import 前缀 / 环境变量 / 证书 CN / 库文件名 / 导出格式全部统一为 `postlite` | 一个程序两个名字容易在排查时误判，改名一次说清楚 |

改名涉及的标识（V0.1 尚未发布，未做兼容别名）：

| 旧 | 新 |
| --- | --- |
| 模块 / import 前缀 `apibox` | `postlite` |
| `cmd/apibox`、`bin/apibox` | `cmd/postlite`、`bin/postlite` |
| 环境变量 `APIBOX_MASTER_KEY` | `POSTLITE_MASTER_KEY` |
| 数据库文件 `apibox.db` | `postlite.db` |
| 自签证书 CN / SAN `apibox` | `postlite` |
| 导出格式 `apibox/v1` | `postlite/v1` |

带来的操作影响：已有部署需同步改环境变量名或改用 `-master-key[-file]`，
并把 `apibox.db` 重命名为 `postlite.db`（旧导出文件仍可导入——导入只校验 `name`，不校验 `format`）。

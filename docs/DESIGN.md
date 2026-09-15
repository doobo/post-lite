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
| 前端 | **普通静态文件，零构建步骤** | `internal/web/static/{index.html,app.js,loginenc.js,app.css}`，改完重新 `go build` 即生效 |
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
  body_type     TEXT NOT NULL DEFAULT 'none',   -- none | json | raw | graphql
  body          TEXT,                           -- graphql 时存 query 文档
  variables     TEXT,                           -- graphql 的 variables（JSON 对象），可空
  use_proxy     INTEGER NOT NULL DEFAULT 0,     -- 1 = 走 settings.proxy_url，默认直连
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
- 迁移按版本号追加（`migrations` 切片）：V2 加 `use_proxy`（默认 0，升级后存量请求保持直连，不会突然改路由），
  V3 加 `variables`（可空，只有 `body_type=graphql` 才会被读）。

## 5. 认证、会话与 RBAC

- 登录握手：`GET /api/auth/login-key` 下发**进程内临时** RSA-2048 公钥（SPKI base64，另附 `n` / `e`
  供纯 JS 回退用）与 16B 一次性挑战；挑战 2 分钟有效、用后即焚，上限 4096 条，**满了淘汰最旧一条**
  而不是拒绝发新挑战（未认证接口不能因为被刷就让所有人都登不上）。
  前端用 RSA-OAEP/SHA-256 加密 `{"c":挑战,"p":口令}`，以 `{username, enc}` 提交。
- 服务端**不接受明文** `password` 字段：缺 `enc` 回 `400 encryption_required`，解密失败 / 挑战过期或被重放
  回 `400 bad_login_payload`（两手都不计失败次数——没有校验任何口令，锁的是猜密码的人，不是密钥过期的人）。
  解密拿到口令后照旧走 scrypt 校验，通过再生成 32B 随机 token（`crypto/rand`）。
  Cookie `session=<token>`，`HttpOnly; SameSite=Lax`，TLS 下附加 `Secure`，`MaxAge=24h`。
- 会话：服务端只存 `sha256(token)`；24h **硬过期、无滑动续期**——宁可让用户重新登录，
  也不让一个会话无限延长。过期行在登录时顺带 `PurgeExpired`。
- 限流：同一 IP 登录失败 5 次锁定 15 分钟，进程内存计数（重启即清零，内网部署可接受）。
- 忘记口令没有“找回”这回事（scrypt 单向），所以另给一条离线通道：`cmd/pwreset` 直接改数据目录里的库。
  它和 `POST /api/users/{id}/reset-password` 复用同一套 `HashPassword` / `SetPassword` 与审计行，
  区别只在 actor 写作 `cli`；同样**不吊销会话**（重置后请自行登出），也刻意不做“把库里的哈希解密/打印”这种事。
- 中间件：`auth.Middleware` 只负责「解析 cookie → 注入 user 上下文」，不做拒绝；
  需要鉴权的 handler 用 `requireUser` / `RequireRole("admin")` 显式声明，
  未登录路径（登录页、静态资源）才能安全穿过。
- 越权防护放在 **repository 层**：`CanView` / `CanManage` / `CanUseRequest` 统一按 `owner_id` 过滤，
  这样 handler 漏写检查也不会越权读别人数据。
- 例外是**删除请求**：`DELETE /api/requests/{id}` 用 `requireAdmin`，普通用户即使能编辑自己的请求也删不了
  （删掉一条请求会把它在 history 里的关联留成孤儿，这类不可逆操作只给管理员）；前端只在 `role === 'admin'`
  时才渲染删除按钮，服务端这道检查才是真正生效的那一道。

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

### GraphQL

- **是一个 `body_type`，不是一个新协议**：`graphql` 的请求仍然是普通 HTTP POST，只是上线格式由服务端拼。
  `body` 存 query 文档、`variables` 单独一列（编辑器就是 query / variables 两个面板，而且 variables 需要单独的 JSON 校验）。
- **在哪里拼**：`execute.go` 先按普通规则解析占位符（query 与 variables 一起），再调 `executor.GraphQLBody()`
  拼出 `{"query":…,"variables":…}`，并把 `body_type` 归成 `json`——于是 Content-Type、脱敏、history、
  代理这条链路完全不需要为 GraphQL 写特例（executor 依旧是个普通 HTTP 客户端）。
- **variables 为空就不带这个键**：带 `"variables": ""` 会被 GraphQL 服务端当类型错，带 `{}` 只是噪声。
- **variables 不是合法 JSON 就直接 400**：最常见的错误是把 JSON 写成字符串或写成 `id=42`，与其让远端回一个
  难懂的 schema 错误，不如在发送前说清楚（错误信息会点明是 variables 的问题）。
- 选 `graphql` 时若方法还是 `GET`，`app.js` 会顺手改成 `POST`（GraphQL 查询不走 query-string）。

### 代理（HTTP/HTTPS）

- **配置**：`settings.proxy_url`，只能 `http://` 或 `https://`（可带 `user:pass@`），空 = 直连；`PUT /api/settings`
  时校验，`socks5://` 或裸 `host:port` 一律 `400`（不装作支持）。
- **开关粒度是请求**：`requests.use_proxy`（编辑器里的 `use proxy`，默认关闭）/ `ad_hoc.use_proxy`。
  勾了但没配代理 → `400 proxy_not_configured`，**不静默改回直连**（静默降级会让人以为隔离生效了）。
- **传输层**：`Executor` 维护一份 `proxyURL -> *http.Transport` 缓存（带 `http.ProxyURL`），连接池因此能跨请求复用；
  空 URL 直接用共享的直连 transport。同一实例里两种请求可以并发，互不影响。
- **SSRF 策略分叉**（重要）：直连 → 完整 DNS + CIDR 白名单；走代理 → 只校验 `http/https` + 必须带 host。
  理由：代理自己解析目标，本地 DNS 查不到的主机正是代理的用处；代理地址是 admin 在设置里显式声明的出口，
  可信级别等同于白名单本身。重定向每一跳仍按当前模式重新校验，所以代理模式也拦得住 `file://` 之类的跳转。

## 9. REST API

除集合导出（直接返回原始 JSON 附件、不套信封）外，统一信封：
`{"ok":true,"data":...}` / `{"ok":false,"error":{"code","message"}}`。
鉴权失败 `401`、越权 `403`、SSRF 拦截 `451`。

```
Auth          GET  /api/auth/login-key  POST /api/auth/login         POST /api/auth/logout
              GET  /api/auth/me
Users(admin)  GET/POST /api/users       DELETE /api/users/{id}
              POST /api/users/{id}/disable   POST /api/users/{id}/enable
              POST /api/users/{id}/reset-password
Collections   GET/POST /api/collections GET/PUT/DELETE /api/collections/{id}
              POST /api/collections/{id}/export
              POST /api/collections/import      # {json, global}，global=true 仅 admin
              GET/POST /api/collections/{id}/folders
Requests      GET/POST /api/requests    GET/PUT/DELETE /api/requests/{id}   # DELETE 仅 admin
Environments  GET/POST /api/environments  GET/PUT/DELETE /api/environments/{id}
              POST /api/environments/activate
Secrets       POST /api/secrets         PUT /api/secrets/{name}
(admin)       GET /api/secrets          DELETE /api/secrets/{id}
Execute       POST /api/execute         # { request_id | ad_hoc{..., variables, use_proxy}, vars, active_env,
                                        #   follow_redirects }
History       GET /api/history?request_id=&limit=   GET/DELETE /api/history/{id}
Settings      GET/PUT /api/settings     # ssrf_whitelist / exec_timeout / max_history / proxy_url
```

`PUT /api/settings` 在写入前统一校验所有字段，避免「改一半」的半应用状态。

## 10. 前端

```
internal/web/static/
├── index.html   # 登录页 + 应用外壳（内联模板，无构建）
├── app.js       # 全部状态与视图渲染（vanilla JS，无依赖、无 CDN）
├── loginenc.js  # 登录口令加密的纯 JS 回退（无 crypto.subtle 时用）
└── app.css
```

- `internal/web/web.go` 用 `//go:embed all:static` 打包，`Handler()` 提供 SPA 回退：
  命中静态文件就直接服务，否则回 `index.html`。
- **静态资源必须可校验**：`go:embed` 的文件没有 mtime，浏览器会自行启发式缓存，于是升级二进制后
  页面可能还在跑上一版的 `app.js`——表现就是新功能“不见了”。所以每个资源都带
  `ETag`（内容 SHA-256 前缀）与 `Cache-Control: no-cache`：每次加载都回源校验，没变就 `304`，
  升级后普通刷新一定能拿到新版。新增资源不需要登记，启动时扫描 `static/` 一次建成表。
- 视图：登录页 → 侧栏（Collections 树 / Environments / History / Secrets(admin) / Users(admin) / Settings(admin)）
  + 请求编辑器（method、url、Headers/Params/Body/Vars 分页签、Send → 响应面板 Body/Headers 分页签）。
- `api()` 统一处理信封与 `401`：任何非登录接口返回 401 就回到登录页，
  这样服务端删了会话（例如被禁用）时前端不会卡在假登录态。
- 安全性：所有插值都经过 `esc()` / `escAttr()`，避免把响应内容当 HTML 渲染。

### 交互约定（视觉参考 hoppscotch）

- **按方法配色**：`--method-get/post/put/patch/delete-color` 一组变量，树上的标签与 URL 旁的方法选择框同色，
  请求一眼可辨。新增一个方法只需加一个变量加一条 `.verb.m-XXX` 规则。
- **分页签而不是长滚动**：请求面板（Headers / Params / Body / Vars）与响应面板（Body / Headers）
  都用 `hidden` 属性切换，且**未选中的面板仍留在 DOM 里**：`save` / `send` 照旧收集全部字段，
  浏览器查找（Ctrl+F）也能命中；页签上的计数（`data-count`）用来提示隐藏面板里有内容。
- **键盘优先**：`Ctrl/Cmd+Enter` 发送、`Ctrl/Cmd+S` 保存（拦掉浏览器「保存网页」弹窗）、
  URL 框里回车即发送。发送中按钮禁用并显示 spinner，避免双击发出两个请求。
- **树可折叠**：集合与文件夹独立展开/折叠且默认全展开；折叠只加 `hidden` 类，节点仍在 DOM 中。
- **不用原生弹窗**：`alert` / `confirm` / `prompt` 一律换掉。结果是头部那串可堆叠、可关闭、8 秒自动消失的
  通知胶囊（`#flash` 是容器），确认与输入共用 `#dialog` 这一个表单（Enter 确认，Escape / 点遮罩 / Cancel 取消，
  破坏性操作用红色按钮，只读字段配 Copy）。好处不只是好看：原生弹窗阻塞页面、偷走焦点、无法排版，
  也无法被走查脚本断言。
- **复制要能降级**：`navigator.clipboard` 需要安全上下文（内网明文 HTTP 不满足）且文档要有焦点，
  两条路径都失败才提示 `copy failed`。
- **登录加密也要能降级**：`crypto.subtle` 同样只在安全上下文（HTTPS / localhost）存在，所以内网明文 HTTP 下
  `encryptPassword()` 会落到内嵌的 `loginenc.js`（纯 JS RSA-OAEP + SHA-256，随机数取 `crypto.getRandomValues`
  ——它不像 `subtle` 那样要求安全上下文，两者都没有才报“cannot encrypt the login request — use HTTPS”）。
  两条路径都产出同一个 `{username, enc}` 请求体，服务端不需要知道是哪条。
- **主题是浏览器偏好，不是服务端设置**：三套调色板写在 `app.css` 的 `html[data-theme="light"|"black"]` 里
  （`:root` 就是原来的 dark），头部 `#theme-select` 切换，选择存 `localStorage`（`postlite.theme`）——
  换主题不该影响别人，也不该需要写库。`applyTheme()` 在 app.js 解析时立即执行（脚本在 body 末尾、首帧之前），
  所以刷新不会先闪一下默认配色；`localStorage` 被禁用时回退到 dark，而不是白屏。
- **删除请求的按钮按角色渲染**：它出现在编辑器 URL 行，但只有 `state.user.role === 'admin'` 时才生成——
  `.admin-only` 那套是 `startApp()` 一次性给静态导航元素打 `display:none`，登录后才渲染出来的内容收不到，
  所以动态内容一律在渲染时判角色。确认走统一的页内弹窗（破坏性操作是红色按钮）。
- **响应式**：窄屏（< 820px）时侧栏变成横向条带、导航换行、树限高，避免小窗口出现横向滚动。

### 改 UI 时必须守住的锚点

`uitest.mjs` 与 `internal/web/web_test.go` 用真实浏览器与内嵌资源校验界面，动手前先看它们锁定了什么：

- `web_test.go`：`<title>PostLite</title>`、静态资源不得引用外部 URL、静态资源必须带 `ETag` 且条件请求回 `304`、
  `app.css` 必须保留 `[hidden] { display: none !important; }`、登录外壳与导航的 id 集合、
  主题选择器与两套非默认调色板必须同时存在、请求删除按钮必须在渲染时判 admin 角色。
- `uitest.mjs`：登录表单与 `#login-err`、`#who` 含用户名、`.admin-only` 在非 admin 下 `display:none`、`#req-gql`
  在 `body_type=graphql` 时才展开（走查还会用 `about:reload-probe` 这种哨兵值确认真的从服务端重载了）、
  `#content` 里的关键 id（`#new-*` / `#req-*` / `#btn-save` / `#btn-send` / `#send-status` / `#set-*`），
  以及一批**按文案精确匹配**的按钮（`Log out`、`Create`、`+ row`、`Save vars`、`Set active user`、
  `Store encrypted`、`View`、`Reset password`）——往这些按钮里塞快捷提示文字会让匹配失败。
- 提示与确认都走页内实现：`#flash` 是通知胶囊的容器（断言它的文本），`#dialog` 是确认/输入弹窗
  （断言 `#dialog-input` 的值、`#dialog-ok` / `#dialog-cancel`）；走查还会断言整轮里
  `window.__alerts` / `window.__prompts` 始终为空，也就是**没有任何地方退回原生弹窗**。
- 响应面板保持 `Response` 与状态码相邻（`/Response\s*200/`）并保留 `.result` 容器；
  历史列表保留 `<table><tr>` 结构，并把 URL 渲染成可见文本（测试查的是 `innerText`）。
- 新增的走查锚点：`#theme-select`（三套配色 + 刷新后仍记得）、`#btn-del-req`（admin 删除，走 `#dialog-ok` 确认）、
  `#set-proxy` 与 `#req-proxy`（代理设置校验、请求级开关存盘、代理不通时报错而不是悄悄直连）。
  注意 `THEME` 这一步会 `Page.reload()`，之后的断言必须先等会话恢复（`#app-view` 不再 hidden），
  否则登录页面里也存在的头部元素会让走查误以为已登录。

## 11. 项目结构

```
postlite/
├── cmd/postlite/
│   ├── main.go              # flag 解析、TLS、路由挂载、优雅退出
│   ├── helpers.go           # 首启建 admin、自签证书生成、panic 恢复
│   └── *_test.go            # 端到端 handler / 安全测试
├── cmd/pwreset/             # 运维命令：离线重置口令（直接改库，复用同一套哈希与审计）
├── internal/
│   ├── auth/                # password.go / session.go / middleware.go / ratelimit.go / loginenc.go
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
make build      # bin/postlite + bin/pwreset（后者是离线重置口令的运维命令）
make pwreset    # 只构建 bin/pwreset
make run        # HTTPS，:5680，数据目录 ./data
make run-plain  # http://127.0.0.1:5681（仅开发）
make vet        # go vet ./...
make test       # go test ./...
```

首启自动建库、生成 `master.key` 与自签证书，并创建 `admin` 账号，**一次性密码打印到 stderr**
（与启动日志同一输出流），必须登录后到 Users 里重置。

两个注意点：

- 端口约定：TLS 默认 `:5680`，本地明文调试用 `127.0.0.1:5681`（两个模式互相独立，可以同时起）。
- `-plain` 模式下 `SecureCookie=false`（明文 HTTP 下 `Secure` cookie 会被浏览器丢弃）。登录加密不受影响：
  非安全上下文没有 `crypto.subtle`，前端改用内嵌的 `loginenc.js`（见第 10 节）。
- `-data` 目录决定「身份」：换一个数据目录 = 换一套用户、密钥与历史。

## 13. 安全清单

- [x] 主密钥不落 SQLite，文件 0600，启动打印指纹便于核对
- [x] Secret 无读值接口；请求快照 / 响应 / history / 审计日志全链路脱敏
- [x] 登录限流（5 次 / 15 分钟）；会话 24h 硬过期；Cookie `HttpOnly` + `SameSite=Lax`（TLS 下 `Secure`）
- [x] 登录口令 RSA-OAEP 加密传输 + 一次性挑战防重放；服务端拒绝明文口令（明文 HTTP 走内嵌纯 JS 实现）
- [x] 删除请求仅 admin（前端按角色渲染按钮，服务端 `requireAdmin` 兜底），并写审计
- [x] 代理是 admin 显式配置的出口：直连仍受 SSRF 白名单约束，走代理时只校验协议与 host，重定向逐跳复核
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

**V0.2（进行中）**

已落地：主题切换（Light / Dark / Black）、请求删除（admin-only）、HTTP/HTTPS 代理（设置 + 请求级开关）、
GraphQL 请求类型（query + variables 面板）。

仍在计划内：WebSocket / SSE / Socket.IO / MQTT 请求类型、form-data / 文件上传、
请求前置后置脚本（JS 沙箱）、团队空间、导出 OpenAPI。
（这份清单来自仓库根的 `Task.md`，它不入库，所以实现进度以本节为准。）

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

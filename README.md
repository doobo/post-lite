# PostLite

内网环境的 Postman 替代品：单个 Go 二进制 + 内嵌 Web UI，不依赖任何外部服务、不加载 CDN，
所有出站请求由服务端代发，密钥**只写不读**。

- **单文件部署**：前端静态文件通过 `go:embed` 编进二进制，拷一个文件就能跑
- **零/极简依赖**：以 Go 标准库为主，直接依赖只有 `modernc.org/sqlite`（纯 Go、无 cgo）与
  `golang.org/x/crypto`（scrypt）；go.mod 中其余条目是 SQLite 驱动的传递依赖（标记为 `// indirect`）
- **密钥不落明文**：Secret 用 AES-256-GCM 加密入库，服务端不提供任何读取明文的接口
- **多用户 + RBAC**：`admin` / `user` 两种角色，资源按 owner 隔离

浏览器**不直接**访问目标 API（避免 CORS、避免暴露内网拓扑），执行统一走
`POST /api/execute`，由服务端代理发起，响应脱敏后返回。

---

## 快速开始

```bash
make build                 # 产出 bin/postlite（服务器）与 bin/pwreset（离线重置口令）
make run                   # HTTPS，:5680，数据目录 ./data
# 或本地调试用明文 HTTP（不要用于生产）
make run-plain             # http://127.0.0.1:5681
```

> Windows 上一般没有 `make`，等价命令、端口约定以及“为什么改完代码要先停服务”见
> [开发与测试 → Windows 本地开发](#windows-本地开发)。

首启会自动建库、生成 `master.key` 与自签证书，并创建 `admin` 账号，
**一次性密码打印到 stderr**（与启动日志同一输出流）：

```
first start: created admin user (id=1) with one-time password: abcdEFGH2345mnopX
change it after first login (Users -> reset-password).
```

浏览器打开 `https://<host>:5680`（自签证书需手动信任），用 `admin` + 上面的一次性密码登录，
然后到 Users 里重置密码。构建需要 Go 1.27（见 `go.mod`）。

### 忘记口令：离线重置

内置一个运维命令，直接改数据目录里的库（口令是 scrypt 单向哈希，没有“找回”，只能重设）：

```bash
./bin/pwreset -data ./data -list                      # 看这个数据目录里有哪些用户
./bin/pwreset -data ./data -user admin                # 随机生成新口令并打印一次
./bin/pwreset -data ./data -user admin -password 'xxx'  # 也可指定（注意会进 shell 历史）
```

没编译过就用 `go run ./cmd/pwreset …`（`make build` 会同时产出 `bin/postlite` 与 `bin/pwreset`）。
行为与 `POST /api/users/{id}/reset-password` 一致：同一套 scrypt 参数，同一套审计记录（署名 `cli`，写进 `settings.audit_log`）；
服务在跑也能用（WAL 支持并发写，服务端每次登录都重读用户表），但**不会吊销已有会话**，
重置后请把该用户已登录的地方登出。

### 启动参数

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `-addr` | `:5680` | 监听地址 |
| `-data` | `./data` | 数据目录（SQLite、master.key、证书） |
| `-cert` / `-key` | 空 | TLS 证书；留空则自动在数据目录生成自签证书（ECDSA P-256） |
| `-plain` | `false` | 以明文 HTTP 运行（仅限开发） |
| `-timeout` | `60s` | 默认执行超时 |
| `-max-history` | `1000` | history 保留条数 |
| `-master-key` | 空 | Vault 主密钥（32B 的 hex 或 base64），优先级最高 |
| `-master-key-file` | `data/master.key` | 主密钥文件，不存在则自动生成（0600） |

主密钥来源优先级：`-master-key` > 环境变量 `POSTLITE_MASTER_KEY` > `-master-key-file`。
启动时日志会打印 `key_fingerprint`（sha256 前 4 字节）便于核对，主密钥**永不写入 SQLite**。

---

## 功能概览

- **Collections / Folders / Requests**：集合支持嵌套文件夹（`parent_id`），请求方法仅允许 `GET/POST/PUT/PATCH/DELETE`（服务端校验），支持 Headers、Query、Body（UI 提供 `none` / `json` / `raw` / `graphql`）
- **GraphQL**：Body 类型选 `graphql` 后，上面写 query、下面写 variables（JSON 对象，可空）；发送时服务端拼成 `{"query":…,"variables":…}` 以 `application/json` POST，`{{VAR}}` / `{{sec.NAME}}` 在 query 与 variables 里都会解析；variables 不是合法 JSON 时直接 `400`，不会带着畸形 body 出去
- **Environments**：`global`（admin 创建/管理）与 `user` 两种作用域；激活状态存在服务端 settings（`active_global_env`、`active_env_user_<uid>`），因此是按用户持久生效的
- **Secret Vault**：只写不读，覆盖更新，命中才解密（进程内缓存 5 分钟，写入即失效）
- **变量**：`{{VAR}}` 占位符在 URL / Headers / Query / Body 统一解析（正则 `\{\{([\w.]+)\}\}`）
- **执行**：服务端代发，默认不跟随重定向（可请求级开启，最多 5 跳），响应体截断 10MB，history 仅存脱敏后 1MB
- **代理**：管理员在 Settings 里配一个 `http://` 或 `https://` 代理（空 = 直连）；**每个请求自己决定**是否走代理（编辑器里的 `use proxy`，默认关闭，存在请求上）
- **主题**：Light（灰白）/ Dark / Black 三套配色，头部下拉切换，选择记在浏览器 `localStorage`（不是服务端设置，不影响别人）
- **请求删除**：已保存的请求可在编辑器里删除，**仅 admin 可用**（普通用户看不到按钮，直接调接口也会 `403`）
- **History**：脱敏快照（请求 + 响应），查询/删除按用户隔离，自动按条数上限清理（上限是**全库总量**，不是每人一份）
- **导入 / 导出**：集合可导出为 `format: "postlite/v1"` 的 JSON 附件（直接下载原始 JSON，不套 ok 信封），再用 `POST /api/collections/import`（`{json, global}`）导入；`global: true` 仅 admin 可用
- **Web UI**（`internal/web/static`，无构建步骤）：登录页 + 可折叠 Collections 树 + 请求编辑器（Headers / Params / Body / Vars 分页签）+ Environments / History / Secrets / Users / Settings（后三者为 admin 可见）；交互参考 hoppscotch：按 HTTP 方法配色、三套主题切换、`Ctrl/Cmd+Enter` 发送、`Ctrl/Cmd+S` 保存、响应面板 Body / Headers 分页与一键复制；
  提示与确认全部在页内完成（可堆叠的通知胶囊 + 统一弹窗），**不使用浏览器原生 `alert` / `confirm` / `prompt`**

### 变量解析优先级

1. 请求级临时变量（执行时由 UI 传入）
2. 已激活的 user Environment
3. 已激活的 global Environment
4. `secrets` 表（占位符写作 `{{sec.NAME}}`，命中才解密）

未命中的占位符会原样保留并出现在执行结果的 `warnings` 中（去重后按名排序）；若 URL 解析后仍含 `{{`，
执行直接返回 `400 unresolved_variable`。

### RBAC

| 能力 | admin | user |
| --- | --- | --- |
| 用户增删 / 禁用 / 重置密码 | ✅ | ❌ |
| 列出 / 写入 / 删除 Secret | ✅ | ❌ |
| 创建与管理全局 Environment、全局 Collection | ✅ | ❌ |
| 查看全局 Collection / Environment | ✅ | ✅ |
| 管理自己的 Collection、Folder、Request、Environment | ✅ | ✅ |
| 删除已保存的请求 | ✅ | ❌ |
| 执行可见 Collection 中的全局请求 | ✅ | ✅ |
| 执行自己的请求、引用 `{{sec.NAME}}` 注入密钥 | ✅ | ✅（但看不到 Secret 名字与值） |
| 查看 / 删除自己的 History | ✅ | ✅ |

### 管理员设置项

通过 `PUT /api/settings` 修改（写入前统一校验，避免半应用）：

- `ssrf_whitelist`：CIDR 列表，逗号分隔，默认 `10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8`
- `exec_timeout`：如 `60s` / `2m` 或纯秒数，覆盖 `-timeout`
- `max_history`：正整数，覆盖 `-max-history`
- `proxy_url`：`http://host:port` 或 `https://host:port`（可带 `user:pass@`），**空字符串 = 直连**；`socks5://` 暂不支持，非 http(s) 会被 `400` 拒绝。
  请求只有在自己的 `use_proxy` 打开时才走它，且此时 **SSRF 白名单不再过滤目标地址**（目标由代理解析和访问），
  详见「安全设计」

---

## REST API

除集合导出（直接返回原始 JSON 附件）外，所有接口返回统一信封：
`{"ok":true,"data":...}` 或 `{"ok":false,"error":{"code","message"}}`。
鉴权失败 `401`、越权 `403`、SSRF 拦截 `451`（并写审计日志）。

```
Auth          GET  /api/auth/login-key        POST /api/auth/login         POST /api/auth/logout
              GET  /api/auth/me
Users(admin)  GET/POST /api/users             DELETE /api/users/{id}
              POST /api/users/{id}/disable    POST /api/users/{id}/enable
              POST /api/users/{id}/reset-password
Collections   GET/POST /api/collections       GET/PUT/DELETE /api/collections/{id}
              POST /api/collections/{id}/export   POST /api/collections/import
              GET/POST /api/collections/{id}/folders
Requests      GET/POST /api/requests          GET/PUT /api/requests/{id}
              DELETE /api/requests/{id}       # 仅 admin，普通用户 403
Environments  GET/POST /api/environments      GET/PUT/DELETE /api/environments/{id}
              POST /api/environments/activate
Secrets       POST /api/secrets               PUT /api/secrets/{name}
(admin)       GET  /api/secrets               DELETE /api/secrets/{id}      # GET 仅返回 id + name + updated_at
Execute       POST /api/execute               # { request_id | ad_hoc{..., use_proxy}, vars, active_env,
                                              #   follow_redirects }；响应带 proxied 布尔值
History       GET /api/history?request_id=&limit=   GET /api/history/{id}   DELETE /api/history/{id}
Settings      GET/PUT /api/settings           # 含 proxy_url（空 = 直连）
```

请求体上限 4MB；登录接口按 IP 限流（失败 5 次锁定 15 分钟）。

登录口令不走明文：`GET /api/auth/login-key` 下发临时 RSA 公钥（SPKI，另附 `n` / `e`）与一次性挑战，
前端用 RSA-OAEP/SHA-256 加密 `{"c":挑战,"p":口令}`，以 `{username, enc}` 提交；挑战用后即焚，
重放与篡改都会得到 `400 bad_login_payload`。**明文 `password` 字段不再被接受**（`400 encryption_required`），
所以 curl / 脚本走登录也要先拿公钥加密。

---

## 安全设计

- **Master Key**：32B 随机数，来源见上文，**不写入数据库**，文件权限 0600
- **加密**：AES-256-GCM，每次写入生成 12B 随机 nonce，存储 `nonce(12) || ciphertext || tag(16)`
  （Go 的 `AEAD.Seal` 把认证标签追加在密文之后）
- **只写不读**：`POST /api/secrets` 只回 `id` 与 `name`（值不参与响应），无读取明文的接口；
  值只在执行引擎内存中出现，出站请求快照 / 响应 / history / 审计日志全部脱敏为 `***`
- **Secret 命名**：须匹配 `^[a-zA-Z][a-zA-Z0-9._-]*$`；重名返回 `409`，改用 `PUT /api/secrets/{name}` 覆盖
- **登录传输加密**：临时 RSA-2048（进程内生成，重启即换）+ 一次性挑战，RSA-OAEP/SHA-256 加密口令；
  前端优先用 WebCrypto，**非安全上下文**（明文 HTTP 下 `crypto.subtle` 不存在）自动回退到随二进制内嵌的
  `loginenc.js`（纯 JS RSA-OAEP，无 CDN、无构建步骤）
- **会话**：32B 随机 token，服务端只存 `sha256(token)`，24h 硬过期无滑动续期；
  Cookie `HttpOnly; SameSite=Lax`（TLS 下附加 `Secure`）
- **SSRF 防护**：执行前 DNS 解析，所有 A/AAAA 结果都必须落在白名单 CIDR 内；
  跟随重定向时每一跳重新校验
- **代理与 SSRF 的边界**：直连请求一律过白名单；**走了代理的请求不再检查目标地址**（代理自己解析并访问，
  本地 DNS 查不到的内网/外部主机正是代理存在的意义），但仍强制 `http/https` + 必须带 host，重定向每一跳同样检查；
  代理地址本身是 admin 在 Settings 里显式声明的出口，请把它指向你信任的主机。未配置代理时勾选 `use proxy`
  会直接报 `400 proxy_not_configured`，**不会静默改回直连**
- **越权防护**：repository 层统一按 `owner_id` 过滤（`CanView` / `CanManage` / `CanUseRequest`）
- **审计**：用户、Secret、设置、全局 Collection/Environment、SSRF 拦截等操作写审计日志
  （stderr + `settings` 表的 `audit_log`，最多保留 500 条）

---

## 项目结构

```
postlite/
├── cmd/postlite/
│   ├── main.go              # flag 解析、TLS、路由挂载、优雅退出
│   ├── helpers.go           # 首启建 admin、自签证书生成、panic 恢复
│   └── *_test.go            # 端到端 handler / 安全测试
├── cmd/pwreset/            # 运维命令：忘记口令时离线重置（直接改库，复用同一套哈希与审计）
├── internal/
│   ├── auth/                # scrypt 口令、会话、限流、鉴权中间件、登录加密握手（loginenc.go）
│   ├── config/              # 运行配置
│   ├── crypto/              # Secret Vault（Seal/Open、主密钥加载、缓存）
│   ├── db/                  # SQLite 打开（WAL）+ 版本化迁移
│   ├── models/              # 表结构体
│   ├── repository/          # 各实体 repo，统一 owner 过滤
│   ├── httpapi/             # REST handler（server/execute/settings/...）
│   ├── executor/            # 出站执行、SSRF 校验、变量解析、脱敏
│   └── web/static/          # 内嵌前端（index.html / app.js / app.css / loginenc.js）
│                            #   loginenc.js：明文 HTTP（无 crypto.subtle）时的纯 JS RSA-OAEP 回退
├── docs/DESIGN.md          # 设计说明（为什么这么设计）
├── go.mod
└── Makefile
```

## 开发与测试

```bash
make vet        # go vet ./...
make test       # go test ./...
make build
```

测试覆盖鉴权/限流、Vault 加解密、SSRF 策略、变量解析与脱敏、迁移与 repository 权限过滤。

前端是普通静态文件（`internal/web/static`），**没有构建步骤**，改完重新 `go build` 即可内嵌生效。
内嵌资源带 `ETag` + `Cache-Control: no-cache`，每次加载都会回源校验（没变就是 `304`），
所以升级二进制后**普通刷新**就能拿到新版界面，不需要硬刷新清缓存。

仓库根目录还有两个本地联调脚本：`uitest.mjs` 用 Chrome DevTools Protocol 驱动真实 SPA 做端到端走查
（`ADMIN_PW=... BASE_URL=http://127.0.0.1:5681 node uitest.mjs`），`uidiag.mjs` 用于界面诊断。
二者都是临时调试工具，不是 CI 的一部分。

### Windows 本地开发

Git Bash / PowerShell 里一般**没有 `make`**，直接用等价的 go 命令，另外有三个 Windows 特有的坑：

```bash
go vet ./... && go test ./...
go build -ldflags="-s -w" -o bin/postlite ./cmd/postlite
go build -ldflags="-s -w" -o bin/pwreset ./cmd/pwreset          # 忘了口令时用（可选）
./bin/postlite -plain -addr 127.0.0.1:5681 -data ./dev-data     # 本地明文调试
```

- **端口约定**：TLS 默认 `:5680`，本地明文调试固定用 `127.0.0.1:5681`（就是 `make run` / `make run-plain`
  这两个端口，两者互不冲突，可以同时起）。`-data` 指向哪个目录就等于用哪一套用户、密钥与历史，
  调试建议单独用 `./dev-data`，不要和 `./data` 混用。
- **改完代码要先停服务再 build**：Windows 会锁住正在运行的 exe。实测在服务运行时执行
  `go build -o bin/postlite …` 虽然返回成功，却会把旧二进制挪成 `bin/postlite~`（要手动删），
  有时还会直接失败（`Access is denied`，或者下次启动时报 `Permission denied`）。
  **前端是内嵌进二进制的**，所以改完 `internal/web/static` 也必须重新 build 并重启才生效。
- **后台起服务**：`nohup ./bin/postlite … > dev-server.log 2>&1 & disown`，日志看 `dev-server.log`；
  停服务先查 PID 再 kill，注意 Git Bash 里 `taskkill` 的开关要写双斜杠，否则会被当成路径转换：

  ```bash
  netstat -ano | grep 127.0.0.1:5681      # 最后一列是 PID
  taskkill //F //PID <pid>                # //F，不能写成 /F
  ```

- 仓库根 `.gitattributes` 已固定 LF，所以即使本机 `core.autocrlf=true`，克隆下来的 `Makefile` 也不会被换成 CRLF。

`uitest.mjs` 是针对**空库**写的走查（它会自己建集合、用户、密钥），所以要另起一套全新数据目录的实例，
密码取首次启动日志里的一次性密码；浏览器侧需要带调试端口的 Chrome：

```bash
./bin/postlite -plain -addr 127.0.0.1:5681 -data ./dev-ui-data > dev-ui.log 2>&1 &
grep -oE 'one-time password: [A-Za-z0-9]+' dev-ui.log
"/c/Program Files/Google/Chrome/Application/chrome.exe" --remote-debugging-port=9222 --user-data-dir=.cdp-profile &
ADMIN_PW=<上面的一次性密码> BASE_URL=http://127.0.0.1:5681 node uitest.mjs
```

> 命名约定：产品名与 Web UI 标题是 `PostLite`，Go 模块名与二进制名是 `postlite`
> （Go 标识符不能带连字符），两者指同一个程序。

## 路线图（V0.2）

WebSocket 代理、form-data / 文件上传、SSE 流式响应、请求前置后置脚本（JS 沙箱）、
团队空间、导出 OpenAPI。各模块的设计取舍与实现细节见 [`docs/DESIGN.md`](docs/DESIGN.md)。

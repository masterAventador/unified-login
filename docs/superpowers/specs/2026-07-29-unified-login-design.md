# 统一登录体系设计文档

- 日期：2026-07-29
- 状态：待评审
- 适用范围：作者名下全部个人产品（Web、桌面、未来移动端）

## 1. 背景与目标

作者名下有多个独立产品（现有 agent-platform、automation-tool、common-agent 等，后续还会新增），当前各产品各有一套登录实现，账号互不相通。本项目建设一套独立的统一认证中心，达成三个目标：

1. **一套账号走遍所有产品**：用户注册一次，可登录名下任意产品。
2. **真正的单点登录**：在任一产品登录后，打开其他产品无需再次输入密码。
3. **新产品接入成本趋近于零**：接入一个新产品 = 加一段配置 + 装一个套件，不需要再写一遍登录逻辑。

**非目标**：本项目不承担任何产品的业务权限管理。认证中心只回答"你是谁"，不回答"你能干什么"。

## 2. 一期范围

### 2.1 交付内容

| 类别 | 交付物 |
| --- | --- |
| 认证中心 | 注册、登录、登出、跨产品免登、修改密码、管理 API |
| 管理后台 | 用户列表与搜索、禁用/启用账号、重置密码 |
| 接入套件 | Web 前端 TS 包、Python FastAPI 验签依赖、Tauri 桌面端套件 |
| demo 接入方 | demo-web-a、demo-web-b、demo-api、demo-desktop |
| 测试 | 单元、集成、协议一致性、Playwright 端到端 |

### 2.2 明确不做

| 不做的事 | 原因 |
| --- | --- |
| 邮件发送与邮箱真实性验证 | 需求明确不做。数据库预留 `email_verified` 字段，接真实发信时不需要改表 |
| 用户自助"忘记密码" | 不发邮件在技术上无法做自助重置。只能由管理员在后台重置 |
| 个人资料（昵称、头像） | 一期不做。各产品若需要显示名，暂用邮箱 |
| 会话设备列表与远程踢下线 | 一期不做 |
| 第三方登录（GitHub / Google 等） | 一期不做。架构上是加一个 identity provider，不影响现有设计 |
| 移动端代码 | 一期不写。认证中心侧无需为移动端做任何改动，未来只是配置里多一个 client |

## 3. 技术选型

| 项 | 选型 | 版本 | 说明 |
| --- | --- | --- | --- |
| 语言 | Java | 17 LTS | Spring Boot 4.1 的最低要求版本，且为开发机既有环境；本项目不需要更高版本的语言特性 |
| 应用框架 | Spring Boot | 4.1.0 | |
| 授权服务器 | Spring Authorization Server | 7.1.0 | 提供完整 OIDC 协议端点 |
| 数据库 | PostgreSQL | 16+ | |
| 数据库迁移 | Flyway | 随 Spring Boot 版本 | |
| 密码哈希 | Argon2id | Spring Security 内置 | 参数见 §6.2 |
| 登录页渲染 | Thymeleaf | 随 Spring Boot 版本 | 服务端渲染，不做 SPA |
| 管理后台前端 | Vite + TypeScript | — | 与作者现有前端栈一致 |
| 测试 | JUnit 5、Mockito、Testcontainers、Playwright | — | |

**关于语言异构的记录**：作者现有个人项目后端均为 Python FastAPI。选择 Java 使认证中心成为唯一的 JVM 服务，需额外维护一条构建与部署链。此代价在知情后由作者确认接受。因协议层为标准 OIDC，接入方语言不受影响——产品后端只需用公钥验签 JWT。

**关于与全局 Java 后端规范的偏离**：全局规则 `~/.claude/rules/java-backend.md` 的默认选型为 Java 21 + Spring Boot 3.x + MySQL + Redis。本项目的偏离项与理由如下，依据该规则「写明理由即可偏离」条款：

| 偏离项 | 本项目取值 | 理由 |
| --- | --- | --- |
| Spring Boot 3.x → 4.1 | 4.1.0 | Spring Authorization Server 自 7.0 起并入 Spring Security 7，只能配 Spring Boot 4.x。要用官方授权服务器就没有第二种选择 |
| Java 21 → 17 | 17 | 开发机既有 JDK；升级并切换 `JAVA_HOME` 会波及机器上其他 Java 项目，而本项目用不到 21 相对 17 的任何特性 |
| MySQL → PostgreSQL | PostgreSQL 16 | 由作者在选型阶段确认 |
| Redis | 不引入 | 认证中心无缓存与分布式会话需求。一期为单实例部署，登录限流计数保存在应用内存中 |

## 4. 架构

### 4.1 组件划分

```
接入端（各产品）
  ├── Web 产品前端      Vite + TS SPA，授权码 + PKCE
  ├── 桌面端            Tauri 2.11，系统浏览器 + 本地回环回调
  ├── 移动端            未来，同一套协议
  └── 管理后台          Vite + TS SPA，自身也是一个 client
                              │
                              ▼
认证中心  auth.<主域名>   Spring Boot 单体应用
  ├── 页面层            Thymeleaf：登录页、注册页、修改密码页
  ├── OIDC 协议端点     框架提供：authorize / token / jwks / userinfo / logout
  ├── 用户与凭证域      自研：邮箱唯一性、Argon2id 哈希、账号状态
  └── 管理 API          自研：用户列表、禁用启用、重置密码
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
        PostgreSQL                    各产品后端（Python FastAPI）
        app_user + 框架三张表          拉 JWKS 缓存，本地验签，不回调
```

### 4.2 认证中心内部分层

认证中心是单体应用，按领域分包，每个包对外只暴露一个服务接口：

| 包 | 职责 | 对外接口 |
| --- | --- | --- |
| `user` | 用户实体、仓储、邮箱规范化、状态流转 | `UserService` |
| `registration` | 注册用例：校验、查重、建号 | `RegistrationService` |
| `password` | 密码哈希、强度校验、改密与重置 | `PasswordService` |
| `admin` | 管理用例：查询、禁用、重置 | `AdminUserService` |
| `config` | Security 过滤链、授权服务器配置、client 同步 | 无（配置类） |
| `web` | Thymeleaf 控制器与表单对象 | 无（入口层） |

依赖方向单向：`web` / `admin` → `registration` / `password` → `user`。`user` 不依赖任何上层包。

### 4.3 建议目录结构

```
unified-login/
├── auth-server/                  # Spring Boot 应用
│   ├── src/main/java/com/aventador/unifiedlogin/
│   │   ├── config/  user/  registration/  password/  admin/  web/
│   ├── src/main/resources/
│   │   ├── db/migration/         # Flyway 脚本
│   │   ├── templates/            # Thymeleaf 模板
│   │   └── application.yml
│   └── src/test/java/            # 与源码同包路径
├── admin-ui/                     # 管理后台 SPA
├── sdk/
│   ├── web-ts/                   # 浏览器接入套件
│   ├── python-fastapi/           # Python 验签依赖
│   └── tauri/                    # Rust + TS 桌面端套件
├── demo/
│   ├── demo-web-a/  demo-web-b/  demo-api/  demo-desktop/
├── e2e/                          # Playwright 用例
└── docs/
```

Java 包名为 `com.aventador.unifiedlogin`。

**本项目不采用 `business_packages/` + `foundation_packages/` 双层多模块结构**，而使用单 Maven 模块 + 按职责分包。依据全局规则 `~/.claude/rules/java-backend.md` 的「单一职责基础设施服务可用单模块」例外条款，理由：

- 认证中心只有一个业务领域（用户身份），且该领域不会随业务增长分裂——所有产品的业务权限都由各产品自管，认证中心永远只回答「你是谁」；
- 基础层 8 个包中，本项目只用得到错误码与 Web 响应封装两项，对象存储、缓存、WebSocket 等一概不需要，套用双层结构会产出 6 个以上空壳模块；
- 对外只提供 HTTP 一种协议入口。

采用例外的前提条件在本项目中的落实：包按职责划分（`user` / `password` / `registration` / `admin` / `config` / `web` / `security`），依赖方向严格单向，领域包不反向依赖 Web 层与配置层。若本服务将来长出第二个业务领域，需重新评估是否升级为双层结构。

## 5. 数据模型

### 5.1 app_user（唯一需要自行设计的表）

| 字段 | 类型 | 约束 | 说明 |
| --- | --- | --- | --- |
| `id` | UUID | 主键 | 全局用户 ID，即 JWT 的 `sub`。生成后永不变更 |
| `email` | varchar(320) | 唯一索引 | 存储前统一转小写并去除首尾空白 |
| `password_hash` | varchar(255) | 非空 | Argon2id 输出，含算法参数与盐 |
| `status` | varchar(16) | 非空，默认 `ACTIVE` | `ACTIVE` / `DISABLED` |
| `email_verified` | boolean | 非空，默认 `true` | 预留位。当前注册即写 true |
| `is_platform_admin` | boolean | 非空，默认 `false` | 管理后台准入标记 |
| `password_changed_at` | timestamptz | 非空 | 早于此时间签发的 refresh token 一律失效 |
| `created_at` | timestamptz | 非空 | |
| `updated_at` | timestamptz | 非空 | |

**邮箱唯一性实现**：`email` 列本身存小写值，并建普通唯一索引。写入前在应用层规范化（trim + toLowerCase）。不使用 citext 扩展，避免部署时的扩展依赖。

**索引**：`email` 唯一索引；`status` 普通索引（管理后台按状态筛选用）。

### 5.2 框架自带表

由 Spring Authorization Server 定义，直接采用官方 schema，不做修改：

- `oauth2_registered_client`：各产品的 client 注册信息
- `oauth2_authorization`：授权码与已签发 token 记录，token 撤销依赖此表
- `oauth2_authorization_consent`：授权同意记录（自家产品全部配置为跳过同意页）

### 5.3 管理员初始化

配置项 `unified-login.bootstrap.admin-emails` 为邮箱列表。应用启动时，将列表中已存在的用户的 `is_platform_admin` 置为 `true`。该操作幂等，不创建用户——管理员必须先自行注册。配置中移除某邮箱不会自动撤销其管理员标记，撤销需在管理后台操作或直接改库。

## 6. 认证与凭证策略

### 6.1 OIDC 配置

- 授权类型：仅 `authorization_code` 与 `refresh_token`。不启用 implicit、password、client_credentials。
- 所有 client 均为 public client（无 client_secret），**强制 PKCE**（S256）。
- 所有 client 配置为跳过授权同意页（自家产品无需用户确认授权）。
- 签名算法：RS256，密钥对在部署时生成并持久化（不可每次启动随机生成，否则重启后所有 token 失效）。

### 6.2 密码策略

- 强度规则：长度 8–64 字符，不限制字符类型（遵循 NIST SP 800-63B 现行建议：强制字符类型组合反而诱导出可预测的弱密码）。
- 哈希算法：Argon2id，参数 `memory=19456 KiB, iterations=2, parallelism=1, saltLength=16, hashLength=32`（OWASP 现行推荐值）。
- 密码只在传输中出现一次，绝不记录进任何日志。

### 6.3 Token 与会话寿命

| 凭证 | 寿命 | 说明 |
| --- | --- | --- |
| Access Token（JWT） | 15 分钟 | 各产品后端本地验签使用。因无法单独撤销，故意做短 |
| Refresh Token | 30 天 | 一次性使用 + 轮转 |
| ID Token | 15 分钟（跟随 access token） | 仅用于登录完成时确认用户身份，禁止用于调用接口 |
| 认证中心会话 Cookie | 14 天，滑动续期 | 仅种在 `auth` 子域。它有效即免登生效 |

**Refresh token 轮转规则**：每次刷新作废旧 token 并签发新 token。同一个 refresh token 被使用第二次，判定为凭证泄漏，立即撤销该用户全部有效 token，强制重新登录。

**关于 ID Token 寿命的框架约束**：Spring Authorization Server 的 `TokenSettings` 不提供 ID token 存活时间的配置项（只能配签名算法），ID token 的过期时间由 `accessTokenTimeToLive` 决定。因此它必然是 15 分钟，无法单独缩短。这在安全上可接受：ID token 只在登录完成的那一次交互中被前端读取一次，之后即被丢弃，实际暴露窗口远小于名义寿命；且它不被任何接口接受为凭证。

**会话 Cookie 属性**：`HttpOnly`、`Secure`、`SameSite=Lax`、`Domain` 不设置（即仅 `auth` 子域自身可用）。

### 6.4 Access Token 载荷

| Claim | 内容 |
| --- | --- |
| `sub` | `app_user.id`（UUID） |
| `email` | 用户邮箱 |
| `iss` | 认证中心 issuer URL |
| `aud` | 目标 client_id |
| `exp` / `iat` | 时间戳 |

**不包含任何角色或权限信息**。产品自行用 `sub` 关联本地业务权限。

## 7. 认证流程

### 7.1 Web 首次登录

1. 前端生成随机 `code_verifier`（存 sessionStorage）与 `code_challenge`（S256）。
2. 整页跳转 `<issuer>/oauth2/authorize`，携带 `client_id`、`redirect_uri`、`code_challenge`、`state`、`scope=openid`。
3. 认证中心无有效会话 → 渲染登录页。
4. 用户提交邮箱密码 → 规范化邮箱 → 查用户 → Argon2id 校验 → 检查 `status=ACTIVE` → 种下会话 Cookie。
5. 302 回跳 `redirect_uri?code=<一次性码>&state=<原值>`。
6. 前端校验 `state` 一致后，用 `code` + `code_verifier` 换取三个 token。
7. **全部 token 只保存在内存变量中，不写 localStorage、sessionStorage 或 Cookie**。

### 7.2 跨产品免登（SSO）

产品 B 重复 7.1 的第 1–2 步（携带 B 自己的 `client_id`）。第 3 步时认证中心检测到会话 Cookie 有效，**不渲染登录页**，直接执行第 5 步回跳。用户可感知的只有一次地址栏跳转。

### 7.3 页面刷新后的静默续签

1. 页面刷新导致内存中的 token 丢失。
2. 前端在隐藏 iframe 中请求 `<issuer>/oauth2/authorize?prompt=none&...`。
3. 会话有效 → 直接回跳带 code；会话已过期 → **返回错误而非渲染登录页**（`prompt=none` 的语义保证）。
4. 前端收到 code 则换取 token 继续；收到错误则跳转登录页。

**该机制的前置约束**：静默续签依赖 iframe 中的请求能携带认证中心的会话 Cookie。这要求产品域与认证中心域属于同一 registrable domain（如 `a.example.com` 与 `auth.example.com`），此时浏览器视为 same-site，`SameSite=Lax` 的 Cookie 正常发送。**若未来某产品部署在完全不同的主域名下，静默续签将失效**，届时该产品需改用跳转式续签（整页跳 authorize 再跳回）。此约束必须在接入文档中写明。

### 7.4 桌面端（Tauri）登录

1. Rust 侧在 `127.0.0.1` 启动临时 HTTP 服务，端口由系统随机分配，仅用于接收本次回调。
2. 用**系统默认浏览器**打开 `<issuer>/oauth2/authorize?redirect_uri=http://127.0.0.1:<port>/callback&...`。
3. 若系统浏览器中已有认证中心会话（例如用户此前登录过任一 Web 产品），直接回跳，无需输入密码；否则渲染登录页。
4. 浏览器回跳至本地回调地址，页面显示"登录成功，可关闭此页"。
5. Rust 侧校验 `state` 与预期一致 → 用 code + verifier 换 token → **立即关闭临时服务**。
6. Refresh token 写入操作系统凭据库（macOS 钥匙串 / Windows 凭据管理器 / Linux Secret Service）；access token 仅存内存。
7. 应用下次启动时从凭据库取回 refresh token 直接换 access token，30 天内无需重新登录。

**明确禁止**：不得在应用内嵌 WebView 中渲染登录页。WebView 拥有独立 Cookie 存储，会使全端 SSO 失效，且用户无法确认自己在向谁输入密码。

### 7.5 登出

产品内的"退出登录"只清除本产品持有的 token，**不结束认证中心会话**。用户在同一浏览器内重新点击登录会立即免登回来，这是 SSO 体系的预期行为。

框架提供的 `/connect/logout` 端点客观存在且可结束认证中心会话，但一期不在任何产品中暴露入口。若后续需要全局登出，直接引导用户至该端点即可，无需改造认证中心。

### 7.6 修改密码

登录态下，用户在认证中心页面提交旧密码与新密码。校验旧密码通过后：更新 `password_hash`、更新 `password_changed_at`、**撤销该用户全部已签发的 refresh token**。其他设备上的 access token 最长 15 分钟后自然失效。

## 8. 接入套件

### 8.1 Web 前端 TS 包（`sdk/web-ts`）

对外暴露：`login()`、`logout()`、`getAccessToken()`、`onAuthStateChange()`。内部封装 PKCE 生成与校验、`state` 校验、授权码换取、内存 token 管理、过期前自动刷新、`prompt=none` 静默续签。

`getAccessToken()` 在 token 即将过期时自动刷新后返回，调用方无需感知刷新时机。

### 8.2 Python FastAPI 验签依赖（`sdk/python-fastapi`）

对外暴露一个 FastAPI 依赖项，注入后得到当前用户的 `sub` 与 `email`。内部封装：启动时拉取 JWKS 并缓存、按 `kid` 选择公钥、验签、校验 `iss` / `aud` / `exp`、密钥轮换时自动重新拉取。

**不回调认证中心**，因此认证中心不可用时不影响已登录用户访问各产品业务接口。

### 8.3 Tauri 桌面端套件（`sdk/tauri`）

Rust 侧：临时回环服务、`state` 校验、token 换取、系统凭据库读写。TS 侧：调用 Rust 命令的薄封装，接口与 Web 包保持一致，便于同构前端代码复用。

## 9. 管理后台

独立 SPA，自身作为一个 OIDC client 登录，登录流程与普通产品完全一致。后端管理 API 校验两件事：token 有效，且 `sub` 对应用户的 `is_platform_admin` 为 `true`。

功能：用户列表（分页、按邮箱搜索、按状态筛选）、禁用/启用账号、重置密码（管理员直接设新密码，同时撤销该用户全部 refresh token）。

## 10. 安全设计与失败路径

| 情况 | 处理 |
| --- | --- |
| 邮箱已注册 | 注册页提示"该邮箱已被注册"，不透露账号是否活跃 |
| 密码错误 / 账号不存在 | 返回**完全相同**的提示文案。实现要求：邮箱不存在时也必须执行一次等价的 Argon2id 运算再返回失败，否则响应时间差异同样会泄漏账号是否存在 |
| 连续登录失败 | 同一邮箱连续失败 5 次锁定 15 分钟；同一 IP 每分钟登录尝试上限 20 次。**对不存在的邮箱同样计数并锁定**——否则「是否会被锁定」本身就泄漏了账号是否存在。计数状态保存在应用内存中（一期为单实例部署）；未来多实例部署时需迁移至共享存储，此约束需在部署文档中注明 |
| 账号已禁用 | 登录直接拒绝；持有的 refresh token 也无法换取新 token |
| Refresh token 重放 | 判定泄漏，撤销该用户全部 token |
| 回调地址不在白名单 | 直接报错，**绝不执行回跳**（防开放重定向） |
| 改密后的旧 token | 早于 `password_changed_at` 签发的 refresh token 全部失效 |
| 静默续签时会话已过期 | `prompt=none` 返回错误，前端据此跳转登录页 |
| 桌面端回调 `state` 不符 | 丢弃该 code，不换取 token，提示重新登录 |
| 认证中心不可用 | 已登录用户访问业务接口不受影响；新登录与 token 续期受阻 |

**已知并接受的取舍**：access token 为 15 分钟自包含 JWT，故管理后台禁用某用户后，该用户最长仍可访问业务接口 15 分钟。消除此延迟的唯一方式是让产品后端每次请求回调认证中心查状态，代价是丧失本地验签的可用性优势（认证中心故障将导致全线不可用）。当前产品量级下接受该延迟。

## 11. 测试策略

遵循 TDD：所有含业务逻辑的代码先写失败测试，运行确认失败，再写最小实现。

| 层级 | 工具 | 覆盖内容 |
| --- | --- | --- |
| 单元 | JUnit 5 + Mockito | 邮箱规范化与格式校验、密码强度规则、Argon2id 哈希与验证、账号状态流转 |
| 集成 | `@SpringBootTest` + Testcontainers（真实 PostgreSQL） | 注册接口、登录表单提交、改密、管理 API、完整 authorize→token 换取 |
| 协议一致性 | MockMvc | JWKS 公钥可验开签发的 token、discovery 文档字段完整、**refresh token 重放被拒**、回调白名单校验 |
| 端到端 | Playwright | 见 §11.1 |

### 11.1 端到端验收用例（必须纳入仓库回归集）

1. 注册新账号 → 登录 demo-web-a 成功
2. **打开 demo-web-b → 未出现登录页，直接进入已登录状态**（SSO 核心验收）
3. demo-web-a 刷新页面 → 保持登录态（静默续签生效）
4. demo-api 的受保护接口在带 token 时返回 200、不带 token 时返回 401
5. 修改密码 → 另一浏览器上下文中的 refresh token 立即失效（该上下文尝试续期时被拒、被迫重新登录）。注意：此用例断言的是 **refresh 被拒**，而非"立刻掉线"——旧 access token 仍会在其剩余寿命内有效，最长 15 分钟，这是 §10 已接受的取舍
6. 管理后台禁用该账号 → 该账号无法再次登录
7. demo-desktop 完成一次完整登录并在重启后保持登录态

用例 2 是本项目存在的理由，也是 demo-web-b 存在的唯一原因——只有一个接入方时，免登在物理上无法被验证。

### 11.2 验收前置要求

所有自动化测试以无头模式运行。宣称任一功能可用之前，必须在真实链路上以真实用户操作方式走通，不接受"接口返回 200"或"元素可定位"作为验收依据。

## 12. 部署与配置

单体应用，一个容器 + 一个 PostgreSQL 实例。

关键配置项（均为环境变量注入，不写死在代码中）：

| 配置项 | 说明 |
| --- | --- |
| `ISSUER_URL` | 认证中心对外 URL，如 `https://auth.<主域名>` |
| `DB_*` | PostgreSQL 连接信息 |
| `JWT_KEY_STORE` | RSA 密钥对存放位置。**必须持久化**，否则重启后全部 token 失效 |
| `BOOTSTRAP_ADMIN_EMAILS` | 启动时置为管理员的邮箱列表 |
| `CLIENTS_CONFIG` | 各产品 client 注册信息（client_id、名称、回调地址白名单） |

client 注册信息写在配置文件中并纳入版本控制，应用启动时同步入库。新增产品 = 改配置 + 重启。回调地址白名单作为安全边界置于代码仓库中，比放在运行时可改的数据库中更不易被误改。

**HTTPS 为硬性要求**：会话 Cookie 带 `Secure` 标记，非 HTTPS 环境下浏览器不会保存，SSO 无法工作。

本地开发的唯一例外：各服务统一使用 `http://localhost:<不同端口>`。浏览器将 `localhost` 视为安全上下文，`Secure` Cookie 在其上正常工作，因此**代码中不需要任何"本地关闭 Secure"的分支**。差异仅存在于配置值（issuer URL、回调地址白名单），产品代码路径与生产完全一致。

需要注意的副作用：本地开发时各服务是 `localhost` 的不同端口，属于 same-site，静默续签同样正常工作；但这掩盖了 §7.3 描述的跨主域名限制——若未来某产品要部署到不同主域名，本地环境无法复现该问题，需在预发环境验证。

## 13. 实现阶段划分

本 spec 覆盖面较大，实现按五个阶段推进。**每个阶段结束时都必须有一个可以用真实用户操作验证的成果**，不允许出现"写完三个模块再一起验收"的阶段。

| 阶段 | 内容 | 阶段结束时可验证的事实 |
| --- | --- | --- |
| 一 · 地基 | 认证中心骨架、`app_user` 表与迁移、注册、登录页、登录失败限流、授权码 + PKCE 流程、demo-web-a | 能在浏览器完成注册并登录 demo-web-a；暴力尝试密码会被锁定 |
| 二 · SSO 兑现 | Web TS 套件、静默续签、demo-web-b | 登录 A 后打开 B **不出现登录页**，刷新页面保持登录 |
| 三 · 资源服务器 | Python FastAPI 验签依赖、demo-api | 带 token 访问受保护接口返回 200，不带返回 401 |
| 四 · 账号自服务与管理 | 修改密码、管理 API、管理后台 SPA | 改密后旧 refresh token 被拒；后台禁用后无法登录 |
| 五 · 桌面端 | Tauri 套件（Rust 回环回调 + 凭据库）、demo-desktop | 桌面端完成登录，重启后仍是登录态 |

阶段二是整个项目的价值验证点。若阶段二无法通过，后续阶段的意义都需重新评估。

## 14. 未来演进

| 事项 | 影响面 |
| --- | --- |
| 接入真实邮件发送与邮箱验证 | 仅改注册逻辑与登录校验，`email_verified` 字段已预留，不需改表 |
| 用户自助找回密码 | 依赖上一项完成 |
| 第三方登录（GitHub 等） | 新增 identity provider 配置，不影响现有流程 |
| 移动端接入 | 认证中心零改动，配置中新增一个 client |
| 个人资料（昵称、头像） | 新增字段并在 userinfo 端点下发 |
| 会话设备管理与远程踢下线 | 需扩展 `oauth2_authorization` 的查询与展示 |

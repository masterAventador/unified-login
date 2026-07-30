# 交接文档：接手本项目前必读

写给**没有参与过阶段一**的执行者（人或 AI）。阶段一踩过的坑都在这里，不读会重踩。

---

## 1. 当前状态

阶段一已完成并合并到 `main`（提交 `5489063`）。

- 后端 152 个测试 + 5 条真实浏览器端到端用例，全绿
- 可用最小闭环：邮箱注册登录 → 授权码 + PKCE → 换令牌 → 刷新 → 接入方拿到身份

**权威文档，改动前必读：**

| 文件 | 作用 |
| --- | --- |
| `docs/superpowers/specs/2026-07-29-unified-login-design.md` | **设计权威依据**。含全部决策、偏离登记、已知取舍、失败路径表 |
| `docs/superpowers/plans/2026-07-29-unified-login-phase1.md` | 阶段一实现计划。其 Global Constraints 段落是框架坑的原始记录 |
| `docs/deployment-notes.md` | 部署形态会改变代码行为的地方 |
| `docs/local-development.md` | 本地启动与验收步骤 |

规格书与实现冲突时，**先确认规格书是不是写错了**——阶段一有三处规格书失实是靠实测发现的。

---

## 2. 环境

```bash
# 跑后端测试必须先设，否则 Testcontainers 找不到 Docker（本机 Docker 由 colima 提供）
export DOCKER_HOST=unix:///Users/aventador/.colima/default/docker.sock
export TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock

cd auth-server && ./mvnw test
```

- Java 17（**不要升级**，开发机其他项目依赖当前环境）
- 本机 5432 被用户自己的 Homebrew postgresql@14 占用。验收用容器映射到 **55432** 并用 `DB_URL` 指过去
- 本机已装 Google Chrome。Playwright 用 `channel: "chrome"` 复用它，**绝对禁止执行 `playwright install`**
- 4173 上的 vite、`agent-browser-chrome-*` 与 `automation-tool-pytest-*` 容器属于**别的项目，一律不要触碰**

---

## 3. 框架坑清单（文档查不到，只能实测撞出来）

Spring Boot 4.1 + Spring Security / Spring Authorization Server 7.1。**SAS 已并入 Spring Security，版本号从 1.5.x 直接跳到 7.x**，网上绝大多数教程都是 1.x 的，照抄会编译失败。

### 3.1 编译期就会失败的

| 坑 | 正确写法 |
| --- | --- |
| `OAuth2AuthorizationServerConfigurer.authorizationServer()` 静态工厂不存在 | 用无参构造 `new OAuth2AuthorizationServerConfigurer()` |
| 两个配置类换了包 | `...config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer`、`...config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration`。其余类包路径未变 |
| `@AutoConfigureMockMvc` 不在旧包 | 现位于 `org.springframework.boot.webmvc.test.autoconfigure`，需依赖 `spring-boot-starter-webmvc-test` |
| Jackson 是 3.x | 包名 `tools.jackson.*`，不是 `com.fasterxml.jackson.*`。异常全部非受检 |
| Testcontainers 2.x 改名 | artifactId 带 `testcontainers-` 前缀；容器类在 `org.testcontainers.postgresql.PostgreSQLContainer` 且**不再是泛型类** |
| BouncyCastle 未被 Boot 管理 | 必须显式声明版本，`Argon2PasswordEncoder` 运行时依赖它 |

### 3.2 静默失效的（最危险，不报错、测试还可能全绿）

**① 公有客户端默认拿不到 refresh token。**
`OAuth2RefreshTokenGenerator.generate()` 在「`authorization_code` + `ClientAuthenticationMethod.NONE`」时直接返回 `null`。令牌响应里只是少一个字段，不报任何错。我们所有客户端都是公有客户端，已用自定义 `OAuth2TokenGenerator` 覆盖。

**② 自定义 `OAuth2TokenGenerator` 后，框架不再自动装配 `OAuth2TokenCustomizer`。**
必须手动 `jwtGenerator.setJwtCustomizer(...)`，否则 sub/email 定制静默失效。

**③ 公有客户端的刷新请求过不了客户端认证。**
`PublicClientAuthenticationConverter` 首行调 `matchesPkceTokenRequest`（= 授权码请求 **且** 带 `code_verifier`），刷新请求两条都不满足；其余内置转换器都要密钥/证书/断言。表现是刷新请求 302 跳登录页。已用自定义转换器 + 提供者覆盖。

**④ 自定义客户端认证转换器必须限定端点。**
客户端认证过滤器同时覆盖 token / introspect / revoke / device_authorization / par 五个端点，且自定义转换器被插在最前面。不限定端点会让任何人带公开的 `client_id` + 一个无关的 `grant_type=refresh_token` 就能内省他人令牌、撤销他人令牌。**这是阶段一出过的 Critical。**

**⑤ `ProviderManager` 对普通 `AuthenticationException` 只记 `lastException` 后继续遍历。**
这个机制坑了两次：
- 想在令牌端点**追加**一个 provider 来否决请求 → **无效**，框架 provider 随后照样签发令牌。必须**替换**框架 provider。
- 断言错误码时钉的可能是框架兜底 provider 抛的码，不是被测逻辑产生的 → 用例偶发失败，且失败形态与真实安全回归完全同形。

**⑥ MockMvc 测授权端点必须把参数放进 query string。**
框架用 `request.getQueryString()` 过滤参数，`.param()` 只填 parameterMap 不填 queryString，参数会被整批丢弃并报 `invalid_request`。GET `/oauth2/authorize` 一律写成 `get("/oauth2/authorize?response_type=code&...")`。POST `/oauth2/token` 不受影响。

**⑦ 授权码流程测试必须走真实表单登录。**
`.with(user(...))` 造的主体缺少 Spring Security 7 的 `FactorGrantedAuthority`，框架签发 token 时要从它推导认证时间，会抛 `authenticationTime cannot be null`。

**⑧ `@DynamicPropertySource` 放在配置类里会被静默忽略。**
只在测试类中生效。要在配置类里注册动态属性，用 `@Bean DynamicPropertyRegistrar`。

**⑨ 只配 `server.servlet.session.timeout` 不会给 Cookie 加 `Max-Age`。**
浏览器把它当会话 Cookie，一关浏览器 SSO 就归零。必须显式配 `server.servlet.session.cookie.max-age`。

**⑩ 框架官方 schema 的 `principal_name` 是 `varchar(200)`。**
我们邮箱最长 320，照抄会让长邮箱账号「注册成功、登录成功、打开任何产品 500」且永久卡死。已由 `V3` 迁移放宽。

**⑪ ID token 寿命是框架硬编码的 30 分钟。**
与 `accessTokenTimeToLive` 无关（`JwtGenerator` 里写死，源码带 `// TODO Allow configuration`）。改 access token 寿命不会影响它。

**⑫ 令牌端点带 `Authorization: Bearer` 头会返回 `400 invalid_client`。**
`BearerTokenAuthenticationFilter` 排在 `OAuth2TokenEndpointFilter` 之前，会覆盖客户端认证结果。SDK 若用统一 HTTP 封装自动附加 access token，必须对认证中心端点显式排除。

---

## 4. 工作纪律（阶段一血泪总结）

### 4.1 测试必须有区分力

**写完一条守护性断言，立刻做变异测试**：把它守的那段生产代码改坏，确认用例真的变红，再改回来。

阶段一出现过五次「保护写了但没人守着」：
- CORS 的三处安全收窄（只挂令牌端点、只放行 POST、不开 credentials）全部可以被改坏而 139 个测试全绿
- 会话 Cookie 的 `HttpOnly` / `Secure` / `SameSite` 三项同时改坏，142 个测试全绿
- 自定义 provider 的拒绝分支改成「弃权」，全量仍全绿

**变异要双向**：既验「保护失效时用例变红」，也验「保护过度时正向用例变红」。只验一个方向说明不了问题。

**变异前必须确认改动真的编译进产物**。`target/classes`、`target/test-classes`、前端 `dist/` 里都可能有陈旧副本，导致「以为改了其实跑的是旧版」而得出错误结论。这个坑踩过三次。用 `rm -rf target/classes target/test-classes` 或 `javap` 核对。

### 4.2 绝对禁止的测试写法

- ❌ 用 `try/catch`、`if (x != null)`、条件分支让测试在数据缺失时静默通过。**阶段一真实发生过：实现者撞上拿不到 refresh token 的障碍后用 try/catch 把断言整段跳过，掩盖了真实缺陷两轮。**
- ❌ 断言「不是 404」「是 3xx」这类模糊条件代替真正验证
- ❌ 把断言钉在「哪个组件最后抛异常」这种副产物上
- ❌ 异步场景里把「断言不存在」排在同步断言之前——页面还空着时它瞬间成立，等于没写

### 4.3 遇到障碍必须上报

撞上做不下去的障碍要**停下来报告 BLOCKED 和具体现象**，不要发明变通方案绕过去。阶段一有一轮就是绕过去导致缺陷被掩盖两轮。

### 4.4 真实验收不可替代

MockMvc 全绿 ≠ 真实可用。阶段一最后一个任务用真实浏览器抓到了 136 个测试全绿都没发现的缺陷：`/oauth2/token` 缺少 CORS 放行，服务端 200、令牌照签、日志无异常，浏览器却把响应整个丢弃。

**每个阶段都必须有一道真实链路验收**，用真实浏览器/真实客户端走真实用户路径。

### 4.5 服务用完就关

跑完测试立刻停掉本轮起的所有服务（后端、dev server、数据库容器）并确认端口释放。浏览器一律无头，不要弹窗口打断用户。

---

## 5. 阶段二起步前必须先做的三件事

这三条是阶段一整体审查发现的，**不先做阶段二会卡住或返工**：

1. **`prompt=none` 当前被自家过滤链截胡**。授权服务器链上配了 `.anyRequest().authenticated()`，而 `AuthorizationFilter` 排在 `OAuth2AuthorizationEndpointFilter` **之前**，匿名的 `prompt=none` 请求在前者就被拒、跳 `/login`，框架那段 `login_required` 逻辑成了死代码。实测：有会话正常回跳带 code，无会话返回 302 跳登录页而不是 `login_required`。
2. **授权端点默认 `X-Frame-Options: deny`**，iframe 直接被浏览器拒绝渲染，且父页面因跨源读不到 iframe location，**没有任何错误信号回到产品侧**，SDK 只能挂到自己超时。
3. **discovery 文档与实际能力不符**：宣告了 `client_credentials` 与 token-exchange（规格书明确不启用），而 `token_endpoint_auth_methods_supported` 里**没有 `none`**——等于在说"本服务器不支持公有客户端"，恰好说反。任何按 discovery 自动选认证方式的标准库都会走进死胡同。

---

## 6. 提交规范

- commit message **用中文**，conventional 前缀可保留英文
- **不加任何 AI 署名**（不要 Co-Authored-By）
- 合并分支用 `git merge --no-ff`
- worktree 统一建在 `<项目根>/wt/` 下
- **部署必须由用户当次明确下令**，任何授权都不构成部署许可

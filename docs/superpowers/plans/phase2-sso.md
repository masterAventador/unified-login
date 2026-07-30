# 阶段二实现计划：SSO 兑现

> **执行前必读**：`docs/HANDOVER.md`（框架坑清单与工作纪律）、`docs/superpowers/specs/2026-07-29-unified-login-design.md`（设计权威依据，重点 §7.2、§7.3、§8.1）。

**目标：** 让第二个产品在用户不重新输密码的情况下拿到令牌，并让页面刷新后登录态不丢。

**为什么这个阶段最关键：** 规格书写明「阶段二是整个项目的价值验证点。若阶段二无法通过，后续阶段的意义都需重新评估」。阶段一只有一个接入方，"单点登录"的"单点"根本没体现出来。

**验收标准（一句话）：** 登录 A 之后打开 B **不出现登录页**；刷新页面**保持登录**。

**技术栈：** TypeScript（SDK 与 demo）、Vite、Playwright；认证中心侧改动仍是 Spring Boot 4.1 + Spring Security 7.1。

## Global Constraints

以下对本阶段每个 Task 都生效：

- **HANDOVER.md 第 3 节的十二条框架坑全部适用**，不再重复。
- **TDD 铁律**：先写测试 → 运行并**亲眼看到失败** → 写最小实现 → 运行确认通过 → 提交。
- **变异测试**：每写一条守护性断言，立刻把它守的生产代码改坏确认变红，双向都要验。变异前先清 `target/classes`、`target/test-classes`、前端 `dist/`。
- **禁止假测试**：不得用 try/catch、if 判空、条件分支让测试在数据缺失时静默通过。
- 所有客户端都是**公有客户端**（`ClientAuthenticationMethod.NONE`）、强制 PKCE、跳过同意页。
- SDK **不得**给认证中心端点附加 `Authorization: Bearer` 头（坑 ⑫）。
- SDK **不要**依赖 discovery 自动配置，直到 Task 3 修好它。
- Playwright 用 `channel: "chrome"` 复用本机 Chrome，**禁止 `playwright install`**；一律无头。
- 起的服务用完就关，确认端口释放；本机 5432、4173 与 `automation-tool-*` 容器不要触碰。
- 提交信息用中文，不加 AI 署名。

### 本阶段的已知限制

- 静默续签依赖产品域与认证中心域属于同一 registrable domain（`SameSite=Lax` 才会发 Cookie）。跨主域名的产品需改用跳转式续签，不在本阶段范围。
- 会话 Cookie 是固定 14 天，非滑动续期（见规格书 §6.3 更正）。

---

## File Structure

```
auth-server/src/main/java/com/aventador/unifiedlogin/config/
├── AuthorizationServerConfig.java          修改：授权端点入口点、frame 放行、discovery 定制
└── PromptNoneAuthenticationEntryPoint.java 新建：prompt=none 时按 RFC 回传 login_required

sdk/web-ts/
├── package.json / tsconfig.json / vite.config.ts
├── src/
│   ├── index.ts            对外 API：login/logout/getAccessToken/onAuthStateChange
│   ├── pkce.ts             code_verifier 生成与 S256 推导
│   ├── storage.ts          verifier/state 的短期存放与清理
│   ├── tokens.ts           内存令牌管理、过期判定、自动刷新
│   └── silent-renew.ts     隐藏 iframe 的 prompt=none 续签
└── test/                   Vitest 单元测试

demo/demo-web-b/            第二个接入方，结构对齐 demo-web-a
e2e/tests/sso.spec.ts       跨产品免登与刷新保持登录的验收
```

---

## Task 1：让 `prompt=none` 返回标准错误而不是跳登录页

**Files:**
- Create: `auth-server/src/main/java/com/aventador/unifiedlogin/config/PromptNoneAuthenticationEntryPoint.java`
- Modify: `auth-server/src/main/java/com/aventador/unifiedlogin/config/AuthorizationServerConfig.java`
- Test: `auth-server/src/test/java/com/aventador/unifiedlogin/config/PromptNoneTest.java`

**Interfaces:**
- Produces：匿名 + `prompt=none` 的授权请求，返回 302 到 `redirect_uri?error=login_required&state=...`，而不是跳 `/login`

**背景（必读，否则会走错方向）：** 框架**原生支持** `prompt=none`——`OAuth2AuthorizationCodeRequestAuthenticationProvider` 会抛 `login_required` 并按 RFC 6749 §4.1.2.1 回传到 redirect_uri。但在本项目配置下那段是死代码：授权服务器链配了 `.anyRequest().authenticated()`，而 `AuthorizationFilter` 排在 `OAuth2AuthorizationEndpointFilter` **之前**，匿名请求在前者就被拒了。

- [ ] **Step 1: 写失败的测试**

三条用例：
1. 有会话 + `prompt=none` → 302 回跳 `redirect_uri` 且带 `code`（回归，防止修复把正常路径弄坏）
2. **无会话 + `prompt=none`** → 302 回跳 `redirect_uri` 且带 `error=login_required`，**不含 `code`**，且 `state` 原样回传
3. 无会话 + **不带** `prompt=none` → 仍跳 `/login`（回归，普通登录路径不受影响）

注意坑 ⑥：授权参数必须拼进 query string，用 `OAuth2TestFlows.authorizeUri(...)`。

- [ ] **Step 2: 运行确认失败**

预期用例 2 失败，实际得到 302 跳 `/login`。

- [ ] **Step 3: 实现入口点**

新建 `PromptNoneAuthenticationEntryPoint`：识别 `prompt=none`，**校验 `redirect_uri` 确实在该 client 的白名单内**（不校验就是开放重定向），按 RFC 回传 `error=login_required` 与原 `state`；不是 `prompt=none` 的请求委托给原有的 `LoginUrlAuthenticationEntryPoint`。

在 `AuthorizationServerConfig` 的 `exceptionHandling` 里替换成它。

> ⚠ **不要**用「放开 `.anyRequest().authenticated()`」的办法绕过——那会让授权端点对匿名完全敞开。

- [ ] **Step 4: 运行确认通过，并做变异验证**

变异：把 redirect_uri 白名单校验去掉 → 必须有用例变红（补一条「未注册的 redirect_uri + prompt=none 不得回跳」）。

- [ ] **Step 5: 全量测试 + 提交**

---

## Task 2：为授权端点放开 frame 限制

**Files:**
- Modify: `auth-server/src/main/java/com/aventador/unifiedlogin/config/AuthorizationServerConfig.java`
- Test: 同 Task 1 的测试类追加

**背景：** 认证中心默认 `X-Frame-Options: deny`，隐藏 iframe 里的 `prompt=none` 请求会被浏览器直接拒绝渲染。更麻烦的是父页面因跨源读不到 iframe location，**没有任何错误信号回到产品侧**，SDK 只能挂到超时。

- [ ] **Step 1: 写失败的测试**

1. `GET /oauth2/authorize` 的响应**不含** `X-Frame-Options: DENY`
2. `GET /login` 的响应**仍然含** `X-Frame-Options: DENY`（登录页被嵌套是点击劫持面，必须保持拒绝）

- [ ] **Step 2: 运行确认失败**
- [ ] **Step 3: 实现**

只对授权端点放开，**不要全局关掉** `frameOptions`。

- [ ] **Step 4: 运行确认通过 + 变异验证**

变异：改成全局关闭 → 用例 2 必须变红。

- [ ] **Step 5: 全量测试 + 提交**

---

## Task 3：让 discovery 文档与实际能力一致

**Files:**
- Modify: `auth-server/src/main/java/com/aventador/unifiedlogin/config/AuthorizationServerConfig.java`
- Test: `auth-server/src/test/java/com/aventador/unifiedlogin/config/OidcEndpointsTest.java`

**背景：** 当前 discovery 宣告 `client_credentials` 与 token-exchange（规格书 §6.1 明确不启用），且 `token_endpoint_auth_methods_supported` 里**没有 `none`**——等于说"不支持公有客户端"，恰好说反。任何按 discovery 自动选认证方式的标准 OIDC 库都会走进死胡同，直接抵消"新产品接入成本趋近于零"的目标。

- [ ] **Step 1: 写失败的测试**

- `grant_types_supported` **恰好等于** `["authorization_code", "refresh_token"]`
- `token_endpoint_auth_methods_supported` **包含** `none`

> 现有测试用 `hasItems` 只断言"包含"，断不出"多了不该有的"。这里必须用**精确相等**。

- [ ] **Step 2 – 5**：确认失败 → 定制 `OidcProviderConfigurationCustomizer` → 确认通过 → 变异（加回 `client_credentials` 应变红）→ 全量 + 提交

---

## Task 4：Web TS 套件的 PKCE 与令牌管理

**Files:**
- Create: `sdk/web-ts/src/pkce.ts`、`storage.ts`、`tokens.ts` 及对应 Vitest 测试

**Interfaces:**
- Produces：
  - `createPkcePair(): Promise<{verifier: string, challenge: string}>`
  - `TokenStore`：内存持有 access/refresh/id token 与过期时刻，`isExpiringSoon(skewSeconds)`

**要求：**
- `code_verifier` 用 `crypto.getRandomValues` 取 **32 字节**（256 bit）后 base64url；challenge 用 S256
- verifier 与 state 存 `sessionStorage`，**换令牌前即删除**（阶段一 demo 的做法，防 XSS 读走）
- 令牌**只存内存**，不进 localStorage/sessionStorage
- `isExpiringSoon` 留出时钟偏移余量（建议 60 秒）

- [ ] 每个函数按 TDD 逐个写：先测试后实现，一条一条来

---

## Task 5：Web TS 套件的对外 API 与自动刷新

**Files:**
- Create: `sdk/web-ts/src/index.ts` 及测试

**Interfaces（规格书 §8.1 规定的对外面）：**
- `login(): Promise<void>` — 生成 PKCE、存 state、跳转授权端点
- `logout(): void` — **只清本产品持有的令牌，不结束认证中心会话**（规格书 §7.5）
- `getAccessToken(): Promise<string>` — 令牌即将过期时自动刷新后返回，调用方无需感知刷新时机
- `onAuthStateChange(cb): () => void` — 订阅登录态变化，返回取消订阅函数

**要求：**
- 回调处理必须校验 `state`，不符则**丢弃 code、不换令牌**（规格书 §10）
- 换令牌与刷新的请求**不得附加 `Authorization` 头**（坑 ⑫）
- 并发调用 `getAccessToken()` 时只发起一次刷新（避免刷新风暴导致轮转互相作废）

> ⚠ 一次性轮转意味着**两个并发刷新会互相作废**：先到的那个把旧 token 换掉，后到的那个拿着已作废的 token 会被判为重放。并发合并不是优化，是正确性要求。

- [ ] TDD 逐个 API 写。并发合并那条要专门写一条「同时调用十次只发起一次刷新」的测试

---

## Task 6：静默续签

**Files:**
- Create: `sdk/web-ts/src/silent-renew.ts` 及测试

**Interfaces:**
- `silentRenew(): Promise<TokenSet | null>` — 隐藏 iframe 请求 `prompt=none`，成功返回令牌，会话失效返回 `null`

**要求：**
- iframe 必须设超时兜底（建议 10 秒）；超时按失败处理
- 用完立刻移除 iframe
- 通过 `postMessage` 从回调页把结果传回父页面，并**校验 `event.origin`**（不校验就是任意站点可伪造登录态）
- 会话失效时收到 `error=login_required`（依赖 Task 1）→ 返回 `null`，由调用方决定跳登录页

- [ ] TDD。`event.origin` 校验那条必须做变异：去掉校验后，伪造 origin 的消息必须能让用例变红

---

## Task 7：demo-web-b 与跨产品免登验收

**Files:**
- Create: `demo/demo-web-b/`（结构对齐 `demo/demo-web-a`）
- Modify: `auth-server/src/main/resources/application.yml`（注册 demo-web-b 客户端）
- Create: `e2e/tests/sso.spec.ts`

**要求：**
- demo-web-b 接入 Task 5 的 SDK，**不要复制粘贴 demo-web-a 的手写逻辑**
- 渲染用户信息**必须用 `textContent`**，不得用 `innerHTML`（阶段一在这里出过实证的注入 sink）

**E2E 用例（这是本阶段的验收关卡）：**
1. 在 A 登录 → 打开 B → **不出现登录页**，直接显示已登录用户
2. 在 B 刷新页面 → **保持登录**（静默续签生效）
3. A 登出 → B **仍是登录态**（规格书 §7.5：登出只清本产品令牌）
4. 会话失效后刷新 → 跳登录页而不是无限挂起

- [ ] 每条用例都要做变异验证。用例 1 变异：把 SDK 的 `prompt=none` 去掉 → 必须变红

---

## Task 8：阶段二整体验收与 E2E 接入 CI

**Files:**
- Modify: `e2e/playwright.config.ts`

**背景：** 阶段一的 E2E 没有 `webServer` 配置，必须人工先起数据库 + 后端 + 前端才能跑，规格书 §11 要求「可接入 CI」这一条没兑现。忘了起服务时得到的是一堆 `ERR_CONNECTION_REFUSED` 超时，而不是清晰的"服务没起"。

- [ ] 加 `webServer` 自动拉起后端与两个 demo
- [ ] 全量后端测试 + 全部 E2E 全绿
- [ ] **真实链路验收**：真实浏览器手工走一遍 A 登录 → 打开 B → 刷新，确认与自动化结果一致
- [ ] 服务清理确认

---

## 阶段二完成标准

1. 后端全量测试与全部 E2E 用例全绿
2. 真实浏览器中：登录 A 后打开 B 不出现登录页；B 刷新后保持登录
3. `prompt=none` 在会话失效时返回 `login_required` 而非跳登录页
4. discovery 文档与实际能力一致
5. SDK 对外只暴露规格书 §8.1 规定的四个 API
6. 服务全部停止，端口释放

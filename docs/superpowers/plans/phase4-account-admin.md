# 阶段四实现计划：账号自服务与管理后台

> **执行前必读**：`docs/HANDOVER.md`、`docs/superpowers/specs/2026-07-29-unified-login-design.md`（重点 §7.6、§9、§10）。

**目标：** 用户能改自己的密码；管理员能查用户列表、禁用账号、重置密码。

**技术栈：** 后端 Spring Boot 4.1（同阶段一）；管理后台前端 TypeScript + Vite（接阶段二的 SDK）。

## Global Constraints

- **HANDOVER.md 的框架坑与工作纪律全部适用。**
- 管理员用 `app_user.is_platform_admin` 字段标记，**不引入角色体系**（规格书 §3：认证中心只回答"你是谁"）。
- 认证中心签发的令牌**依然不含任何角色或权限声明**——管理 API 的鉴权在认证中心内部做，不下发到令牌里。
- 密码规则不变：8–64 字符，不限字符类型，Argon2id 参数不变。
- 提交信息用中文，不加 AI 署名。

### ⚠ 本阶段最容易出的事故

阶段一整体审查发现过一个**正好卡在本阶段的陷阱**（已修复，但要理解它为什么会发生）：

> 框架的刷新流程用的是**首次登录时序列化进 `oauth2_authorization` 的 principal 快照，从不回查用户表**。所以"禁用账号"这个操作如果只改用户表，被禁用的账号照样能用 refresh token 无限续期。而验收标准"后台禁用后无法登录"**会通过**——因为登录路径确实被拒了——但账号实际仍在正常访问所有产品。

阶段一已经把刷新 provider 替换成带账号回查的版本，所以这条现在是通的。**但本阶段新增的每一个"让账号失效"的操作（禁用、改密、重置密码）都必须验证同样的事**：不能只验"登录被拒"，必须验"持有的 refresh token 也换不出新令牌"。

---

## File Structure

```
auth-server/src/main/java/com/aventador/unifiedlogin/
├── account/
│   ├── PasswordChangeService.java     改密 + 撤销该用户全部 refresh token
│   ├── PasswordChangeController.java  登录态下的改密页
│   └── ...
├── admin/
│   ├── AdminUserController.java       管理 API
│   ├── AdminUserService.java          列表、禁用/启用、重置密码
│   └── PlatformAdminGuard.java        管理接口的准入判断
└── user/AppUser.java                  已有 is_platform_admin 字段

auth-server/src/main/resources/db/migration/V4__...sql   若需要新字段
admin-web/                             管理后台 SPA
```

---

## Task 1：撤销某用户全部 refresh token 的能力

**Files:** `auth-server/.../account/TokenRevocationService.java` + 测试

**这是本阶段的地基**，改密、禁用、重置密码都要用它。

**Interfaces:**
- `revokeAllTokensOf(UUID userId)` — 让该用户所有已签发的 refresh token 失效

**要求：**
- 直接操作 `oauth2_authorization` 表（按 `principal_name` 定位），或用框架的 `OAuth2AuthorizationService` 逐个作废
- **必须验证真实终态**：撤销后用之前拿到的 refresh token 去换令牌，断言换不出来；同时断言**其他用户的令牌不受影响**

- [ ] TDD + 变异（撤销逻辑改成空实现 → 用例必须变红；改成撤销所有人的 → "其他用户不受影响"必须变红）

---

## Task 2：修改密码

**Files:** `auth-server/.../account/PasswordChangeService.java`、`PasswordChangeController.java`、改密页模板 + 测试

**流程（规格书 §7.6）：** 登录态下提交旧密码与新密码 → 校验旧密码 → 更新 `password_hash` 与 `password_changed_at` → **撤销该用户全部 refresh token**。

**必测：**
- 旧密码错误 → 拒绝，且不产生任何副作用
- 新密码不满足规则 → 拒绝
- 成功后：新密码能登录、旧密码不能登录
- **成功后：改密前拿到的 refresh token 换不出新令牌**（用 Task 1 的能力）
- 其他设备上的 access token 最长 15 分钟后自然失效（规格书已登记的取舍，写进测试注释即可，不必测）

- [ ] TDD 逐条

---

## Task 3：管理接口的准入

**Files:** `auth-server/.../admin/PlatformAdminGuard.java` + 测试

**要求：**
- 只有 `is_platform_admin = true` 的用户能访问 `/admin/**`
- 非管理员访问 → **403**，且响应内容不得泄漏该接口存在与否之外的信息
- 未登录访问 → 401/跳登录页

> ⚠ **必须写"普通用户访问管理接口被拒"的用例，并做变异验证**。本项目出现过五次"保护写了但没人守着"，管理接口是最不能出这个问题的地方。

- [ ] TDD + 变异（把准入判断去掉 → 普通用户用例必须变红）

---

## Task 4：管理 API

**Files:** `auth-server/.../admin/AdminUserController.java`、`AdminUserService.java` + 测试

**接口：**
- 用户列表：分页、按邮箱搜索、按状态筛选
- 禁用/启用账号
- 重置密码（管理员直接设新密码）

**要求：**
- 禁用账号后：**该用户登录被拒 且 持有的 refresh token 换不出新令牌**（两条都要断言，见本文档开头的陷阱说明）
- 重置密码后：同样撤销该用户全部 refresh token
- 列表接口**不得返回 `password_hash`**——写一条用例断言响应里不含该字段
- 管理员不能禁用自己（否则可能把最后一个管理员锁死）

- [ ] TDD 逐条 + 变异

---

## Task 5：管理后台 SPA

**Files:** `admin-web/`

**要求：**
- 接阶段二的 SDK 登录，**不要自己手写 PKCE 流程**
- 渲染用户数据**必须用 `textContent`**，不得 `innerHTML`（邮箱是用户自选内容，阶段一在这里出过实证的注入 sink）
- 非管理员登录后进入后台 → 显示"无权限"，不要白屏或报错堆栈

---

## Task 6：阶段四真实链路验收

**E2E 用例：**
1. 用户改密 → 另一浏览器上下文中的 refresh token 立即失效（该上下文尝试续期时被拒、被迫重新登录）
2. 管理员禁用某账号 → 该账号无法登录，**且其 refresh token 换不出新令牌**
3. 管理员重置密码 → 新密码可登录、旧密码不可、旧 refresh token 失效
4. 普通用户访问管理后台 → 无权限

> 用例 1 断言的是 **refresh 被拒**，不是"立刻掉线"——旧 access token 仍会在剩余寿命内有效（最长 15 分钟），这是规格书已接受的取舍。

- [ ] 每条都做变异验证

---

## 阶段四完成标准

1. 全量后端测试与全部 E2E 全绿
2. 改密、禁用、重置密码三个操作**都验证了 refresh token 真的失效**，不只是"登录被拒"
3. 管理接口有"普通用户被拒"的用例且经变异验证
4. 列表接口不泄漏密码哈希
5. 服务全部停止，端口释放

# 阶段三实现计划：资源服务器验签依赖

> **执行前必读**：`docs/HANDOVER.md`、`docs/superpowers/specs/2026-07-29-unified-login-design.md`（重点 §8.2、§9）。

**目标：** 让 Python FastAPI 写的产品后端能本地验签认证中心签发的令牌，拿到当前用户身份。

**核心约束（规格书 §8.2）：** **不回调认证中心**。验签全靠本地缓存的 JWKS 公钥，因此认证中心不可用时不影响已登录用户访问各产品业务接口。这是整套架构的可用性基础，不能为了省事改成每次请求都去问认证中心。

**技术栈：** Python 3.11+、FastAPI、PyJWT（或 python-jose）、httpx、pytest。

## Global Constraints

- **HANDOVER.md 第 4 节的工作纪律全部适用**（TDD、变异测试、禁止假测试、真实验收）。
- 验签必须校验 `iss`、`aud`、`exp`，缺一不可。
- **禁止**把 `sub` 以外的任何字段当作用户主键——`sub` 是不可变 UUID，`email` 会变。
- JWKS 缓存必须支持**密钥轮换时自动重新拉取**：遇到未知 `kid` 时重新拉一次，而不是直接拒绝。
- 重新拉取要有**频率上限**（防止伪造 `kid` 的请求打爆认证中心），建议同一 `kid` 失败后至少间隔一段时间才重试。
- Python 包不要发布到 PyPI，本阶段以本地可 `pip install -e` 的形式交付。
- 提交信息用中文，不加 AI 署名。

---

## File Structure

```
sdk/python-fastapi/
├── pyproject.toml
├── src/unified_login/
│   ├── __init__.py
│   ├── jwks.py         JWKS 拉取、缓存、按 kid 选公钥、轮换重拉
│   ├── verifier.py     验签与声明校验
│   ├── dependency.py   FastAPI 依赖项，注入后得到 CurrentUser
│   └── models.py       CurrentUser(sub, email)
└── tests/

demo/demo-api/          最小 FastAPI 产品后端，一个受保护接口 + 一个公开接口
```

---

## Task 1：JWKS 拉取与缓存

**Files:** `sdk/python-fastapi/src/unified_login/jwks.py` + 测试

**Interfaces:**
- `JwksCache(issuer: str, http_client)` — `get_key(kid) -> PublicKey`

**要求：**
- 首次调用时拉取 `<issuer>/oauth2/jwks`
- 命中缓存直接返回；**未知 `kid` 时重新拉取一次**（密钥轮换场景）
- 重拉有频率上限，避免伪造 `kid` 打爆认证中心
- 拉取失败时**不要**静默返回 None 让验签放行——必须抛出，由上层拒绝请求

- [ ] TDD。**变异必做**：把"未知 kid 重拉"去掉 → 轮换场景用例必须变红；把"频率上限"去掉 → 打爆防护用例必须变红

---

## Task 2：验签与声明校验

**Files:** `sdk/python-fastapi/src/unified_login/verifier.py` + 测试

**要求逐条写测试，每条都要有对应的拒绝用例：**

| 场景 | 期望 |
| --- | --- |
| 合法令牌 | 通过，返回 `sub` 与 `email` |
| 签名被篡改 | 拒绝 |
| `exp` 已过期 | 拒绝 |
| `iss` 不是本认证中心 | 拒绝 |
| `aud` 不是本产品的 client_id | 拒绝 |
| `alg: none` | 拒绝（**必须显式限定允许的算法**，否则可被算法混淆攻击绕过） |
| 用 HMAC 冒充 RSA（把公钥当密钥） | 拒绝（同上，算法白名单） |

> ⚠ `alg: none` 与算法混淆是 JWT 最经典的两个漏洞。**必须显式传 `algorithms=["RS256"]`**，不要依赖库的默认行为。这两条测试必须做变异：去掉算法白名单后必须变红。

- [ ] TDD，一条一条来

---

## Task 3：FastAPI 依赖项

**Files:** `sdk/python-fastapi/src/unified_login/dependency.py`、`models.py` + 测试

**Interfaces:**
- `CurrentUser`：`sub: UUID`、`email: str`
- `require_user()` — FastAPI 依赖项，注入后得到 `CurrentUser`

**要求：**
- 从 `Authorization: Bearer <token>` 取令牌
- 缺失或格式不对 → **401**，并按规范带 `WWW-Authenticate: Bearer`
- 验签失败 → 401
- **不要**在这里做业务权限判断——认证中心只回答"你是谁"，权限由各产品自管（规格书 §3）

- [ ] TDD

---

## Task 4：demo-api 与真实链路验收

**Files:** `demo/demo-api/`、`e2e/tests/resource-server.spec.ts`

**要求：**
- 一个受保护接口（需要令牌）、一个公开接口（不需要）
- **真实链路验收**：用阶段二的 SDK 在浏览器里真实登录，拿真实令牌调 demo-api，断言拿到 200 与正确的 `sub`；不带令牌断言 401

**必须验证的可用性场景（这是本阶段的核心价值）：**
- 认证中心**停掉**之后，已持有有效令牌的请求**仍能访问 demo-api**（证明不回调认证中心）
- 这条用例要真的把认证中心进程停掉再发请求，不要用 mock

- [ ] 上述可用性用例必须做变异：如果实现改成每次回调认证中心，这条必须变红

---

## 阶段三完成标准

1. 全部 pytest 用例与 E2E 用例全绿
2. 真实链路：浏览器登录拿到的真实令牌能调通 demo-api 受保护接口
3. **认证中心停机后，已登录用户仍能访问 demo-api**
4. 算法白名单、`iss`/`aud`/`exp` 校验各有拒绝用例且经变异验证
5. 服务全部停止，端口释放

# 本地开发与验收

## 前置

- Java 17、Maven、Python 3.11+、uv、Node 22+、pnpm、Docker（供 Testcontainers 使用）
- 本地 PostgreSQL：`docker run --rm -e POSTGRES_DB=unified_login -e POSTGRES_USER=unified_login -e POSTGRES_PASSWORD=unified_login -p 127.0.0.1:5432:5432 postgres:16-alpine`

若本机 5432 已被别的 PostgreSQL 占用，把容器映射到其他端口并用 `DB_URL` 指过去即可，
例如映射 `-p 127.0.0.1:55432:5432` 后以 `DB_URL=jdbc:postgresql://127.0.0.1:55432/unified_login` 启动认证中心。
这只是换了一个数据库地址，读取配置与连接的代码路径与生产完全相同。

## 启动

1. 认证中心：`cd auth-server && ./mvnw spring-boot:run`（监听 9000）
2. demo-web-a：`cd demo/demo-web-a && pnpm install && pnpm dev`（监听 5173）
3. Web SDK：`cd sdk/web-ts && pnpm install`
4. demo-web-b：`cd demo/demo-web-b && pnpm install && pnpm dev`（监听 5174）
5. Python SDK：`cd sdk/python-fastapi && uv sync --locked`
6. demo-api：`cd demo/demo-api && uv sync --locked`，再按接入它的前端 client_id 配置
   `RESOURCE_AUDIENCE` 后启动 `uv run uvicorn demo_api.app:app --host 127.0.0.1 --port 8000`
7. 账号管理后台：`cd admin-web && pnpm install && pnpm dev`（监听 5175）

## 端到端验收

先在单独终端启动隔离数据库：

```bash
docker run --rm --name unified-login-e2e-postgres \
  -e POSTGRES_DB=unified_login \
  -e POSTGRES_USER=unified_login \
  -e POSTGRES_PASSWORD=unified_login \
  -p 127.0.0.1:55432:5432 postgres:16-alpine
```

首次运行或锁文件变化后安装六个前端包的依赖，再执行测试：

```bash
pnpm --dir sdk/web-ts install --frozen-lockfile
pnpm --dir demo/demo-web-a install --frozen-lockfile
pnpm --dir demo/demo-web-b install --frozen-lockfile
pnpm --dir demo/demo-api/frontend install --frozen-lockfile
pnpm --dir admin-web install --frozen-lockfile
PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 pnpm --dir e2e install --frozen-lockfile
pnpm --dir e2e test
```

E2E 固定连接映射到 55432 的隔离 PostgreSQL。数据库就绪后，不要手工启动其他服务：
Playwright 会从生产构建自动拉起认证中心、两个 Web Demo、demo-api 及其浏览器客户端，并在
测试结束后停止它们。资源服务器用例另起 9001 的隔离认证中心，拿到真实令牌并缓存公钥后会
真实停止该 Java 进程，再断言 8000 的受保护接口仍可访问。运行前应确认
9000、9001、19001、5173、5174、5175、5274、8000 空闲；配置不会复用已有进程，以免误测开发服务器或其他项目。

配置已用 `channel: "chrome"` 复用本机 Google Chrome，**不要执行 `playwright install`**。
`PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1` 可避免安装 E2E 依赖时顺带下载一份 Chromium。

当前一整轮 17 条 E2E 的两个认证中心分别独立计数；任一进程收到的 `/login` 提交都低于
地址限流每分钟 20 次的阈值，
因此**按生产默认配置跑一轮不会触发限流**，不需要为验收调整任何阈值。
每次执行命令都会启动新的认证中心进程，进程内的地址计数不会跨轮累计。
账号维度的锁定阈值不要调整，E2E 用例本身不会触发它。

## 手工验证限流

限流的自动化覆盖在 `LoginRateLimitIntegrationTest`（真实 Spring 上下文 + 真实数据库）。
不放进 E2E 是因为一旦触发锁定会干扰同批次的其他用例。若要手工确认，用同一个邮箱连续
输错 5 次密码，第 6 次即使密码正确也会跳到 `/login?locked` 并显示锁定提示。

## 接入方的跨域前提

浏览器里的接入方是从自己的源跨源 POST `/oauth2/token` 换令牌的。认证中心按
`unified-login.clients[].redirect-uris` 推导出允许的源并放行该端点的跨域请求，
新接入方只要把回调地址配进去就自动生效，不需要另维护一份跨域名单。
回调地址写错域名或端口的表现是页面侧一句 `Failed to fetch`，而服务端日志一切正常——
遇到这个现象先核对回调地址与接入方实际运行的源是否一致。

## 收尾

Playwright 会自动停止全部认证中心、API 与 Demo。验收结束后再停掉 PostgreSQL 容器，
并确认 9000、9001、19001、5173、5174、5175、5274、8000、55432 已释放。

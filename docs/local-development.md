# 本地开发与验收

## 前置

- Java 17、Maven、Node 22+、pnpm、Docker（供 Testcontainers 使用）
- 本地 PostgreSQL：`docker run --rm -e POSTGRES_DB=unified_login -e POSTGRES_USER=unified_login -e POSTGRES_PASSWORD=unified_login -p 5432:5432 postgres:16-alpine`

若本机 5432 已被别的 PostgreSQL 占用，把容器映射到其他端口并用 `DB_URL` 指过去即可，
例如映射 `-p 55432:5432` 后以 `DB_URL=jdbc:postgresql://127.0.0.1:55432/unified_login` 启动认证中心。
这只是换了一个数据库地址，读取配置与连接的代码路径与生产完全相同。

## 启动

1. 认证中心：`cd auth-server && ./mvnw spring-boot:run`（监听 9000）
2. demo-web-a：`cd demo/demo-web-a && pnpm install && pnpm dev`（监听 5173）

## 端到端验收

```bash
cd e2e && pnpm install && pnpm test
```

配置已用 `channel: "chrome"` 复用本机 Google Chrome，**不要执行 `playwright install`**。
安装依赖时用 `PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 pnpm install` 可避免顺带下载一份 Chromium。

一整轮 E2E 只会向 `/login` 提交 6 次（五条用例分别是 1、1、1、0、2 次），而地址限流的阈值是每分钟 20 次，
因此**按生产默认配置跑一轮不会触发限流**，不需要为验收调整任何阈值。
只有在一分钟内反复重跑五轮以上时才会撞上。真要密集重跑，用环境变量把阈值调高：

```bash
UNIFIED_LOGIN_LOGIN_RATE_LIMIT_MAXATTEMPTSPERIPPERMINUTE=1000 ./mvnw spring-boot:run
```

这是**配置值差异，不是代码分支**——限流的判定逻辑与生产完全是同一条路径，只是阈值不同。
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

验收结束后停掉 PostgreSQL 容器与两个开发服务，避免端口与资源占用。

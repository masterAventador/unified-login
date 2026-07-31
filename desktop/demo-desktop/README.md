# 统一登录桌面端

Tauri 2 示例应用。授权页只会由 Rust 调起系统默认浏览器，应用 WebView 只显示本地登录状态。
Refresh Token 保存在操作系统凭据库，Access Token 只存在于 Rust 进程内存。

## 本地校验

```bash
pnpm install --frozen-lockfile
pnpm test
pnpm typecheck
pnpm tauri build --bundles app
```

Rust 侧校验：

```bash
cd src-tauri
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

## macOS 生产应用静默验收

验收脚本只接受 `target/release/bundle/macos` 下的 `.app`。它会在不抢前台的情况下隐藏
启动 release 产物，用独立临时条目验证 macOS 钥匙串写入、读取与删除，并通过 Playwright
无头浏览器验证首次登录、浏览器 SSO、refresh token 轮换恢复和伪造 `state` 拒绝。运行前：

1. 在 `127.0.0.1:55432` 启动项目专用 PostgreSQL，容器名为
   `unified-login-e2e-postgres`。
2. 不要手工启动认证中心或其他前端服务；Playwright 会从当前分支构建并在后台管理它们。
3. 保持生产 `.app` 位于默认构建目录，或通过 `DESKTOP_APP_PATH` 指向同一 release
   构建路径下的产物。

然后运行：

```bash
pnpm test:acceptance:headless
```

脚本不会弹出桌面窗口或浏览器窗口，也不会打印 OAuth code、令牌或钥匙串内容；无论成功
失败，都会关闭桌面进程并删除独立测试凭据。

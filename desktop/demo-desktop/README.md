# 统一登录桌面端

Tauri 2 示例应用。授权页只会由 Rust 调起系统默认浏览器，应用 WebView 只显示本地登录状态。
Refresh Token 保存在操作系统凭据库，Access Token 只存在于 Rust 进程内存。

## 本地校验

```bash
pnpm install --frozen-lockfile
pnpm test
pnpm test:acceptance:unit
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

## macOS 生产应用验收

验收脚本只接受 `target/release/bundle/macos` 下的 `.app`，并按真实用户路径验证首次登录、
浏览器 SSO、凭据库恢复、伪造 `state` 和登出清理。运行前：

1. 在 `127.0.0.1:55432` 启动项目专用 PostgreSQL，容器名为
   `unified-login-e2e-postgres`。
2. 在 `http://localhost:9000` **全新启动**当前分支构建的认证中心；全新进程确保系统浏览器
   遗留的旧 Session Cookie 无法复用，首次登录场景不会得到假阳性。
3. 给运行脚本的终端开启 macOS“辅助功能”权限，以便操作生产应用和系统默认浏览器。
4. 保持生产 `.app` 位于默认构建目录，或通过 `DESKTOP_APP_PATH` 指向同一 release
   构建路径下的产物。

然后运行：

```bash
pnpm test:acceptance:macos
```

脚本不会打印 OAuth code、令牌或钥匙串内容；无论成功失败，都会关闭桌面进程并删除测试凭据。

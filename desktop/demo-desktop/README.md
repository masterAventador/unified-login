# 统一登录桌面端

Tauri 2 示例应用。授权页只会由 Rust 调起系统默认浏览器，应用 WebView 只显示本地登录状态。
Refresh Token 保存在操作系统凭据库，Access Token 只存在于 Rust 进程内存。
认证协议、凭据生命周期、Tauri commands 和前端并发状态均来自 `unified-login-tauri` /
`@unified-login/tauri`；本应用只保留认证配置、单实例与窗口策略和 UI。
运行期间会在 Access Token 到期前静默轮换；应用限制为单实例，避免多个进程同时消费同一
Refresh Token。生产 issuer 必须使用 HTTPS，本地回环地址是唯一的 HTTP 例外。

## 本地校验

```bash
pnpm install --frozen-lockfile
pnpm test
pnpm typecheck
pnpm test:acceptance:unit
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

验收脚本只使用当前源码在 Cargo 实际目标目录的 `release/bundle/macos` 下生成的最终
生产 `.app`，不会构建或保留任何含测试驱动的应用变体。它通过只存在于临时目录的
原生 LaunchServices 启动器以 `visible=false` 隐藏启动真实应用，并记录本轮应用的精确
PID 供失败路径清理；验收通过应用自己的按钮、Tauri command、回环服务和系统凭据库验证：

- 伪造 `state` 的回调被拒绝，且不会留下凭据；
- headless 系统 Chrome 完成桌面端首次登录；
- 真实 Demo Web A 建立认证中心会话后，桌面端复用该会话且无需再次输入密码；
- 连续两次应用重启后都能用当轮 refresh token 恢复登录，证明轮换凭据已写回；
- 登出删除凭据，再次重启后需要登录。

真实应用仍调用系统默认浏览器打开授权地址；验收进程只在外部拦截该地址，交给 headless
Chrome 访问，不替换应用内的 OAuth 实现。另一个只存在于临时目录的 macOS 动态库探针
通过系统加载机制操作生产应用已有的隐藏 WKWebView；它不参与 Tauri 构建、不写入 `.app`，
也不改变生产二进制。各验收阶段使用动态空闲且带随机控制令牌的回环端口。隐藏窗口与独立
凭据条目只使用生产代码已有的运行参数读取路径，桌面 issuer 使用生产应用默认配置。

1. 在 `127.0.0.1:55432` 启动项目专用 PostgreSQL，容器名为
   `unified-login-e2e-postgres`。
2. 不要手工启动认证中心或其他前端服务；脚本会从当前分支构建并在后台管理认证中心与
   Demo Web A。
3. 复用本机已安装的 Google Chrome；不要执行 `playwright install`。

然后运行：

```bash
pnpm test:acceptance:headless
```

脚本不会弹出桌面窗口或浏览器窗口，也不会打印 OAuth code、令牌或钥匙串内容；每轮验收
使用独立的钥匙串 service，成功或失败都会关闭自己启动的进程并删除测试凭据。

Windows 安装包的真机复验步骤见
[`WINDOWS-TAURI-ACCEPTANCE.md`](../../docs/WINDOWS-TAURI-ACCEPTANCE.md)。

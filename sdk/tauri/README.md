# Unified Login Tauri SDK

这套 SDK 面向 Tauri 2 桌面应用，由同一目录中的 Rust crate 和
`@unified-login/tauri` TypeScript 包组成。SDK 不包含登录按钮、页面或窗口样式；每个产品
继续拥有自己的 UI，只复用认证协议、凭据生命周期和前端状态编排。

## SDK 负责什么

- 用系统默认浏览器发起 Authorization Code + PKCE 登录，并校验随机 `state`；
- 在随机 IPv4 回环端口接收一次回调，换取并刷新令牌；
- access token 只保存在 Rust 进程内存；
- refresh token 保存在 Windows Credential Manager、macOS 钥匙串或 Linux Secret
  Service，并在刷新轮换后写回；
- 启动恢复、过期刷新、旧凭据迁移、登出删除、并发登录/登出和结构化错误；
- 提供受 Tauri capability 保护的 `login`、`get_access_token`、`logout` 插件命令；
- TypeScript 层提供与 Web SDK 对齐的 `login`、`logout`、`getAccessToken`、
  `onAuthStateChange` 四个方法。

产品应用仍负责 `client_id`、issuer、scope、凭据 service 名称、单实例策略、窗口行为、
按钮和错误文案。桌面端是无法安全保存 client secret 的公有客户端，因此配置中没有
client secret；`client_id` 必须先由统一登录后端登记。

## Rust 接入

应用依赖本 crate 后，只需构造配置并注册插件：

```rust
use unified_login_tauri::auth::AuthConfig;
use unified_login_tauri::plugin::Builder as AuthPluginBuilder;

let config = AuthConfig::builder(
    "https://login.example.com",
    "registered-desktop-client",
    "com.example.product",
)
.scopes(["openid", "profile"])
.build();

tauri::Builder::default()
    .plugin(AuthPluginBuilder::from_config_result(config).build());
```

`from_config_result` 会把运行时配置错误转成稳定的 `configuration` 错误，不会让应用在
启动阶段 panic。应用需要在凭据被保存后的确切时机执行窗口策略时，可使用
`on_login_success`；回调只提供扩展点，不假定窗口标签或 UI。

同一凭据 service 不应由多个应用进程同时消费轮换 refresh token。应用应注册自己的
单实例插件，并自行决定第二实例到来时显示或聚焦哪个窗口。

## Capability

允许主窗口调用 SDK 默认命令：

```json
{
  "permissions": [
    "core:default",
    "unified-login-tauri:default"
  ]
}
```

## TypeScript 接入

安装 `@unified-login/tauri` 后，把 Tauri 的 `invoke` 注入客户端：

```ts
import { invoke } from '@tauri-apps/api/core'
import { TauriAuthClient } from '@unified-login/tauri'

const auth = new TauriAuthClient(invoke)
```

应用的 UI 只调用公开的四个方法，并按 `TauriAuthError.code` 区分需要重新登录、临时网络
故障和配置错误。SDK 不向普通配置文件写入任何明文 token。

## 校验

```bash
pnpm install --frozen-lockfile
pnpm test
pnpm typecheck
pnpm test:consumer

cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

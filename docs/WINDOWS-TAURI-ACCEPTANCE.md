# Windows Tauri 真机验收交接

## 1. 验收边界

这份清单只补 macOS 无法代替的 Windows 真机证据：MSI、Windows Credential
Manager、系统默认浏览器、WebView2、回环随机端口和 Windows 防火墙。

- 候选分支：`phase5-desktop`
- 只有本清单全部通过后，阶段五才能声明跨平台完成并合并 `main`
- 任一必验项失败都按 `BLOCKED` 上报，不要改成 `tauri dev`、明文凭据文件或内嵌
  WebView 绕过
- 不执行 `pnpm test:acceptance:headless`；该命令使用 AppKit、WKWebView 和 macOS
  动态库注入，只适用于 macOS
- 不执行 `playwright install`；本清单不需要下载浏览器
- 不部署任何环境

## 2. 证据安全

可以记录版本、命令结果、MSI SHA-256、界面状态和 Credential Manager 条目名称。
以下内容不得出现在截图、终端复制或问题报告中：

- 完整授权 URL（含 `state`、PKCE challenge 和回调参数）
- OAuth authorization code
- access token、refresh token、ID token
- Credential Manager 条目的密码/机密内容
- 测试账号的真实密码

## 3. 环境与候选提交

在 PowerShell 中进入仓库后执行：

```powershell
git fetch origin
git switch phase5-desktop
git pull --ff-only origin phase5-desktop
git status --short
git rev-parse HEAD

node --version
pnpm --version
rustc -Vv
cargo --version
java -version
docker version
winget list "Microsoft Edge WebView2 Runtime"
```

要求：

- `git status --short` 没有输出
- Rust host 是 `x86_64-pc-windows-msvc`，不是 GNU 工具链
- 已安装 Visual Studio C++ Build Tools、Windows SDK 和 WebView2 Runtime
- 记录 Windows 版本、默认浏览器及以上版本输出；若 `winget` 查不到 WebView2，
  从“设置 → 应用 → 已安装的应用”记录版本
- 开始前确认 `9000` 和 `55432` 没有被其他项目占用：

```powershell
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Where-Object LocalPort -In 9000, 55432
```

## 4. Windows 本机门禁与 MSI

```powershell
cd desktop\demo-desktop
$env:PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD = "1"

pnpm install --frozen-lockfile
pnpm test
pnpm typecheck
pnpm test:acceptance:unit

cd src-tauri
cargo fmt --all -- --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cd ..

Push-Location ..\..\sdk\tauri
cargo fmt --all -- --check
cargo test --locked
cargo test --locked --test system_credentials -- --ignored
cargo clippy --locked --all-targets -- -D warnings
Pop-Location

pnpm tauri build --bundles msi

$msi = Get-ChildItem .\src-tauri\target\release\bundle\msi\*.msi |
  Sort-Object LastWriteTime -Descending |
  Select-Object -First 1
$msi.FullName
Get-FileHash $msi.FullName -Algorithm SHA256
```

以上命令必须全部退出码为 0。保存 MSI 路径和 SHA-256，不要用 `pnpm tauri dev`
代替安装包。

## 5. 启动真实依赖

打开两个新的 PowerShell 窗口。

窗口 A 在仓库根目录以前台方式启动项目专用 PostgreSQL：

```powershell
docker run --rm --name unified-login-e2e-postgres `
  -e POSTGRES_DB=unified_login `
  -e POSTGRES_USER=unified_login `
  -e POSTGRES_PASSWORD=unified_login `
  -p 127.0.0.1:55432:5432 postgres:16-alpine
```

窗口 B 在 `auth-server` 目录构建并启动当前候选提交：

```powershell
$env:DB_URL = "jdbc:postgresql://127.0.0.1:55432/unified_login"
$env:DB_USERNAME = "unified_login"
$env:DB_PASSWORD = "unified_login"
$env:SERVER_ADDRESS = "127.0.0.1"

.\mvnw.cmd -DskipTests clean package
java -jar target\auth-server.jar
```

浏览器打开 `http://127.0.0.1:9000/.well-known/openid-configuration` 能看到 JSON
后再继续。认证中心和数据库都保持前台运行，便于最后用 `Ctrl+C` 精确停止。

## 6. 安装 release MSI

回到 `desktop\demo-desktop`：

```powershell
Start-Process msiexec.exe -Wait -ArgumentList '/i', "`"$($msi.FullName)`""
```

安装完成后只从 Windows 开始菜单启动“统一登录桌面端”。任务管理器中不得同时存在多个
应用实例；启动时不得弹出命令行窗口。

## 7. 必验场景

### A. 全新登录与系统浏览器

1. 若以前测过，先在应用内退出登录；再确认 Windows Credential Manager 中没有目标名称
   含 `com.aventador.unified-login.demo-desktop` 的通用凭据。
2. 从开始菜单启动应用，确认只显示本地登录状态，应用内没有账号、密码输入框或登录网页。
3. 点击登录，确认由 Windows **系统默认浏览器**打开认证中心。
4. 使用一次性测试账号完成注册/登录。
5. 浏览器回调页应显示“登录成功，可关闭此页”，应用显示“你已登录”。
6. 浏览器里不要复制地址栏完整 URL。

### B. 浏览器 SSO

1. 保持默认浏览器中的认证中心会话，不清 Cookie。
2. 在应用内退出登录，确认应用回到“需要登录”。
3. 再点登录，必须直接回调成功，不能再次要求输入密码。

### C. Credential Manager 与两次重启轮换

登录成功后执行：

```powershell
cmdkey /list |
  Select-String "com.aventador.unified-login.demo-desktop" -Context 2, 2
```

只记录目标名称，不打开或复制机密。要求：

1. 登录后存在一个匹配的通用凭据。
2. 完全退出应用，从开始菜单重开，应用自动恢复为已登录。
3. 再完全退出并重开一次，仍自动恢复为已登录；这验证第一次恢复写回的轮换 refresh
   token 可继续使用。
4. 应用配置目录、日志和普通文件中没有以 token、credential、secret 命名的明文凭据
   文件；Credential Manager 是唯一的持久凭据位置。

可用下面的只读命令定位可能的应用目录；不要把浏览器缓存或 Cookie 数据复制到报告：

```powershell
Get-ChildItem $env:APPDATA, $env:LOCALAPPDATA -Force -ErrorAction SilentlyContinue |
  Where-Object Name -Match "统一登录|demo-desktop|unified-login"
```

### D. 登出与缺失凭据降级

1. 在应用内退出登录。
2. 再运行上面的 `cmdkey /list` 检查，匹配凭据必须消失。
3. 完全退出并重开，应用显示“需要登录”，不得恢复已登录。
4. 再登录一次并完全退出应用。
5. 打开“控制面板 → 凭据管理器 → Windows 凭据 → 通用凭据”，删除目标名称含
   `com.aventador.unified-login.demo-desktop` 的测试条目。
6. 重开应用，必须优雅显示“需要登录”，不得崩溃、白屏或无限加载。

### E. 随机回环端口与防火墙

点击登录后、完成浏览器登录前，在 PowerShell 执行：

```powershell
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Where-Object LocalAddress -EQ "127.0.0.1" |
  Sort-Object LocalPort
```

要求：

- 桌面应用只在 `127.0.0.1` 的当轮随机高位端口监听回调，不监听 `0.0.0.0`
- 连续两轮登录的回调端口不同
- 不需要开放公网入站，不应弹出要求允许公网访问的 Windows 防火墙对话框
- 若意外出现防火墙对话框，先拒绝；应用必须在有界时间内显示可重试失败，不能永久卡住，
  并把这一项按 `BLOCKED` 上报

## 8. 结果回填

复制下面模板回填；不要附完整授权 URL 或任何 token：

```text
Windows Tauri 验收
- 候选 commit:
- Windows 版本:
- 默认浏览器及版本:
- WebView2 版本:
- rustc host / 版本:
- MSI 文件名:
- MSI SHA-256:

门禁
- pnpm install --frozen-lockfile: PASS / FAIL
- pnpm test: PASS / FAIL
- pnpm typecheck: PASS / FAIL
- pnpm test:acceptance:unit: PASS / FAIL
- cargo fmt/test/clippy: PASS / FAIL
- pnpm tauri build --bundles msi: PASS / FAIL

真实场景
- release MSI 安装并从开始菜单启动: PASS / FAIL
- 无命令行窗口、无内嵌登录页: PASS / FAIL
- 系统默认浏览器首次登录: PASS / FAIL
- 浏览器已有会话时 SSO 免输密码: PASS / FAIL
- Credential Manager 存在且普通文件无明文凭据: PASS / FAIL
- 第一次重启恢复并轮换: PASS / FAIL
- 第二次重启使用轮换凭据恢复: PASS / FAIL
- 应用登出删除凭据: PASS / FAIL
- 删除凭据后优雅降级: PASS / FAIL
- 127.0.0.1 随机端口且无公网防火墙放行: PASS / FAIL

失败信息（仅 FAIL 时）:
- 失败步骤:
- 预期:
- 实际:
- 已脱敏日志/截图:
```

任一项为 `FAIL` 时不要自行改代码或换测试路径，直接回传模板并标记 `BLOCKED`。

### 2026-08-01 实机结果

```text
Windows Tauri 验收
- 候选 commit: b77e4dd4d4fb0afa8efa731b02cb80c7ca5c2bdf
- 构建工作树: F:\\unified-login-msi-b77e4dd（从候选 commit 的 bundle 全新克隆，构建前后 git status 均为空）
- Windows 版本: Windows 11 Home 10.0.26200（build 26200）
- 默认浏览器及版本: Google Chrome 150.0.7871.187（ChromeHTML）
- WebView2 版本: 150.0.4078.105
- rustc host / 版本: rustc 1.96.1 / x86_64-pc-windows-msvc
- MSI 文件名: 统一登录桌面端_0.1.0_x64_zh-CN.msi
- MSI SHA-256: D943F76E2CDC8D05B094F6CF832A2454E4948249945832E4DC97741AC95375D2

门禁
- pnpm install --frozen-lockfile: PASS
- pnpm test: PASS（31/31）
- pnpm typecheck: PASS
- pnpm test:acceptance:unit: PASS（22/22）
- 桌面壳 cargo fmt/test/clippy: PASS（Rust 10/10）
- Tauri SDK cargo fmt/test/clippy: PASS（常规 Rust 55/55；Credential Manager 实机用例默认忽略）
- Tauri SDK Credential Manager 实机往返: PASS（1/1；结束后临时凭据条目 0）
- pnpm tauri build --bundles msi: PASS
- 项目级 Playwright 真实 Chrome E2E: PASS（19/19）

真实场景
- release MSI 安装并从开始菜单启动: PASS
- 无命令行窗口、无内嵌登录页: PASS
- 系统默认浏览器首次登录: PASS
- 浏览器已有会话时 SSO 免输密码: PASS
- Credential Manager 存在且普通文件无明文凭据: PASS
- 第一次重启恢复并轮换: PASS
- 第二次重启使用轮换凭据恢复: PASS
- 应用登出删除凭据: PASS
- 删除凭据后优雅降级: PASS
- 127.0.0.1 随机端口且无公网防火墙放行: PASS
```

补充说明：验收通过 SSH 驱动登录用户的交互式计划任务执行。远程会话无法提供可截取的
Chrome 顶层窗口，因此默认浏览器这一项采用三组互相独立的证据闭环：Windows 默认浏览器
关联为 ChromeHTML；应用点击登录后出现非 headless 的默认 Chrome 进程；进程收到的授权
请求经脱敏脚本验证包含候选应用生成的 client、随机 `state`、PKCE 和回环地址。注册、密码
登录、回调成功页与保留 Cookie 后的零次登录页跳转，则在同一台真机、同版本 Chrome 和从
上述干净工作树构建、重装的 release 应用上完成。该限制只影响远程桌面截图，不影响默认
浏览器调用或 OAuth 行为证据。

另外确认：安装目录为 `C:\Program Files\统一登录桌面端\`，开始菜单快捷方式可启动且
应用保持单实例；运行期间没有控制台子进程、没有新增启用的 Windows 防火墙规则、没有监听
`0.0.0.0`，应用数据目录中没有以 token、credential 或 secret 命名的明文凭据文件。最终
项目级 E2E 另在 `b77e4dd` 的全新 F 盘副本上启动全部生产构建服务并使用系统 Chrome
无头通道执行，19 项全部通过；结束后 9000、9001、19001、5173、5174、5175、5274、
8000 与 55432 均已释放。

## 9. 收尾

1. 应用内退出登录，确认测试凭据已删除。
2. 关闭桌面应用和默认浏览器中的测试页。
3. 在认证中心窗口按 `Ctrl+C`。
4. 在数据库窗口按 `Ctrl+C`；`--rm` 会删除本轮容器。
5. 确认端口释放：

```powershell
Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
  Where-Object LocalPort -In 9000, 55432
```

6. 不再保留 MSI 时，可从“设置 → 应用 → 已安装的应用”卸载“统一登录桌面端”。

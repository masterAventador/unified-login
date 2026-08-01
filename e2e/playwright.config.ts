import { defineConfig } from '@playwright/test'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'

const authServerDirectory = fileURLToPath(new URL('../auth-server/', import.meta.url))
const adminWebDirectory = fileURLToPath(new URL('../admin-web/', import.meta.url))
const demoADirectory = fileURLToPath(new URL('../demo/demo-web-a/', import.meta.url))
const demoBDirectory = fileURLToPath(new URL('../demo/demo-web-b/', import.meta.url))
const demoApiFrontendDirectory = fileURLToPath(
  new URL('../demo/demo-api/frontend/', import.meta.url),
)
const e2eDirectory = fileURLToPath(new URL('./', import.meta.url))
const mavenWrapper = process.platform === 'win32' ? 'mvnw.cmd' : './mvnw'

export const authServerWebServer = {
  name: '认证中心',
  command: `${mavenWrapper} -DskipTests clean package && java -jar target/auth-server.jar`,
  cwd: authServerDirectory,
  env: {
    DB_URL: 'jdbc:postgresql://127.0.0.1:55432/unified_login',
    DB_USERNAME: 'unified_login',
    DB_PASSWORD: 'unified_login',
    SERVER_ADDRESS: '127.0.0.1',
    ADMIN_WEB_REDIRECT_URI: 'http://localhost:5175/callback',
    // 整套并行 E2E 都从同一个回环地址登录，不能让用例彼此消耗生产默认的每 IP 额度。
    // 生产配置仍保持 20；这里只有受管测试进程显式提高阈值。
    UNIFIED_LOGIN_LOGIN_RATE_LIMIT_MAX_ATTEMPTS_PER_IP_PER_MINUTE: '1000',
  },
  url: 'http://127.0.0.1:9000/.well-known/openid-configuration',
  timeout: 120_000,
  reuseExistingServer: false,
  gracefulShutdown: { signal: 'SIGTERM' as const, timeout: 10_000 },
}

export const adminWebServer = {
  name: '账号管理后台',
  command: 'pnpm build && pnpm exec vite preview --host 127.0.0.1',
  cwd: adminWebDirectory,
  // preview 与 Node 健康探针直接走 IPv4；浏览器仍保留 localhost Origin，
  // 再由下方 Chrome 参数固定解析到同一个受管 IPv4 服务。
  url: 'http://127.0.0.1:5175',
  timeout: 60_000,
  reuseExistingServer: false,
  gracefulShutdown: { signal: 'SIGTERM' as const, timeout: 5_000 },
}

export const demoApiWebServer = {
  name: 'Demo API',
  // 同步依赖时保留开发机代理，仅在启动本地 API 子进程时清除。
  command: 'node scripts/start-demo-api.mjs',
  cwd: e2eDirectory,
  env: {
    ALLOWED_ORIGINS: 'http://127.0.0.1:5274',
    ISSUER_URL: 'http://127.0.0.1:9001',
    RESOURCE_AUDIENCE: 'demo-api',
    UV_CACHE_DIR: join(tmpdir(), 'unified-login-uv-cache'),
  },
  url: 'http://127.0.0.1:8000/public',
  timeout: 60_000,
  reuseExistingServer: false,
  gracefulShutdown: { signal: 'SIGTERM' as const, timeout: 5_000 },
}

export const browserLoopbackArguments = [
  '--host-resolver-rules=MAP localhost 127.0.0.1',
]

export default defineConfig({
  testDir: './tests',
  timeout: 60_000,
  webServer: [
    authServerWebServer,
    {
      name: 'Demo Web A',
      command: 'pnpm build && pnpm preview',
      cwd: demoADirectory,
      url: 'http://127.0.0.1:5173',
      timeout: 60_000,
      reuseExistingServer: false,
      gracefulShutdown: { signal: 'SIGTERM', timeout: 5_000 },
    },
    {
      name: 'Demo Web B',
      command: 'pnpm build && pnpm preview',
      cwd: demoBDirectory,
      url: 'http://127.0.0.1:5174',
      timeout: 60_000,
      reuseExistingServer: false,
      gracefulShutdown: { signal: 'SIGTERM', timeout: 5_000 },
    },
    adminWebServer,
    {
      name: '资源验收认证中心',
      command: 'node scripts/resource-auth-server.mjs',
      cwd: e2eDirectory,
      url: 'http://127.0.0.1:19001/health',
      timeout: 60_000,
      reuseExistingServer: false,
      gracefulShutdown: { signal: 'SIGTERM', timeout: 10_000 },
    },
    demoApiWebServer,
    {
      name: 'Demo API 浏览器客户端',
      command: 'pnpm build && pnpm preview',
      cwd: demoApiFrontendDirectory,
      url: 'http://127.0.0.1:5274',
      timeout: 60_000,
      reuseExistingServer: false,
      gracefulShutdown: { signal: 'SIGTERM', timeout: 5_000 },
    },
  ],
  use: {
    // 复用本机已安装的 Google Chrome，不下载独立 Chromium
    channel: 'chrome',
    headless: true,
    baseURL: 'http://localhost:5173',
    // 浏览器地址继续使用 OAuth 注册的 localhost，同站 Cookie 语义不变；
    // 但连接固定落到受管 IPv4 服务，避免 Windows 命中残留的 ::1 进程。
    launchOptions: { args: browserLoopbackArguments },
  },
})

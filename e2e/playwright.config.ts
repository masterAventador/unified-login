import { defineConfig } from '@playwright/test'
import { fileURLToPath } from 'node:url'

const authServerDirectory = fileURLToPath(new URL('../auth-server/', import.meta.url))
const demoADirectory = fileURLToPath(new URL('../demo/demo-web-a/', import.meta.url))
const demoBDirectory = fileURLToPath(new URL('../demo/demo-web-b/', import.meta.url))
const mavenWrapper = process.platform === 'win32' ? 'mvnw.cmd' : './mvnw'

export default defineConfig({
  testDir: './tests',
  timeout: 60_000,
  webServer: [
    {
      name: '认证中心',
      command: `${mavenWrapper} -DskipTests clean package && java -jar target/auth-server.jar`,
      cwd: authServerDirectory,
      env: {
        DB_URL: 'jdbc:postgresql://127.0.0.1:55432/unified_login',
        DB_USERNAME: 'unified_login',
        DB_PASSWORD: 'unified_login',
        SERVER_ADDRESS: '127.0.0.1',
      },
      url: 'http://127.0.0.1:9000/.well-known/openid-configuration',
      timeout: 120_000,
      reuseExistingServer: false,
      gracefulShutdown: { signal: 'SIGTERM', timeout: 10_000 },
    },
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
  ],
  use: {
    // 复用本机已安装的 Google Chrome，不下载独立 Chromium
    channel: 'chrome',
    headless: true,
    baseURL: 'http://localhost:5173',
  },
})

import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: './tests',
  timeout: 60_000,
  use: {
    // 复用本机已安装的 Google Chrome，不下载独立 Chromium
    channel: 'chrome',
    headless: true,
    baseURL: 'http://localhost:5173',
  },
})

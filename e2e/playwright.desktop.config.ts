import { defineConfig } from '@playwright/test'

import baseConfig, { authServerWebServer } from './playwright.config'

export default defineConfig({
  ...baseConfig,
  testMatch: 'desktop-oauth.spec.ts',
  webServer: [authServerWebServer],
})

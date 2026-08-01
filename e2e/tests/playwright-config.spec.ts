import { expect, test } from '@playwright/test'

import {
  adminWebServer,
  authServerWebServer,
  browserLoopbackArguments,
  demoApiWebServer,
} from '../playwright.config'
import { ADMIN_BASE } from './support/auth'

test('并行 E2E 不共享生产环境的回环 IP 登录限流额度', () => {
  expect(
    authServerWebServer.env
      .UNIFIED_LOGIN_LOGIN_RATE_LIMIT_MAX_ATTEMPTS_PER_IP_PER_MINUTE,
  ).toBe('1000')
})

test('Windows 上的浏览器 localhost 固定解析到受管的 IPv4 服务', () => {
  expect(adminWebServer.command).toContain('vite preview --host 127.0.0.1')
  expect(adminWebServer.url).toBe('http://127.0.0.1:5175')
  expect(ADMIN_BASE).toBe('http://localhost:5175')
  expect(authServerWebServer.env.ADMIN_WEB_REDIRECT_URI).toBe(
    `${ADMIN_BASE}/callback`,
  )
  expect(browserLoopbackArguments).toContain(
    '--host-resolver-rules=MAP localhost 127.0.0.1',
  )
})

test('Demo API 通过两阶段脚本安装依赖并启动服务', () => {
  expect(demoApiWebServer.command).toBe('node scripts/start-demo-api.mjs')
})

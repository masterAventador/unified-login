import { expect, test } from '@playwright/test'

import { authServerWebServer } from '../playwright.config'

test('并行 E2E 不共享生产环境的回环 IP 登录限流额度', () => {
  expect(
    authServerWebServer.env
      .UNIFIED_LOGIN_LOGIN_RATE_LIMIT_MAX_ATTEMPTS_PER_IP_PER_MINUTE,
  ).toBe('1000')
})

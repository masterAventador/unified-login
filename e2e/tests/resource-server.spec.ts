import { expect, test } from '@playwright/test'

import { PASSWORD, uniqueEmail } from './support/auth'

test.describe.configure({ retries: 1 })

const RESOURCE_AUTH_BASE = 'http://127.0.0.1:9001'
const RESOURCE_AUTH_MANAGER_BASE = 'http://127.0.0.1:19001'
const RESOURCE_CLIENT_BASE = 'http://127.0.0.1:5274'
const RESOURCE_API_BASE = 'http://127.0.0.1:8000'

interface ApiResult {
  readonly status: number
  readonly body: unknown
}

function tokenSubject(accessToken: string): string {
  const encodedClaims = accessToken.split('.')[1]
  if (encodedClaims === undefined) {
    throw new Error('访问令牌格式无效')
  }
  const claims: unknown = JSON.parse(
    Buffer.from(encodedClaims, 'base64url').toString('utf8'),
  )
  if (
    typeof claims !== 'object'
    || claims === null
    || typeof (claims as Record<string, unknown>).sub !== 'string'
  ) {
    throw new Error('访问令牌缺少 sub')
  }
  return (claims as Record<string, string>).sub
}

test('真实令牌在认证中心停机后仍能访问 demo-api', async ({ page, request }) => {
  const email = uniqueEmail()
  const startResponse = await request.post(`${RESOURCE_AUTH_MANAGER_BASE}/start`)
  expect(startResponse.status()).toBe(204)

  await page.goto(`${RESOURCE_AUTH_BASE}/register`)
  await page.fill('#email', email)
  await page.fill('#password', PASSWORD)
  await page.click('button[type="submit"]')
  await expect(page.getByTestId('login-registered')).toBeVisible()

  await page.goto(RESOURCE_CLIENT_BASE)
  await expect(page).toHaveURL(/^http:\/\/127\.0\.0\.1:9001\/login/)
  await page.fill('#username', email)
  await page.fill('#password', PASSWORD)
  const tokenResponsePromise = page.waitForResponse((response) => {
    const url = new URL(response.url())
    return (
      url.origin === RESOURCE_AUTH_BASE
      && url.pathname === '/oauth2/token'
      && response.request().method() === 'POST'
    )
  })
  await page.click('button[type="submit"]')

  const tokenResponse = await tokenResponsePromise
  expect(tokenResponse.status()).toBe(200)
  const tokenPayload = await tokenResponse.json() as Record<string, unknown>
  expect(typeof tokenPayload.access_token).toBe('string')
  const accessToken = tokenPayload.access_token as string
  const expectedSubject = tokenSubject(accessToken)
  await expect(page.getByTestId('signed-in-user')).toHaveText(`已登录：${email}`)

  const withoutToken = await page.evaluate(async (url): Promise<ApiResult> => {
    const response = await fetch(`${url}/protected`)
    return { status: response.status, body: await response.json() }
  }, RESOURCE_API_BASE)
  expect(withoutToken.status).toBe(401)

  const stopResponse = await request.post(`${RESOURCE_AUTH_MANAGER_BASE}/stop`)
  expect(stopResponse.status()).toBe(204)
  await expect.poll(
    async () => {
      try {
        await request.get(
          `${RESOURCE_AUTH_BASE}/.well-known/openid-configuration`,
          { timeout: 500 },
        )
        return 'online'
      }
      catch {
        return 'offline'
      }
    },
    { timeout: 10_000 },
  ).toBe('offline')

  const firstProtectedRequestAfterShutdown = await page.evaluate(
    async ({ url, token }): Promise<ApiResult> => {
      const response = await fetch(`${url}/protected`, {
        headers: { Authorization: `Bearer ${token}` },
      })
      return { status: response.status, body: await response.json() }
    },
    { url: RESOURCE_API_BASE, token: accessToken },
  )
  expect(firstProtectedRequestAfterShutdown.status).toBe(200)
  expect(firstProtectedRequestAfterShutdown.body).toEqual({
    sub: expectedSubject,
    email,
  })
})

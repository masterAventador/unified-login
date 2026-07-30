import { expect, type Page } from '@playwright/test'

export const AUTH_BASE = 'http://localhost:9000'
export const DEMO_A_BASE = 'http://localhost:5173'
export const DEMO_B_BASE = 'http://localhost:5174'
export const ADMIN_BASE = 'http://localhost:5175'
export const PASSWORD = 'a valid password'

export interface TokenEndpointPayload {
  readonly accessToken: string
  readonly refreshToken: string
}

export function uniqueEmail(): string {
  return `e2e-${Date.now()}-${Math.floor(Math.random() * 10000)}@example.com`
}

/**
 * 服务端邮箱正则只禁 `@` 与空白，尖括号一路放行，因此这是一个能真正落库的邮箱。
 * 页面若把它当 HTML 拼进去，`<img>` 会被解析成真实元素。
 */
export function htmlInjectionEmail(): string {
  return `<img/src=x>${Date.now()}-${Math.floor(Math.random() * 10000)}@example.com`
}

/** 读取当前页面表单里的 CSRF 令牌。 */
async function csrfToken(page: Page): Promise<string> {
  return page.locator('input[name="_csrf"]').first().inputValue()
}

/**
 * 绕开浏览器表单控件直接提交注册。
 *
 * 登录页与注册页的输入框是 `type="email"`，浏览器自带的客户端校验会拦下含尖括号的邮箱；
 * 而客户端校验只是个提示，攻击者用任意 HTTP 客户端就能跳过。这里走的是同一个服务端端点，
 * 只是不经过那层提示——正是真实攻击者的做法。请求共用页面的 cookie，会话是连续的。
 */
export async function registerDirectly(page: Page, email: string): Promise<void> {
  await page.goto(`${AUTH_BASE}/register`)
  const response = await page.request.post(`${AUTH_BASE}/register`, {
    form: { email, password: PASSWORD, _csrf: await csrfToken(page) },
  })
  // 注册被拒时控制器会重新渲染注册页（同样是 200），只有落到 /login?registered 才代表真的入库了
  expect(response.url()).toContain('/login?registered')
}

/** 同上，直接提交登录表单。 */
export async function loginDirectly(
  page: Page,
  email: string,
  password = PASSWORD,
): Promise<void> {
  await page.goto(`${AUTH_BASE}/login`)
  const response = await page.request.post(`${AUTH_BASE}/login`, {
    form: { username: email, password, _csrf: await csrfToken(page) },
  })
  // 登录失败同样是 200（重新渲染登录页），只有落到 /login?error 之外才算成功。
  // 不断言的话，登录静默失败只会表现为后面某个 toBeVisible() 超时，排查时看不出真正原因
  expect(response.url()).not.toContain('/login?error')
}

export async function registerThroughUi(page: Page, email: string): Promise<void> {
  await page.goto(`${AUTH_BASE}/register`)
  await page.fill('#email', email)
  await page.fill('#password', PASSWORD)
  await page.click('button[type="submit"]')
  await expect(page.getByTestId('login-registered')).toBeVisible()
}

export async function loginDemoA(page: Page, email: string): Promise<void> {
  await page.goto(DEMO_A_BASE)
  await page.getByTestId('login-button').click()
  await page.waitForURL(/\/login/)
  await page.fill('#username', email)
  await page.fill('#password', PASSWORD)
  await page.click('button[type="submit"]')
  await page.waitForURL(`${DEMO_A_BASE}/**`)
  await expect(page.getByTestId('signed-in-user')).toHaveText(`已登录：${email}`)
}

export async function loginDemoB(
  page: Page,
  email: string,
  password = PASSWORD,
): Promise<TokenEndpointPayload> {
  await page.goto(DEMO_B_BASE)
  await page.waitForURL(/^http:\/\/localhost:9000\/login/)
  await page.fill('#username', email)
  await page.fill('#password', password)
  const tokenResponsePromise = waitForTokenResponse(page, 'authorization_code')
  await page.click('button[type="submit"]')
  const tokens = await tokenPayload(await tokenResponsePromise)
  await expect(page.getByTestId('signed-in-user')).toHaveText(`已登录：${email}`)
  return tokens
}

export async function loginAdminWeb(
  page: Page,
  email: string,
  password = PASSWORD,
): Promise<TokenEndpointPayload> {
  await page.goto(ADMIN_BASE)
  await expect(page.getByTestId('admin-login')).toBeVisible()
  await page.getByTestId('admin-login').click()
  await page.waitForURL(/^http:\/\/localhost:9000\/login/)
  await page.fill('#username', email)
  await page.fill('#password', password)
  const tokenResponsePromise = waitForTokenResponse(page, 'authorization_code')
  await page.click('button[type="submit"]')
  return tokenPayload(await tokenResponsePromise)
}

export async function expectLoginRejected(
  page: Page,
  email: string,
  password: string,
): Promise<void> {
  await page.goto(`${AUTH_BASE}/login`)
  await page.fill('#username', email)
  await page.fill('#password', password)
  await page.click('button[type="submit"]')
  await expect(page.getByTestId('login-error')).toHaveText('邮箱或密码不正确')
}

export function waitForTokenResponse(
  page: Page,
  grantType: 'authorization_code' | 'refresh_token',
) {
  return page.waitForResponse((response) => {
    const request = response.request()
    const requestBody = new URLSearchParams(request.postData() ?? '')
    const url = new URL(response.url())
    return url.origin === AUTH_BASE
      && url.pathname === '/oauth2/token'
      && request.method() === 'POST'
      && requestBody.get('grant_type') === grantType
  })
}

export async function expectRefreshRejected(
  page: Page,
  clientId: string,
  refreshToken: string,
): Promise<void> {
  const response = await page.request.post(`${AUTH_BASE}/oauth2/token`, {
    form: {
      grant_type: 'refresh_token',
      client_id: clientId,
      refresh_token: refreshToken,
    },
  })
  expect(response.status()).toBe(400)
  const payload = await response.json() as Record<string, unknown>
  expect(payload).toMatchObject({ error: 'invalid_grant' })
  expect(payload).not.toHaveProperty('access_token')
  expect(payload).not.toHaveProperty('refresh_token')
}

async function tokenPayload(response: Awaited<ReturnType<typeof waitForTokenResponse>>)
  : Promise<TokenEndpointPayload> {
  expect(response.status()).toBe(200)
  const payload = await response.json() as Record<string, unknown>
  expect(typeof payload.access_token).toBe('string')
  expect(typeof payload.refresh_token).toBe('string')
  return {
    accessToken: payload.access_token as string,
    refreshToken: payload.refresh_token as string,
  }
}

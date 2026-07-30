import { expect, test } from '@playwright/test'

import {
  AUTH_BASE,
  DEMO_B_BASE,
  htmlInjectionEmail,
  loginDirectly,
  loginDemoA,
  registerDirectly,
  registerThroughUi,
  uniqueEmail,
} from './support/auth'

test('在 A 登录后打开 B 不出现登录页，直接显示同一用户', async ({ context, page }) => {
  const email = uniqueEmail()
  await registerThroughUi(page, email)
  await loginDemoA(page, email)

  const productB = await context.newPage()
  const authorizationRequests: URL[] = []
  const topLevelLoginUrls: string[] = []
  productB.on('request', (request) => {
    const requestUrl = new URL(request.url())
    if (
      requestUrl.origin === AUTH_BASE
      && requestUrl.pathname === '/oauth2/authorize'
    ) {
      authorizationRequests.push(requestUrl)
    }
  })
  productB.on('framenavigated', (frame) => {
    const frameUrl = new URL(frame.url())
    if (
      frame === productB.mainFrame()
      && frameUrl.origin === AUTH_BASE
      && frameUrl.pathname === '/login'
    ) {
      topLevelLoginUrls.push(frame.url())
    }
  })

  await productB.goto(DEMO_B_BASE)

  await expect(productB.getByTestId('signed-in-user')).toHaveText(`已登录：${email}`)
  expect(topLevelLoginUrls).toEqual([])
  expect(authorizationRequests.some(
    (requestUrl) => requestUrl.searchParams.get('prompt') === 'none',
  )).toBe(true)
})

test('B 刷新页面后通过新的静默续签保持登录', async ({ context, page }) => {
  const email = uniqueEmail()
  await registerThroughUi(page, email)
  await loginDemoA(page, email)

  const productB = await context.newPage()
  const authorizationRequests: URL[] = []
  productB.on('request', (request) => {
    const requestUrl = new URL(request.url())
    if (
      requestUrl.origin === AUTH_BASE
      && requestUrl.pathname === '/oauth2/authorize'
    ) {
      authorizationRequests.push(requestUrl)
    }
  })
  await productB.goto(DEMO_B_BASE)
  await expect(productB.getByTestId('signed-in-user')).toHaveText(`已登录：${email}`)
  const requestsBeforeReload = authorizationRequests.length

  await productB.reload()

  await expect(productB.getByTestId('signed-in-user')).toHaveText(`已登录：${email}`)
  expect(authorizationRequests.length).toBeGreaterThan(requestsBeforeReload)
  expect(authorizationRequests.at(-1)?.searchParams.get('prompt')).toBe('none')
})

test('A 登出只清 A 的登录态，B 刷新后仍保持登录', async ({ context, page }) => {
  const email = uniqueEmail()
  await registerThroughUi(page, email)
  await loginDemoA(page, email)

  const productB = await context.newPage()
  await productB.goto(DEMO_B_BASE)
  await expect(productB.getByTestId('signed-in-user')).toHaveText(`已登录：${email}`)

  await page.getByTestId('logout-button').click()
  await expect(page.getByTestId('login-button')).toBeVisible()

  await productB.reload()
  await expect(productB.getByTestId('signed-in-user')).toHaveText(`已登录：${email}`)
})

test('认证中心会话失效后刷新 B 会进入登录页而不是无限等待', async ({ context, page }) => {
  const email = uniqueEmail()
  await registerThroughUi(page, email)
  await loginDemoA(page, email)

  const productB = await context.newPage()
  await productB.goto(DEMO_B_BASE)
  await expect(productB.getByTestId('signed-in-user')).toHaveText(`已登录：${email}`)
  expect((await context.cookies(AUTH_BASE)).some(
    (cookie) => cookie.name === 'AUTH_SESSION',
  )).toBe(true)

  await context.clearCookies({ name: 'AUTH_SESSION' })
  expect((await context.cookies(AUTH_BASE)).some(
    (cookie) => cookie.name === 'AUTH_SESSION',
  )).toBe(false)
  await productB.reload()

  await expect(productB).toHaveURL(
    /^http:\/\/localhost:9000\/login(?:[?#].*)?$/,
    { timeout: 15_000 },
  )
  await expect(productB.locator('#username')).toBeVisible()
})

test('B 交互登录成功后离开回调路径，会话失效时仍能重新进入登录页', async ({ context, page }) => {
  const email = uniqueEmail()
  await registerThroughUi(page, email)

  await page.goto(DEMO_B_BASE)
  await expect(page).toHaveURL(/^http:\/\/localhost:9000\/login(?:[?#].*)?$/)
  await page.locator('#username').fill(email)
  await page.locator('#password').fill('a valid password')
  await page.locator('button[type="submit"]').click()

  await expect(page.getByTestId('signed-in-user')).toHaveText(`已登录：${email}`)
  await expect(page).toHaveURL(`${DEMO_B_BASE}/`)

  await context.clearCookies({ name: 'AUTH_SESSION' })
  await page.reload()

  await expect(page).toHaveURL(
    /^http:\/\/localhost:9000\/login(?:[?#].*)?$/,
    { timeout: 15_000 },
  )
  await expect(page.locator('#username')).toBeVisible()
})

test('B 只在成功处理顶层回调后规范化地址', async ({ page }) => {
  await page.goto(`${DEMO_B_BASE}/callback?code=forged-code&state=forged-state`)

  await expect(page.getByTestId('auth-error')).toHaveText('回调缺少必要参数')
  await expect(page).toHaveURL(`${DEMO_B_BASE}/callback`)
})

test('B 把令牌中的攻击性邮箱按原始文本显示，不创建注入元素', async ({ page }) => {
  const email = htmlInjectionEmail()
  await registerDirectly(page, email)
  await loginDirectly(page, email)

  await page.goto(DEMO_B_BASE)

  await expect(page.getByTestId('signed-in-user')).toHaveText(`已登录：${email}`)
  await expect(page.locator('#app img')).toHaveCount(0)
})

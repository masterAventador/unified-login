import { expect, test, type BrowserContext, type Page } from '@playwright/test'

import {
  ADMIN_BASE,
  AUTH_BASE,
  PASSWORD,
  expectLoginRejected,
  expectRefreshRejected,
  loginAdminWeb,
  loginDemoB,
  loginDirectly,
  registerThroughUi,
  uniqueEmail,
  waitForTokenResponse,
} from './support/auth'
import { promoteToPlatformAdmin } from './support/database'

const RESET_PASSWORD = 'a replacement password'

test.describe.serial('阶段四账号失效真实链路', () => {
  let managementContext: BrowserContext
  let managementPage: Page
  let managementAdminEmail: string
  let ordinaryContext: BrowserContext | undefined

  test.beforeAll(async ({ browser }) => {
    managementContext = await browser.newContext()
    managementPage = await managementContext.newPage()
    managementAdminEmail = uniqueEmail()
    await registerThroughUi(managementPage, managementAdminEmail)
    promoteToPlatformAdmin(managementAdminEmail)
    await loginAdminWeb(managementPage, managementAdminEmail)
    await expect(managementPage.getByTestId('email-filter')).toBeVisible()
  })

  test.afterAll(async () => {
    await ordinaryContext?.close()
    await managementContext.close()
  })

  test('用户改密后另一浏览器续期被拒并被迫重新登录', async ({ browser }) => {
    const email = uniqueEmail()
    const setupContext = await browser.newContext()
    const setupPage = await setupContext.newPage()
    await registerThroughUi(setupPage, email)
    promoteToPlatformAdmin(email)
    await setupContext.close()

    const deviceContext = await browser.newContext()
    const devicePage = await deviceContext.newPage()
    await devicePage.clock.install()
    const deviceTokens = await loginAdminWeb(devicePage, email)
    await expect(devicePage.getByTestId('email-filter')).toBeVisible()

    const passwordContext = await browser.newContext()
    const passwordPage = await passwordContext.newPage()
    await loginDirectly(passwordPage, email)
    await passwordPage.goto(`${AUTH_BASE}/account/password`)
    await passwordPage.fill('#currentPassword', PASSWORD)
    await passwordPage.fill('#newPassword', RESET_PASSWORD)
    await passwordPage.click('button[type="submit"]')
    await expect(passwordPage.getByTestId('password-change-success')).toBeVisible()

    await devicePage.clock.fastForward(14 * 60 * 1000 + 1_000)
    const refreshResponsePromise = waitForTokenResponse(devicePage, 'refresh_token')
    await devicePage.getByRole('button', { name: '查询' }).click()
    const refreshResponse = await refreshResponsePromise
    expect(refreshResponse.status()).toBe(400)
    expect(await refreshResponse.json()).toMatchObject({ error: 'invalid_grant' })
    await expect(devicePage.getByTestId('admin-login')).toBeVisible()

    await passwordContext.close()
    await deviceContext.close()
    expect(deviceTokens.refreshToken).not.toBe('')
  })

  test('管理员禁用账号后登录与旧 refresh token 同时失效', async ({ browser }) => {
    const email = uniqueEmail()
    const targetContext = await browser.newContext()
    const targetPage = await targetContext.newPage()
    await registerThroughUi(targetPage, email)
    const targetTokens = await loginDemoB(targetPage, email)

    await filterManagementTable(email)
    const row = managementPage.locator('tr').filter({ hasText: email })
    await expect(row).toHaveCount(1)
    await row.getByTestId('disable-user').click()
    await expect(row).toContainText('已禁用')

    await expectRefreshRejected(
      targetPage,
      'demo-web-b',
      targetTokens.refreshToken,
    )
    const rejectedContext = await browser.newContext()
    await expectLoginRejected(
      await rejectedContext.newPage(),
      email,
      PASSWORD,
    )

    await rejectedContext.close()
    await targetContext.close()
  })

  test('管理员重置密码后仅新密码可登录且旧 refresh token 失效', async ({ browser }) => {
    const email = uniqueEmail()
    const targetContext = await browser.newContext()
    const targetPage = await targetContext.newPage()
    await registerThroughUi(targetPage, email)
    const targetTokens = await loginDemoB(targetPage, email)

    await filterManagementTable(email)
    const row = managementPage.locator('tr').filter({ hasText: email })
    const resetResponsePromise = managementPage.waitForResponse((response) => (
      response.request().method() === 'POST'
      && new URL(response.url()).pathname.endsWith('/reset-password')
    ))
    managementPage.once('dialog', async (dialog) => {
      await dialog.accept(RESET_PASSWORD)
    })
    await row.getByTestId('reset-password').click()
    expect((await resetResponsePromise).status()).toBe(204)

    await expectRefreshRejected(
      targetPage,
      'demo-web-b',
      targetTokens.refreshToken,
    )
    const oldPasswordContext = await browser.newContext()
    await expectLoginRejected(
      await oldPasswordContext.newPage(),
      email,
      PASSWORD,
    )
    await oldPasswordContext.close()

    const newPasswordContext = await browser.newContext()
    await loginDemoB(
      await newPasswordContext.newPage(),
      email,
      RESET_PASSWORD,
    )
    ordinaryContext = newPasswordContext
    await targetContext.close()
  })

  test('普通用户进入管理后台稳定显示无权限并可切换账号', async () => {
    if (ordinaryContext === undefined) {
      throw new Error('上一条用例未准备已登录的普通用户上下文')
    }
    const page = await ordinaryContext.newPage()
    await page.goto(ADMIN_BASE)

    await expect(page.getByTestId('forbidden')).toContainText('无权限')
    const authorizationRequestPromise = page.waitForRequest((request) => {
      const url = new URL(request.url())
      return url.origin === AUTH_BASE
        && url.pathname === '/oauth2/authorize'
        && url.searchParams.get('prompt') === 'login'
    })
    await page.getByTestId('switch-account').click()
    await authorizationRequestPromise
    await expect(page).toHaveURL(/^http:\/\/localhost:9000\/login/)
    await expect(page.locator('#username')).toBeVisible()
  })

  async function filterManagementTable(email: string): Promise<void> {
    await managementPage.getByTestId('email-filter').fill(email)
    await managementPage.getByRole('button', { name: '查询' }).click()
    await expect(managementPage.locator('tr').filter({ hasText: email }))
      .toHaveCount(1)
  }
})

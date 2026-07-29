import { expect, test } from '@playwright/test'

const AUTH_BASE = 'http://localhost:9000'

function uniqueEmail(): string {
  return `e2e-${Date.now()}-${Math.floor(Math.random() * 10000)}@example.com`
}

test('新用户注册后可通过统一登录进入 demo-web-a', async ({ page }) => {
  const email = uniqueEmail()
  const password = 'a valid password'

  await page.goto(`${AUTH_BASE}/register`)
  await page.fill('#email', email)
  await page.fill('#password', password)
  await page.click('button[type="submit"]')

  await expect(page.getByTestId('login-registered')).toBeVisible()

  await page.goto('/')
  await page.getByTestId('login-button').click()

  await page.waitForURL(/\/login/)
  await page.fill('#username', email)
  await page.fill('#password', password)
  await page.click('button[type="submit"]')

  await page.waitForURL('http://localhost:5173/**')
  // 断言到具体邮箱而不只是「元素出现」：令牌换取失败或 id_token 缺 email 声明时，
  // 页面同样会渲染出这个元素，只是内容变成「已登录：undefined」——只判可见会放过这种情况
  await expect(page.getByTestId('signed-in-user')).toHaveText(`已登录：${email}`)
})

test('已在认证中心登录后再次进入产品无需重新输入密码', async ({ page }) => {
  const email = uniqueEmail()
  const password = 'a valid password'

  await page.goto(`${AUTH_BASE}/register`)
  await page.fill('#email', email)
  await page.fill('#password', password)
  await page.click('button[type="submit"]')

  await page.fill('#username', email)
  await page.fill('#password', password)
  await page.click('button[type="submit"]')

  await page.goto('/')
  await page.getByTestId('login-button').click()

  // 认证中心已有会话，应直接回跳而不出现登录表单
  await expect(page.getByTestId('signed-in-user')).toHaveText(`已登录：${email}`)
  await expect(page.locator('#username')).toHaveCount(0)
})

test('密码错误时提示信息不透露账号是否存在', async ({ page }) => {
  const email = uniqueEmail()

  await page.goto(`${AUTH_BASE}/register`)
  await page.fill('#email', email)
  await page.fill('#password', 'a valid password')
  await page.click('button[type="submit"]')

  await page.fill('#username', email)
  await page.fill('#password', 'wrong password')
  await page.click('button[type="submit"]')
  const wrongPasswordMessage = await page.getByTestId('login-error').textContent()

  await page.goto(`${AUTH_BASE}/login`)
  await page.fill('#username', uniqueEmail())
  await page.fill('#password', 'a valid password')
  await page.click('button[type="submit"]')
  const unknownAccountMessage = await page.getByTestId('login-error').textContent()

  // 先确认提示确实有内容：两边都渲染成空串时「两者相等」会无声通过，那样这条用例就白写了
  expect(wrongPasswordMessage?.trim()).toBeTruthy()
  expect(wrongPasswordMessage).toBe(unknownAccountMessage)
})

import { expect, test, type Page } from '@playwright/test'

const AUTH_BASE = 'http://localhost:9000'

const PASSWORD = 'a valid password'

function uniqueEmail(): string {
  return `e2e-${Date.now()}-${Math.floor(Math.random() * 10000)}@example.com`
}

/**
 * 服务端邮箱正则只禁 `@` 与空白，尖括号一路放行，因此这是一个能真正落库的邮箱。
 * 页面若把它当 HTML 拼进去，`<img>` 会被解析成真实元素。
 */
function htmlInjectionEmail(): string {
  return `<img/src=x>${Date.now()}-${Math.floor(Math.random() * 10000)}@example.com`
}

/** 读取当前页面表单里的 CSRF 令牌。 */
async function csrfToken(page: Page): Promise<string> {
  return page.locator('input[name="_csrf"]').first().inputValue()
}

/**
 * 绕开浏览器表单控件直接提交注册。
 *
 * <p>登录页与注册页的输入框是 `type="email"`，浏览器自带的客户端校验会拦下含尖括号的邮箱；
 * 而客户端校验只是个提示，攻击者用任意 HTTP 客户端就能跳过。这里走的是同一个服务端端点，
 * 只是不经过那层提示——正是真实攻击者的做法。请求共用页面的 cookie，会话是连续的。
 */
async function registerDirectly(page: Page, email: string): Promise<void> {
  await page.goto(`${AUTH_BASE}/register`)
  const response = await page.request.post(`${AUTH_BASE}/register`, {
    form: { email, password: PASSWORD, _csrf: await csrfToken(page) },
  })
  // 注册被拒时控制器会重新渲染注册页（同样是 200），只有落到 /login?registered 才代表真的入库了
  expect(response.url()).toContain('/login?registered')
}

/** 同上，直接提交登录表单。 */
async function loginDirectly(page: Page, email: string): Promise<void> {
  await page.goto(`${AUTH_BASE}/login`)
  const response = await page.request.post(`${AUTH_BASE}/login`, {
    form: { username: email, password: PASSWORD, _csrf: await csrfToken(page) },
  })
  // 登录失败同样是 200（重新渲染登录页），只有落到 /login?error 之外才算成功。
  // 不断言的话，登录静默失败只会表现为后面某个 toBeVisible() 超时，排查时看不出真正原因
  expect(response.url()).not.toContain('/login?error')
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

/**
 * 邮箱是用户自选的，服务端只挡 `@` 与空白，尖括号能一路存进 id_token 的 email 声明。
 * demo-web-a 是给真实接入方照抄的模板，把声明当 HTML 拼进页面的写法一旦被抄走，
 * 落到「令牌存 localStorage」的应用里就是可被读走令牌的注入点。这里钉住它必须按文本渲染。
 */
test('邮箱里的 HTML 被当文本渲染，不会在接入方页面里变成元素', async ({ page }) => {
  const email = htmlInjectionEmail()

  await registerDirectly(page, email)
  await loginDirectly(page, email)

  await page.goto('/')
  await page.getByTestId('login-button').click()

  // 必须先同步到终态再断言「不存在」：换令牌是异步的，页面渲染出来之前 #app 是空的，
  // 此时任何 toHaveCount(0) 都会立刻成立——先断言登录态可见，后面的断言才有意义
  await expect(page.getByTestId('signed-in-user')).toBeVisible()
  // 终态断言：整个页面里不能凭空多出注入者指定的元素
  await expect(page.locator('#app img')).toHaveCount(0)
  // 原样显示：邮箱里的尖括号必须是可见字符，而不是被浏览器解析掉的标签
  await expect(page.getByTestId('signed-in-user')).toHaveText(`已登录：${email}`)
})

test('伪造的回调因 state 不符被拒绝，页面显示错误而不是登录态', async ({ page }) => {
  // 这里刻意不预先登录：有会话时点登录会立刻免登回跳，页面根本停不在认证中心，
  // 拿不到「已写入 state 但尚未回调」的中间态。没有会话才会停在登录页。
  await page.goto('/')
  await page.getByTestId('login-button').click()
  // 停在认证中心登录页即说明 state 与 code_verifier 已写进 demo 的 sessionStorage
  await expect(page.locator('#username')).toBeVisible()

  // 攻击者把自己拿到的 code 塞进受害者的回调地址，但 state 对不上
  await page.goto('/callback?code=forged-authorization-code&state=not-the-expected-state')

  await expect(page.getByTestId('auth-error')).toBeVisible()
  await expect(page.getByTestId('auth-error')).toHaveText(/state 校验失败/)
  // 真正要守的是终态：绝不能因为收到伪造回调就进入登录态
  await expect(page.getByTestId('signed-in-user')).toHaveCount(0)
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

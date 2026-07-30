import { completeLogin, currentUser, isLoggedIn, startLogin } from './auth'

const app = document.querySelector<HTMLDivElement>('#app')!

/**
 * 一律用 textContent 而不是 innerHTML 写入动态内容。
 *
 * <p>这里要显示的邮箱来自 id_token 的 email 声明，而邮箱是用户注册时自选的：
 * 服务端只禁 `@` 与空白，尖括号、引号、斜杠都能存进去。用 innerHTML 拼接时
 * 这些字符会被当标签解析，注入者指定的元素会真的出现在接入方页面上。
 * 本文件是给接入方照抄的模板，这个写法必须一开始就是对的。
 */
function paragraph(testId: string, text: string): HTMLParagraphElement {
  const element = document.createElement('p')
  element.setAttribute('data-testid', testId)
  element.textContent = text
  return element
}

async function render(): Promise<void> {
  if (window.location.pathname === '/callback') {
    try {
      await completeLogin(window.location.search)
      window.history.replaceState({}, '', '/')
    }
    catch (error) {
      app.replaceChildren(paragraph('auth-error', (error as Error).message))
      return
    }
  }

  if (isLoggedIn()) {
    app.replaceChildren(paragraph('signed-in-user', `已登录：${currentUser()}`))
    return
  }

  const loginButton = document.createElement('button')
  loginButton.type = 'button'
  loginButton.setAttribute('data-testid', 'login-button')
  loginButton.textContent = '登录'
  loginButton.addEventListener('click', () => { void startLogin() })
  app.replaceChildren(loginButton)
}

void render()

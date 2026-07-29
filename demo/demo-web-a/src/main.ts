import { completeLogin, currentUser, isLoggedIn, startLogin } from './auth'

const app = document.querySelector<HTMLDivElement>('#app')!

async function render(): Promise<void> {
  if (window.location.pathname === '/callback') {
    try {
      await completeLogin(window.location.search)
      window.history.replaceState({}, '', '/')
    }
    catch (error) {
      app.innerHTML = `<p data-testid="auth-error">${(error as Error).message}</p>`
      return
    }
  }

  if (isLoggedIn()) {
    app.innerHTML = `<p data-testid="signed-in-user">已登录：${currentUser()}</p>`
    return
  }

  app.innerHTML = '<button type="button" data-testid="login-button">登录</button>'
  document.querySelector('[data-testid="login-button"]')!
    .addEventListener('click', () => { void startLogin() })
}

void render()

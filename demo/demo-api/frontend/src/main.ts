import WebAuthClient from '@unified-login/web'

const authClient = new WebAuthClient({
  issuer: 'http://127.0.0.1:9001',
  clientId: 'demo-api',
  redirectUri: 'http://127.0.0.1:5274/callback',
})

const app = document.querySelector<HTMLDivElement>('#app')!

function paragraph(testId: string, text: string): HTMLParagraphElement {
  const element = document.createElement('p')
  element.setAttribute('data-testid', testId)
  element.textContent = text
  return element
}

function emailFromAccessToken(accessToken: string): string {
  const encodedClaims = accessToken.split('.')[1]
  if (encodedClaims === undefined) {
    throw new Error('访问令牌格式无效')
  }
  const claims: unknown = JSON.parse(
    new TextDecoder().decode(
      Uint8Array.from(
        atob(encodedClaims.replace(/-/g, '+').replace(/_/g, '/')),
        (character) => character.charCodeAt(0),
      ),
    ),
  )
  if (
    typeof claims !== 'object'
    || claims === null
    || typeof (claims as Record<string, unknown>).email !== 'string'
  ) {
    throw new Error('访问令牌缺少 email')
  }
  return (claims as Record<string, string>).email
}

async function render(): Promise<void> {
  const isTopLevelCallback = (
    window.parent === window
    && window.location.pathname === '/callback'
  )
  try {
    const accessToken = await authClient.getAccessToken()
    if (isTopLevelCallback) {
      history.replaceState(history.state, '', '/')
    }
    app.replaceChildren(
      paragraph('signed-in-user', `已登录：${emailFromAccessToken(accessToken)}`),
    )
  }
  catch (error) {
    if (window.parent !== window || window.location.pathname === '/callback') {
      app.replaceChildren(paragraph('auth-error', (error as Error).message))
      return
    }
    await authClient.login()
  }
}

void render()

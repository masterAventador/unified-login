import type { AuthView } from './app'

type Action = 'login' | 'retry' | 'logout' | undefined
type Tone = 'busy' | 'success' | 'warning' | 'error'

export class DomAuthView implements AuthView {
  private readonly statusIndicator: HTMLElement
  private readonly statusLabel: HTMLElement
  private readonly statusTitle: HTMLElement
  private readonly statusMessage: HTMLElement
  private readonly loginButton: HTMLButtonElement
  private readonly retryButton: HTMLButtonElement
  private readonly logoutButton: HTMLButtonElement

  constructor(document: Document) {
    this.statusIndicator = required(document, 'status-indicator')
    this.statusLabel = required(document, 'status-label')
    this.statusTitle = required(document, 'status-title')
    this.statusMessage = required(document, 'status-message')
    this.loginButton = requiredButton(document, 'login-button')
    this.retryButton = requiredButton(document, 'retry-button')
    this.logoutButton = requiredButton(document, 'logout-button')
  }

  onLogin(listener: () => void): void {
    this.loginButton.addEventListener('click', listener)
  }

  onRetry(listener: () => void): void {
    this.retryButton.addEventListener('click', listener)
  }

  onLogout(listener: () => void): void {
    this.logoutButton.addEventListener('click', listener)
  }

  showBusy(message: string): void {
    this.render('请稍候', message, '这可能需要几秒钟。', 'busy')
  }

  showAuthenticated(): void {
    this.render(
      '已安全连接',
      '你已登录',
      '应用已从认证中心取得新的访问凭据。',
      'success',
      'logout',
    )
  }

  showLoginRequired(): void {
    this.render(
      '需要登录',
      '连接你的账号',
      '点击后会打开系统默认浏览器。完成登录后会自动返回这里。',
      'warning',
      'login',
    )
  }

  showRetryable(message: string): void {
    this.render(
      '连接中断',
      '暂时无法恢复登录',
      message,
      'warning',
      'retry',
    )
  }

  showError(message: string): void {
    this.render('未完成', '操作未完成', message, 'error', 'retry')
  }

  private render(
    label: string,
    title: string,
    message: string,
    tone: Tone,
    action?: Action,
  ): void {
    this.statusLabel.textContent = label
    this.statusTitle.textContent = title
    this.statusMessage.textContent = message
    this.statusIndicator.dataset.tone = tone

    this.loginButton.hidden = action !== 'login'
    this.retryButton.hidden = action !== 'retry'
    this.logoutButton.hidden = action !== 'logout'
    this.loginButton.disabled = action === undefined
    this.retryButton.disabled = action === undefined
    this.logoutButton.disabled = action === undefined
  }
}

function required(document: Document, id: string): HTMLElement {
  const element = document.getElementById(id)
  if (element === null) {
    throw new Error(`缺少必要界面元素: ${id}`)
  }
  return element
}

function requiredButton(document: Document, id: string): HTMLButtonElement {
  const element = required(document, id)
  if (!(element instanceof HTMLButtonElement)) {
    throw new Error(`界面元素不是按钮: ${id}`)
  }
  return element
}

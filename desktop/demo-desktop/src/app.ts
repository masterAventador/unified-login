import type { AuthStatus, DesktopAuthApi } from './api'

export interface AuthView {
  showBusy(message: string): void
  showAuthenticated(): void
  showLoginRequired(): void
  showRetryable(message: string): void
  showError(message: string): void
}

export class AuthController {
  constructor(
    private readonly api: DesktopAuthApi,
    private readonly view: AuthView,
  ) {}

  async initialize(): Promise<void> {
    this.view.showBusy('正在恢复登录状态…')
    try {
      this.showStatus(await this.api.restore())
    } catch {
      this.view.showError('暂时无法恢复登录状态，请重试')
    }
  }

  async login(): Promise<void> {
    this.view.showBusy('请在系统浏览器中完成登录…')
    try {
      this.showStatus(await this.api.login())
    } catch {
      this.view.showError('登录未完成，请重试')
    }
  }

  async logout(): Promise<void> {
    this.view.showBusy('正在退出登录…')
    try {
      await this.api.logout()
      this.view.showLoginRequired()
    } catch {
      this.view.showError('退出登录未完成，请重试')
    }
  }

  private showStatus(status: AuthStatus): void {
    switch (status) {
      case 'authenticated':
        this.view.showAuthenticated()
        break
      case 'loginRequired':
        this.view.showLoginRequired()
        break
      case 'retryable':
        this.view.showRetryable('暂时无法连接认证中心，请重试')
        break
    }
  }
}

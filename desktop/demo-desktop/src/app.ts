import type { TauriAuthClientApi } from '../../../sdk/tauri/ts/index'

export interface AuthView {
  showBusy(message: string): void
  showAuthenticated(): void
  showLoginRequired(): void
  showRetryable(message: string): void
  showError(message: string): void
}

export class AuthController {
  private maintenanceEnabled = false
  private maintenanceInProgress = false
  private retryOperation: () => Promise<void> = () => this.initialize()
  private userOperationInProgress = false
  private userOperationGeneration = 0

  constructor(
    private readonly api: TauriAuthClientApi,
    private readonly view: AuthView,
  ) {}

  async initialize(): Promise<void> {
    this.view.showBusy('正在恢复登录状态…')
    try {
      await this.api.getAccessToken()
      this.showAuthenticated()
    } catch (error) {
      this.showAccessTokenFailure(error, () => this.initialize())
    }
  }

  async maintain(): Promise<void> {
    if (
      !this.maintenanceEnabled
      || this.maintenanceInProgress
      || this.userOperationInProgress
    ) {
      return
    }
    this.maintenanceInProgress = true
    const generation = this.userOperationGeneration
    try {
      await this.api.getAccessToken()
    } catch (error) {
      if (this.isCurrentMaintenance(generation)) {
        this.showAccessTokenFailure(error, () => this.initialize())
      }
    } finally {
      this.maintenanceInProgress = false
    }
  }

  async retry(): Promise<void> {
    await this.retryOperation()
  }

  async login(): Promise<void> {
    this.maintenanceEnabled = false
    this.userOperationInProgress = true
    this.userOperationGeneration += 1
    this.view.showBusy('请在系统浏览器中完成登录…')
    try {
      await this.api.login()
      this.showAuthenticated()
    } catch {
      this.showFailure('登录未完成，请重试', () => this.login())
    } finally {
      this.userOperationInProgress = false
    }
  }

  async logout(): Promise<void> {
    this.maintenanceEnabled = false
    this.userOperationInProgress = true
    this.userOperationGeneration += 1
    this.view.showBusy('正在退出登录…')
    try {
      await this.api.logout()
      this.view.showLoginRequired()
    } catch {
      this.showFailure('退出登录未完成，请重试', () => this.logout())
    } finally {
      this.userOperationInProgress = false
    }
  }

  private showFailure(
    message: string,
    retryOperation: () => Promise<void>,
  ): void {
    this.maintenanceEnabled = false
    this.retryOperation = retryOperation
    this.view.showError(message)
  }

  private showAccessTokenFailure(
    error: unknown,
    retryOperation: () => Promise<void>,
  ): void {
    this.maintenanceEnabled = false
    const code = commandErrorCode(error)
    if (code === 'loginRequired') {
      this.view.showLoginRequired()
      return
    }
    if (code === 'retryable') {
      this.retryOperation = retryOperation
      this.view.showRetryable('暂时无法连接认证中心，请重试')
      return
    }
    this.showFailure('暂时无法恢复登录状态，请重试', retryOperation)
  }

  private showAuthenticated(): void {
    this.maintenanceEnabled = true
    this.view.showAuthenticated()
  }

  private isCurrentMaintenance(generation: number): boolean {
    return this.maintenanceEnabled
      && !this.userOperationInProgress
      && generation === this.userOperationGeneration
  }
}

function commandErrorCode(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null || !('code' in error)) {
    return undefined
  }
  return typeof error.code === 'string' ? error.code : undefined
}

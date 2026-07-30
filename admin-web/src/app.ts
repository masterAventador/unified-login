import { AdminApiError } from './api'
import type { UserPage, UserQuery } from './api'

export type { UserPage, UserQuery } from './api'

export interface AdminLoginOptions {
  readonly prompt?: 'login'
}

const INITIAL_QUERY: UserQuery = {
  email: '',
  status: '',
  page: 0,
  size: 20,
}

export interface AdminAuthPort {
  getAccessToken(): Promise<string>
  login(options?: AdminLoginOptions): Promise<void>
  logout(): void
  onAuthStateChange(listener: (authenticated: boolean) => void): () => void
}

export interface AdminApiPort {
  listUsers(accessToken: string, query: UserQuery): Promise<UserPage>
  disable(accessToken: string, userId: string): Promise<void>
  enable(accessToken: string, userId: string): Promise<void>
  resetPassword(
    accessToken: string,
    userId: string,
    newPassword: string,
  ): Promise<void>
}

export interface AdminActions {
  changeQuery(query: UserQuery): Promise<void>
  disable(userId: string): Promise<void>
  enable(userId: string): Promise<void>
  resetPassword(userId: string, newPassword: string): Promise<void>
  logout(): void
}

export interface AdminViewPort {
  showLoading(): void
  showLogin(login: () => Promise<void>): void
  showForbidden(switchAccount: () => Promise<void>): void
  showError(message: string): void
  showUsers(
    page: UserPage,
    actions: AdminActions,
    query: UserQuery,
    operationError?: string,
  ): void
}

export class AdminApplication {
  private query = INITIAL_QUERY
  private currentPage: UserPage | null = null
  private credentialsInvalidated = false

  constructor(
    private readonly auth: AdminAuthPort,
    private readonly api: AdminApiPort,
    private readonly view: AdminViewPort,
  ) {
    this.auth.onAuthStateChange((authenticated) => {
      this.credentialsInvalidated = !authenticated
    })
  }

  async start(): Promise<void> {
    await this.loadUsers()
  }

  private async loadUsers(): Promise<void> {
    this.view.showLoading()
    try {
      const accessToken = await this.auth.getAccessToken()
      const page = await this.api.listUsers(accessToken, this.query)
      if (this.query.page > 0 && this.query.page >= page.totalPages) {
        this.query = {
          ...this.query,
          page: Math.max(0, page.totalPages - 1),
        }
        await this.loadUsers()
        return
      }
      this.currentPage = page
      this.view.showUsers(page, this.actions(), this.query)
    } catch (error) {
      this.handleError(error)
    }
  }

  private actions(): AdminActions {
    return {
      changeQuery: async (query) => {
        this.query = query
        await this.loadUsers()
      },
      disable: async (userId) => {
        await this.mutate(
          (token) => this.api.disable(token, userId),
          '不能禁用当前登录的管理员账号',
        )
      },
      enable: async (userId) => {
        await this.mutate(
          (token) => this.api.enable(token, userId),
          '无法启用该账号，请检查账号状态后重试',
        )
      },
      resetPassword: async (userId, newPassword) => {
        await this.mutate(
          (token) => this.api.resetPassword(token, userId, newPassword),
          '新密码必须为 8–64 个字符',
        )
      },
      logout: () => {
        this.auth.logout()
        this.showLogin()
      },
    }
  }

  private async mutate(
    operation: (accessToken: string) => Promise<void>,
    expectedErrorMessage: string,
  ): Promise<void> {
    this.view.showLoading()
    try {
      await operation(await this.auth.getAccessToken())
      await this.loadUsers()
    } catch (error) {
      if (error instanceof AdminApiError
        && (error.status === 400 || error.status === 409)
        && this.currentPage !== null) {
        this.view.showUsers(
          this.currentPage,
          this.actions(),
          this.query,
          expectedErrorMessage,
        )
        return
      }
      this.handleError(error)
    }
  }

  private handleError(error: unknown): void {
    if (error instanceof AdminApiError && error.status === 403) {
      this.view.showForbidden(async () => {
        this.auth.logout()
        await this.auth.login({ prompt: 'login' })
      })
      return
    }
    if (error instanceof AdminApiError && error.status === 401) {
      this.auth.logout()
      this.showLogin()
      return
    }
    if (error instanceof Error && error.message === '当前没有可用的登录令牌') {
      this.showLogin()
      return
    }
    if (this.credentialsInvalidated) {
      this.showLogin()
      return
    }
    this.view.showError('暂时无法加载管理后台，请稍后重试')
  }

  private showLogin(): void {
    this.view.showLogin(async () => {
      await this.auth.login()
    })
  }
}

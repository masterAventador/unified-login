export type UserStatus = 'ACTIVE' | 'DISABLED'

export interface AdminUser {
  readonly id: string
  readonly email: string
  readonly status: UserStatus
  readonly emailVerified: boolean
  readonly platformAdmin: boolean
  readonly passwordChangedAt: string
  readonly createdAt: string
  readonly updatedAt: string
}

export interface UserPage {
  readonly content: readonly AdminUser[]
  readonly page: number
  readonly size: number
  readonly totalElements: number
  readonly totalPages: number
}

export interface UserQuery {
  readonly email: string
  readonly status: UserStatus | ''
  readonly page: number
  readonly size: number
}

export class AdminApiError extends Error {
  constructor(readonly status: number) {
    super(`管理接口请求失败：${status}`)
  }
}

export class AdminApi {
  private readonly baseUrl: string

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`
  }

  async listUsers(accessToken: string, query: UserQuery): Promise<UserPage> {
    const url = new URL('admin/users', this.baseUrl)
    url.searchParams.set('email', query.email)
    if (query.status !== '') {
      url.searchParams.set('status', query.status)
    }
    url.searchParams.set('page', String(query.page))
    url.searchParams.set('size', String(query.size))

    const response = await this.request(url.toString(), accessToken)
    return parseUserPage(await response.json())
  }

  async disable(accessToken: string, userId: string): Promise<void> {
    await this.post(accessToken, userId, 'disable')
  }

  async enable(accessToken: string, userId: string): Promise<void> {
    await this.post(accessToken, userId, 'enable')
  }

  async resetPassword(
    accessToken: string,
    userId: string,
    newPassword: string,
  ): Promise<void> {
    await this.request(
      this.userActionUrl(userId, 'reset-password'),
      accessToken,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ newPassword }),
      },
    )
  }

  private async post(
    accessToken: string,
    userId: string,
    action: 'disable' | 'enable',
  ): Promise<void> {
    await this.request(
      this.userActionUrl(userId, action),
      accessToken,
      {
        method: 'POST',
        headers: { Authorization: `Bearer ${accessToken}` },
      },
    )
  }

  private userActionUrl(userId: string, action: string): string {
    const encodedUserId = encodeURIComponent(userId)
    return new URL(`admin/users/${encodedUserId}/${action}`, this.baseUrl).toString()
  }

  private async request(
    url: string,
    accessToken: string,
    init?: RequestInit,
  ): Promise<Response> {
    const response = await fetch(url, init ?? {
      headers: { Authorization: `Bearer ${accessToken}` },
    })
    if (!response.ok) {
      throw new AdminApiError(response.status)
    }
    return response
  }
}

function parseUserPage(value: unknown): UserPage {
  if (!isRecord(value)
    || !Array.isArray(value.content)
    || !value.content.every(isAdminUser)
    || !isNonNegativeInteger(value.page)
    || !isPositiveInteger(value.size)
    || !isNonNegativeInteger(value.totalElements)
    || !isNonNegativeInteger(value.totalPages)) {
    throw new Error('用户列表响应格式无效')
  }
  return value as unknown as UserPage
}

function isAdminUser(value: unknown): value is AdminUser {
  if (!isRecord(value)) {
    return false
  }
  return typeof value.id === 'string'
    && typeof value.email === 'string'
    && (value.status === 'ACTIVE' || value.status === 'DISABLED')
    && typeof value.emailVerified === 'boolean'
    && typeof value.platformAdmin === 'boolean'
    && typeof value.passwordChangedAt === 'string'
    && typeof value.createdAt === 'string'
    && typeof value.updatedAt === 'string'
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0
}

function isPositiveInteger(value: unknown): value is number {
  return isNonNegativeInteger(value) && value > 0
}

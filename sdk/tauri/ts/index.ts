export type AuthStateChangeListener = (authenticated: boolean) => void

export const TAURI_AUTH_ERROR_CODES = [
  'configuration',
  'credentials',
  'loginInProgress',
  'loginOptions',
  'loginFailed',
  'loginRequired',
  'retryable',
  'restoreFailed',
  'logoutFailed',
  'staleOperation',
] as const

export type TauriAuthErrorCode = typeof TAURI_AUTH_ERROR_CODES[number]

const AUTH_ERROR_CODES = new Set<string>(TAURI_AUTH_ERROR_CODES)
const AUTH_ERROR_MESSAGES: Readonly<Record<TauriAuthErrorCode, string>> = {
  configuration: '桌面端认证配置无效',
  credentials: '操作系统凭据库暂时不可用',
  loginInProgress: '已有认证操作正在进行',
  loginOptions: '桌面端登录选项无效',
  loginFailed: '登录未完成，请重试',
  loginRequired: '当前没有可用的登录令牌',
  retryable: '暂时无法连接认证中心',
  restoreFailed: '暂时无法恢复登录状态',
  logoutFailed: '退出登录未完成',
  staleOperation: '认证状态已在操作期间发生变化',
}

export class TauriAuthError extends Error {
  readonly code: TauriAuthErrorCode

  constructor(
    code: TauriAuthErrorCode,
    message: string = AUTH_ERROR_MESSAGES[code],
    options?: ErrorOptions,
  ) {
    super(message, options)
    this.name = 'TauriAuthError'
    this.code = code
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function normalizeAuthError(
  error: unknown,
  fallbackCode: TauriAuthErrorCode,
): TauriAuthError {
  if (error instanceof TauriAuthError) {
    return error
  }
  if (
    isRecord(error)
    && typeof error.code === 'string'
    && AUTH_ERROR_CODES.has(error.code)
    && typeof error.message === 'string'
  ) {
    return new TauriAuthError(
      error.code as TauriAuthErrorCode,
      error.message,
      { cause: error },
    )
  }
  return new TauriAuthError(fallbackCode, undefined, { cause: error })
}

const PLUGIN_INVOKE_PREFIX = 'plugin:unified-login-tauri|'
const LOGIN_COMMAND = `${PLUGIN_INVOKE_PREFIX}login`
const LOGOUT_COMMAND = `${PLUGIN_INVOKE_PREFIX}logout`
const GET_ACCESS_TOKEN_COMMAND = `${PLUGIN_INVOKE_PREFIX}get_access_token`

export interface TauriAuthLoginOptions {
  readonly prompt?: 'login'
}

export interface TauriAuthClientApi {
  login(options?: TauriAuthLoginOptions): Promise<void>
  logout(): Promise<void>
  getAccessToken(): Promise<string>
  onAuthStateChange(listener: AuthStateChangeListener): () => void
}

export type TauriInvoke = (
  command: string,
  arguments_?: Record<string, unknown>,
) => Promise<unknown>

export class TauriAuthClient implements TauriAuthClientApi {
  readonly #invoke: TauriInvoke
  readonly #listeners = new Set<AuthStateChangeListener>()
  #authenticated = false
  #authGeneration = 0
  #loginInFlight: {
    readonly operation: Promise<void>
    readonly prompt: TauriAuthLoginOptions['prompt']
  } | undefined
  #logoutInFlight: Promise<void> | undefined

  constructor(invoke: TauriInvoke) {
    this.#invoke = invoke
  }

  login(options: TauriAuthLoginOptions = {}): Promise<void> {
    if (this.#logoutInFlight !== undefined) {
      return Promise.reject(new TauriAuthError(
        'loginInProgress',
        '退出登录正在进行',
      ))
    }
    if (this.#loginInFlight !== undefined) {
      if (this.#loginInFlight.prompt === options.prompt) {
        return this.#loginInFlight.operation
      }
      return Promise.reject(new TauriAuthError(
        'loginInProgress',
        '已有不同选项的登录流程正在进行',
      ))
    }
    const generation = ++this.#authGeneration
    const operation = (async () => {
      if (options.prompt === undefined) {
        await this.#invoke(LOGIN_COMMAND)
      } else {
        await this.#invoke(LOGIN_COMMAND, { prompt: options.prompt })
      }
      this.#assertCurrentGeneration(generation)
      this.#setAuthenticated(true, generation)
      this.#assertCurrentGeneration(generation)
    })().catch((error: unknown) => {
      throw normalizeAuthError(error, 'loginFailed')
    })
    const trackedOperation = operation.finally(() => {
      if (this.#loginInFlight?.operation === trackedOperation) {
        this.#loginInFlight = undefined
      }
    })
    this.#loginInFlight = {
      operation: trackedOperation,
      prompt: options.prompt,
    }
    return trackedOperation
  }

  logout(): Promise<void> {
    if (this.#logoutInFlight !== undefined) {
      return this.#logoutInFlight
    }
    const generation = ++this.#authGeneration
    const operation = (async () => {
      await this.#invoke(LOGOUT_COMMAND)
      this.#assertCurrentGeneration(generation)
      this.#loginInFlight = undefined
      this.#setAuthenticated(false, generation)
      this.#assertCurrentGeneration(generation)
    })().catch((error: unknown) => {
      throw normalizeAuthError(error, 'logoutFailed')
    })
    const trackedOperation = operation.finally(() => {
      if (this.#logoutInFlight === trackedOperation) {
        this.#logoutInFlight = undefined
      }
    })
    this.#logoutInFlight = trackedOperation
    return trackedOperation
  }

  async getAccessToken(): Promise<string> {
    if (this.#logoutInFlight !== undefined) {
      throw new TauriAuthError('logoutFailed', '退出登录正在进行')
    }
    if (this.#loginInFlight !== undefined) {
      throw new TauriAuthError('loginInProgress', '登录正在进行')
    }
    const generation = this.#authGeneration
    try {
      const accessToken = await this.#invoke(GET_ACCESS_TOKEN_COMMAND) as string
      this.#assertCurrentGeneration(generation)
      this.#setAuthenticated(true, generation)
      this.#assertCurrentGeneration(generation)
      return accessToken
    } catch (error) {
      this.#assertCurrentGeneration(generation)
      this.#setAuthenticated(false, generation)
      this.#assertCurrentGeneration(generation)
      throw normalizeAuthError(error, 'restoreFailed')
    }
  }

  onAuthStateChange(listener: AuthStateChangeListener): () => void {
    this.#listeners.add(listener)
    return () => {
      this.#listeners.delete(listener)
    }
  }

  #assertCurrentGeneration(generation: number): void {
    if (generation !== this.#authGeneration) {
      throw new TauriAuthError('staleOperation', '登录状态已失效')
    }
  }

  #setAuthenticated(authenticated: boolean, generation: number): void {
    if (this.#authenticated === authenticated) {
      return
    }
    this.#authenticated = authenticated
    for (const listener of this.#listeners) {
      if (generation !== this.#authGeneration) {
        break
      }
      try {
        void Promise.resolve(listener(authenticated)).catch(() => undefined)
      } catch {
        // 一个产品监听器失败不能阻断认证操作或其他监听器。
      }
    }
  }
}

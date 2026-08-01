export type AuthStateChangeListener = (authenticated: boolean) => void

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
      return Promise.reject(new Error('退出登录正在进行'))
    }
    if (this.#loginInFlight !== undefined) {
      if (this.#loginInFlight.prompt === options.prompt) {
        return this.#loginInFlight.operation
      }
      return Promise.reject(new Error('已有不同选项的登录流程正在进行'))
    }
    const generation = ++this.#authGeneration
    const operation = (async () => {
      if (options.prompt === undefined) {
        await this.#invoke('login')
      } else {
        await this.#invoke('login', { prompt: options.prompt })
      }
      this.#assertCurrentGeneration(generation)
      this.#setAuthenticated(true, generation)
      this.#assertCurrentGeneration(generation)
    })()
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
      await this.#invoke('logout')
      this.#assertCurrentGeneration(generation)
      this.#loginInFlight = undefined
      this.#setAuthenticated(false, generation)
      this.#assertCurrentGeneration(generation)
    })()
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
      throw new Error('退出登录正在进行')
    }
    if (this.#loginInFlight !== undefined) {
      throw new Error('登录正在进行')
    }
    const generation = this.#authGeneration
    try {
      const accessToken = await this.#invoke('get_access_token') as string
      this.#assertCurrentGeneration(generation)
      this.#setAuthenticated(true, generation)
      this.#assertCurrentGeneration(generation)
      return accessToken
    } catch (error) {
      this.#assertCurrentGeneration(generation)
      this.#setAuthenticated(false, generation)
      this.#assertCurrentGeneration(generation)
      throw error
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
      throw new Error('登录状态已失效')
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

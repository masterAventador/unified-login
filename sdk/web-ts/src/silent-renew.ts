import { createPkcePair } from './pkce'
import type { AuthorizationRequestStore } from './storage'
import type { TokenSet } from './tokens'

export const SILENT_RENEW_MESSAGE_TYPE = '@unified-login/web:silent-renew'

const DEFAULT_TIMEOUT_MS = 10_000

export interface SilentRenewConfig {
  readonly issuer: string
  readonly clientId: string
  readonly redirectUri: string
  readonly timeoutMs?: number
}

interface SilentRenewSuccessMessage {
  readonly type: typeof SILENT_RENEW_MESSAGE_TYPE
  readonly clientId: string
  readonly state: string
  readonly status: 'success'
  readonly tokens: TokenSet
}

interface SilentRenewErrorMessage {
  readonly type: typeof SILENT_RENEW_MESSAGE_TYPE
  readonly clientId: string
  readonly state: string
  readonly status: 'error'
  readonly error: string
}

type SilentRenewMessage = SilentRenewSuccessMessage | SilentRenewErrorMessage

type SilentRenewRequestStore = Pick<
  AuthorizationRequestStore,
  'save' | 'clearIfState'
>

function issuerEndpoint(issuer: string, path: string): string {
  const issuerBase = issuer.endsWith('/') ? issuer : `${issuer}/`
  return new URL(path, issuerBase).toString()
}

function isTokenSet(value: unknown): value is TokenSet {
  if (typeof value !== 'object' || value === null) {
    return false
  }
  const tokens = value as Record<string, unknown>
  return typeof tokens.accessToken === 'string'
    && tokens.accessToken.length > 0
    && typeof tokens.refreshToken === 'string'
    && tokens.refreshToken.length > 0
    && typeof tokens.idToken === 'string'
    && tokens.idToken.length > 0
    && typeof tokens.expiresAt === 'number'
    && Number.isFinite(tokens.expiresAt)
}

function parseMessage(value: unknown): SilentRenewMessage | null {
  if (typeof value !== 'object' || value === null) {
    return null
  }
  const message = value as Record<string, unknown>
  if (
    message.type !== SILENT_RENEW_MESSAGE_TYPE
    || typeof message.clientId !== 'string'
    || typeof message.state !== 'string'
  ) {
    return null
  }
  if (message.status === 'success' && isTokenSet(message.tokens)) {
    return message as unknown as SilentRenewSuccessMessage
  }
  if (message.status === 'error' && typeof message.error === 'string') {
    return message as unknown as SilentRenewErrorMessage
  }
  return null
}

export function postSilentRenewSuccess(
  config: SilentRenewConfig,
  state: string,
  tokens: TokenSet,
): void {
  window.parent.postMessage({
    type: SILENT_RENEW_MESSAGE_TYPE,
    clientId: config.clientId,
    state,
    status: 'success',
    tokens: { ...tokens },
  } satisfies SilentRenewSuccessMessage, new URL(config.redirectUri).origin)
}

export function postSilentRenewError(
  config: SilentRenewConfig,
  state: string,
  error: string,
): void {
  window.parent.postMessage({
    type: SILENT_RENEW_MESSAGE_TYPE,
    clientId: config.clientId,
    state,
    status: 'error',
    error,
  } satisfies SilentRenewErrorMessage, new URL(config.redirectUri).origin)
}

export class SilentRenewClient {
  private generation = 0
  private cancelActiveRequest: (() => void) | null = null

  constructor(
    private readonly config: SilentRenewConfig,
    private readonly requestStore: SilentRenewRequestStore,
  ) {
  }

  cancel(): void {
    this.generation += 1
    const cancel = this.cancelActiveRequest
    this.cancelActiveRequest = null
    cancel?.()
  }

  async silentRenew(): Promise<TokenSet | null> {
    this.cancel()
    const requestGeneration = this.generation
    const pkce = await createPkcePair()
    if (requestGeneration !== this.generation) {
      throw new Error('静默续签已取消')
    }
    const state = crypto.randomUUID()
    this.requestStore.save({ state, verifier: pkce.verifier })

    const authorizationUrl = new URL(issuerEndpoint(this.config.issuer, 'oauth2/authorize'))
    authorizationUrl.search = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: 'openid',
      prompt: 'none',
      state,
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
    }).toString()

    const redirectOrigin = new URL(this.config.redirectUri).origin
    const iframe = document.createElement('iframe')
    iframe.hidden = true
    iframe.style.display = 'none'
    iframe.setAttribute('aria-hidden', 'true')
    iframe.src = authorizationUrl.toString()

    return new Promise<TokenSet | null>((resolve, reject) => {
      let settled = false
      let timeoutId: ReturnType<typeof setTimeout> | undefined
      const cleanup = () => {
        if (timeoutId !== undefined) {
          clearTimeout(timeoutId)
        }
        window.removeEventListener('message', handleMessage)
        iframe.remove()
        try {
          this.requestStore.clearIfState(state)
        } catch {
          // 浏览器存储不可用不能让 iframe 请求永远停在未完成状态。
        }
        if (this.generation === requestGeneration) {
          this.cancelActiveRequest = null
        }
      }
      const finish = (result: TokenSet | null) => {
        if (settled) {
          return
        }
        settled = true
        cleanup()
        resolve(result)
      }
      const fail = (error: Error) => {
        if (settled) {
          return
        }
        settled = true
        cleanup()
        reject(error)
      }
      const handleMessage = (event: MessageEvent) => {
        if (event.origin !== redirectOrigin || event.source !== iframe.contentWindow) {
          return
        }
        const message = parseMessage(event.data)
        if (
          message === null
          || message.clientId !== this.config.clientId
          || message.state !== state
        ) {
          return
        }
        if (message.status === 'success') {
          finish({ ...message.tokens })
          return
        }
        if (message.error === 'login_required' || message.error === 'invalid_grant') {
          finish(null)
          return
        }
        fail(new Error(`静默续签失败：${message.error}`))
      }

      window.addEventListener('message', handleMessage)
      this.cancelActiveRequest = () => {
        fail(new Error('静默续签已取消'))
      }
      timeoutId = setTimeout(() => {
        fail(new Error('静默续签超时'))
      }, this.config.timeoutMs ?? DEFAULT_TIMEOUT_MS)
      try {
        document.body.appendChild(iframe)
      } catch (error) {
        fail(error instanceof Error ? error : new Error('无法创建静默续签 iframe'))
      }
    })
  }
}

import { createPkcePair } from './pkce'
import {
  SilentRenewClient,
  postSilentRenewError,
  postSilentRenewSuccess,
} from './silent-renew'
import {
  AuthorizationRequestStore,
  StateIndexedAuthorizationRequestStore,
} from './storage'
import { TokenStore } from './tokens'
import type { TokenSet } from './tokens'

interface TokenEndpointResponse {
  readonly access_token: string
  readonly refresh_token?: string
  readonly id_token?: string
  readonly expires_in: number
}

class TokenEndpointError extends Error {
  constructor(
    readonly status: number,
    readonly oauthError?: string,
  ) {
    super(`换取令牌失败：${status}`)
  }

  get invalidatesCredentials(): boolean {
    return this.oauthError === 'invalid_grant'
  }
}

function parseTokenEndpointResponse(value: unknown): TokenEndpointResponse {
  if (typeof value !== 'object' || value === null) {
    throw new Error('令牌响应格式无效')
  }
  const payload = value as Record<string, unknown>
  if (
    typeof payload.access_token !== 'string'
    || payload.access_token.length === 0
    || typeof payload.expires_in !== 'number'
    || !Number.isFinite(payload.expires_in)
    || payload.expires_in <= 0
    || (payload.refresh_token !== undefined && typeof payload.refresh_token !== 'string')
    || (payload.id_token !== undefined && typeof payload.id_token !== 'string')
  ) {
    throw new Error('令牌响应格式无效')
  }
  return payload as unknown as TokenEndpointResponse
}

export interface WebAuthClientConfig {
  readonly issuer: string
  readonly clientId: string
  readonly redirectUri: string
}

export type AuthStateChangeListener = (authenticated: boolean) => void

export default class WebAuthClient {
  private readonly authorizationRequestStore: AuthorizationRequestStore
  private readonly silentAuthorizationRequestStore: StateIndexedAuthorizationRequestStore
  private readonly silentRenewClient: SilentRenewClient
  private readonly explicitLogoutKey: string
  private readonly tokenStore = new TokenStore()
  private readonly authStateListeners = new Set<AuthStateChangeListener>()
  private authenticated = false
  private authGeneration = 0
  private authorizationCallbackInFlight: Promise<string> | null = null
  private refreshInFlight: Promise<string> | null = null
  private silentRenewEnabled = true
  private silentRenewInFlight: Promise<string> | null = null

  constructor(private readonly config: WebAuthClientConfig) {
    this.explicitLogoutKey = `${config.clientId}.explicit_logout`
    this.authorizationRequestStore = new AuthorizationRequestStore(
      config.clientId,
      sessionStorage,
    )
    this.silentAuthorizationRequestStore = new StateIndexedAuthorizationRequestStore(
      `${config.clientId}.silent`,
      sessionStorage,
    )
    this.silentRenewClient = new SilentRenewClient(
      config,
      this.silentAuthorizationRequestStore,
    )
    this.silentRenewEnabled = sessionStorage.getItem(this.explicitLogoutKey) !== 'true'
  }

  async login(): Promise<void> {
    sessionStorage.removeItem(this.explicitLogoutKey)
    this.silentRenewEnabled = true
    this.silentRenewClient.cancel()
    this.silentRenewInFlight = null
    const pkce = await createPkcePair()
    const state = crypto.randomUUID()
    this.authorizationRequestStore.save({ state, verifier: pkce.verifier })

    const issuerBase = this.config.issuer.endsWith('/')
      ? this.config.issuer
      : `${this.config.issuer}/`
    const authorizationUrl = new URL('oauth2/authorize', issuerBase)
    authorizationUrl.search = new URLSearchParams({
      response_type: 'code',
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      scope: 'openid',
      state,
      code_challenge: pkce.challenge,
      code_challenge_method: 'S256',
    }).toString()

    location.assign(authorizationUrl.toString())
  }

  logout(): void {
    this.authGeneration += 1
    try {
      sessionStorage.setItem(this.explicitLogoutKey, 'true')
    } catch {
      // 存储配额或浏览器策略不能阻断当前页面清除令牌；本实例仍保持显式登出态。
    }
    this.silentRenewEnabled = false
    this.silentRenewClient.cancel()
    this.authorizationCallbackInFlight = null
    this.refreshInFlight = null
    this.silentRenewInFlight = null
    this.authorizationRequestStore.clear()
    this.tokenStore.clear()
    this.#setAuthenticated(false)
  }

  onAuthStateChange(listener: AuthStateChangeListener): () => void {
    this.authStateListeners.add(listener)
    return () => {
      this.authStateListeners.delete(listener)
    }
  }

  async getAccessToken(): Promise<string> {
    if (
      sessionStorage.getItem(this.explicitLogoutKey) === 'true'
      && !this.#isAuthorizationCallback()
    ) {
      this.silentRenewEnabled = false
      this.silentRenewClient.cancel()
      this.silentRenewInFlight = null
      this.tokenStore.clear()
      this.#setAuthenticated(false)
      throw new Error('当前没有可用的登录令牌')
    }
    const currentTokens = this.tokenStore.get()
    if (currentTokens !== null) {
      if (!this.tokenStore.isExpiringSoon()) {
        return currentTokens.accessToken
      }
      if (currentTokens.refreshToken !== undefined) {
        if (this.refreshInFlight === null) {
          const refreshGeneration = this.authGeneration
          const refreshPromise = this.#refreshTokens(
            currentTokens.refreshToken,
            currentTokens.idToken,
            refreshGeneration,
          ).catch((error: unknown) => {
            if (
              error instanceof TokenEndpointError
              && error.invalidatesCredentials
              && this.authGeneration === refreshGeneration
            ) {
              this.tokenStore.clear()
              this.#setAuthenticated(false)
            }
            throw error
          })
          const trackedPromise = refreshPromise.finally(() => {
            if (this.refreshInFlight === trackedPromise) {
              this.refreshInFlight = null
            }
          })
          this.refreshInFlight = trackedPromise
        }
        return this.refreshInFlight
      }
    }

    if (this.authorizationCallbackInFlight !== null) {
      return this.authorizationCallbackInFlight
    }

    if (this.#isAuthorizationCallback()) {
      const callbackPromise = this.#completeAuthorizationCallback()
      const trackedPromise = callbackPromise.finally(() => {
        if (this.authorizationCallbackInFlight === trackedPromise) {
          this.authorizationCallbackInFlight = null
        }
      })
      this.authorizationCallbackInFlight = trackedPromise
      return trackedPromise
    }

    if (
      !this.silentRenewEnabled
      || typeof window === 'undefined'
      || typeof document === 'undefined'
    ) {
      throw new Error('当前没有可用的登录令牌')
    }
    if (this.silentRenewInFlight === null) {
      const renewGeneration = this.authGeneration
      const renewPromise = this.silentRenewClient.silentRenew().then((tokens) => {
        if (tokens === null) {
          this.silentRenewEnabled = false
          throw new Error('当前没有可用的登录令牌')
        }
        return this.#storeTokenSet(tokens, renewGeneration)
      })
      const trackedPromise = renewPromise.finally(() => {
        if (this.silentRenewInFlight === trackedPromise) {
          this.silentRenewInFlight = null
        }
      })
      this.silentRenewInFlight = trackedPromise
    }
    return this.silentRenewInFlight
  }

  #isAuthorizationCallback(): boolean {
    const currentUrl = new URL(location.href)
    const redirectUrl = new URL(this.config.redirectUri)
    return currentUrl.origin === redirectUrl.origin
      && currentUrl.pathname === redirectUrl.pathname
      && (currentUrl.searchParams.has('code') || currentUrl.searchParams.has('error'))
  }

  async #completeAuthorizationCallback(): Promise<string> {
    const callbackUrl = new URL(location.href)
    const cleanedCallbackUrl = new URL(callbackUrl)
    const oauthResponseParameters = [
      'code',
      'state',
      'error',
      'error_description',
      'error_uri',
      'iss',
      'session_state',
    ]
    oauthResponseParameters.forEach((parameter) => {
      cleanedCallbackUrl.searchParams.delete(parameter)
    })
    history.replaceState(
      history.state,
      '',
      `${cleanedCallbackUrl.pathname}${cleanedCallbackUrl.search}${cleanedCallbackUrl.hash}`,
    )

    const code = callbackUrl.searchParams.get('code')
    const returnedState = callbackUrl.searchParams.get('state')
    if (returnedState === null) {
      this.authorizationRequestStore.clear()
      this.silentAuthorizationRequestStore.clear()
      throw new Error('回调缺少必要参数')
    }
    let pendingRequest = this.authorizationRequestStore.takeIfState(returnedState)
    let isSilentCallback = false
    if (pendingRequest === null) {
      pendingRequest = this.silentAuthorizationRequestStore.takeIfState(returnedState)
      isSilentCallback = pendingRequest !== null
    }
    if (pendingRequest === null) {
      const discardedInteractiveRequest = this.authorizationRequestStore.take()
      const hadSilentRequests = this.silentAuthorizationRequestStore.hasPending()
      if (discardedInteractiveRequest === null && !hadSilentRequests) {
        throw new Error('回调缺少必要参数')
      }
      throw new Error('state 校验失败，拒绝换取令牌')
    }
    const authorizationError = callbackUrl.searchParams.get('error')
    if (authorizationError !== null) {
      if (isSilentCallback && this.#isEmbedded()) {
        postSilentRenewError(this.config, returnedState, authorizationError)
        throw new Error(`静默续签失败：${authorizationError}`)
      }
      throw new Error(`授权失败：${authorizationError}`)
    }
    if (code === null) {
      throw new Error('回调缺少必要参数')
    }
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: this.config.clientId,
      code,
      redirect_uri: this.config.redirectUri,
      code_verifier: pendingRequest.verifier,
    })
    const callbackGeneration = this.authGeneration
    try {
      const payload = await this.#requestTokens(body)
      if (payload.refresh_token === undefined || payload.id_token === undefined) {
        throw new Error('令牌响应格式无效')
      }
      const tokens = this.#createTokenSet(payload, {})
      const accessToken = this.#storeTokenSet(tokens, callbackGeneration)
      if (isSilentCallback && this.#isEmbedded()) {
        postSilentRenewSuccess(this.config, returnedState, tokens)
      }
      return accessToken
    } catch (error) {
      if (isSilentCallback && this.#isEmbedded()) {
        postSilentRenewError(
          this.config,
          returnedState,
          sessionStorage.getItem(this.explicitLogoutKey) === 'true'
            ? 'login_state_invalidated'
            : error instanceof TokenEndpointError && error.invalidatesCredentials
              ? 'invalid_grant'
              : 'token_exchange_failed',
        )
      }
      throw error
    }
  }

  async #refreshTokens(
    refreshToken: string,
    idToken: string | undefined,
    refreshGeneration: number,
  ): Promise<string> {
    const body = new URLSearchParams({
      grant_type: 'refresh_token',
      client_id: this.config.clientId,
      refresh_token: refreshToken,
    })
    const payload = await this.#requestTokens(body)
    return this.#storeTokenSet(
      this.#createTokenSet(payload, { refreshToken, idToken }),
      refreshGeneration,
    )
  }

  async #requestTokens(body: URLSearchParams): Promise<TokenEndpointResponse> {
    const response = await fetch(this.#issuerEndpoint('oauth2/token'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    })
    if (!response.ok) {
      let oauthError: string | undefined
      try {
        const errorPayload: unknown = await response.json()
        if (typeof errorPayload === 'object' && errorPayload !== null) {
          const candidate = (errorPayload as Record<string, unknown>).error
          if (typeof candidate === 'string') {
            oauthError = candidate
          }
        }
      } catch {
        // 非 JSON 错误响应仍按临时端点故障处理，保留现有凭据。
      }
      throw new TokenEndpointError(response.status, oauthError)
    }
    return parseTokenEndpointResponse(await response.json())
  }

  #createTokenSet(
    payload: TokenEndpointResponse,
    previous: { refreshToken?: string, idToken?: string },
  ): TokenSet {
    return {
      accessToken: payload.access_token,
      refreshToken: payload.refresh_token ?? previous.refreshToken,
      idToken: payload.id_token ?? previous.idToken,
      expiresAt: Date.now() + payload.expires_in * 1_000,
    }
  }

  #storeTokenSet(tokens: TokenSet, authGeneration: number): string {
    if (
      authGeneration !== this.authGeneration
      || sessionStorage.getItem(this.explicitLogoutKey) === 'true'
    ) {
      throw new Error('登录状态已失效')
    }
    this.tokenStore.set(tokens)
    this.#setAuthenticated(true)
    return tokens.accessToken
  }

  #isEmbedded(): boolean {
    return typeof window !== 'undefined' && window.parent !== window
  }

  #setAuthenticated(authenticated: boolean): void {
    if (this.authenticated === authenticated) {
      return
    }
    this.authenticated = authenticated
    this.authStateListeners.forEach((listener) => {
      const reportError = (error: unknown) => {
        console.error('认证状态订阅者执行失败', error)
      }
      try {
        void Promise.resolve(listener(authenticated)).catch(reportError)
      } catch (error) {
        reportError(error)
      }
    })
  }

  #issuerEndpoint(path: string): string {
    const issuerBase = this.config.issuer.endsWith('/')
      ? this.config.issuer
      : `${this.config.issuer}/`
    return new URL(path, issuerBase).toString()
  }
}

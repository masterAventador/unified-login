import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  SILENT_RENEW_MESSAGE_TYPE,
  SilentRenewClient,
  postSilentRenewError,
  postSilentRenewSuccess,
} from './silent-renew'
import { StateIndexedAuthorizationRequestStore } from './storage'
import { MemoryStorage } from './test-support'
import type { TokenSet } from './tokens'

const CONFIG = {
  issuer: 'http://localhost:9000',
  clientId: 'demo-web-b',
  redirectUri: 'http://localhost:5174/callback',
}
const TOKENS: TokenSet = {
  accessToken: 'silent-access-token',
  refreshToken: 'silent-refresh-token',
  idToken: 'silent-id-token',
  expiresAt: Date.parse('2026-07-30T01:00:00Z'),
}
const webCrypto = globalThis.crypto

interface BrowserHarness {
  readonly iframe: {
    hidden: boolean
    src: string
    readonly contentWindow: object
    readonly style: { display: string }
    readonly remove: ReturnType<typeof vi.fn>
    readonly setAttribute: ReturnType<typeof vi.fn>
  }
  readonly appendChild: ReturnType<typeof vi.fn>
  dispatchMessage(event: {
    origin: string
    source: object
    data: unknown
  }): void
}

afterEach(() => {
  vi.unstubAllGlobals()
})

function installBrowserHarness(): BrowserHarness {
  let messageHandler: ((event: MessageEvent) => void) | undefined
  const iframeWindow = {}
  const iframe = {
    hidden: false,
    src: '',
    contentWindow: iframeWindow,
    style: { display: '' },
    remove: vi.fn(),
    setAttribute: vi.fn(),
  }
  const appendChild = vi.fn()
  vi.stubGlobal('document', {
    createElement: vi.fn((tagName: string) => {
      expect(tagName).toBe('iframe')
      return iframe
    }),
    body: { appendChild },
  })
  vi.stubGlobal('window', {
    addEventListener: vi.fn((type: string, handler: (event: MessageEvent) => void) => {
      expect(type).toBe('message')
      messageHandler = handler
    }),
    removeEventListener: vi.fn((type: string, handler: (event: MessageEvent) => void) => {
      expect(type).toBe('message')
      if (messageHandler === handler) {
        messageHandler = undefined
      }
    }),
  })
  vi.stubGlobal('crypto', {
    getRandomValues: (target: Uint8Array) => {
      target.fill(0)
      return target
    },
    randomUUID: () => 'silent-state',
    subtle: webCrypto.subtle,
  })

  return {
    iframe,
    appendChild,
    dispatchMessage(event) {
      if (messageHandler === undefined) {
        throw new Error('message listener 尚未安装')
      }
      messageHandler(event as MessageEvent)
    },
  }
}

async function waitForIframe(harness: BrowserHarness): Promise<void> {
  await vi.waitFor(() => {
    expect(harness.appendChild).toHaveBeenCalledOnce()
  })
}

describe('SilentRenewClient.silentRenew', () => {
  it('用隐藏 iframe 发起 prompt=none，并只接受目标 iframe 从合法 origin 回传的令牌', async () => {
    const harness = installBrowserHarness()
    const storage = new MemoryStorage()
    const requestStore = new StateIndexedAuthorizationRequestStore(
      `${CONFIG.clientId}.silent`,
      storage,
    )
    const renewPromise = new SilentRenewClient(CONFIG, requestStore).silentRenew()
    await waitForIframe(harness)

    expect(harness.iframe.hidden).toBe(true)
    expect(harness.iframe.style.display).toBe('none')
    expect(harness.iframe.setAttribute).toHaveBeenCalledWith('aria-hidden', 'true')
    const authorizationUrl = new URL(harness.iframe.src)
    expect(`${authorizationUrl.origin}${authorizationUrl.pathname}`).toBe(
      'http://localhost:9000/oauth2/authorize',
    )
    expect(Object.fromEntries(authorizationUrl.searchParams)).toMatchObject({
      response_type: 'code',
      client_id: 'demo-web-b',
      redirect_uri: 'http://localhost:5174/callback',
      scope: 'openid',
      prompt: 'none',
      state: 'silent-state',
      code_challenge_method: 'S256',
    })
    expect(authorizationUrl.searchParams.get('code_challenge')).not.toBe('')
    expect(storage.getItem(
      'demo-web-b.silent.request.silent-state',
    )).not.toBeNull()

    let settled = false
    void renewPromise.finally(() => {
      settled = true
    })
    harness.dispatchMessage({
      origin: 'http://attacker.example.com',
      source: harness.iframe.contentWindow,
      data: {
        type: SILENT_RENEW_MESSAGE_TYPE,
        clientId: CONFIG.clientId,
        state: 'silent-state',
        status: 'success',
        tokens: { ...TOKENS, accessToken: 'attacker-token' },
      },
    })
    await Promise.resolve()
    expect(settled).toBe(false)

    harness.dispatchMessage({
      origin: 'http://localhost:5174',
      source: {},
      data: {
        type: SILENT_RENEW_MESSAGE_TYPE,
        clientId: CONFIG.clientId,
        state: 'silent-state',
        status: 'success',
        tokens: { ...TOKENS, accessToken: 'sibling-frame-token' },
      },
    })
    await Promise.resolve()
    expect(settled).toBe(false)

    harness.dispatchMessage({
      origin: 'http://localhost:5174',
      source: harness.iframe.contentWindow,
      data: {
        type: SILENT_RENEW_MESSAGE_TYPE,
        clientId: CONFIG.clientId,
        state: 'silent-state',
        status: 'success',
        tokens: TOKENS,
      },
    })

    await expect(renewPromise).resolves.toEqual(TOKENS)
    expect(harness.iframe.remove).toHaveBeenCalledOnce()
    expect(storage.length).toBe(0)
  })

  it('收到合法 login_required 时返回 null 并立即移除 iframe', async () => {
    const harness = installBrowserHarness()
    const requestStore = new StateIndexedAuthorizationRequestStore(
      `${CONFIG.clientId}.silent`,
      new MemoryStorage(),
    )
    const renewPromise = new SilentRenewClient(CONFIG, requestStore).silentRenew()
    await waitForIframe(harness)

    harness.dispatchMessage({
      origin: 'http://localhost:5174',
      source: harness.iframe.contentWindow,
      data: {
        type: SILENT_RENEW_MESSAGE_TYPE,
        clientId: CONFIG.clientId,
        state: 'silent-state',
        status: 'error',
        error: 'login_required',
      },
    })

    await expect(renewPromise).resolves.toBeNull()
    expect(harness.iframe.remove).toHaveBeenCalledOnce()
  })

  it('清理旧请求时不删除后来写入的 PKCE 凭据', async () => {
    const harness = installBrowserHarness()
    const storage = new MemoryStorage()
    const requestStore = new StateIndexedAuthorizationRequestStore(
      `${CONFIG.clientId}.silent`,
      storage,
    )
    const renewPromise = new SilentRenewClient(CONFIG, requestStore).silentRenew()
    await waitForIframe(harness)
    requestStore.save({ state: 'new-state', verifier: 'new-verifier' })

    harness.dispatchMessage({
      origin: 'http://localhost:5174',
      source: harness.iframe.contentWindow,
      data: {
        type: SILENT_RENEW_MESSAGE_TYPE,
        clientId: CONFIG.clientId,
        state: 'silent-state',
        status: 'error',
        error: 'login_required',
      },
    })

    await expect(renewPromise).resolves.toBeNull()
    expect(storage.getItem(
      'demo-web-b.silent.request.new-state',
    )).toBe('new-verifier')
  })

  it('可以主动取消仍在等待的 iframe 请求', async () => {
    const harness = installBrowserHarness()
    const storage = new MemoryStorage()
    const requestStore = new StateIndexedAuthorizationRequestStore(
      `${CONFIG.clientId}.silent`,
      storage,
    )
    const client = new SilentRenewClient(CONFIG, requestStore)
    const renewPromise = client.silentRenew()
    void renewPromise.catch(() => undefined)
    await waitForIframe(harness)

    client.cancel()

    await expect(renewPromise).rejects.toThrow('静默续签已取消')
    expect(harness.iframe.remove).toHaveBeenCalledOnce()
    expect(storage.length).toBe(0)
  })

  it('临时凭据清理失败时取消仍会拒绝请求并移除 iframe', async () => {
    const harness = installBrowserHarness()
    const storage = new MemoryStorage()
    const requestStore = new StateIndexedAuthorizationRequestStore(
      `${CONFIG.clientId}.silent`,
      storage,
    )
    const client = new SilentRenewClient(CONFIG, requestStore)
    const renewPromise = client.silentRenew()
    void renewPromise.catch(() => undefined)
    await waitForIframe(harness)
    vi.spyOn(storage, 'removeItem').mockImplementation(() => {
      throw new DOMException('storage unavailable', 'SecurityError')
    })

    expect(() => client.cancel()).not.toThrow()

    await expect(renewPromise).rejects.toThrow('静默续签已取消')
    expect(harness.iframe.remove).toHaveBeenCalledOnce()
  })

  it('超时后拒绝、移除 iframe 并清理临时凭据', async () => {
    const harness = installBrowserHarness()
    const storage = new MemoryStorage()
    const requestStore = new StateIndexedAuthorizationRequestStore(
      `${CONFIG.clientId}.silent`,
      storage,
    )
    const renewPromise = new SilentRenewClient(
      { ...CONFIG, timeoutMs: 5 },
      requestStore,
    ).silentRenew()
    const timeoutExpectation = expect(renewPromise).rejects.toThrow('静默续签超时')
    await waitForIframe(harness)

    await timeoutExpectation
    expect(harness.iframe.remove).toHaveBeenCalledOnce()
    expect(storage.length).toBe(0)
  })

  it('非 login_required 错误立即拒绝并移除 iframe', async () => {
    const harness = installBrowserHarness()
    const requestStore = new StateIndexedAuthorizationRequestStore(
      `${CONFIG.clientId}.silent`,
      new MemoryStorage(),
    )
    const renewPromise = new SilentRenewClient(CONFIG, requestStore).silentRenew()
    await waitForIframe(harness)

    harness.dispatchMessage({
      origin: 'http://localhost:5174',
      source: harness.iframe.contentWindow,
      data: {
        type: SILENT_RENEW_MESSAGE_TYPE,
        clientId: CONFIG.clientId,
        state: 'silent-state',
        status: 'error',
        error: 'token_exchange_failed',
      },
    })

    await expect(renewPromise).rejects.toThrow('静默续签失败：token_exchange_failed')
    expect(harness.iframe.remove).toHaveBeenCalledOnce()
  })
})

describe('静默续签回调消息', () => {
  it('只把成功或失败结果定向发送给 redirectUri 的源', () => {
    const postMessage = vi.fn()
    vi.stubGlobal('window', { parent: { postMessage } })

    postSilentRenewSuccess(CONFIG, 'returned-state', TOKENS)
    postSilentRenewError(CONFIG, 'returned-state', 'login_required')

    expect(postMessage).toHaveBeenNthCalledWith(1, {
      type: SILENT_RENEW_MESSAGE_TYPE,
      clientId: CONFIG.clientId,
      state: 'returned-state',
      status: 'success',
      tokens: TOKENS,
    }, 'http://localhost:5174')
    expect(postMessage).toHaveBeenNthCalledWith(2, {
      type: SILENT_RENEW_MESSAGE_TYPE,
      clientId: CONFIG.clientId,
      state: 'returned-state',
      status: 'error',
      error: 'login_required',
    }, 'http://localhost:5174')
  })
})

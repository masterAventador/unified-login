import { afterEach, describe, expect, it, vi } from 'vitest'

import WebAuthClient from './index'
import { MemoryStorage } from './test-support'

const CONFIG = {
  issuer: 'http://localhost:9000',
  clientId: 'demo-web-b',
  redirectUri: 'http://localhost:5174/callback',
}
const ZERO_BYTES_CHALLENGE = 'DwBzhbb51LfusnSGBa_hqYSgo7-j8BTQnip4TOnlzRo'
const webCrypto = globalThis.crypto

type Equal<Left, Right> =
  (<Value>() => Value extends Left ? 1 : 2) extends
    (<Value>() => Value extends Right ? 1 : 2)
    ? true
    : false
type Assert<Condition extends true> = Condition
type _PublicApiIsExactlyFourMethods = Assert<Equal<
  keyof WebAuthClient,
  'login' | 'logout' | 'getAccessToken' | 'onAuthStateChange'
>>

afterEach(() => {
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

function stubLocation(href: string): void {
  const url = new URL(href)
  vi.stubGlobal('location', {
    assign: vi.fn(),
    href: url.toString(),
    origin: url.origin,
    pathname: url.pathname,
    search: url.search,
  })
}

describe('WebAuthClient.login', () => {
  it('运行时原型只公开规格规定的四个方法', () => {
    expect(Object.getOwnPropertyNames(WebAuthClient.prototype).sort()).toEqual([
      'constructor',
      'getAccessToken',
      'login',
      'logout',
      'onAuthStateChange',
    ])
  })

  it('保存 PKCE 请求并整页跳转到 authorization code 授权端点', async () => {
    const storage = new MemoryStorage()
    const assign = vi.fn()
    vi.stubGlobal('sessionStorage', storage)
    vi.stubGlobal('location', {
      assign,
      href: 'http://localhost:5174/',
      origin: 'http://localhost:5174',
      pathname: '/',
      search: '',
    })
    vi.stubGlobal('crypto', {
      getRandomValues: (target: Uint8Array) => {
        target.fill(0)
        return target
      },
      randomUUID: () => 'fixed-login-state',
      subtle: webCrypto.subtle,
    })

    await new WebAuthClient(CONFIG).login()

    expect(storage.getItem('demo-web-b.state')).toBe('fixed-login-state')
    expect(storage.getItem('demo-web-b.code_verifier')).toBe('A'.repeat(43))
    expect(assign).toHaveBeenCalledOnce()
    const authorizationUrl = new URL(assign.mock.calls[0]?.[0] as string)
    expect(`${authorizationUrl.origin}${authorizationUrl.pathname}`).toBe(
      'http://localhost:9000/oauth2/authorize',
    )
    expect(Object.fromEntries(authorizationUrl.searchParams)).toEqual({
      response_type: 'code',
      client_id: 'demo-web-b',
      redirect_uri: 'http://localhost:5174/callback',
      scope: 'openid',
      state: 'fixed-login-state',
      code_challenge: ZERO_BYTES_CHALLENGE,
      code_challenge_method: 'S256',
    })
  })
})

describe('WebAuthClient.getAccessToken 回调处理', () => {
  it('校验并一次性清除 state/verifier 后，无 Bearer 头换取令牌', async () => {
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    const replaceState = vi.fn()
    const fetchMock = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
      expect(storage.length).toBe(0)
      expect(init?.headers).toEqual({
        'Content-Type': 'application/x-www-form-urlencoded',
      })
      return new Response(JSON.stringify({
        access_token: 'access-token',
        refresh_token: 'refresh-token',
        id_token: 'id-token',
        expires_in: 900,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    })
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', { state: {}, replaceState })
    vi.stubGlobal('fetch', fetchMock)

    const client = new WebAuthClient(CONFIG)

    await expect(client.getAccessToken()).resolves.toBe('access-token')
    await expect(client.getAccessToken()).resolves.toBe('access-token')
    expect(fetchMock).toHaveBeenCalledOnce()
    const [input, init] = fetchMock.mock.calls[0]!
    expect(input).toBe('http://localhost:9000/oauth2/token')
    expect(Object.fromEntries(new URLSearchParams(init?.body as string))).toEqual({
      grant_type: 'authorization_code',
      client_id: 'demo-web-b',
      code: 'one-time-code',
      redirect_uri: 'http://localhost:5174/callback',
      code_verifier: 'code-verifier',
    })
    expect(replaceState).toHaveBeenCalledWith({}, '', '/callback')
  })

  it('授权回调处理中的并发调用共享同一次授权码交换', async () => {
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    let resolveTokenExchange!: (response: Response) => void
    const tokenExchangeResponse = new Promise<Response>((resolve) => {
      resolveTokenExchange = resolve
    })
    const fetchMock = vi.fn().mockReturnValue(tokenExchangeResponse)
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', {
      replaceState: vi.fn((_state, _title, url: string) => {
        stubLocation(new URL(url, location.href).toString())
      }),
    })
    vi.stubGlobal('fetch', fetchMock)
    const client = new WebAuthClient(CONFIG)

    const firstToken = client.getAccessToken()
    const secondToken = client.getAccessToken()

    expect(fetchMock).toHaveBeenCalledOnce()
    resolveTokenExchange(new Response(JSON.stringify({
      access_token: 'access-token',
      refresh_token: 'refresh-token',
      id_token: 'id-token',
      expires_in: 900,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))
    await expect(Promise.all([firstToken, secondToken])).resolves.toEqual([
      'access-token',
      'access-token',
    ])
    expect(fetchMock).toHaveBeenCalledOnce()
  })

  it('清理 OAuth 回调参数时保留应用自身的查询参数', async () => {
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    const replaceState = vi.fn()
    vi.stubGlobal('sessionStorage', storage)
    stubLocation(
      'http://localhost:5174/callback?tenant=acme&code=one-time-code&state=expected-state',
    )
    vi.stubGlobal('history', { state: {}, replaceState })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      access_token: 'access-token',
      refresh_token: 'refresh-token',
      id_token: 'id-token',
      expires_in: 900,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })))
    const client = new WebAuthClient({
      ...CONFIG,
      redirectUri: 'http://localhost:5174/callback?tenant=acme',
    })

    await expect(client.getAccessToken()).resolves.toBe('access-token')

    expect(replaceState).toHaveBeenCalledWith({}, '', '/callback?tenant=acme')
  })

  it('清理 OAuth 回调参数时保留宿主 SPA 的 history.state', async () => {
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    const routeState = { idx: 4, key: 'callback-route', scrollY: 320 }
    const replaceState = vi.fn()
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', { state: routeState, replaceState })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      access_token: 'access-token',
      refresh_token: 'refresh-token',
      id_token: 'id-token',
      expires_in: 900,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })))
    const client = new WebAuthClient(CONFIG)

    await expect(client.getAccessToken()).resolves.toBe('access-token')

    expect(replaceState).toHaveBeenCalledWith(routeState, '', '/callback')
  })

  it('state 不匹配时丢弃 code 与临时凭据且绝不请求令牌端点', async () => {
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    const fetchMock = vi.fn()
    const replaceState = vi.fn()
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=stolen-code&state=attacker-state')
    vi.stubGlobal('history', { state: {}, replaceState })
    vi.stubGlobal('fetch', fetchMock)

    const client = new WebAuthClient(CONFIG)

    await expect(client.getAccessToken()).rejects.toThrow('state 校验失败')
    expect(fetchMock).not.toHaveBeenCalled()
    expect(storage.length).toBe(0)
    expect(replaceState).toHaveBeenCalledWith({}, '', '/callback')
  })

  it('令牌端点拒绝授权码时不建立伪登录态', async () => {
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    const authStateListener = vi.fn()
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      error: 'invalid_grant',
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    }))
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=expired-code&state=expected-state')
    vi.stubGlobal('history', { replaceState: vi.fn() })
    vi.stubGlobal('fetch', fetchMock)
    const client = new WebAuthClient(CONFIG)
    client.onAuthStateChange(authStateListener)

    await expect(client.getAccessToken()).rejects.toThrow('换取令牌失败：400')
    expect(authStateListener).not.toHaveBeenCalled()
    stubLocation('http://localhost:5174/')
    await expect(client.getAccessToken()).rejects.toThrow('当前没有可用的登录令牌')
    expect(fetchMock).toHaveBeenCalledOnce()
  })

  it.each([
    ['access_token', {
      refresh_token: 'refresh-token',
      id_token: 'id-token',
      expires_in: 900,
    }],
    ['refresh_token', {
      access_token: 'access-token',
      id_token: 'id-token',
      expires_in: 900,
    }],
    ['id_token', {
      access_token: 'access-token',
      refresh_token: 'refresh-token',
      expires_in: 900,
    }],
    ['expires_in', {
      access_token: 'access-token',
      refresh_token: 'refresh-token',
      id_token: 'id-token',
    }],
  ])('令牌端点返回缺少 %s 的 200 响应时拒绝建立登录态', async (_field, payload) => {
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    const authStateListener = vi.fn()
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify(payload), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', { replaceState: vi.fn() })
    vi.stubGlobal('fetch', fetchMock)
    const client = new WebAuthClient(CONFIG)
    client.onAuthStateChange(authStateListener)

    await expect(client.getAccessToken()).rejects.toThrow('令牌响应格式无效')
    expect(authStateListener).not.toHaveBeenCalled()
    stubLocation('http://localhost:5174/')
    await expect(client.getAccessToken()).rejects.toThrow('当前没有可用的登录令牌')
  })
})

describe('WebAuthClient.getAccessToken 自动刷新', () => {
  it('十个并发调用共享同一次无 Bearer 头的 refresh token 请求', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-07-30T00:00:00Z'))
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    let resolveRefresh!: (response: Response) => void
    const refreshResponse = new Promise<Response>((resolve) => {
      resolveRefresh = resolve
    })
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        access_token: 'old-access-token',
        refresh_token: 'old-refresh-token',
        id_token: 'id-token',
        expires_in: 30,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }))
      .mockReturnValueOnce(refreshResponse)
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', { replaceState: vi.fn() })
    vi.stubGlobal('fetch', fetchMock)
    const client = new WebAuthClient(CONFIG)
    await client.getAccessToken()
    stubLocation('http://localhost:5174/')

    const pendingTokens = Array.from({ length: 10 }, () => client.getAccessToken())

    expect(fetchMock).toHaveBeenCalledTimes(2)
    const [input, init] = fetchMock.mock.calls[1]!
    expect(input).toBe('http://localhost:9000/oauth2/token')
    expect(init?.headers).toEqual({
      'Content-Type': 'application/x-www-form-urlencoded',
    })
    expect(Object.fromEntries(new URLSearchParams(init?.body as string))).toEqual({
      grant_type: 'refresh_token',
      client_id: 'demo-web-b',
      refresh_token: 'old-refresh-token',
    })

    resolveRefresh(new Response(JSON.stringify({
      access_token: 'new-access-token',
      refresh_token: 'new-refresh-token',
      expires_in: 900,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))

    await expect(Promise.all(pendingTokens)).resolves.toEqual(
      Array.from({ length: 10 }, () => 'new-access-token'),
    )
    await expect(client.getAccessToken()).resolves.toBe('new-access-token')
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('刷新被拒绝时清除旧令牌并通知退出登录', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-07-30T00:00:00Z'))
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    const authStateListener = vi.fn()
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        access_token: 'old-access-token',
        refresh_token: 'old-refresh-token',
        id_token: 'id-token',
        expires_in: 30,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: 'invalid_grant',
      }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      }))
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', { replaceState: vi.fn() })
    vi.stubGlobal('fetch', fetchMock)
    const client = new WebAuthClient(CONFIG)
    client.onAuthStateChange(authStateListener)
    await client.getAccessToken()
    stubLocation('http://localhost:5174/')

    await expect(client.getAccessToken()).rejects.toThrow('换取令牌失败：400')

    expect(authStateListener).toHaveBeenNthCalledWith(1, true)
    expect(authStateListener).toHaveBeenNthCalledWith(2, false)
    await expect(client.getAccessToken()).rejects.toThrow('当前没有可用的登录令牌')
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('临时刷新故障保留凭据与登录态并允许稍后重试', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-07-30T00:00:00Z'))
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    const authStateListener = vi.fn()
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        access_token: 'old-access-token',
        refresh_token: 'old-refresh-token',
        id_token: 'id-token',
        expires_in: 30,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        error: 'temporarily_unavailable',
      }), {
        status: 503,
        headers: { 'Content-Type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        access_token: 'new-access-token',
        refresh_token: 'new-refresh-token',
        expires_in: 900,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }))
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', { replaceState: vi.fn() })
    vi.stubGlobal('fetch', fetchMock)
    const client = new WebAuthClient(CONFIG)
    client.onAuthStateChange(authStateListener)
    await client.getAccessToken()
    stubLocation('http://localhost:5174/')

    await expect(client.getAccessToken()).rejects.toThrow('换取令牌失败：503')
    expect(authStateListener.mock.calls).toEqual([[true]])
    await expect(client.getAccessToken()).resolves.toBe('new-access-token')
    expect(authStateListener.mock.calls).toEqual([[true]])
    expect(fetchMock).toHaveBeenCalledTimes(3)
  })

  it('登出发生在刷新途中时，迟到的响应不能恢复登录态', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-07-30T00:00:00Z'))
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    let resolveRefresh!: (response: Response) => void
    const refreshResponse = new Promise<Response>((resolve) => {
      resolveRefresh = resolve
    })
    const authStateListener = vi.fn()
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        access_token: 'old-access-token',
        refresh_token: 'old-refresh-token',
        id_token: 'id-token',
        expires_in: 30,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }))
      .mockReturnValueOnce(refreshResponse)
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', { replaceState: vi.fn() })
    vi.stubGlobal('fetch', fetchMock)
    const client = new WebAuthClient(CONFIG)
    client.onAuthStateChange(authStateListener)
    await client.getAccessToken()
    stubLocation('http://localhost:5174/')
    const pendingRefresh = client.getAccessToken()
    expect(fetchMock).toHaveBeenCalledTimes(2)

    client.logout()
    resolveRefresh(new Response(JSON.stringify({
      access_token: 'late-access-token',
      refresh_token: 'late-refresh-token',
      expires_in: 900,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))

    await expect(pendingRefresh).rejects.toThrow('登录状态已失效')
    await expect(client.getAccessToken()).rejects.toThrow('当前没有可用的登录令牌')
    expect(authStateListener.mock.calls).toEqual([[true], [false]])
  })
})

describe('WebAuthClient 登录态订阅与登出', () => {
  it('通知登录态变化、支持取消订阅，登出只清本地令牌', async () => {
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      access_token: 'access-token',
      refresh_token: 'refresh-token',
      id_token: 'id-token',
      expires_in: 900,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))
    const removedListener = vi.fn()
    const activeListener = vi.fn()
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', { replaceState: vi.fn() })
    vi.stubGlobal('fetch', fetchMock)
    const client = new WebAuthClient(CONFIG)
    const unsubscribe = client.onAuthStateChange(removedListener)
    client.onAuthStateChange(activeListener)

    await client.getAccessToken()
    expect(removedListener).toHaveBeenCalledExactlyOnceWith(true)
    expect(activeListener).toHaveBeenCalledExactlyOnceWith(true)

    unsubscribe()
    stubLocation('http://localhost:5174/')
    client.logout()

    expect(removedListener).toHaveBeenCalledExactlyOnceWith(true)
    expect(activeListener).toHaveBeenNthCalledWith(2, false)
    await expect(client.getAccessToken()).rejects.toThrow('当前没有可用的登录令牌')
    expect(fetchMock).toHaveBeenCalledOnce()
  })
})

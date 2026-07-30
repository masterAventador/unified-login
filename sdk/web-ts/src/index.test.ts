import { afterEach, describe, expect, it, vi } from 'vitest'

import WebAuthClient from './index'
import { SILENT_RENEW_MESSAGE_TYPE } from './silent-renew'
import { MemoryStorage } from './test-support'

const CONFIG = {
  issuer: 'http://localhost:9000',
  clientId: 'demo-web-b',
  redirectUri: 'http://localhost:5174/callback',
}
const ZERO_BYTES_CHALLENGE = 'DwBzhbb51LfusnSGBa_hqYSgo7-j8BTQnip4TOnlzRo'
const INVALIDATED_AUTH_MARKER = 'invalidated'
const loginMarker = (generation: number | string) => `login:${generation}`
const RECOVERED_AUTH_GENERATION_PATTERN =
  /^recovered:[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}:0$/
const webCrypto = globalThis.crypto

class LogoutMarkerWriteFailureStorage extends MemoryStorage {
  override setItem(key: string, value: string): void {
    if (key === `${CONFIG.clientId}.explicit_logout`) {
      throw new DOMException('storage quota exceeded', 'QuotaExceededError')
    }
    super.setItem(key, value)
  }
}

class AuthGenerationWriteFailureStorage extends MemoryStorage {
  override setItem(key: string, value: string): void {
    if (key === `${CONFIG.clientId}.auth_generation`) {
      throw new DOMException('storage quota exceeded', 'QuotaExceededError')
    }
    super.setItem(key, value)
  }
}

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
  vi.restoreAllMocks()
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

  it.each([
    'not-an-integer',
    '',
    ' 1 ',
    '01',
    '-1',
    '1.5',
    '9007199254740992',
  ])('损坏的共享代次 %j 使当前身份失效但允许重新登录恢复', async (
    storedGeneration,
  ) => {
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.auth_generation', storedGeneration)
    const assign = vi.fn()
    vi.stubGlobal('sessionStorage', storage)
    vi.stubGlobal('location', {
      assign,
      href: 'http://localhost:5174/',
      origin: 'http://localhost:5174',
      pathname: '/',
      search: '',
    })
    const client = new WebAuthClient(CONFIG)

    const recoveredGeneration = storage.getItem('demo-web-b.auth_generation')
    expect(recoveredGeneration).toMatch(RECOVERED_AUTH_GENERATION_PATTERN)
    expect(storage.getItem('demo-web-b.explicit_logout')).toBe(
      INVALIDATED_AUTH_MARKER,
    )
    await expect(client.getAccessToken()).rejects.toThrow(
      '当前没有可用的登录令牌',
    )

    await client.login()

    const loginGeneration = recoveredGeneration!.replace(/:0$/, ':1')
    expect(storage.getItem('demo-web-b.auth_generation')).toBe(loginGeneration)
    expect(storage.getItem('demo-web-b.explicit_logout')).toBe(
      loginMarker(loginGeneration),
    )
    expect(assign).toHaveBeenCalledOnce()
  })

  it('损坏代次恢复后新登录不得因 ABA 碰撞重新放行旧实例', async () => {
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.auth_generation', '1')
    storage.setItem('demo-web-b.state', 'old-state')
    storage.setItem('demo-web-b.code_verifier', 'old-verifier')
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        access_token: 'old-access-token',
        refresh_token: 'old-refresh-token',
        id_token: 'old-id-token',
        expires_in: 900,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        access_token: 'new-access-token',
        refresh_token: 'new-refresh-token',
        id_token: 'new-id-token',
        expires_in: 900,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }))
    vi.stubGlobal('sessionStorage', storage)
    vi.stubGlobal('history', { state: null, replaceState: vi.fn() })
    vi.stubGlobal('fetch', fetchMock)
    stubLocation('http://localhost:5174/callback?code=old-code&state=old-state')
    const oldClient = new WebAuthClient(CONFIG)
    await oldClient.getAccessToken()

    storage.setItem('demo-web-b.auth_generation', 'corrupt')
    stubLocation('http://localhost:5174/')
    const reloginClient = new WebAuthClient(CONFIG)
    await reloginClient.login()
    const newState = storage.getItem('demo-web-b.state')
    stubLocation(`http://localhost:5174/callback?code=new-code&state=${newState}`)
    const newClient = new WebAuthClient(CONFIG)
    await expect(newClient.getAccessToken()).resolves.toBe('new-access-token')
    stubLocation('http://localhost:5174/')

    await expect(oldClient.getAccessToken()).rejects.toThrow(
      '当前没有可用的登录令牌',
    )
  })

  it('保存 PKCE 请求并整页跳转到 authorization code 授权端点', async () => {
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.explicit_logout', INVALIDATED_AUTH_MARKER)
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

    expect(storage.getItem('demo-web-b.explicit_logout')).toBe(loginMarker(1))
    expect(storage.getItem('demo-web-b.auth_generation')).toBe('1')
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

  it('切换账号时由 SDK 添加 prompt=login 强制重新认证', async () => {
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
      randomUUID: () => 'switch-account-state',
      subtle: webCrypto.subtle,
    })

    await new WebAuthClient(CONFIG).login({ prompt: 'login' })

    const authorizationUrl = new URL(assign.mock.calls[0]?.[0] as string)
    expect(authorizationUrl.searchParams.get('prompt')).toBe('login')
  })

  it('登录保护标记写入失败时在失效现有身份与跳转前终止', async () => {
    const storage = new LogoutMarkerWriteFailureStorage()
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    const assign = vi.fn()
    const authStateListener = vi.fn()
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      access_token: 'old-access-token',
      refresh_token: 'old-refresh-token',
      id_token: 'old-id-token',
      expires_in: 900,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', { state: null, replaceState: vi.fn() })
    vi.stubGlobal('fetch', fetchMock)
    const client = new WebAuthClient(CONFIG)
    client.onAuthStateChange(authStateListener)
    await client.getAccessToken()
    vi.stubGlobal('location', {
      assign,
      href: 'http://localhost:5174/',
      origin: 'http://localhost:5174',
      pathname: '/',
      search: '',
    })

    await expect(client.login()).rejects.toThrow(
      'storage quota exceeded',
    )

    expect(storage.getItem('demo-web-b.auth_generation')).toBeNull()
    expect(storage.getItem('demo-web-b.state')).toBeNull()
    expect(storage.getItem('demo-web-b.code_verifier')).toBeNull()
    expect(authStateListener.mock.calls).toEqual([[true]])
    await expect(client.getAccessToken()).resolves.toBe('old-access-token')
    expect(fetchMock).toHaveBeenCalledOnce()
    expect(assign).not.toHaveBeenCalled()
  })

  it('共享代次写入失败时仍清除当前身份并通知退出登录', async () => {
    const storage = new AuthGenerationWriteFailureStorage()
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    const authStateListener = vi.fn()
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      access_token: 'old-access-token',
      refresh_token: 'old-refresh-token',
      id_token: 'old-id-token',
      expires_in: 900,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', { state: null, replaceState: vi.fn() })
    vi.stubGlobal('fetch', fetchMock)
    const client = new WebAuthClient(CONFIG)
    client.onAuthStateChange(authStateListener)
    await client.getAccessToken()
    stubLocation('http://localhost:5174/')

    await expect(client.login()).rejects.toThrow('storage quota exceeded')

    expect(storage.getItem('demo-web-b.explicit_logout')).toBe(INVALIDATED_AUTH_MARKER)
    expect(authStateListener.mock.calls).toEqual([[true], [false]])
    await expect(client.getAccessToken()).rejects.toThrow(
      '当前没有可用的登录令牌',
    )
    expect(fetchMock).toHaveBeenCalledOnce()
  })

  it('退出通知中同步发起的新登录不得被外层旧登录覆盖', async () => {
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.state', 'old-state')
    storage.setItem('demo-web-b.code_verifier', 'old-verifier')
    const assign = vi.fn()
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      access_token: 'old-access-token',
      refresh_token: 'old-refresh-token',
      id_token: 'old-id-token',
      expires_in: 900,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=old-code&state=old-state')
    vi.stubGlobal('history', { state: null, replaceState: vi.fn() })
    vi.stubGlobal('fetch', fetchMock)
    const client = new WebAuthClient(CONFIG)
    await client.getAccessToken()
    vi.stubGlobal('location', {
      assign,
      href: 'http://localhost:5174/',
      origin: 'http://localhost:5174',
      pathname: '/',
      search: '',
    })
    let newestLogin: Promise<void> | undefined
    client.onAuthStateChange((authenticated) => {
      if (!authenticated && newestLogin === undefined) {
        newestLogin = client.login()
      }
    })

    const supersededLogin = client.login()

    await expect(supersededLogin).rejects.toThrow('登录状态已失效')
    await expect(newestLogin).resolves.toBeUndefined()
    expect(storage.getItem('demo-web-b.auth_generation')).toBe('2')
    expect(storage.getItem('demo-web-b.explicit_logout')).toBe(loginMarker(2))
    expect(assign).toHaveBeenCalledOnce()

    const callbackState = storage.getItem('demo-web-b.state')
    stubLocation(`http://localhost:5174/callback?code=new-code&state=${callbackState}`)
    vi.stubGlobal('history', { state: null, replaceState: vi.fn() })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      access_token: 'new-access-token',
      refresh_token: 'new-refresh-token',
      id_token: 'new-id-token',
      expires_in: 900,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })))

    await expect(new WebAuthClient(CONFIG).getAccessToken()).resolves.toBe(
      'new-access-token',
    )
    expect(storage.getItem('demo-web-b.explicit_logout')).toBeNull()
  })

  it('重复登录推进代次时立即废止上一轮尚未回调的授权请求', async () => {
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.state', 'old-state')
    storage.setItem('demo-web-b.code_verifier', 'old-verifier')
    let resolveDigest!: (value: ArrayBuffer) => void
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/')
    vi.stubGlobal('crypto', {
      getRandomValues: webCrypto.getRandomValues.bind(webCrypto),
      randomUUID: () => 'new-state',
      subtle: {
        digest: vi.fn(() => new Promise<ArrayBuffer>((resolve) => {
          resolveDigest = resolve
        })),
      },
    })
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      access_token: 'old-access-token',
      refresh_token: 'old-refresh-token',
      id_token: 'old-id-token',
      expires_in: 900,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))
    vi.stubGlobal('fetch', fetchMock)
    const reloginClient = new WebAuthClient(CONFIG)

    const pendingLogin = reloginClient.login()

    expect(storage.getItem('demo-web-b.state')).toBeNull()
    expect(storage.getItem('demo-web-b.code_verifier')).toBeNull()
    stubLocation('http://localhost:5174/callback?code=old-code&state=old-state')
    vi.stubGlobal('history', { state: null, replaceState: vi.fn() })
    await expect(new WebAuthClient(CONFIG).getAccessToken()).rejects.toThrow(
      '回调缺少必要参数',
    )
    expect(fetchMock).not.toHaveBeenCalled()

    resolveDigest(new Uint8Array(32).buffer)
    await pendingLogin
  })

  it('重新登录通知退出前先让同 clientId 的其他实例失效', async () => {
    const storage = new MemoryStorage()
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        access_token: 'first-access-token',
        refresh_token: 'first-refresh-token',
        id_token: 'first-id-token',
        expires_in: 900,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        access_token: 'second-access-token',
        refresh_token: 'second-refresh-token',
        id_token: 'second-id-token',
        expires_in: 900,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }))
    vi.stubGlobal('sessionStorage', storage)
    vi.stubGlobal('history', { state: null, replaceState: vi.fn() })
    vi.stubGlobal('fetch', fetchMock)
    const firstClient = new WebAuthClient(CONFIG)
    const secondClient = new WebAuthClient(CONFIG)
    storage.setItem('demo-web-b.state', 'first-state')
    storage.setItem('demo-web-b.code_verifier', 'first-verifier')
    stubLocation('http://localhost:5174/callback?code=first-code&state=first-state')
    await firstClient.getAccessToken()
    storage.setItem('demo-web-b.state', 'second-state')
    storage.setItem('demo-web-b.code_verifier', 'second-verifier')
    stubLocation('http://localhost:5174/callback?code=second-code&state=second-state')
    await secondClient.getAccessToken()
    stubLocation('http://localhost:5174/')
    let tokenRequestedDuringNotification: Promise<string> | undefined
    firstClient.onAuthStateChange((authenticated) => {
      if (!authenticated) {
        tokenRequestedDuringNotification = secondClient.getAccessToken()
        void tokenRequestedDuringNotification.catch(() => undefined)
      }
    })

    await firstClient.login()

    await expect(tokenRequestedDuringNotification).rejects.toThrow(
      '当前没有可用的登录令牌',
    )
  })

  it('登出后重新登录期间仍让同 clientId 的旧实例保持失效', async () => {
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', { state: null, replaceState: vi.fn() })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      access_token: 'old-access-token',
      refresh_token: 'old-refresh-token',
      id_token: 'old-id-token',
      expires_in: 900,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })))
    const oldClient = new WebAuthClient(CONFIG)
    const reloginClient = new WebAuthClient(CONFIG)
    await oldClient.getAccessToken()
    stubLocation('http://localhost:5174/')
    reloginClient.logout()

    let resolveDigest!: (value: ArrayBuffer) => void
    vi.stubGlobal('crypto', {
      getRandomValues: webCrypto.getRandomValues.bind(webCrypto),
      randomUUID: () => 'relogin-state',
      subtle: {
        digest: vi.fn(() => new Promise<ArrayBuffer>((resolve) => {
          resolveDigest = resolve
        })),
      },
    })

    const pendingLogin = reloginClient.login()

    expect(storage.getItem('demo-web-b.explicit_logout')).toBe(loginMarker(2))
    await expect(oldClient.getAccessToken()).rejects.toThrow(
      '当前没有可用的登录令牌',
    )

    resolveDigest(new Uint8Array(32).buffer)
    await pendingLogin
  })
})

describe('WebAuthClient.getAccessToken 回调处理', () => {
  it('重新登录的授权码成功换令牌后才解除显式登出保护', async () => {
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.explicit_logout', loginMarker(1))
    storage.setItem('demo-web-b.auth_generation', '1')
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', { state: null, replaceState: vi.fn() })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      access_token: 'new-access-token',
      refresh_token: 'new-refresh-token',
      id_token: 'new-id-token',
      expires_in: 900,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })))

    const client = new WebAuthClient(CONFIG)

    await expect(client.getAccessToken()).resolves.toBe('new-access-token')
    expect(storage.getItem('demo-web-b.explicit_logout')).toBeNull()
  })

  it('授权码交换期间发生跨实例登出时迟到响应不得撤销登出', async () => {
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.explicit_logout', loginMarker(1))
    storage.setItem('demo-web-b.auth_generation', '1')
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    let resolveTokenExchange!: (response: Response) => void
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', { state: null, replaceState: vi.fn() })
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>((resolve) => {
      resolveTokenExchange = resolve
    })))
    const callbackClient = new WebAuthClient(CONFIG)
    const logoutClient = new WebAuthClient(CONFIG)

    const pendingCallback = callbackClient.getAccessToken()
    logoutClient.logout()
    resolveTokenExchange(new Response(JSON.stringify({
      access_token: 'late-access-token',
      refresh_token: 'late-refresh-token',
      id_token: 'late-id-token',
      expires_in: 900,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))

    await expect(pendingCallback).rejects.toThrow('登录状态已失效')
    expect(storage.getItem('demo-web-b.explicit_logout')).toBe(INVALIDATED_AUTH_MARKER)
  })

  it('共享代次写入失败时迟到授权回调仍不得撤销跨实例登出', async () => {
    const storage = new AuthGenerationWriteFailureStorage()
    storage.setItem('demo-web-b.explicit_logout', loginMarker(0))
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    let resolveTokenExchange!: (response: Response) => void
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', { state: null, replaceState: vi.fn() })
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>((resolve) => {
      resolveTokenExchange = resolve
    })))
    const callbackClient = new WebAuthClient(CONFIG)
    const logoutClient = new WebAuthClient(CONFIG)

    const pendingCallback = callbackClient.getAccessToken()
    logoutClient.logout()
    resolveTokenExchange(new Response(JSON.stringify({
      access_token: 'late-access-token',
      refresh_token: 'late-refresh-token',
      id_token: 'late-id-token',
      expires_in: 900,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))

    await expect(pendingCallback).rejects.toThrow('登录状态已失效')
    expect(storage.getItem('demo-web-b.explicit_logout')).toBe(INVALIDATED_AUTH_MARKER)
  })

  it('授权码交换期间当前实例登出时迟到响应不得撤销登出', async () => {
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.explicit_logout', loginMarker(1))
    storage.setItem('demo-web-b.auth_generation', '1')
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    let resolveTokenExchange!: (response: Response) => void
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', {
      state: null,
      replaceState: vi.fn((_state, _title, url: string) => {
        stubLocation(new URL(url, location.href).toString())
      }),
    })
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>((resolve) => {
      resolveTokenExchange = resolve
    })))
    const client = new WebAuthClient(CONFIG)

    const pendingCallback = client.getAccessToken()
    client.logout()
    resolveTokenExchange(new Response(JSON.stringify({
      access_token: 'late-access-token',
      refresh_token: 'late-refresh-token',
      id_token: 'late-id-token',
      expires_in: 900,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))

    await expect(pendingCallback).rejects.toThrow('登录状态已失效')
    expect(storage.getItem('demo-web-b.explicit_logout')).toBe(INVALIDATED_AUTH_MARKER)
    await expect(client.getAccessToken()).rejects.toThrow('当前没有可用的登录令牌')
  })

  it('授权码交换期间发生跨实例登出后新调用不得复用在途回调', async () => {
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.explicit_logout', loginMarker(1))
    storage.setItem('demo-web-b.auth_generation', '1')
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    let resolveTokenExchange!: (response: Response) => void
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', {
      state: null,
      replaceState: vi.fn((_state, _title, url: string) => {
        stubLocation(new URL(url, location.href).toString())
      }),
    })
    vi.stubGlobal('fetch', vi.fn(() => new Promise<Response>((resolve) => {
      resolveTokenExchange = resolve
    })))
    const callbackClient = new WebAuthClient(CONFIG)
    const logoutClient = new WebAuthClient(CONFIG)

    const pendingCallback = callbackClient.getAccessToken()
    logoutClient.logout()
    const postLogoutRequest = callbackClient.getAccessToken()
    resolveTokenExchange(new Response(JSON.stringify({
      access_token: 'late-access-token',
      refresh_token: 'late-refresh-token',
      id_token: 'late-id-token',
      expires_in: 900,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))

    await expect(postLogoutRequest).rejects.toThrow('当前没有可用的登录令牌')
    await expect(pendingCallback).rejects.toThrow('登录状态已失效')
  })

  it('重新登录成功并解除保护后旧实例仍不得返回旧身份令牌', async () => {
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.state', 'old-state')
    storage.setItem('demo-web-b.code_verifier', 'old-verifier')
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        access_token: 'old-access-token',
        refresh_token: 'old-refresh-token',
        id_token: 'old-id-token',
        expires_in: 900,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        access_token: 'new-access-token',
        refresh_token: 'new-refresh-token',
        id_token: 'new-id-token',
        expires_in: 900,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }))
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=old-code&state=old-state')
    vi.stubGlobal('history', { state: null, replaceState: vi.fn() })
    vi.stubGlobal('fetch', fetchMock)
    const oldClient = new WebAuthClient(CONFIG)
    await expect(oldClient.getAccessToken()).resolves.toBe('old-access-token')

    storage.setItem('demo-web-b.auth_generation', '1')
    storage.setItem('demo-web-b.explicit_logout', loginMarker(1))
    storage.setItem('demo-web-b.state', 'new-state')
    storage.setItem('demo-web-b.code_verifier', 'new-verifier')
    stubLocation('http://localhost:5174/callback?code=new-code&state=new-state')
    const newClient = new WebAuthClient(CONFIG)
    await expect(newClient.getAccessToken()).resolves.toBe('new-access-token')
    stubLocation('http://localhost:5174/')

    await expect(oldClient.getAccessToken()).rejects.toThrow(
      '当前没有可用的登录令牌',
    )
  })

  it('旧代次实例不得借新登录回调消费授权码与 PKCE 状态', async () => {
    const storage = new MemoryStorage()
    const fetchMock = vi.fn()
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/')
    const oldClient = new WebAuthClient(CONFIG)

    storage.setItem('demo-web-b.auth_generation', '1')
    storage.setItem('demo-web-b.explicit_logout', loginMarker(1))
    storage.setItem('demo-web-b.state', 'new-state')
    storage.setItem('demo-web-b.code_verifier', 'new-verifier')
    stubLocation('http://localhost:5174/callback?code=new-code&state=new-state')
    vi.stubGlobal('history', { state: null, replaceState: vi.fn() })
    vi.stubGlobal('fetch', fetchMock)

    await expect(oldClient.getAccessToken()).rejects.toThrow('登录状态已失效')
    expect(fetchMock).not.toHaveBeenCalled()
    expect(storage.getItem('demo-web-b.state')).toBe('new-state')
    expect(storage.getItem('demo-web-b.code_verifier')).toBe('new-verifier')
  })

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

  it('重新登录标记存在时并发回调仍共享同一次授权码交换', async () => {
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.explicit_logout', loginMarker(1))
    storage.setItem('demo-web-b.auth_generation', '1')
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    let resolveTokenExchange!: (response: Response) => void
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', {
      state: null,
      replaceState: vi.fn((_state, _title, url: string) => {
        stubLocation(new URL(url, location.href).toString())
      }),
    })
    const fetchMock = vi.fn(() => new Promise<Response>((resolve) => {
      resolveTokenExchange = resolve
    }))
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

  it('刷新凭据失效时清除旧令牌、通知退出且不得静默恢复', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-07-30T00:00:00Z'))
    const storage = new MemoryStorage()
    const appendChild = vi.fn()
    const browserWindow: Record<string, unknown> = {
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    }
    browserWindow.parent = browserWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      createElement: vi.fn(() => ({
        hidden: false,
        src: '',
        contentWindow: {},
        style: { display: '' },
        remove: vi.fn(),
        setAttribute: vi.fn(),
      })),
      body: { appendChild },
    })
    vi.stubGlobal('crypto', {
      getRandomValues: (target: Uint8Array) => {
        target.fill(0)
        return target
      },
      randomUUID: () => 'must-not-be-used',
      subtle: {
        digest: vi.fn().mockResolvedValue(new Uint8Array(32).buffer),
      },
    })
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
    const retryAfterRevocation = client.getAccessToken()
    void retryAfterRevocation.catch(() => undefined)
    await vi.runAllTimersAsync()
    await expect(retryAfterRevocation).rejects.toThrow('当前没有可用的登录令牌')
    expect(appendChild).not.toHaveBeenCalled()

    const reloadedClient = new WebAuthClient(CONFIG)
    const retryAfterReload = reloadedClient.getAccessToken()
    void retryAfterReload.catch(() => undefined)
    await vi.runAllTimersAsync()
    await expect(retryAfterReload).rejects.toThrow('当前没有可用的登录令牌')
    expect(storage.getItem('demo-web-b.explicit_logout')).toBe(INVALIDATED_AUTH_MARKER)
    expect(appendChild).not.toHaveBeenCalled()
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

  it('另一实例登录使在途刷新失效时立即通知当前实例退出', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-07-30T00:00:00Z'))
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    let resolveRefresh!: (response: Response) => void
    const authStateListener = vi.fn()
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        access_token: 'old-access-token',
        refresh_token: 'old-refresh-token',
        id_token: 'old-id-token',
        expires_in: 30,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }))
      .mockReturnValueOnce(new Promise<Response>((resolve) => {
        resolveRefresh = resolve
      }))
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', { replaceState: vi.fn() })
    vi.stubGlobal('fetch', fetchMock)
    const activeClient = new WebAuthClient(CONFIG)
    const reloginClient = new WebAuthClient(CONFIG)
    activeClient.onAuthStateChange(authStateListener)
    await activeClient.getAccessToken()
    stubLocation('http://localhost:5174/')

    const pendingRefresh = activeClient.getAccessToken()
    await reloginClient.login()
    resolveRefresh(new Response(JSON.stringify({
      access_token: 'late-access-token',
      refresh_token: 'late-refresh-token',
      expires_in: 900,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))

    await expect(pendingRefresh).rejects.toThrow('登录状态已失效')
    expect(authStateListener.mock.calls).toEqual([[true], [false]])
  })

  it('另一实例登录后过时刷新即使临时失败也立即通知当前实例退出', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-07-30T00:00:00Z'))
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    let resolveRefresh!: (response: Response) => void
    const authStateListener = vi.fn()
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        access_token: 'old-access-token',
        refresh_token: 'old-refresh-token',
        id_token: 'old-id-token',
        expires_in: 30,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }))
      .mockReturnValueOnce(new Promise<Response>((resolve) => {
        resolveRefresh = resolve
      }))
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', { replaceState: vi.fn() })
    vi.stubGlobal('fetch', fetchMock)
    const activeClient = new WebAuthClient(CONFIG)
    const reloginClient = new WebAuthClient(CONFIG)
    activeClient.onAuthStateChange(authStateListener)
    await activeClient.getAccessToken()
    stubLocation('http://localhost:5174/')

    const staleRefresh = activeClient.getAccessToken()
    await reloginClient.login()
    resolveRefresh(new Response(JSON.stringify({
      error: 'temporarily_unavailable',
    }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' },
    }))

    await expect(staleRefresh).rejects.toThrow('换取令牌失败：503')
    expect(authStateListener.mock.calls).toEqual([[true], [false]])
    expect(storage.getItem('demo-web-b.explicit_logout')).toBe(loginMarker(1))
  })

  it('旧代次刷新被拒不得用登出标记覆盖另一实例的新登录', async () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-07-30T00:00:00Z'))
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.state', 'old-state')
    storage.setItem('demo-web-b.code_verifier', 'old-verifier')
    let resolveOldRefresh!: (response: Response) => void
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        access_token: 'old-access-token',
        refresh_token: 'old-refresh-token',
        id_token: 'old-id-token',
        expires_in: 30,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }))
      .mockReturnValueOnce(new Promise<Response>((resolve) => {
        resolveOldRefresh = resolve
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify({
        access_token: 'new-access-token',
        refresh_token: 'new-refresh-token',
        id_token: 'new-id-token',
        expires_in: 900,
      }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }))
    vi.stubGlobal('sessionStorage', storage)
    vi.stubGlobal('fetch', fetchMock)
    vi.stubGlobal('history', { state: null, replaceState: vi.fn() })
    stubLocation('http://localhost:5174/callback?code=old-code&state=old-state')
    const oldClient = new WebAuthClient(CONFIG)
    const reloginClient = new WebAuthClient(CONFIG)
    const oldAuthStateListener = vi.fn()
    oldClient.onAuthStateChange(oldAuthStateListener)
    await oldClient.getAccessToken()

    stubLocation('http://localhost:5174/')
    const staleRefresh = oldClient.getAccessToken()
    await reloginClient.login()
    const newState = storage.getItem('demo-web-b.state')
    stubLocation(`http://localhost:5174/callback?code=new-code&state=${newState}`)
    const newClient = new WebAuthClient(CONFIG)
    await expect(newClient.getAccessToken()).resolves.toBe('new-access-token')
    expect(storage.getItem('demo-web-b.explicit_logout')).toBeNull()

    resolveOldRefresh(new Response(JSON.stringify({ error: 'invalid_grant' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    }))

    await expect(staleRefresh).rejects.toThrow('换取令牌失败：400')
    expect(oldAuthStateListener.mock.calls).toEqual([[true], [false]])
    expect(storage.getItem('demo-web-b.explicit_logout')).toBeNull()
    await expect(newClient.getAccessToken()).resolves.toBe('new-access-token')
  })
})

describe('WebAuthClient 登录态订阅与登出', () => {
  it('同一 clientId 的另一个实例登出后，当前实例的既有令牌也立即失效', async () => {
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', { state: null, replaceState: vi.fn() })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      access_token: 'access-token',
      refresh_token: 'refresh-token',
      id_token: 'id-token',
      expires_in: 900,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })))
    const activeClient = new WebAuthClient(CONFIG)
    const logoutClient = new WebAuthClient(CONFIG)
    await activeClient.getAccessToken()
    stubLocation('http://localhost:5174/')

    logoutClient.logout()

    await expect(activeClient.getAccessToken()).rejects.toThrow(
      '当前没有可用的登录令牌',
    )
  })

  it('跨实例登出标记写入失败时共享代次仍使旧实例失效', async () => {
    const storage = new LogoutMarkerWriteFailureStorage()
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', { state: null, replaceState: vi.fn() })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      access_token: 'access-token',
      refresh_token: 'refresh-token',
      id_token: 'id-token',
      expires_in: 900,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })))
    const activeClient = new WebAuthClient(CONFIG)
    const logoutClient = new WebAuthClient(CONFIG)
    await activeClient.getAccessToken()
    stubLocation('http://localhost:5174/')

    expect(() => logoutClient.logout()).not.toThrow()
    expect(storage.getItem('demo-web-b.explicit_logout')).toBeNull()
    await expect(activeClient.getAccessToken()).rejects.toThrow(
      '当前没有可用的登录令牌',
    )
  })

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

  it('登录通知中同步登出时不得返回已失效令牌或继续发送过期通知', async () => {
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', {
      state: null,
      replaceState: vi.fn((_state, _title, url: string) => {
        stubLocation(new URL(url, location.href).toString())
      }),
    })
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
    const reentrantListener = vi.fn((authenticated: boolean) => {
      if (authenticated) {
        client.logout()
      }
    })
    const trailingListener = vi.fn()
    client.onAuthStateChange(reentrantListener)
    client.onAuthStateChange(trailingListener)

    await expect(client.getAccessToken()).rejects.toThrow('登录状态已失效')

    expect(reentrantListener.mock.calls).toEqual([[true], [false]])
    expect(trailingListener.mock.calls).toEqual([[false]])
    await expect(client.getAccessToken()).rejects.toThrow('当前没有可用的登录令牌')
  })

  it('订阅者抛错时不改变认证结果，并继续通知其他订阅者', async () => {
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    const listenerError = new Error('订阅者故障')
    const failingListener = vi.fn(() => {
      throw listenerError
    })
    const healthyListener = vi.fn()
    const errorReporter = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', { state: null, replaceState: vi.fn() })
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
    client.onAuthStateChange(failingListener)
    client.onAuthStateChange(healthyListener)

    await expect(client.getAccessToken()).resolves.toBe('access-token')
    stubLocation('http://localhost:5174/')
    expect(() => client.logout()).not.toThrow()

    expect(failingListener.mock.calls).toEqual([[true], [false]])
    expect(healthyListener.mock.calls).toEqual([[true], [false]])
    expect(errorReporter.mock.calls).toEqual([
      ['认证状态订阅者执行失败', listenerError],
      ['认证状态订阅者执行失败', listenerError],
    ])
  })

  it('异步订阅者拒绝时不产生未处理异常，并继续通知其他订阅者', async () => {
    const storage = new MemoryStorage()
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    const listenerError = new Error('异步订阅者故障')
    const failingListener = vi.fn(async () => {
      throw listenerError
    })
    const healthyListener = vi.fn()
    const errorReporter = vi.spyOn(console, 'error').mockImplementation(() => undefined)
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', { state: null, replaceState: vi.fn() })
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
    client.onAuthStateChange(failingListener)
    client.onAuthStateChange(healthyListener)

    await expect(client.getAccessToken()).resolves.toBe('access-token')

    expect(healthyListener).toHaveBeenCalledExactlyOnceWith(true)
    await vi.waitFor(() => {
      expect(errorReporter).toHaveBeenCalledExactlyOnceWith(
        '认证状态订阅者执行失败',
        listenerError,
      )
    })
  })

  it('登出标记写入失败时仍清除内存令牌并通知退出登录', async () => {
    const storage = new LogoutMarkerWriteFailureStorage()
    storage.setItem('demo-web-b.state', 'expected-state')
    storage.setItem('demo-web-b.code_verifier', 'code-verifier')
    const authStateListener = vi.fn()
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=one-time-code&state=expected-state')
    vi.stubGlobal('history', { state: null, replaceState: vi.fn() })
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
    client.onAuthStateChange(authStateListener)
    await client.getAccessToken()
    stubLocation('http://localhost:5174/')

    expect(() => client.logout()).not.toThrow()

    expect(authStateListener.mock.calls).toEqual([[true], [false]])
    await expect(client.getAccessToken()).rejects.toThrow(
      '当前没有可用的登录令牌',
    )
  })
})

describe('WebAuthClient 静默续签集成', () => {
  it('同一 clientId 的既有实例也必须响应另一个实例的显式登出', async () => {
    const storage = new MemoryStorage()
    const appendChild = vi.fn()
    const browserWindow: Record<string, unknown> = {
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    }
    browserWindow.parent = browserWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      createElement: vi.fn(() => ({
        hidden: false,
        src: '',
        contentWindow: {},
        style: { display: '' },
        remove: vi.fn(),
        setAttribute: vi.fn(),
      })),
      body: { appendChild },
    })
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/')
    const firstClient = new WebAuthClient(CONFIG)
    const existingSecondClient = new WebAuthClient(CONFIG)

    firstClient.logout()

    await expect(existingSecondClient.getAccessToken()).rejects.toThrow(
      '当前没有可用的登录令牌',
    )
    expect(appendChild).not.toHaveBeenCalled()
  })

  it('显式登出标记跨页面刷新保留，新实例也不得静默恢复登录', async () => {
    const storage = new MemoryStorage()
    const appendChild = vi.fn()
    const browserWindow: Record<string, unknown> = {
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    }
    browserWindow.parent = browserWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      createElement: vi.fn(() => ({
        hidden: false,
        src: '',
        contentWindow: {},
        style: { display: '' },
        remove: vi.fn(),
        setAttribute: vi.fn(),
      })),
      body: { appendChild },
    })
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/')
    const originalClient = new WebAuthClient(CONFIG)
    originalClient.logout()

    const reloadedClient = new WebAuthClient(CONFIG)

    await expect(reloadedClient.getAccessToken()).rejects.toThrow(
      '当前没有可用的登录令牌',
    )
    expect(appendChild).not.toHaveBeenCalled()
  })

  it('显式登出后 getAccessToken 不得借认证中心会话自动恢复登录', async () => {
    vi.useFakeTimers()
    const storage = new MemoryStorage()
    const appendChild = vi.fn()
    const browserWindow: Record<string, unknown> = {
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
    }
    browserWindow.parent = browserWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      createElement: vi.fn(() => ({
        hidden: false,
        src: '',
        contentWindow: {},
        style: { display: '' },
        remove: vi.fn(),
        setAttribute: vi.fn(),
      })),
      body: { appendChild },
    })
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/')
    vi.stubGlobal('crypto', {
      getRandomValues: (target: Uint8Array) => target,
      randomUUID: () => 'must-not-be-used',
      subtle: {
        digest: vi.fn().mockResolvedValue(new Uint8Array(32).buffer),
      },
    })
    const client = new WebAuthClient(CONFIG)
    client.logout()

    const tokenPromise = client.getAccessToken()
    void tokenPromise.catch(() => undefined)
    await vi.runAllTimersAsync()

    await expect(tokenPromise).rejects.toThrow('当前没有可用的登录令牌')
    expect(appendChild).not.toHaveBeenCalled()
  })

  it('内存令牌丢失时并发调用只创建一个 iframe，并保存回传令牌', async () => {
    const storage = new MemoryStorage()
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
    const browserWindow: Record<string, unknown> = {
      addEventListener: vi.fn((_type: string, handler: (event: MessageEvent) => void) => {
        messageHandler = handler
      }),
      removeEventListener: vi.fn((_type: string, handler: (event: MessageEvent) => void) => {
        if (messageHandler === handler) {
          messageHandler = undefined
        }
      }),
    }
    browserWindow.parent = browserWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      createElement: vi.fn(() => iframe),
      body: { appendChild },
    })
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/')
    vi.stubGlobal('crypto', {
      getRandomValues: (target: Uint8Array) => {
        target.fill(0)
        return target
      },
      randomUUID: () => 'silent-state',
      subtle: webCrypto.subtle,
    })
    const authStateListener = vi.fn()
    const client = new WebAuthClient(CONFIG)
    client.onAuthStateChange(authStateListener)

    const firstToken = client.getAccessToken()
    const secondToken = client.getAccessToken()
    const combinedTokens = Promise.all([firstToken, secondToken])
    void combinedTokens.catch(() => undefined)
    await vi.waitFor(() => {
      expect(appendChild).toHaveBeenCalledOnce()
    })

    expect(messageHandler).toBeDefined()
    messageHandler?.({
      origin: 'http://localhost:5174',
      source: iframeWindow,
      data: {
        type: SILENT_RENEW_MESSAGE_TYPE,
        clientId: CONFIG.clientId,
        state: 'silent-state',
        status: 'success',
        tokens: {
          accessToken: 'silent-access-token',
          refreshToken: 'silent-refresh-token',
          idToken: 'silent-id-token',
          expiresAt: Date.now() + 900_000,
        },
      },
    } as MessageEvent)

    await expect(combinedTokens).resolves.toEqual([
      'silent-access-token',
      'silent-access-token',
    ])
    await expect(client.getAccessToken()).resolves.toBe('silent-access-token')
    expect(authStateListener).toHaveBeenCalledExactlyOnceWith(true)
    expect(iframe.remove).toHaveBeenCalledOnce()
    expect(appendChild).toHaveBeenCalledOnce()
  })

  it('静默换码被 invalid_grant 拒绝后停止后续 iframe 重试', async () => {
    const storage = new MemoryStorage()
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
    const browserWindow: Record<string, unknown> = {
      addEventListener: vi.fn((_type: string, handler: (event: MessageEvent) => void) => {
        messageHandler = handler
      }),
      removeEventListener: vi.fn(),
    }
    browserWindow.parent = browserWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      createElement: vi.fn(() => iframe),
      body: { appendChild },
    })
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/')
    vi.stubGlobal('crypto', {
      getRandomValues: (target: Uint8Array) => {
        target.fill(0)
        return target
      },
      randomUUID: () => 'silent-state',
      subtle: webCrypto.subtle,
    })
    const client = new WebAuthClient(CONFIG)
    const firstAttempt = client.getAccessToken()
    void firstAttempt.catch(() => undefined)
    await vi.waitFor(() => {
      expect(appendChild).toHaveBeenCalledOnce()
    })

    messageHandler?.({
      origin: 'http://localhost:5174',
      source: iframeWindow,
      data: {
        type: SILENT_RENEW_MESSAGE_TYPE,
        clientId: CONFIG.clientId,
        state: 'silent-state',
        status: 'error',
        error: 'invalid_grant',
      },
    } as MessageEvent)

    await expect(firstAttempt).rejects.toThrow('当前没有可用的登录令牌')
    await expect(client.getAccessToken()).rejects.toThrow(
      '当前没有可用的登录令牌',
    )
    expect(appendChild).toHaveBeenCalledOnce()
    expect(iframe.remove).toHaveBeenCalledOnce()
  })

  it('同一 clientId 的两个实例并发静默续签时分别保存自己的 PKCE 请求', async () => {
    const storage = new MemoryStorage()
    const messageHandlers = new Set<(event: MessageEvent) => void>()
    const iframes: Array<{
      hidden: boolean
      src: string
      contentWindow: object
      style: { display: string }
      remove: ReturnType<typeof vi.fn>
      setAttribute: ReturnType<typeof vi.fn>
    }> = []
    const appendChild = vi.fn()
    const browserWindow: Record<string, unknown> = {
      addEventListener: vi.fn((_type: string, handler: (event: MessageEvent) => void) => {
        messageHandlers.add(handler)
      }),
      removeEventListener: vi.fn((_type: string, handler: (event: MessageEvent) => void) => {
        messageHandlers.delete(handler)
      }),
    }
    browserWindow.parent = browserWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      createElement: vi.fn(() => {
        const iframe = {
          hidden: false,
          src: '',
          contentWindow: {},
          style: { display: '' },
          remove: vi.fn(),
          setAttribute: vi.fn(),
        }
        iframes.push(iframe)
        return iframe
      }),
      body: { appendChild },
    })
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/')
    let stateIndex = 0
    vi.stubGlobal('crypto', {
      getRandomValues: (target: Uint8Array) => {
        target.fill(stateIndex)
        return target
      },
      randomUUID: () => ['first-state', 'second-state'][stateIndex++]!,
      subtle: webCrypto.subtle,
    })
    const firstToken = new WebAuthClient(CONFIG).getAccessToken()
    const secondToken = new WebAuthClient(CONFIG).getAccessToken()
    const combinedTokens = Promise.all([firstToken, secondToken])
    void combinedTokens.catch(() => undefined)
    await vi.waitFor(() => {
      expect(appendChild).toHaveBeenCalledTimes(2)
    })

    expect(storage.getItem(
      'demo-web-b.silent.request.first-state',
    )).not.toBeNull()
    expect(storage.getItem(
      'demo-web-b.silent.request.second-state',
    )).not.toBeNull()

    for (const [index, state] of ['first-state', 'second-state'].entries()) {
      for (const handler of [...messageHandlers]) {
        handler({
          origin: 'http://localhost:5174',
          source: iframes[index]!.contentWindow,
          data: {
            type: SILENT_RENEW_MESSAGE_TYPE,
            clientId: CONFIG.clientId,
            state,
            status: 'success',
            tokens: {
              accessToken: `${state}-access-token`,
              refreshToken: `${state}-refresh-token`,
              idToken: `${state}-id-token`,
              expiresAt: Date.now() + 900_000,
            },
          },
        } as MessageEvent)
      }
    }

    await expect(combinedTokens).resolves.toEqual(expect.arrayContaining([
      'first-state-access-token',
      'second-state-access-token',
    ]))
    expect(storage.length).toBe(0)
  })

  it('另一个实例显式登出后，迟到的静默续签结果不得恢复登录态', async () => {
    const storage = new MemoryStorage()
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
    const browserWindow: Record<string, unknown> = {
      addEventListener: vi.fn((_type: string, handler: (event: MessageEvent) => void) => {
        messageHandler = handler
      }),
      removeEventListener: vi.fn(),
    }
    browserWindow.parent = browserWindow
    vi.stubGlobal('window', browserWindow)
    vi.stubGlobal('document', {
      createElement: vi.fn(() => iframe),
      body: { appendChild },
    })
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/')
    vi.stubGlobal('crypto', {
      getRandomValues: (target: Uint8Array) => {
        target.fill(0)
        return target
      },
      randomUUID: () => 'silent-state',
      subtle: webCrypto.subtle,
    })
    const logoutClient = new WebAuthClient(CONFIG)
    const renewingClient = new WebAuthClient(CONFIG)
    const tokenPromise = renewingClient.getAccessToken()
    void tokenPromise.catch(() => undefined)
    await vi.waitFor(() => {
      expect(appendChild).toHaveBeenCalledOnce()
    })

    logoutClient.logout()
    expect(storage.getItem(
      'demo-web-b.silent.request.silent-state',
    )).not.toBeNull()
    messageHandler?.({
      origin: 'http://localhost:5174',
      source: iframeWindow,
      data: {
        type: SILENT_RENEW_MESSAGE_TYPE,
        clientId: CONFIG.clientId,
        state: 'silent-state',
        status: 'success',
        tokens: {
          accessToken: 'late-access-token',
          refreshToken: 'late-refresh-token',
          idToken: 'late-id-token',
          expiresAt: Date.now() + 900_000,
        },
      },
    } as MessageEvent)

    await expect(tokenPromise).rejects.toThrow('登录状态已失效')
    await expect(renewingClient.getAccessToken()).rejects.toThrow(
      '当前没有可用的登录令牌',
    )
  })

  it('iframe 中的合法授权回调换取令牌后定向回传完整令牌集', async () => {
    const storage = new MemoryStorage()
    storage.setItem(
      'demo-web-b.silent.request.expected-state',
      'code-verifier',
    )
    const postMessage = vi.fn()
    const childWindow: Record<string, unknown> = {}
    childWindow.parent = { postMessage }
    vi.stubGlobal('window', childWindow)
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=silent-code&state=expected-state')
    vi.stubGlobal('history', { state: { key: 'silent-callback' }, replaceState: vi.fn() })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      access_token: 'silent-access-token',
      refresh_token: 'silent-refresh-token',
      id_token: 'silent-id-token',
      expires_in: 900,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })))

    await expect(new WebAuthClient(CONFIG).getAccessToken()).resolves.toBe(
      'silent-access-token',
    )

    expect(postMessage).toHaveBeenCalledExactlyOnceWith({
      type: SILENT_RENEW_MESSAGE_TYPE,
      clientId: CONFIG.clientId,
      state: 'expected-state',
      status: 'success',
      tokens: {
        accessToken: 'silent-access-token',
        refreshToken: 'silent-refresh-token',
        idToken: 'silent-id-token',
        expiresAt: expect.any(Number),
      },
    }, 'http://localhost:5174')
  })

  it('未知 state 的回调不得删除其他并发静默请求的 PKCE 凭据', async () => {
    const storage = new MemoryStorage()
    storage.setItem(
      'demo-web-b.silent.request.first-state',
      'first-verifier',
    )
    storage.setItem(
      'demo-web-b.silent.request.second-state',
      'second-verifier',
    )
    const fetchMock = vi.fn()
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=stolen-code&state=unknown-state')
    vi.stubGlobal('history', { state: null, replaceState: vi.fn() })
    vi.stubGlobal('fetch', fetchMock)
    const childWindow: Record<string, unknown> = {}
    childWindow.parent = {}
    vi.stubGlobal('window', childWindow)

    await expect(new WebAuthClient(CONFIG).getAccessToken()).rejects.toThrow(
      'state 校验失败',
    )

    expect(fetchMock).not.toHaveBeenCalled()
    expect(storage.getItem(
      'demo-web-b.silent.request.first-state',
    )).toBe('first-verifier')
    expect(storage.getItem(
      'demo-web-b.silent.request.second-state',
    )).toBe('second-verifier')
  })

  it('iframe 中的 login_required 校验 state 后回传，且绝不请求令牌端点', async () => {
    const storage = new MemoryStorage()
    storage.setItem(
      'demo-web-b.silent.request.expected-state',
      'code-verifier',
    )
    const postMessage = vi.fn()
    const fetchMock = vi.fn()
    const childWindow: Record<string, unknown> = {}
    childWindow.parent = { postMessage }
    vi.stubGlobal('window', childWindow)
    vi.stubGlobal('sessionStorage', storage)
    stubLocation(
      'http://localhost:5174/callback?error=login_required&state=expected-state',
    )
    vi.stubGlobal('history', { state: null, replaceState: vi.fn() })
    vi.stubGlobal('fetch', fetchMock)

    await expect(new WebAuthClient(CONFIG).getAccessToken()).rejects.toThrow(
      '静默续签失败：login_required',
    )

    expect(postMessage).toHaveBeenCalledExactlyOnceWith({
      type: SILENT_RENEW_MESSAGE_TYPE,
      clientId: CONFIG.clientId,
      state: 'expected-state',
      status: 'error',
      error: 'login_required',
    }, 'http://localhost:5174')
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('iframe 换码失败时立即回传错误，父页无需等待超时', async () => {
    const storage = new MemoryStorage()
    storage.setItem(
      'demo-web-b.silent.request.expected-state',
      'code-verifier',
    )
    const postMessage = vi.fn()
    const childWindow: Record<string, unknown> = {}
    childWindow.parent = { postMessage }
    vi.stubGlobal('window', childWindow)
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=silent-code&state=expected-state')
    vi.stubGlobal('history', { state: null, replaceState: vi.fn() })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      error: 'temporarily_unavailable',
    }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' },
    })))

    await expect(new WebAuthClient(CONFIG).getAccessToken()).rejects.toThrow(
      '换取令牌失败：503',
    )

    expect(postMessage).toHaveBeenCalledExactlyOnceWith({
      type: SILENT_RENEW_MESSAGE_TYPE,
      clientId: CONFIG.clientId,
      state: 'expected-state',
      status: 'error',
      error: 'token_exchange_failed',
    }, 'http://localhost:5174')
  })

  it('iframe 换码收到 invalid_grant 时原样回传账号失效原因', async () => {
    const storage = new MemoryStorage()
    storage.setItem(
      'demo-web-b.silent.request.expected-state',
      'code-verifier',
    )
    const postMessage = vi.fn()
    const childWindow: Record<string, unknown> = {}
    childWindow.parent = { postMessage }
    vi.stubGlobal('window', childWindow)
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=silent-code&state=expected-state')
    vi.stubGlobal('history', { state: null, replaceState: vi.fn() })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      error: 'invalid_grant',
    }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
    })))

    await expect(new WebAuthClient(CONFIG).getAccessToken()).rejects.toThrow(
      '换取令牌失败：400',
    )

    expect(postMessage).toHaveBeenCalledExactlyOnceWith({
      type: SILENT_RENEW_MESSAGE_TYPE,
      clientId: CONFIG.clientId,
      state: 'expected-state',
      status: 'error',
      error: 'invalid_grant',
    }, 'http://localhost:5174')
  })

  it('iframe 换码途中发生跨实例登出时立即回传失效错误', async () => {
    const storage = new MemoryStorage()
    storage.setItem(
      'demo-web-b.silent.request.expected-state',
      'code-verifier',
    )
    storage.setItem('demo-web-b.explicit_logout', INVALIDATED_AUTH_MARKER)
    const postMessage = vi.fn()
    const childWindow: Record<string, unknown> = {}
    childWindow.parent = { postMessage }
    vi.stubGlobal('window', childWindow)
    vi.stubGlobal('sessionStorage', storage)
    stubLocation('http://localhost:5174/callback?code=silent-code&state=expected-state')
    vi.stubGlobal('history', { state: null, replaceState: vi.fn() })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(JSON.stringify({
      access_token: 'late-access-token',
      refresh_token: 'late-refresh-token',
      id_token: 'late-id-token',
      expires_in: 900,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    })))

    await expect(new WebAuthClient(CONFIG).getAccessToken()).rejects.toThrow(
      '登录状态已失效',
    )

    expect(postMessage).toHaveBeenCalledExactlyOnceWith({
      type: SILENT_RENEW_MESSAGE_TYPE,
      clientId: CONFIG.clientId,
      state: 'expected-state',
      status: 'error',
      error: 'login_state_invalidated',
    }, 'http://localhost:5174')
  })
})

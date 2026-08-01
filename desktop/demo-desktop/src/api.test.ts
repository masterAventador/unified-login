import { describe, expect, it, vi } from 'vitest'

import {
  TauriAuthClient,
  type TauriAuthClientApi,
} from '../../../sdk/tauri/ts/index'
import type WebAuthClient from '../../../sdk/web-ts/src/index'

type Equal<Left, Right> =
  (<Value>() => Value extends Left ? 1 : 2) extends
    (<Value>() => Value extends Right ? 1 : 2)
    ? true
    : false
type Assert<Condition extends true> = Condition
type WebAuthClientApi = Pick<
  WebAuthClient,
  'login' | 'logout' | 'getAccessToken' | 'onAuthStateChange'
>
const PUBLIC_API_MATCHES_WEB_SDK: Assert<
  Equal<TauriAuthClientApi, WebAuthClientApi>
> = true

describe('TauriAuthClient', () => {
  it('运行时原型只公开与 Web SDK 相同的四个方法', () => {
    expect(PUBLIC_API_MATCHES_WEB_SDK).toBe(true)
    expect(Object.getOwnPropertyNames(TauriAuthClient.prototype).sort()).toEqual([
      'constructor',
      'getAccessToken',
      'login',
      'logout',
      'onAuthStateChange',
    ])
  })

  it('登录返回 void 并通知认证状态', async () => {
    const invoke = vi.fn().mockResolvedValue('authenticated')
    const listener = vi.fn()
    const client = new TauriAuthClient(invoke)
    client.onAuthStateChange(listener)

    await expect(client.login()).resolves.toBeUndefined()

    expect(invoke).toHaveBeenCalledExactlyOnceWith('login')
    expect(listener).toHaveBeenCalledExactlyOnceWith(true)
  })

  it('强制重新登录选项会传给 Rust 命令', async () => {
    const invoke = vi.fn().mockResolvedValue('authenticated')
    const client = new TauriAuthClient(invoke)

    await client.login({ prompt: 'login' })

    expect(invoke).toHaveBeenCalledExactlyOnceWith('login', {
      prompt: 'login',
    })
  })

  it('重复登录复用正在进行的操作且不使首个登录失效', async () => {
    let completeLogin!: () => void
    const loginOperation = new Promise<void>((resolve) => {
      completeLogin = resolve
    })
    const invoke = vi.fn().mockReturnValue(loginOperation)
    const listener = vi.fn()
    const client = new TauriAuthClient(invoke)
    client.onAuthStateChange(listener)

    const firstLogin = client.login()
    const repeatedLogin = client.login()
    completeLogin()

    await expect(Promise.allSettled([firstLogin, repeatedLogin])).resolves
      .toEqual([
        { status: 'fulfilled', value: undefined },
        { status: 'fulfilled', value: undefined },
      ])
    expect(invoke).toHaveBeenCalledExactlyOnceWith('login')
    expect(listener).toHaveBeenCalledExactlyOnceWith(true)
  })

  it('不同选项的并发登录会明确拒绝而不静默吞掉强制登录', async () => {
    let completeLogin!: () => void
    const loginOperation = new Promise<void>((resolve) => {
      completeLogin = resolve
    })
    const invoke = vi.fn().mockReturnValue(loginOperation)
    const client = new TauriAuthClient(invoke)

    const firstLogin = client.login()
    const conflictingLogin = client.login({ prompt: 'login' })
    completeLogin()

    await expect(firstLogin).resolves.toBeUndefined()
    await expect(conflictingLogin).rejects.toThrow(
      '已有不同选项的登录流程正在进行',
    )
    expect(invoke).toHaveBeenCalledExactlyOnceWith('login')
  })

  it('重新登录进行中拒绝读取前一个账号的 access token', async () => {
    let completeLogin!: () => void
    const invoke = vi.fn((command: string) => {
      if (command === 'login') {
        return new Promise<void>((resolve) => {
          completeLogin = resolve
        })
      }
      if (command === 'get_access_token') {
        return Promise.resolve('previous-account-access-secret')
      }
      return Promise.resolve(undefined)
    })
    const client = new TauriAuthClient(invoke)
    await client.getAccessToken()

    const login = client.login({ prompt: 'login' })
    const accessToken = client.getAccessToken()
    completeLogin()

    await expect(accessToken).rejects.toThrow('登录正在进行')
    await expect(login).resolves.toBeUndefined()
    expect(invoke.mock.calls).toEqual([
      ['get_access_token'],
      ['login', { prompt: 'login' }],
    ])
  })

  it('登出后立即重试会启动新登录而不是复用已取消的旧流程', async () => {
    let rejectCancelledLogin!: (error: Error) => void
    const cancelledLogin = new Promise<void>((_resolve, reject) => {
      rejectCancelledLogin = reject
    })
    const invoke = vi.fn()
      .mockReturnValueOnce(cancelledLogin)
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce('authenticated')
    const client = new TauriAuthClient(invoke)

    const firstLogin = client.login()
    const firstLoginResult = firstLogin.catch((error: unknown) => error)
    await client.logout()
    const retriedLogin = client.login()
    rejectCancelledLogin(new Error('旧登录已取消'))

    await expect(firstLoginResult).resolves.toEqual(new Error('旧登录已取消'))
    await expect(retriedLogin).resolves.toBeUndefined()
    expect(invoke.mock.calls).toEqual([
      ['login'],
      ['logout'],
      ['login'],
    ])
  })

  it('通过 Rust 命令取得可自动刷新的 access token 并通知认证状态', async () => {
    const invoke = vi.fn().mockResolvedValue('access-secret')
    const listener = vi.fn()
    const client = new TauriAuthClient(invoke)
    client.onAuthStateChange(listener)

    await expect(client.getAccessToken()).resolves.toBe('access-secret')

    expect(invoke).toHaveBeenCalledExactlyOnceWith('get_access_token')
    expect(listener).toHaveBeenCalledExactlyOnceWith(true)
  })

  it('没有登录令牌时通知失效并保留后端稳定错误', async () => {
    const invoke = vi.fn()
      .mockResolvedValueOnce('access-secret')
      .mockRejectedValueOnce({
        code: 'loginRequired',
        message: '当前没有可用的登录令牌',
      })
    const listener = vi.fn()
    const client = new TauriAuthClient(invoke)
    client.onAuthStateChange(listener)
    await client.getAccessToken()

    await expect(client.getAccessToken()).rejects.toMatchObject({
      code: 'loginRequired',
    })
    expect(listener.mock.calls).toEqual([[true], [false]])
  })

  it('登出返回 void、通知失效且取消订阅后不再回调', async () => {
    const invoke = vi.fn()
      .mockResolvedValueOnce('access-secret')
      .mockResolvedValueOnce(undefined)
      .mockResolvedValueOnce(undefined)
    const listener = vi.fn()
    const client = new TauriAuthClient(invoke)
    const unsubscribe = client.onAuthStateChange(listener)
    await client.getAccessToken()

    await expect(client.logout()).resolves.toBeUndefined()
    unsubscribe()
    await client.logout()

    expect(invoke.mock.calls).toEqual([
      ['get_access_token'],
      ['logout'],
      ['logout'],
    ])
    expect(listener.mock.calls).toEqual([[true], [false]])
  })

  it('重复登出复用正在进行的操作且只通知一次退出', async () => {
    let completeLogout!: () => void
    const invoke = vi.fn((command: string) => {
      if (command === 'get_access_token') {
        return Promise.resolve('access-secret')
      }
      if (command === 'logout') {
        if (completeLogout !== undefined) {
          return Promise.reject({ code: 'logoutFailed' })
        }
        return new Promise<void>((resolve) => {
          completeLogout = resolve
        })
      }
      return Promise.resolve(undefined)
    })
    const listener = vi.fn()
    const client = new TauriAuthClient(invoke)
    client.onAuthStateChange(listener)
    await client.getAccessToken()

    const firstLogout = client.logout()
    const repeatedLogout = client.logout()
    completeLogout()

    await expect(Promise.allSettled([firstLogout, repeatedLogout])).resolves
      .toEqual([
        { status: 'fulfilled', value: undefined },
        { status: 'fulfilled', value: undefined },
      ])
    expect(invoke.mock.calls).toEqual([
      ['get_access_token'],
      ['logout'],
    ])
    expect(listener.mock.calls).toEqual([[true], [false]])
  })

  it('登出进行中拒绝新登录且不使成功登出失效', async () => {
    let completeLogout!: () => void
    const invoke = vi.fn((command: string) => {
      if (command === 'get_access_token') {
        return Promise.resolve('access-secret')
      }
      if (command === 'logout') {
        return new Promise<void>((resolve) => {
          completeLogout = resolve
        })
      }
      return Promise.reject(new Error('登出时不应调用登录命令'))
    })
    const listener = vi.fn()
    const client = new TauriAuthClient(invoke)
    client.onAuthStateChange(listener)
    await client.getAccessToken()

    const logout = client.logout()
    const login = client.login()
    completeLogout()

    await expect(login).rejects.toThrow('退出登录正在进行')
    await expect(logout).resolves.toBeUndefined()
    expect(invoke.mock.calls).toEqual([
      ['get_access_token'],
      ['logout'],
    ])
    expect(listener.mock.calls).toEqual([[true], [false]])
  })

  it('登出进行中拒绝取得 access token 且不恢复认证状态', async () => {
    let completeLogout!: () => void
    const invoke = vi.fn((command: string) => {
      if (command === 'get_access_token') {
        return Promise.resolve('stale-access-secret')
      }
      if (command === 'logout') {
        return new Promise<void>((resolve) => {
          completeLogout = resolve
        })
      }
      return Promise.resolve(undefined)
    })
    const listener = vi.fn()
    const client = new TauriAuthClient(invoke)
    client.onAuthStateChange(listener)

    const logout = client.logout()
    const accessToken = client.getAccessToken()
    completeLogout()

    await expect(accessToken).rejects.toThrow('退出登录正在进行')
    await expect(logout).resolves.toBeUndefined()
    expect(invoke.mock.calls).toEqual([
      ['logout'],
    ])
    expect(listener).not.toHaveBeenCalledWith(true)
  })

  it('一个监听器抛错不会阻断其他监听器或认证操作', async () => {
    const client = new TauriAuthClient(
      vi.fn().mockResolvedValue('access-secret'),
    )
    const healthyListener = vi.fn()
    client.onAuthStateChange(() => {
      throw new Error('监听器内部失败')
    })
    client.onAuthStateChange(healthyListener)

    await expect(client.getAccessToken()).resolves.toBe('access-secret')
    expect(healthyListener).toHaveBeenCalledExactlyOnceWith(true)
  })

  it('异步监听器拒绝也会被收口且不影响其他监听器', async () => {
    const client = new TauriAuthClient(
      vi.fn().mockResolvedValue('access-secret'),
    )
    const rejectedListener = Promise.reject(new Error('异步监听器失败'))
    void rejectedListener.catch(() => undefined)
    const catchRejection = vi.spyOn(rejectedListener, 'catch')
    const healthyListener = vi.fn()
    client.onAuthStateChange(() => rejectedListener)
    client.onAuthStateChange(healthyListener)

    await expect(client.getAccessToken()).resolves.toBe('access-secret')
    await Promise.resolve()

    expect(catchRejection).toHaveBeenCalledOnce()
    expect(healthyListener).toHaveBeenCalledExactlyOnceWith(true)
  })

  it('登出开始后拒绝更早发出的 access token 结果', async () => {
    let completeAccessToken!: (value: string) => void
    const invoke = vi.fn((command: string) => {
      if (command === 'get_access_token') {
        return new Promise<string>((resolve) => {
          completeAccessToken = resolve
        })
      }
      return Promise.resolve(undefined)
    })
    const listener = vi.fn()
    const client = new TauriAuthClient(invoke)
    client.onAuthStateChange(listener)

    const accessToken = client.getAccessToken()
    await client.logout()
    completeAccessToken('stale-access-secret')

    await expect(accessToken).rejects.toThrow('登录状态已失效')
    expect(listener).not.toHaveBeenCalledWith(true)
  })

  it('认证通知同步触发登出后拒绝旧令牌并停止过期通知', async () => {
    const invoke = vi.fn(async (command: string) => (
      command === 'get_access_token' ? 'access-secret' : undefined
    ))
    const client = new TauriAuthClient(invoke)
    let logout: Promise<void> | undefined
    const reentrantListener = vi.fn((authenticated: boolean) => {
      if (authenticated) {
        logout = client.logout()
      }
    })
    const trailingListener = vi.fn()
    client.onAuthStateChange(reentrantListener)
    client.onAuthStateChange(trailingListener)

    await expect(client.getAccessToken()).rejects.toThrow('登录状态已失效')
    await logout

    expect(reentrantListener.mock.calls).toEqual([[true], [false]])
    expect(trailingListener.mock.calls).toEqual([[false]])
  })
})

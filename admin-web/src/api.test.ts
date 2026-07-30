import { afterEach, describe, expect, it, vi } from 'vitest'

import { AdminApi, AdminApiError } from './api'

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('AdminApi', () => {
  it('使用 Bearer token 和明确的筛选参数读取用户页', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      content: [],
      page: 2,
      size: 20,
      totalElements: 0,
      totalPages: 0,
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))
    vi.stubGlobal('fetch', fetchMock)

    const result = await new AdminApi('http://localhost:9000').listUsers(
      'access-token',
      { email: 'alice+ops@example.com', status: 'DISABLED', page: 2, size: 20 },
    )

    expect(result.page).toBe(2)
    expect(fetchMock).toHaveBeenCalledOnce()
    const [requestUrl, request] = fetchMock.mock.calls[0] as [string, RequestInit]
    expect(new URL(requestUrl).searchParams).toEqual(new URLSearchParams({
      email: 'alice+ops@example.com',
      status: 'DISABLED',
      page: '2',
      size: '20',
    }))
    expect(request.headers).toEqual({ Authorization: 'Bearer access-token' })
  })

  it('禁用、启用和重置密码只向目标管理端点发送所需数据', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }))
    vi.stubGlobal('fetch', fetchMock)
    const api = new AdminApi('http://localhost:9000')

    await api.disable('token', 'user-1')
    await api.enable('token', 'user-2')
    await api.resetPassword('token', 'user-3', 'a replacement password')

    expect(fetchMock.mock.calls.map(([url]) => url)).toEqual([
      'http://localhost:9000/admin/users/user-1/disable',
      'http://localhost:9000/admin/users/user-2/enable',
      'http://localhost:9000/admin/users/user-3/reset-password',
    ])
    expect(fetchMock.mock.calls[0]?.[1]).toEqual({
      method: 'POST',
      headers: { Authorization: 'Bearer token' },
    })
    expect(fetchMock.mock.calls[2]?.[1]).toEqual({
      method: 'POST',
      headers: {
        Authorization: 'Bearer token',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ newPassword: 'a replacement password' }),
    })
  })

  it('把 403 转成可判别的无权限错误且不泄漏响应正文', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(
      'internal stack trace',
      { status: 403 },
    )))

    const request = new AdminApi('http://localhost:9000')
      .listUsers('ordinary-user-token', { email: '', status: '', page: 0, size: 20 })

    await expect(request).rejects.toMatchObject({
      status: 403,
      message: '管理接口请求失败：403',
    } satisfies Partial<AdminApiError>)
    await expect(request).rejects.not.toThrow('internal stack trace')
  })
})

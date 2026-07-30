import { describe, expect, it, vi } from 'vitest'

import { AdminApplication } from './app'
import { AdminApiError } from './api'
import type { AdminApiPort, AdminAuthPort, AdminViewPort, UserPage } from './app'

const EMPTY_PAGE: UserPage = {
  content: [],
  page: 0,
  size: 20,
  totalElements: 0,
  totalPages: 0,
}

function testPorts(): {
  auth: AdminAuthPort
  api: AdminApiPort
  view: AdminViewPort
} {
  return {
    auth: {
      getAccessToken: vi.fn().mockResolvedValue('access-token'),
      login: vi.fn().mockResolvedValue(undefined),
      logout: vi.fn(),
      onAuthStateChange: vi.fn().mockReturnValue(() => {}),
    },
    api: {
      listUsers: vi.fn().mockResolvedValue(EMPTY_PAGE),
      disable: vi.fn().mockResolvedValue(undefined),
      enable: vi.fn().mockResolvedValue(undefined),
      resetPassword: vi.fn().mockResolvedValue(undefined),
    },
    view: {
      showLoading: vi.fn(),
      showLogin: vi.fn(),
      showForbidden: vi.fn(),
      showError: vi.fn(),
      showUsers: vi.fn(),
    },
  }
}

describe('AdminApplication', () => {
  it('普通用户进入后台时稳定显示无权限，不显示错误堆栈', async () => {
    const ports = testPorts()
    vi.mocked(ports.api.listUsers).mockRejectedValue(
      new AdminApiError(403),
    )

    await new AdminApplication(ports.auth, ports.api, ports.view).start()

    expect(ports.view.showForbidden).toHaveBeenCalledOnce()
    expect(ports.view.showError).not.toHaveBeenCalled()
    expect(ports.auth.login).not.toHaveBeenCalled()
    const switchAccount = vi.mocked(ports.view.showForbidden).mock.calls[0]?.[0]
    await switchAccount?.()
    expect(ports.auth.logout).toHaveBeenCalledOnce()
    expect(ports.auth.login).toHaveBeenCalledWith({ prompt: 'login' })
    expect(ports.view.showLogin).not.toHaveBeenCalled()
  })

  it('没有登录令牌时显示登录入口，并由入口调用阶段二 SDK', async () => {
    const ports = testPorts()
    vi.mocked(ports.auth.getAccessToken).mockRejectedValue(
      new Error('当前没有可用的登录令牌'),
    )

    await new AdminApplication(ports.auth, ports.api, ports.view).start()

    expect(ports.view.showLogin).toHaveBeenCalledOnce()
    const login = vi.mocked(ports.view.showLogin).mock.calls[0]?.[0]
    await login?.()
    expect(ports.auth.login).toHaveBeenCalledOnce()
  })

  it('管理操作成功后重新读取当前筛选页', async () => {
    const ports = testPorts()
    const application = new AdminApplication(ports.auth, ports.api, ports.view)
    await application.start()
    const actions = vi.mocked(ports.view.showUsers).mock.calls[0]?.[1]

    await actions?.disable('user-id')
    await actions?.enable('user-id')
    await actions?.resetPassword('user-id', 'a replacement password')
    vi.mocked(ports.api.listUsers).mockResolvedValue({
      ...EMPTY_PAGE,
      page: 1,
      totalPages: 2,
    })
    await actions?.changeQuery({
      email: 'alice@example.com',
      status: 'ACTIVE',
      page: 1,
      size: 20,
    })

    expect(ports.api.disable).toHaveBeenCalledWith('access-token', 'user-id')
    expect(ports.api.enable).toHaveBeenCalledWith('access-token', 'user-id')
    expect(ports.api.resetPassword).toHaveBeenCalledWith(
      'access-token',
      'user-id',
      'a replacement password',
    )
    expect(ports.api.listUsers).toHaveBeenLastCalledWith('access-token', {
      email: 'alice@example.com',
      status: 'ACTIVE',
      page: 1,
      size: 20,
    })
    expect(ports.view.showUsers).toHaveBeenLastCalledWith(
      {
        ...EMPTY_PAGE,
        page: 1,
        totalPages: 2,
      },
      expect.any(Object),
      {
        email: 'alice@example.com',
        status: 'ACTIVE',
        page: 1,
        size: 20,
      },
    )
  })

  it.each([
    {
      action: 'disable' as const,
      status: 409,
      message: '不能禁用当前登录的管理员账号',
    },
    {
      action: 'resetPassword' as const,
      status: 400,
      message: '新密码必须为 8–64 个字符',
    },
  ])('可预期的 $status 操作失败保留用户列表与恢复入口', async ({
    action,
    status,
    message,
  }) => {
    const ports = testPorts()
    const page: UserPage = {
      ...EMPTY_PAGE,
      content: [{
        id: 'user-id',
        email: 'admin@example.com',
        status: 'ACTIVE',
        emailVerified: true,
        platformAdmin: true,
        passwordChangedAt: '2026-07-31T00:00:00Z',
        createdAt: '2026-07-31T00:00:00Z',
        updatedAt: '2026-07-31T00:00:00Z',
      }],
      totalElements: 1,
      totalPages: 1,
    }
    vi.mocked(ports.api.listUsers).mockResolvedValue(page)
    vi.mocked(ports.api[action]).mockRejectedValue(new AdminApiError(status))
    const application = new AdminApplication(ports.auth, ports.api, ports.view)
    await application.start()
    const actions = vi.mocked(ports.view.showUsers).mock.calls[0]?.[1]

    if (action === 'disable') {
      await actions?.disable('user-id')
    } else {
      await actions?.resetPassword('user-id', 'short')
    }

    expect(ports.view.showError).not.toHaveBeenCalled()
    expect(ports.view.showUsers).toHaveBeenLastCalledWith(
      page,
      expect.any(Object),
      INITIAL_QUERY_FOR_TEST,
      message,
    )
  })

  it('非预期的管理操作失败仍进入统一错误态', async () => {
    const ports = testPorts()
    const application = new AdminApplication(ports.auth, ports.api, ports.view)
    await application.start()
    const rendersBeforeMutation = vi.mocked(ports.view.showUsers).mock.calls.length
    const actions = vi.mocked(ports.view.showUsers).mock.calls[0]?.[1]
    vi.mocked(ports.api.enable).mockRejectedValue(new AdminApiError(500))

    await actions?.enable('user-id')

    expect(ports.view.showError).toHaveBeenCalledWith(
      '暂时无法加载管理后台，请稍后重试',
    )
    expect(ports.view.showUsers).toHaveBeenCalledTimes(rendersBeforeMutation)
  })

  it('refresh 凭据被 SDK 撤销后直接显示重新登录入口', async () => {
    const ports = testPorts()
    let authStateListener: ((authenticated: boolean) => void) | undefined
    vi.mocked(ports.auth.onAuthStateChange).mockImplementation((listener) => {
      authStateListener = listener
      return () => {}
    })
    vi.mocked(ports.auth.getAccessToken).mockImplementation(async () => {
      authStateListener?.(false)
      throw new Error('换取令牌失败：400')
    })

    await new AdminApplication(ports.auth, ports.api, ports.view).start()

    expect(ports.view.showLogin).toHaveBeenCalledOnce()
    expect(ports.view.showError).not.toHaveBeenCalled()
  })

  it('筛选操作使当前页越界时回退并只渲染最后一个有效页', async () => {
    const ports = testPorts()
    const application = new AdminApplication(ports.auth, ports.api, ports.view)
    await application.start()
    const actions = vi.mocked(ports.view.showUsers).mock.calls[0]?.[1]
    vi.mocked(ports.api.listUsers)
      .mockResolvedValueOnce({
        ...EMPTY_PAGE,
        page: 2,
        totalPages: 2,
      })
      .mockResolvedValueOnce({
        ...EMPTY_PAGE,
        page: 1,
        totalPages: 2,
      })
    const rendersBeforeReload = vi.mocked(ports.view.showUsers).mock.calls.length

    await actions?.changeQuery({
      email: 'last-page@example.com',
      status: 'ACTIVE',
      page: 2,
      size: 20,
    })

    expect(ports.api.listUsers).toHaveBeenNthCalledWith(
      2,
      'access-token',
      {
        email: 'last-page@example.com',
        status: 'ACTIVE',
        page: 2,
        size: 20,
      },
    )
    expect(ports.api.listUsers).toHaveBeenNthCalledWith(
      3,
      'access-token',
      {
        email: 'last-page@example.com',
        status: 'ACTIVE',
        page: 1,
        size: 20,
      },
    )
    expect(ports.view.showUsers).toHaveBeenCalledTimes(rendersBeforeReload + 1)
    expect(ports.view.showUsers).toHaveBeenLastCalledWith(
      expect.objectContaining({ page: 1, totalPages: 2 }),
      expect.any(Object),
      expect.objectContaining({ page: 1 }),
    )
  })
})

const INITIAL_QUERY_FOR_TEST = {
  email: '',
  status: '' as const,
  page: 0,
  size: 20,
}

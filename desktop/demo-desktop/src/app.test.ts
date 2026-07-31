import { describe, expect, it, vi } from 'vitest'

import type { AuthStatus, DesktopAuthApi } from './api'
import { AuthController, type AuthView } from './app'

describe('AuthController', () => {
  it('启动时从系统凭据库恢复登录态', async () => {
    const { api, view } = harness('authenticated')

    await new AuthController(api, view).initialize()

    expect(view.showBusy).toHaveBeenCalledWith('正在恢复登录状态…')
    expect(api.restore).toHaveBeenCalledOnce()
    expect(view.showAuthenticated).toHaveBeenCalledOnce()
  })

  it('网络暂不可用时保留凭据并显示可重试状态', async () => {
    const { api, view } = harness('retryable')

    await new AuthController(api, view).initialize()

    expect(view.showRetryable).toHaveBeenCalledWith('暂时无法连接认证中心，请重试')
    expect(view.showLoginRequired).not.toHaveBeenCalled()
  })

  it('登录命令通过系统浏览器完成后显示登录态', async () => {
    const { api, view } = harness('loginRequired')
    vi.mocked(api.login).mockResolvedValue('authenticated')
    const controller = new AuthController(api, view)

    await controller.login()

    expect(view.showBusy).toHaveBeenCalledWith('请在系统浏览器中完成登录…')
    expect(api.login).toHaveBeenCalledOnce()
    expect(view.showAuthenticated).toHaveBeenCalledOnce()
  })

  it('登出删除凭据后只显示登录入口', async () => {
    const { api, view } = harness('authenticated')
    const controller = new AuthController(api, view)

    await controller.logout()

    expect(api.logout).toHaveBeenCalledOnce()
    expect(view.showLoginRequired).toHaveBeenCalledOnce()
  })

  it('后端错误被转成稳定文案而不展示内部细节', async () => {
    const { api, view } = harness('loginRequired')
    vi.mocked(api.login).mockRejectedValue({
      code: 'callbackFailed',
      message: '包含内部路径 /Users/someone/private',
    })

    await new AuthController(api, view).login()

    expect(view.showError).toHaveBeenCalledWith('登录未完成，请重试')
    expect(view.showError).not.toHaveBeenCalledWith(
      expect.stringContaining('/Users/someone/private'),
    )
  })
})

function harness(restoreStatus: AuthStatus): {
  api: DesktopAuthApi
  view: AuthView
} {
  return {
    api: {
      restore: vi.fn().mockResolvedValue(restoreStatus),
      login: vi.fn().mockResolvedValue('authenticated'),
      logout: vi.fn().mockResolvedValue(undefined),
    },
    view: {
      showBusy: vi.fn(),
      showAuthenticated: vi.fn(),
      showLoginRequired: vi.fn(),
      showRetryable: vi.fn(),
      showError: vi.fn(),
    },
  }
}

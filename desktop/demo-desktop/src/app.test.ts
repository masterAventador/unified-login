import { describe, expect, it, vi } from 'vitest'

import type { TauriAuthClientApi } from '@unified-login/tauri'
import { AuthController, type AuthView } from './app'

describe('AuthController', () => {
  it('启动时通过 getAccessToken 恢复登录态', async () => {
    const { api, view } = harness()

    await new AuthController(api, view).initialize()

    expect(view.showBusy).toHaveBeenCalledWith('正在恢复登录状态…')
    expect(api.getAccessToken).toHaveBeenCalledOnce()
    expect(view.showAuthenticated).toHaveBeenCalledOnce()
  })

  it('启动时没有凭据就显示登录入口', async () => {
    const { api, view } = harness()
    vi.mocked(api.getAccessToken).mockRejectedValueOnce({
      code: 'loginRequired',
    })

    await new AuthController(api, view).initialize()

    expect(view.showLoginRequired).toHaveBeenCalledOnce()
    expect(view.showError).not.toHaveBeenCalled()
  })

  it('网络暂不可用时显示可重试状态', async () => {
    const { api, view } = harness()
    vi.mocked(api.getAccessToken).mockRejectedValueOnce({
      code: 'retryable',
    })

    await new AuthController(api, view).initialize()

    expect(view.showRetryable).toHaveBeenCalledWith('暂时无法连接认证中心，请重试')
    expect(view.showLoginRequired).not.toHaveBeenCalled()
  })

  it('后台维护有效会话时不打断当前界面', async () => {
    const { api, view } = harness()
    const controller = new AuthController(api, view)
    await controller.initialize()
    vi.clearAllMocks()

    await controller.maintain()

    expect(api.getAccessToken).toHaveBeenCalledOnce()
    expect(view.showBusy).not.toHaveBeenCalled()
    expect(view.showAuthenticated).not.toHaveBeenCalled()
  })

  it('上一轮后台维护未结束时不会再发出重叠请求', async () => {
    const { api, view } = harness()
    const controller = new AuthController(api, view)
    await controller.initialize()
    vi.clearAllMocks()
    let completeMaintenance!: (accessToken: string) => void
    vi.mocked(api.getAccessToken).mockImplementationOnce(() => (
      new Promise<string>((resolve) => {
        completeMaintenance = resolve
      })
    ))

    const firstMaintenance = controller.maintain()
    const overlappingMaintenance = controller.maintain()

    expect(api.getAccessToken).toHaveBeenCalledOnce()
    completeMaintenance('rotated-access-token')
    await Promise.all([firstMaintenance, overlappingMaintenance])
    expect(view.showRetryable).not.toHaveBeenCalled()
  })

  it('用户正在浏览器登录时后台维护不会覆盖忙碌状态', async () => {
    const { api, view } = harness()
    let completeLogin!: () => void
    vi.mocked(api.login).mockImplementation(() => (
      new Promise<void>((resolve) => {
        completeLogin = resolve
      })
    ))
    const controller = new AuthController(api, view)

    const login = controller.login()
    await controller.maintain()

    expect(api.getAccessToken).not.toHaveBeenCalled()
    expect(view.showLoginRequired).not.toHaveBeenCalled()

    completeLogin()
    await login
  })

  it('已经发出的后台维护响应不会覆盖后来开始的登录', async () => {
    const { api, view } = harness()
    const controller = new AuthController(api, view)
    await controller.initialize()
    vi.clearAllMocks()

    let rejectMaintenance!: (reason: unknown) => void
    let completeLogin!: () => void
    vi.mocked(api.getAccessToken).mockImplementationOnce(() => (
      new Promise<string>((_, reject) => {
        rejectMaintenance = reject
      })
    ))
    vi.mocked(api.login).mockImplementationOnce(() => (
      new Promise<void>((resolve) => {
        completeLogin = resolve
      })
    ))

    const maintenance = controller.maintain()
    const login = controller.login()
    expect(view.showBusy).toHaveBeenCalledWith('请在系统浏览器中完成登录…')

    completeLogin()
    await login
    rejectMaintenance({ code: 'loginRequired' })
    await maintenance

    expect(view.showLoginRequired).not.toHaveBeenCalled()
    expect(view.showAuthenticated).toHaveBeenCalledOnce()
  })

  it('登录失败等待用户重试时后台维护不会改回登录入口', async () => {
    const { api, view } = harness()
    vi.mocked(api.login).mockRejectedValueOnce(new Error('回调校验失败'))
    const controller = new AuthController(api, view)

    await controller.login()
    await controller.maintain()

    expect(api.getAccessToken).not.toHaveBeenCalled()
    expect(view.showError).toHaveBeenCalledWith('登录未完成，请重试')
    expect(view.showLoginRequired).not.toHaveBeenCalled()
  })

  it('登录命令通过系统浏览器完成后显示登录态', async () => {
    const { api, view } = harness()
    const controller = new AuthController(api, view)

    await controller.login()

    expect(view.showBusy).toHaveBeenCalledWith('请在系统浏览器中完成登录…')
    expect(api.login).toHaveBeenCalledOnce()
    expect(view.showAuthenticated).toHaveBeenCalledOnce()
  })

  it('登出删除凭据后只显示登录入口', async () => {
    const { api, view } = harness()
    const controller = new AuthController(api, view)

    await controller.logout()

    expect(api.logout).toHaveBeenCalledOnce()
    expect(view.showLoginRequired).toHaveBeenCalledOnce()
  })

  it('后端错误被转成稳定文案而不展示内部细节', async () => {
    const { api, view } = harness()
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

  it('登录失败后的重试会重新执行登录', async () => {
    const { api, view } = harness()
    vi.mocked(api.login)
      .mockRejectedValueOnce(new Error('首次登录失败'))
      .mockResolvedValueOnce(undefined)
    const controller = new AuthController(api, view)

    await controller.login()
    await controller.retry()

    expect(api.login).toHaveBeenCalledTimes(2)
    expect(api.getAccessToken).not.toHaveBeenCalled()
    expect(view.showAuthenticated).toHaveBeenCalledOnce()
  })

  it('恢复失败后的重试会重新取得 access token', async () => {
    const { api, view } = harness()
    vi.mocked(api.getAccessToken)
      .mockRejectedValueOnce(new Error('首次恢复失败'))
      .mockResolvedValueOnce('access-secret')
    const controller = new AuthController(api, view)

    await controller.initialize()
    await controller.retry()

    expect(api.getAccessToken).toHaveBeenCalledTimes(2)
    expect(view.showAuthenticated).toHaveBeenCalledOnce()
  })

  it('登出失败后的重试会重新执行登出', async () => {
    const { api, view } = harness()
    vi.mocked(api.logout)
      .mockRejectedValueOnce(new Error('首次登出失败'))
      .mockResolvedValueOnce(undefined)
    const controller = new AuthController(api, view)

    await controller.logout()
    await controller.retry()

    expect(api.logout).toHaveBeenCalledTimes(2)
    expect(api.getAccessToken).not.toHaveBeenCalled()
    expect(view.showLoginRequired).toHaveBeenCalledOnce()
  })
})

function harness(): {
  api: TauriAuthClientApi
  view: AuthView
} {
  return {
    api: {
      login: vi.fn().mockResolvedValue(undefined),
      logout: vi.fn().mockResolvedValue(undefined),
      getAccessToken: vi.fn().mockResolvedValue('access-secret'),
      onAuthStateChange: vi.fn().mockReturnValue(() => undefined),
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

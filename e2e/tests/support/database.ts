import { expect } from '@playwright/test'
import { execFileSync } from 'node:child_process'

const E2E_POSTGRES_CONTAINER = 'unified-login-e2e-postgres'
const SAFE_EMAIL = /^[a-z0-9@.-]+$/

/**
 * 管理后台本身正是要验收的入口，不能拿它给首个管理员授权。
 * bootstrap 启动映射已由真实 Spring 集成测试覆盖；E2E 在账号注册后直接准备角色，
 * 后续所有登录、鉴权、列表和账号操作仍完整经过生产链路。
 */
export function promoteToPlatformAdmin(email: string): void {
  expect(email).toMatch(SAFE_EMAIL)
  const output = execFileSync(
    'docker',
    [
      'exec',
      E2E_POSTGRES_CONTAINER,
      'psql',
      '-U',
      'unified_login',
      '-d',
      'unified_login',
      '-v',
      'ON_ERROR_STOP=1',
      '-c',
      `UPDATE app_user SET is_platform_admin = TRUE WHERE email = '${email}'`,
    ],
    { encoding: 'utf8' },
  )
  expect(output.trim()).toBe('UPDATE 1')
}

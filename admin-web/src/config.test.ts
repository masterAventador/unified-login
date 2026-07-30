import { describe, expect, it } from 'vitest'

import { createAdminRuntimeConfig } from './config'

describe('createAdminRuntimeConfig', () => {
  it('使用部署注入的认证中心地址与当前页面来源生成回调', () => {
    expect(createAdminRuntimeConfig(
      'https://auth.example.com/',
      'https://admin.example.com',
    )).toEqual({
      authServer: 'https://auth.example.com',
      redirectUri: 'https://admin.example.com/callback',
    })
  })

  it('拒绝非 HTTP 协议和带路径的认证中心地址', () => {
    expect(() => createAdminRuntimeConfig(
      'file:///etc/passwd',
      'https://admin.example.com',
    )).toThrow('认证中心地址无效')
    expect(() => createAdminRuntimeConfig(
      'https://auth.example.com/nested',
      'https://admin.example.com',
    )).toThrow('认证中心地址不能包含路径')
  })
})

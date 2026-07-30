import { describe, expect, it } from 'vitest'

import { TokenStore } from './tokens'

describe('TokenStore', () => {
  it('仅在实例内存中持有完整令牌集与绝对过期时刻', () => {
    const store = new TokenStore()
    const tokens = {
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
      idToken: 'id-token',
      expiresAt: 1_700_000_000_000,
    }

    store.set(tokens)

    expect(store.get()).toEqual(tokens)
    expect(new TokenStore().get()).toBeNull()

    store.clear()
    expect(store.get()).toBeNull()
  })

  it('默认提前 60 秒判定即将过期，并允许调用方覆盖偏移量', () => {
    let now = 1_700_000_000_000
    const store = new TokenStore(() => now)
    store.set({
      accessToken: 'access-token',
      expiresAt: now + 61_000,
    })

    expect(store.isExpiringSoon()).toBe(false)

    now += 1_000
    expect(store.isExpiringSoon()).toBe(true)
    expect(store.isExpiringSoon(30)).toBe(false)
  })

  it('没有令牌时不报告即将过期', () => {
    expect(new TokenStore().isExpiringSoon()).toBe(false)
  })
})

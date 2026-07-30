import { describe, expect, it } from 'vitest'

import { AuthorizationRequestStore } from './storage'

class MemoryStorage implements Storage {
  private readonly values = new Map<string, string>()

  get length(): number {
    return this.values.size
  }

  clear(): void {
    this.values.clear()
  }

  getItem(key: string): string | null {
    return this.values.get(key) ?? null
  }

  key(index: number): string | null {
    return [...this.values.keys()][index] ?? null
  }

  removeItem(key: string): void {
    this.values.delete(key)
  }

  setItem(key: string, value: string): void {
    this.values.set(key, value)
  }
}

describe('AuthorizationRequestStore', () => {
  it('用客户端命名空间保存 state 与 verifier，并在取出时立即删除', () => {
    const storage = new MemoryStorage()
    const store = new AuthorizationRequestStore('demo-web-a', storage)

    store.save({ state: 'expected-state', verifier: 'code-verifier' })

    expect(storage.getItem('demo-web-a.state')).toBe('expected-state')
    expect(storage.getItem('demo-web-a.code_verifier')).toBe('code-verifier')
    expect(store.take()).toEqual({
      state: 'expected-state',
      verifier: 'code-verifier',
    })
    expect(storage.length).toBe(0)
    expect(store.take()).toBeNull()
  })

  it('任一字段缺失时拒绝返回残缺请求并清理另一字段', () => {
    const storage = new MemoryStorage()
    const store = new AuthorizationRequestStore('demo-web-a', storage)
    storage.setItem('demo-web-a.state', 'orphaned-state')

    expect(store.take()).toBeNull()
    expect(storage.length).toBe(0)
  })
})

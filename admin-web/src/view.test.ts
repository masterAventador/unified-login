import { describe, expect, it, vi } from 'vitest'

import { AdminDomView } from './view'
import type { AdminActions, UserPage } from './app'

class MemoryElement {
  readonly children: MemoryElement[] = []
  readonly attributes = new Map<string, string>()
  readonly listeners = new Map<string, EventListener>()
  className = ''
  disabled = false
  textContent: string | null = null
  type = ''
  value = ''

  constructor(readonly tagName: string) {}

  set innerHTML(_value: string) {
    throw new Error('禁止使用 innerHTML')
  }

  append(...nodes: MemoryElement[]): void {
    this.children.push(...nodes)
  }

  replaceChildren(...nodes: MemoryElement[]): void {
    this.children.splice(0, this.children.length, ...nodes)
  }

  setAttribute(name: string, value: string): void {
    this.attributes.set(name, value)
  }

  addEventListener(type: string, listener: EventListener): void {
    this.listeners.set(type, listener)
  }
}

class MemoryDocument {
  readonly createdTags: string[] = []

  createElement(tagName: string): MemoryElement {
    this.createdTags.push(tagName)
    return new MemoryElement(tagName)
  }
}

function allText(root: MemoryElement): string[] {
  return [
    ...(root.textContent === null ? [] : [root.textContent]),
    ...root.children.flatMap(allText),
  ]
}

describe('AdminDomView', () => {
  it('把用户可控邮箱只写入 textContent，不解析成元素', () => {
    const document = new MemoryDocument()
    const root = new MemoryElement('main')
    const injectionEmail = '<img/src=x onerror=alert(1)>@example.com'
    const page: UserPage = {
      content: [{
        id: 'user-id',
        email: injectionEmail,
        status: 'ACTIVE',
        emailVerified: false,
        platformAdmin: false,
        passwordChangedAt: '2026-07-31T00:00:00Z',
        createdAt: '2026-07-31T00:00:00Z',
        updatedAt: '2026-07-31T00:00:00Z',
      }],
      page: 0,
      size: 20,
      totalElements: 1,
      totalPages: 1,
    }
    const actions: AdminActions = {
      changeQuery: vi.fn(),
      disable: vi.fn(),
      enable: vi.fn(),
      resetPassword: vi.fn(),
      logout: vi.fn(),
    }

    new AdminDomView(
      document as unknown as Document,
      root as unknown as HTMLElement,
    ).showUsers(page, actions, {
      email: '',
      status: '',
      page: 0,
      size: 20,
    })

    expect(allText(root)).toContain(injectionEmail)
    expect(document.createdTags).not.toContain('img')
  })

  it('重新渲染用户页时保留当前邮箱与状态筛选条件', () => {
    const document = new MemoryDocument()
    const root = new MemoryElement('main')
    const actions: AdminActions = {
      changeQuery: vi.fn(),
      disable: vi.fn(),
      enable: vi.fn(),
      resetPassword: vi.fn(),
      logout: vi.fn(),
    }

    new AdminDomView(
      document as unknown as Document,
      root as unknown as HTMLElement,
    ).showUsers({
      content: [],
      page: 1,
      size: 20,
      totalElements: 0,
      totalPages: 2,
    }, actions, {
      email: 'alice@example.com',
      status: 'DISABLED',
      page: 1,
      size: 20,
    })

    const controls = descendants(root)
    expect(controls.find((element) => element.tagName === 'input')?.value)
      .toBe('alice@example.com')
    expect(controls.find((element) => element.tagName === 'select')?.value)
      .toBe('DISABLED')
  })

  it('无权限态只显示固定文案，不暴露服务端异常', () => {
    const document = new MemoryDocument()
    const root = new MemoryElement('main')

    new AdminDomView(
      document as unknown as Document,
      root as unknown as HTMLElement,
    ).showForbidden(vi.fn().mockResolvedValue(undefined))

    expect(allText(root)).toContain('无权限')
    expect(allText(root)).toContain('退出并更换账号')
    expect(allText(root).join(' ')).not.toContain('stack')
  })
})

function descendants(root: MemoryElement): MemoryElement[] {
  return [root, ...root.children.flatMap(descendants)]
}

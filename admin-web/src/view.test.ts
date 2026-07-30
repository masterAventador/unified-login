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
  removed = false

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

  remove(): void {
    this.removed = true
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

  it('翻页沿用已生效的筛选条件而不是输入框中尚未提交的值', () => {
    const document = new MemoryDocument()
    const root = new MemoryElement('main')
    const changeQuery = vi.fn()
    const actions: AdminActions = {
      changeQuery,
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
      page: 0,
      size: 20,
      totalElements: 40,
      totalPages: 2,
    }, actions, {
      email: 'applied@example.com',
      status: 'ACTIVE',
      page: 0,
      size: 20,
    })

    const controls = descendants(root)
    const email = controls.find((element) => element.tagName === 'input')
    const status = controls.find((element) => element.tagName === 'select')
    const next = controls.find((element) => element.textContent === '下一页')
    expect(email).toBeDefined()
    expect(status).toBeDefined()
    expect(next).toBeDefined()
    email!.value = 'draft@example.com'
    status!.value = 'DISABLED'
    next!.listeners.get('click')!(new Event('click'))

    expect(changeQuery).toHaveBeenCalledWith({
      email: 'applied@example.com',
      status: 'ACTIVE',
      page: 1,
      size: 20,
    })
  })

  it('在密码输入框中收集重置密码且提交给对应账号', () => {
    const document = new MemoryDocument()
    const root = new MemoryElement('main')
    const resetPassword = vi.fn().mockResolvedValue(undefined)
    const actions: AdminActions = {
      changeQuery: vi.fn(),
      disable: vi.fn(),
      enable: vi.fn(),
      resetPassword,
      logout: vi.fn(),
    }

    new AdminDomView(
      document as unknown as Document,
      root as unknown as HTMLElement,
    ).showUsers({
      content: [{
        id: 'target-user',
        email: 'target@example.com',
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
    }, actions, {
      email: '',
      status: '',
      page: 0,
      size: 20,
    })

    const reset = descendants(root).find(
      (element) => element.attributes.get('data-testid') === 'reset-password',
    )
    expect(reset).toBeDefined()
    reset!.listeners.get('click')!(new Event('click'))

    const dialog = descendants(root).find(
      (element) => element.attributes.get('data-testid') === 'reset-password-dialog',
    )
    const password = descendants(root).find(
      (element) => element.attributes.get('data-testid') === 'new-password',
    )
    const form = descendants(root).find((element) => (
      element.tagName === 'form'
      && element.attributes.get('data-testid') === 'reset-password-form'
    ))
    expect(dialog?.attributes.get('role')).toBe('dialog')
    expect(dialog?.attributes.get('aria-modal')).toBe('true')
    expect(password?.type).toBe('password')
    password!.value = 'new secret password'
    form!.listeners.get('submit')!({
      preventDefault: vi.fn(),
    } as unknown as Event)

    expect(resetPassword).toHaveBeenCalledWith('target-user', 'new secret password')
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

  it('操作失败提示与用户列表同时渲染，管理员仍可继续操作', () => {
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
      page: 0,
      size: 20,
      totalElements: 0,
      totalPages: 0,
    }, actions, {
      email: '',
      status: '',
      page: 0,
      size: 20,
    }, '新密码必须为 8–64 个字符')

    expect(allText(root)).toContain('新密码必须为 8–64 个字符')
    expect(descendants(root).some(
      (element) => element.attributes.get('data-testid') === 'operation-error',
    )).toBe(true)
    expect(allText(root)).toContain('退出')
    expect(allText(root)).toContain('查询')
  })
})

function descendants(root: MemoryElement): MemoryElement[] {
  return [root, ...root.children.flatMap(descendants)]
}

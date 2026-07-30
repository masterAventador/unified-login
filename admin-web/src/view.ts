import type { AdminActions, UserPage, UserQuery } from './app'
import type { AdminUser, UserStatus } from './api'

export class AdminDomView {
  constructor(
    private readonly document: Document,
    private readonly root: HTMLElement,
  ) {}

  showLoading(): void {
    this.root.replaceChildren(this.statePanel('正在加载…', 'loading'))
  }

  showLogin(login: () => Promise<void>): void {
    const button = this.button('登录管理后台', 'primary')
    button.setAttribute('data-testid', 'admin-login')
    button.addEventListener('click', () => {
      button.disabled = true
      void login().catch(() => {
        button.disabled = false
        this.showError('无法跳转到登录页，请稍后重试')
      })
    })
    const panel = this.statePanel('请使用统一账号登录', 'login-state')
    panel.append(button)
    this.root.replaceChildren(panel)
  }

  showForbidden(switchAccount: () => Promise<void>): void {
    const panel = this.statePanel('无权限', 'forbidden')
    const button = this.button('退出并更换账号', 'ghost')
    button.setAttribute('data-testid', 'switch-account')
    button.addEventListener('click', () => {
      button.disabled = true
      void switchAccount().catch(() => {
        button.disabled = false
        this.showError('无法切换账号，请稍后重试')
      })
    })
    panel.append(
      this.text('当前账号不是平台管理员。', 'state-detail'),
      button,
    )
    this.root.replaceChildren(panel)
  }

  showError(message: string): void {
    const panel = this.statePanel('加载失败', 'error')
    panel.append(this.text(message, 'state-detail'))
    this.root.replaceChildren(panel)
  }

  showUsers(page: UserPage, actions: AdminActions, query: UserQuery): void {
    const shell = this.element('div', 'admin-shell')
    shell.append(
      this.header(actions),
      this.filters(page, actions, query),
      this.userTable(page, actions),
      this.pagination(page, actions),
    )
    this.root.replaceChildren(shell)
  }

  private header(actions: AdminActions): HTMLElement {
    const header = this.element('header', 'topbar')
    const titleGroup = this.element('div')
    titleGroup.append(
      this.text('统一登录', 'eyebrow'),
      this.heading('账号管理'),
    )
    const logout = this.button('退出', 'ghost')
    logout.setAttribute('data-testid', 'admin-logout')
    logout.addEventListener('click', actions.logout)
    header.append(titleGroup, logout)
    return header
  }

  private filters(
    page: UserPage,
    actions: AdminActions,
    query: UserQuery,
  ): HTMLElement {
    const form = this.element('form', 'filters')
    const email = this.document.createElement('input')
    email.type = 'search'
    email.name = 'email'
    email.placeholder = '按邮箱搜索'
    email.value = query.email
    email.setAttribute('aria-label', '按邮箱搜索')
    email.setAttribute('data-testid', 'email-filter')

    const status = this.document.createElement('select')
    status.name = 'status'
    status.setAttribute('aria-label', '按账号状态筛选')
    status.setAttribute('data-testid', 'status-filter')
    status.append(
      this.option('', '全部状态'),
      this.option('ACTIVE', '正常'),
      this.option('DISABLED', '已禁用'),
    )
    status.value = query.status

    const submit = this.button('查询', 'primary')
    submit.type = 'submit'
    form.append(email, status, submit)
    form.addEventListener('submit', (event) => {
      event.preventDefault()
      void actions.changeQuery({
        email: email.value,
        status: status.value as UserStatus | '',
        page: 0,
        size: page.size,
      })
    })
    return form
  }

  private userTable(page: UserPage, actions: AdminActions): HTMLElement {
    const region = this.element('section', 'table-card')
    region.setAttribute('aria-label', '用户列表')
    const summary = this.text(`共 ${page.totalElements} 个账号`, 'result-count')
    region.append(summary)

    if (page.content.length === 0) {
      region.append(this.text('没有符合条件的账号', 'empty-state'))
      return region
    }

    const table = this.element('table')
    const header = this.element('thead')
    const headerRow = this.element('tr')
    for (const label of ['邮箱', '状态', '邮箱验证', '管理员', '创建时间', '操作']) {
      headerRow.append(this.cell('th', label))
    }
    header.append(headerRow)

    const body = this.element('tbody')
    for (const user of page.content) {
      body.append(this.userRow(user, actions))
    }
    table.append(header, body)
    region.append(table)
    return region
  }

  private userRow(user: AdminUser, actions: AdminActions): HTMLElement {
    const row = this.element('tr')
    row.setAttribute('data-user-id', user.id)
    row.append(
      this.cell('td', user.email, 'email-cell'),
      this.cell('td', user.status === 'ACTIVE' ? '正常' : '已禁用', `status ${user.status.toLowerCase()}`),
      this.cell('td', user.emailVerified ? '已验证' : '未验证'),
      this.cell('td', user.platformAdmin ? '是' : '否'),
      this.cell('td', formatTimestamp(user.createdAt)),
      this.actionsCell(user, actions),
    )
    return row
  }

  private actionsCell(user: AdminUser, actions: AdminActions): HTMLElement {
    const cell = this.element('td', 'row-actions')
    const statusAction = this.button(
      user.status === 'ACTIVE' ? '禁用' : '启用',
      user.status === 'ACTIVE' ? 'danger' : 'secondary',
    )
    statusAction.setAttribute(
      'data-testid',
      user.status === 'ACTIVE' ? 'disable-user' : 'enable-user',
    )
    statusAction.addEventListener('click', () => {
      void (user.status === 'ACTIVE'
        ? actions.disable(user.id)
        : actions.enable(user.id))
    })

    const reset = this.button('重置密码', 'ghost')
    reset.setAttribute('data-testid', 'reset-password')
    reset.addEventListener('click', () => {
      const newPassword = window.prompt(`为 ${user.email} 设置新密码（8–64 个字符）`)
      if (newPassword !== null) {
        void actions.resetPassword(user.id, newPassword)
      }
    })
    cell.append(statusAction, reset)
    return cell
  }

  private pagination(page: UserPage, actions: AdminActions): HTMLElement {
    const navigation = this.element('nav', 'pagination')
    navigation.setAttribute('aria-label', '用户列表分页')
    const previous = this.button('上一页', 'ghost')
    previous.disabled = page.page <= 0
    previous.addEventListener('click', () => {
      void actions.changeQuery(this.pageQuery(page, page.page - 1))
    })
    const position = this.text(
      page.totalPages === 0 ? '第 0 / 0 页' : `第 ${page.page + 1} / ${page.totalPages} 页`,
      'page-position',
    )
    const next = this.button('下一页', 'ghost')
    next.disabled = page.page + 1 >= page.totalPages
    next.addEventListener('click', () => {
      void actions.changeQuery(this.pageQuery(page, page.page + 1))
    })
    navigation.append(previous, position, next)
    return navigation
  }

  private pageQuery(page: UserPage, targetPage: number): UserQuery {
    const email = this.root.querySelector<HTMLInputElement>('[name="email"]')?.value ?? ''
    const status = this.root.querySelector<HTMLSelectElement>('[name="status"]')?.value ?? ''
    return {
      email,
      status: status as UserStatus | '',
      page: targetPage,
      size: page.size,
    }
  }

  private statePanel(title: string, testId: string): HTMLElement {
    const panel = this.element('section', 'state-panel')
    panel.setAttribute('data-testid', testId)
    panel.append(
      this.text('统一登录 · 管理后台', 'eyebrow'),
      this.heading(title),
    )
    return panel
  }

  private heading(text: string): HTMLHeadingElement {
    const heading = this.document.createElement('h1')
    heading.textContent = text
    return heading
  }

  private text(text: string, className?: string): HTMLParagraphElement {
    const paragraph = this.document.createElement('p')
    paragraph.textContent = text
    if (className !== undefined) {
      paragraph.className = className
    }
    return paragraph
  }

  private cell(
    tagName: 'th' | 'td',
    text: string,
    className?: string,
  ): HTMLTableCellElement {
    const cell = this.document.createElement(tagName)
    cell.textContent = text
    if (className !== undefined) {
      cell.className = className
    }
    return cell
  }

  private button(text: string, variant: string): HTMLButtonElement {
    const button = this.document.createElement('button')
    button.type = 'button'
    button.className = `button ${variant}`
    button.textContent = text
    return button
  }

  private option(value: string, text: string): HTMLOptionElement {
    const option = this.document.createElement('option')
    option.value = value
    option.textContent = text
    return option
  }

  private element<K extends keyof HTMLElementTagNameMap>(
    tagName: K,
    className?: string,
  ): HTMLElementTagNameMap[K] {
    const element = this.document.createElement(tagName)
    if (className !== undefined) {
      element.className = className
    }
    return element
  }
}

function formatTimestamp(value: string): string {
  const timestamp = new Date(value)
  return Number.isNaN(timestamp.getTime())
    ? '—'
    : new Intl.DateTimeFormat('zh-CN', {
      dateStyle: 'medium',
      timeStyle: 'short',
    }).format(timestamp)
}

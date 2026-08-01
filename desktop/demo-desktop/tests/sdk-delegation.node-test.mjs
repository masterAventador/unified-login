import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'

const rustSource = await readFile(
  new URL('../src-tauri/src/lib.rs', import.meta.url),
  'utf8',
)
const capability = JSON.parse(await readFile(
  new URL('../src-tauri/capabilities/default.json', import.meta.url),
  'utf8',
))

test('桌面应用只注册 SDK 插件而不复制认证命令与凭据生命周期', () => {
  assert.match(rustSource, /unified_login_tauri::plugin::Builder/)
  assert.doesNotMatch(rustSource, /\bAuthClient\b/)
  assert.doesNotMatch(rustSource, /struct AppState\b/)
  assert.doesNotMatch(rustSource, /SystemCredentialStore/)
  assert.doesNotMatch(rustSource, /#\[tauri::command\]/)
  assert.doesNotMatch(rustSource, /generate_handler!\[/)
  assert.doesNotMatch(
    rustSource,
    /current_auth_config\(\)\.expect/,
    '运行时配置错误必须由 SDK 插件返回结构化错误，不能让应用启动期 panic',
  )
})

test('主窗口只通过 SDK 默认权限调用认证命令', () => {
  assert.ok(capability.permissions.includes('unified-login-tauri:default'))
})

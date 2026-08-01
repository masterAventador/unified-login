import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import { normalizeSourceMap } from '../scripts/normalize-source-map.mjs'

const manifest = JSON.parse(await readFile(
  new URL('../package.json', import.meta.url),
  'utf8',
))
const rustSource = await readFile(
  new URL('./consumer-app/src/lib.rs', import.meta.url),
  'utf8',
)
const tsSource = await readFile(
  new URL('./consumer-app/src/auth.ts', import.meta.url),
  'utf8',
)
const capability = JSON.parse(await readFile(
  new URL('./consumer-app/capabilities/default.json', import.meta.url),
  'utf8',
))
const sourceMap = JSON.parse(await readFile(
  new URL('../dist/index.js.map', import.meta.url),
  'utf8',
))
const { TauriAuthClient } = await import('@unified-login/tauri')

test('TypeScript 适配层以独立包产物公开', () => {
  assert.equal(manifest.name, '@unified-login/tauri')
  assert.equal(manifest.private, undefined)
  assert.equal(manifest.publishConfig.access, 'public')
  assert.equal(manifest.exports['.'].import, './dist/index.js')
  assert.equal(manifest.exports['.'].types, './dist/index.d.ts')
  assert.deepEqual(manifest.files, ['dist'])
})

test('发布的 source map 内联源码且无需包外文件即可解析', () => {
  assert.equal(sourceMap.sources.length, 1)
  assert.equal(sourceMap.sourcesContent.length, sourceMap.sources.length)
  assert.match(sourceMap.sourcesContent[0], /export class TauriAuthClient/)
  assert.doesNotMatch(sourceMap.sourcesContent[0], /\r/)
})

test('已有 Windows 工作区的 CRLF 源码也会在构建时归一化', () => {
  const normalized = normalizeSourceMap({
    sourcesContent: ['first\r\nsecond\rthird\n'],
  })
  assert.deepEqual(normalized.sourcesContent, ['first\nsecond\nthird\n'])
})

test('第二个应用只配置插件、创建客户端和声明权限', () => {
  assert.match(rustSource, /AuthPluginBuilder::from_config_result/)
  assert.doesNotMatch(rustSource, /\bAuthClient\b/)
  assert.doesNotMatch(rustSource, /SystemCredentialStore|SessionManager|LoginAttempt/)
  assert.doesNotMatch(rustSource, /#\[tauri::command\]|generate_handler!\[/)

  assert.match(tsSource, /from '@unified-login\/tauri'/)
  assert.doesNotMatch(tsSource, /plugin:unified-login-tauri|invoke\(['"](?:login|logout|get_access_token)/)

  assert.ok(capability.permissions.includes('unified-login-tauri:default'))
})

test('编译后的包产物可由消费者按包名加载并调用', async () => {
  const calls = []
  const client = new TauriAuthClient(async (command) => {
    calls.push(command)
    return 'consumer-access-token'
  })

  assert.equal(await client.getAccessToken(), 'consumer-access-token')
  assert.deepEqual(calls, [
    'plugin:unified-login-tauri|get_access_token',
  ])
})

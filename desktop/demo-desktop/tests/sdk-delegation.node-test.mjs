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
const packageManifest = JSON.parse(await readFile(
  new URL('../package.json', import.meta.url),
  'utf8',
))
const frontendSources = await Promise.all([
  '../src/api.ts',
  '../src/app.ts',
  '../src/app.test.ts',
].map(async (path) => readFile(new URL(path, import.meta.url), 'utf8')))

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

test('桌面应用通过独立 SDK 包接入而不引用仓库内部源码路径', () => {
  assert.equal(
    packageManifest.dependencies['@unified-login/tauri'],
    'file:../../sdk/tauri',
  )
  for (const source of frontendSources) {
    assert.match(source, /from '@unified-login\/tauri'/)
    assert.doesNotMatch(source, /sdk\/tauri\/ts\/index/)
  }
})

test('桌面开发、检查和生产构建都先编译本地 SDK 包产物', () => {
  assert.equal(
    packageManifest.scripts['build:sdk'],
    'tsc -p ../../sdk/tauri/tsconfig.build.json && node ../../sdk/tauri/scripts/normalize-source-map.mjs',
    'SDK 必须复用桌面端冻结安装的 TypeScript，不能在构建阶段触发第二次依赖安装',
  )
  for (const script of ['dev', 'build', 'typecheck']) {
    assert.match(
      packageManifest.scripts[script],
      /^pnpm run build:sdk && /,
      `${script} 必须先重新编译本地 SDK`,
    )
  }
})

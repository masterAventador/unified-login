import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'

const source = await readFile(
  new URL('../src-tauri/src/lib.rs', import.meta.url),
  'utf8',
)

test('桌面正式命令只委托给 SDK AuthClient', () => {
  assert.match(source, /\bAuthClient\b/)
  assert.doesNotMatch(source, /\bLoginAttempt\b/)
  assert.doesNotMatch(source, /\bSessionManager\b/)
  assert.doesNotMatch(source, /\bTokenClient\b/)
  assert.doesNotMatch(source, /struct LoginLifecycle\b/)
})

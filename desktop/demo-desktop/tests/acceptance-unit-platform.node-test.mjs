import assert from 'node:assert/strict'
import { test } from 'node:test'

import { acceptanceUnitTestFiles } from './acceptance-unit-platform.mjs'

test('只在 macOS 选择依赖 xcrun、AppKit 和 DYLD 的验收辅助测试', () => {
  assert.deepEqual(acceptanceUnitTestFiles('linux'), [
    'tests/acceptance-unit-platform.node-test.mjs',
    'tests/acceptance-auth-server.node-test.mjs',
    'tests/acceptance-environment.node-test.mjs',
    'tests/acceptance-http.node-test.mjs',
    'tests/acceptance-java.node-test.mjs',
    'tests/acceptance-workspace.node-test.mjs',
    'tests/macos-external-driver-compilation.node-test.mjs',
    'tests/production-artifact-path.node-test.mjs',
  ])
  assert.deepEqual(acceptanceUnitTestFiles('win32'), [
    'tests/acceptance-unit-platform.node-test.mjs',
    'tests/acceptance-auth-server.node-test.mjs',
    'tests/acceptance-environment.node-test.mjs',
    'tests/acceptance-http.node-test.mjs',
    'tests/acceptance-java.node-test.mjs',
    'tests/acceptance-workspace.node-test.mjs',
    'tests/macos-external-driver-compilation.node-test.mjs',
    'tests/production-artifact-path.node-test.mjs',
  ])
  assert.deepEqual(acceptanceUnitTestFiles('darwin'), [
    'tests/acceptance-unit-platform.node-test.mjs',
    'tests/acceptance-auth-server.node-test.mjs',
    'tests/acceptance-environment.node-test.mjs',
    'tests/acceptance-http.node-test.mjs',
    'tests/acceptance-java.node-test.mjs',
    'tests/acceptance-workspace.node-test.mjs',
    'tests/macos-external-driver-compilation.node-test.mjs',
    'tests/production-artifact-path.node-test.mjs',
    'tests/acceptance-processes.node-test.mjs',
    'tests/browser-opener-interceptor.node-test.mjs',
    'tests/macos-application-launch.node-test.mjs',
    'tests/macos-webview-driver.node-test.mjs',
  ])
})

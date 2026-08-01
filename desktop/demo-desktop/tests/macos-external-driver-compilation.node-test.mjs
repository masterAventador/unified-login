import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  browserDriverCompilerArguments,
  webviewDriverCompilerArguments,
} from './macos-external-driver-compilation.mjs'

test('外置动态库明确使用最终生产应用的 Rust 目标架构', () => {
  const browserArguments = browserDriverCompilerArguments({
    output: '/tmp/browser-driver.dylib',
    productionTarget: 'x86_64-apple-darwin',
    source: '/repo/browser-driver.c',
  })
  const webviewArguments = webviewDriverCompilerArguments({
    output: '/tmp/webview-driver.dylib',
    productionTarget: 'aarch64-apple-darwin',
    source: '/repo/webview-driver.m',
  })

  assert.deepEqual(browserArguments.slice(0, 4), [
    'clang',
    '-target',
    'x86_64-apple-darwin',
    '-dynamiclib',
  ])
  assert.deepEqual(webviewArguments.slice(0, 4), [
    'clang',
    '-target',
    'aarch64-apple-darwin',
    '-dynamiclib',
  ])
  assert.equal(browserArguments.at(-1), '/tmp/browser-driver.dylib')
  assert.equal(webviewArguments.at(-1), '/tmp/webview-driver.dylib')
})

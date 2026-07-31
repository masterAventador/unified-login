import assert from 'node:assert/strict'
import { join, resolve } from 'node:path'
import { test } from 'node:test'

import {
  macosProductionArtifact,
  rustHostTarget,
} from './production-artifact-path.mjs'

test('生产验收从 Cargo metadata 的实际目标目录读取本轮应用', () => {
  const targetDirectory = resolve('unified-login-build-output')
  const artifact = macosProductionArtifact(
    JSON.stringify({
      target_directory: targetDirectory,
    }),
    '统一登录桌面端.app',
    'aarch64-apple-darwin',
  )

  assert.equal(
    artifact,
    join(
      targetDirectory,
      'aarch64-apple-darwin',
      'release',
      'bundle',
      'macos',
      '统一登录桌面端.app',
    ),
  )
  assert.ok(!artifact.includes(join('src-tauri', 'target')))
})

test('Cargo metadata 缺少绝对目标目录时拒绝猜测默认产物', () => {
  assert.throws(
    () => macosProductionArtifact('{"target_directory":"target"}', '应用.app'),
    /Cargo metadata 没有返回绝对目标目录/,
  )
  assert.throws(
    () => macosProductionArtifact(
      '{}',
      '应用.app',
      'aarch64-apple-darwin',
    ),
    /Cargo metadata 没有返回绝对目标目录/,
  )
})

test('生产目标三元组必须是单个安全路径片段', () => {
  const metadata = JSON.stringify({
    target_directory: resolve('unified-login-build-output'),
  })

  assert.throws(
    () => macosProductionArtifact(metadata, '应用.app', '../release'),
    /生产目标三元组无效/,
  )
})

test('从 rustc 版本信息取得本机生产目标且拒绝缺失值', () => {
  assert.equal(
    rustHostTarget(
      'rustc 1.97.0 (example)\n'
      + 'binary: rustc\n'
      + 'host: aarch64-apple-darwin\n',
    ),
    'aarch64-apple-darwin',
  )
  assert.throws(
    () => rustHostTarget('rustc 1.97.0 (example)\n'),
    /rustc 没有返回本机目标/,
  )
})

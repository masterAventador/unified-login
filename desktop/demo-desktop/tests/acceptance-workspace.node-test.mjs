import assert from 'node:assert/strict'
import { access, readFile, rm } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import {
  prepareWorkspace,
  withTemporaryDirectory,
} from './acceptance-workspace.mjs'

const REPOSITORY_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')

test('临时工作目录在首个准备动作失败时也会立即清理', async () => {
  let createdDirectory

  try {
    await assert.rejects(
      withTemporaryDirectory(
        'desktop-early-failure-',
        async (directory) => {
          createdDirectory = directory
          throw new Error('端口分配失败')
        },
      ),
      /端口分配失败/,
    )

    await assert.rejects(
      access(createdDirectory),
      (error) => error?.code === 'ENOENT',
    )
  } finally {
    if (createdDirectory !== undefined) {
      await rm(createdDirectory, { recursive: true, force: true })
    }
  }
})

test('独立前端 workspace 冻结安装依赖后才开始生产构建', async () => {
  const calls = []
  const run = async (...arguments_) => {
    calls.push(arguments_)
  }

  await prepareWorkspace(run, '/repository/demo-web-a', 'Demo Web A')

  assert.deepEqual(calls, [
    [
      'pnpm',
      ['install', '--frozen-lockfile'],
      'Demo Web A 依赖冻结安装失败',
      '/repository/demo-web-a',
    ],
    [
      'pnpm',
      ['build'],
      'Demo Web A 生产构建失败',
      '/repository/demo-web-a',
    ],
  ])
})

test('独立前端生产构建接收本轮受管配置', async () => {
  const calls = []
  const run = async (...arguments_) => {
    calls.push(arguments_)
  }

  await prepareWorkspace(
    run,
    '/repository/demo-web-a',
    'Demo Web A',
    { VITE_UNIFIED_LOGIN_ISSUER: 'http://localhost:19000' },
  )

  assert.deepEqual(calls[1], [
    'pnpm',
    ['build'],
    'Demo Web A 生产构建失败',
    '/repository/demo-web-a',
    { VITE_UNIFIED_LOGIN_ISSUER: 'http://localhost:19000' },
  ])
})

test('Demo Web A 用 URL 语义拼接动态 issuer 端点', async () => {
  const source = await readFile(
    join(REPOSITORY_ROOT, 'demo', 'demo-web-a', 'src', 'auth.ts'),
    'utf8',
  )

  assert.match(source, /new URL\(['"]oauth2\/authorize['"], ISSUER\)/)
  assert.match(source, /new URL\(['"]oauth2\/token['"], ISSUER\)/)
  assert.doesNotMatch(source, /\$\{ISSUER\}\/oauth2\//)
})

import assert from 'node:assert/strict'
import { access, rm } from 'node:fs/promises'
import { test } from 'node:test'

import {
  prepareWorkspace,
  withTemporaryDirectory,
} from './acceptance-workspace.mjs'

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

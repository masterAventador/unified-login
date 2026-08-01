import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

export async function withTemporaryDirectory(prefix, action) {
  const directory = await mkdtemp(join(tmpdir(), prefix))
  try {
    return await action(directory)
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}

export async function prepareWorkspace(run, directory, name) {
  await run(
    'pnpm',
    ['install', '--frozen-lockfile'],
    `${name} 依赖冻结安装失败`,
    directory,
  )
  await run(
    'pnpm',
    ['build'],
    `${name} 生产构建失败`,
    directory,
  )
}

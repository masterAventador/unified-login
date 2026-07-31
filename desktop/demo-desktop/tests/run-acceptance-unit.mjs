import { spawnSync } from 'node:child_process'

import { acceptanceUnitTestFiles } from './acceptance-unit-platform.mjs'

const files = acceptanceUnitTestFiles(process.platform)
if (process.platform !== 'darwin') {
  process.stdout.write(
    '桌面验收辅助测试：当前平台跳过仅适用于 macOS 的静默应用探针\n',
  )
}

const result = spawnSync(process.execPath, ['--test', ...files], {
  stdio: 'inherit',
})
if (result.error !== undefined) {
  throw result.error
}
process.exitCode = result.status ?? 1

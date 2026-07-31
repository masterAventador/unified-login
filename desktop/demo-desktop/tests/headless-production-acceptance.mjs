import { access, realpath } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const BINARY_NAME = 'demo-desktop'
const HERE = dirname(fileURLToPath(import.meta.url))
const PROJECT_DIRECTORY = dirname(HERE)
const REPOSITORY_ROOT = join(PROJECT_DIRECTORY, '..', '..')
const DEFAULT_APP = join(
  PROJECT_DIRECTORY,
  'src-tauri',
  'target',
  'release',
  'bundle',
  'macos',
  '统一登录桌面端.app',
)

if (process.platform !== 'darwin') {
  throw new Error('桌面生产产物验收必须在 macOS 上运行')
}

const artifact = await realpath(process.env.DESKTOP_APP_PATH ?? DEFAULT_APP)
await assertProductionArtifact(artifact)

try {
  report('在后台隐藏启动 release .app')
  terminateArtifact()
  run(
    '/usr/bin/open',
    ['-g', '-j', '-n', artifact],
    '无法在后台启动生产桌面应用',
  )
  await waitUntil(isArtifactRunning, '生产桌面应用没有成功启动')
} finally {
  terminateArtifact()
}

report('无界面验证 macOS 钥匙串写入、读取与删除')
run(
  'cargo',
  [
    'test',
    '--locked',
    '--test',
    'system_credentials',
    '--',
    '--ignored',
    '--exact',
    'macos_system_keychain_round_trip_is_headless_and_deletes_the_entry',
  ],
  'macOS 系统凭据库验收失败',
  join(REPOSITORY_ROOT, 'sdk', 'tauri'),
  'inherit',
)

report('用 Playwright headless 验证桌面 OAuth、SSO、刷新与伪造回调')
run(
  'pnpm',
  [
    'exec',
    'playwright',
    'test',
    '--config',
    'playwright.desktop.config.ts',
  ],
  '桌面 OAuth 无头浏览器验收失败',
  join(REPOSITORY_ROOT, 'e2e'),
  'inherit',
)

report('生产桌面端静默验收全部通过')

async function assertProductionArtifact(appPath) {
  const expectedSegment = join('target', 'release', 'bundle', 'macos')
  if (!appPath.includes(expectedSegment) || !appPath.endsWith('.app')) {
    throw new Error('验收入口必须是 Tauri release bundle 产出的 .app')
  }
  await access(join(appPath, 'Contents', 'MacOS', BINARY_NAME))
}

function isArtifactRunning() {
  return spawnSync('/usr/bin/pgrep', ['-x', BINARY_NAME], {
    stdio: 'ignore',
  }).status === 0
}

function terminateArtifact() {
  const result = spawnSync('/usr/bin/pkill', ['-x', BINARY_NAME], {
    stdio: 'ignore',
  })
  if (![0, 1].includes(result.status ?? -1)) {
    throw new Error('无法清理桌面验收进程')
  }
}

async function waitUntil(predicate, failureMessage, timeout = 10_000) {
  const deadline = Date.now() + timeout
  while (Date.now() < deadline) {
    if (predicate()) {
      return
    }
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  throw new Error(failureMessage)
}

function run(
  executable,
  arguments_,
  failureMessage,
  cwd = PROJECT_DIRECTORY,
  stdio = 'ignore',
) {
  const result = spawnSync(executable, arguments_, {
    cwd,
    env: {
      ...process.env,
      PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: '1',
    },
    stdio,
  })
  if (result.status !== 0) {
    throw new Error(failureMessage)
  }
}

function report(message) {
  process.stdout.write(`桌面验收：${message}\n`)
}

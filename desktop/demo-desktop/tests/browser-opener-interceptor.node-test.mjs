import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const SOURCE = join(HERE, 'browser-opener-interceptor.c')
const LAUNCHER_SOURCE = join(HERE, 'browser-opener-interceptor-launcher.c')

test('外置驱动捕获浏览器 URL 且不执行被拦截程序', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'desktop-browser-driver-'))
  const library = join(directory, 'browser-opener-interceptor.dylib')
  const launcher = join(directory, 'browser-opener-interceptor-launcher')
  const capture = join(directory, 'authorization-url')

  try {
    const compilation = spawnSync(
      '/usr/bin/xcrun',
      ['clang', '-dynamiclib', '-Wall', '-Werror', SOURCE, '-o', library],
      { encoding: 'utf8' },
    )
    assert.equal(
      compilation.status,
      0,
      compilation.stderr || '浏览器驱动编译失败',
    )
    const launcherCompilation = spawnSync(
      '/usr/bin/xcrun',
      ['clang', '-Wall', '-Werror', LAUNCHER_SOURCE, '-o', launcher],
      { encoding: 'utf8' },
    )
    assert.equal(
      launcherCompilation.status,
      0,
      launcherCompilation.stderr || '浏览器驱动测试启动器编译失败',
    )

    const authorizationUrl = 'https://example.invalid/authorize?state=expected'
    const intercepted = spawnSync(
      launcher,
      ['/usr/bin/printf', authorizationUrl],
      {
        encoding: 'utf8',
        env: {
          ...process.env,
          DYLD_INSERT_LIBRARIES: library,
          UNIFIED_LOGIN_INTERCEPT_EXECUTABLE: '/usr/bin/printf',
          UNIFIED_LOGIN_BROWSER_URL_FILE: capture,
        },
      },
    )

    assert.equal(intercepted.status, 0, intercepted.stderr)
    assert.equal(intercepted.stdout, '')
    assert.equal(await readFile(capture, 'utf8'), authorizationUrl)

    await rm(capture)
    const explicitlySelectedBrowser = spawnSync(
      launcher,
      [
        '/usr/bin/true',
        '-a',
        'Google Chrome',
        '--',
        authorizationUrl,
      ],
      {
        encoding: 'utf8',
        env: {
          ...process.env,
          DYLD_INSERT_LIBRARIES: library,
          UNIFIED_LOGIN_INTERCEPT_EXECUTABLE: '/usr/bin/true',
          UNIFIED_LOGIN_BROWSER_URL_FILE: capture,
        },
      },
    )

    assert.equal(
      explicitlySelectedBrowser.status,
      3,
      explicitlySelectedBrowser.stderr,
    )
    await assert.rejects(
      readFile(capture, 'utf8'),
      (error) => error?.code === 'ENOENT',
      '显式用 -a 选择浏览器时不得被当作系统默认浏览器调用',
    )
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
})

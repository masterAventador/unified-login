import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { EventEmitter } from 'node:events'
import {
  mkdtemp,
  mkdir,
  rm,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { PassThrough } from 'node:stream'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import {
  macosApplicationLauncherArguments,
  stopMacosApplication,
  stopMacosLauncher,
  waitForFile,
  waitForMacosApplicationProcessId,
} from './macos-application-launch.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))

test('最终应用启动器必须通过 LaunchServices 隐藏启动实际 app bundle', () => {
  const artifact = resolve('统一登录桌面端.app')

  assert.deepEqual(
    macosApplicationLauncherArguments(artifact, {
      UNIFIED_LOGIN_WINDOW_STARTUP_MODE: 'hidden',
      UNIFIED_LOGIN_WEBVIEW_DRIVER_PORT: '49152',
    }),
    [
      artifact,
      'UNIFIED_LOGIN_WINDOW_STARTUP_MODE=hidden',
      'UNIFIED_LOGIN_WEBVIEW_DRIVER_PORT=49152',
    ],
  )
})

test('LaunchServices 启动器拒绝非 app 产物和非法环境变量名', () => {
  assert.throws(
    () => macosApplicationLauncherArguments(resolve('demo-desktop'), {}),
    /必须是绝对 app bundle 路径/,
  )
  assert.throws(
    () => macosApplicationLauncherArguments(resolve('应用.app'), {
      'INVALID-NAME': 'value',
    }),
    /环境变量名无效/,
  )
})

test('实际 PID 等待给 LaunchServices 冷启动三十秒预算', async () => {
  const launcher = new EventEmitter()
  launcher.stdout = new PassThrough()
  let scheduled
  let cleared

  const processIdPromise = waitForMacosApplicationProcessId(
    launcher,
    undefined,
    {
      clearTimer: (timer) => {
        cleared = timer
      },
      setTimer: (callback, duration) => {
        scheduled = { callback, duration }
        return 42_001
      },
    },
  )

  assert.equal(scheduled.duration, 30_000)
  launcher.stdout.write('42002\n')
  assert.equal(await processIdPromise, 42_002)
  assert.equal(cleared, 42_001)
})

test('探针失联时用启动器返回的精确应用 PID 兜底终止后代应用', async () => {
  const calls = []
  const launcher = { exitCode: null, signalCode: null }

  await stopMacosApplication({
    applicationProcessId: 42_001,
    driver: {
      terminate: async () => {
        calls.push('driver')
        throw new Error('探针失联')
      },
    },
    isLauncherRunning: () => true,
    launcher,
    stopApplicationProcess: async (pid) => calls.push(`pid:${pid}`),
    stopLauncher: async (child) => {
      assert.equal(child, launcher)
      calls.push('launcher')
    },
    waitForLauncherExit: async () => calls.push('wait'),
  })

  assert.deepEqual(calls, [
    'driver',
    'pid:42001',
    'wait',
    'launcher',
  ])
})

test('探针已响应但 LaunchServices 未退出时仍用精确 PID 兜底', async () => {
  const calls = []
  let waitCount = 0

  await stopMacosApplication({
    applicationProcessId: 42_002,
    driver: {
      terminate: async () => calls.push('driver'),
    },
    isLauncherRunning: () => true,
    launcher: {},
    stopApplicationProcess: async (pid) => calls.push(`pid:${pid}`),
    stopLauncher: async () => calls.push('launcher'),
    waitForLauncherExit: async () => {
      calls.push('wait')
      waitCount += 1
      if (waitCount === 1) {
        throw new Error('LaunchServices 未退出')
      }
    },
  })

  assert.deepEqual(calls, [
    'driver',
    'wait',
    'pid:42002',
    'wait',
    'launcher',
  ])
})

test('启动器已异常退出时仍终止已记录的生产应用 PID', async () => {
  const calls = []
  const launcher = { exitCode: 70, signalCode: null }

  await stopMacosApplication({
    applicationProcessId: 42_003,
    driver: {
      terminate: async () => calls.push('driver'),
    },
    isLauncherRunning: () => false,
    launcher,
    stopApplicationProcess: async (pid) => calls.push(`pid:${pid}`),
    stopLauncher: async (child) => {
      assert.equal(child, launcher)
      calls.push('launcher')
    },
    waitForLauncherExit: async () => calls.push('wait'),
  })

  assert.deepEqual(calls, [
    'pid:42003',
    'launcher',
  ])
})

test('尚未取得应用 PID 的准备失败也会终止并等待启动器退出', async () => {
  const child = spawn(
    process.execPath,
    ['-e', 'setInterval(() => {}, 1000)'],
    { stdio: 'ignore' },
  )

  try {
    await stopMacosLauncher(child)

    assert.ok(
      child.exitCode !== null || child.signalCode !== null,
      '启动器必须在清理完成前退出',
    )
  } finally {
    if (child.exitCode === null && child.signalCode === null) {
      child.kill('SIGTERM')
      await waitForExit(child, 5_000)
    }
  }
})

test('LaunchServices 冷启动超过五秒仍等待明确的应用启动标记', async () => {
  let elapsed = 0
  const marker = await waitForFile(
    '/tmp/deterministic-cold-launch-marker',
    '冷启动不应在五秒时提前失败',
    {
      now: () => elapsed,
      pollInterval: 1_000,
      read: async () => {
        if (elapsed < 12_000) {
          const error = new Error('标记尚未生成')
          error.code = 'ENOENT'
          throw error
        }
        return '42001\n'
      },
      sleep: async (duration) => {
        elapsed += duration
      },
    },
  )

  assert.equal(marker, '42001\n')
  assert.equal(elapsed, 12_000)
})

test('异步 LaunchServices 尚未返回 PID 时收到终止信号也会清理已提交的应用', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'desktop-launch-signal-'))
  const launcher = join(directory, 'macos-application-launcher')
  const delayLibrary = join(directory, 'macos-launch-delay.dylib')
  const applicationBundle = join(directory, 'DelayedApplication.app')
  const executableDirectory = join(applicationBundle, 'Contents', 'MacOS')
  const executable = join(executableDirectory, 'delayed-application')
  const marker = join(directory, 'delayed-application.pid')
  let child
  let applicationProcessId

  try {
    await mkdir(executableDirectory, { recursive: true })
    compileNative(
      [
        '-fobjc-arc',
        '-Wall',
        '-Werror',
        join(HERE, 'macos-application-launcher.m'),
        '-framework',
        'AppKit',
        '-framework',
        'Foundation',
        '-o',
        launcher,
      ],
      'LaunchServices 启动器',
    )
    compileNative(
      [
        '-fobjc-arc',
        '-Wall',
        '-Werror',
        join(HERE, 'macos-delayed-application.m'),
        '-framework',
        'AppKit',
        '-framework',
        'Foundation',
        '-o',
        executable,
      ],
      '延迟启动测试应用',
    )
    compileNative(
      [
        '-dynamiclib',
        '-Wall',
        '-Werror',
        join(HERE, 'macos-launch-delay.c'),
        '-o',
        delayLibrary,
      ],
      '延迟启动动态库',
    )
    await writeFile(
      join(applicationBundle, 'Contents', 'Info.plist'),
      applicationInfoPlist(directory),
    )
    const signing = spawnSync(
      '/usr/bin/codesign',
      ['--force', '--deep', '--sign', '-', applicationBundle],
      { encoding: 'utf8' },
    )
    assert.equal(signing.status, 0, signing.stderr || '测试应用签名失败')

    child = spawn(
      launcher,
      [
        applicationBundle,
        `DYLD_INSERT_LIBRARIES=${delayLibrary}`,
        `UNIFIED_LOGIN_DELAYED_APP_PID_FILE=${marker}`,
      ],
      { stdio: ['ignore', 'pipe', 'pipe'] },
    )
    const stderr = []
    child.stderr.on('data', (chunk) => stderr.push(chunk))

    applicationProcessId = Number(
      await waitForFile(marker, '延迟应用没有进入 completion handler 前置窗口'),
    )
    assert.ok(
      Number.isInteger(applicationProcessId) && applicationProcessId > 1,
      '延迟应用必须报告有效 PID',
    )

    child.kill('SIGTERM')
    const exit = await waitForExit(child, 5_000)
    assert.equal(
      exit.code,
      143,
      Buffer.concat(stderr).toString() || '启动器应以 SIGTERM 对应状态退出',
    )
    await waitForProcessExit(applicationProcessId, 2_000)
  } finally {
    const failures = []
    try {
      await stopMacosLauncher(child)
    } catch (error) {
      failures.push(error)
    }
    try {
      if (
        applicationProcessId !== undefined
        && isProcessRunning(applicationProcessId)
      ) {
        process.kill(applicationProcessId, 'SIGTERM')
        await waitForProcessExit(applicationProcessId, 2_000)
      }
    } catch (error) {
      failures.push(error)
    }
    try {
      await rm(directory, { recursive: true, force: true })
    } catch (error) {
      failures.push(error)
    }
    if (failures.length > 0) {
      throw new AggregateError(failures, '启动器回归测试资源清理失败')
    }
  }
})

function compileNative(arguments_, label) {
  const result = spawnSync('/usr/bin/xcrun', ['clang', ...arguments_], {
    encoding: 'utf8',
  })
  assert.equal(result.status, 0, result.stderr || `${label}编译失败`)
}

function applicationInfoPlist(directory) {
  const uniqueIdentifier = directory
    .replaceAll(/[^A-Za-z0-9]/g, '')
    .slice(-24)
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>delayed-application</string>
  <key>CFBundleIdentifier</key><string>com.aventador.test.${uniqueIdentifier}</string>
  <key>CFBundleName</key><string>DelayedApplication</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSBackgroundOnly</key><true/>
</dict>
</plist>
`
}

function waitForExit(child, timeout) {
  return new Promise((resolve_, reject) => {
    const timer = setTimeout(
      () => reject(new Error('等待 LaunchServices 启动器退出超时')),
      timeout,
    )
    child.once('error', (error) => {
      clearTimeout(timer)
      reject(error)
    })
    child.once('exit', (code, signal) => {
      clearTimeout(timer)
      resolve_({ code, signal })
    })
  })
}

async function waitForProcessExit(processId, timeout) {
  const deadline = Date.now() + timeout
  while (Date.now() < deadline) {
    if (!isProcessRunning(processId)) {
      return
    }
    await new Promise((resolve_) => setTimeout(resolve_, 10))
  }
  assert.fail(`异步启动的应用进程仍然存活: ${processId}`)
}

function isProcessRunning(processId) {
  try {
    process.kill(processId, 0)
    return true
  } catch (error) {
    if (error?.code === 'ESRCH') {
      return false
    }
    throw error
  }
}

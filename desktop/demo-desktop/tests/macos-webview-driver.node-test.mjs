import assert from 'node:assert/strict'
import { dirname, join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

import {
  createProcessSupervisor,
  findAvailablePort,
} from './acceptance-processes.mjs'
import { withTemporaryDirectory } from './acceptance-workspace.mjs'
import { createWebViewDriver } from './macos-webview-driver.mjs'
import {
  activateActionScript,
  interactiveActionScript,
} from './webview-actions.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const DRIVER_SOURCE = join(HERE, 'macos-webview-driver.m')
const HOST_SOURCE = join(HERE, 'macos-webview-driver-host.m')

test('进程外探针可操作隐藏 WKWebView 且拒绝错误令牌', async () => {
  await withTemporaryDirectory(
    'desktop-webview-driver-',
    async (directory) => {
      const library = join(directory, 'macos-webview-driver.dylib')
      const host = join(directory, 'macos-webview-driver-host')
      const supervisor = createProcessSupervisor()
      const port = await findAvailablePort()
      const token = randomUUID().repeat(2)

      compile(
        [
          '-dynamiclib',
          '-fobjc-arc',
          '-Wall',
          '-Werror',
          DRIVER_SOURCE,
          '-framework',
          'AppKit',
          '-framework',
          'Foundation',
          '-framework',
          'Security',
          '-framework',
          'WebKit',
          '-o',
          library,
        ],
        'WebView 测试探针编译失败',
      )
      compile(
        [
          '-fobjc-arc',
          '-Wall',
          '-Werror',
          HOST_SOURCE,
          '-framework',
          'AppKit',
          '-framework',
          'WebKit',
          '-o',
          host,
        ],
        '隐藏 WebView 测试宿主编译失败',
      )

      const child = supervisor.start(host, [], {
        env: {
          ...process.env,
          DYLD_INSERT_LIBRARIES: library,
          UNIFIED_LOGIN_WEBVIEW_DRIVER_EXECUTABLE:
            'macos-webview-driver-host',
          UNIFIED_LOGIN_WEBVIEW_DRIVER_PORT: String(port),
          UNIFIED_LOGIN_WEBVIEW_DRIVER_TOKEN: token,
        },
        stdio: 'ignore',
      })
      const driver = createWebViewDriver({ port, token })

      try {
        await waitForDriver(driver)
        assert.equal(
          await driver.evaluate(
            "document.getElementById('action')?.textContent ?? null",
          ),
          'ready',
        )
        assert.equal(
          await driver.evaluate(interactiveActionScript('action')),
          true,
        )
        assert.equal(
          await driver.evaluate(interactiveActionScript('covered')),
          false,
        )
        assert.equal(
          await driver.evaluate(activateActionScript('covered')),
          false,
        )
        assert.equal(
          await driver.evaluate(activateActionScript('action')),
          true,
        )
        assert.equal(
          await driver.evaluate(
            "document.getElementById('action')?.dataset.clicked ?? null",
          ),
          'yes',
        )
        await assert.rejects(
          createWebViewDriver({
            port,
            token: `${token}-forged`,
          }).evaluate('1'),
          /unauthorized/,
        )
        await driver.terminate()
        await waitForChildExit(child)
      } finally {
        await supervisor.stop(child)
      }
    },
  )
})

async function waitForChildExit(child) {
  const deadline = Date.now() + 10_000
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) {
      return
    }
    await new Promise((resolve) => setTimeout(resolve, 20))
  }
  throw new Error('WebView 测试探针没有终止宿主应用')
}

function compile(arguments_, failureMessage) {
  const result = spawnSync('/usr/bin/xcrun', ['clang', ...arguments_], {
    encoding: 'utf8',
  })
  assert.equal(result.status, 0, result.stderr || failureMessage)
}

async function waitForDriver(driver) {
  const deadline = Date.now() + 10_000
  while (Date.now() < deadline) {
    try {
      if (
        await driver.evaluate(
          "document.getElementById('action')?.textContent ?? null",
        ) === 'ready'
      ) {
        return
      }
    } catch {
      // 隐藏宿主和 WKWebView 尚未完成初始化。
    }
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  throw new Error('WebView 测试探针未能操作隐藏宿主')
}

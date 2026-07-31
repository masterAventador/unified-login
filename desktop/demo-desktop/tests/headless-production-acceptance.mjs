import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { access, mkdtemp, readFile, realpath, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { chromium, expect as playwrightExpect } from '@playwright/test'

import {
  assertLocalhostPortAvailable,
  assertPortAvailable,
  createProcessSupervisor,
  findAvailablePort,
} from './acceptance-processes.mjs'
import {
  ACCEPTANCE_AUTH_ISSUER,
  acceptanceAuthServerOverrides,
} from './acceptance-auth-server.mjs'
import {
  acceptanceCredentialService,
  acceptanceSignalConfigurations,
  authServerEnvironment,
  credentialAccount,
  productionAppEnvironment,
} from './acceptance-environment.mjs'
import { responseIsOkWithin } from './acceptance-http.mjs'
import { javaExecutable } from './acceptance-java.mjs'
import { prepareWorkspace } from './acceptance-workspace.mjs'
import {
  macosApplicationLauncherArguments,
  stopMacosApplication,
  waitForMacosApplicationProcessId,
} from './macos-application-launch.mjs'
import {
  browserDriverCompilerArguments,
  webviewDriverCompilerArguments,
} from './macos-external-driver-compilation.mjs'
import { createWebViewDriver } from './macos-webview-driver.mjs'
import {
  macosProductionArtifact,
  rustHostTarget,
} from './production-artifact-path.mjs'
import {
  activateActionScript,
  interactiveActionScript,
} from './webview-actions.mjs'

const BINARY_NAME = 'demo-desktop'
const HERE = dirname(fileURLToPath(import.meta.url))
const PROJECT_DIRECTORY = dirname(HERE)
const REPOSITORY_ROOT = join(PROJECT_DIRECTORY, '..', '..')
const AUTH_SERVER_DIRECTORY = join(REPOSITORY_ROOT, 'auth-server')
const DEMO_WEB_A_DIRECTORY = join(REPOSITORY_ROOT, 'demo', 'demo-web-a')
const TAURI_DIRECTORY = join(PROJECT_DIRECTORY, 'src-tauri')
const APP_BUNDLE_NAME = '统一登录桌面端.app'
const BROWSER_DRIVER_SOURCE = join(HERE, 'browser-opener-interceptor.c')
const WEBVIEW_DRIVER_SOURCE = join(HERE, 'macos-webview-driver.m')
const APPLICATION_LAUNCHER_SOURCE =
  join(HERE, 'macos-application-launcher.m')
const AUTH_ISSUER = ACCEPTANCE_AUTH_ISSUER
const AUTH_HEALTH_BASE = 'http://127.0.0.1:9000'
const DEMO_WEB_A_BASE = 'http://localhost:5173'
const DEMO_WEB_A_HEALTH_BASE = 'http://127.0.0.1:5173'
const VITE_EXECUTABLE = join(
  DEMO_WEB_A_DIRECTORY,
  'node_modules',
  'vite',
  'bin',
  'vite.js',
)
const PASSWORD = 'a valid password'
const CLIENT_ID = 'demo-desktop'
const CREDENTIAL_ACCOUNT = credentialAccount(
  'refresh-token',
  AUTH_ISSUER,
  CLIENT_ID,
)
const ACCEPTANCE_SERVICE = acceptanceCredentialService(
  process.pid,
  randomUUID(),
)

if (process.platform !== 'darwin') {
  throw new Error('桌面生产产物验收必须在 macOS 上运行')
}

const temporaryDirectory = await mkdtemp(
  join(tmpdir(), 'unified-login-desktop-acceptance-'),
)
const browserDriverLibrary = join(
  temporaryDirectory,
  'browser-opener-interceptor.dylib',
)
const webviewDriverLibrary = join(
  temporaryDirectory,
  'macos-webview-driver.dylib',
)
const applicationLauncher = join(
  temporaryDirectory,
  'macos-application-launcher',
)
const browserUrlFile = join(temporaryDirectory, 'authorization-url')
const processSupervisor = createProcessSupervisor()
let authServer
let demoWebA
let headlessBrowser
let cleanupPromise

installSignalCleanup()

try {
  await assertLocalhostPortAvailable(9000)
  await assertLocalhostPortAvailable(5173)

  const productionTarget = await currentRustHostTarget()
  report('编译位于生产包之外的浏览器地址捕获器与隐藏 WebView 探针')
  await compileExternalDrivers(productionTarget)

  report('从当前源码构建最终生产 release 应用')
  await run(
    'pnpm',
    [
      'tauri',
      'build',
      '--target',
      productionTarget,
      '--bundles',
      'app',
    ],
    '最终生产 release 应用构建失败',
  )
  const artifact = await productionArtifact(productionTarget)
  await assertNoEmbeddedDriver(artifact)

  report('从当前分支构建认证中心并准备真实 Demo Web A')
  await run(
    './mvnw',
    ['-DskipTests', 'clean', 'package'],
    '认证中心生产包构建失败',
    AUTH_SERVER_DIRECTORY,
  )
  await prepareWorkspace(run, DEMO_WEB_A_DIRECTORY, 'Demo Web A')

  report('后台启动本轮认证中心与真实 Demo Web A')
  authServer = startAuthServer()
  await waitForService(
    `${AUTH_HEALTH_BASE}/.well-known/openid-configuration`,
    authServer,
    9000,
    '本轮认证中心没有在 9000 端口就绪',
    60_000,
  )
  demoWebA = startDemoWebA()
  await waitForService(
    DEMO_WEB_A_HEALTH_BASE,
    demoWebA,
    5173,
    '本轮 Demo Web A 没有在 5173 端口就绪',
    30_000,
  )

  report('最终生产应用隐藏完成伪造回调、首次登录与网页到桌面 SSO')
  await withProductionApp(artifact, loginAndSso)

  report('最终生产应用隐藏重启后从系统凭据库恢复并写回轮换凭据')
  await withProductionApp(artifact, restoreRotatedCredential)

  report('最终生产应用第二次隐藏重启后用轮换凭据再次恢复，再完成登出')
  await withProductionApp(artifact, restoreAndLogout)

  report('最终生产应用隐藏再次重启后保持需要登录')
  await withProductionApp(artifact, remainsLoggedOut)

  report('最终生产桌面端静默真实验收全部通过')
} finally {
  await cleanup()
}

async function productionArtifact(productionTarget) {
  const metadata = await processSupervisor.capture(
    'cargo',
    ['metadata', '--format-version', '1', '--no-deps'],
    {
      cwd: TAURI_DIRECTORY,
      env: process.env,
    },
  )
  if (metadata.code !== 0) {
    throw new Error('无法从 Cargo metadata 取得本轮构建目标目录')
  }
  const artifact = await realpath(
    macosProductionArtifact(
      metadata.stdout,
      APP_BUNDLE_NAME,
      productionTarget,
    ),
  )
  await access(applicationBinary(artifact))
  return artifact
}

async function currentRustHostTarget() {
  const version = await processSupervisor.capture(
    'rustc',
    ['-vV'],
    {
      cwd: TAURI_DIRECTORY,
      env: process.env,
    },
  )
  if (version.code !== 0) {
    throw new Error('无法取得本机 Rust 生产目标')
  }
  return rustHostTarget(version.stdout)
}

function applicationBinary(artifact) {
  return join(artifact, 'Contents', 'MacOS', BINARY_NAME)
}

async function assertNoEmbeddedDriver(artifact) {
  const binary = await readFile(applicationBinary(artifact))
  if (binary.includes(Buffer.from('wdio-webdriver'))) {
    throw new Error('最终生产产物包含不应随产品发布的嵌入式 WebDriver')
  }
}

async function compileExternalDrivers(productionTarget) {
  await run(
    '/usr/bin/xcrun',
    browserDriverCompilerArguments({
      output: browserDriverLibrary,
      productionTarget,
      source: BROWSER_DRIVER_SOURCE,
    }),
    '系统浏览器地址捕获器编译失败',
  )
  await run(
    '/usr/bin/xcrun',
    webviewDriverCompilerArguments({
      output: webviewDriverLibrary,
      productionTarget,
      source: WEBVIEW_DRIVER_SOURCE,
    }),
    '隐藏 WebView 测试探针编译失败',
  )
  await run(
    '/usr/bin/xcrun',
    [
      'clang',
      '-fobjc-arc',
      '-Wall',
      '-Werror',
      APPLICATION_LAUNCHER_SOURCE,
      '-framework',
      'AppKit',
      '-framework',
      'Foundation',
      '-o',
      applicationLauncher,
    ],
    'LaunchServices 精确进程启动器编译失败',
  )
}

function startAuthServer() {
  return processSupervisor.start(
    javaExecutable(process.env),
    ['-jar', 'target/auth-server.jar'],
    {
      cwd: AUTH_SERVER_DIRECTORY,
      env: authServerEnvironment(
        process.env,
        acceptanceAuthServerOverrides(temporaryDirectory),
      ),
      stdio: 'ignore',
    },
  )
}

function startDemoWebA() {
  return processSupervisor.start(
    process.execPath,
    [
      VITE_EXECUTABLE,
      'preview',
      '--host',
      '127.0.0.1',
      '--port',
      '5173',
      '--strictPort',
    ],
    {
      cwd: DEMO_WEB_A_DIRECTORY,
      env: process.env,
      stdio: 'ignore',
    },
  )
}

async function withProductionApp(artifact, scenario) {
  const driverPort = await findAvailablePort()
  await assertPortAvailable(driverPort)
  const driverToken = randomUUID().repeat(2)
  const applicationEnvironment = {
    DYLD_INSERT_LIBRARIES:
      `${browserDriverLibrary}:${webviewDriverLibrary}`,
    UNIFIED_LOGIN_BROWSER_URL_FILE: browserUrlFile,
    UNIFIED_LOGIN_CREDENTIAL_SERVICE: ACCEPTANCE_SERVICE,
    UNIFIED_LOGIN_INTERCEPT_EXECUTABLE: '/usr/bin/open',
    UNIFIED_LOGIN_WEBVIEW_DRIVER_EXECUTABLE: BINARY_NAME,
    UNIFIED_LOGIN_WEBVIEW_DRIVER_PORT: String(driverPort),
    UNIFIED_LOGIN_WEBVIEW_DRIVER_TOKEN: driverToken,
    UNIFIED_LOGIN_WINDOW_STARTUP_MODE: 'hidden',
  }
  const child = processSupervisor.start(
    applicationLauncher,
    macosApplicationLauncherArguments(artifact, applicationEnvironment),
    {
      env: productionAppEnvironment(process.env, {}),
      stdio: ['ignore', 'pipe', 'ignore'],
    },
  )
  const driver = createWebViewDriver({
    port: driverPort,
    token: driverToken,
  })
  let applicationProcessId

  try {
    applicationProcessId =
      await waitForMacosApplicationProcessId(child)
    await waitForDriver(driver, child)
    await scenario(driver)
  } finally {
    await stopProductionApp(driver, child, applicationProcessId)
  }
}

async function stopProductionApp(
  driver,
  launcher,
  applicationProcessId,
) {
  await stopMacosApplication({
    applicationProcessId,
    driver,
    isLauncherRunning: childIsRunning,
    launcher,
    stopApplicationProcess: (processId) => {
      if (processId === undefined) {
        throw new Error('清理最终生产应用时缺少精确 PID')
      }
      return processSupervisor.stopProcessId(processId)
    },
    stopLauncher: (child) => processSupervisor.stop(child),
    waitForLauncherExit: () => (
      waitUntil(
        () => !childIsRunning(launcher),
        'LaunchServices 没有在应用终止后退出',
        10_000,
      )
    ),
  })
}

function childIsRunning(child) {
  return child.exitCode === null && child.signalCode === null
}

async function loginAndSso(driver) {
  await assertKeychainEntryMissing()
  await waitForAction(driver, 'login-button')

  await clearCapturedAuthorization()
  await clickAction(driver, 'login-button')
  const forgedAttempt = await capturedAuthorization()
  const forgedCallback = callbackUrl(
    forgedAttempt,
    'forged-code',
    'forged-state',
  )
  const forgedResponse = await fetch(forgedCallback, {
    signal: AbortSignal.timeout(2_000),
  })
  assert.equal(forgedResponse.status, 400)
  await waitForAction(driver, 'retry-button')
  await assertKeychainEntryMissing()

  headlessBrowser = await chromium.launch({
    channel: 'chrome',
    headless: true,
  })
  const context = await headlessBrowser.newContext()
  const page = await context.newPage()
  const email = `desktop-${Date.now()}-${randomUUID()}@example.com`

  try {
    await page.goto(`${AUTH_ISSUER}/register`)
    await page.fill('#email', email)
    await page.fill('#password', PASSWORD)
    await page.click('button[type="submit"]')
    await playwrightExpect(page.getByTestId('login-registered')).toBeVisible()

    await clearCapturedAuthorization()
    await clickAction(driver, 'retry-button')
    await page.goto(await capturedAuthorization())
    await playwrightExpect(page).toHaveURL(
      /^http:\/\/localhost:9000\/login/,
    )
    await page.fill('#username', email)
    await page.fill('#password', PASSWORD)
    await page.click('button[type="submit"]')
    await playwrightExpect(
      page.getByText('登录成功，可关闭此页'),
    ).toBeVisible()
    await waitForAction(driver, 'logout-button')
    await assertKeychainEntryPresent()

    await clickAction(driver, 'logout-button')
    await waitForAction(driver, 'login-button')
    await assertKeychainEntryMissing()

    await context.clearCookies({ name: 'AUTH_SESSION' })
    assert.equal(
      (await context.cookies(AUTH_ISSUER))
        .some((cookie) => cookie.name === 'AUTH_SESSION'),
      false,
    )
    await page.goto(DEMO_WEB_A_BASE)
    await page.getByTestId('login-button').click()
    await playwrightExpect(page).toHaveURL(
      /^http:\/\/localhost:9000\/login/,
    )
    await page.fill('#username', email)
    await page.fill('#password', PASSWORD)
    await page.click('button[type="submit"]')
    await playwrightExpect(page.getByTestId('signed-in-user')).toHaveText(
      `已登录：${email}`,
    )
    assert.equal(
      (await context.cookies(AUTH_ISSUER))
        .some((cookie) => cookie.name === 'AUTH_SESSION'),
      true,
    )

    await clearCapturedAuthorization()
    await clickAction(driver, 'login-button')
    const loginNavigations = []
    const navigationListener = (frame) => {
      if (
        frame === page.mainFrame()
        && /^http:\/\/localhost:9000\/login/.test(frame.url())
      ) {
        loginNavigations.push(frame.url())
      }
    }
    page.on('framenavigated', navigationListener)
    try {
      await page.goto(await capturedAuthorization())
      await playwrightExpect(
        page.getByText('登录成功，可关闭此页'),
      ).toBeVisible()
    } finally {
      page.off('framenavigated', navigationListener)
    }
    assert.deepEqual(loginNavigations, [])
    await waitForAction(driver, 'logout-button')
    await assertKeychainEntryPresent()
  } finally {
    await context.close()
    await headlessBrowser.close()
    headlessBrowser = undefined
  }
}

async function restoreAndLogout(driver) {
  await assertKeychainEntryPresent()
  await waitForAction(driver, 'logout-button')
  await clickAction(driver, 'logout-button')
  await waitForAction(driver, 'login-button')
  await assertKeychainEntryMissing()
}

async function restoreRotatedCredential(driver) {
  await assertKeychainEntryPresent()
  await waitForAction(driver, 'logout-button')
  await assertKeychainEntryPresent()
}

async function remainsLoggedOut(driver) {
  await assertKeychainEntryMissing()
  await waitForAction(driver, 'login-button')
}

async function waitForDriver(driver, child) {
  await waitUntil(async () => {
    assertChildIsRunning(child)
    try {
      return (
        await driver.evaluate(
          "document.getElementById('page-title')?.textContent ?? null",
        ) === '桌面端安全登录'
      )
    } catch {
      return false
    }
  }, '进程外探针没有连接到最终生产应用的隐藏 WebView', 30_000)
}

async function waitForAction(driver, id) {
  await waitUntil(
    () => driver.evaluate(interactiveActionScript(id)),
    `最终生产应用没有显示可操作按钮: ${id}`,
    20_000,
  )
}

async function clickAction(driver, id) {
  const clicked = await driver.evaluate(activateActionScript(id))
  assert.equal(clicked, true, `最终生产应用按钮不可点击: ${id}`)
}

async function clearCapturedAuthorization() {
  await rm(browserUrlFile, { force: true })
}

async function capturedAuthorization() {
  const deadline = Date.now() + 20_000
  while (Date.now() < deadline) {
    try {
      const value = await readFile(browserUrlFile, 'utf8')
      const url = new URL(value)
      if (
        url.origin === AUTH_ISSUER
        && url.pathname === '/oauth2/authorize'
        && url.searchParams.get('client_id') === CLIENT_ID
      ) {
        return url.toString()
      }
    } catch (error) {
      if (
        !(
          error instanceof Error
          && 'code' in error
          && error.code === 'ENOENT'
        )
        && !(error instanceof TypeError)
      ) {
        throw error
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  throw new Error('最终生产应用没有调起系统浏览器授权地址')
}

function callbackUrl(authorization, code, state) {
  const redirectUri = new URL(authorization).searchParams.get('redirect_uri')
  if (redirectUri === null) {
    throw new Error('桌面授权地址缺少回环回调')
  }
  const callback = new URL(redirectUri)
  callback.searchParams.set('code', code)
  callback.searchParams.set('state', state)
  return callback.toString()
}

async function assertKeychainEntryPresent() {
  assert.equal(
    await keychainEntryStatus(),
    0,
    '系统凭据库缺少 refresh token',
  )
}

async function assertKeychainEntryMissing() {
  assert.equal(
    await keychainEntryStatus(),
    44,
    '系统凭据库仍残留 refresh token',
  )
}

async function keychainEntryStatus() {
  const result = await processSupervisor.capture(
    '/usr/bin/security',
    [
      'find-generic-password',
      '-s',
      ACCEPTANCE_SERVICE,
      '-a',
      CREDENTIAL_ACCOUNT,
    ],
  )
  return result.code
}

async function waitForService(
  url,
  child,
  port,
  failureMessage,
  timeout,
) {
  await waitUntil(async () => {
    assertChildIsRunning(child, `${failureMessage}：进程已经退出`)
    return (
      await responseIsOkWithin(url, 500)
      && await processSupervisor.childOwnsPort(child, port)
    )
  }, failureMessage, timeout)
}

function assertChildIsRunning(child, message = '最终生产应用意外退出') {
  if (!childIsRunning(child)) {
    throw new Error(message)
  }
}

async function waitUntil(predicate, failureMessage, timeout) {
  const deadline = Date.now() + timeout
  while (Date.now() < deadline) {
    if (await predicate()) {
      return
    }
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  throw new Error(failureMessage)
}

async function deleteCredential() {
  const result = await processSupervisor.capture(
    '/usr/bin/security',
    [
      'delete-generic-password',
      '-s',
      ACCEPTANCE_SERVICE,
      '-a',
      CREDENTIAL_ACCOUNT,
    ],
  )
  if (![0, 44].includes(result.code ?? -1)) {
    throw new Error('无法清理桌面验收凭据')
  }
}

async function run(
  executable,
  arguments_,
  failureMessage,
  cwd = PROJECT_DIRECTORY,
) {
  const result = await processSupervisor.run(executable, arguments_, {
    cwd,
    env: {
      ...process.env,
      PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD: '1',
    },
    stdio: 'inherit',
  })
  if (result.code !== 0) {
    throw new Error(failureMessage)
  }
}

function installSignalCleanup() {
  for (const { exitCode, signal } of acceptanceSignalConfigurations()) {
    process.once(signal, () => {
      cleanup()
        .catch(() => {
          process.stderr.write('桌面验收：中断清理未能完整完成\n')
        })
        .finally(() => {
          process.exit(exitCode)
        })
    })
  }
}

async function cleanup() {
  cleanupPromise ??= cleanupResources()
  return cleanupPromise
}

async function cleanupResources() {
  const failures = []
  await captureCleanupFailure(
    () => headlessBrowser?.close(),
    failures,
  )
  headlessBrowser = undefined
  await captureCleanupFailure(
    () => processSupervisor.stop(demoWebA),
    failures,
  )
  demoWebA = undefined
  await captureCleanupFailure(
    () => processSupervisor.stop(authServer),
    failures,
  )
  authServer = undefined
  await captureCleanupFailure(() => processSupervisor.stopAll(), failures)
  await captureCleanupFailure(() => deleteCredential(), failures)
  await captureCleanupFailure(
    () => rm(temporaryDirectory, { recursive: true, force: true }),
    failures,
  )
  if (failures.length > 0) {
    throw new AggregateError(failures, '桌面验收资源清理失败')
  }
}

async function captureCleanupFailure(action, failures) {
  try {
    await action()
  } catch (error) {
    failures.push(error)
  }
}

function report(message) {
  process.stdout.write(`桌面验收：${message}\n`)
}

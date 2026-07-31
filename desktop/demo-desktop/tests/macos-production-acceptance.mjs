import {
  access,
  lstat,
  readFile,
  readdir,
  realpath,
} from 'node:fs/promises'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

import {
  containsPlaintextSecret,
  loopbackPortFromLsof,
  parseBrowserProbe,
  validateBrowserLoginUrl,
} from './acceptance-helpers.mjs'

const BUNDLE_ID = 'com.aventador.unified-login.demo-desktop'
const BINARY_NAME = 'demo-desktop'
const KEYCHAIN_SERVICE = BUNDLE_ID
const KEYCHAIN_ACCOUNT = 'refresh-token'
const AUTH_BASE = 'http://localhost:9000'
const TEST_PASSWORD = 'a valid password'
const HERE = dirname(fileURLToPath(import.meta.url))
const PROJECT_DIRECTORY = dirname(HERE)
const DEFAULT_APP = join(
  PROJECT_DIRECTORY,
  'src-tauri',
  'target',
  'release',
  'bundle',
  'macos',
  '统一登录桌面端.app',
)
const APP_DRIVER = join(HERE, 'app-driver.applescript')
const BROWSER_DRIVER = join(HERE, 'browser-driver.applescript')

if (process.platform !== 'darwin') {
  throw new Error('真实桌面验收必须在 macOS 生产构建上运行')
}

const artifact = await realpath(process.env.DESKTOP_APP_PATH ?? DEFAULT_APP)
await assertProductionArtifact(artifact)
await waitForAuthServer()

const email = `desktop-${Date.now()}-${crypto.randomUUID()}@example.com`
let appPid
let systemBrowserBundleId

try {
  report('准备独立账号并清空系统凭据库')
  await registerUser(email, TEST_PASSWORD)
  deleteKeychainEntry()
  terminateRunningArtifact()

  report('场景 4/5：伪造 state 回调必须被拒绝')
  launchArtifact(artifact)
  await waitForAppButton('使用系统浏览器登录')
  appPid = desktopPid()
  clickAppButton('使用系统浏览器登录')
  await waitForBrowserLoginPage()
  const forgedPort = await waitForLoopbackPort(appPid)
  const forgedResponse = await fetch(
    `http://127.0.0.1:${forgedPort}/callback?code=forged-code&state=forged-state`,
  )
  if (forgedResponse.status !== 400) {
    throw new Error('伪造 state 回调没有被回环服务明确拒绝')
  }
  await waitForAppButton('重试')
  clickAppButton('重试')
  await waitForAppButton('使用系统浏览器登录')

  report('场景 1/5：全新安装从系统默认浏览器完成首次登录')
  clickAppButton('使用系统浏览器登录')
  await waitForBrowserLoginPage()
  fillSystemBrowserLogin(email, TEST_PASSWORD)
  await waitForAppButton('退出登录')
  const firstSecret = readKeychainSecret()
  try {
    await assertSecretAbsentFromApplicationFiles(firstSecret)
  } finally {
    firstSecret.fill(0)
  }

  report('场景 2/5：浏览器已有会话时不输入任何字符直接完成 SSO')
  clickAppButton('退出登录')
  await waitForAppButton('使用系统浏览器登录')
  clickAppButton('使用系统浏览器登录')
  await waitForAppButton('退出登录', 12_000)
  assertKeychainEntryPresent()

  report('场景 3/5：关闭生产应用再打开后从凭据库恢复登录态')
  terminatePid(appPid)
  await waitForProcessExit()
  launchArtifact(artifact)
  await waitForAppButton('退出登录')
  appPid = desktopPid()

  report('场景 5/5：登出删除凭据，重启后保持未登录')
  clickAppButton('退出登录')
  await waitForAppButton('使用系统浏览器登录')
  assertKeychainEntryMissing()
  terminatePid(appPid)
  await waitForProcessExit()
  launchArtifact(artifact)
  await waitForAppButton('使用系统浏览器登录')
  assertKeychainEntryMissing()

  report('真实生产应用 5 个场景全部通过')
} finally {
  terminateRunningArtifact()
  deleteKeychainEntry()
}

async function assertProductionArtifact(appPath) {
  const expectedSegment = join('target', 'release', 'bundle', 'macos')
  if (!appPath.includes(expectedSegment) || !appPath.endsWith('.app')) {
    throw new Error('验收入口必须是 Tauri release bundle 产出的 .app')
  }
  await access(join(appPath, 'Contents', 'MacOS', BINARY_NAME))
}

async function registerUser(emailAddress, password) {
  const registrationPage = await fetch(`${AUTH_BASE}/register`, {
    redirect: 'manual',
  })
  if (!registrationPage.ok) {
    throw new Error('无法打开注册页准备桌面验收账号')
  }
  const cookies = cookiesFrom(registrationPage)
  const html = await registrationPage.text()
  const csrf = csrfTokenFrom(html)
  const response = await fetch(`${AUTH_BASE}/register`, {
    method: 'POST',
    redirect: 'manual',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Cookie: cookies,
    },
    body: new URLSearchParams({
      email: emailAddress,
      password,
      _csrf: csrf,
    }),
  })
  if (response.status !== 302) {
    throw new Error('桌面验收账号注册失败')
  }
  const location = response.headers.get('location') ?? ''
  if (!location.includes('/login?registered')) {
    throw new Error('桌面验收账号没有进入注册成功状态')
  }
}

function csrfTokenFrom(html) {
  const match = /name="_csrf"[^>]*value="([^"]+)"/.exec(html)
  if (match?.[1] === undefined) {
    throw new Error('注册页缺少 CSRF 令牌')
  }
  return match[1]
}

function cookiesFrom(response) {
  const values = response.headers.getSetCookie()
  if (values.length === 0) {
    throw new Error('注册页没有建立服务端会话')
  }
  return values.map((value) => value.split(';', 1)[0]).join('; ')
}

function launchArtifact(appPath) {
  run('/usr/bin/open', ['-n', appPath], '无法启动生产桌面应用')
}

function terminateRunningArtifact() {
  const result = spawnSync('/usr/bin/pkill', ['-x', BINARY_NAME], {
    stdio: 'ignore',
  })
  if (![0, 1].includes(result.status ?? -1)) {
    throw new Error('无法清理桌面验收进程')
  }
}

function terminatePid(pid) {
  try {
    process.kill(pid, 'SIGTERM')
  } catch (error) {
    if (error?.code !== 'ESRCH') {
      throw new Error('无法关闭桌面验收进程')
    }
  }
}

function desktopPid() {
  const value = runAppleScript(APP_DRIVER, [BUNDLE_ID, 'pid'])
  const pid = Number(value)
  if (!Number.isInteger(pid) || pid <= 0) {
    throw new Error('无法识别生产桌面应用进程')
  }
  return pid
}

function clickAppButton(name) {
  runAppleScript(APP_DRIVER, [BUNDLE_ID, 'click-button', name])
}

async function waitForAppButton(name, timeout = 30_000) {
  await waitUntil(
    () =>
      tryAppleScript(APP_DRIVER, [BUNDLE_ID, 'button-exists', name]) ===
      'true',
    `桌面应用没有显示“${name}”`,
    timeout,
  )
}

function currentSystemBrowser() {
  const value = tryAppleScript(BROWSER_DRIVER, ['current-url'])
  if (value === undefined) {
    return undefined
  }
  try {
    return parseBrowserProbe(value)
  } catch {
    return undefined
  }
}

async function waitForBrowserLoginPage() {
  await waitUntil(() => {
    const browser = currentSystemBrowser()
    if (browser === undefined) {
      return false
    }
    try {
      validateBrowserLoginUrl(browser.url)
      systemBrowserBundleId = browser.bundleId
      return true
    } catch {
      return false
    }
  }, '系统默认浏览器没有打开认证中心登录页')
}

function fillSystemBrowserLogin(emailAddress, password) {
  if (systemBrowserBundleId === undefined) {
    throw new Error('尚未识别系统默认浏览器')
  }
  runAppleScript(BROWSER_DRIVER, [
    'fill-login',
    systemBrowserBundleId,
    emailAddress,
    password,
  ])
}

async function waitForLoopbackPort(pid) {
  let port
  await waitUntil(() => {
    const result = spawnSync(
      '/usr/sbin/lsof',
      ['-a', '-p', String(pid), '-nP', '-iTCP', '-sTCP:LISTEN', '-Fn'],
      { encoding: 'utf8' },
    )
    if (result.status !== 0) {
      return false
    }
    try {
      port = loopbackPortFromLsof(result.stdout)
      return true
    } catch {
      return false
    }
  }, '登录流程没有建立唯一的 IPv4 回环监听端口')
  return port
}

function readKeychainSecret() {
  const result = spawnSync(
    '/usr/bin/security',
    [
      'find-generic-password',
      '-s',
      KEYCHAIN_SERVICE,
      '-a',
      KEYCHAIN_ACCOUNT,
      '-w',
    ],
    { encoding: 'buffer' },
  )
  if (result.status !== 0) {
    throw new Error('系统凭据库里没有桌面端 refresh token')
  }
  const secret = trimAsciiWhitespace(result.stdout)
  if (secret.length === 0) {
    throw new Error('系统凭据库里的 refresh token 为空')
  }
  return secret
}

function assertKeychainEntryMissing() {
  const result = spawnSync(
    '/usr/bin/security',
    [
      'find-generic-password',
      '-s',
      KEYCHAIN_SERVICE,
      '-a',
      KEYCHAIN_ACCOUNT,
      '-w',
    ],
    { stdio: 'ignore' },
  )
  if (result.status !== 44) {
    throw new Error('无法证明登出后系统凭据库条目已删除')
  }
}

function assertKeychainEntryPresent() {
  const secret = readKeychainSecret()
  secret.fill(0)
}

function deleteKeychainEntry() {
  const result = spawnSync(
    '/usr/bin/security',
    [
      'delete-generic-password',
      '-s',
      KEYCHAIN_SERVICE,
      '-a',
      KEYCHAIN_ACCOUNT,
    ],
    { stdio: 'ignore' },
  )
  if (![0, 44].includes(result.status ?? -1)) {
    throw new Error('无法清理桌面验收凭据')
  }
}

function trimAsciiWhitespace(value) {
  let start = 0
  let end = value.length
  while (start < end && isAsciiWhitespace(value[start])) {
    start += 1
  }
  while (end > start && isAsciiWhitespace(value[end - 1])) {
    end -= 1
  }
  return value.subarray(start, end)
}

function isAsciiWhitespace(value) {
  return value === 9 || value === 10 || value === 13 || value === 32
}

async function assertSecretAbsentFromApplicationFiles(secret) {
  const library = join(homedir(), 'Library')
  const roots = [
    join(library, 'Application Support', BUNDLE_ID),
    join(library, 'Caches', BUNDLE_ID),
    join(library, 'Containers', BUNDLE_ID),
    join(library, 'Preferences', `${BUNDLE_ID}.plist`),
    join(library, 'Saved Application State', `${BUNDLE_ID}.savedState`),
    join(library, 'WebKit', BUNDLE_ID),
  ]
  for (const root of roots) {
    await scanPath(root, secret)
  }
}

async function scanPath(path, secret) {
  let metadata
  try {
    metadata = await lstat(path)
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return
    }
    throw new Error(`无法检查桌面应用数据路径: ${path}`)
  }
  if (metadata.isSymbolicLink()) {
    return
  }
  if (metadata.isDirectory()) {
    for (const child of await readdir(path)) {
      await scanPath(join(path, child), secret)
    }
    return
  }
  if (metadata.isFile()) {
    const content = await readFile(path)
    if (containsPlaintextSecret(content, secret)) {
      throw new Error(`refresh token 以明文写入了磁盘文件: ${path}`)
    }
  }
}

async function waitForAuthServer() {
  await waitUntil(async () => {
    try {
      const response = await fetch(
        `${AUTH_BASE}/.well-known/openid-configuration`,
        { signal: AbortSignal.timeout(500) },
      )
      return response.ok
    } catch {
      return false
    }
  }, '认证中心没有在 localhost:9000 就绪', 60_000)
}

async function waitForProcessExit() {
  await waitUntil(() => {
    const result = spawnSync('/usr/bin/pgrep', ['-x', BINARY_NAME], {
      stdio: 'ignore',
    })
    return result.status === 1
  }, '桌面应用没有在预期时间内退出')
}

async function waitUntil(predicate, failureMessage, timeout = 30_000) {
  const deadline = Date.now() + timeout
  while (Date.now() < deadline) {
    if (await predicate()) {
      return
    }
    await new Promise((resolve) => setTimeout(resolve, 100))
  }
  throw new Error(failureMessage)
}

function runAppleScript(script, arguments_) {
  return run('/usr/bin/osascript', [script, ...arguments_], 'macOS 界面自动化失败')
}

function tryAppleScript(script, arguments_) {
  const result = spawnSync('/usr/bin/osascript', [script, ...arguments_], {
    encoding: 'utf8',
  })
  return result.status === 0 ? result.stdout.trim() : undefined
}

function run(executable, arguments_, failureMessage) {
  const result = spawnSync(executable, arguments_, {
    encoding: 'utf8',
    env: process.env,
  })
  if (result.status !== 0) {
    throw new Error(failureMessage)
  }
  return result.stdout.trim()
}

function report(message) {
  process.stdout.write(`桌面验收：${message}\n`)
}

import { spawn } from 'node:child_process'
import { mkdtempSync, rmSync } from 'node:fs'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const AUTH_BASE = 'http://127.0.0.1:9001'
const MANAGER_HOST = '127.0.0.1'
const MANAGER_PORT = 19001
const START_TIMEOUT_MS = 30_000
const STOP_TIMEOUT_MS = 10_000
const POLL_INTERVAL_MS = 100

const runtimeDirectory = mkdtempSync(
  join(tmpdir(), 'unified-login-resource-auth-'),
)
const keyStore = join(runtimeDirectory, 'jwt-signing-key.json')

let authProcess = null
let operation = Promise.resolve()
let shuttingDown = false

function delay(milliseconds) {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds)
  })
}

function enqueue(task) {
  const next = operation.then(task, task)
  operation = next.catch(() => undefined)
  return next
}

function spawnAuthProcess() {
  const child = spawn(
    'java',
    [
      '-jar',
      'target/auth-server.jar',
      '--server.address=127.0.0.1',
      '--server.port=9001',
      '--spring.datasource.url=jdbc:postgresql://127.0.0.1:55432/unified_login',
      '--spring.datasource.username=unified_login',
      '--spring.datasource.password=unified_login',
      '--unified-login.issuer=http://127.0.0.1:9001',
      `--unified-login.jwt-key-store=${keyStore}`,
      '--unified-login.clients[0].client-id=demo-api',
      '--unified-login.clients[0].client-name=Demo API',
      '--unified-login.clients[0].redirect-uris[0]=http://127.0.0.1:5274/callback',
    ],
    {
      cwd: new URL('../../auth-server/', import.meta.url),
      stdio: 'inherit',
    },
  )
  child.once('exit', () => {
    if (authProcess === child) {
      authProcess = null
    }
  })
  return child
}

async function waitUntilReady(child) {
  const deadline = Date.now() + START_TIMEOUT_MS
  while (Date.now() < deadline) {
    if (authProcess !== child || child.exitCode !== null) {
      throw new Error('资源验收认证中心在就绪前退出')
    }
    try {
      const response = await fetch(
        `${AUTH_BASE}/.well-known/openid-configuration`,
        { signal: AbortSignal.timeout(500) },
      )
      if (response.ok) {
        return
      }
    }
    catch {
      // Java 进程尚未监听时继续轮询，超时后由下方统一报错。
    }
    await delay(POLL_INTERVAL_MS)
  }
  throw new Error('等待资源验收认证中心启动超时')
}

async function startAuth() {
  if (shuttingDown) {
    throw new Error('资源验收认证中心管理器正在退出')
  }
  if (authProcess !== null) {
    await waitUntilReady(authProcess)
    return
  }

  const child = spawnAuthProcess()
  authProcess = child
  const spawnError = new Promise((_, reject) => {
    child.once('error', reject)
  })
  try {
    await Promise.race([waitUntilReady(child), spawnError])
  }
  catch (error) {
    await stopAuth()
    throw error
  }
}

async function stopAuth() {
  const child = authProcess
  if (child === null) {
    return
  }
  if (child.exitCode !== null || child.signalCode !== null) {
    authProcess = null
    return
  }

  const exited = new Promise((resolve) => {
    child.once('exit', resolve)
  })
  child.kill('SIGTERM')
  let timeoutId
  const timedOut = await Promise.race([
    exited.then(() => false),
    new Promise((resolve) => {
      timeoutId = setTimeout(() => resolve(true), STOP_TIMEOUT_MS)
    }),
  ])
  clearTimeout(timeoutId)
  if (timedOut) {
    child.kill('SIGKILL')
    await exited
  }
}

function send(response, statusCode, body = '') {
  response.writeHead(statusCode, {
    'Content-Length': Buffer.byteLength(body),
    'Content-Type': 'text/plain; charset=utf-8',
  })
  response.end(body)
}

const manager = createServer((request, response) => {
  const requestUrl = new URL(
    request.url ?? '/',
    `http://${MANAGER_HOST}:${MANAGER_PORT}`,
  )
  if (request.method === 'GET' && requestUrl.pathname === '/health') {
    send(response, 200, 'ok')
    return
  }
  if (request.method === 'POST' && requestUrl.pathname === '/start') {
    void enqueue(startAuth).then(
      () => send(response, 204),
      (error) => send(response, 500, String(error)),
    )
    return
  }
  if (request.method === 'POST' && requestUrl.pathname === '/stop') {
    void enqueue(stopAuth).then(
      () => send(response, 204),
      (error) => send(response, 500, String(error)),
    )
    return
  }
  send(response, 404, 'not found')
})

async function shutdown() {
  if (shuttingDown) {
    return
  }
  shuttingDown = true
  manager.close()
  await enqueue(stopAuth)
  rmSync(runtimeDirectory, { recursive: true, force: true })
}

process.once('SIGINT', () => {
  void shutdown()
})
process.once('SIGTERM', () => {
  void shutdown()
})

try {
  await enqueue(startAuth)
  manager.listen(MANAGER_PORT, MANAGER_HOST)
}
catch (error) {
  await shutdown()
  throw error
}

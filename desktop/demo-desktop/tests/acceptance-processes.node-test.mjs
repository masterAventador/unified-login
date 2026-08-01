import assert from 'node:assert/strict'
import { createServer } from 'node:net'
import { test } from 'node:test'

import {
  assertLocalhostPortAvailable,
  assertPortAvailable,
  createProcessSupervisor,
  findAvailablePort,
} from './acceptance-processes.mjs'

test('为每轮隐藏 WebView 探针分配当前空闲的随机端口', async () => {
  const occupiedPortServer = createServer()
  await listen(occupiedPortServer, 0)
  const occupiedPort = occupiedPortServer.address().port

  try {
    const port = await findAvailablePort()

    assert.ok(Number.isInteger(port))
    assert.ok(port > 0 && port <= 65_535)
    assert.notEqual(port, occupiedPort)
    await assertPortAvailable(port)
  } finally {
    await close(occupiedPortServer)
  }
})

test('端口已经被其他服务占用时拒绝启动验收认证中心', async () => {
  const server = createServer()
  await listen(server, 0)
  const port = server.address().port

  try {
    await assert.rejects(
      assertPortAvailable(port),
      new RegExp(`${port} 端口已被占用`),
    )
  } finally {
    await close(server)
  }
})

test('localhost 的 IPv6 回环端口被占用时也拒绝启动验收服务', async () => {
  const server = createServer()
  await listenIpv6Only(server, 0)
  const port = server.address().port

  try {
    await assert.rejects(
      assertLocalhostPortAvailable(port),
      new RegExp(`${port} 端口已被占用`),
    )
  } finally {
    await close(server)
  }
})

test('停止受管进程时同时清理它留在同一进程组的子进程', async () => {
  const portProbe = createServer()
  await listen(portProbe, 0)
  const port = portProbe.address().port
  await close(portProbe)

  const supervisor = createProcessSupervisor()
  const childProgram = [
    "const { createServer } = require('node:net')",
    `createServer().listen(${port}, '127.0.0.1')`,
    'setInterval(() => {}, 1000)',
  ].join(';')
  const parentProgram = [
    "const { spawn } = require('node:child_process')",
    `spawn(process.execPath, ['-e', ${JSON.stringify(childProgram)}], { stdio: 'ignore' })`,
    'setInterval(() => {}, 1000)',
  ].join(';')
  const parent = supervisor.start(process.execPath, ['-e', parentProgram], {
    stdio: 'ignore',
  })

  try {
    await waitUntilPortIsOccupied(port)
    await supervisor.stop(parent)
    await assertPortAvailable(port)
  } finally {
    await supervisor.stopAll()
  }
})

test('捕获命令会等待继承管道的后代写完输出', async () => {
  const supervisor = createProcessSupervisor()
  const descendantProgram = [
    "setTimeout(() => process.stdout.write('late-output'), 100)",
  ].join(';')
  const parentProgram = [
    "const { spawn } = require('node:child_process')",
    `spawn(process.execPath, ['-e', ${JSON.stringify(descendantProgram)}], { stdio: ['ignore', process.stdout, 'ignore'] }).unref()`,
  ].join(';')

  try {
    const result = await supervisor.capture(
      process.execPath,
      ['-e', parentProgram],
    )

    assert.equal(result.code, 0)
    assert.equal(result.stdout, 'late-output')
  } finally {
    await supervisor.stopAll()
  }
})

test('可按本轮记录的精确 PID 清理 LaunchServices 后代进程', async () => {
  const supervisor = createProcessSupervisor()
  const target = supervisor.start(
    process.execPath,
    ['-e', 'setInterval(() => {}, 1000)'],
    { stdio: 'ignore' },
  )
  const unrelated = supervisor.start(
    process.execPath,
    ['-e', 'setInterval(() => {}, 1000)'],
    { stdio: 'ignore' },
  )

  try {
    await supervisor.stopProcessId(target.pid)
    await waitUntilChildExited(target)

    assert.ok(
      target.exitCode !== null || target.signalCode !== null,
      '目标 PID 应已退出',
    )
    assert.equal(unrelated.exitCode, null)
    assert.equal(unrelated.signalCode, null)
  } finally {
    await supervisor.stopAll()
  }
})

function listen(server, port) {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, '127.0.0.1', resolve)
  })
}

function listenIpv6Only(server, port) {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen({
      host: '::1',
      port,
      ipv6Only: true,
    }, resolve)
  })
}

function close(server) {
  return new Promise((resolve, reject) => {
    server.close((error) => {
      if (error === undefined) {
        resolve()
      } else {
        reject(error)
      }
    })
  })
}

async function waitUntilPortIsOccupied(port) {
  const deadline = Date.now() + 5_000
  while (Date.now() < deadline) {
    try {
      await assertPortAvailable(port)
    } catch {
      return
    }
    await new Promise((resolve) => setTimeout(resolve, 50))
  }
  throw new Error('子进程没有按时监听测试端口')
}

async function waitUntilChildExited(child) {
  const deadline = Date.now() + 1_000
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) {
      return
    }
    await new Promise((resolve) => setTimeout(resolve, 10))
  }
  throw new Error('按精确 PID 终止的子进程没有退出')
}

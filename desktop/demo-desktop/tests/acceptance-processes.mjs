import { spawn } from 'node:child_process'
import { createServer } from 'node:net'

const PROCESS_STOP_TIMEOUT = 10_000

export function createProcessSupervisor() {
  const activeChildren = new Set()

  function start(executable, arguments_, options = {}) {
    const child = spawn(executable, arguments_, {
      ...options,
      detached: process.platform !== 'win32',
    })
    activeChildren.add(child)
    return child
  }

  async function run(executable, arguments_, options = {}) {
    const child = start(executable, arguments_, options)
    try {
      return await waitForExit(child)
    } finally {
      await stop(child)
    }
  }

  async function capture(executable, arguments_, options = {}) {
    const child = start(executable, arguments_, {
      ...options,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    const stdout = []
    const stderr = []
    child.stdout.on('data', (chunk) => stdout.push(chunk))
    child.stderr.on('data', (chunk) => stderr.push(chunk))

    try {
      const result = await waitForClose(child)
      return {
        ...result,
        stdout: Buffer.concat(stdout).toString('utf8'),
        stderr: Buffer.concat(stderr).toString('utf8'),
      }
    } finally {
      await stop(child)
    }
  }

  async function childOwnsPort(child, port) {
    if (child.pid === undefined) {
      return false
    }
    const result = await capture(
      '/usr/sbin/lsof',
      [
        '-nP',
        '-a',
        '-p',
        String(child.pid),
        `-iTCP:${port}`,
        '-sTCP:LISTEN',
      ],
    )
    return result.code === 0 && result.stdout.trim() !== ''
  }

  async function stop(child) {
    if (child === undefined) {
      return
    }

    try {
      signalProcessGroup(child, 'SIGTERM')
      const parentExited = await waitForExitUntil(child)
      const processGroupExited = (
        parentExited
        && await waitForProcessGroupUntilGone(child)
      )
      if (!processGroupExited) {
        signalProcessGroup(child, 'SIGKILL')
        await waitForExitUntil(child)
        if (!(await waitForProcessGroupUntilGone(child))) {
          throw new Error('受管进程组在强制终止后仍未退出')
        }
      }
    } finally {
      activeChildren.delete(child)
    }
  }

  async function stopAll() {
    await Promise.all([...activeChildren].map((child) => stop(child)))
  }

  async function stopProcessId(processId) {
    if (!Number.isInteger(processId) || processId <= 1) {
      throw new Error('拒绝终止无效的进程 PID')
    }

    signalProcessId(processId, 'SIGTERM')
    if (await waitForProcessIdUntilGone(processId)) {
      return
    }
    signalProcessId(processId, 'SIGKILL')
    if (!(await waitForProcessIdUntilGone(processId))) {
      throw new Error(`PID ${processId} 在强制终止后仍未退出`)
    }
  }

  return {
    capture,
    childOwnsPort,
    run,
    start,
    stop,
    stopAll,
    stopProcessId,
  }
}

export async function assertLocalhostPortAvailable(port) {
  await assertPortAvailable(port, '127.0.0.1')
  await assertPortAvailable(port, '::1')
}

export function assertPortAvailable(port, host = '127.0.0.1') {
  const server = createServer()
  return new Promise((resolve, reject) => {
    server.once('error', (error) => {
      if (error.code === 'EADDRINUSE') {
        reject(
          new Error(`${host} 的 ${port} 端口已被占用，拒绝复用未知旧服务`),
        )
      } else {
        reject(error)
      }
    })
    server.listen(
      {
        host,
        port,
        exclusive: true,
      },
      () => {
        server.close((error) => {
          if (error === undefined) {
            resolve()
          } else {
            reject(error)
          }
        })
      },
    )
  })
}

export function findAvailablePort() {
  const server = createServer()
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(
      {
        host: '127.0.0.1',
        port: 0,
        exclusive: true,
      },
      () => {
        const address = server.address()
        if (address === null || typeof address === 'string') {
          server.close()
          reject(new Error('无法取得随机回环端口'))
          return
        }
        server.close((error) => {
          if (error === undefined) {
            resolve(address.port)
          } else {
            reject(error)
          }
        })
      },
    )
  })
}

function isRunning(child) {
  return child.exitCode === null && child.signalCode === null
}

function signalProcessGroup(child, signal) {
  if (child.pid === undefined) {
    return
  }

  try {
    if (process.platform === 'win32') {
      child.kill(signal)
    } else {
      process.kill(-child.pid, signal)
    }
  } catch (error) {
    if (error.code !== 'ESRCH') {
      throw error
    }
  }
}

function signalProcessId(processId, signal) {
  try {
    process.kill(processId, signal)
  } catch (error) {
    if (error.code !== 'ESRCH') {
      throw error
    }
  }
}

function waitForExit(child) {
  if (!isRunning(child)) {
    return Promise.resolve({
      code: child.exitCode,
      signal: child.signalCode,
    })
  }

  return new Promise((resolve, reject) => {
    child.once('error', reject)
    child.once('exit', (code, signal) => resolve({ code, signal }))
  })
}

function waitForClose(child) {
  return new Promise((resolve, reject) => {
    child.once('error', reject)
    child.once('close', (code, signal) => resolve({ code, signal }))
  })
}

async function waitForExitUntil(child) {
  if (!isRunning(child)) {
    return true
  }

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => resolve(false), PROCESS_STOP_TIMEOUT)
    waitForExit(child).then(
      () => {
        clearTimeout(timeout)
        resolve(true)
      },
      (error) => {
        clearTimeout(timeout)
        reject(error)
      },
    )
  })
}

async function waitForProcessGroupUntilGone(child) {
  if (process.platform === 'win32' || child.pid === undefined) {
    return !isRunning(child)
  }

  const deadline = Date.now() + PROCESS_STOP_TIMEOUT
  while (Date.now() < deadline) {
    if (!processGroupExists(child.pid)) {
      return true
    }
    await new Promise((resolve) => setTimeout(resolve, 20))
  }
  return !processGroupExists(child.pid)
}

async function waitForProcessIdUntilGone(processId) {
  const deadline = Date.now() + PROCESS_STOP_TIMEOUT
  while (Date.now() < deadline) {
    if (!processIdExists(processId)) {
      return true
    }
    await new Promise((resolve) => setTimeout(resolve, 20))
  }
  return !processIdExists(processId)
}

function processGroupExists(processGroupId) {
  try {
    process.kill(-processGroupId, 0)
    return true
  } catch (error) {
    if (error.code === 'ESRCH') {
      return false
    }
    if (error.code === 'EPERM') {
      return true
    }
    throw error
  }
}

function processIdExists(processId) {
  try {
    process.kill(processId, 0)
    return true
  } catch (error) {
    if (error.code === 'ESRCH') {
      return false
    }
    if (error.code === 'EPERM') {
      return true
    }
    throw error
  }
}

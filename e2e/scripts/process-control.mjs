import { spawn } from 'node:child_process'

function isRunning(child) {
  return child.exitCode === null && child.signalCode === null
}

function waitForExit(child) {
  if (!isRunning(child)) {
    return Promise.resolve(child.exitCode)
  }
  return new Promise((resolve, reject) => {
    child.once('error', reject)
    child.once('exit', (code) => resolve(code))
  })
}

export async function stopChildProcess(
  child,
  {
    platform = process.platform,
    spawnProcess = spawn,
    timeoutMs = 10_000,
  } = {},
) {
  if (!isRunning(child)) {
    return
  }

  if (platform === 'win32') {
    if (child.pid === undefined) {
      throw new Error('无法终止没有 pid 的 Windows 子进程')
    }
    const taskkill = spawnProcess(
      'taskkill.exe',
      ['/pid', String(child.pid), '/T', '/F'],
      { stdio: 'ignore', windowsHide: true },
    )
    const exitCode = await waitForExit(taskkill)
    if (exitCode !== 0 && isRunning(child)) {
      throw new Error(`taskkill 终止子进程失败，退出码 ${exitCode}`)
    }
    return
  }

  const exited = waitForExit(child)
  child.kill('SIGTERM')
  let timeoutId
  const timedOut = await Promise.race([
    exited.then(() => false),
    new Promise((resolve) => {
      timeoutId = setTimeout(() => resolve(true), timeoutMs)
    }),
  ])
  clearTimeout(timeoutId)
  if (timedOut && isRunning(child)) {
    child.kill('SIGKILL')
    await exited
  }
}

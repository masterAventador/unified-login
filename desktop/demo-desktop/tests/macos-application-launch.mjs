import { readFile } from 'node:fs/promises'
import { isAbsolute } from 'node:path'

const ENVIRONMENT_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/

export function macosApplicationLauncherArguments(artifact, environment) {
  if (!isAbsolute(artifact) || !artifact.endsWith('.app')) {
    throw new Error('LaunchServices 目标必须是绝对 app bundle 路径')
  }

  const arguments_ = [artifact]
  for (const [name, value] of Object.entries(environment)) {
    if (!ENVIRONMENT_NAME_PATTERN.test(name)) {
      throw new Error(`LaunchServices 环境变量名无效: ${name}`)
    }
    if (typeof value !== 'string' || value.includes('\0')) {
      throw new Error(`LaunchServices 环境变量值无效: ${name}`)
    }
    arguments_.push(`${name}=${value}`)
  }
  return arguments_
}

export function waitForMacosApplicationProcessId(
  launcher,
  timeout = 30_000,
  {
    clearTimer = clearTimeout,
    setTimer = setTimeout,
  } = {},
) {
  if (launcher.stdout === null) {
    throw new Error('LaunchServices 启动器没有 PID 输出管道')
  }

  return new Promise((resolve, reject) => {
    let output = ''
    const timer = setTimer(
      () => finish(new Error('LaunchServices 启动器没有返回应用 PID')),
      timeout,
    )
    const onData = (chunk) => {
      output += chunk
      const newline = output.indexOf('\n')
      if (newline === -1) {
        return
      }
      const processId = Number(output.slice(0, newline))
      if (!Number.isInteger(processId) || processId <= 1) {
        finish(new Error('LaunchServices 启动器返回了无效应用 PID'))
        return
      }
      finish(undefined, processId)
    }
    const onError = (error) => finish(error)
    const onExit = () => {
      finish(new Error('LaunchServices 启动器在返回应用 PID 前退出'))
    }
    const finish = (error, processId) => {
      clearTimer(timer)
      launcher.stdout.off('data', onData)
      launcher.off('error', onError)
      launcher.off('exit', onExit)
      if (error === undefined) {
        resolve(processId)
      } else {
        reject(error)
      }
    }

    launcher.stdout.on('data', onData)
    launcher.once('error', onError)
    launcher.once('exit', onExit)
  })
}

export async function waitForFile(
  path,
  message,
  {
    now = Date.now,
    pollInterval = 10,
    read = (candidate) => readFile(candidate, 'utf8'),
    sleep = (duration) => (
      new Promise((resolve) => setTimeout(resolve, duration))
    ),
    timeout = 30_000,
  } = {},
) {
  const deadline = now() + timeout
  while (now() < deadline) {
    try {
      return await read(path)
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        throw error
      }
    }
    await sleep(pollInterval)
  }
  throw new Error(message)
}

export async function stopMacosLauncher(launcher, timeout = 10_000) {
  if (launcher === undefined || !childIsRunning(launcher)) {
    return
  }

  launcher.kill('SIGTERM')
  await new Promise((resolve, reject) => {
    const timer = setTimeout(
      () => reject(new Error('等待 LaunchServices 启动器终止超时')),
      timeout,
    )
    const finish = (action, value) => {
      clearTimeout(timer)
      launcher.off('error', onError)
      launcher.off('exit', onExit)
      action(value)
    }
    const onError = (error) => finish(reject, error)
    const onExit = () => finish(resolve)

    launcher.once('error', onError)
    launcher.once('exit', onExit)
  })
}

export async function stopMacosApplication({
  applicationProcessId,
  driver,
  isLauncherRunning,
  launcher,
  stopApplicationProcess,
  stopLauncher,
  waitForLauncherExit,
}) {
  try {
    if (!isLauncherRunning(launcher)) {
      await stopApplicationProcess(applicationProcessId)
      return
    }

    let driverFailed = false
    try {
      await driver.terminate()
    } catch {
      driverFailed = true
    }
    if (driverFailed) {
      await stopApplicationProcess(applicationProcessId)
    }

    try {
      await waitForLauncherExit()
    } catch {
      await stopApplicationProcess(applicationProcessId)
      await waitForLauncherExit()
    }
  } finally {
    await stopLauncher(launcher)
  }
}

function childIsRunning(child) {
  return child.exitCode === null && child.signalCode === null
}

import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import test from 'node:test'

import { stopChildProcess } from './process-control.mjs'

function runningChild(pid = 4242) {
  const child = new EventEmitter()
  child.pid = pid
  child.exitCode = null
  child.signalCode = null
  child.killCalls = []
  child.kill = (signal) => {
    child.killCalls.push(signal)
    return true
  }
  return child
}

test('Windows 使用 taskkill 终止整个认证中心进程树', async () => {
  const child = runningChild()
  const spawnCalls = []

  await stopChildProcess(child, {
    platform: 'win32',
    spawnProcess(command, args, options) {
      spawnCalls.push({ command, args, options })
      const taskkill = new EventEmitter()
      taskkill.exitCode = null
      taskkill.signalCode = null
      queueMicrotask(() => {
        taskkill.exitCode = 0
        taskkill.emit('exit', 0, null)
      })
      return taskkill
    },
  })

  assert.deepEqual(spawnCalls, [
    {
      command: 'taskkill.exe',
      args: ['/pid', '4242', '/T', '/F'],
      options: { stdio: 'ignore', windowsHide: true },
    },
  ])
  assert.deepEqual(child.killCalls, [])
})

test('非 Windows 平台先发送 SIGTERM 并等待子进程退出', async () => {
  const child = runningChild()
  child.kill = (signal) => {
    child.killCalls.push(signal)
    queueMicrotask(() => {
      child.signalCode = signal
      child.emit('exit', null, signal)
    })
    return true
  }

  await stopChildProcess(child, {
    platform: 'darwin',
    timeoutMs: 50,
  })

  assert.deepEqual(child.killCalls, ['SIGTERM'])
})

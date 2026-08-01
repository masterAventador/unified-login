import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'

import { createDemoApiProcessPlan } from './demo-api-process.mjs'

const demoApiDirectory = fileURLToPath(
  new URL('../../demo/demo-api/', import.meta.url),
)
const plan = createDemoApiProcessPlan({
  environment: process.env,
})

for (const [index, step] of plan.entries()) {
  const exitCode = await run(step)
  if (exitCode !== 0 || index === plan.length - 1) {
    process.exitCode = exitCode
    break
  }
}

function run(step) {
  return new Promise((resolve, reject) => {
    const child = spawn(step.command, step.arguments, {
      cwd: demoApiDirectory,
      env: step.environment,
      stdio: 'inherit',
      windowsHide: true,
    })
    child.once('error', reject)
    child.once('exit', (code, signal) => {
      if (signal !== null) {
        resolve(1)
        return
      }
      resolve(code ?? 1)
    })
  })
}

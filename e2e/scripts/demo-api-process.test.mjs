import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

import { createDemoApiProcessPlan } from './demo-api-process.mjs'

describe('Demo API 验收进程', () => {
  it('依赖同步保留代理，API 进程才清除代理', () => {
    const environment = {
      ALL_PROXY: 'socks5://127.0.0.1:1080',
      http_proxy: 'http://127.0.0.1:1080',
      KEEP_ME: 'value',
    }

    const [sync, serve] = createDemoApiProcessPlan({
      environment,
    })

    assert.deepEqual(sync, {
      command: 'uv',
      arguments: ['sync', '--locked'],
      environment,
    })
    assert.equal(serve.environment.ALL_PROXY, '')
    assert.equal(serve.environment.http_proxy, '')
    assert.equal(serve.environment.KEEP_ME, 'value')
    assert.equal(serve.environment.NO_PROXY, 'localhost,127.0.0.1')
    assert.equal(serve.environment.no_proxy, 'localhost,127.0.0.1')
  })

  it('从 uv 刚同步的同一项目环境启动', () => {
    const [, serve] = createDemoApiProcessPlan({
      environment: {
        UV_PROJECT_ENVIRONMENT: '/custom/project-environment',
      },
    })

    assert.equal(serve.command, 'uv')
    assert.deepEqual(serve.arguments.slice(0, 3), [
      'run',
      '--locked',
      '--no-sync',
    ])
    assert.equal(
      serve.environment.UV_PROJECT_ENVIRONMENT,
      '/custom/project-environment',
    )
  })
})

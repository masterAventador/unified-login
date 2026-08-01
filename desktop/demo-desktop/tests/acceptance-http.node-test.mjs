import assert from 'node:assert/strict'
import { test } from 'node:test'

import { responseIsOkWithin } from './acceptance-http.mjs'

test('服务就绪探测会中断单次无响应请求', async () => {
  const startedAt = Date.now()
  const neverResponds = (_url, options) => new Promise((_, reject) => {
    options.signal.addEventListener(
      'abort',
      () => reject(options.signal.reason),
      { once: true },
    )
  })

  assert.equal(
    await responseIsOkWithin(
      'http://127.0.0.1:9000/health',
      50,
      neverResponds,
    ),
    false,
  )
  assert.ok(Date.now() - startedAt < 1_000)
})

test('服务就绪探测只接受成功响应', async () => {
  const response = (ok) => async () => ({ ok })

  assert.equal(
    await responseIsOkWithin(
      'http://example.invalid',
      50,
      response(true),
    ),
    true,
  )
  assert.equal(
    await responseIsOkWithin(
      'http://example.invalid',
      50,
      response(false),
    ),
    false,
  )
})

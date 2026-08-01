import assert from 'node:assert/strict'
import { join } from 'node:path'
import { test } from 'node:test'

import {
  acceptanceAuthServerOverrides,
} from './acceptance-auth-server.mjs'

test('受管认证中心把 JWT 签名密钥限制在本轮临时目录', () => {
  const temporaryDirectory = join('test-fixtures', 'desktop-acceptance')
  assert.deepEqual(
    acceptanceAuthServerOverrides(temporaryDirectory),
    {
      DB_URL: 'jdbc:postgresql://127.0.0.1:55432/unified_login',
      DB_USERNAME: 'unified_login',
      DB_PASSWORD: 'unified_login',
      SERVER_ADDRESS: '127.0.0.1',
      SERVER_PORT: '9000',
      ISSUER_URL: 'http://localhost:9000',
      JWT_KEY_STORE: join(temporaryDirectory, 'jwt-signing-key.json'),
    },
  )
})

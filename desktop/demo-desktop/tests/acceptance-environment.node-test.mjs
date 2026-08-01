import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  acceptanceCredentialService,
  acceptanceSignalConfigurations,
  authServerEnvironment,
  credentialAccount,
  productionAppEnvironment,
} from './acceptance-environment.mjs'

test('相同 PID 的每轮验收仍使用相互隔离的钥匙串 service', () => {
  const first = acceptanceCredentialService(42_001, 'first-run')
  const second = acceptanceCredentialService(42_001, 'second-run')

  assert.equal(
    first,
    'com.aventador.unified-login.acceptance.42001.first-run',
  )
  assert.equal(
    second,
    'com.aventador.unified-login.acceptance.42001.second-run',
  )
  assert.notEqual(first, second)
})

test('验收脚本与 Rust 应用使用同一 issuer 和 client 凭据账号', () => {
  assert.equal(
    credentialAccount(
      'refresh-token',
      'http://localhost:9000',
      'demo-desktop',
    ),
    'refresh-token:WIQfe4OExQeL_wrKK52Bq0zoALxUBWsX0qYCKjX5gJY',
  )
  assert.equal(
    credentialAccount(
      'refresh-token',
      'http://localhost:9000/',
      'demo-desktop',
    ),
    'refresh-token:WIQfe4OExQeL_wrKK52Bq0zoALxUBWsX0qYCKjX5gJY',
  )
  assert.notEqual(
    credentialAccount(
      'refresh-token',
      'http://localhost:9001',
      'demo-desktop',
    ),
    credentialAccount(
      'refresh-token',
      'http://localhost:9000',
      'demo-desktop',
    ),
  )
})

test('终端关闭、交互中断和终止信号均先清理再返回标准退出码', () => {
  assert.deepEqual(acceptanceSignalConfigurations(), [
    { exitCode: 129, signal: 'SIGHUP' },
    { exitCode: 130, signal: 'SIGINT' },
    { exitCode: 143, signal: 'SIGTERM' },
  ])
})

test('生产应用验收继承普通环境但移除外部 issuer 覆盖', () => {
  const environment = productionAppEnvironment(
    {
      PATH: '/usr/bin',
      DYLD_INSERT_LIBRARIES: '/tmp/external.dylib',
      UNIFIED_LOGIN_CREDENTIAL_SERVICE: 'external-service',
      UNIFIED_LOGIN_ISSUER: 'https://external.example',
    },
    {
      UNIFIED_LOGIN_WINDOW_STARTUP_MODE: 'hidden',
    },
  )

  assert.deepEqual(environment, {
    PATH: '/usr/bin',
    UNIFIED_LOGIN_WINDOW_STARTUP_MODE: 'hidden',
  })
  assert.equal('UNIFIED_LOGIN_ISSUER' in environment, false)
})

test('受管认证中心固定本轮端口和 issuer', () => {
  const environment = authServerEnvironment(
    {
      PATH: '/usr/bin',
      SPRING_APPLICATION_JSON:
        '{"spring":{"datasource":{"url":"jdbc:postgresql://external/db"}}}',
      SPRING_DATASOURCE_URL: 'jdbc:postgresql://external/other',
      SPRING_CONFIG_ADDITIONAL_LOCATION: 'file:/external/config/',
      UNIFIED_LOGIN_ISSUER: 'https://spring-relaxed-binding.example',
      JAVA_TOOL_OPTIONS:
        '-Dspring.datasource.url=jdbc:postgresql://external/tool-options',
      JDK_JAVA_OPTIONS:
        '-Dspring.datasource.url=jdbc:postgresql://external/jdk-options',
      _JAVA_OPTIONS:
        '-Dspring.datasource.url=jdbc:postgresql://external/java-options',
      SERVER_PORT: '9100',
      ISSUER_URL: 'https://external.example',
      JWT_KEY_STORE: '/external/production-signing-key.json',
      BOOTSTRAP_ADMIN_EMAILS: 'desktop@example.com',
      ADMIN_WEB_REDIRECT_URI: 'https://external.example/callback',
    },
    {
      SERVER_PORT: '9000',
      ISSUER_URL: 'http://localhost:9000',
      JWT_KEY_STORE: '/tmp/acceptance/jwt-signing-key.json',
    },
  )

  assert.deepEqual(environment, {
    PATH: '/usr/bin',
    SERVER_PORT: '9000',
    ISSUER_URL: 'http://localhost:9000',
    JWT_KEY_STORE: '/tmp/acceptance/jwt-signing-key.json',
  })
  assert.equal('SPRING_DATASOURCE_URL' in environment, false)
  assert.equal('SPRING_APPLICATION_JSON' in environment, false)
  assert.equal('JAVA_TOOL_OPTIONS' in environment, false)
  assert.equal('BOOTSTRAP_ADMIN_EMAILS' in environment, false)
  assert.equal('ADMIN_WEB_REDIRECT_URI' in environment, false)
})

test('受管认证中心不会继承外部 JWT 签名密钥路径', () => {
  assert.deepEqual(
    authServerEnvironment(
      {
        JWT_KEY_STORE: '/external/production-signing-key.json',
      },
      {},
    ),
    {},
  )
})

test('受管认证中心按 Spring 宽松绑定规则清除非标准大小写和分隔符', () => {
  const environment = authServerEnvironment(
    {
      PATH: '/usr/bin',
      spring_datasource_url: 'jdbc:postgresql://external/lowercase',
      'spring.config.additional-location': 'file:/external/config/',
      'server-port': '9100',
      unified_login_jwt_key_store: '/external/lowercase-key.json',
      'unified-login.issuer': 'https://external.example',
      db_url: 'jdbc:postgresql://external/placeholder',
      'jwt.key.store': '/external/dotted-key.json',
    },
    {
      SERVER_PORT: '9000',
      DB_URL: 'jdbc:postgresql://127.0.0.1:55432/unified_login',
      JWT_KEY_STORE: '/tmp/acceptance/jwt-signing-key.json',
    },
  )

  assert.deepEqual(environment, {
    PATH: '/usr/bin',
    SERVER_PORT: '9000',
    DB_URL: 'jdbc:postgresql://127.0.0.1:55432/unified_login',
    JWT_KEY_STORE: '/tmp/acceptance/jwt-signing-key.json',
  })
})

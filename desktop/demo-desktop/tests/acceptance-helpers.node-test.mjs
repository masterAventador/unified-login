import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  containsPlaintextSecret,
  loopbackPortFromLsof,
  parseBrowserProbe,
  validateBrowserLoginUrl,
} from './acceptance-helpers.mjs'

test('extracts the single IPv4 loopback listener owned by the desktop process', () => {
  const output = [
    'p12345',
    'fcwd',
    'n/Applications/统一登录桌面端.app/Contents/MacOS',
    'f18',
    'n127.0.0.1:49152',
  ].join('\n')

  assert.equal(loopbackPortFromLsof(output), 49152)
})

test('rejects ambiguous, wildcard, non-loopback, and invalid listeners', () => {
  assert.throws(
    () => loopbackPortFromLsof('n127.0.0.1:49152\nn127.0.0.1:49153'),
    /恰好.*一个/,
  )
  assert.throws(() => loopbackPortFromLsof('n*:49152'), /恰好.*一个/)
  assert.throws(() => loopbackPortFromLsof('n127.0.0.1:0'), /恰好.*一个/)
  assert.throws(() => loopbackPortFromLsof('n0.0.0.0:49152'), /恰好.*一个/)
})

test('accepts only the local authentication server login page', () => {
  assert.doesNotThrow(() =>
    validateBrowserLoginUrl('http://localhost:9000/login'),
  )
  assert.doesNotThrow(() =>
    validateBrowserLoginUrl('localhost:9000/login'),
  )
  assert.throws(
    () => validateBrowserLoginUrl('https://attacker.example/login'),
    /认证中心登录页/,
  )
  assert.throws(
    () => validateBrowserLoginUrl('http://localhost:9000/oauth2/authorize'),
    /认证中心登录页/,
  )
})

test('detects an exact secret byte sequence without treating substrings as evidence', () => {
  const secret = Buffer.from('refresh-token-unique-value')

  assert.equal(
    containsPlaintextSecret(
      Buffer.from('prefix-refresh-token-unique-value-suffix'),
      secret,
    ),
    true,
  )
  assert.equal(
    containsPlaintextSecret(Buffer.from('refresh-token-unique'), secret),
    false,
  )
})

test('accepts supported system browsers and rejects unrelated frontmost apps', () => {
  assert.deepEqual(
    parseBrowserProbe('com.google.Chrome\nhttp://localhost:9000/login'),
    {
      bundleId: 'com.google.Chrome',
      url: 'http://localhost:9000/login',
    },
  )
  assert.deepEqual(
    parseBrowserProbe('com.apple.Safari\nlocalhost:9000/login'),
    {
      bundleId: 'com.apple.Safari',
      url: 'localhost:9000/login',
    },
  )
  assert.deepEqual(
    parseBrowserProbe('com.microsoft.edgemac\nhttp://localhost:9000/login'),
    {
      bundleId: 'com.microsoft.edgemac',
      url: 'http://localhost:9000/login',
    },
  )
  assert.throws(
    () => parseBrowserProbe('com.attacker.fake\nhttp://localhost:9000/login'),
    /受支持的系统浏览器/,
  )
})

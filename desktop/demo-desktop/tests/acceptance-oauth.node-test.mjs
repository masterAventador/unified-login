import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  createAuthorizationRequest,
  exchangeAuthorizationCode,
} from './acceptance-oauth.mjs'

test('真实迁移凭据授权请求使用 PKCE S256 和独立 state', () => {
  let randomInvocation = 0
  const request = createAuthorizationRequest({
    clientId: 'demo-desktop',
    issuer: 'http://localhost:19000',
    randomBytes: () => Buffer.alloc(32, ++randomInvocation),
    redirectUri: 'http://127.0.0.1:42001/callback',
  })
  const url = new URL(request.authorizationUrl)

  assert.equal(url.searchParams.get('code_challenge_method'), 'S256')
  assert.equal(
    url.searchParams.get('code_challenge'),
    'VtX6czP210fbQsI5QH5dpMMvTHnzXQkrE0_TWkAtnFw',
  )
  assert.equal(url.searchParams.get('state'), request.state)
  assert.equal(url.searchParams.get('redirect_uri'), request.redirectUri)
  assert.notEqual(request.state, request.verifier)
})

test('真实迁移凭据只接受带 refresh token 的成功令牌响应', async () => {
  const calls = []
  const refreshToken = await exchangeAuthorizationCode({
    clientId: 'demo-desktop',
    code: 'one-time-code',
    fetch: async (...arguments_) => {
      calls.push(arguments_)
      return new Response(JSON.stringify({
        access_token: 'access-secret',
        refresh_token: 'refresh-secret',
        expires_in: 900,
      }))
    },
    issuer: 'http://localhost:19000',
    redirectUri: 'http://127.0.0.1:42001/callback',
    verifier: 'pkce-verifier',
  })

  assert.equal(refreshToken, 'refresh-secret')
  assert.equal(calls.length, 1)
  assert.equal(calls[0][0], 'http://localhost:19000/oauth2/token')
  assert.equal(calls[0][1].headers['Content-Type'], 'application/x-www-form-urlencoded')
  assert.equal(calls[0][1].body.get('code_verifier'), 'pkce-verifier')

  await assert.rejects(
    exchangeAuthorizationCode({
      clientId: 'demo-desktop',
      code: 'one-time-code',
      fetch: async () => new Response('{}'),
      issuer: 'http://localhost:19000',
      redirectUri: 'http://127.0.0.1:42001/callback',
      verifier: 'pkce-verifier',
    }),
    /refresh token/,
  )
})

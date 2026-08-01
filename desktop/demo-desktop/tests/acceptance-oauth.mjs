import { createHash, randomBytes as secureRandomBytes } from 'node:crypto'

export function createAuthorizationRequest({
  clientId,
  issuer,
  randomBytes = secureRandomBytes,
  redirectUri,
}) {
  const verifier = randomBytes(32).toString('base64url')
  const state = randomBytes(32).toString('base64url')
  const challenge = createHash('sha256')
    .update(verifier)
    .digest('base64url')
  const authorization = new URL('/oauth2/authorize', issuer)
  authorization.search = new URLSearchParams({
    client_id: clientId,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid',
    state,
  }).toString()
  return {
    authorizationUrl: authorization.toString(),
    redirectUri,
    state,
    verifier,
  }
}

export async function exchangeAuthorizationCode({
  clientId,
  code,
  fetch: fetchImplementation = globalThis.fetch,
  issuer,
  redirectUri,
  verifier,
}) {
  const body = new URLSearchParams({
    client_id: clientId,
    code,
    code_verifier: verifier,
    grant_type: 'authorization_code',
    redirect_uri: redirectUri,
  })
  const response = await fetchImplementation(
    new URL('/oauth2/token', issuer).toString(),
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body,
    },
  )
  if (!response.ok) {
    throw new Error(`真实迁移凭据换取失败：HTTP ${response.status}`)
  }
  const payload = await response.json()
  if (
    typeof payload.refresh_token !== 'string'
    || payload.refresh_token.length === 0
  ) {
    throw new Error('真实迁移凭据响应缺少 refresh token')
  }
  return payload.refresh_token
}

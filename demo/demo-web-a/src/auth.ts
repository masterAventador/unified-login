const CONFIGURED_ISSUER = import.meta.env.VITE_UNIFIED_LOGIN_ISSUER
  ?? 'http://localhost:9000'
const ISSUER = CONFIGURED_ISSUER.endsWith('/')
  ? CONFIGURED_ISSUER
  : `${CONFIGURED_ISSUER}/`
const CLIENT_ID = 'demo-web-a'
const REDIRECT_URI = 'http://localhost:5173/callback'
const VERIFIER_KEY = 'demo-web-a.code_verifier'
const STATE_KEY = 'demo-web-a.state'

let accessToken: string | null = null
let idTokenEmail: string | null = null

function randomString(byteLength: number): string {
  const bytes = new Uint8Array(byteLength)
  crypto.getRandomValues(bytes)
  return base64UrlEncode(bytes)
}

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = ''
  bytes.forEach((b) => {
    binary += String.fromCharCode(b)
  })
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

async function deriveChallenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return base64UrlEncode(new Uint8Array(digest))
}

export async function startLogin(): Promise<void> {
  const verifier = randomString(32)
  const state = randomString(16)
  sessionStorage.setItem(VERIFIER_KEY, verifier)
  sessionStorage.setItem(STATE_KEY, state)

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: 'openid',
    state,
    code_challenge: await deriveChallenge(verifier),
    code_challenge_method: 'S256',
  })

  const authorizationUrl = new URL('oauth2/authorize', ISSUER)
  authorizationUrl.search = params.toString()
  window.location.assign(authorizationUrl.toString())
}

export async function completeLogin(search: string): Promise<void> {
  const params = new URLSearchParams(search)
  const code = params.get('code')
  const returnedState = params.get('state')
  const expectedState = sessionStorage.getItem(STATE_KEY)
  const verifier = sessionStorage.getItem(VERIFIER_KEY)

  if (!code || !verifier) {
    throw new Error('回调缺少必要参数')
  }
  if (!returnedState || returnedState !== expectedState) {
    throw new Error('state 校验失败，拒绝换取令牌')
  }

  sessionStorage.removeItem(STATE_KEY)
  sessionStorage.removeItem(VERIFIER_KEY)

  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: CLIENT_ID,
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier,
  })

  const response = await fetch(new URL('oauth2/token', ISSUER), {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body,
  })

  if (!response.ok) {
    throw new Error(`换取令牌失败：${response.status}`)
  }

  const payload = await response.json()
  accessToken = payload.access_token
  idTokenEmail = readEmailFromIdToken(payload.id_token)
}

function readEmailFromIdToken(idToken: string): string {
  const claims = JSON.parse(atob(idToken.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')))
  // sub 是永不变更的用户 UUID，email 是可变的显示用字段，此处要显示的是后者
  return claims.email
}

export function isLoggedIn(): boolean {
  return accessToken !== null
}

export function currentUser(): string | null {
  return idTokenEmail
}

export function logout(): void {
  accessToken = null
  idTokenEmail = null
}

import { createHash, randomBytes } from 'node:crypto'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'

import { expect, test, type APIRequestContext } from '@playwright/test'

import {
  AUTH_BASE,
  PASSWORD,
  registerThroughUi,
  uniqueEmail,
} from './support/auth'

const DESKTOP_CLIENT_ID = 'demo-desktop'

interface CallbackResult {
  readonly accepted: boolean
  readonly code?: string
}

interface AuthorizationAttempt {
  readonly authorizationUrl: string
  readonly callbackResult: Promise<CallbackResult>
  readonly redirectUri: string
  readonly verifier: string
  close(): Promise<void>
}

test('桌面 OAuth 链路在无头系统浏览器中完成首登、SSO、恢复和伪造回调拒绝', async ({
  page,
  request,
}) => {
  const email = uniqueEmail()
  await registerThroughUi(page, email)

  const first = await startAuthorizationAttempt()
  try {
    await page.goto(first.authorizationUrl)
    await expect(page).toHaveURL(/^http:\/\/localhost:9000\/login/)
    await page.fill('#username', email)
    await page.fill('#password', PASSWORD)
    await page.click('button[type="submit"]')

    const firstCallback = await first.callbackResult
    expect(firstCallback.accepted).toBe(true)
    expect(firstCallback.code).toBeTruthy()
    const firstTokens = await exchangeCode(
      request,
      firstCallback.code!,
      first.verifier,
      first.redirectUri,
    )
    expect(firstTokens.refreshToken).not.toBe('')
  } finally {
    await first.close()
  }

  const second = await startAuthorizationAttempt()
  const loginPageNavigations: string[] = []
  page.on('framenavigated', (frame) => {
    if (
      frame === page.mainFrame()
      && /^http:\/\/localhost:9000\/login/.test(frame.url())
    ) {
      loginPageNavigations.push(frame.url())
    }
  })
  let secondTokens: TokenPayload
  try {
    await page.goto(second.authorizationUrl)
    const secondCallback = await second.callbackResult
    expect(secondCallback.accepted).toBe(true)
    expect(secondCallback.code).toBeTruthy()
    expect(loginPageNavigations).toEqual([])
    secondTokens = await exchangeCode(
      request,
      secondCallback.code!,
      second.verifier,
      second.redirectUri,
    )
  } finally {
    await second.close()
  }

  const restoredTokens = await refreshTokens(request, secondTokens.refreshToken)
  expect(restoredTokens.accessToken).not.toBe('')
  expect(restoredTokens.refreshToken).not.toBe(secondTokens.refreshToken)

  const replay = await request.post(`${AUTH_BASE}/oauth2/token`, {
    form: {
      grant_type: 'refresh_token',
      client_id: DESKTOP_CLIENT_ID,
      refresh_token: secondTokens.refreshToken,
    },
  })
  expect(replay.status()).toBe(400)
  expect(await replay.json()).toMatchObject({ error: 'invalid_grant' })

  const forged = await startAuthorizationAttempt()
  try {
    const forgedResponse = await request.get(
      `${forged.redirectUri}?code=forged-code&state=forged-state`,
    )
    expect(forgedResponse.status()).toBe(400)
    expect(await forged.callbackResult).toEqual({ accepted: false })
  } finally {
    await forged.close()
  }
})

interface TokenPayload {
  readonly accessToken: string
  readonly refreshToken: string
}

async function exchangeCode(
  request: APIRequestContext,
  code: string,
  verifier: string,
  redirectUri: string,
): Promise<TokenPayload> {
  const response = await request.post(`${AUTH_BASE}/oauth2/token`, {
    form: {
      grant_type: 'authorization_code',
      client_id: DESKTOP_CLIENT_ID,
      code,
      code_verifier: verifier,
      redirect_uri: redirectUri,
    },
  })
  expect(response.status()).toBe(200)
  return tokenPayload(await response.json())
}

async function refreshTokens(
  request: APIRequestContext,
  refreshToken: string,
): Promise<TokenPayload> {
  const response = await request.post(`${AUTH_BASE}/oauth2/token`, {
    form: {
      grant_type: 'refresh_token',
      client_id: DESKTOP_CLIENT_ID,
      refresh_token: refreshToken,
    },
  })
  expect(response.status()).toBe(200)
  return tokenPayload(await response.json())
}

function tokenPayload(payload: Record<string, unknown>): TokenPayload {
  expect(typeof payload.access_token).toBe('string')
  expect(typeof payload.refresh_token).toBe('string')
  return {
    accessToken: payload.access_token as string,
    refreshToken: payload.refresh_token as string,
  }
}

async function startAuthorizationAttempt(): Promise<AuthorizationAttempt> {
  const verifier = randomBytes(32).toString('base64url')
  const challenge = createHash('sha256').update(verifier).digest('base64url')
  const expectedState = randomBytes(32).toString('base64url')
  let resolveCallback!: (result: CallbackResult) => void
  const callbackResult = new Promise<CallbackResult>((resolve) => {
    resolveCallback = resolve
  })

  let callbackUri = ''
  let handled = false
  let server!: Server
  server = createServer((incoming, response) => {
    if (handled) {
      response.writeHead(410, { Connection: 'close' })
      response.end()
      return
    }
    handled = true
    const callback = new URL(incoming.url ?? '/', callbackUri)
    const accepted = (
      incoming.method === 'GET'
      && callback.pathname === '/callback'
      && callback.searchParams.get('state') === expectedState
      && (callback.searchParams.get('code')?.length ?? 0) > 0
    )
    response.writeHead(accepted ? 200 : 400, {
      Connection: 'close',
      'Content-Type': 'text/html; charset=utf-8',
    })
    response.end(
      accepted
        ? '<!doctype html><title>登录成功</title><p>登录成功，可关闭此页</p>'
        : '<!doctype html><title>登录未完成</title><p>登录请求无效</p>',
    )
    resolveCallback({
      accepted,
      ...(accepted ? { code: callback.searchParams.get('code')! } : {}),
    })
    server.close()
  })
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', () => resolve())
  })

  callbackUri = redirectUri(server)
  const authorizationUrl = new URL('/oauth2/authorize', AUTH_BASE)
  authorizationUrl.search = new URLSearchParams({
    response_type: 'code',
    client_id: DESKTOP_CLIENT_ID,
    redirect_uri: callbackUri,
    scope: 'openid',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    state: expectedState,
  }).toString()

  return {
    authorizationUrl: authorizationUrl.toString(),
    callbackResult,
    redirectUri: callbackUri,
    verifier,
    close: () => new Promise<void>((resolve, reject) => {
      if (!server.listening) {
        resolve()
        return
      }
      server.close((error) => error === undefined ? resolve() : reject(error))
    }),
  }
}

function redirectUri(server: Server): string {
  const address = server.address()
  if (address === null || typeof address === 'string') {
    throw new Error('桌面无头验收回环服务没有 IPv4 监听地址')
  }
  return `http://127.0.0.1:${(address as AddressInfo).port}/callback`
}

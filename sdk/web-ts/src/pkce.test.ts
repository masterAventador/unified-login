import { afterEach, describe, expect, it, vi } from 'vitest'

import { createPkcePair } from './pkce'

const RFC_7636_VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
const RFC_7636_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'
const RFC_7636_RANDOM_BYTES = Uint8Array.from([
  0x74, 0x18, 0xdf, 0xb4, 0x97, 0x99, 0xe0, 0x25,
  0x4f, 0xfa, 0x60, 0x7d, 0xd8, 0xad, 0xbb, 0xba,
  0x16, 0xd4, 0x25, 0x4d, 0x69, 0xd6, 0xbf, 0xf0,
  0x5b, 0x58, 0x05, 0x58, 0x53, 0x84, 0x8d, 0x79,
])

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('createPkcePair', () => {
  it('用 32 字节安全随机数生成 RFC 7636 S256 verifier 与 challenge', async () => {
    const getRandomValues = vi.fn((target: Uint8Array) => {
      target.set(RFC_7636_RANDOM_BYTES)
      return target
    })
    vi.stubGlobal('crypto', {
      getRandomValues,
      subtle: globalThis.crypto.subtle,
    })

    const pair = await createPkcePair()

    expect(getRandomValues).toHaveBeenCalledOnce()
    expect(getRandomValues.mock.calls[0]?.[0]).toBeInstanceOf(Uint8Array)
    expect(getRandomValues.mock.calls[0]?.[0]).toHaveLength(32)
    expect(pair).toEqual({
      verifier: RFC_7636_VERIFIER,
      challenge: RFC_7636_CHALLENGE,
    })
  })
})

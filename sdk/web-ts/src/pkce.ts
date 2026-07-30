const VERIFIER_BYTE_LENGTH = 32

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = ''
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte)
  })
  return btoa(binary)
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

export async function createPkcePair(): Promise<{ verifier: string, challenge: string }> {
  const randomBytes = new Uint8Array(VERIFIER_BYTE_LENGTH)
  crypto.getRandomValues(randomBytes)
  const verifier = base64UrlEncode(randomBytes)
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))

  return {
    verifier,
    challenge: base64UrlEncode(new Uint8Array(digest)),
  }
}

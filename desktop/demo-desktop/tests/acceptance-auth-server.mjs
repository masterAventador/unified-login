import { join } from 'node:path'

export const ACCEPTANCE_AUTH_ISSUER = 'http://localhost:9000'

export function acceptanceAuthServerOverrides(temporaryDirectory) {
  return {
    DB_URL: 'jdbc:postgresql://127.0.0.1:55432/unified_login',
    DB_USERNAME: 'unified_login',
    DB_PASSWORD: 'unified_login',
    SERVER_ADDRESS: '127.0.0.1',
    SERVER_PORT: '9000',
    ISSUER_URL: ACCEPTANCE_AUTH_ISSUER,
    JWT_KEY_STORE: join(
      temporaryDirectory,
      'jwt-signing-key.json',
    ),
  }
}

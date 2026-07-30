const DEFAULT_EXPIRY_SKEW_SECONDS = 60

export interface TokenSet {
  readonly accessToken: string
  readonly refreshToken?: string
  readonly idToken?: string
  readonly expiresAt: number
}

export class TokenStore {
  private tokens: TokenSet | null = null

  constructor(private readonly now: () => number = Date.now) {
  }

  set(tokens: TokenSet): void {
    this.tokens = { ...tokens }
  }

  get(): TokenSet | null {
    return this.tokens === null ? null : { ...this.tokens }
  }

  clear(): void {
    this.tokens = null
  }

  isExpiringSoon(skewSeconds = DEFAULT_EXPIRY_SKEW_SECONDS): boolean {
    return this.tokens !== null
      && this.tokens.expiresAt <= this.now() + skewSeconds * 1_000
  }
}

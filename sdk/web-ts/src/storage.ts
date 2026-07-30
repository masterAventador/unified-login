export interface PendingAuthorizationRequest {
  state: string
  verifier: string
}

export class AuthorizationRequestStore {
  private readonly stateKey: string
  private readonly verifierKey: string

  constructor(namespace: string, private readonly storage: Storage) {
    this.stateKey = `${namespace}.state`
    this.verifierKey = `${namespace}.code_verifier`
  }

  save(request: PendingAuthorizationRequest): void {
    this.storage.setItem(this.stateKey, request.state)
    this.storage.setItem(this.verifierKey, request.verifier)
  }

  take(): PendingAuthorizationRequest | null {
    const state = this.storage.getItem(this.stateKey)
    const verifier = this.storage.getItem(this.verifierKey)
    this.clear()

    return state !== null && verifier !== null ? { state, verifier } : null
  }

  takeIfState(expectedState: string): PendingAuthorizationRequest | null {
    if (this.storage.getItem(this.stateKey) !== expectedState) {
      return null
    }
    return this.take()
  }

  clearIfState(expectedState: string): void {
    if (this.storage.getItem(this.stateKey) === expectedState) {
      this.clear()
    }
  }

  clear(): void {
    this.storage.removeItem(this.stateKey)
    this.storage.removeItem(this.verifierKey)
  }
}

export class StateIndexedAuthorizationRequestStore {
  private readonly requestKeyPrefix: string

  constructor(namespace: string, private readonly storage: Storage) {
    this.requestKeyPrefix = `${namespace}.request.`
  }

  save(request: PendingAuthorizationRequest): void {
    this.storage.setItem(this.#requestKey(request.state), request.verifier)
  }

  takeIfState(expectedState: string): PendingAuthorizationRequest | null {
    const requestKey = this.#requestKey(expectedState)
    const verifier = this.storage.getItem(requestKey)
    if (verifier === null) {
      return null
    }
    this.storage.removeItem(requestKey)
    return { state: expectedState, verifier }
  }

  clearIfState(expectedState: string): void {
    this.storage.removeItem(this.#requestKey(expectedState))
  }

  hasPending(): boolean {
    return this.#pendingKeys().length > 0
  }

  clear(): void {
    this.#pendingKeys().forEach((key) => {
      this.storage.removeItem(key)
    })
  }

  #requestKey(state: string): string {
    return `${this.requestKeyPrefix}${encodeURIComponent(state)}`
  }

  #pendingKeys(): string[] {
    const keys: string[] = []
    for (let index = 0; index < this.storage.length; index += 1) {
      const key = this.storage.key(index)
      if (key?.startsWith(this.requestKeyPrefix) === true) {
        keys.push(key)
      }
    }
    return keys
  }
}

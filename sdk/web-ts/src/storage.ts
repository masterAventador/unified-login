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

  clear(): void {
    this.storage.removeItem(this.stateKey)
    this.storage.removeItem(this.verifierKey)
  }
}

import { invoke } from '@tauri-apps/api/core'

export type AuthStatus = 'authenticated' | 'loginRequired' | 'retryable'

export interface DesktopAuthApi {
  restore(): Promise<AuthStatus>
  login(): Promise<AuthStatus>
  logout(): Promise<void>
}

export class TauriDesktopAuthApi implements DesktopAuthApi {
  restore(): Promise<AuthStatus> {
    return invoke<AuthStatus>('restore_session')
  }

  login(): Promise<AuthStatus> {
    return invoke<AuthStatus>('login')
  }

  logout(): Promise<void> {
    return invoke<void>('logout')
  }
}

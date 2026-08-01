import { invoke } from '@tauri-apps/api/core'
import {
  TauriAuthClient,
  type TauriAuthClientApi,
} from '@unified-login/tauri'

export function createTauriAuthClient(): TauriAuthClientApi {
  return new TauriAuthClient(invoke)
}

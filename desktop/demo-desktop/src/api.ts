import { invoke } from '@tauri-apps/api/core'
import {
  TauriAuthClient,
  type TauriAuthClientApi,
} from '../../../sdk/tauri/ts/index'

export function createTauriAuthClient(): TauriAuthClientApi {
  return new TauriAuthClient(invoke)
}

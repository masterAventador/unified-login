import {
  TauriAuthClient,
  type TauriAuthClientApi,
  type TauriInvoke,
} from '@unified-login/tauri'

export function createAuthClient(invoke: TauriInvoke): TauriAuthClientApi {
  return new TauriAuthClient(invoke)
}

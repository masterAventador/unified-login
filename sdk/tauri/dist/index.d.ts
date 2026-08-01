export type AuthStateChangeListener = (authenticated: boolean) => void;
export declare const TAURI_AUTH_ERROR_CODES: readonly ["configuration", "credentials", "loginInProgress", "loginOptions", "loginFailed", "loginRequired", "retryable", "restoreFailed", "logoutFailed", "staleOperation"];
export type TauriAuthErrorCode = typeof TAURI_AUTH_ERROR_CODES[number];
export declare class TauriAuthError extends Error {
    readonly code: TauriAuthErrorCode;
    constructor(code: TauriAuthErrorCode, message?: string, options?: ErrorOptions);
}
export interface TauriAuthLoginOptions {
    readonly prompt?: 'login';
}
export interface TauriAuthClientApi {
    login(options?: TauriAuthLoginOptions): Promise<void>;
    logout(): Promise<void>;
    getAccessToken(): Promise<string>;
    onAuthStateChange(listener: AuthStateChangeListener): () => void;
}
export type TauriInvoke = (command: string, arguments_?: Record<string, unknown>) => Promise<unknown>;
export declare class TauriAuthClient implements TauriAuthClientApi {
    #private;
    constructor(invoke: TauriInvoke);
    login(options?: TauriAuthLoginOptions): Promise<void>;
    logout(): Promise<void>;
    getAccessToken(): Promise<string>;
    onAuthStateChange(listener: AuthStateChangeListener): () => void;
}

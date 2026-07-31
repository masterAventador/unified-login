use serde::Serialize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tauri::{AppHandle, Manager, State};
use unified_login_tauri::credentials::SystemCredentialStore;
use unified_login_tauri::exchange::TokenClient;
use unified_login_tauri::login::LoginAttempt;
use unified_login_tauri::session::{AuthStatus, SessionManager};

const CLIENT_ID: &str = "demo-desktop";
const CREDENTIAL_SERVICE: &str = "com.aventador.unified-login.demo-desktop";
const CREDENTIAL_ACCOUNT: &str = "refresh-token";
const DEFAULT_ISSUER: &str = "http://localhost:9000";
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(120);

struct AppState {
    issuer: String,
    login_token_client: TokenClient,
    session: SessionManager<SystemCredentialStore>,
    login_in_progress: AtomicBool,
}

impl AppState {
    fn new() -> Result<Self, CommandError> {
        let issuer =
            std::env::var("UNIFIED_LOGIN_ISSUER").unwrap_or_else(|_| DEFAULT_ISSUER.to_owned());
        let login_token_client =
            TokenClient::new(&issuer, CLIENT_ID).map_err(|_| CommandError::configuration())?;
        let session_token_client =
            TokenClient::new(&issuer, CLIENT_ID).map_err(|_| CommandError::configuration())?;
        let store = SystemCredentialStore::new(CREDENTIAL_SERVICE, CREDENTIAL_ACCOUNT)
            .map_err(|_| CommandError::credentials())?;

        Ok(Self {
            issuer,
            login_token_client,
            session: SessionManager::new(session_token_client, store),
            login_in_progress: AtomicBool::new(false),
        })
    }

    fn begin_login(&self) -> Result<LoginGuard<'_>, CommandError> {
        if self
            .login_in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(CommandError::login_in_progress());
        }
        Ok(LoginGuard(&self.login_in_progress))
    }
}

struct LoginGuard<'a>(&'a AtomicBool);

impl Drop for LoginGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CommandError {
    code: &'static str,
    message: &'static str,
}

impl CommandError {
    fn configuration() -> Self {
        Self {
            code: "configuration",
            message: "桌面端认证配置无效",
        }
    }

    fn credentials() -> Self {
        Self {
            code: "credentials",
            message: "操作系统凭据库暂时不可用",
        }
    }

    fn login_in_progress() -> Self {
        Self {
            code: "loginInProgress",
            message: "已有登录流程正在进行",
        }
    }

    fn login_failed() -> Self {
        Self {
            code: "loginFailed",
            message: "登录未完成，请重试",
        }
    }

    fn restore_failed() -> Self {
        Self {
            code: "restoreFailed",
            message: "暂时无法恢复登录状态",
        }
    }

    fn logout_failed() -> Self {
        Self {
            code: "logoutFailed",
            message: "退出登录未完成",
        }
    }
}

#[tauri::command]
async fn restore_session(state: State<'_, AppState>) -> Result<&'static str, CommandError> {
    state
        .session
        .restore()
        .await
        .map(status_name)
        .map_err(|_| CommandError::restore_failed())
}

#[tauri::command]
async fn login(app: AppHandle, state: State<'_, AppState>) -> Result<&'static str, CommandError> {
    let _guard = state.begin_login()?;
    let attempt =
        LoginAttempt::start(&state.issuer, CLIENT_ID).map_err(|_| CommandError::login_failed())?;
    tauri_plugin_opener::open_url(attempt.authorization_url(), None::<&str>)
        .map_err(|_| CommandError::login_failed())?;
    let tokens = attempt
        .complete(&state.login_token_client, CALLBACK_TIMEOUT)
        .await
        .map_err(|_| CommandError::login_failed())?;
    state
        .session
        .accept_tokens(tokens)
        .map_err(|_| CommandError::credentials())?;
    // 令牌已经成功保存后，窗口聚焦只能算尽力而为；不能因为窗口此刻正在关闭、
    // 被系统拒绝抢焦点等纯 UI 原因，把一次成功登录错误地报告成失败。
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.set_focus();
    }
    Ok("authenticated")
}

#[tauri::command]
fn logout(state: State<'_, AppState>) -> Result<(), CommandError> {
    state
        .session
        .logout()
        .map_err(|_| CommandError::logout_failed())
}

fn status_name(status: AuthStatus) -> &'static str {
    match status {
        AuthStatus::Authenticated => "authenticated",
        AuthStatus::LoginRequired => "loginRequired",
        AuthStatus::Retryable => "retryable",
    }
}

pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            app.manage(AppState::new().map_err(|error| error.message)?);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![restore_session, login, logout])
        .run(tauri::generate_context!())
        .expect("Tauri 桌面应用启动失败");
}

#[cfg(test)]
mod tests {
    use super::{AppState, status_name};
    use unified_login_tauri::session::AuthStatus;

    #[test]
    fn maps_every_core_status_to_the_frontend_contract() {
        assert_eq!(status_name(AuthStatus::Authenticated), "authenticated");
        assert_eq!(status_name(AuthStatus::LoginRequired), "loginRequired");
        assert_eq!(status_name(AuthStatus::Retryable), "retryable");
    }

    #[test]
    fn prevents_overlapping_login_attempts_and_releases_after_completion() {
        let state = AppState::new().expect("测试认证配置应有效");
        let first = state.begin_login().expect("首次登录应占用互斥位");
        assert!(state.begin_login().is_err(), "并发登录必须被拒绝");
        drop(first);
        assert!(state.begin_login().is_ok(), "流程结束后必须允许重新登录");
    }
}

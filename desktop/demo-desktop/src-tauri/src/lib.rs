use serde::Serialize;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tauri::{AppHandle, Manager, State};
use unified_login_tauri::credentials::{
    CredentialError, SystemCredentialStore, scoped_credential_account,
};
use unified_login_tauri::exchange::TokenClient;
use unified_login_tauri::login::{LoginAttempt, LoginCancellation};
use unified_login_tauri::session::{AccessTokenStatus, SessionManager};

const CLIENT_ID: &str = "demo-desktop";
const CREDENTIAL_SERVICE: &str = "com.aventador.unified-login.demo-desktop";
const CREDENTIAL_ACCOUNT: &str = "refresh-token";
const CREDENTIAL_SERVICE_ENV: &str = "UNIFIED_LOGIN_CREDENTIAL_SERVICE";
const DEFAULT_ISSUER: &str = "http://localhost:9000";
const CALLBACK_TIMEOUT: Duration = Duration::from_secs(120);
const WINDOW_STARTUP_MODE_ENV: &str = "UNIFIED_LOGIN_WINDOW_STARTUP_MODE";

#[derive(Clone, Copy, Debug, PartialEq)]
enum WindowStartupMode {
    Default,
    Hidden,
}

impl WindowStartupMode {
    fn should_show_window(&self) -> bool {
        *self == Self::Default
    }

    fn should_focus_after_login(&self) -> bool {
        *self == Self::Default
    }
}

fn window_startup_mode(value: Option<&str>) -> WindowStartupMode {
    match value {
        Some("hidden") => WindowStartupMode::Hidden,
        _ => WindowStartupMode::Default,
    }
}

fn current_window_startup_mode() -> WindowStartupMode {
    window_startup_mode(std::env::var(WINDOW_STARTUP_MODE_ENV).ok().as_deref())
}

trait ExistingInstanceTarget {
    fn focus(&self);
    fn show(&self);
}

impl<R: tauri::Runtime> ExistingInstanceTarget for tauri::WebviewWindow<R> {
    fn focus(&self) {
        let _ = self.set_focus();
    }

    fn show(&self) {
        let _ = self.show();
    }
}

fn activate_existing_instance<T: ExistingInstanceTarget>(
    target: &T,
    startup_mode: &WindowStartupMode,
) {
    if startup_mode.should_show_window() {
        target.show();
        target.focus();
    }
}

#[cfg(any(target_os = "macos", test))]
trait ActivationPolicyTarget {
    fn suppress_activation(&mut self);
}

#[cfg(target_os = "macos")]
impl<R: tauri::Runtime> ActivationPolicyTarget for tauri::App<R> {
    fn suppress_activation(&mut self) {
        self.set_activation_policy(tauri::ActivationPolicy::Prohibited);
    }
}

#[cfg(any(target_os = "macos", test))]
fn configure_macos_activation<T: ActivationPolicyTarget>(
    mut target: T,
    startup_mode: &WindowStartupMode,
) -> T {
    if *startup_mode == WindowStartupMode::Hidden {
        target.suppress_activation();
    }
    target
}

fn credential_service(value: Option<&str>) -> &str {
    value
        .filter(|candidate| !candidate.is_empty())
        .unwrap_or(CREDENTIAL_SERVICE)
}

struct AppState {
    auth: StdMutex<AppAuthState>,
    auth_configuration: AuthConfiguration,
    login_lifecycle: StdMutex<LoginLifecycle>,
}

type CredentialStoreFactory =
    dyn Fn(&str, &str) -> Result<SystemCredentialStore, CredentialError> + Send + Sync;

struct AuthConfiguration {
    issuer: String,
    credential_service: String,
    store_factory: Arc<CredentialStoreFactory>,
}

#[derive(Default)]
struct LoginLifecycle {
    active_login: Option<Arc<ActiveLogin>>,
    logout_in_progress: bool,
}

struct ActiveLogin {
    cancellation: LoginCancellation,
    finished: tokio::sync::watch::Sender<bool>,
}

impl ActiveLogin {
    fn new() -> Self {
        let (finished, _) = tokio::sync::watch::channel(false);
        Self {
            cancellation: LoginCancellation::new(),
            finished,
        }
    }

    fn finish(&self) {
        self.finished.send_replace(true);
    }

    async fn wait_for_finish(&self) {
        let mut finished = self.finished.subscribe();
        while !*finished.borrow_and_update() {
            if finished.changed().await.is_err() {
                return;
            }
        }
    }
}

enum AppAuthState {
    Ready(Arc<AuthResources>),
    Unavailable(CommandError),
}

struct AuthResources {
    issuer: String,
    login_token_client: TokenClient,
    session: SessionManager<SystemCredentialStore>,
}

impl AppState {
    fn new() -> Self {
        let issuer =
            std::env::var("UNIFIED_LOGIN_ISSUER").unwrap_or_else(|_| DEFAULT_ISSUER.to_owned());
        let credential_service_override = std::env::var(CREDENTIAL_SERVICE_ENV).ok();
        Self::new_with_store_factory(
            issuer,
            credential_service(credential_service_override.as_deref()),
            SystemCredentialStore::new,
        )
    }

    fn new_with_store_factory<F>(issuer: String, credential_service: &str, store_factory: F) -> Self
    where
        F: Fn(&str, &str) -> Result<SystemCredentialStore, CredentialError> + Send + Sync + 'static,
    {
        let store_factory: Arc<CredentialStoreFactory> = Arc::new(store_factory);
        let auth = Self::initialize_auth(&issuer, credential_service, store_factory.as_ref())
            .map_or_else(AppAuthState::Unavailable, |resources| {
                AppAuthState::Ready(Arc::new(resources))
            });
        Self {
            auth: StdMutex::new(auth),
            auth_configuration: AuthConfiguration {
                issuer,
                credential_service: credential_service.to_owned(),
                store_factory,
            },
            login_lifecycle: StdMutex::new(LoginLifecycle::default()),
        }
    }

    fn initialize_auth(
        issuer: &str,
        credential_service: &str,
        store_factory: &CredentialStoreFactory,
    ) -> Result<AuthResources, CommandError> {
        let login_token_client =
            TokenClient::new(issuer, CLIENT_ID).map_err(|_| CommandError::configuration())?;
        let session_token_client =
            TokenClient::new(issuer, CLIENT_ID).map_err(|_| CommandError::configuration())?;
        let credential_account = scoped_credential_account(CREDENTIAL_ACCOUNT, issuer, CLIENT_ID)
            .map_err(|_| CommandError::configuration())?;
        let store = store_factory(credential_service, &credential_account)
            .map_err(|_| CommandError::credentials())?;

        Ok(AuthResources {
            issuer: issuer.to_owned(),
            login_token_client,
            session: SessionManager::new(session_token_client, store),
        })
    }

    fn auth_resources(&self) -> Result<Arc<AuthResources>, CommandError> {
        let mut auth = self.auth.lock().expect("认证资源锁不应中毒");
        if matches!(
            &*auth,
            AppAuthState::Unavailable(error) if *error == CommandError::credentials()
        ) {
            *auth = Self::initialize_auth(
                &self.auth_configuration.issuer,
                &self.auth_configuration.credential_service,
                self.auth_configuration.store_factory.as_ref(),
            )
            .map_or_else(AppAuthState::Unavailable, |resources| {
                AppAuthState::Ready(Arc::new(resources))
            });
        }
        match &*auth {
            AppAuthState::Ready(resources) => Ok(Arc::clone(resources)),
            AppAuthState::Unavailable(error) => Err(*error),
        }
    }

    fn begin_login(&self) -> Result<LoginGuard<'_>, CommandError> {
        let mut lifecycle = self.login_lifecycle.lock().expect("登录生命周期锁不应中毒");
        if lifecycle.logout_in_progress || lifecycle.active_login.is_some() {
            return Err(CommandError::login_in_progress());
        }
        let active_login = Arc::new(ActiveLogin::new());
        lifecycle.active_login = Some(Arc::clone(&active_login));
        Ok(LoginGuard {
            lifecycle: &self.login_lifecycle,
            active_login,
        })
    }

    fn begin_logout(&self) -> Result<LogoutGuard<'_>, CommandError> {
        let mut lifecycle = self.login_lifecycle.lock().expect("登录生命周期锁不应中毒");
        if lifecycle.logout_in_progress {
            return Err(CommandError::logout_failed());
        }
        lifecycle.logout_in_progress = true;
        let active_login = lifecycle.active_login.clone();
        if let Some(active_login) = &active_login {
            active_login.cancellation.cancel();
        }
        Ok(LogoutGuard {
            lifecycle: &self.login_lifecycle,
            active_login,
        })
    }
}

struct LoginGuard<'a> {
    lifecycle: &'a StdMutex<LoginLifecycle>,
    active_login: Arc<ActiveLogin>,
}

impl LoginGuard<'_> {
    fn cancellation(&self) -> LoginCancellation {
        self.active_login.cancellation.clone()
    }
}

impl Drop for LoginGuard<'_> {
    fn drop(&mut self) {
        let mut lifecycle = self.lifecycle.lock().expect("登录生命周期锁不应中毒");
        if lifecycle
            .active_login
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, &self.active_login))
        {
            lifecycle.active_login = None;
        }
        self.active_login.finish();
    }
}

struct LogoutGuard<'a> {
    lifecycle: &'a StdMutex<LoginLifecycle>,
    active_login: Option<Arc<ActiveLogin>>,
}

impl LogoutGuard<'_> {
    async fn wait_for_active_login(&self) {
        if let Some(active_login) = &self.active_login {
            active_login.wait_for_finish().await;
        }
    }
}

impl Drop for LogoutGuard<'_> {
    fn drop(&mut self) {
        self.lifecycle
            .lock()
            .expect("登录生命周期锁不应中毒")
            .logout_in_progress = false;
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
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

    fn login_options() -> Self {
        Self {
            code: "loginOptions",
            message: "桌面端登录选项无效",
        }
    }

    fn login_failed() -> Self {
        Self {
            code: "loginFailed",
            message: "登录未完成，请重试",
        }
    }

    fn login_required() -> Self {
        Self {
            code: "loginRequired",
            message: "当前没有可用的登录令牌",
        }
    }

    fn retryable() -> Self {
        Self {
            code: "retryable",
            message: "暂时无法连接认证中心",
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

fn required_access_token(access_token: AccessTokenStatus) -> Result<String, CommandError> {
    match access_token {
        AccessTokenStatus::Available(value) => Ok(value),
        AccessTokenStatus::LoginRequired => Err(CommandError::login_required()),
        AccessTokenStatus::Retryable => Err(CommandError::retryable()),
    }
}

fn force_login(prompt: Option<&str>) -> Result<bool, CommandError> {
    match prompt {
        None => Ok(false),
        Some("login") => Ok(true),
        Some(_) => Err(CommandError::login_options()),
    }
}

#[tauri::command]
async fn get_access_token(state: State<'_, AppState>) -> Result<String, CommandError> {
    let access_token = state
        .auth_resources()?
        .session
        .access_token()
        .await
        .map_err(|_| CommandError::restore_failed())?;
    required_access_token(access_token)
}

#[tauri::command]
async fn login(
    app: AppHandle,
    state: State<'_, AppState>,
    prompt: Option<String>,
) -> Result<&'static str, CommandError> {
    let resources = state.auth_resources()?;
    let prompt = force_login(prompt.as_deref())?.then_some("login");
    let login_guard = state.begin_login()?;
    let login_generation = resources.session.begin_login();
    let attempt = LoginAttempt::start_with_prompt(&resources.issuer, CLIENT_ID, prompt)
        .map_err(|_| CommandError::login_failed())?;
    tauri_plugin_opener::open_url(attempt.authorization_url(), None::<&str>)
        .map_err(|_| CommandError::login_failed())?;
    let tokens = attempt
        .complete_with_cancellation(
            &resources.login_token_client,
            CALLBACK_TIMEOUT,
            login_guard.cancellation(),
        )
        .await
        .map_err(|_| CommandError::login_failed())?;
    let accepted = resources
        .session
        .accept_login_tokens(login_generation, tokens)
        .await
        .map_err(|_| CommandError::credentials())?;
    if !accepted {
        return Err(CommandError::login_failed());
    }
    // 令牌已经成功保存后，窗口聚焦只能算尽力而为；不能因为窗口此刻正在关闭、
    // 被系统拒绝抢焦点等纯 UI 原因，把一次成功登录错误地报告成失败。
    if current_window_startup_mode().should_focus_after_login()
        && let Some(window) = app.get_webview_window("main")
    {
        let _ = window.set_focus();
    }
    Ok("authenticated")
}

#[tauri::command]
async fn logout(state: State<'_, AppState>) -> Result<(), CommandError> {
    let resources = state.auth_resources()?;
    let logout_guard = state.begin_logout()?;
    let result = resources
        .session
        .logout()
        .await
        .map_err(|_| CommandError::logout_failed());
    logout_guard.wait_for_active_login().await;
    result
}

pub fn run() {
    let startup_mode = current_window_startup_mode();
    let setup_mode = startup_mode;
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            if let Some(window) = app.get_webview_window("main") {
                activate_existing_instance(&window, &current_window_startup_mode());
            }
        }))
        .setup(move |app| {
            app.manage(AppState::new());
            let window = app
                .get_webview_window("main")
                .ok_or("找不到桌面应用主窗口")?;
            if setup_mode.should_show_window() {
                window.show()?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![login, get_access_token, logout])
        .build(tauri::generate_context!())
        .expect("Tauri 桌面应用构建失败");
    #[cfg(target_os = "macos")]
    let app = configure_macos_activation(app, &startup_mode);
    app.run(|_, _| {});
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{
        ActivationPolicyTarget, AppState, CREDENTIAL_SERVICE, DEFAULT_ISSUER,
        ExistingInstanceTarget, WindowStartupMode, activate_existing_instance,
        configure_macos_activation, credential_service, window_startup_mode,
    };
    use unified_login_tauri::credentials::{CredentialError, SystemCredentialStore};
    use unified_login_tauri::session::AccessTokenStatus;

    #[test]
    fn access_token_command_rejects_a_missing_session_with_a_stable_error() {
        assert_eq!(
            super::required_access_token(AccessTokenStatus::LoginRequired),
            Err(super::CommandError::login_required())
        );
        assert_eq!(
            super::required_access_token(AccessTokenStatus::Retryable),
            Err(super::CommandError::retryable())
        );
        assert_eq!(
            super::required_access_token(AccessTokenStatus::Available("access-secret".to_owned())),
            Ok("access-secret".to_owned())
        );
    }

    #[test]
    fn automation_window_mode_is_hidden_without_changing_the_default() {
        assert_eq!(window_startup_mode(None), WindowStartupMode::Default);
        assert_eq!(
            window_startup_mode(Some("hidden")),
            WindowStartupMode::Hidden
        );
        assert_eq!(
            window_startup_mode(Some("unexpected")),
            WindowStartupMode::Default
        );
        assert!(WindowStartupMode::Default.should_show_window());
        assert!(!WindowStartupMode::Hidden.should_show_window());
        assert!(WindowStartupMode::Default.should_focus_after_login());
        assert!(!WindowStartupMode::Hidden.should_focus_after_login());
    }

    #[test]
    fn activation_configuration_owns_and_returns_the_target_before_the_event_loop() {
        let hidden = configure_macos_activation(
            FakeActivationPolicyTarget::default(),
            &WindowStartupMode::Hidden,
        );
        assert_eq!(hidden.suppression_count, 1);

        let default = configure_macos_activation(
            FakeActivationPolicyTarget::default(),
            &WindowStartupMode::Default,
        );
        assert_eq!(default.suppression_count, 0);
    }

    #[test]
    fn second_instance_focuses_only_the_normal_visible_application() {
        let visible = FakeExistingInstanceTarget::default();
        activate_existing_instance(&visible, &WindowStartupMode::Default);
        assert_eq!(visible.show_count.get(), 1);
        assert_eq!(visible.focus_count.get(), 1);

        let hidden = FakeExistingInstanceTarget::default();
        activate_existing_instance(&hidden, &WindowStartupMode::Hidden);
        assert_eq!(hidden.show_count.get(), 0);
        assert_eq!(hidden.focus_count.get(), 0);
    }

    #[test]
    fn isolated_credential_service_does_not_change_the_production_default() {
        assert_eq!(credential_service(None), CREDENTIAL_SERVICE);
        assert_eq!(credential_service(Some("")), CREDENTIAL_SERVICE);
        assert_eq!(
            credential_service(Some("com.aventador.unified-login.acceptance.isolated")),
            "com.aventador.unified-login.acceptance.isolated"
        );
    }

    #[test]
    fn prevents_overlapping_login_attempts_and_releases_after_completion() {
        let state = AppState::new();
        let first = state.begin_login().expect("首次登录应占用互斥位");
        assert!(state.begin_login().is_err(), "并发登录必须被拒绝");
        drop(first);
        assert!(state.begin_login().is_ok(), "流程结束后必须允许重新登录");
    }

    #[tokio::test]
    async fn logout_cancels_and_waits_for_the_active_login_before_allowing_retry() {
        let state = AppState::new();
        let login = state.begin_login().expect("首次登录应占用互斥位");
        let cancellation = login.cancellation();

        let logout = state.begin_logout().expect("登出应进入受管生命周期");

        assert!(cancellation.is_cancelled(), "登出必须立即取消活动登录");
        assert!(state.begin_login().is_err(), "登出结束前不得启动新登录");
        drop(login);
        logout.wait_for_active_login().await;
        assert!(
            state.begin_login().is_err(),
            "登出守卫释放前仍不得启动新登录"
        );
        drop(logout);
        assert!(
            state.begin_login().is_ok(),
            "登出完整结束后必须允许立即重试"
        );
    }

    #[test]
    fn credential_store_initialization_failure_becomes_managed_state() {
        let state = AppState::new_with_store_factory(
            DEFAULT_ISSUER.to_owned(),
            CREDENTIAL_SERVICE,
            |_, _| {
                Err(CredentialError::Unavailable(
                    "用户拒绝访问凭据库".to_owned(),
                ))
            },
        );

        assert!(matches!(
            state.auth_resources(),
            Err(error) if error == super::CommandError::credentials()
        ));
    }

    #[test]
    fn credential_store_initialization_is_retried_after_a_temporary_failure() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_for_factory = Arc::clone(&attempts);
        let state = AppState::new_with_store_factory(
            DEFAULT_ISSUER.to_owned(),
            CREDENTIAL_SERVICE,
            move |service, account| {
                if attempts_for_factory.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Err(CredentialError::Unavailable("凭据库暂时不可用".to_owned()));
                }
                SystemCredentialStore::new(service, account)
            },
        );

        assert!(
            state.auth_resources().is_ok(),
            "系统凭据库恢复后，同一个应用实例的重试必须重新初始化认证资源"
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn login_prompt_accepts_only_the_shared_web_sdk_contract() {
        assert_eq!(super::force_login(None), Ok(false));
        assert_eq!(super::force_login(Some("login")), Ok(true));
        assert_eq!(
            super::force_login(Some("none")),
            Err(super::CommandError::login_options())
        );
    }

    #[derive(Default)]
    struct FakeActivationPolicyTarget {
        suppression_count: usize,
    }

    impl ActivationPolicyTarget for FakeActivationPolicyTarget {
        fn suppress_activation(&mut self) {
            self.suppression_count += 1;
        }
    }

    #[derive(Default)]
    struct FakeExistingInstanceTarget {
        focus_count: std::cell::Cell<usize>,
        show_count: std::cell::Cell<usize>,
    }

    impl ExistingInstanceTarget for FakeExistingInstanceTarget {
        fn focus(&self) {
            self.focus_count.set(self.focus_count.get() + 1);
        }

        fn show(&self) {
            self.show_count.set(self.show_count.get() + 1);
        }
    }
}

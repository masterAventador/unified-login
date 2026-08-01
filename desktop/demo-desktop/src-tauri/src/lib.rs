use std::sync::{Arc, Mutex as StdMutex};
use tauri::{AppHandle, Manager, State};
use unified_login_tauri::auth::{AuthClient, AuthConfig, AuthError, AuthErrorCode, LoginOptions};
use unified_login_tauri::credentials::{
    CredentialError, MigratingCredentialStore, SystemCredentialStore,
};

const CLIENT_ID: &str = "demo-desktop";
const CREDENTIAL_SERVICE: &str = "com.aventador.unified-login.demo-desktop";
const CREDENTIAL_ACCOUNT: &str = "refresh-token";
const CREDENTIAL_SERVICE_ENV: &str = "UNIFIED_LOGIN_CREDENTIAL_SERVICE";
const DEFAULT_ISSUER: &str = "http://localhost:9000";
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
}

type CredentialStoreFactory =
    dyn Fn(&str, &str) -> Result<SystemCredentialStore, CredentialError> + Send + Sync;

struct AuthConfiguration {
    issuer: String,
    credential_service: String,
    store_factory: Arc<CredentialStoreFactory>,
}

enum AppAuthState {
    Ready(Arc<DesktopAuthClient>),
    Unavailable(AuthError),
}

type CompatibleCredentialStore =
    MigratingCredentialStore<SystemCredentialStore, SystemCredentialStore>;
type DesktopAuthClient = AuthClient<CompatibleCredentialStore>;

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
        }
    }

    fn initialize_auth(
        issuer: &str,
        credential_service: &str,
        store_factory: &CredentialStoreFactory,
    ) -> Result<DesktopAuthClient, AuthError> {
        let config = AuthConfig::builder(issuer, CLIENT_ID, credential_service)
            .credential_account(CREDENTIAL_ACCOUNT)
            .build()?;
        let current_store = store_factory(credential_service, config.credential_account())
            .map_err(AuthError::from)?;
        let legacy_account = config.legacy_credential_account().ok_or(AuthError {
            code: AuthErrorCode::Configuration,
            message: "桌面端认证配置无效",
        })?;
        let legacy_store =
            store_factory(credential_service, legacy_account).map_err(AuthError::from)?;
        let store = MigratingCredentialStore::new(current_store, legacy_store);
        AuthClient::new(config, store)
    }

    fn auth_client(&self) -> Result<Arc<DesktopAuthClient>, AuthError> {
        let mut auth = self.auth.lock().expect("认证资源锁不应中毒");
        if matches!(
            &*auth,
            AppAuthState::Unavailable(error) if error.code == AuthErrorCode::Credentials
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
}

#[tauri::command]
async fn get_access_token(state: State<'_, AppState>) -> Result<String, AuthError> {
    state.auth_client()?.access_token().await
}

#[tauri::command]
async fn login(
    app: AppHandle,
    state: State<'_, AppState>,
    prompt: Option<String>,
) -> Result<&'static str, AuthError> {
    let options = LoginOptions::from_prompt(prompt.as_deref())?;
    state
        .auth_client()?
        .login(options, |authorization_url| {
            tauri_plugin_opener::open_url(authorization_url, None::<&str>)
                .map_err(|error| error.to_string())
        })
        .await?;
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
async fn logout(state: State<'_, AppState>) -> Result<(), AuthError> {
    state.auth_client()?.logout().await
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
    use unified_login_tauri::auth::AuthErrorCode;
    use unified_login_tauri::credentials::{CredentialError, SystemCredentialStore};

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
            state.auth_client(),
            Err(error) if error.code == AuthErrorCode::Credentials
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
            state.auth_client().is_ok(),
            "系统凭据库恢复后，同一个应用实例的重试必须重新初始化认证资源"
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
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

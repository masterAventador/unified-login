//! 标准 Tauri 插件适配层。
//!
//! 应用只负责提供认证配置和可选的登录成功回调；认证命令、浏览器跳转、系统凭据库、
//! 旧凭据迁移以及临时凭据库故障后的重试均由 SDK 管理。

use std::sync::{Arc, Mutex as StdMutex};

use tauri::plugin::{Builder as TauriPluginBuilder, TauriPlugin};
use tauri::{AppHandle, Manager, Runtime, State};

use crate::auth::{AuthClient, AuthConfig, AuthError, AuthErrorCode, LoginOptions};
use crate::credentials::{CredentialError, MigratingCredentialStore, SystemCredentialStore};

pub const PLUGIN_NAME: &str = "unified-login-tauri";
pub const PLUGIN_INVOKE_PREFIX: &str = "plugin:unified-login-tauri|";

type CompatibleCredentialStore =
    MigratingCredentialStore<SystemCredentialStore, SystemCredentialStore>;
type DesktopAuthClient = AuthClient<CompatibleCredentialStore>;
type CredentialStoreFactory =
    dyn Fn(&str, &str) -> Result<SystemCredentialStore, CredentialError> + Send + Sync;
type LoginSuccessHandler<R> = dyn Fn(&AppHandle<R>) + Send + Sync;

enum PluginAuthState {
    Ready(Arc<DesktopAuthClient>),
    Unavailable(AuthError),
}

struct PluginState<R: Runtime> {
    auth: StdMutex<PluginAuthState>,
    config: Option<AuthConfig>,
    store_factory: Arc<CredentialStoreFactory>,
    on_login_success: Option<Arc<LoginSuccessHandler<R>>>,
}

impl<R: Runtime> PluginState<R> {
    fn from_config_result(
        config: Result<AuthConfig, AuthError>,
        on_login_success: Option<Arc<LoginSuccessHandler<R>>>,
    ) -> Self {
        Self::from_config_result_with_store_factory(
            config,
            on_login_success,
            SystemCredentialStore::new,
        )
    }

    fn from_config_result_with_store_factory<F>(
        config: Result<AuthConfig, AuthError>,
        on_login_success: Option<Arc<LoginSuccessHandler<R>>>,
        store_factory: F,
    ) -> Self
    where
        F: Fn(&str, &str) -> Result<SystemCredentialStore, CredentialError> + Send + Sync + 'static,
    {
        let store_factory: Arc<CredentialStoreFactory> = Arc::new(store_factory);
        let (auth, config) = match config {
            Ok(config) => {
                let auth = Self::initialize_auth(&config, store_factory.as_ref())
                    .map_or_else(PluginAuthState::Unavailable, |client| {
                        PluginAuthState::Ready(Arc::new(client))
                    });
                (auth, Some(config))
            }
            Err(error) => (PluginAuthState::Unavailable(error), None),
        };
        Self {
            auth: StdMutex::new(auth),
            config,
            store_factory,
            on_login_success,
        }
    }

    fn initialize_auth(
        config: &AuthConfig,
        store_factory: &CredentialStoreFactory,
    ) -> Result<DesktopAuthClient, AuthError> {
        let current_store = store_factory(config.credential_service(), config.credential_account())
            .map_err(AuthError::from)?;
        let legacy_account = config
            .legacy_credential_account()
            .ok_or_else(AuthError::configuration)?;
        let legacy_store =
            store_factory(config.credential_service(), legacy_account).map_err(AuthError::from)?;
        AuthClient::new(
            config.clone(),
            MigratingCredentialStore::new(current_store, legacy_store),
        )
    }

    fn auth_client(&self) -> Result<Arc<DesktopAuthClient>, AuthError> {
        let mut auth = self.auth.lock().expect("认证资源锁不应中毒");
        if matches!(
            &*auth,
            PluginAuthState::Unavailable(error) if error.code == AuthErrorCode::Credentials
        ) {
            let config = self
                .config
                .as_ref()
                .expect("只有完成配置后才可能发生凭据库初始化错误");
            *auth = Self::initialize_auth(config, self.store_factory.as_ref())
                .map_or_else(PluginAuthState::Unavailable, |client| {
                    PluginAuthState::Ready(Arc::new(client))
                });
        }
        match &*auth {
            PluginAuthState::Ready(client) => Ok(Arc::clone(client)),
            PluginAuthState::Unavailable(error) => Err(*error),
        }
    }

    fn notify_login_success(&self, app: &AppHandle<R>) {
        if let Some(handler) = &self.on_login_success {
            handler(app);
        }
    }
}

#[tauri::command]
async fn get_access_token<R: Runtime>(
    _app: AppHandle<R>,
    state: State<'_, PluginState<R>>,
) -> Result<String, AuthError> {
    state.auth_client()?.access_token().await
}

#[tauri::command]
async fn login<R: Runtime>(
    app: AppHandle<R>,
    state: State<'_, PluginState<R>>,
    prompt: Option<String>,
) -> Result<(), AuthError> {
    let options = LoginOptions::from_prompt(prompt.as_deref())?;
    state
        .auth_client()?
        .login(options, |authorization_url| {
            open::that_detached(authorization_url).map_err(|error| error.to_string())
        })
        .await?;
    state.notify_login_success(&app);
    Ok(())
}

#[tauri::command]
async fn logout<R: Runtime>(
    _app: AppHandle<R>,
    state: State<'_, PluginState<R>>,
) -> Result<(), AuthError> {
    state.auth_client()?.logout().await
}

/// 构建统一登录 Tauri 插件。
///
/// `on_login_success` 只提供应用级窗口策略扩展点，SDK 不包含任何窗口标签或 UI 样式。
pub struct Builder<R: Runtime> {
    config: Result<AuthConfig, AuthError>,
    on_login_success: Option<Arc<LoginSuccessHandler<R>>>,
}

impl<R: Runtime> Builder<R> {
    pub fn new(config: AuthConfig) -> Self {
        Self {
            config: Ok(config),
            on_login_success: None,
        }
    }

    /// 接收运行时配置构建结果。配置无效时插件仍正常注册，认证命令会向前端返回稳定的
    /// `configuration` 错误，应用不会在事件循环启动前 panic。
    pub fn from_config_result(config: Result<AuthConfig, AuthError>) -> Self {
        Self {
            config,
            on_login_success: None,
        }
    }

    pub fn on_login_success<F>(mut self, handler: F) -> Self
    where
        F: Fn(&AppHandle<R>) + Send + Sync + 'static,
    {
        self.on_login_success = Some(Arc::new(handler));
        self
    }

    pub fn build(self) -> TauriPlugin<R> {
        let config = self.config;
        let on_login_success = self.on_login_success;
        TauriPluginBuilder::new(PLUGIN_NAME)
            .setup(move |app, _api| {
                app.manage(PluginState::from_config_result(config, on_login_success));
                Ok(())
            })
            .invoke_handler(tauri::generate_handler![login, get_access_token, logout])
            .build()
    }
}

pub fn init<R: Runtime>(config: AuthConfig) -> TauriPlugin<R> {
    Builder::new(config).build()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tauri::test::MockRuntime;

    use super::PluginState;
    use crate::auth::{AuthConfig, AuthErrorCode};
    use crate::credentials::{CredentialError, SystemCredentialStore};

    fn config() -> AuthConfig {
        AuthConfig::builder(
            "https://login.example.com",
            "desktop-client",
            "com.example.desktop",
        )
        .build()
        .expect("测试配置应有效")
    }

    #[test]
    fn credential_store_initialization_failure_becomes_managed_state() {
        let state = PluginState::<MockRuntime>::from_config_result_with_store_factory(
            Ok(config()),
            None,
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
    fn invalid_runtime_configuration_becomes_managed_state_without_touching_credentials() {
        let invalid_config = AuthConfig::builder(
            "not a valid issuer",
            "desktop-client",
            "com.example.desktop",
        )
        .build();
        let state = PluginState::<MockRuntime>::from_config_result_with_store_factory(
            invalid_config,
            None,
            |_, _| panic!("配置无效时不得初始化系统凭据库"),
        );

        assert!(matches!(
            state.auth_client(),
            Err(error) if error.code == AuthErrorCode::Configuration
        ));
    }

    #[test]
    fn credential_store_initialization_is_retried_after_a_temporary_failure() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let attempts_for_factory = Arc::clone(&attempts);
        let state = PluginState::<MockRuntime>::from_config_result_with_store_factory(
            Ok(config()),
            None,
            move |service, account| {
                if attempts_for_factory.fetch_add(1, Ordering::SeqCst) == 0 {
                    return Err(CredentialError::Unavailable("凭据库暂时不可用".to_owned()));
                }
                SystemCredentialStore::new(service, account)
            },
        );

        assert!(
            state.auth_client().is_ok(),
            "系统凭据库恢复后，同一个应用实例的重试必须重新初始化认证资源",
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }
}

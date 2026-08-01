use crate::credentials::{
    CredentialError, CredentialStore, ScopedCredentialStore, legacy_scoped_credential_account,
    scoped_credential_account,
};
use crate::exchange::TokenClient;
use crate::issuer::validated_issuer;
use crate::login::{LoginAttempt, LoginCancellation, validated_scopes};
use crate::session::{AccessTokenStatus, SessionManager};
use serde::Serialize;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

const DEFAULT_CALLBACK_TIMEOUT: Duration = Duration::from_secs(120);
const DEFAULT_CREDENTIAL_ACCOUNT: &str = "refresh-token";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AuthErrorCode {
    Configuration,
    Credentials,
    LoginInProgress,
    LoginOptions,
    LoginFailed,
    LoginRequired,
    Retryable,
    RestoreFailed,
    LogoutFailed,
    StaleOperation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, thiserror::Error)]
#[error("{message}")]
#[serde(rename_all = "camelCase")]
pub struct AuthError {
    pub code: AuthErrorCode,
    pub message: &'static str,
}

impl AuthError {
    pub(crate) const fn configuration() -> Self {
        Self::new(AuthErrorCode::Configuration, "桌面端认证配置无效")
    }

    pub(crate) const fn credentials() -> Self {
        Self::new(AuthErrorCode::Credentials, "操作系统凭据库暂时不可用")
    }

    pub(crate) const fn login_in_progress() -> Self {
        Self::new(AuthErrorCode::LoginInProgress, "已有登录流程正在进行")
    }

    pub(crate) const fn login_failed() -> Self {
        Self::new(AuthErrorCode::LoginFailed, "登录未完成，请重试")
    }

    pub(crate) const fn login_required() -> Self {
        Self::new(AuthErrorCode::LoginRequired, "当前没有可用的登录令牌")
    }

    pub(crate) const fn retryable() -> Self {
        Self::new(AuthErrorCode::Retryable, "暂时无法连接认证中心")
    }

    pub(crate) const fn restore_failed() -> Self {
        Self::new(AuthErrorCode::RestoreFailed, "暂时无法恢复登录状态")
    }

    pub(crate) const fn logout_failed() -> Self {
        Self::new(AuthErrorCode::LogoutFailed, "退出登录未完成")
    }

    pub(crate) const fn stale_operation() -> Self {
        Self::new(
            AuthErrorCode::StaleOperation,
            "认证状态已在操作期间发生变化",
        )
    }

    const fn new(code: AuthErrorCode, message: &'static str) -> Self {
        Self { code, message }
    }
}

impl From<CredentialError> for AuthError {
    fn from(_: CredentialError) -> Self {
        Self::credentials()
    }
}

#[derive(Clone, Debug)]
pub struct AuthConfig {
    issuer: String,
    client_id: String,
    scopes: Vec<String>,
    credential_service: String,
    credential_account: String,
    legacy_credential_account: Option<String>,
    callback_timeout: Duration,
}

impl AuthConfig {
    pub fn builder(
        issuer: impl Into<String>,
        client_id: impl Into<String>,
        credential_service: impl Into<String>,
    ) -> AuthConfigBuilder {
        AuthConfigBuilder {
            issuer: issuer.into(),
            client_id: client_id.into(),
            scopes: vec!["openid".to_owned()],
            credential_service: credential_service.into(),
            credential_account: DEFAULT_CREDENTIAL_ACCOUNT.to_owned(),
            callback_timeout: DEFAULT_CALLBACK_TIMEOUT,
        }
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    pub fn credential_service(&self) -> &str {
        &self.credential_service
    }

    pub fn credential_account(&self) -> &str {
        &self.credential_account
    }

    pub fn legacy_credential_account(&self) -> Option<&str> {
        self.legacy_credential_account.as_deref()
    }

    pub fn callback_timeout(&self) -> Duration {
        self.callback_timeout
    }
}

pub struct AuthConfigBuilder {
    issuer: String,
    client_id: String,
    scopes: Vec<String>,
    credential_service: String,
    credential_account: String,
    callback_timeout: Duration,
}

impl AuthConfigBuilder {
    pub fn scopes<I, V>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = V>,
        V: Into<String>,
    {
        self.scopes = scopes.into_iter().map(Into::into).collect();
        self
    }

    pub fn credential_account(mut self, credential_account: impl Into<String>) -> Self {
        self.credential_account = credential_account.into();
        self
    }

    pub fn callback_timeout(mut self, callback_timeout: Duration) -> Self {
        self.callback_timeout = callback_timeout;
        self
    }

    pub fn build(self) -> Result<AuthConfig, AuthError> {
        let issuer = validated_issuer(&self.issuer).map_err(|_| AuthError::configuration())?;
        if self.client_id.trim().is_empty()
            || self.credential_service.trim().is_empty()
            || self.credential_account.trim().is_empty()
            || self.callback_timeout.is_zero()
            || validated_scopes(&self.scopes).is_err()
        {
            return Err(AuthError::configuration());
        }
        let credential_account =
            scoped_credential_account(&self.credential_account, issuer.as_str(), &self.client_id)
                .map_err(|_| AuthError::configuration())?;
        let legacy_credential_account = Some(
            legacy_scoped_credential_account(
                &self.credential_account,
                issuer.as_str(),
                &self.client_id,
            )
            .map_err(|_| AuthError::configuration())?,
        );
        Ok(AuthConfig {
            issuer: issuer.into(),
            client_id: self.client_id,
            scopes: self.scopes,
            credential_service: self.credential_service,
            credential_account,
            legacy_credential_account,
            callback_timeout: self.callback_timeout,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LoginOptions {
    pub prompt: Option<LoginPrompt>,
}

impl LoginOptions {
    pub fn from_prompt(prompt: Option<&str>) -> Result<Self, AuthError> {
        match prompt {
            None => Ok(Self::default()),
            Some("login") => Ok(Self {
                prompt: Some(LoginPrompt::Login),
            }),
            Some(_) => Err(AuthError::new(
                AuthErrorCode::LoginOptions,
                "桌面端登录选项无效",
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoginPrompt {
    Login,
}

impl LoginPrompt {
    fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
        }
    }
}

pub struct AuthClient<S: CredentialStore> {
    config: AuthConfig,
    login_token_client: TokenClient,
    session: SessionManager<ScopedCredentialStore<S>>,
    login_lifecycle: StdMutex<LoginLifecycle>,
}

impl<S: CredentialStore> AuthClient<S> {
    pub fn new(config: AuthConfig, store: S) -> Result<Self, AuthError> {
        let login_token_client =
            TokenClient::new_with_scopes(config.issuer(), config.client_id(), config.scopes())
                .map_err(|_| AuthError::configuration())?;
        let session_token_client =
            TokenClient::new_with_scopes(config.issuer(), config.client_id(), config.scopes())
                .map_err(|_| AuthError::configuration())?;
        let scoped_store = ScopedCredentialStore::new(store, config.scopes())?;
        Ok(Self {
            config,
            login_token_client,
            session: SessionManager::new(session_token_client, scoped_store),
            login_lifecycle: StdMutex::new(LoginLifecycle::default()),
        })
    }

    pub async fn login<F>(&self, options: LoginOptions, open_url: F) -> Result<(), AuthError>
    where
        F: FnOnce(&str) -> Result<(), String> + Send,
    {
        let login_guard = self.begin_login()?;
        let login_generation = self.session.begin_login();
        let prompt = options.prompt.map(LoginPrompt::as_str);
        let attempt = LoginAttempt::start_with_options(
            self.config.issuer(),
            self.config.client_id(),
            self.config.scopes(),
            prompt,
        )
        .map_err(|_| AuthError::login_failed())?;
        login_guard.open_authorization_url(attempt.authorization_url(), open_url)?;
        let tokens = attempt
            .complete_with_cancellation(
                &self.login_token_client,
                self.config.callback_timeout(),
                login_guard.cancellation(),
            )
            .await
            .map_err(|_| AuthError::login_failed())?;
        let accepted = self
            .session
            .accept_login_tokens(login_generation, tokens)
            .await
            .map_err(|_| AuthError::credentials())?;
        if !accepted {
            return Err(AuthError::login_failed());
        }
        Ok(())
    }

    pub async fn access_token(&self) -> Result<String, AuthError> {
        let generation = self.begin_access_token()?;
        let access_token = self.session.access_token().await;
        self.ensure_current_generation(generation)?;
        let access_token = access_token.map_err(|_| AuthError::restore_failed())?;
        match access_token {
            AccessTokenStatus::Available(value) => Ok(value),
            AccessTokenStatus::LoginRequired => Err(AuthError::login_required()),
            AccessTokenStatus::Retryable => Err(AuthError::retryable()),
        }
    }

    pub async fn logout(&self) -> Result<(), AuthError> {
        let logout_guard = self.begin_logout()?;
        let result = self
            .session
            .logout()
            .await
            .map_err(|_| AuthError::logout_failed());
        logout_guard.wait_for_active_login().await;
        result
    }

    fn begin_login(&self) -> Result<LoginGuard<'_>, AuthError> {
        let mut lifecycle = self.login_lifecycle.lock().expect("登录生命周期锁不应中毒");
        if lifecycle.logout_in_progress || lifecycle.active_login.is_some() {
            return Err(AuthError::login_in_progress());
        }
        lifecycle.generation = lifecycle.generation.wrapping_add(1);
        let active_login = Arc::new(ActiveLogin::new());
        lifecycle.active_login = Some(Arc::clone(&active_login));
        Ok(LoginGuard {
            lifecycle: &self.login_lifecycle,
            active_login,
        })
    }

    fn begin_logout(&self) -> Result<LogoutGuard<'_>, AuthError> {
        let mut lifecycle = self.login_lifecycle.lock().expect("登录生命周期锁不应中毒");
        if lifecycle.logout_in_progress {
            return Err(AuthError::logout_failed());
        }
        lifecycle.logout_in_progress = true;
        lifecycle.generation = lifecycle.generation.wrapping_add(1);
        let active_login = lifecycle.active_login.clone();
        if let Some(active_login) = &active_login {
            active_login.cancellation.cancel();
        }
        Ok(LogoutGuard {
            lifecycle: &self.login_lifecycle,
            active_login,
        })
    }

    fn begin_access_token(&self) -> Result<u64, AuthError> {
        let lifecycle = self.login_lifecycle.lock().expect("登录生命周期锁不应中毒");
        if lifecycle.active_login.is_some() {
            return Err(AuthError::login_in_progress());
        }
        if lifecycle.logout_in_progress {
            return Err(AuthError::logout_failed());
        }
        Ok(lifecycle.generation)
    }

    fn ensure_current_generation(&self, generation: u64) -> Result<(), AuthError> {
        let lifecycle = self.login_lifecycle.lock().expect("登录生命周期锁不应中毒");
        if lifecycle.generation != generation
            || lifecycle.active_login.is_some()
            || lifecycle.logout_in_progress
        {
            return Err(AuthError::stale_operation());
        }
        Ok(())
    }
}

#[derive(Default)]
struct LoginLifecycle {
    active_login: Option<Arc<ActiveLogin>>,
    logout_in_progress: bool,
    generation: u64,
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

struct LoginGuard<'a> {
    lifecycle: &'a StdMutex<LoginLifecycle>,
    active_login: Arc<ActiveLogin>,
}

impl LoginGuard<'_> {
    fn cancellation(&self) -> LoginCancellation {
        self.active_login.cancellation.clone()
    }

    fn open_authorization_url<F>(
        &self,
        authorization_url: &str,
        open_url: F,
    ) -> Result<(), AuthError>
    where
        F: FnOnce(&str) -> Result<(), String>,
    {
        let lifecycle = self.lifecycle.lock().expect("登录生命周期锁不应中毒");
        let is_current = lifecycle
            .active_login
            .as_ref()
            .is_some_and(|active| Arc::ptr_eq(active, &self.active_login));
        if lifecycle.logout_in_progress
            || !is_current
            || self.active_login.cancellation.is_cancelled()
        {
            return Err(AuthError::login_failed());
        }
        open_url(authorization_url).map_err(|_| AuthError::login_failed())
    }
}

impl Drop for LoginGuard<'_> {
    fn drop(&mut self) {
        self.active_login.cancellation.cancel();
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

#[cfg(test)]
mod tests {
    use super::{AuthClient, AuthConfig, AuthErrorCode};
    use crate::credentials::{CredentialError, CredentialStore};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    #[test]
    fn cancelled_login_cannot_open_the_authorization_url() {
        let config = AuthConfig::builder(
            "http://localhost:9000",
            "demo-desktop",
            "credential-service",
        )
        .callback_timeout(Duration::from_secs(1))
        .build()
        .expect("合法配置应可创建");
        let client = AuthClient::new(config, EmptyStore).expect("认证客户端应可创建");
        let login_guard = client.begin_login().expect("首次登录应可开始");
        let logout_guard = client.begin_logout().expect("登出应取消活动登录");
        let opened = AtomicBool::new(false);

        let result = login_guard.open_authorization_url("https://auth.example.com", |_| {
            opened.store(true, Ordering::SeqCst);
            Ok(())
        });

        assert_eq!(
            result.expect_err("已取消登录不得再打开系统浏览器").code,
            AuthErrorCode::LoginFailed,
        );
        assert!(!opened.load(Ordering::SeqCst));
        drop(login_guard);
        drop(logout_guard);
    }

    #[test]
    fn dropping_login_guard_cancels_the_background_loopback_listener() {
        let config = AuthConfig::builder(
            "http://localhost:9000",
            "demo-desktop",
            "credential-service",
        )
        .build()
        .expect("合法配置应可创建");
        let client = AuthClient::new(config, EmptyStore).expect("认证客户端应能创建");
        let login_guard = client.begin_login().expect("首次登录应能开始");
        let cancellation = login_guard.cancellation();

        drop(login_guard);

        assert!(
            cancellation.is_cancelled(),
            "登录 future 被丢弃时必须停止已经启动的回环监听"
        );
    }

    struct EmptyStore;

    impl CredentialStore for EmptyStore {
        fn load_refresh_token(&self) -> Result<Option<String>, CredentialError> {
            Ok(None)
        }

        fn save_refresh_token(&self, _refresh_token: &str) -> Result<(), CredentialError> {
            Ok(())
        }

        fn delete_refresh_token(&self) -> Result<(), CredentialError> {
            Ok(())
        }

        fn delete_refresh_token_if_matches(
            &self,
            _expected_refresh_token: &str,
        ) -> Result<bool, CredentialError> {
            Ok(false)
        }
    }
}

use crate::credentials::{
    CredentialError, CredentialRestore, CredentialStore, restore_for_startup,
};
use crate::exchange::{TokenClient, TokenError, TokenResponse};
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};
use tokio::sync::Mutex as AsyncMutex;

const ACCESS_TOKEN_REFRESH_MARGIN: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStatus {
    Authenticated,
    LoginRequired,
    Retryable,
}

#[derive(Clone, PartialEq, Eq)]
pub enum AccessTokenStatus {
    Available(String),
    LoginRequired,
    Retryable,
}

impl std::fmt::Debug for AccessTokenStatus {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Available(_) => formatter
                .debug_tuple("Available")
                .field(&"[REDACTED]")
                .finish(),
            Self::LoginRequired => formatter.write_str("LoginRequired"),
            Self::Retryable => formatter.write_str("Retryable"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoginGeneration(u64);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SessionError {
    #[error(transparent)]
    Credential(#[from] CredentialError),
    #[error(transparent)]
    Token(#[from] TokenError),
}

pub struct SessionManager<S: CredentialStore> {
    token_client: TokenClient,
    store: S,
    access_token: StdMutex<Option<InMemoryAccessToken>>,
    refresh_gate: AsyncMutex<()>,
    login_generation: AtomicU64,
}

struct InMemoryAccessToken {
    value: String,
    expires_at: SystemTime,
}

impl InMemoryAccessToken {
    fn from_response(tokens: TokenResponse) -> Self {
        Self::from_response_at(tokens, SystemTime::now())
    }

    fn from_response_at(tokens: TokenResponse, now: SystemTime) -> Self {
        let expires_at = now
            .checked_add(Duration::from_secs(tokens.expires_in))
            .unwrap_or(now);
        Self {
            value: tokens.access_token,
            expires_at,
        }
    }

    fn is_valid(&self) -> bool {
        self.is_valid_at(SystemTime::now())
    }

    fn is_valid_at(&self, now: SystemTime) -> bool {
        now < self.expires_at
    }

    fn is_fresh(&self) -> bool {
        self.is_fresh_at(SystemTime::now())
    }

    fn is_fresh_at(&self, now: SystemTime) -> bool {
        now.checked_add(ACCESS_TOKEN_REFRESH_MARGIN)
            .is_some_and(|refresh_deadline| refresh_deadline < self.expires_at)
    }
}

impl<S: CredentialStore> SessionManager<S> {
    pub fn new(token_client: TokenClient, store: S) -> Self {
        Self {
            token_client,
            store,
            access_token: StdMutex::new(None),
            refresh_gate: AsyncMutex::new(()),
            login_generation: AtomicU64::new(0),
        }
    }

    pub fn is_authenticated(&self) -> bool {
        self.current_access_token().is_some()
    }

    pub async fn access_token(&self) -> Result<AccessTokenStatus, SessionError> {
        let status = self.restore().await?;
        let current = self
            .current_access_token()
            .map(AccessTokenStatus::Available);
        match status {
            AuthStatus::Authenticated => Ok(current.unwrap_or(AccessTokenStatus::Retryable)),
            AuthStatus::LoginRequired => Ok(AccessTokenStatus::LoginRequired),
            AuthStatus::Retryable => Ok(current.unwrap_or(AccessTokenStatus::Retryable)),
        }
    }

    pub fn begin_login(&self) -> LoginGeneration {
        LoginGeneration(self.login_generation.load(Ordering::Acquire))
    }

    pub async fn accept_login_tokens(
        &self,
        generation: LoginGeneration,
        tokens: TokenResponse,
    ) -> Result<bool, SessionError> {
        let _guard = self.refresh_gate.lock().await;
        if generation.0 != self.login_generation.load(Ordering::Acquire) {
            return Ok(false);
        }
        self.accept_tokens_unlocked(tokens)?;
        Ok(true)
    }

    fn accept_tokens_unlocked(&self, tokens: TokenResponse) -> Result<(), SessionError> {
        self.store.save_refresh_token(&tokens.refresh_token)?;
        let access_token = InMemoryAccessToken::from_response(tokens);
        *self
            .access_token
            .lock()
            .expect("access token 内存锁不应中毒") = Some(access_token);
        Ok(())
    }

    pub async fn restore(&self) -> Result<AuthStatus, SessionError> {
        let _guard = self.refresh_gate.lock().await;
        if self
            .access_token
            .lock()
            .expect("access token 内存锁不应中毒")
            .as_ref()
            .is_some_and(InMemoryAccessToken::is_fresh)
        {
            return Ok(AuthStatus::Authenticated);
        }

        let CredentialRestore::Available(refresh_token) = restore_for_startup(&self.store) else {
            self.clear_access_token();
            return Ok(AuthStatus::LoginRequired);
        };

        match self.token_client.refresh(&refresh_token).await {
            Ok(tokens) => {
                self.accept_tokens_unlocked(tokens)?;
                Ok(AuthStatus::Authenticated)
            }
            Err(TokenError::ReauthenticationRequired) => {
                if self.store.delete_refresh_token_if_matches(&refresh_token)? {
                    self.clear_access_token();
                    Ok(AuthStatus::LoginRequired)
                } else {
                    Ok(AuthStatus::Retryable)
                }
            }
            Err(TokenError::Network(_)) => Ok(AuthStatus::Retryable),
            Err(error) => Err(SessionError::Token(error)),
        }
    }

    pub async fn logout(&self) -> Result<(), SessionError> {
        self.login_generation.fetch_add(1, Ordering::AcqRel);
        let _guard = self.refresh_gate.lock().await;
        self.store.delete_refresh_token()?;
        self.clear_access_token();
        Ok(())
    }

    fn clear_access_token(&self) {
        *self
            .access_token
            .lock()
            .expect("access token 内存锁不应中毒") = None;
    }

    fn current_access_token(&self) -> Option<String> {
        self.access_token
            .lock()
            .expect("access token 内存锁不应中毒")
            .as_ref()
            .filter(|token| token.is_valid())
            .map(|token| token.value.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::{AccessTokenStatus, AuthStatus, InMemoryAccessToken, SessionError, SessionManager};
    use crate::credentials::{CredentialError, CredentialStore};
    use crate::exchange::{TokenClient, TokenError, TokenResponse};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, UNIX_EPOCH};
    use tiny_http::{Header, Response, Server, StatusCode};

    #[tokio::test]
    async fn completing_login_persists_only_refresh_token_and_keeps_access_in_memory() {
        let store = Arc::new(FakeStore::default());
        let manager = SessionManager::new(unused_token_client(), Arc::clone(&store));

        accept_current_login_tokens(&manager, tokens("access-one", "refresh-one")).await;

        assert!(manager.is_authenticated());
        assert_eq!(
            manager.access_token().await.expect("访问令牌应可取得"),
            AccessTokenStatus::Available("access-one".to_owned()),
        );
        assert_eq!(store.value(), Some("refresh-one".to_owned()));
    }

    #[test]
    fn access_token_status_debug_output_redacts_the_token() {
        let output = format!(
            "{:?}",
            AccessTokenStatus::Available("access-secret".to_owned())
        );

        assert_eq!(output, "Available(\"[REDACTED]\")");
        assert!(!output.contains("access-secret"));
    }

    #[tokio::test]
    async fn expired_access_token_is_not_reported_as_authenticated() {
        let store = Arc::new(FakeStore::default());
        let manager = SessionManager::new(unused_token_client(), Arc::clone(&store));

        accept_current_login_tokens(
            &manager,
            tokens_with_expiry("expired-access", "refresh-one", 0),
        )
        .await;

        assert!(!manager.is_authenticated());
    }

    #[test]
    fn access_token_expiry_uses_wall_clock_time_across_system_sleep() {
        let issued_at = UNIX_EPOCH + Duration::from_secs(10_000);
        let token = InMemoryAccessToken::from_response_at(
            tokens_with_expiry("access-one", "refresh-one", 900),
            issued_at,
        );

        assert!(token.is_valid_at(issued_at + Duration::from_secs(899)));
        assert!(!token.is_valid_at(issued_at + Duration::from_secs(900)));
        assert!(token.is_fresh_at(issued_at + Duration::from_secs(869)));
        assert!(!token.is_fresh_at(issued_at + Duration::from_secs(870)));
    }

    #[tokio::test]
    async fn valid_access_token_avoids_unnecessary_refresh_rotation() {
        let store = Arc::new(FakeStore::default());
        let manager = SessionManager::new(unused_token_client(), Arc::clone(&store));
        accept_current_login_tokens(&manager, tokens("access-one", "refresh-one")).await;

        assert_eq!(
            manager.restore().await.expect("有效会话不需要访问网络"),
            AuthStatus::Authenticated,
        );
        assert_eq!(store.value(), Some("refresh-one".to_owned()));
    }

    #[tokio::test]
    async fn near_expiry_access_token_refreshes_and_rotates_the_credential() {
        let issuer = fake_token_endpoint(
            200,
            r#"{"access_token":"access-two","refresh_token":"refresh-two","expires_in":900}"#,
        );
        let store = Arc::new(FakeStore::default());
        let manager = SessionManager::new(
            TokenClient::new(&issuer, "demo-desktop").expect("客户端应合法"),
            Arc::clone(&store),
        );
        accept_current_login_tokens(&manager, tokens_with_expiry("access-one", "refresh-one", 1))
            .await;

        assert_eq!(
            manager.restore().await.expect("临近过期会话应刷新"),
            AuthStatus::Authenticated,
        );
        assert_eq!(
            manager
                .access_token()
                .await
                .expect("轮换后的访问令牌应可取得"),
            AccessTokenStatus::Available("access-two".to_owned()),
        );
        assert_eq!(store.value(), Some("refresh-two".to_owned()));
    }

    #[tokio::test]
    async fn concurrent_restore_serializes_refresh_token_rotation() {
        let (issuer, request_count) = fake_rotating_token_endpoint();
        let store = Arc::new(FakeStore::with_value("refresh-one"));
        let manager = Arc::new(SessionManager::new(
            TokenClient::new(&issuer, "demo-desktop").expect("客户端应合法"),
            Arc::clone(&store),
        ));

        let (first, second) = tokio::join!(manager.restore(), manager.restore());

        assert_eq!(first.expect("首次恢复应成功"), AuthStatus::Authenticated);
        assert_eq!(
            second.expect("并发恢复应复用首次结果"),
            AuthStatus::Authenticated
        );
        assert_eq!(store.value(), Some("refresh-two".to_owned()));
        assert_eq!(
            request_count
                .recv_timeout(Duration::from_secs(1))
                .expect("假端点应报告请求数"),
            1,
            "同一轮换凭据只能发送一次刷新请求",
        );
    }

    #[tokio::test]
    async fn startup_refreshes_and_persists_the_rotated_refresh_token() {
        let issuer = fake_token_endpoint(
            200,
            r#"{"access_token":"access-two","refresh_token":"refresh-two","expires_in":900}"#,
        );
        let store = Arc::new(FakeStore::with_value("refresh-one"));
        let manager = SessionManager::new(
            TokenClient::new(&issuer, "demo-desktop").expect("客户端应合法"),
            Arc::clone(&store),
        );

        assert_eq!(
            manager.restore().await.expect("启动恢复应成功"),
            AuthStatus::Authenticated
        );
        assert!(manager.is_authenticated());
        assert_eq!(store.value(), Some("refresh-two".to_owned()));
    }

    #[tokio::test]
    async fn revoked_refresh_token_is_deleted_and_requires_login() {
        let issuer = fake_token_endpoint(
            400,
            r#"{"error":"invalid_grant","error_description":"revoked"}"#,
        );
        let store = Arc::new(FakeStore::with_value("revoked-refresh"));
        let manager = SessionManager::new(
            TokenClient::new(&issuer, "demo-desktop").expect("客户端应合法"),
            Arc::clone(&store),
        );

        assert_eq!(
            manager.restore().await.expect("凭据失效不是基础设施错误"),
            AuthStatus::LoginRequired
        );
        assert!(!manager.is_authenticated());
        assert_eq!(store.value(), None);
    }

    #[tokio::test]
    async fn invalid_client_is_a_configuration_error_and_preserves_the_refresh_token() {
        let issuer = fake_token_endpoint(
            400,
            r#"{"error":"invalid_client","error_description":"client configuration unavailable"}"#,
        );
        let store = Arc::new(FakeStore::with_value("still-valid-refresh"));
        let manager = SessionManager::new(
            TokenClient::new(&issuer, "demo-desktop").expect("客户端应合法"),
            Arc::clone(&store),
        );

        let result = manager.restore().await;

        assert!(
            matches!(result, Err(SessionError::Token(TokenError::Protocol(_)))),
            "客户端配置错误必须上报协议错误，实际为 {result:?}",
        );
        assert_eq!(
            store.value(),
            Some("still-valid-refresh".to_owned()),
            "客户端配置恢复后仍可能继续使用原 refresh token，不得删除",
        );
    }

    #[tokio::test]
    async fn network_failure_is_retryable_and_preserves_the_refresh_token() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("应占到临时端口");
        let issuer = format!("http://{}", listener.local_addr().expect("应有地址"));
        drop(listener);
        let store = Arc::new(FakeStore::with_value("still-valid-refresh"));
        let manager = SessionManager::new(
            TokenClient::new(&issuer, "demo-desktop").expect("客户端应合法"),
            Arc::clone(&store),
        );

        assert_eq!(
            manager.restore().await.expect("网络错误应转成可重试状态"),
            AuthStatus::Retryable
        );
        assert!(!manager.is_authenticated());
        assert_eq!(store.value(), Some("still-valid-refresh".to_owned()));
    }

    #[tokio::test]
    async fn access_token_reports_retryable_when_network_is_down_and_no_token_is_valid() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("应占到临时端口");
        let issuer = format!("http://{}", listener.local_addr().expect("应有地址"));
        drop(listener);
        let manager = SessionManager::new(
            TokenClient::new(&issuer, "demo-desktop").expect("客户端应合法"),
            Arc::new(FakeStore::with_value("still-valid-refresh")),
        );

        assert_eq!(
            manager.access_token().await.expect("网络错误应成为状态"),
            AccessTokenStatus::Retryable
        );
    }

    #[tokio::test]
    async fn logout_clears_memory_and_deletes_the_vault_entry() {
        let store = Arc::new(FakeStore::default());
        let manager = SessionManager::new(unused_token_client(), Arc::clone(&store));
        accept_current_login_tokens(&manager, tokens("access-one", "refresh-one")).await;

        manager.logout().await.expect("登出应成功");

        assert!(!manager.is_authenticated());
        assert_eq!(store.value(), None);
    }

    #[tokio::test]
    async fn logout_invalidates_an_unfinished_login_before_it_can_persist_tokens() {
        let store = Arc::new(FakeStore::default());
        let manager = SessionManager::new(unused_token_client(), Arc::clone(&store));
        let login_generation = manager.begin_login();

        manager.logout().await.expect("登出应成功");
        let accepted = manager
            .accept_login_tokens(login_generation, tokens("stale-access", "stale-refresh"))
            .await
            .expect("取消旧登录不应成为凭据库错误");

        assert!(!accepted, "登出前开始的登录结果必须被丢弃");
        assert!(!manager.is_authenticated());
        assert_eq!(store.value(), None);
    }

    async fn accept_current_login_tokens<S: CredentialStore>(
        manager: &SessionManager<S>,
        tokens: TokenResponse,
    ) {
        assert!(
            manager
                .accept_login_tokens(manager.begin_login(), tokens)
                .await
                .expect("登录令牌应可接纳"),
        );
    }

    fn tokens(access_token: &str, refresh_token: &str) -> TokenResponse {
        tokens_with_expiry(access_token, refresh_token, 900)
    }

    fn tokens_with_expiry(
        access_token: &str,
        refresh_token: &str,
        expires_in: u64,
    ) -> TokenResponse {
        TokenResponse {
            access_token: access_token.to_owned(),
            refresh_token: refresh_token.to_owned(),
            id_token: None,
            expires_in,
        }
    }

    fn unused_token_client() -> TokenClient {
        TokenClient::new("http://127.0.0.1:9", "demo-desktop").expect("客户端应合法")
    }

    fn fake_token_endpoint(status: u16, body: &'static str) -> String {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("假令牌端点应能绑定");
        let address = listener.local_addr().expect("假令牌端点应有地址");
        let server = Server::from_listener(listener, None).expect("假令牌端点应能启动");

        thread::spawn(move || {
            let request = server
                .recv_timeout(Duration::from_secs(2))
                .expect("假令牌端点监听不应失败")
                .expect("应收到刷新请求");
            let content_type = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                .expect("静态响应头应合法");
            request
                .respond(
                    Response::from_string(body)
                        .with_status_code(StatusCode(status))
                        .with_header(content_type),
                )
                .expect("假令牌响应应可返回");
        });

        format!("http://{address}")
    }

    fn fake_rotating_token_endpoint() -> (String, std::sync::mpsc::Receiver<usize>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("假令牌端点应能绑定");
        let address = listener.local_addr().expect("假令牌端点应有地址");
        let server = Server::from_listener(listener, None).expect("假令牌端点应能启动");
        let (sender, receiver) = std::sync::mpsc::channel();

        thread::spawn(move || {
            let first = server.recv().expect("应收到首次刷新请求");
            thread::sleep(Duration::from_millis(50));
            respond(
                first,
                200,
                r#"{"access_token":"access-two","refresh_token":"refresh-two","expires_in":900}"#,
            );

            let mut count = 1;
            if let Some(second) = server
                .recv_timeout(Duration::from_millis(250))
                .expect("并发请求探测不应失败")
            {
                count += 1;
                respond(
                    second,
                    400,
                    r#"{"error":"invalid_grant","error_description":"rotated"}"#,
                );
            }
            sender.send(count).expect("请求数应可发送");
        });

        (format!("http://{address}"), receiver)
    }

    fn respond(request: tiny_http::Request, status: u16, body: &'static str) {
        let content_type = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
            .expect("静态响应头应合法");
        request
            .respond(
                Response::from_string(body)
                    .with_status_code(StatusCode(status))
                    .with_header(content_type),
            )
            .expect("假令牌响应应可返回");
    }

    #[derive(Default)]
    struct FakeStore {
        value: Mutex<Option<String>>,
    }

    impl FakeStore {
        fn with_value(value: &str) -> Self {
            Self {
                value: Mutex::new(Some(value.to_owned())),
            }
        }

        fn value(&self) -> Option<String> {
            self.value.lock().expect("测试锁不应中毒").clone()
        }
    }

    impl CredentialStore for Arc<FakeStore> {
        fn load_refresh_token(&self) -> Result<Option<String>, CredentialError> {
            Ok(self.value())
        }

        fn save_refresh_token(&self, refresh_token: &str) -> Result<(), CredentialError> {
            *self.value.lock().expect("测试锁不应中毒") = Some(refresh_token.to_owned());
            Ok(())
        }

        fn delete_refresh_token(&self) -> Result<(), CredentialError> {
            *self.value.lock().expect("测试锁不应中毒") = None;
            Ok(())
        }

        fn delete_refresh_token_if_matches(
            &self,
            expected_refresh_token: &str,
        ) -> Result<bool, CredentialError> {
            let mut value = self.value.lock().expect("测试锁不应中毒");
            if value.as_deref() != Some(expected_refresh_token) {
                return Ok(false);
            }
            *value = None;
            Ok(true)
        }
    }
}

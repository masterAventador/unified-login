use crate::credentials::{
    CredentialError, CredentialRestore, CredentialStore, restore_for_startup,
};
use crate::exchange::{TokenClient, TokenError, TokenResponse};
use std::sync::Mutex;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthStatus {
    Authenticated,
    LoginRequired,
    Retryable,
}

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
    access_token: Mutex<Option<String>>,
}

impl<S: CredentialStore> SessionManager<S> {
    pub fn new(token_client: TokenClient, store: S) -> Self {
        Self {
            token_client,
            store,
            access_token: Mutex::new(None),
        }
    }

    pub fn is_authenticated(&self) -> bool {
        self.access_token
            .lock()
            .expect("access token 内存锁不应中毒")
            .is_some()
    }

    pub fn accept_tokens(&self, tokens: TokenResponse) -> Result<(), SessionError> {
        self.store.save_refresh_token(&tokens.refresh_token)?;
        *self
            .access_token
            .lock()
            .expect("access token 内存锁不应中毒") = Some(tokens.access_token);
        Ok(())
    }

    pub async fn restore(&self) -> Result<AuthStatus, SessionError> {
        let CredentialRestore::Available(refresh_token) = restore_for_startup(&self.store) else {
            return Ok(AuthStatus::LoginRequired);
        };

        match self.token_client.refresh(&refresh_token).await {
            Ok(tokens) => {
                self.accept_tokens(tokens)?;
                Ok(AuthStatus::Authenticated)
            }
            Err(TokenError::ReauthenticationRequired) => {
                self.store.delete_refresh_token()?;
                *self
                    .access_token
                    .lock()
                    .expect("access token 内存锁不应中毒") = None;
                Ok(AuthStatus::LoginRequired)
            }
            Err(TokenError::Network(_)) => Ok(AuthStatus::Retryable),
            Err(error) => Err(SessionError::Token(error)),
        }
    }

    pub fn logout(&self) -> Result<(), SessionError> {
        self.store.delete_refresh_token()?;
        *self
            .access_token
            .lock()
            .expect("access token 内存锁不应中毒") = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{AuthStatus, SessionManager};
    use crate::credentials::{CredentialError, CredentialStore};
    use crate::exchange::{TokenClient, TokenResponse};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;
    use tiny_http::{Header, Response, Server, StatusCode};

    #[test]
    fn completing_login_persists_only_refresh_token_and_keeps_access_in_memory() {
        let store = Arc::new(FakeStore::default());
        let manager = SessionManager::new(unused_token_client(), Arc::clone(&store));

        manager
            .accept_tokens(tokens("access-one", "refresh-one"))
            .expect("登录令牌应可接纳");

        assert!(manager.is_authenticated());
        assert_eq!(store.value(), Some("refresh-one".to_owned()));
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

    #[test]
    fn logout_clears_memory_and_deletes_the_vault_entry() {
        let store = Arc::new(FakeStore::default());
        let manager = SessionManager::new(unused_token_client(), Arc::clone(&store));
        manager
            .accept_tokens(tokens("access-one", "refresh-one"))
            .expect("登录令牌应可接纳");

        manager.logout().expect("登出应成功");

        assert!(!manager.is_authenticated());
        assert_eq!(store.value(), None);
    }

    fn tokens(access_token: &str, refresh_token: &str) -> TokenResponse {
        TokenResponse {
            access_token: access_token.to_owned(),
            refresh_token: refresh_token.to_owned(),
            id_token: None,
            expires_in: 900,
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
    }
}

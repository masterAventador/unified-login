use crate::exchange::{TokenClient, TokenError, TokenResponse};
use crate::issuer::validated_issuer;
use crate::loopback::{LoopbackError, LoopbackServer};
use crate::pkce::{PkcePair, RandomError, generate_pkce, generate_state};
use std::time::Duration;
use tokio::sync::watch;

#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    #[error(transparent)]
    Loopback(#[from] LoopbackError),
    #[error(transparent)]
    Random(#[from] RandomError),
    #[error(transparent)]
    Token(#[from] TokenError),
    #[error("OAuth 配置无效: {0}")]
    Configuration(String),
    #[error("等待认证回调的后台任务失败: {0}")]
    CallbackTask(String),
}

pub struct LoginAttempt {
    loopback: LoopbackServer,
    pkce: PkcePair,
    state: String,
    authorization_url: String,
    redirect_uri: String,
}

#[derive(Clone)]
pub struct LoginCancellation {
    cancelled: watch::Sender<bool>,
}

impl LoginCancellation {
    pub fn new() -> Self {
        let (cancelled, _) = watch::channel(false);
        Self { cancelled }
    }

    pub fn cancel(&self) {
        self.cancelled.send_replace(true);
    }

    pub fn is_cancelled(&self) -> bool {
        *self.cancelled.borrow()
    }

    async fn cancelled(&self) {
        let mut cancelled = self.cancelled.subscribe();
        while !*cancelled.borrow_and_update() {
            if cancelled.changed().await.is_err() {
                return;
            }
        }
    }
}

impl Default for LoginCancellation {
    fn default() -> Self {
        Self::new()
    }
}

impl LoginAttempt {
    pub fn start(issuer: &str, client_id: &str) -> Result<Self, LoginError> {
        Self::start_with_prompt(issuer, client_id, None)
    }

    pub fn start_with_prompt(
        issuer: &str,
        client_id: &str,
        prompt: Option<&str>,
    ) -> Result<Self, LoginError> {
        if !matches!(prompt, None | Some("login")) {
            return Err(LoginError::Configuration(
                "prompt 只允许使用 login".to_owned(),
            ));
        }
        let loopback = LoopbackServer::bind()?;
        let redirect_uri = loopback.redirect_uri();
        let pkce = generate_pkce()?;
        let state = generate_state()?;
        let issuer = validated_issuer(issuer).map_err(LoginError::Configuration)?;
        let mut authorization_url = issuer
            .join("oauth2/authorize")
            .map_err(|error| LoginError::Configuration(format!("授权端点 URL 无效: {error}")))?;
        let mut query = authorization_url.query_pairs_mut();
        query
            .append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("scope", "openid")
            .append_pair("code_challenge", &pkce.challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("state", &state);
        if let Some(prompt) = prompt {
            query.append_pair("prompt", prompt);
        }
        drop(query);

        Ok(Self {
            loopback,
            pkce,
            state,
            authorization_url: authorization_url.into(),
            redirect_uri,
        })
    }

    pub fn authorization_url(&self) -> &str {
        &self.authorization_url
    }

    pub fn redirect_uri(&self) -> &str {
        &self.redirect_uri
    }

    pub async fn complete(
        self,
        token_client: &TokenClient,
        timeout: Duration,
    ) -> Result<TokenResponse, LoginError> {
        self.complete_with_cancellation(token_client, timeout, LoginCancellation::new())
            .await
    }

    pub async fn complete_with_cancellation(
        self,
        token_client: &TokenClient,
        timeout: Duration,
        cancellation: LoginCancellation,
    ) -> Result<TokenResponse, LoginError> {
        let Self {
            loopback,
            pkce,
            state,
            redirect_uri,
            ..
        } = self;
        let callback_cancellation = cancellation.clone();
        let callback = tokio::task::spawn_blocking(move || {
            loopback
                .wait_for_callback_until(&state, timeout, || callback_cancellation.is_cancelled())
        })
        .await
        .map_err(|error| LoginError::CallbackTask(error.to_string()))??;

        tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(LoginError::Loopback(LoopbackError::Cancelled)),
            result = token_client.exchange_code(&callback.code, &pkce.verifier, &redirect_uri) => {
                result.map_err(LoginError::from)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{LoginAttempt, LoginCancellation, LoginError};
    use crate::exchange::TokenClient;
    use crate::loopback::LoopbackError;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::sync::mpsc::{self, Receiver};
    use std::thread;
    use std::time::Duration;
    use tiny_http::{Header, Response, Server, StatusCode};
    use url::Url;

    #[test]
    fn authorization_url_contains_state_pkce_and_runtime_loopback_redirect() {
        let attempt =
            LoginAttempt::start("http://localhost:9000", "demo-desktop").expect("登录尝试应能创建");
        let authorization_url = Url::parse(attempt.authorization_url()).expect("授权地址应合法");
        let query = authorization_url
            .query_pairs()
            .collect::<std::collections::HashMap<_, _>>();

        assert_eq!(
            authorization_url.as_str().split('?').next(),
            Some("http://localhost:9000/oauth2/authorize")
        );
        assert_eq!(
            query.get("response_type").map(|value| value.as_ref()),
            Some("code")
        );
        assert_eq!(
            query.get("client_id").map(|value| value.as_ref()),
            Some("demo-desktop")
        );
        assert_eq!(
            query.get("scope").map(|value| value.as_ref()),
            Some("openid")
        );
        assert_eq!(
            query
                .get("code_challenge_method")
                .map(|value| value.as_ref()),
            Some("S256")
        );
        assert_eq!(
            query.get("redirect_uri").map(|value| value.as_ref()),
            Some(attempt.redirect_uri())
        );
        assert_eq!(query.get("state").map(|value| value.len()), Some(43));
        assert_eq!(
            query.get("code_challenge").map(|value| value.len()),
            Some(43)
        );
    }

    #[test]
    fn explicit_login_prompt_is_included_in_the_authorization_url() {
        let attempt =
            LoginAttempt::start_with_prompt("http://localhost:9000", "demo-desktop", Some("login"))
                .expect("强制登录尝试应能创建");
        let authorization_url = Url::parse(attempt.authorization_url()).expect("授权地址应合法");

        assert_eq!(
            authorization_url
                .query_pairs()
                .find_map(|(name, value)| (name == "prompt").then(|| value.into_owned())),
            Some("login".to_owned())
        );
    }

    #[test]
    fn plain_http_issuer_is_allowed_only_for_loopback_development() {
        for issuer in ["http://auth.example.com", "http://192.0.2.10:9000"] {
            assert!(
                matches!(
                    LoginAttempt::start(issuer, "demo-desktop"),
                    Err(LoginError::Configuration(_))
                ),
                "非回环 HTTP issuer 必须被拒绝: {issuer}",
            );
        }

        LoginAttempt::start("https://auth.example.com", "demo-desktop")
            .expect("生产 HTTPS issuer 应被接受");
        LoginAttempt::start("http://127.0.0.1:9000", "demo-desktop")
            .expect("本地回环 HTTP issuer 应被接受");
    }

    #[tokio::test]
    async fn forged_state_is_rejected_before_any_token_request() {
        let (issuer, token_request_seen) = fake_token_endpoint();
        let token_client = TokenClient::new(&issuer, "demo-desktop").expect("令牌客户端应能创建");
        let attempt = LoginAttempt::start(&issuer, "demo-desktop").expect("登录尝试应能创建");
        let callback_address = callback_address(attempt.redirect_uri());

        let forged_callback = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            let response = send_get(
                callback_address,
                "/callback?code=attacker-code&state=forged-state",
            );
            assert!(response.starts_with("HTTP/1.1 400"));
        });

        let result = attempt
            .complete(&token_client, Duration::from_secs(2))
            .await;

        assert!(
            matches!(
                result,
                Err(LoginError::Loopback(LoopbackError::StateMismatch))
            ),
            "伪造 state 必须以明确的校验错误结束，实际为 {result:?}"
        );
        forged_callback.join().expect("伪造回调线程不应 panic");
        assert!(
            !token_request_seen
                .recv_timeout(Duration::from_secs(1))
                .expect("假令牌端点应报告是否收到请求"),
            "state 不匹配时授权码必须被丢弃，绝不能请求令牌端点"
        );
    }

    #[tokio::test]
    async fn cancellation_stops_the_loopback_listener_without_waiting_for_timeout() {
        let token_client =
            TokenClient::new("http://127.0.0.1:9", "demo-desktop").expect("令牌客户端应能创建");
        let attempt =
            LoginAttempt::start("http://localhost:9000", "demo-desktop").expect("登录尝试应能创建");
        let callback_address = callback_address(attempt.redirect_uri());
        let cancellation = LoginCancellation::new();
        let cancellation_for_task = cancellation.clone();
        let completion = tokio::spawn(async move {
            attempt
                .complete_with_cancellation(
                    &token_client,
                    Duration::from_millis(250),
                    cancellation_for_task,
                )
                .await
        });

        thread::sleep(Duration::from_millis(20));
        cancellation.cancel();
        let result = completion.await.expect("取消任务不应 panic");

        assert!(matches!(
            result,
            Err(LoginError::Loopback(LoopbackError::Cancelled))
        ));
        assert!(
            TcpStream::connect_timeout(&callback_address, Duration::from_millis(200)).is_err(),
            "取消后必须立即关闭临时回环监听端口"
        );
    }

    fn fake_token_endpoint() -> (String, Receiver<bool>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("假令牌端点应能绑定");
        let address = listener.local_addr().expect("假令牌端点应有地址");
        let server = Server::from_listener(listener, None).expect("假令牌端点应能启动");
        let (sender, receiver) = mpsc::channel();

        thread::spawn(move || {
            let request = server
                .recv_timeout(Duration::from_millis(500))
                .expect("假令牌端点监听不应失败");
            let Some(mut request) = request else {
                sender.send(false).expect("结果应可发送");
                return;
            };

            let mut body = String::new();
            request
                .as_reader()
                .read_to_string(&mut body)
                .expect("令牌请求体应可读取");
            sender.send(true).expect("结果应可发送");
            let content_type = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                .expect("静态响应头应合法");
            request
                .respond(
                    Response::from_string(
                        r#"{"access_token":"stolen","refresh_token":"stolen","expires_in":900}"#,
                    )
                    .with_status_code(StatusCode(200))
                    .with_header(content_type),
                )
                .expect("假令牌响应应可返回");
        });

        (format!("http://{address}"), receiver)
    }

    fn callback_address(redirect_uri: &str) -> SocketAddr {
        let url = Url::parse(redirect_uri).expect("回调地址应合法");
        SocketAddr::from(([127, 0, 0, 1], url.port().expect("回调地址应包含临时端口")))
    }

    fn send_get(address: SocketAddr, target: &str) -> String {
        let mut stream = TcpStream::connect(address).expect("测试客户端应连上回环服务");
        write!(
            stream,
            "GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            address.port()
        )
        .expect("测试请求应写入");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("测试响应应可读取");
        response
    }
}

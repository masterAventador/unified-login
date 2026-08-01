use crate::issuer::{issuer_uses_loopback, validated_issuer};
use reqwest::StatusCode;
use serde::Deserialize;
use std::time::Duration;
use url::Url;

const TOKEN_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const TOKEN_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, PartialEq, Eq)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub id_token: Option<String>,
    pub expires_in: u64,
}

impl std::fmt::Debug for TokenResponse {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TokenResponse")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("id_token", &self.id_token.as_ref().map(|_| "[REDACTED]"))
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TokenError {
    #[error("认证中心暂时无法连接: {0}")]
    Network(String),
    #[error("登录凭据已失效，需要重新登录")]
    ReauthenticationRequired,
    #[error("认证中心返回了无效响应: {0}")]
    Protocol(String),
}

pub struct TokenClient {
    endpoint: Url,
    client_id: String,
    http: reqwest::Client,
    expected_scopes: Option<Vec<String>>,
}

impl TokenClient {
    pub fn new(issuer: &str, client_id: &str) -> Result<Self, TokenError> {
        Self::new_with_options(issuer, client_id, TOKEN_REQUEST_TIMEOUT, None)
    }

    pub fn new_with_scopes(
        issuer: &str,
        client_id: &str,
        scopes: &[String],
    ) -> Result<Self, TokenError> {
        if scopes.is_empty() || scopes.iter().any(String::is_empty) {
            return Err(TokenError::Protocol("scope 不能为空".to_owned()));
        }
        let mut expected_scopes = scopes.to_vec();
        expected_scopes.sort_unstable();
        expected_scopes.dedup();
        Self::new_with_options(
            issuer,
            client_id,
            TOKEN_REQUEST_TIMEOUT,
            Some(expected_scopes),
        )
    }

    #[cfg(test)]
    fn new_with_request_timeout(
        issuer: &str,
        client_id: &str,
        request_timeout: Duration,
    ) -> Result<Self, TokenError> {
        Self::new_with_options(issuer, client_id, request_timeout, None)
    }

    fn new_with_options(
        issuer: &str,
        client_id: &str,
        request_timeout: Duration,
        expected_scopes: Option<Vec<String>>,
    ) -> Result<Self, TokenError> {
        let issuer = validated_issuer(issuer).map_err(TokenError::Protocol)?;
        let bypass_proxy = issuer_uses_loopback(&issuer);
        let endpoint = issuer
            .join("oauth2/token")
            .map_err(|error| TokenError::Protocol(format!("令牌端点 URL 无效: {error}")))?;
        if client_id.is_empty() {
            return Err(TokenError::Protocol("client_id 不能为空".to_owned()));
        }
        let mut http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(request_timeout)
            .connect_timeout(request_timeout.min(TOKEN_CONNECT_TIMEOUT));
        if bypass_proxy {
            http = http.no_proxy();
        }
        let http = http
            .build()
            .map_err(|error| TokenError::Network(format!("HTTP 客户端初始化失败: {error}")))?;

        Ok(Self {
            endpoint,
            client_id: client_id.to_owned(),
            http,
            expected_scopes,
        })
    }

    pub async fn exchange_code(
        &self,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
    ) -> Result<TokenResponse, TokenError> {
        self.request(
            &[
                ("grant_type", "authorization_code"),
                ("client_id", &self.client_id),
                ("code", code),
                ("code_verifier", verifier),
                ("redirect_uri", redirect_uri),
            ],
            RequestKind::AuthorizationCode,
        )
        .await
    }

    pub async fn refresh(&self, refresh_token: &str) -> Result<TokenResponse, TokenError> {
        self.request(
            &[
                ("grant_type", "refresh_token"),
                ("client_id", &self.client_id),
                ("refresh_token", refresh_token),
            ],
            RequestKind::Refresh,
        )
        .await
    }

    async fn request(
        &self,
        form: &[(&str, &str)],
        request_kind: RequestKind,
    ) -> Result<TokenResponse, TokenError> {
        let response = self
            .http
            .post(self.endpoint.clone())
            .form(form)
            .send()
            .await
            .map_err(|error| TokenError::Network(error.to_string()))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|error| TokenError::Network(error.to_string()))?;

        if !status.is_success() {
            return Err(classify_oauth_error(status, &body, request_kind));
        }

        let payload: TokenPayload = serde_json::from_str(&body)
            .map_err(|error| TokenError::Protocol(format!("令牌响应不是合法 JSON: {error}")))?;
        let refresh_token = payload
            .refresh_token
            .filter(|value| !value.is_empty())
            .ok_or_else(|| TokenError::Protocol("令牌响应缺少 refresh_token".to_owned()))?;
        if payload.access_token.is_empty() {
            return Err(TokenError::Protocol("令牌响应缺少 access_token".to_owned()));
        }
        if let (Some(expected), Some(granted)) = (&self.expected_scopes, payload.scope) {
            let mut granted = granted
                .split_ascii_whitespace()
                .map(str::to_owned)
                .collect::<Vec<_>>();
            granted.sort_unstable();
            granted.dedup();
            if &granted != expected {
                return Err(TokenError::Protocol(
                    "令牌响应授予的 scope 与客户端配置不一致".to_owned(),
                ));
            }
        }

        Ok(TokenResponse {
            access_token: payload.access_token,
            refresh_token,
            id_token: payload.id_token,
            expires_in: payload.expires_in,
        })
    }
}

#[derive(Clone, Copy)]
enum RequestKind {
    AuthorizationCode,
    Refresh,
}

#[derive(Deserialize)]
struct TokenPayload {
    access_token: String,
    refresh_token: Option<String>,
    id_token: Option<String>,
    expires_in: u64,
    scope: Option<String>,
}

#[derive(Deserialize)]
struct OAuthErrorPayload {
    error: String,
}

fn classify_oauth_error(status: StatusCode, body: &str, request_kind: RequestKind) -> TokenError {
    if status.is_server_error() {
        return TokenError::Network(format!("认证中心返回 HTTP {}", status.as_u16()));
    }
    let oauth_error = serde_json::from_str::<OAuthErrorPayload>(body)
        .map(|payload| payload.error)
        .unwrap_or_else(|_| format!("HTTP {}", status.as_u16()));
    if matches!(request_kind, RequestKind::Refresh) && oauth_error == "invalid_grant" {
        return TokenError::ReauthenticationRequired;
    }
    TokenError::Protocol(format!("OAuth 错误: {oauth_error}"))
}

#[cfg(test)]
mod tests {
    use super::{TokenClient, TokenError};
    use crate::issuer::issuer_uses_loopback;
    use std::collections::HashMap;
    use std::net::TcpListener;
    use std::sync::mpsc::{self, Receiver};
    use std::thread;
    use std::time::{Duration, Instant};
    use tiny_http::{Header, Response, Server, StatusCode};
    use url::Url;

    #[tokio::test]
    async fn exchanges_code_with_pkce_form_and_without_authorization_header() {
        let (issuer, captured) = fake_token_endpoint(
            200,
            r#"{
                "access_token":"access-one",
                "refresh_token":"refresh-one",
                "id_token":"id-one",
                "expires_in":900,
                "token_type":"Bearer"
            }"#,
        );
        let client = TokenClient::new(&issuer, "demo-desktop").expect("客户端配置应合法");

        let tokens = client
            .exchange_code(
                "one-time-code",
                "pkce-verifier",
                "http://127.0.0.1:49152/callback",
            )
            .await
            .expect("授权码应换到令牌");

        assert_eq!(tokens.access_token, "access-one");
        assert_eq!(tokens.refresh_token, "refresh-one");
        assert_eq!(tokens.id_token.as_deref(), Some("id-one"));
        assert_eq!(tokens.expires_in, 900);

        let request = captured.recv().expect("应捕获令牌请求");
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/oauth2/token");
        assert!(
            !request.headers.contains_key("authorization"),
            "公有客户端调用令牌端点绝不能附加 Authorization 头"
        );
        assert!(
            request
                .headers
                .get("content-type")
                .is_some_and(|value| value.starts_with("application/x-www-form-urlencoded"))
        );
        assert_eq!(
            request.form,
            HashMap::from([
                ("grant_type".to_owned(), "authorization_code".to_owned()),
                ("client_id".to_owned(), "demo-desktop".to_owned()),
                ("code".to_owned(), "one-time-code".to_owned()),
                ("code_verifier".to_owned(), "pkce-verifier".to_owned()),
                (
                    "redirect_uri".to_owned(),
                    "http://127.0.0.1:49152/callback".to_owned(),
                ),
            ])
        );
    }

    #[tokio::test]
    async fn configured_client_rejects_a_token_response_with_reduced_scopes() {
        let (issuer, _) = fake_token_endpoint(
            200,
            r#"{
                "access_token":"access-one",
                "refresh_token":"refresh-one",
                "expires_in":900,
                "scope":"openid"
            }"#,
        );
        let client = TokenClient::new_with_scopes(
            &issuer,
            "demo-desktop",
            &["openid".to_owned(), "profile".to_owned()],
        )
        .expect("客户端配置应合法");

        let result = client
            .exchange_code(
                "one-time-code",
                "pkce-verifier",
                "http://127.0.0.1:49152/callback",
            )
            .await;

        assert!(
            matches!(result, Err(TokenError::Protocol(_))),
            "令牌端缩减授权 scope 时必须拒绝建立错误会话，实际为 {result:?}",
        );
    }

    #[tokio::test]
    async fn token_endpoint_redirect_never_forwards_authorization_secrets() {
        let (issuer, redirected_request_seen) = redirecting_token_endpoint();
        let client = TokenClient::new(&issuer, "demo-desktop").expect("客户端配置应合法");

        let result = client
            .exchange_code(
                "one-time-code",
                "pkce-verifier",
                "http://127.0.0.1:49152/callback",
            )
            .await;
        let redirected_request_seen = redirected_request_seen
            .recv_timeout(Duration::from_secs(1))
            .expect("重定向目标应报告是否收到请求");

        assert!(
            matches!(result, Err(TokenError::Protocol(_))),
            "令牌端点重定向必须被拒绝，实际为 {result:?}",
        );
        assert!(
            !redirected_request_seen,
            "authorization code 与 PKCE verifier 绝不能被转发到重定向目标",
        );
    }

    #[test]
    fn token_client_rejects_plain_http_for_non_loopback_issuers() {
        for issuer in ["http://auth.example.com", "http://192.0.2.10:9000"] {
            assert!(
                matches!(
                    TokenClient::new(issuer, "demo-desktop"),
                    Err(TokenError::Protocol(_))
                ),
                "非回环 HTTP issuer 必须被拒绝: {issuer}",
            );
        }

        TokenClient::new("https://auth.example.com", "demo-desktop")
            .expect("生产 HTTPS issuer 应被接受");
        TokenClient::new("http://[::1]:9000", "demo-desktop")
            .expect("本地回环 HTTP issuer 应被接受");
    }

    #[tokio::test]
    async fn stalled_token_endpoint_is_bounded_by_request_timeout() {
        let issuer = stalling_token_endpoint(Duration::from_millis(500));
        let client = TokenClient::new_with_request_timeout(
            &issuer,
            "demo-desktop",
            Duration::from_millis(50),
        )
        .expect("测试客户端配置应合法");
        let started = Instant::now();

        let result = client.refresh("still-valid-token").await;

        assert!(
            matches!(result, Err(TokenError::Network(_))),
            "令牌端点超时应归类为网络错误，实际为 {result:?}",
        );
        assert!(
            started.elapsed() < Duration::from_millis(250),
            "令牌请求必须在配置的总超时内结束",
        );
    }

    #[tokio::test]
    async fn localhost_issuer_reaches_an_ipv4_loopback_token_endpoint() {
        let (ipv4_issuer, captured) = fake_token_endpoint(
            200,
            r#"{
                "access_token":"access-localhost",
                "refresh_token":"refresh-localhost",
                "expires_in":900,
                "token_type":"Bearer"
            }"#,
        );
        let issuer = ipv4_issuer.replace("127.0.0.1", "localhost");
        let client = TokenClient::new(&issuer, "demo-desktop").expect("客户端配置应合法");

        let tokens = client
            .exchange_code(
                "one-time-code",
                "pkce-verifier",
                "http://127.0.0.1:49152/callback",
            )
            .await
            .expect("localhost 应能连接仅监听 IPv4 回环的令牌端点");

        assert_eq!(tokens.refresh_token, "refresh-localhost");
        assert_eq!(
            captured.recv().expect("应捕获令牌请求").path,
            "/oauth2/token",
        );
    }

    #[test]
    fn localhost_and_both_ip_families_are_classified_as_loopback_issuers() {
        for issuer in [
            "http://localhost:9000",
            "http://127.0.0.1:9000",
            "http://[::1]:9000",
        ] {
            assert!(
                issuer_uses_loopback(&Url::parse(issuer).expect("issuer 应合法")),
                "{issuer} 应绕过系统代理",
            );
        }
        assert!(!issuer_uses_loopback(
            &Url::parse("https://auth.example.com").expect("issuer 应合法"),
        ));
    }

    #[tokio::test]
    async fn refresh_rotates_the_refresh_token_without_authorization_header() {
        let (issuer, captured) = fake_token_endpoint(
            200,
            r#"{
                "access_token":"access-two",
                "refresh_token":"refresh-two",
                "expires_in":900,
                "token_type":"Bearer"
            }"#,
        );
        let client = TokenClient::new(&issuer, "demo-desktop").expect("客户端配置应合法");

        let tokens = client
            .refresh("refresh-one")
            .await
            .expect("刷新应返回轮转后的令牌");

        assert_eq!(tokens.refresh_token, "refresh-two");
        let request = captured.recv().expect("应捕获刷新请求");
        assert!(!request.headers.contains_key("authorization"));
        assert_eq!(
            request.form,
            HashMap::from([
                ("grant_type".to_owned(), "refresh_token".to_owned()),
                ("client_id".to_owned(), "demo-desktop".to_owned()),
                ("refresh_token".to_owned(), "refresh-one".to_owned()),
            ])
        );
    }

    #[tokio::test]
    async fn invalid_refresh_requires_login_but_network_failure_is_retryable() {
        let (issuer, _) = fake_token_endpoint(
            400,
            r#"{"error":"invalid_grant","error_description":"revoked"}"#,
        );
        let client = TokenClient::new(&issuer, "demo-desktop").expect("客户端配置应合法");

        assert_eq!(
            client.refresh("revoked-token").await,
            Err(TokenError::ReauthenticationRequired)
        );

        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("应占到测试端口");
        let unavailable_issuer = format!("http://{}", listener.local_addr().expect("应有地址"));
        drop(listener);
        let unavailable =
            TokenClient::new(&unavailable_issuer, "demo-desktop").expect("客户端配置应合法");

        let unavailable_result = unavailable.refresh("still-valid-token").await;
        assert!(
            matches!(unavailable_result, Err(TokenError::Network(_))),
            "无法连接应归类为可重试网络错误，实际为 {unavailable_result:?}"
        );
    }

    #[test]
    fn token_response_debug_output_never_exposes_tokens() {
        let response = super::TokenResponse {
            access_token: "access-super-secret".to_owned(),
            refresh_token: "refresh-super-secret".to_owned(),
            id_token: Some("id-super-secret".to_owned()),
            expires_in: 900,
        };

        let debug = format!("{response:?}");

        assert!(!debug.contains("access-super-secret"));
        assert!(!debug.contains("refresh-super-secret"));
        assert!(!debug.contains("id-super-secret"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[derive(Debug)]
    struct CapturedRequest {
        method: String,
        path: String,
        headers: HashMap<String, String>,
        form: HashMap<String, String>,
    }

    fn fake_token_endpoint(
        status: u16,
        response_body: &'static str,
    ) -> (String, Receiver<CapturedRequest>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("假令牌端点应能绑定");
        let address = listener.local_addr().expect("假令牌端点应有地址");
        let server = Server::from_listener(listener, None).expect("假令牌端点应能启动");
        let (sender, receiver) = mpsc::channel();

        thread::spawn(move || {
            let mut request = server.recv().expect("应收到一条令牌请求");
            let headers = request
                .headers()
                .iter()
                .map(|header| {
                    (
                        header.field.as_str().to_ascii_lowercase().to_string(),
                        header.value.as_str().to_owned(),
                    )
                })
                .collect();
            let mut body = String::new();
            request
                .as_reader()
                .read_to_string(&mut body)
                .expect("表单应可读取");
            let form = url::form_urlencoded::parse(body.as_bytes())
                .map(|(key, value)| (key.into_owned(), value.into_owned()))
                .collect();
            let _ = sender.send(CapturedRequest {
                method: request.method().as_str().to_owned(),
                path: request.url().to_owned(),
                headers,
                form,
            });

            let content_type = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                .expect("静态响应头应合法");
            request
                .respond(
                    Response::from_string(response_body)
                        .with_status_code(StatusCode(status))
                        .with_header(content_type),
                )
                .expect("假令牌响应应可返回");
        });

        (format!("http://{address}/"), receiver)
    }

    fn stalling_token_endpoint(delay: Duration) -> String {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("假令牌端点应能绑定");
        let address = listener.local_addr().expect("假令牌端点应有地址");
        let server = Server::from_listener(listener, None).expect("假令牌端点应能启动");

        thread::spawn(move || {
            let _request = server.recv().expect("应收到一条令牌请求");
            thread::sleep(delay);
        });

        format!("http://{address}/")
    }

    fn redirecting_token_endpoint() -> (String, Receiver<bool>) {
        let redirect_target_listener =
            TcpListener::bind(("127.0.0.1", 0)).expect("重定向目标应能绑定");
        let redirect_target_address = redirect_target_listener
            .local_addr()
            .expect("重定向目标应有地址");
        let redirect_target =
            Server::from_listener(redirect_target_listener, None).expect("重定向目标应能启动");
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let request = redirect_target
                .recv_timeout(Duration::from_millis(500))
                .expect("重定向目标监听不应失败");
            let Some(request) = request else {
                sender.send(false).expect("重定向探测结果应可发送");
                return;
            };
            sender.send(true).expect("重定向探测结果应可发送");
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
                .expect("重定向目标响应应可返回");
        });

        let issuer_listener = TcpListener::bind(("127.0.0.1", 0)).expect("假 issuer 应能绑定");
        let issuer_address = issuer_listener.local_addr().expect("假 issuer 应有地址");
        let issuer = Server::from_listener(issuer_listener, None).expect("假 issuer 应能启动");
        thread::spawn(move || {
            let request = issuer.recv().expect("假 issuer 应收到令牌请求");
            let location = Header::from_bytes(
                &b"Location"[..],
                format!("http://{redirect_target_address}/collect").as_bytes(),
            )
            .expect("重定向地址应合法");
            request
                .respond(Response::empty(StatusCode(307)).with_header(location))
                .expect("重定向响应应可返回");
        });

        (format!("http://{issuer_address}/"), receiver)
    }
}

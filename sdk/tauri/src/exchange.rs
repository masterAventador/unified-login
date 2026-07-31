use reqwest::StatusCode;
use serde::Deserialize;
use url::Url;

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
}

impl TokenClient {
    pub fn new(issuer: &str, client_id: &str) -> Result<Self, TokenError> {
        let mut issuer = Url::parse(issuer)
            .map_err(|error| TokenError::Protocol(format!("issuer URL 无效: {error}")))?;
        if !matches!(issuer.scheme(), "http" | "https")
            || issuer.host_str().is_none()
            || !issuer.username().is_empty()
            || issuer.password().is_some()
            || issuer.fragment().is_some()
        {
            return Err(TokenError::Protocol(
                "issuer URL 必须是 HTTP(S) 绝对地址".to_owned(),
            ));
        }
        if !issuer.path().ends_with('/') {
            issuer.set_path(&format!("{}/", issuer.path()));
        }
        let endpoint = issuer
            .join("oauth2/token")
            .map_err(|error| TokenError::Protocol(format!("令牌端点 URL 无效: {error}")))?;
        if client_id.is_empty() {
            return Err(TokenError::Protocol("client_id 不能为空".to_owned()));
        }

        Ok(Self {
            endpoint,
            client_id: client_id.to_owned(),
            http: reqwest::Client::new(),
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
    if matches!(request_kind, RequestKind::Refresh)
        && matches!(oauth_error.as_str(), "invalid_grant" | "invalid_client")
    {
        return TokenError::ReauthenticationRequired;
    }
    TokenError::Protocol(format!("OAuth 错误: {oauth_error}"))
}

#[cfg(test)]
mod tests {
    use super::{TokenClient, TokenError};
    use std::collections::HashMap;
    use std::net::TcpListener;
    use std::sync::mpsc::{self, Receiver};
    use std::thread;
    use tiny_http::{Header, Response, Server, StatusCode};

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
}

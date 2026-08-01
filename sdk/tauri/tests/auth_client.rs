use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use tiny_http::{Header, Response, Server, StatusCode};
use tokio::sync::oneshot;
use unified_login_tauri::auth::{AuthClient, AuthConfig, AuthErrorCode, LoginOptions, LoginPrompt};
use unified_login_tauri::credentials::{CredentialError, CredentialStore};
use url::Url;

#[test]
fn auth_configuration_rejects_unsafe_or_incomplete_values() {
    for result in [
        AuthConfig::builder("https://auth.example.com", "", "credential-service").build(),
        AuthConfig::builder("https://auth.example.com", "desktop", "").build(),
        AuthConfig::builder("https://auth.example.com", "desktop", "credential-service")
            .credential_account("")
            .build(),
        AuthConfig::builder("https://auth.example.com", "desktop", "credential-service")
            .scopes(["openid", "profile email"])
            .build(),
        AuthConfig::builder("https://auth.example.com", "desktop", "credential-service")
            .scopes(["openid", "profile\"email"])
            .build(),
        AuthConfig::builder("https://auth.example.com", "desktop", "credential-service")
            .scopes(["openid", "profile\\email"])
            .build(),
        AuthConfig::builder("https://auth.example.com", "desktop", "credential-service")
            .scopes(["openid", "个人资料"])
            .build(),
        AuthConfig::builder("https://auth.example.com", "desktop", "credential-service")
            .scopes(["profile"])
            .build(),
        AuthConfig::builder("https://auth.example.com", "desktop", "credential-service")
            .callback_timeout(Duration::ZERO)
            .build(),
    ] {
        assert_eq!(
            result.expect_err("无效桌面认证配置必须被拒绝").code,
            AuthErrorCode::Configuration,
        );
    }
}

#[test]
fn credential_account_is_stable_across_scope_changes_but_isolated_by_issuer_and_client() {
    let config = |issuer: &str, client_id: &str, scopes: &[&str]| {
        AuthConfig::builder(issuer, client_id, "credential-service")
            .scopes(scopes.iter().copied())
            .build()
            .expect("合法配置应可创建")
    };
    let original = config(
        "https://auth.example.com",
        "desktop",
        &["openid", "profile", "email"],
    );
    let reordered = config(
        "https://auth.example.com/",
        "desktop",
        &["email", "openid", "profile"],
    );
    let other_issuer = config(
        "https://login.example.com",
        "desktop",
        &["openid", "profile", "email"],
    );
    let other_client = config(
        "https://auth.example.com",
        "another-desktop",
        &["openid", "profile", "email"],
    );
    let other_scopes = config(
        "https://auth.example.com",
        "desktop",
        &["openid", "profile"],
    );

    assert_eq!(
        original.credential_account(),
        reordered.credential_account()
    );
    assert_ne!(original.credential_account(), "refresh-token");
    assert_ne!(
        original.credential_account(),
        other_issuer.credential_account()
    );
    assert_ne!(
        original.credential_account(),
        other_client.credential_account()
    );
    assert_eq!(
        original.credential_account(),
        other_scopes.credential_account()
    );
    assert!(
        original.legacy_credential_account().is_some(),
        "自定义 scope 也必须清理旧账号，但凭据内容层不得恢复授权不足的 token"
    );
    assert!(
        config("https://auth.example.com", "desktop", &["openid"])
            .legacy_credential_account()
            .is_some(),
        "旧版默认 openid 凭据应有一次性迁移来源"
    );
}

#[test]
fn login_options_parse_only_the_shared_web_sdk_prompt_contract() {
    assert_eq!(
        LoginOptions::from_prompt(None).expect("省略 prompt 应合法"),
        LoginOptions::default(),
    );
    assert_eq!(
        LoginOptions::from_prompt(Some("login")).expect("强制登录 prompt 应合法"),
        LoginOptions {
            prompt: Some(LoginPrompt::Login),
        },
    );
    assert_eq!(
        LoginOptions::from_prompt(Some("none"))
            .expect_err("SDK 必须拒绝不支持的 prompt")
            .code,
        AuthErrorCode::LoginOptions,
    );
}

#[tokio::test]
async fn client_owns_the_complete_login_scope_and_token_lifecycle() {
    let (issuer, token_request) = successful_token_endpoint();
    let store = SharedStore::default();
    let config = AuthConfig::builder(&issuer, "demo-desktop", "credential-service")
        .scopes(["openid", "profile", "email"])
        .callback_timeout(Duration::from_secs(2))
        .build()
        .expect("合法配置应可创建");
    let client = Arc::new(AuthClient::new(config, store.clone()).expect("认证客户端应可创建"));
    let opened_authorization_url = Arc::new(Mutex::new(None));
    let opened_authorization_url_for_browser = Arc::clone(&opened_authorization_url);

    client
        .login(
            LoginOptions {
                prompt: Some(LoginPrompt::Login),
            },
            move |authorization_url| {
                *opened_authorization_url_for_browser
                    .lock()
                    .expect("授权地址锁不应中毒") = Some(authorization_url.to_owned());
                let authorization_url =
                    Url::parse(authorization_url).map_err(|error| error.to_string())?;
                let query = authorization_url
                    .query_pairs()
                    .map(|(name, value)| (name.into_owned(), value.into_owned()))
                    .collect::<HashMap<_, _>>();
                let redirect_uri = query
                    .get("redirect_uri")
                    .ok_or("授权地址缺少 redirect_uri")?
                    .to_owned();
                let state = query.get("state").ok_or("授权地址缺少 state")?.to_owned();
                thread::spawn(move || {
                    thread::sleep(Duration::from_millis(20));
                    send_callback(&redirect_uri, &state);
                });
                Ok(())
            },
        )
        .await
        .expect("SDK 应完成完整登录编排");

    let authorization_url = opened_authorization_url
        .lock()
        .expect("授权地址锁不应中毒")
        .clone()
        .expect("SDK 应调用浏览器打开器");
    let query = Url::parse(&authorization_url)
        .expect("授权地址应合法")
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<HashMap<_, _>>();
    assert_eq!(
        query.get("scope").map(String::as_str),
        Some("openid profile email")
    );
    assert_eq!(query.get("prompt").map(String::as_str), Some("login"));
    assert_eq!(
        client
            .access_token()
            .await
            .expect("登录后应取得 access token"),
        "access-one",
    );
    assert!(
        store.value().is_some(),
        "refresh token 应保存为带 scope 的凭据"
    );
    assert_ne!(
        store.value().as_deref(),
        Some("refresh-one"),
        "稳定账号内不得保存无法判定授权 scope 的裸 refresh token",
    );
    assert_eq!(
        token_request
            .join()
            .expect("令牌端点线程不应 panic")
            .get("client_id")
            .map(String::as_str),
        Some("demo-desktop"),
    );

    let (reauthentication_opened, reauthentication_opened_receiver) = oneshot::channel();
    let reauthentication_client = Arc::clone(&client);
    let reauthentication = tokio::spawn(async move {
        reauthentication_client
            .login(LoginOptions::default(), move |_| {
                reauthentication_opened
                    .send(())
                    .map_err(|_| "无法记录重新登录".to_owned())
            })
            .await
    });
    reauthentication_opened_receiver
        .await
        .expect("重新登录应打开浏览器");
    assert_eq!(
        client
            .access_token()
            .await
            .expect_err("重新登录期间绝不能返回前一账号令牌")
            .code,
        AuthErrorCode::LoginInProgress,
    );

    client.logout().await.expect("登出应清理 SDK 会话");
    assert_eq!(
        reauthentication
            .await
            .expect("重新登录任务不应 panic")
            .expect_err("登出应取消重新登录")
            .code,
        AuthErrorCode::LoginFailed,
    );
    assert_eq!(store.value(), None);
    assert_eq!(
        client
            .access_token()
            .await
            .expect_err("登出后必须要求重新登录")
            .code,
        AuthErrorCode::LoginRequired,
    );
}

#[tokio::test]
async fn access_token_started_before_logout_cannot_return_after_logout_begins() {
    let (issuer, refresh_received, release_refresh) = gated_refresh_endpoint();
    let store = SharedStore::with_value("refresh-before-logout");
    let client = Arc::new(
        AuthClient::new(
            AuthConfig::builder(&issuer, "demo-desktop", "credential-service")
                .build()
                .expect("合法配置应可创建"),
            store.clone(),
        )
        .expect("认证客户端应可创建"),
    );
    let access_client = Arc::clone(&client);
    let access = tokio::spawn(async move { access_client.access_token().await });
    refresh_received.await.expect("令牌读取应先进入刷新请求");

    let mut logout = Box::pin(client.logout());
    tokio::select! {
        biased;
        result = &mut logout => panic!("刷新请求放行前登出不应结束: {result:?}"),
        _ = tokio::time::sleep(Duration::from_millis(10)) => {}
    }
    release_refresh.send(()).expect("刷新响应应可继续返回");

    assert_eq!(
        access
            .await
            .expect("令牌任务不应 panic")
            .expect_err("登出开始后早先的令牌读取必须失效")
            .code,
        AuthErrorCode::StaleOperation,
    );
    logout.await.expect("登出应成功");
    assert_eq!(store.value(), None);
}

#[tokio::test]
async fn logout_cancels_an_active_login_and_releases_the_lifecycle_for_retry() {
    let config = AuthConfig::builder(
        "http://localhost:9000",
        "demo-desktop",
        "credential-service",
    )
    .callback_timeout(Duration::from_secs(5))
    .build()
    .expect("合法配置应可创建");
    let client = Arc::new(AuthClient::new(config, SharedStore::default()).expect("客户端应可创建"));
    let (opened, opened_receiver) = oneshot::channel();
    let login_client = Arc::clone(&client);
    let login = tokio::spawn(async move {
        login_client
            .login(LoginOptions::default(), move |authorization_url| {
                opened
                    .send(authorization_url.to_owned())
                    .map_err(|_| "无法记录授权地址".to_owned())?;
                Ok(())
            })
            .await
    });
    opened_receiver.await.expect("登录应先打开系统浏览器");

    let overlapping = client
        .login(LoginOptions::default(), |_| {
            panic!("并发登录不应再次打开系统浏览器")
        })
        .await
        .expect_err("Rust SDK 必须拒绝重叠登录");
    assert_eq!(overlapping.code, AuthErrorCode::LoginInProgress);

    tokio::time::timeout(Duration::from_secs(1), client.logout())
        .await
        .expect("登出不应等待完整回调超时")
        .expect("取消活动登录后应成功登出");
    assert_eq!(
        login
            .await
            .expect("登录任务不应 panic")
            .expect_err("活动登录应被登出取消")
            .code,
        AuthErrorCode::LoginFailed,
    );

    let retry = client
        .login(LoginOptions::default(), |_| Err("测试主动停止".to_owned()))
        .await
        .expect_err("测试打开器会主动失败");
    assert_eq!(retry.code, AuthErrorCode::LoginFailed);
}

#[derive(Clone, Default)]
struct SharedStore {
    value: Arc<Mutex<Option<String>>>,
}

impl SharedStore {
    fn with_value(value: &str) -> Self {
        Self {
            value: Arc::new(Mutex::new(Some(value.to_owned()))),
        }
    }

    fn value(&self) -> Option<String> {
        self.value.lock().expect("凭据锁不应中毒").clone()
    }
}

fn gated_refresh_endpoint() -> (String, oneshot::Receiver<()>, oneshot::Sender<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("假令牌端点应能绑定");
    let address = listener.local_addr().expect("假令牌端点应有地址");
    let server = Server::from_listener(listener, None).expect("假令牌端点应能启动");
    let (received, received_receiver) = oneshot::channel();
    let (release, release_receiver) = oneshot::channel();
    thread::spawn(move || {
        let request = server.recv().expect("应收到 refresh token 请求");
        received.send(()).expect("刷新请求通知应可发送");
        release_receiver
            .blocking_recv()
            .expect("刷新响应应被测试放行");
        let content_type = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
            .expect("静态响应头应合法");
        request
            .respond(
                Response::from_string(
                    r#"{"access_token":"stale-access","refresh_token":"rotated-refresh","expires_in":900}"#,
                )
                .with_status_code(StatusCode(200))
                .with_header(content_type),
            )
            .expect("刷新响应应可返回");
    });
    (format!("http://{address}"), received_receiver, release)
}

impl CredentialStore for SharedStore {
    fn load_refresh_token(&self) -> Result<Option<String>, CredentialError> {
        Ok(self.value())
    }

    fn save_refresh_token(&self, refresh_token: &str) -> Result<(), CredentialError> {
        *self.value.lock().expect("凭据锁不应中毒") = Some(refresh_token.to_owned());
        Ok(())
    }

    fn delete_refresh_token(&self) -> Result<(), CredentialError> {
        *self.value.lock().expect("凭据锁不应中毒") = None;
        Ok(())
    }

    fn delete_refresh_token_if_matches(
        &self,
        expected_refresh_token: &str,
    ) -> Result<bool, CredentialError> {
        let mut value = self.value.lock().expect("凭据锁不应中毒");
        if value.as_deref() != Some(expected_refresh_token) {
            return Ok(false);
        }
        *value = None;
        Ok(true)
    }
}

fn successful_token_endpoint() -> (String, thread::JoinHandle<HashMap<String, String>>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("假令牌端点应能绑定");
    let address = listener.local_addr().expect("假令牌端点应有地址");
    let server = Server::from_listener(listener, None).expect("假令牌端点应能启动");
    let request = thread::spawn(move || {
        let mut request = server.recv().expect("应收到令牌交换请求");
        let mut body = String::new();
        request
            .as_reader()
            .read_to_string(&mut body)
            .expect("令牌请求体应可读取");
        let parameters = url::form_urlencoded::parse(body.as_bytes())
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        let content_type = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
            .expect("静态响应头应合法");
        request
            .respond(
                Response::from_string(
                    r#"{"access_token":"access-one","refresh_token":"refresh-one","expires_in":900}"#,
                )
                .with_status_code(StatusCode(200))
                .with_header(content_type),
            )
            .expect("令牌响应应可返回");
        parameters
    });
    (format!("http://{address}"), request)
}

fn send_callback(redirect_uri: &str, state: &str) {
    let redirect_uri = Url::parse(redirect_uri).expect("回调地址应合法");
    let address = SocketAddr::new(
        redirect_uri
            .host_str()
            .expect("回调应有主机")
            .parse()
            .expect("回调主机应为 IP"),
        redirect_uri.port().expect("回调应有端口"),
    );
    let mut stream = TcpStream::connect(address).expect("应能连接 SDK 回环服务");
    write!(
        stream,
        "GET /callback?code=one-time-code&state={state} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n",
    )
    .expect("回调请求应可写入");
    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("回调响应应可读取");
    assert!(response.starts_with("HTTP/1.1 200"));
}

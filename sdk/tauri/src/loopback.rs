use std::net::{SocketAddr, TcpListener};
use std::time::Duration;
use tiny_http::{Header, Method, Response, Server, StatusCode};
use url::Url;

const SUCCESS_PAGE: &str = r#"<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>登录成功</title></head>
<body><main><h1>登录成功，可关闭此页</h1><p>你现在可以返回桌面应用。</p></main></body>
</html>"#;

const ERROR_PAGE: &str = r#"<!doctype html>
<html lang="zh-CN">
<head><meta charset="utf-8"><title>登录未完成</title></head>
<body><main><h1>登录请求无效</h1><p>请关闭此页并在桌面应用中重新登录。</p></main></body>
</html>"#;

#[derive(PartialEq, Eq)]
pub struct AuthorizationCallback {
    pub code: String,
}

impl std::fmt::Debug for AuthorizationCallback {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizationCallback")
            .field("code", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum LoopbackError {
    #[error("无法绑定本机回环地址: {0}")]
    Bind(#[source] std::io::Error),
    #[error("无法启动回环 HTTP 服务: {0}")]
    Server(String),
    #[error("等待认证回调超时")]
    Timeout,
    #[error("认证回调已取消")]
    Cancelled,
    #[error("认证回调请求无效")]
    InvalidRequest,
    #[error("认证回调 state 校验失败")]
    StateMismatch,
    #[error("认证服务器返回错误: {0}")]
    Authorization(String),
    #[error("无法返回回调页面: {0}")]
    Respond(#[source] std::io::Error),
}

pub struct LoopbackServer {
    server: Server,
    address: SocketAddr,
}

impl LoopbackServer {
    pub fn bind() -> Result<Self, LoopbackError> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(LoopbackError::Bind)?;
        let address = listener.local_addr().map_err(LoopbackError::Bind)?;
        let server = Server::from_listener(listener, None)
            .map_err(|error| LoopbackError::Server(error.to_string()))?;
        Ok(Self { server, address })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }

    pub fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}/callback", self.address.port())
    }

    pub fn wait_for_callback(
        self,
        expected_state: &str,
        timeout: Duration,
    ) -> Result<AuthorizationCallback, LoopbackError> {
        self.wait_for_callback_until(expected_state, timeout, || false)
    }

    pub(crate) fn wait_for_callback_until(
        self,
        expected_state: &str,
        timeout: Duration,
        is_cancelled: impl Fn() -> bool,
    ) -> Result<AuthorizationCallback, LoopbackError> {
        let started_at = std::time::Instant::now();
        let request = loop {
            if is_cancelled() {
                return Err(LoopbackError::Cancelled);
            }
            let Some(remaining) = timeout.checked_sub(started_at.elapsed()) else {
                return Err(LoopbackError::Timeout);
            };
            if remaining.is_zero() {
                return Err(LoopbackError::Timeout);
            }
            match self
                .server
                .recv_timeout(remaining.min(Duration::from_millis(25)))
                .map_err(LoopbackError::Respond)?
            {
                Some(request) => break request,
                None => continue,
            }
        };

        if request.method() != &Method::Get {
            respond(request, StatusCode(400), ERROR_PAGE)?;
            return Err(LoopbackError::InvalidRequest);
        }

        let callback_url = Url::parse(&format!("http://127.0.0.1{}", request.url()))
            .map_err(|_| LoopbackError::InvalidRequest)?;
        if callback_url.path() != "/callback" {
            respond(request, StatusCode(404), ERROR_PAGE)?;
            return Err(LoopbackError::InvalidRequest);
        }

        let parameters = callback_url
            .query_pairs()
            .collect::<std::collections::HashMap<_, _>>();
        if let Some(error) = parameters.get("error") {
            let error = error.to_string();
            respond(request, StatusCode(400), ERROR_PAGE)?;
            return Err(LoopbackError::Authorization(error));
        }

        if parameters.get("state").map(|value| value.as_ref()) != Some(expected_state) {
            respond(request, StatusCode(400), ERROR_PAGE)?;
            return Err(LoopbackError::StateMismatch);
        }

        let code = parameters
            .get("code")
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);
        let Some(code) = code else {
            respond(request, StatusCode(400), ERROR_PAGE)?;
            return Err(LoopbackError::InvalidRequest);
        };

        let response = respond(request, StatusCode(200), SUCCESS_PAGE);
        Ok(finish_valid_callback(code, response))
    }
}

fn finish_valid_callback(
    code: String,
    response: Result<(), LoopbackError>,
) -> AuthorizationCallback {
    // 浏览器可能在回跳后立刻关闭页面。提示页是否成功写完不改变已经完成的
    // method、path、state 与授权码校验，也不能阻断后续令牌交换。
    let _response_was_delivered = response.is_ok();
    AuthorizationCallback { code }
}

fn respond(
    request: tiny_http::Request,
    status: StatusCode,
    body: &'static str,
) -> Result<(), LoopbackError> {
    let content_type = Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..])
        .expect("静态 Content-Type 响应头必须合法");
    request
        .respond(
            Response::from_string(body)
                .with_status_code(status)
                .with_header(content_type),
        )
        .map_err(LoopbackError::Respond)
}

#[cfg(test)]
mod tests {
    use super::{AuthorizationCallback, LoopbackError, LoopbackServer};
    use std::io::{Read, Write};
    use std::net::{IpAddr, SocketAddr, TcpStream};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn binds_ipv4_loopback_on_an_os_assigned_port() {
        let first = LoopbackServer::bind().expect("第一个回环服务应能启动");
        let second = LoopbackServer::bind().expect("第二个回环服务应能启动");

        assert_eq!(first.local_addr().ip(), IpAddr::from([127, 0, 0, 1]));
        assert_ne!(first.local_addr().port(), 0);
        assert_ne!(first.local_addr().port(), second.local_addr().port());
        assert_eq!(
            first.redirect_uri(),
            format!("http://127.0.0.1:{}/callback", first.local_addr().port())
        );
    }

    #[test]
    fn accepts_exactly_one_callback_then_closes_the_listener() {
        let server = LoopbackServer::bind().expect("回环服务应能启动");
        let address = server.local_addr();

        let callback = thread::spawn(move || {
            server.wait_for_callback("expected-state", Duration::from_secs(2))
        });

        let response = send_get(address, "/callback?code=one-time-code&state=expected-state");

        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(response.contains("登录成功，可关闭此页"));
        assert_eq!(
            callback
                .join()
                .expect("回调线程不应 panic")
                .expect("回调应成功"),
            AuthorizationCallback {
                code: "one-time-code".to_owned(),
            }
        );

        assert!(
            TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_err(),
            "处理一次回调后监听端口必须立即关闭"
        );
    }

    #[test]
    fn authorization_callback_debug_output_redacts_the_one_time_code() {
        let callback = AuthorizationCallback {
            code: "one-time-super-secret".to_owned(),
        };

        let debug = format!("{callback:?}");

        assert!(!debug.contains("one-time-super-secret"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn valid_callback_survives_success_page_write_failure() {
        let callback = super::finish_valid_callback(
            "one-time-code".to_owned(),
            Err(LoopbackError::Respond(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "浏览器已经关闭回调页",
            ))),
        );

        assert_eq!(
            callback,
            AuthorizationCallback {
                code: "one-time-code".to_owned(),
            }
        );
    }

    #[test]
    fn callback_without_authorization_code_returns_the_error_page() {
        let server = LoopbackServer::bind().expect("回环服务应能启动");
        let address = server.local_addr();
        let callback = thread::spawn(move || {
            server.wait_for_callback("expected-state", Duration::from_secs(2))
        });

        let response = send_get(address, "/callback?state=expected-state");

        assert!(response.starts_with("HTTP/1.1 400"));
        assert!(response.contains("登录请求无效"));
        assert!(matches!(
            callback.join().expect("回调线程不应 panic"),
            Err(LoopbackError::InvalidRequest),
        ));
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

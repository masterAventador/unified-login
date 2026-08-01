use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};
use url::Url;

// 127.0.0.1 的 Cookie 不按端口隔离，系统浏览器因此可能发送数十 KiB 的合法
// 请求头。保留有界上限防止本机进程无限占用内存，同时预留充足兼容余量。
const MAX_REQUEST_HEADER_BYTES: usize = 256 * 1024;
const CALLBACK_POLL_INTERVAL: Duration = Duration::from_millis(25);
const CALLBACK_HEADER_TIMEOUT: Duration = Duration::from_millis(500);

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
    #[error("无法读取认证回调: {0}")]
    Receive(#[source] std::io::Error),
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
    listener: TcpListener,
    address: SocketAddr,
}

impl LoopbackServer {
    pub fn bind() -> Result<Self, LoopbackError> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(LoopbackError::Bind)?;
        let address = listener.local_addr().map_err(LoopbackError::Bind)?;
        listener
            .set_nonblocking(true)
            .map_err(LoopbackError::Bind)?;
        Ok(Self { listener, address })
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
        let started_at = Instant::now();
        let (stream, request_line) = loop {
            if is_cancelled() {
                return Err(LoopbackError::Cancelled);
            }
            let remaining = remaining_time(started_at, timeout)?;
            match self.listener.accept() {
                Ok((mut stream, _peer)) => {
                    stream
                        .set_nonblocking(false)
                        .map_err(LoopbackError::Receive)?;
                    match read_request_line(
                        &mut stream,
                        self.address,
                        started_at,
                        timeout,
                        &is_cancelled,
                    ) {
                        Ok(Some(request_line)) => break (stream, Ok(request_line)),
                        Ok(None) => continue,
                        Err(error @ LoopbackError::InvalidRequest) => {
                            break (stream, Err(error));
                        }
                        Err(error) => return Err(error),
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(remaining.min(CALLBACK_POLL_INTERVAL));
                }
                Err(error) => {
                    return Err(LoopbackError::Server(format!("无法接收回环连接: {error}")));
                }
            }
        };

        // 监听 socket 由当前对象直接持有；收到首个完整 HTTP 请求后同步关闭，
        // 不依赖后台 accept 线程异步退出。空连接、不完整或畸形数据都只作为
        // 本机连接噪声丢弃；只有收到首个完整 HTTP 请求才会消耗本次回调。
        drop(self.listener);

        let (method, target) = match request_line {
            Ok(request_line) => request_line,
            Err(error @ LoopbackError::InvalidRequest) => {
                respond(stream, 400, "Bad Request", ERROR_PAGE)?;
                return Err(error);
            }
            Err(error) => return Err(error),
        };

        if method != "GET" {
            respond(stream, 400, "Bad Request", ERROR_PAGE)?;
            return Err(LoopbackError::InvalidRequest);
        }

        let callback_url = Url::parse(&format!("http://127.0.0.1{target}"))
            .map_err(|_| LoopbackError::InvalidRequest)?;
        if callback_url.path() != "/callback" {
            respond(stream, 404, "Not Found", ERROR_PAGE)?;
            return Err(LoopbackError::InvalidRequest);
        }

        let mut code = None;
        let mut state = None;
        let mut authorization_error = None;
        let mut duplicated_security_parameter = false;
        for (name, value) in callback_url.query_pairs() {
            let target = match name.as_ref() {
                "code" => Some(&mut code),
                "state" => Some(&mut state),
                "error" => Some(&mut authorization_error),
                _ => None,
            };
            if let Some(target) = target
                && target.replace(value.into_owned()).is_some()
            {
                duplicated_security_parameter = true;
            }
        }
        if duplicated_security_parameter {
            respond(stream, 400, "Bad Request", ERROR_PAGE)?;
            return Err(LoopbackError::InvalidRequest);
        }

        if state.as_deref() != Some(expected_state) {
            respond(stream, 400, "Bad Request", ERROR_PAGE)?;
            return Err(LoopbackError::StateMismatch);
        }

        if code.is_some() && authorization_error.is_some() {
            respond(stream, 400, "Bad Request", ERROR_PAGE)?;
            return Err(LoopbackError::InvalidRequest);
        }
        if let Some(error) = authorization_error {
            if error.is_empty() {
                respond(stream, 400, "Bad Request", ERROR_PAGE)?;
                return Err(LoopbackError::InvalidRequest);
            }
            respond(stream, 400, "Bad Request", ERROR_PAGE)?;
            return Err(LoopbackError::Authorization(error));
        }

        let code = code.filter(|value| !value.is_empty());
        let Some(code) = code else {
            respond(stream, 400, "Bad Request", ERROR_PAGE)?;
            return Err(LoopbackError::InvalidRequest);
        };

        let response = respond(stream, 200, "OK", SUCCESS_PAGE);
        Ok(finish_valid_callback(code, response))
    }
}

fn remaining_time(started_at: Instant, timeout: Duration) -> Result<Duration, LoopbackError> {
    timeout
        .checked_sub(started_at.elapsed())
        .filter(|remaining| !remaining.is_zero())
        .ok_or(LoopbackError::Timeout)
}

fn read_request_line(
    stream: &mut TcpStream,
    expected_address: SocketAddr,
    started_at: Instant,
    timeout: Duration,
    is_cancelled: &impl Fn() -> bool,
) -> Result<Option<(String, String)>, LoopbackError> {
    let mut request_bytes = Vec::with_capacity(1024);
    let connection_started_at = Instant::now();
    'read_request: loop {
        if is_cancelled() {
            return Err(LoopbackError::Cancelled);
        }
        let remaining = remaining_time(started_at, timeout)?;
        let Some(header_remaining) =
            CALLBACK_HEADER_TIMEOUT.checked_sub(connection_started_at.elapsed())
        else {
            return Ok(None);
        };
        if header_remaining.is_zero() {
            return Ok(None);
        }
        if stream
            .set_read_timeout(Some(
                remaining.min(header_remaining).min(CALLBACK_POLL_INTERVAL),
            ))
            .is_err()
        {
            return Ok(None);
        }
        let mut chunk = [0_u8; 1024];
        match stream.read(&mut chunk) {
            Ok(0) => return Ok(None),
            Ok(read) => request_bytes.extend_from_slice(&chunk[..read]),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                continue;
            }
            Err(_) => return Ok(None),
        }
        if request_bytes.len() > MAX_REQUEST_HEADER_BYTES {
            return Ok(None);
        }

        let mut header_capacity = 64;
        loop {
            let mut headers = vec![httparse::EMPTY_HEADER; header_capacity];
            let mut request = httparse::Request::new(&mut headers);
            match request.parse(&request_bytes) {
                Ok(httparse::Status::Partial) => continue 'read_request,
                Ok(httparse::Status::Complete(_)) => {
                    if request.version != Some(1) {
                        return Err(LoopbackError::InvalidRequest);
                    }
                    let expected_host = format!("127.0.0.1:{}", expected_address.port());
                    let hosts = request
                        .headers
                        .iter()
                        .filter(|header| header.name.eq_ignore_ascii_case("host"))
                        .collect::<Vec<_>>();
                    if hosts.len() != 1 || hosts[0].value != expected_host.as_bytes() {
                        return Err(LoopbackError::InvalidRequest);
                    }
                    let method = request.method.ok_or(LoopbackError::InvalidRequest)?;
                    let target = request.path.ok_or(LoopbackError::InvalidRequest)?;
                    return Ok(Some((method.to_owned(), target.to_owned())));
                }
                Err(httparse::Error::TooManyHeaders) => {
                    let expanded_capacity =
                        header_capacity.saturating_mul(2).min(request_bytes.len());
                    if expanded_capacity <= header_capacity {
                        return Ok(None);
                    }
                    header_capacity = expanded_capacity;
                }
                Err(_) => return Ok(None),
            }
        }
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
    mut stream: TcpStream,
    status: u16,
    reason: &str,
    body: &'static str,
) -> Result<(), LoopbackError> {
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{body}",
        body.len(),
    )
    .and_then(|()| stream.flush())
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
        let mut first = TcpStream::connect(address).expect("第一个测试客户端应连上回环服务");
        let mut second = TcpStream::connect(address).expect("第二个测试客户端应连上回环服务");
        write_get(
            &mut first,
            address,
            "/callback?code=one-time-code&state=expected-state",
        );
        write_get(
            &mut second,
            address,
            "/callback?code=one-time-code&state=expected-state",
        );

        let callback = thread::spawn(move || {
            server.wait_for_callback("expected-state", Duration::from_secs(2))
        });
        let responses = [read_bounded_response(first), read_bounded_response(second)];

        assert_eq!(
            responses
                .iter()
                .filter(|response| response.starts_with("HTTP/1.1 200"))
                .count(),
            1,
            "预先连到原监听 socket 的两个请求中只能有一个收到成功响应"
        );
        assert!(
            responses
                .iter()
                .any(|response| response.contains("登录成功，可关闭此页"))
        );
        assert_eq!(
            callback
                .join()
                .expect("回调线程不应 panic")
                .expect("回调应成功"),
            AuthorizationCallback {
                code: "one-time-code".to_owned(),
            }
        );
    }

    #[test]
    fn idle_tcp_connection_does_not_consume_the_single_http_callback() {
        let server = LoopbackServer::bind().expect("回环服务应能启动");
        let address = server.local_addr();
        let idle_connection = TcpStream::connect(address).expect("空闲连接应能建立");
        let callback = thread::spawn(move || {
            server.wait_for_callback("expected-state", Duration::from_secs(2))
        });

        thread::sleep(Duration::from_millis(600));
        let response = send_get(address, "/callback?code=one-time-code&state=expected-state");
        drop(idle_connection);

        assert!(response.starts_with("HTTP/1.1 200"));
        assert_eq!(
            callback
                .join()
                .expect("回调线程不应 panic")
                .expect("完整 HTTP 回调应成功"),
            AuthorizationCallback {
                code: "one-time-code".to_owned(),
            }
        );
    }

    #[test]
    fn closed_empty_tcp_connection_does_not_consume_the_single_http_callback() {
        let server = LoopbackServer::bind().expect("回环服务应能启动");
        let address = server.local_addr();
        let empty_connection = TcpStream::connect(address).expect("空连接应能建立");
        drop(empty_connection);
        let callback = thread::spawn(move || {
            server.wait_for_callback("expected-state", Duration::from_secs(2))
        });

        thread::sleep(Duration::from_millis(20));
        let response = send_get(address, "/callback?code=one-time-code&state=expected-state");

        assert!(response.starts_with("HTTP/1.1 200"));
        assert_eq!(
            callback
                .join()
                .expect("回调线程不应 panic")
                .expect("空连接关闭后的完整 HTTP 回调应成功"),
            AuthorizationCallback {
                code: "one-time-code".to_owned(),
            }
        );
    }

    #[test]
    fn malformed_and_incomplete_tcp_connections_do_not_consume_the_http_callback() {
        let server = LoopbackServer::bind().expect("回环服务应能启动");
        let address = server.local_addr();

        let mut malformed = TcpStream::connect(address).expect("畸形连接应能建立");
        malformed
            .write_all(b"not-an-http-request\r\n\r\n")
            .expect("畸形数据应写入");
        drop(malformed);

        let mut incomplete = TcpStream::connect(address).expect("不完整连接应能建立");
        incomplete
            .write_all(b"GET /callback")
            .expect("不完整数据应写入");
        drop(incomplete);

        let callback = thread::spawn(move || {
            server.wait_for_callback("expected-state", Duration::from_secs(2))
        });
        thread::sleep(Duration::from_millis(20));

        let response = send_get(address, "/callback?code=one-time-code&state=expected-state");

        assert!(response.starts_with("HTTP/1.1 200"));
        assert_eq!(
            callback
                .join()
                .expect("回调线程不应 panic")
                .expect("连接噪声后的完整 HTTP 回调应成功"),
            AuthorizationCallback {
                code: "one-time-code".to_owned(),
            }
        );
    }

    #[test]
    fn browser_callback_with_more_than_16_kib_of_cookie_headers_is_accepted() {
        let server = LoopbackServer::bind().expect("回环服务应能启动");
        let address = server.local_addr();
        let callback = thread::spawn(move || {
            server.wait_for_callback("expected-state", Duration::from_secs(2))
        });
        let cookies = (0..12)
            .map(|index| format!("local-{index}={}", "a".repeat(2 * 1024)))
            .collect::<Vec<_>>()
            .join("; ");
        let mut stream = TcpStream::connect(address).expect("浏览器回调应能连上回环服务");
        write!(
            stream,
            "GET /callback?code=one-time-code&state=expected-state HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nCookie: {cookies}\r\nConnection: close\r\n\r\n",
            address.port()
        )
        .expect("带多个本机 Cookie 的回调应写入");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("回调响应应可读取");

        assert!(response.starts_with("HTTP/1.1 200"));
        assert_eq!(
            callback
                .join()
                .expect("回调线程不应 panic")
                .expect("超过 16 KiB 的合法浏览器请求头不应被丢弃"),
            AuthorizationCallback {
                code: "one-time-code".to_owned(),
            }
        );
    }

    #[test]
    fn browser_callback_with_more_than_64_header_fields_is_accepted() {
        let server = LoopbackServer::bind().expect("回环服务应能启动");
        let address = server.local_addr();
        let callback = thread::spawn(move || {
            server.wait_for_callback("expected-state", Duration::from_secs(2))
        });
        let additional_headers = (0..64)
            .map(|index| format!("X-Local-{index}: value-{index}\r\n"))
            .collect::<String>();
        let mut stream = TcpStream::connect(address).expect("浏览器回调应能连上回环服务");
        write!(
            stream,
            "GET /callback?code=one-time-code&state=expected-state HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n{additional_headers}Connection: close\r\n\r\n",
            address.port()
        )
        .expect("带较多合法字段的回调应写入");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("回调响应应可读取");

        assert!(response.starts_with("HTTP/1.1 200"));
        assert_eq!(
            callback
                .join()
                .expect("回调线程不应 panic")
                .expect("超过 64 个字段的合法浏览器请求头不应被丢弃"),
            AuthorizationCallback {
                code: "one-time-code".to_owned(),
            }
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

    #[test]
    fn callback_rejects_a_host_header_for_a_different_authority() {
        let server = LoopbackServer::bind().expect("回环服务应能启动");
        let address = server.local_addr();
        let callback = thread::spawn(move || {
            server.wait_for_callback("expected-state", Duration::from_secs(2))
        });
        let mut stream = TcpStream::connect(address).expect("测试客户端应连上回环服务");
        write!(
            stream,
            "GET /callback?code=one-time-code&state=expected-state HTTP/1.1\r\nHost: attacker.example\r\nConnection: close\r\n\r\n"
        )
        .expect("测试请求应写入");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("测试响应应可读取");

        assert!(response.starts_with("HTTP/1.1 400"));
        assert!(matches!(
            callback.join().expect("回调线程不应 panic"),
            Err(LoopbackError::InvalidRequest),
        ));
    }

    #[test]
    fn authorization_error_must_carry_the_expected_state() {
        let server = LoopbackServer::bind().expect("回环服务应能启动");
        let address = server.local_addr();
        let callback = thread::spawn(move || {
            server.wait_for_callback("expected-state", Duration::from_secs(2))
        });

        let response = send_get(address, "/callback?error=access_denied&state=forged-state");

        assert!(response.starts_with("HTTP/1.1 400"));
        assert!(matches!(
            callback.join().expect("回调线程不应 panic"),
            Err(LoopbackError::StateMismatch),
        ));
    }

    #[test]
    fn authorization_error_with_expected_state_is_reported() {
        let server = LoopbackServer::bind().expect("回环服务应能启动");
        let address = server.local_addr();
        let callback = thread::spawn(move || {
            server.wait_for_callback("expected-state", Duration::from_secs(2))
        });

        let response = send_get(
            address,
            "/callback?error=access_denied&state=expected-state",
        );

        assert!(response.starts_with("HTTP/1.1 400"));
        assert!(matches!(
            callback.join().expect("回调线程不应 panic"),
            Err(LoopbackError::Authorization(error)) if error == "access_denied",
        ));
    }

    #[test]
    fn duplicate_security_parameters_are_rejected_instead_of_folded() {
        for target in [
            "/callback?code=one&state=expected-state&state=expected-state",
            "/callback?code=one&code=two&state=expected-state",
            "/callback?error=access_denied&error=server_error&state=expected-state",
        ] {
            let server = LoopbackServer::bind().expect("回环服务应能启动");
            let address = server.local_addr();
            let callback = thread::spawn(move || {
                server.wait_for_callback("expected-state", Duration::from_secs(2))
            });

            let response = send_get(address, target);

            assert!(response.starts_with("HTTP/1.1 400"));
            assert!(matches!(
                callback.join().expect("回调线程不应 panic"),
                Err(LoopbackError::InvalidRequest),
            ));
        }
    }

    fn send_get(address: SocketAddr, target: &str) -> String {
        let mut stream = TcpStream::connect(address).expect("测试客户端应连上回环服务");
        write_get(&mut stream, address, target);

        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .expect("测试响应应可读取");
        response
    }

    fn write_get(stream: &mut TcpStream, address: SocketAddr, target: &str) {
        write!(
            stream,
            "GET {target} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            address.port()
        )
        .expect("测试请求应写入");
    }

    fn read_bounded_response(mut stream: TcpStream) -> String {
        if stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .is_err()
        {
            return String::new();
        }
        let mut response = Vec::new();
        match stream.read_to_end(&mut response) {
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::WouldBlock
                ) => {}
            Err(error) => panic!("测试响应读取失败: {error}"),
        }
        String::from_utf8_lossy(&response).into_owned()
    }
}

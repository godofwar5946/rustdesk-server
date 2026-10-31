//! 审计回调回归测试：仅使用本地模拟 HTTP 服务，不访问真实 API，也不使用真实密钥。

use super::*;
use std::{
    io::{Read, Write},
    net::TcpListener,
    time::Instant,
};

fn test_config(url: String) -> AuditConfig {
    AuditConfig {
        url,
        secret: "仅用于测试的审计密钥-01234567890123456789012345678901".to_owned(),
        timeout_seconds: 1,
        max_retries: 2,
    }
}

fn http_server(response: String, delay: Duration) -> (String, thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!(
        "http://{}/api/connection-audit/server",
        listener.local_addr().unwrap()
    );
    let worker = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(err) if err.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => panic!("模拟服务未收到请求：{}", err),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut request = Vec::new();
        let mut buf = [0; 1024];
        loop {
            let count = stream.read(&mut buf).unwrap();
            assert!(count > 0, "请求尚未完整到达，连接就已关闭");
            request.extend_from_slice(&buf[..count]);
            assert!(request.len() < MAX_EVENT_BYTES, "模拟请求超过测试上限");
            let text = String::from_utf8_lossy(&request);
            if let Some(end) = text.find("\r\n\r\n") {
                let length = text[..end]
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                if request.len() >= end + 4 + length {
                    break;
                }
            }
        }
        thread::sleep(delay);
        // 超时用例中客户端可能已经关闭连接，写失败属于预期行为。
        let _ = stream.write_all(response.as_bytes());
        String::from_utf8(request).unwrap()
    });
    (url, worker)
}

#[test]
fn accepts_only_success_statuses() {
    for code in [200, 201, 202, 204, 299] {
        assert_eq!(check_status(code), Ok(()));
    }
    for code in [100, 301, 308, 400, 401, 403, 404, 408, 429, 500, 503] {
        assert_eq!(check_status(code), Err(AuditFailure::Http(code)));
    }
}

#[test]
fn retries_only_transient_failures() {
    for code in [408, 429, 500, 502, 503, 504, 599] {
        assert!(AuditFailure::Http(code).retryable());
    }
    for code in [301, 308, 400, 401, 403, 404, 409, 422] {
        assert!(!AuditFailure::Http(code).retryable());
    }
    assert!(AuditFailure::Network(ErrorKind::TimedOut).retryable());
    assert!(AuditFailure::Network(ErrorKind::ConnectionRefused).retryable());
    assert!(!AuditFailure::Network(ErrorKind::InvalidData).retryable());
    assert!(!AuditFailure::Tls.retryable());
    assert!(!AuditFailure::Redirect.retryable());
    assert!(!AuditFailure::HttpsDisabled.retryable());
}

#[test]
fn retries_twice_then_recovers() {
    let mut attempts = 0;
    let mut waits = Vec::new();
    let delivered = deliver_with_retry(
        "测试事件",
        2,
        || {
            attempts += 1;
            if attempts < 3 {
                Err(AuditFailure::Http(503))
            } else {
                Ok(())
            }
        },
        |duration| waits.push(duration.as_secs()),
    );
    assert!(delivered);
    assert_eq!(attempts, 3);
    assert_eq!(waits, vec![1, 2]);
}

#[test]
fn stops_after_retry_budget_and_can_disable_retries() {
    for (max_retries, expected) in [(0, 1), (2, 3), (5, 6)] {
        let mut attempts = 0;
        let mut waits = Vec::new();
        let delivered = deliver_with_retry(
            "测试事件",
            max_retries,
            || {
                attempts += 1;
                Err(AuditFailure::Network(ErrorKind::TimedOut))
            },
            |duration| waits.push(duration.as_secs()),
        );
        assert!(!delivered);
        assert_eq!(attempts, expected);
        assert_eq!(waits.len() as u64, max_retries);
        assert!(waits.iter().all(|seconds| *seconds <= 16));
    }
}

#[test]
fn permanent_failures_do_not_sleep_or_retry() {
    for code in [301, 401, 403, 404] {
        let mut attempts = 0;
        assert!(!deliver_with_retry(
            "测试事件",
            5,
            || {
                attempts += 1;
                Err(AuditFailure::Http(code))
            },
            |_| panic!("永久性错误不应触发重试")
        ));
        assert_eq!(attempts, 1);
    }
}

#[test]
fn validates_callback_address_without_exposing_credentials() {
    assert!(validate_url("https://api.example.com/api/connection-audit/server").is_ok());
    assert!(validate_url("http://127.0.0.1:21114/api/connection-audit/server").is_ok());
    for url in [
        "file:///data/audit",
        "ftp://api.example.com",
        "not-a-url",
        "https://user:password@api.example.com/audit",
        "https://api.example.com/audit#fragment",
        "https://api.example.com/audit\r\nX-Test: injected",
    ] {
        assert!(validate_url(url).is_err());
    }
}

#[test]
fn bounds_configuration_values() {
    for invalid in ["", "0", "61", "-1", "abc", "99999999999999999999999"] {
        assert_eq!(parse_number(invalid, 5, 1, 60), 5);
    }
    assert_eq!(parse_number("60", 5, 1, 60), 60);
    assert_eq!(parse_number("0", 2, 0, 5), 0);
    assert_eq!(parse_number("6", 2, 0, 5), 2);
}

#[test]
fn posts_expected_payload_and_secret_without_reading_response_body() {
    // 声称有巨大响应体但不发送；回调只需要确认响应头中的 2xx 状态。
    let (url, server) = http_server(
        "HTTP/1.1 200 OK\r\nContent-Length: 100000000\r\n\r\n".to_owned(),
        Duration::ZERO,
    );
    let config = test_config(url);
    let body = r#"{"actor":"测试用户","targetId":"123456"}"#;
    assert_eq!(send_once(&config, body), Ok(()));
    let request = server.join().unwrap();
    assert!(request.starts_with("POST /api/connection-audit/server HTTP/1.1\r\n"));
    assert!(request.contains(&format!("X-Connection-Audit-Secret: {}\r\n", config.secret)));
    assert!(request.ends_with(body));
}

#[test]
fn detects_actual_http_error_statuses() {
    for code in [401, 403, 404, 429, 500, 503] {
        let (url, server) = http_server(
            format!("HTTP/1.1 {} Error\r\nContent-Length: 0\r\n\r\n", code),
            Duration::ZERO,
        );
        assert_eq!(
            send_once(&test_config(url), "{}"),
            Err(AuditFailure::Http(code))
        );
        server.join().unwrap();
    }
}

#[test]
fn blocks_redirects_before_forwarding_secret() {
    for code in [301, 302, 303, 307, 308] {
        let destination = TcpListener::bind("127.0.0.1:0").unwrap();
        destination.set_nonblocking(true).unwrap();
        let (url, server) = http_server(
            format!(
                "HTTP/1.1 {} Redirect\r\nLocation: http://{}/other\r\nContent-Length: 0\r\n\r\n",
                code,
                destination.local_addr().unwrap()
            ),
            Duration::ZERO,
        );
        let result = send_once(&test_config(url), "{}");
        assert!(matches!(
            result,
            Err(AuditFailure::Redirect) | Err(AuditFailure::Http(308))
        ));
        server.join().unwrap();
        assert_eq!(
            destination.accept().unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
    }
}

#[test]
fn times_out_slow_callback() {
    let (url, server) = http_server(
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_owned(),
        Duration::from_secs(2),
    );
    let start = Instant::now();
    let result = send_once(&test_config(url), "{}");
    let elapsed = start.elapsed();
    assert!(matches!(
        result,
        Err(AuditFailure::Network(
            ErrorKind::TimedOut | ErrorKind::WouldBlock
        ))
    ));
    assert!(
        elapsed < Duration::from_secs(3),
        "回调超时未生效或测试机器调度严重延迟"
    );
    server.join().unwrap();
}

#[test]
fn rejects_oversized_headers() {
    let response = format!(
        "HTTP/1.1 200 OK\r\nX-Large: {}\r\nContent-Length: 0\r\n\r\n",
        "x".repeat(20 * 1024)
    );
    let (url, server) = http_server(response, Duration::ZERO);
    assert_eq!(
        send_once(&test_config(url), "{}"),
        Err(AuditFailure::InvalidResponse)
    );
    server.join().unwrap();
}

#[test]
fn queue_is_bounded_and_nonblocking() {
    let (sender, receiver) = mpsc::sync_channel(QUEUE_CAPACITY);
    for index in 0..QUEUE_CAPACITY {
        assert!(sender.try_send(index).is_ok());
    }
    assert!(matches!(
        sender.try_send(QUEUE_CAPACITY),
        Err(TrySendError::Full(_))
    ));
    drop(receiver);
    assert!(matches!(
        sender.try_send(0),
        Err(TrySendError::Disconnected(_))
    ));
}

#[test]
fn transport_logs_do_not_echo_error_contents() {
    let failure = transport_failure(minreq::Error::IoError(std::io::Error::new(
        ErrorKind::ConnectionRefused,
        "不得泄漏的密钥或 URL",
    )));
    assert!(!failure.to_string().contains("不得泄漏"));
    assert!(!failure.to_string().contains("URL"));
}

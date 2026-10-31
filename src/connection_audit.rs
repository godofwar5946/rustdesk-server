//! 连接审计的异步投递。不改变票据校验结果，也不等待 API 响应后再允许远程连接。

use once_cell::sync::Lazy;
use std::{
    fmt,
    io::ErrorKind,
    sync::{
        mpsc::{self, SyncSender, TrySendError},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

const QUEUE_CAPACITY: usize = 256;
const WORKER_COUNT: usize = 2;
const MAX_EVENT_BYTES: usize = 64 * 1024;

// 在首次审计事件到来时读取配置，确保 main 已加载 .env；修改后需要重启进程。
static DISPATCHER: Lazy<Option<SyncSender<AuditEvent>>> = Lazy::new(start_dispatcher);

struct AuditEvent {
    id: String,
    body: String,
}

struct AuditConfig {
    url: String,
    secret: String,
    timeout_seconds: u64,
    max_retries: u64,
}

impl AuditConfig {
    fn load() -> Result<Option<Self>, &'static str> {
        let url = read_env(&["CONNECTION_AUDIT_URL", "CONNECTION-AUDIT-URL"]);
        if url.is_empty() {
            return Ok(None);
        }
        let url = validate_url(&url)?;
        let secret = read_env(&[
            "CONNECTION_AUDIT_SECRET",
            "CONNECTION-AUDIT-SECRET",
            "CONNECTION_TICKET_SECRET",
            "CONNECTION-TICKET-SECRET",
        ]);
        if secret.len() < 32 || secret.chars().any(char::is_control) {
            return Err("审计密钥未配置、长度不足 32 字节或含有控制字符");
        }
        Ok(Some(Self {
            url,
            secret,
            timeout_seconds: read_number(
                &[
                    "CONNECTION_AUDIT_TIMEOUT_SECONDS",
                    "CONNECTION-AUDIT-TIMEOUT-SECONDS",
                ],
                5,
                1,
                60,
            ),
            max_retries: read_number(
                &[
                    "CONNECTION_AUDIT_MAX_RETRIES",
                    "CONNECTION-AUDIT-MAX-RETRIES",
                ],
                2,
                0,
                5,
            ),
        }))
    }
}

fn validate_url(value: &str) -> Result<String, &'static str> {
    if value.chars().any(char::is_control) {
        return Err("审计地址不得包含控制字符");
    }
    let url = reqwest::Url::parse(value).map_err(|_| "审计地址不是有效 URL")?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err("审计地址必须是完整的 HTTP 或 HTTPS 地址");
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err("审计地址不得包含用户名、密码或片段，请使用审计密钥请求头认证");
    }
    Ok(url.to_string())
}

fn read_env(names: &[&str]) -> String {
    names
        .iter()
        .find_map(|name| {
            std::env::var(name)
                .ok()
                .map(|v| v.trim().to_owned())
                .filter(|v| !v.is_empty())
        })
        .unwrap_or_default()
}

fn parse_number(value: &str, default: u64, min: u64, max: u64) -> u64 {
    value
        .parse::<u64>()
        .ok()
        .filter(|v| (min..=max).contains(v))
        .unwrap_or(default)
}

fn read_number(names: &[&str], default: u64, min: u64, max: u64) -> u64 {
    let value = read_env(names);
    if !value.is_empty()
        && value
            .parse::<u64>()
            .ok()
            .filter(|v| (min..=max).contains(v))
            .is_none()
    {
        // 不输出配置原值，避免误把密钥填入数字配置后泄漏。
        log::warn!(
            "连接审计配置 {} 无效，使用默认值 {}，允许范围 {}..={}",
            names[0],
            default,
            min,
            max
        );
    }
    parse_number(&value, default, min, max)
}

fn start_dispatcher() -> Option<SyncSender<AuditEvent>> {
    let config = match AuditConfig::load() {
        Ok(Some(config)) => Arc::new(config),
        Ok(None) => return None,
        Err(reason) => {
            log::error!("连接审计回调未启用：{}；修正配置后请重启", reason);
            return None;
        }
    };
    let (sender, receiver) = mpsc::sync_channel::<AuditEvent>(QUEUE_CAPACITY);
    let receiver = Arc::new(Mutex::new(receiver));
    let mut started = 0;
    for index in 0..WORKER_COUNT {
        let config = Arc::clone(&config);
        let receiver = Arc::clone(&receiver);
        let worker = thread::Builder::new()
            .name(format!("connection-audit-{}", index))
            .spawn(move || loop {
                // 仅在取任务时持锁，发送请求和退避期间不占用另一个工作线程。
                let event = {
                    let Ok(receiver) = receiver.lock() else {
                        return;
                    };
                    receiver.recv()
                };
                let Ok(event) = event else {
                    return;
                };
                deliver_with_retry(
                    &event.id,
                    config.max_retries,
                    || send_once(&config, &event.body),
                    thread::sleep,
                );
            });
        match worker {
            Ok(_) => started += 1,
            Err(err) => log::error!("连接审计工作线程创建失败，错误类别={:?}", err.kind()),
        }
    }
    if started == 0 {
        log::error!("连接审计回调不可用：没有可用工作线程；远程连接鉴权仍按原逻辑执行");
        return None;
    }
    log::info!(
        "连接审计回调已启用：HTTPS={}，单次超时={}秒，最大重试={}次，队列容量={}，工作线程={}",
        config.url.starts_with("https://"),
        config.timeout_seconds,
        config.max_retries,
        QUEUE_CAPACITY,
        started
    );
    Some(sender)
}

pub(crate) fn record(body: String) {
    let Some(sender) = DISPATCHER.as_ref() else {
        return;
    };
    let event = AuditEvent {
        id: uuid::Uuid::new_v4().to_string(),
        body,
    };
    if event.body.len() > MAX_EVENT_BYTES {
        log::error!(
            "连接审计事件未投递：event_id={}，事件超过 {} 字节限制",
            event.id,
            MAX_EVENT_BYTES
        );
        return;
    }
    // 队列满时明确记录丢弃，不阻塞远程连接，也不再创建额外投递线程。
    match sender.try_send(event) {
        Ok(()) => {}
        Err(TrySendError::Full(event)) => log::error!(
            "连接审计事件未投递：event_id={}，审计队列已满，请检查 API 可用性",
            event.id
        ),
        Err(TrySendError::Disconnected(event)) => log::error!(
            "连接审计事件未投递：event_id={}，审计工作线程已停止，请重启服务",
            event.id
        ),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum AuditFailure {
    Http(i32),
    Network(ErrorKind),
    Dns,
    Tls,
    Redirect,
    HttpsDisabled,
    InvalidResponse,
}

impl AuditFailure {
    fn retryable(&self) -> bool {
        match self {
            Self::Http(code) => matches!(code, 408 | 429 | 500..=599),
            Self::Network(kind) => !matches!(
                kind,
                ErrorKind::InvalidData | ErrorKind::InvalidInput | ErrorKind::PermissionDenied
            ),
            Self::Dns => true,
            _ => false,
        }
    }
}

impl fmt::Display for AuditFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http(code) => {
                let hint = match code {
                    401 | 403 => "检查 API 与 hbbs/hbbr 的审计密钥和访问策略",
                    404 => "检查回调路径 /api/connection-audit/server",
                    300..=399 => "请直接配置最终回调地址，不允许自动跳转",
                    408 | 429 | 500..=599 => "API 暂时不可用或请求受限",
                    _ => "API 未接受审计事件",
                };
                write!(f, "HTTP {}（{}）", code, hint)
            }
            Self::Network(ErrorKind::TimedOut | ErrorKind::WouldBlock) => write!(f, "回调请求超时"),
            Self::Network(ErrorKind::InvalidData) | Self::Tls => write!(
                f,
                "TLS 校验或响应数据异常，请检查证书域名、有效期和完整证书链"
            ),
            Self::Network(kind) => write!(f, "网络请求失败，错误类别={:?}", kind),
            Self::Dns => write!(f, "回调地址未解析到可用 IP"),
            Self::Redirect => write!(f, "回调发生重定向，已阻止转发审计密钥，请配置最终地址"),
            Self::HttpsDisabled => write!(f, "服务端未编译 HTTPS 支持，请更新镜像"),
            Self::InvalidResponse => write!(f, "回调协议或响应头无效，请检查 API 和代理配置"),
        }
    }
}

fn transport_failure(err: minreq::Error) -> AuditFailure {
    // 不输出原始错误、响应正文、完整 URL 或请求头，防止凭据和个人信息进入日志。
    match err {
        minreq::Error::IoError(err) => AuditFailure::Network(err.kind()),
        minreq::Error::AddressNotFound => AuditFailure::Dns,
        minreq::Error::RustlsCreateConnection(_) => AuditFailure::Tls,
        minreq::Error::TooManyRedirections
        | minreq::Error::InfiniteRedirectionLoop
        | minreq::Error::RedirectLocationMissing => AuditFailure::Redirect,
        minreq::Error::HttpsFeatureNotEnabled => AuditFailure::HttpsDisabled,
        _ => AuditFailure::InvalidResponse,
    }
}

fn check_status(code: i32) -> Result<(), AuditFailure> {
    if (200..300).contains(&code) {
        Ok(())
    } else {
        Err(AuditFailure::Http(code))
    }
}

fn send_once(config: &AuditConfig, body: &str) -> Result<(), AuditFailure> {
    // 仅读取状态码和有上限的响应头，不下载响应正文；HTTPS 保留默认的证书与域名校验。
    let response = minreq::post(&config.url)
        .with_header("Content-Type", "application/json")
        .with_header("X-Connection-Audit-Secret", &config.secret)
        .with_timeout(config.timeout_seconds)
        .with_max_redirects(0)
        .with_max_headers_size(16 * 1024)
        .with_max_status_line_length(1024)
        .with_body(body.as_bytes())
        .send_lazy()
        .map_err(transport_failure)?;
    check_status(response.status_code)
}

fn deliver_with_retry(
    event_id: &str,
    max_retries: u64,
    mut send: impl FnMut() -> Result<(), AuditFailure>,
    mut wait: impl FnMut(Duration),
) -> bool {
    let mut attempt = 1;
    loop {
        match send() {
            Ok(()) => {
                if attempt > 1 {
                    log::info!(
                        "连接审计重试成功：event_id={}，尝试次数={}",
                        event_id,
                        attempt
                    );
                } else {
                    log::debug!("连接审计投递成功：event_id={}", event_id);
                }
                return true;
            }
            Err(failure) if failure.retryable() && attempt <= max_retries => {
                let delay = Duration::from_secs(1 << (attempt - 1).min(4));
                log::warn!(
                    "连接审计回调失败：event_id={}，尝试次数={}，原因={}，将在 {} 秒后重试",
                    event_id,
                    attempt,
                    failure,
                    delay.as_secs()
                );
                wait(delay);
                attempt += 1;
            }
            Err(failure) => {
                log::error!(
                    "连接审计投递失败：event_id={}，尝试次数={}，原因={}；事件未确认入库，不再自动重试",
                    event_id, attempt, failure
                );
                return false;
            }
        }
    }
}

#[cfg(test)]
#[path = "connection_audit_tests.rs"]
mod tests;

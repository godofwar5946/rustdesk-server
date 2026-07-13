use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Default)]
pub(crate) struct TicketClaims {
    pub actor: String,
    pub from_id: String,
    pub target: String,
}

pub(crate) fn enabled() -> bool {
    let value = read_env(&["CONNECTION_AUTH_ENABLED", "CONNECTION-AUTH-ENABLED", "CONNECTION_AUTH", "CONNECTION-AUTH"]);
    matches!(value.to_ascii_uppercase().as_str(), "1" | "Y" | "YES" | "TRUE" | "ON")
}

pub(crate) fn verify_or_error(ticket: &str, expected_target: &str) -> Result<TicketClaims, String> {
    if !enabled() {
        return Ok(TicketClaims { target: expected_target.to_owned(), ..Default::default() });
    }
    if expected_target.trim().is_empty() {
        return Err("缺少目标设备编号".to_owned());
    }
    if ticket.trim().is_empty() {
        return Err("缺少连接鉴权票据".to_owned());
    }
    let secret = read_env(&["CONNECTION_TICKET_SECRET", "CONNECTION-TICKET-SECRET"]);
    if secret.len() < 32 {
        return Err("连接票据密钥未配置或长度不足".to_owned());
    }

    let mut parts = ticket.split('.');
    let Some(payload_part) = parts.next() else { return Err("连接票据格式错误".to_owned()); };
    let Some(signature_part) = parts.next() else { return Err("连接票据格式错误".to_owned()); };
    if parts.next().is_some() || payload_part.is_empty() || signature_part.is_empty() {
        return Err("连接票据格式错误".to_owned());
    }

    let expected_signature = sign(payload_part, &secret)?;
    let provided_signature = decode_base64(signature_part).map_err(|_| "连接票据签名格式错误".to_owned())?;
    if !constant_time_eq(&expected_signature, &provided_signature) {
        return Err("连接票据签名无效".to_owned());
    }

    let payload_bytes = decode_base64(payload_part).map_err(|_| "连接票据内容格式错误".to_owned())?;
    let payload: Value = serde_json::from_slice(&payload_bytes).map_err(|_| "连接票据内容不是有效 JSON".to_owned())?;
    let target = payload.get("target").and_then(Value::as_str).unwrap_or_default().to_owned();
    if target != expected_target {
        return Err("连接票据目标设备不匹配".to_owned());
    }
    let exp = payload.get("exp").and_then(Value::as_i64).unwrap_or_default();
    if exp <= now_epoch_seconds() as i64 {
        return Err("连接票据已过期".to_owned());
    }
    Ok(TicketClaims {
        actor: payload.get("user").and_then(Value::as_str).unwrap_or_default().to_owned(),
        from_id: payload.get("from").and_then(Value::as_str).unwrap_or_default().to_owned(),
        target,
    })
}

pub(crate) fn record_connection_audit(claims: Option<&TicketClaims>, target: &str, source: &str, source_ip: &str, phase: &str, outcome: &str, reason: &str) {
    let url = read_env(&["CONNECTION_AUDIT_URL", "CONNECTION-AUDIT-URL"]);
    if url.is_empty() {
        return;
    }
    let secret = read_env(&["CONNECTION_AUDIT_SECRET", "CONNECTION-AUDIT-SECRET", "CONNECTION_TICKET_SECRET", "CONNECTION-TICKET-SECRET"]);
    if secret.len() < 32 {
        log::warn!("Connection audit skipped: audit secret is not configured");
        return;
    }
    let claims = claims.cloned().unwrap_or_default();
    let body = serde_json::json!({
        "actor": claims.actor,
        "fromId": claims.from_id,
        "targetId": if claims.target.is_empty() { target } else { claims.target.as_str() },
        "source": source,
        "sourceIp": source_ip,
        "phase": phase,
        "outcome": outcome,
        "reason": reason,
    }).to_string();
    std::thread::spawn(move || {
        let result = minreq::post(&url)
            .with_header("Content-Type", "application/json")
            .with_header("X-Connection-Audit-Secret", &secret)
            .with_body(body)
            .send();
        if let Err(err) = result {
            log::warn!("Connection audit callback failed: {}", err);
        }
    });
}

fn sign(payload_part: &str, secret: &str) -> Result<Vec<u8>, String> {
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).map_err(|_| "连接票据密钥无效".to_owned())?;
    mac.update(payload_part.as_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

fn decode_base64(value: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::decode_config(value, base64::URL_SAFE_NO_PAD)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn now_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn read_env(names: &[&str]) -> String {
    for name in names {
        if let Ok(value) = std::env::var(name) {
            let value = value.trim().to_owned();
            if !value.is_empty() {
                return value;
            }
        }
    }
    String::new()
}


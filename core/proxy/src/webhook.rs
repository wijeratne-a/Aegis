use anyhow::{Context, Result};
use chrono::Utc;
use hmac::{Hmac, Mac};
use serde::Serialize;
use sha2::Sha256;
use tracing::warn;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
pub struct WebhookConfig {
    pub url: String,
    pub secret: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebhookEvent {
    pub event_type: String,
    pub request_id: String,
    pub method: String,
    pub target: String,
    pub reason: String,
    pub timestamp_ns: i64,
}

impl WebhookEvent {
    pub fn new(
        event_type: impl Into<String>,
        request_id: impl Into<String>,
        method: impl Into<String>,
        target: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            event_type: event_type.into(),
            request_id: request_id.into(),
            method: method.into(),
            target: target.into(),
            reason: reason.into(),
            timestamp_ns: Utc::now().timestamp_nanos_opt().unwrap_or_default(),
        }
    }
}

pub fn signature_for_payload(secret: &str, payload: &[u8]) -> Result<String> {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).context("failed to initialize HMAC key")?;
    mac.update(payload);
    let signature = hex::encode(mac.finalize().into_bytes());
    Ok(format!("sha256={signature}"))
}

pub async fn emit(client: &reqwest::Client, config: &WebhookConfig, event: &WebhookEvent) {
    let payload = match serde_json::to_vec(event) {
        Ok(payload) => payload,
        Err(err) => {
            warn!("failed to serialize webhook payload: {err}");
            return;
        }
    };

    let signature = match signature_for_payload(&config.secret, &payload) {
        Ok(signature) => signature,
        Err(err) => {
            warn!("failed to sign webhook payload: {err}");
            return;
        }
    };

    let request = client
        .post(&config.url)
        .timeout(std::time::Duration::from_secs(3))
        .header("content-type", "application/json")
        .header("X-Aegis-Signature", signature)
        .body(payload);

    if let Err(err) = request.send().await {
        warn!("webhook delivery failed: {err}");
    }
}

#[cfg(test)]
mod tests {
    use super::signature_for_payload;

    #[test]
    fn signature_has_expected_format_and_value() {
        let sig =
            signature_for_payload("topsecret", br#"{"event_type":"policy_block"}"#).unwrap();
        assert_eq!(
            sig,
            "sha256=6f834b03b863ce427a4eaaec834e886f6da71959ecf7c43c546ccc5c66a0a461"
        );
    }
}

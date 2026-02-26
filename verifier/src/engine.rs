use anyhow::{Context, Result};
use chrono::Utc;
use dashmap::DashMap;
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use serde_json::Value;

use crate::schema::{PotReceipt, VerifyRequest, VerifyResponse};

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Serialize)]
struct UnsignedReceipt<'a> {
    policy_commitment: &'a str,
    trace_hash: String,
    timestamp_ns: i64,
}

pub fn verify_trace(
    request: &VerifyRequest,
    policy_store: &DashMap<String, Value>,
    signing_key: &SigningKey,
) -> Result<VerifyResponse> {
    if !policy_store.contains_key(&request.policy_commitment) {
        return Ok(invalid("unknown policy commitment"));
    }

    let domain = request.agent_metadata.domain.to_ascii_lowercase();
    match domain.as_str() {
        "defi" => {
            if let Some(reason) = verify_defi(request) {
                return Ok(invalid(reason));
            }
        }
        "enterprise" => {
            if let Some(reason) = verify_enterprise(request) {
                return Ok(invalid(reason));
            }
        }
        _ => return Ok(invalid("unsupported domain")),
    }

    let trace_bytes = serde_json::to_vec(&request.execution_trace)
        .context("failed to serialize execution_trace for hashing")?;
    let trace_hash = format!("0x{}", blake3::hash(&trace_bytes).to_hex());
    let timestamp_ns = Utc::now().timestamp_nanos_opt().unwrap_or_default();

    let unsigned = UnsignedReceipt {
        policy_commitment: &request.policy_commitment,
        trace_hash: trace_hash.clone(),
        timestamp_ns,
    };
    let unsigned_bytes =
        serde_json::to_vec(&unsigned).context("failed to serialize PoT receipt for signing")?;
    let signature = signing_key.sign(&unsigned_bytes);

    let proof = PotReceipt {
        policy_commitment: request.policy_commitment.clone(),
        trace_hash,
        timestamp_ns,
        signature: hex_encode(&signature.to_bytes()),
        public_key: hex_encode(signing_key.verifying_key().as_bytes()),
    };

    Ok(VerifyResponse {
        valid: true,
        reason: None,
        proof: Some(proof),
    })
}

fn verify_defi(request: &VerifyRequest) -> Option<String> {
    let max_spend = request.public_values.max_spend.unwrap_or(f64::INFINITY);
    let restricted = request
        .public_values
        .restricted_endpoints
        .clone()
        .unwrap_or_default();

    let mut total_spend = 0.0f64;
    for entry in &request.execution_trace {
        if let Some(amount) = entry.amount {
            total_spend += amount;
        }

        if restricted
            .iter()
            .any(|blocked| entry.target.contains(blocked))
        {
            return Some(format!("restricted endpoint accessed: {}", entry.target));
        }
    }

    if total_spend > max_spend {
        return Some(format!(
            "max spend exceeded: total_spend={total_spend}, max_spend={max_spend}"
        ));
    }
    None
}

fn verify_enterprise(request: &VerifyRequest) -> Option<String> {
    let restricted = request
        .public_values
        .restricted_endpoints
        .clone()
        .unwrap_or_default();

    for entry in &request.execution_trace {
        if let Some(table) = &entry.table {
            if restricted.iter().any(|blocked| blocked == table) {
                return Some(format!("restricted table accessed: {table}"));
            }
        }
    }
    None
}

fn invalid(reason: impl Into<String>) -> VerifyResponse {
    VerifyResponse {
        valid: false,
        reason: Some(reason.into()),
        proof: None,
    }
}

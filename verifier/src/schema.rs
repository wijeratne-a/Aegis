use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterResponse {
    pub policy_commitment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentMetadata {
    pub domain: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TraceEntry {
    pub action: String,
    pub target: String,
    pub amount: Option<f64>,
    pub table: Option<String>,
    pub details: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicValues {
    pub max_spend: Option<f64>,
    pub restricted_endpoints: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyRequest {
    pub agent_metadata: AgentMetadata,
    pub policy_commitment: String,
    pub execution_trace: Vec<TraceEntry>,
    pub public_values: PublicValues,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PotReceipt {
    pub policy_commitment: String,
    pub trace_hash: String,
    pub timestamp_ns: i64,
    pub signature: String,
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyResponse {
    pub valid: bool,
    pub reason: Option<String>,
    pub proof: Option<PotReceipt>,
}

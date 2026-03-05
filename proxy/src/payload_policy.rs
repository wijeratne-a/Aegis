//! Request-level Rego policy evaluation for MITM payload parsing.
//! Evaluates allow/reason against decrypted HTTP request (method, path, host, body, headers, identity).
//! The Rego policy is compiled once at startup; each evaluation clones the pre-built engine.

use anyhow::{Context, Result};
use regorus::Value as RegoValue;
use serde::Serialize;
use std::{fs, path::Path};

pub struct PayloadPolicyEngine {
    engine: regorus::Engine,
}

#[derive(Debug, Clone)]
pub struct PayloadDecision {
    pub allow: bool,
    pub reason: Option<String>,
}

impl PayloadPolicyEngine {
    /// Load and pre-compile payload policy from a file path (e.g. policies/payload.rego).
    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let source = fs::read_to_string(path)
            .with_context(|| format!("failed to read payload policy from {}", path.display()))?;
        let mut engine = regorus::Engine::new();
        engine
            .add_policy("payload.rego".to_string(), source)
            .context("failed to compile payload Rego policy")?;
        Ok(Self { engine })
    }

    /// Evaluate the pre-compiled policy against the given request input.
    pub fn evaluate(&self, input: &impl Serialize) -> Result<PayloadDecision> {
        let mut engine = self.engine.clone();
        let input_json = serde_json::to_string(input)?;
        engine.set_input(RegoValue::from_json_str(&input_json)?);

        let allow = engine.eval_allow_query("data.aegis.payload.allow".to_string(), false);
        if allow {
            return Ok(PayloadDecision {
                allow: true,
                reason: None,
            });
        }

        let reason = engine
            .eval_query("data.aegis.payload.reason".to_string(), false)
            .ok()
            .and_then(|results| results.result.first().cloned())
            .and_then(|row| row.expressions.first().cloned())
            .and_then(|expr| expr.value.as_string().ok().map(|s| s.to_string()));

        Ok(PayloadDecision {
            allow: false,
            reason: reason.or(Some("payload policy denied request".to_string())),
        })
    }
}

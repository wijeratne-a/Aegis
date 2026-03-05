use std::{fs, net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use hyper::{
    body::Incoming,
    server::conn::http1,
    service::service_fn,
    Request,
};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{error, info};

mod certs;
mod intercept;
mod payload_policy;
mod schema_validator;
pub mod telemetry;
mod trace_log;

use certs::{build_mitm_server_config, RootCa};
use intercept::{EnforceMode, LivePolicy, PolicyConfig, ProxyConfig, ProxyState};
use trace_log::TraceLogger;

fn read_policy(path: &str) -> Result<PolicyConfig> {
    let raw = fs::read_to_string(path).with_context(|| format!("failed to read {path}"))?;
    serde_json::from_str(&raw).with_context(|| format!("invalid policy JSON in {path}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    telemetry::init_telemetry()?;

    let policy_path = std::env::var("POLICY_PATH").unwrap_or_else(|_| "policy.json".to_string());
    let enforce_mode = std::env::var("ENFORCE_MODE")
        .unwrap_or_else(|_| "strict".to_string())
        .parse::<EnforceMode>()?;
    let verifier_url =
        std::env::var("VERIFIER_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
    let bind = std::env::var("PROXY_BIND").unwrap_or_else(|_| "0.0.0.0:8080".to_string());
    let trace_wal =
        std::env::var("TRACE_WAL_PATH").unwrap_or_else(|_| "./data/proxy-trace.jsonl".to_string());
    let semantic_deny = std::env::var("SEMANTIC_DENY")
        .map(|v| v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("1"))
        .unwrap_or(true);

    let upstream_timeout_secs = std::env::var("UPSTREAM_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&s| s >= 1 && s <= 300)
        .unwrap_or_else(|| {
            if std::env::var("UPSTREAM_TIMEOUT_SECS").is_ok() {
                error!("UPSTREAM_TIMEOUT_SECS invalid (must be 1-300); using 10");
            }
            10
        });

    let policy = read_policy(&policy_path).unwrap_or_else(|err| {
        error!("failed to load policy from {}: {}; defaulting empty", policy_path, err);
        PolicyConfig::default()
    });

    let root_ca = match (
        std::env::var("AEGIS_CA_CERT_PATH"),
        std::env::var("AEGIS_CA_KEY_PATH"),
    ) {
        (Ok(cert_path), Ok(key_path)) => {
            let cert_pem = fs::read_to_string(&cert_path)
                .with_context(|| format!("failed to read CA cert from {cert_path}"))?;
            let key_pem = fs::read_to_string(&key_path)
                .with_context(|| format!("failed to read CA key from {key_path}"))?;
            RootCa::from_pem(&cert_pem, &key_pem)?
        }
        _ => RootCa::generate()?,
    };
    let ca_pem = root_ca.export_pem();
    if let Ok(ca_path) = std::env::var("AEGIS_CA_PATH") {
        if let Some(parent) = std::path::Path::new(&ca_path).parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&ca_path, &ca_pem)?;
        info!("Root CA written to {}", ca_path);
    }

    let mitm_server_config = build_mitm_server_config(root_ca)?;

    let payload_engine = std::env::var("POLICY_REGO_PATH")
        .unwrap_or_else(|_| "policies/payload.rego".to_string());
    let payload_engine = payload_policy::PayloadPolicyEngine::load_from_path(&payload_engine)
        .map(Arc::new)
        .ok();

    let schema_registry = std::env::var("SCHEMA_REGISTRY_PATH")
        .ok()
        .or_else(|| std::env::var("SCHEMA_DIR").ok().map(|d| format!("{}/registry.json", d)));
    let schema_registry = schema_registry
        .as_ref()
        .and_then(|p| schema_validator::SchemaRegistry::load_from_path(p).ok().flatten())
        .map(Arc::new);

    if schema_registry.is_some() {
        info!("Schema registry loaded for request body validation");
    }

    let live_policy = Arc::new(std::sync::RwLock::new(LivePolicy {
        config: policy.clone(),
        payload_engine: payload_engine.clone(),
    }));

    let state = ProxyState {
        config: Arc::new(ProxyConfig {
            enforce_mode,
            verifier_url,
            policy,
            semantic_deny,
        }),
        logger: TraceLogger::new(&trace_wal)?,
        client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(upstream_timeout_secs))
            .build()
            .context("failed to build reqwest client")?,
        mitm_server_config,
        payload_engine,
        schema_registry,
        ca_pem: Some(ca_pem),
        live_policy,
    };

    let addr: SocketAddr = bind
        .parse()
        .with_context(|| format!("invalid PROXY_BIND address {bind}"))?;
    let listener = TcpListener::bind(addr).await?;
    info!("aegis-proxy listening on http://{addr}");

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state = state.clone();

        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let state = state.clone();
                async move {
                    let resp = match intercept::handle(state.clone(), req, remote_addr).await {
                        Ok(resp) => resp,
                        Err(err) => {
                            error!("proxy request handling error: {err}");
                            let body = if state.config.enforce_mode == EnforceMode::AuditOnly {
                                r#"{"warning":"proxy error in audit_only mode"}"#
                            } else {
                                r#"{"error":"proxy failure in strict mode"}"#
                            };
                            hyper::Response::builder()
                                .status(http::StatusCode::BAD_GATEWAY)
                                .header("content-type", "application/json")
                                .body(http_body_util::Full::new(bytes::Bytes::from(body)))
                                .unwrap_or_else(|_| {
                                    hyper::Response::builder()
                                        .status(http::StatusCode::INTERNAL_SERVER_ERROR)
                                        .body(http_body_util::Full::new(bytes::Bytes::from(
                                            r#"{"error":"internal error"}"#,
                                        )))
                                        .expect("fallback 500 must succeed")
                                })
                        }
                    };
                    Ok::<_, hyper::Error>(resp)
                }
            });

            if let Err(err) = http1::Builder::new()
                .preserve_header_case(true)
                .title_case_headers(true)
                .serve_connection(io, svc)
                .with_upgrades()
                .await
            {
                error!("connection error: {err}");
            }
        });
    }
}

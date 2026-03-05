use anyhow::{Context, Result};
use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::Value;
use std::sync::{Arc, Mutex};
use tracing::warn;

#[async_trait]
pub trait PolicyStore: Send + Sync {
    async fn upsert_policy(&self, commitment: &str, policy: &Value) -> Result<()>;
    async fn has_policy(&self, commitment: &str) -> Result<bool>;
}

pub struct InMemoryPolicyStore {
    policies: DashMap<String, Value>,
}

impl InMemoryPolicyStore {
    pub fn new() -> Self {
        Self {
            policies: DashMap::new(),
        }
    }
}

#[async_trait]
impl PolicyStore for InMemoryPolicyStore {
    async fn upsert_policy(&self, commitment: &str, policy: &Value) -> Result<()> {
        self.policies
            .insert(commitment.to_string(), policy.clone());
        Ok(())
    }

    async fn has_policy(&self, commitment: &str) -> Result<bool> {
        Ok(self.policies.contains_key(commitment))
    }
}

pub struct SqlitePolicyStore {
    conn: Mutex<rusqlite::Connection>,
}

impl SqlitePolicyStore {
    pub fn new(path: &str) -> Result<Self> {
        let conn = rusqlite::Connection::open(path)
            .with_context(|| format!("failed to open sqlite policy db at {path}"))?;
        conn.execute(
            "CREATE TABLE IF NOT EXISTS policies (
                policy_commitment TEXT PRIMARY KEY,
                policy_json TEXT NOT NULL,
                created_at_unix INTEGER NOT NULL DEFAULT (strftime('%s','now'))
            )",
            [],
        )
        .context("failed to initialize sqlite policy table")?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }
}

#[async_trait]
impl PolicyStore for SqlitePolicyStore {
    async fn upsert_policy(&self, commitment: &str, policy: &Value) -> Result<()> {
        let policy_json =
            serde_json::to_string(policy).context("failed to encode policy json for sqlite")?;
        let conn = self.conn.lock().expect("sqlite lock poisoned");
        conn.execute(
            "INSERT INTO policies(policy_commitment, policy_json, created_at_unix)
             VALUES (?1, ?2, strftime('%s','now'))
             ON CONFLICT(policy_commitment)
             DO UPDATE SET policy_json=excluded.policy_json",
            rusqlite::params![commitment, policy_json],
        )
        .context("failed to upsert policy in sqlite store")?;
        Ok(())
    }

    async fn has_policy(&self, commitment: &str) -> Result<bool> {
        let conn = self.conn.lock().expect("sqlite lock poisoned");
        let mut stmt = conn
            .prepare("SELECT 1 FROM policies WHERE policy_commitment = ?1 LIMIT 1")
            .context("failed to prepare sqlite exists query")?;
        let mut rows = stmt
            .query(rusqlite::params![commitment])
            .context("failed to execute sqlite exists query")?;
        Ok(rows.next()?.is_some())
    }
}

pub fn build_policy_store() -> Arc<dyn PolicyStore> {
    let mode = std::env::var("POLICY_STORE").unwrap_or_else(|_| "sqlite".to_string());
    if mode == "memory" || mode == "in_memory" {
        return Arc::new(InMemoryPolicyStore::new());
    }

    let path = std::env::var("POLICY_DB_PATH").unwrap_or_else(|_| "policies.db".to_string());
    match SqlitePolicyStore::new(&path) {
        Ok(store) => Arc::new(store),
        Err(err) => {
            warn!(
                error = %err,
                "sqlite policy store unavailable, falling back to in-memory store"
            );
            Arc::new(InMemoryPolicyStore::new())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sqlite_policy_store_persists_policy() {
        let store = SqlitePolicyStore::new(":memory:").expect("store create");
        let policy = serde_json::json!({ "domain": "defi" });
        store
            .upsert_policy("0xabc", &policy)
            .await
            .expect("insert policy");

        let exists = store.has_policy("0xabc").await.expect("exists query");
        assert!(exists);
        let missing = store.has_policy("0xdef").await.expect("missing query");
        assert!(!missing);
    }
}

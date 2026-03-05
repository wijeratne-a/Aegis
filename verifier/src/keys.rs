use anyhow::{Context, Result};
use async_trait::async_trait;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use std::sync::Arc;

#[async_trait]
pub trait KeyProvider: Send + Sync {
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn public_key_bytes(&self) -> Vec<u8>;
}

pub struct LocalKeyProvider {
    key: SigningKey,
}

impl LocalKeyProvider {
    pub fn new_random() -> Self {
        Self {
            key: SigningKey::generate(&mut OsRng),
        }
    }
}

#[async_trait]
impl KeyProvider for LocalKeyProvider {
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(self.key.sign(data).to_bytes().to_vec())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.key.verifying_key().as_bytes().to_vec()
    }
}

pub struct EnvKeyProvider {
    key: SigningKey,
}

impl EnvKeyProvider {
    pub fn from_env() -> Result<Self> {
        let hex_key = std::env::var("AEGIS_SIGNING_KEY_HEX")
            .context("AEGIS_SIGNING_KEY_HEX missing for EnvKeyProvider")?;
        let raw = hex::decode(hex_key).context("AEGIS_SIGNING_KEY_HEX is invalid hex")?;
        let arr: [u8; 32] = raw
            .as_slice()
            .try_into()
            .context("AEGIS_SIGNING_KEY_HEX must be 32 bytes")?;
        Ok(Self {
            key: SigningKey::from_bytes(&arr),
        })
    }
}

#[async_trait]
impl KeyProvider for EnvKeyProvider {
    async fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        Ok(self.key.sign(data).to_bytes().to_vec())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.key.verifying_key().as_bytes().to_vec()
    }
}

pub struct AwsKmsProvider {
    _key_id: String,
}

impl AwsKmsProvider {
    pub fn new(key_id: String) -> Self {
        Self { _key_id: key_id }
    }
}

#[async_trait]
impl KeyProvider for AwsKmsProvider {
    async fn sign(&self, _data: &[u8]) -> Result<Vec<u8>> {
        anyhow::bail!("AWS KMS provider not yet implemented -- use KEY_PROVIDER=local or env")
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        vec![]
    }
}

pub struct VaultProvider {
    _mount_path: String,
    _key_name: String,
}

impl VaultProvider {
    pub fn new(mount_path: String, key_name: String) -> Self {
        Self {
            _mount_path: mount_path,
            _key_name: key_name,
        }
    }
}

#[async_trait]
impl KeyProvider for VaultProvider {
    async fn sign(&self, _data: &[u8]) -> Result<Vec<u8>> {
        anyhow::bail!("Vault provider not yet implemented -- use KEY_PROVIDER=local or env")
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        vec![]
    }
}

pub fn build_key_provider() -> Result<Arc<dyn KeyProvider>> {
    let provider = std::env::var("KEY_PROVIDER").unwrap_or_else(|_| "local".to_string());
    match provider.as_str() {
        "local" => Ok(Arc::new(LocalKeyProvider::new_random())),
        "env" => Ok(Arc::new(EnvKeyProvider::from_env()?)),
        "aws_kms" => {
            let key_id = std::env::var("AWS_KMS_KEY_ID")
                .context("AWS_KMS_KEY_ID required when KEY_PROVIDER=aws_kms")?;
            Ok(Arc::new(AwsKmsProvider::new(key_id)))
        }
        "vault" => {
            let mount_path = std::env::var("VAULT_MOUNT_PATH")
                .context("VAULT_MOUNT_PATH required when KEY_PROVIDER=vault")?;
            let key_name = std::env::var("VAULT_KEY_NAME")
                .context("VAULT_KEY_NAME required when KEY_PROVIDER=vault")?;
            Ok(Arc::new(VaultProvider::new(mount_path, key_name)))
        }
        _ => anyhow::bail!("unknown KEY_PROVIDER={provider}, expected local|env|aws_kms|vault"),
    }
}

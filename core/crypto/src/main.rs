use std::{
    fs,
    os::unix::fs::PermissionsExt,
    time::SystemTime,
};

use anyhow::Context as _;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use serde::Serialize;

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(Serialize)]
struct Manifest {
    policy_hash: String,
    timestamp_ns: u128,
    task_id: String,
}

#[derive(Serialize)]
struct SignedManifest {
    manifest: Manifest,
    signature: String,
    public_key: String,
}

fn main() -> anyhow::Result<()> {
    // ── Ed25519 key generation ──
    let signing_key = SigningKey::generate(&mut OsRng);

    let key_path = "signing_key.bin";
    fs::write(key_path, signing_key.to_bytes())?;
    fs::set_permissions(key_path, fs::Permissions::from_mode(0o600))?;
    println!("[crypto] Private key written to {key_path} (mode 0600)");

    // ── BLAKE3 integrity hash of policy.json ──
    let policy_bytes = fs::read("policy.json").context("failed to read policy.json")?;
    let policy_hash = blake3::hash(&policy_bytes);
    println!("[crypto] BLAKE3(policy.json) = {}", policy_hash.to_hex());

    // ── Build manifest with high-resolution timestamp and unique TaskID ──
    let timestamp_ns = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_nanos();

    let task_id = hex_encode(&rand::random::<[u8; 16]>());

    let manifest = Manifest {
        policy_hash: policy_hash.to_hex().to_string(),
        timestamp_ns,
        task_id,
    };

    // ── Sign the canonical JSON encoding of the manifest ──
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let signature = signing_key.sign(&manifest_bytes);

    let signed = SignedManifest {
        manifest,
        signature: hex_encode(&signature.to_bytes()),
        public_key: hex_encode(signing_key.verifying_key().as_bytes()),
    };

    let output = serde_json::to_string_pretty(&signed)?;
    fs::write("manifest.json", &output)?;
    println!("[crypto] Signed manifest written to manifest.json");

    Ok(())
}

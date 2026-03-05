//! Root CA and dynamic leaf certificate generation for TLS MITM.
//! Agents must trust the Root CA via REQUESTS_CA_BUNDLE or NODE_EXTRA_CA_CERTS.

use std::sync::Arc;

use anyhow::{Context, Result};
use rcgen::{BasicConstraints, Certificate, CertificateParams, IsCa, KeyPair, SanType};
use rustls::pki_types::PrivateKeyDer;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::ServerConfig;
use tracing::info;

const CERT_CACHE_MAX: usize = 256;

/// Root CA for forging leaf certificates. Generated at proxy startup.
pub struct RootCa {
    cert: Certificate,
    key: KeyPair,
}

impl RootCa {
    /// Generate a new self-signed Root CA in memory.
    pub fn generate() -> Result<Self> {
        let mut params = CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            rcgen::DnValue::Utf8String("Aegis Proxy Root CA".into()),
        );
        params.subject_alt_names =
            vec![SanType::DnsName(rcgen::string::Ia5String::try_from("aegis-proxy-ca.local")?)];
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];

        let key = KeyPair::generate().context("failed to generate CA key pair")?;
        let cert = params
            .self_signed(&key)
            .context("failed to self-sign CA certificate")?;

        info!("Aegis Proxy Root CA generated");
        Ok(Self { cert, key })
    }

    /// Forge a leaf certificate for the given SNI hostname, signed by this CA.
    pub fn forge_leaf(&self, sni: &str) -> Result<rustls::sign::CertifiedKey> {
        let mut params = CertificateParams::new(vec![sni.to_string()])
            .context("invalid SNI for certificate")?;
        params.is_ca = IsCa::NoCa;
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];

        let leaf_key = KeyPair::generate().context("failed to generate leaf key pair")?;
        let issuer = rcgen::Issuer::from_ca_cert_der(self.cert.der(), &self.key)?;
        let leaf_cert = params
            .signed_by(&leaf_key, &issuer)
            .context("failed to sign leaf certificate")?;

        let cert_der: rustls::pki_types::CertificateDer<'static> =
            leaf_cert.der().as_ref().to_vec().into();
        let key_der = PrivateKeyDer::from(leaf_key);

        let ck = rustls::sign::CertifiedKey::from_der(
            vec![cert_der],
            key_der,
            &rustls::crypto::aws_lc_rs::default_provider(),
        )
        .context("failed to build CertifiedKey from DER")?;

        Ok(ck)
    }

    /// Export the CA certificate as PEM for agent trust (REQUESTS_CA_BUNDLE, NODE_EXTRA_CA_CERTS).
    pub fn export_pem(&self) -> String {
        self.cert.pem()
    }
}

/// Resolves server cert by forging a leaf for the SNI from ClientHello.
#[derive(Clone)]
pub struct DynamicCertResolver {
    ca: Arc<RootCa>,
    cache: Arc<dashmap::DashMap<String, Arc<rustls::sign::CertifiedKey>>>,
}

impl DynamicCertResolver {
    pub fn new(ca: RootCa) -> Self {
        Self {
            ca: Arc::new(ca),
            cache: Arc::new(dashmap::DashMap::new()),
        }
    }

    fn resolve_impl(&self, sni: &str) -> Option<Arc<rustls::sign::CertifiedKey>> {
        if let Some(ck) = self.cache.get(sni) {
            return Some(Arc::clone(&ck));
        }
        let ck = self.ca.forge_leaf(sni).ok()?;
        let ck = Arc::new(ck);
        if self.cache.len() < CERT_CACHE_MAX {
            self.cache.insert(sni.to_string(), Arc::clone(&ck));
        }
        Some(ck)
    }
}

impl std::fmt::Debug for DynamicCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicCertResolver").finish()
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let sni_str = client_hello.server_name()?;
        self.resolve_impl(sni_str)
    }
}

/// Build a ServerConfig that uses the dynamic cert resolver for TLS MITM.
pub fn build_mitm_server_config(ca: RootCa) -> Result<Arc<ServerConfig>> {
    let resolver = Arc::new(DynamicCertResolver::new(ca));
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    Ok(Arc::new(config))
}

//! Encryption in transit: the certificate authority MWS signs node
//! certificates with, and the TLS client MWS itself talks to nodes with.
//!
//! ElastiCache's nodes present certificates from Amazon's public CAs; MWS's
//! nodes present one from a CA of its own, which clients trust by loading
//! `GET /_aws/elasticache/ca.pem`.

use std::sync::Arc;

use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose};
use serde::{Deserialize, Serialize};

/// The CA and the server certificate every node presents, kept in state
/// so that restarts keep the certificates clients already trust.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct Pki {
    pub ca_cert_pem: String,
    pub ca_key_pem: String,
    pub server_cert_pem: String,
    pub server_key_pem: String,
    /// What MWS appends to the names of the commands ElastiCache restricts
    /// (`CONFIG-<suffix>`), which nodes are started with.
    pub command_suffix: String,
}

impl Pki {
    /// A new CA, and a server certificate for `names` (DNS names or IP
    /// addresses).
    pub fn generate(names: &[String]) -> Result<Self, String> {
        let ca_key = KeyPair::generate().map_err(|e| e.to_string())?;
        let mut ca = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::OrganizationName, "MWS");
        dn.push(DnType::CommonName, "MWS ElastiCache CA");
        ca.distinguished_name = dn;
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
        let ca_cert = ca.self_signed(&ca_key).map_err(|e| e.to_string())?;

        let key = KeyPair::generate().map_err(|e| e.to_string())?;
        let mut leaf = CertificateParams::new(names.to_vec()).map_err(|e| e.to_string())?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, names.first().map(String::as_str).unwrap_or("localhost"));
        leaf.distinguished_name = dn;
        leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
        leaf.extended_key_usages =
            vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth, rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        let cert = leaf.signed_by(&key, &ca_cert, &ca_key).map_err(|e| e.to_string())?;
        Ok(Self {
            ca_cert_pem: ca_cert.pem(),
            ca_key_pem: ca_key.serialize_pem(),
            server_cert_pem: cert.pem(),
            server_key_pem: key.serialize_pem(),
            command_suffix: String::new(),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.ca_cert_pem.is_empty() && self.command_suffix.is_empty()
    }
}

/// The names node certificates cover: the advertised host, loopback, and
/// the address MWS connects to.
pub fn server_names(advertise_host: &str, connect_host: &str) -> Vec<String> {
    let mut names = vec![advertise_host.to_string()];
    for n in [connect_host, "localhost", "127.0.0.1", "::1", "host.docker.internal"] {
        if !names.iter().any(|x| x == n) {
            names.push(n.to_string());
        }
    }
    names
}

/// The TLS server configuration presenting the node certificate.
pub(crate) fn server_config(pki: &Pki) -> Result<Arc<rustls::ServerConfig>, String> {
    use rustls_pki_types::pem::PemObject;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let certs = rustls_pki_types::CertificateDer::pem_slice_iter(pki.server_cert_pem.as_bytes())
        .chain(rustls_pki_types::CertificateDer::pem_slice_iter(pki.ca_cert_pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
    let key =
        rustls_pki_types::PrivateKeyDer::from_pem_slice(pki.server_key_pem.as_bytes()).map_err(|e| e.to_string())?;
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
    Ok(Arc::new(config))
}

/// A TLS client configuration trusting `ca_pem`.
pub fn client_config(ca_pem: &str) -> Result<Arc<rustls::ClientConfig>, String> {
    use rustls_pki_types::pem::PemObject;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pki_types::CertificateDer::pem_slice_iter(ca_pem.as_bytes()) {
        roots.add(cert.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    }
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issues_a_server_certificate_the_client_trusts() {
        let pki = Pki::generate(&server_names("127.0.0.1", "127.0.0.1")).unwrap();
        assert!(pki.ca_cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pki.server_key_pem.contains("PRIVATE KEY"));
        client_config(&pki.ca_cert_pem).unwrap();
    }
}

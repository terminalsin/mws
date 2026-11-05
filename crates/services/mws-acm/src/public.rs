//! What other AWS services read from ACM. Elastic Load Balancing serves a
//! listener's certificate (with its private key, which never leaves AWS)
//! and marks the certificate in use, so `InUseBy` lists the load balancer
//! and `DeleteCertificate` refuses, as in AWS.

use chrono::{DateTime, Utc};

use crate::Acm;

/// The private key of a certificate a service serves.
#[derive(Debug, Clone)]
pub enum ServerKey {
    /// PKCS#8 DER, for keys ACM generated.
    Pkcs8Der(Vec<u8>),
    /// The PEM an imported certificate came with.
    Pem(Vec<u8>),
}

/// A certificate with everything needed to serve TLS with it.
#[derive(Debug, Clone)]
pub struct ServerCertificate {
    pub arn: String,
    pub account: String,
    pub region: String,
    /// `ISSUED`, `PENDING_VALIDATION`, `EXPIRED`, ...
    pub status: String,
    pub domain_name: String,
    pub subject_alternative_names: Vec<String>,
    /// `RSA_2048`, `EC_prime256v1`, ...
    pub key_algorithm: String,
    pub certificate_pem: Option<String>,
    pub chain_pem: Option<String>,
    pub key: Option<ServerKey>,
    pub not_after: Option<DateTime<Utc>>,
}

impl Acm {
    /// The certificate `arn` with its key, whatever its status.
    pub fn server_certificate(&self, arn: &str) -> Option<ServerCertificate> {
        let st = self.lock();
        let c = st.certificates.get(arn)?;
        let not_after = c.cert_pem.as_deref().and_then(crate::pki::inspect_pem).map(|i| i.not_after);
        let key = match (&c.key_der, &c.imported_key) {
            (Some(der), _) => Some(ServerKey::Pkcs8Der(der.clone())),
            (None, Some(pem)) => Some(ServerKey::Pem(pem.clone())),
            (None, None) => None,
        };
        Some(ServerCertificate {
            arn: c.arn.clone(),
            account: c.account.clone(),
            region: c.region.clone(),
            status: c.status.clone(),
            domain_name: c.domain_name.clone(),
            subject_alternative_names: c.sans.clone(),
            key_algorithm: c.key_algorithm.clone(),
            certificate_pem: c.cert_pem.clone(),
            chain_pem: c.chain_pem.clone(),
            key,
            not_after,
        })
    }

    /// Record that `resource_arn` uses (or no longer uses) the certificate.
    pub fn set_in_use(&self, certificate_arn: &str, resource_arn: &str, in_use: bool) {
        let mut st = self.lock();
        let Some(c) = st.certificates.get_mut(certificate_arn) else { return };
        let present = c.in_use_by.iter().any(|r| r == resource_arn);
        if in_use && !present {
            c.in_use_by.push(resource_arn.to_string());
        } else if !in_use && present {
            c.in_use_by.retain(|r| r != resource_arn);
        }
    }
}

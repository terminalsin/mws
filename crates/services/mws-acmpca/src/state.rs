use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Utc};

use crate::generated::types;

#[derive(Debug, Clone)]
pub struct IssuedCert {
    pub pem: String,
    pub revoked: Option<(String, DateTime<Utc>)>,
}

#[derive(Debug, Clone)]
pub struct Ca {
    pub arn: String,
    pub owner: String,
    pub created_at: DateTime<Utc>,
    pub last_state_change_at: DateTime<Utc>,
    pub ty: String,
    pub status: String,
    pub config: types::CertificateAuthorityConfiguration,
    pub revocation: Option<types::RevocationConfiguration>,
    pub key_storage: Option<String>,
    pub usage_mode: Option<String>,
    /// PKCS#8 DER of the CA private key.
    pub key_der: Vec<u8>,
    pub csr_pem: String,
    pub cert_pem: Option<String>,
    /// Certificates above this CA's own, PEM, nearest first.
    pub chain_pem: Option<String>,
    pub serial: Option<String>,
    pub not_before: Option<DateTime<Utc>>,
    pub not_after: Option<DateTime<Utc>>,
    pub restorable_until: Option<DateTime<Utc>>,
    pub status_before_delete: Option<String>,
    pub tags: BTreeMap<String, String>,
    pub policy: Option<String>,
    pub permissions: Vec<types::Permission>,
    /// Issued certificates by serial (hex, no colons).
    pub certs: BTreeMap<String, IssuedCert>,
    pub issue_tokens: HashMap<String, String>,
}

#[derive(Debug, Default)]
pub struct State {
    pub cas: BTreeMap<String, Ca>,
    pub create_tokens: HashMap<String, String>,
}

use std::collections::{BTreeMap, HashMap};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::generated::types;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedCert {
    pub pem: String,
    pub revoked: Option<(String, DateTime<Utc>)>,
    pub issued_at: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    /// RFC 2253 subject, as audit reports show it.
    pub subject: String,
    pub template_arn: String,
}

/// The CA's current certificate revocation list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Crl {
    pub der: Vec<u8>,
    pub this_update: DateTime<Utc>,
    pub next_update: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub bucket: String,
    pub key: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(default)]
    pub crl: Option<Crl>,
    #[serde(default)]
    pub crl_number: u64,
    #[serde(default)]
    /// Audit reports by report id.
    pub audit_reports: BTreeMap<String, AuditReport>,
    /// The policy AWS RAM wrote for the CA's resource shares, kept apart
    /// from the one `PutPolicy` set; both are evaluated.
    #[serde(default)]
    pub ram_policy: Option<String>,
}

impl Ca {
    /// The CA's resource policy: its own (`PutPolicy`) and the statements
    /// RAM shares added, as one document.
    pub fn effective_policy(&self) -> Option<String> {
        match (&self.policy, &self.ram_policy) {
            (None, None) => None,
            (Some(p), None) | (None, Some(p)) => Some(p.clone()),
            (Some(own), Some(ram)) => {
                let statements = |doc: &str| -> Vec<serde_json::Value> {
                    match serde_json::from_str::<serde_json::Value>(doc).ok().and_then(|v| v.get("Statement").cloned())
                    {
                        Some(serde_json::Value::Array(a)) => a,
                        Some(one) => vec![one],
                        None => Vec::new(),
                    }
                };
                let mut all = statements(own);
                all.extend(statements(ram));
                Some(serde_json::json!({"Version": "2012-10-17", "Statement": all}).to_string())
            }
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub cas: BTreeMap<String, Ca>,
    pub create_tokens: HashMap<String, String>,
}

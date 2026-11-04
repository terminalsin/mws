use std::collections::{BTreeMap, HashMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::pki::{IssuingCa, RootCa};

/// How one domain name of a certificate is validated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainValidation {
    pub domain: String,
    /// The domain validation emails go to (EMAIL), or the domain itself.
    pub validation_domain: String,
    /// `DNS`, `EMAIL`, or `None` for private and imported certificates.
    pub method: Option<String>,
    /// `PENDING_VALIDATION`, `SUCCESS` or `FAILED`.
    pub status: String,
    /// The method a migration (`UpdateCertificateOptions`) moves to.
    #[serde(default)]
    pub requested_method: Option<String>,
    #[serde(default)]
    pub requested_status: Option<String>,
    /// The domain's validation during a managed renewal that needs it
    /// again (`PENDING_VALIDATION` until approved or found, then `SUCCESS`).
    #[serde(default)]
    pub renewal_status: Option<String>,
}

/// A `DOMAIN_VALIDATION_METHOD` update in progress or finished.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodUpdate {
    pub from: String,
    pub to: String,
    pub status: String,
    pub requested_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Renewal {
    pub status: String,
    pub reason: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub arn: String,
    pub account: String,
    pub region: String,
    pub domain_name: String,
    pub sans: Vec<String>,
    /// `AMAZON_ISSUED`, `PRIVATE` or `IMPORTED`.
    pub ty: String,
    pub status: String,
    pub failure_reason: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub issued_at: Option<DateTime<Utc>>,
    pub imported_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason: Option<String>,
    pub key_algorithm: String,
    pub ca_arn: Option<String>,
    pub ct_logging: String,
    pub export_option: String,
    pub managed_by: Option<String>,
    pub validations: Vec<DomainValidation>,
    pub method_update: Option<MethodUpdate>,
    pub cert_pem: Option<String>,
    pub chain_pem: Option<String>,
    /// PKCS#8 DER of a key ACM generated (Amazon-issued and private).
    pub key_der: Option<Vec<u8>>,
    /// The PEM key an imported certificate came with.
    pub imported_key: Option<Vec<u8>>,
    pub exported: bool,
    pub renewal: Option<Renewal>,
    /// Tags in the order they were added; values are optional in ACM.
    pub tags: Vec<(String, Option<String>)>,
    /// `AWS_MANAGED`, `ACME` or `CUSTOMER_PROVIDED`.
    pub origin: String,
    pub acme_endpoint_arn: Option<String>,
    pub acme_account_id: Option<String>,
    /// The Private CA certificate ARN, for private certificates.
    pub pca_certificate_arn: Option<String>,
    /// Times `ResendValidationEmail` was called, for nothing but realism.
    #[serde(default)]
    pub emails_sent: u32,
    /// When the last "ACM Certificate Approaching Expiration" event was
    /// sent (they are daily).
    #[serde(default)]
    pub expiry_event_at: Option<DateTime<Utc>>,
    /// When the `DaysToExpiry` metric was last published (daily).
    #[serde(default)]
    pub metric_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountConfig {
    pub days_before_expiry: i32,
}

impl Default for AccountConfig {
    fn default() -> Self {
        Self { days_before_expiry: 45 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeEndpoint {
    pub arn: String,
    pub account: String,
    pub id: String,
    pub url: String,
    pub status: String,
    pub authorization_behavior: String,
    pub contact: String,
    pub allowed_key_algorithms: Vec<String>,
    pub certificate_tags: Vec<(String, Option<String>)>,
    pub tags: Vec<(String, Option<String>)>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeDomainValidation {
    pub arn: String,
    pub endpoint_arn: String,
    pub domain: String,
    pub exact: bool,
    pub subdomains: bool,
    pub wildcards: bool,
    pub hosted_zone_id: Option<String>,
    pub record_name: String,
    pub record_value: String,
    pub status: String,
    pub failure: Option<(String, String)>,
    pub tags: Vec<(String, Option<String>)>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eab {
    pub arn: String,
    pub endpoint_arn: String,
    pub role_arn: String,
    pub key_id: String,
    /// The HMAC key, base64url without padding as ACME clients take it.
    pub mac_key: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub tags: Vec<(String, Option<String>)>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// An account an ACME client registered through an endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeAccount {
    pub id: String,
    pub endpoint_arn: String,
    pub url: String,
    /// The account key as a JWK.
    pub jwk: serde_json::Value,
    pub thumbprint: String,
    pub status: String,
    pub contacts: Vec<String>,
    pub eab_arn: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AcmeOrder {
    pub id: String,
    pub endpoint_arn: String,
    pub account_id: String,
    pub identifiers: Vec<String>,
    pub status: String,
    pub expires: DateTime<Utc>,
    pub certificate_arn: Option<String>,
    pub error: Option<serde_json::Value>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub certificates: BTreeMap<String, Certificate>,
    /// `account|region|token` to the certificate ARN and when it was used.
    pub request_tokens: HashMap<String, (String, DateTime<Utc>)>,
    pub account_configs: BTreeMap<String, AccountConfig>,
    /// `account|token` for create calls that take an idempotency token.
    pub create_tokens: HashMap<String, String>,
    pub root: Option<RootCa>,
    /// Issuing CAs by key kind.
    pub issuers: BTreeMap<String, IssuingCa>,
    pub endpoints: BTreeMap<String, AcmeEndpoint>,
    pub domain_validations: BTreeMap<String, AcmeDomainValidation>,
    pub eabs: BTreeMap<String, Eab>,
    /// By account id.
    pub acme_accounts: BTreeMap<String, AcmeAccount>,
    pub acme_orders: BTreeMap<String, AcmeOrder>,
    /// Nonces handed out and not yet used. Not worth keeping across restarts.
    #[serde(skip)]
    pub nonces: HashSet<String>,
    /// EventBridge events waiting for the clock source to collect them.
    #[serde(skip)]
    pub pending_events: Vec<crate::events::AcmEvent>,
}

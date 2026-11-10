//! Everything SES remembers, per account and Region. SES v1 and v2 share
//! it: an identity, template or configuration set made through one API is
//! visible through the other, as in AWS.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::v1::types as t1;
use crate::v2::types as t2;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// Keyed by `account:region`.
    pub regions: BTreeMap<String, Region>,
    /// Mail SES sent (or would have handed to a remote mail server).
    pub outbox: Vec<crate::outbox::OutboxMessage>,
    /// Mail SES received, with what its receipt rules did.
    pub received: Vec<crate::outbox::ReceivedMessage>,
    /// Verification links mailed to email identities, by token.
    pub verification_links: BTreeMap<String, VerificationLink>,
    /// List management unsubscribe links, by token.
    pub unsubscribe_links: BTreeMap<String, UnsubscribeLink>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UnsubscribeLink {
    pub account: String,
    pub region: String,
    pub contact_list: String,
    pub topic: Option<String>,
    pub email: String,
    pub message_id: String,
    pub configuration_set: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct VerificationLink {
    pub account: String,
    pub region: String,
    pub identity: String,
    /// The custom verification template the link came from, whose
    /// redirection URLs the link answers with.
    pub template: Option<String>,
}

pub fn region_key(account: &str, region: &str) -> String {
    format!("{account}:{region}")
}

pub fn split_region_key(key: &str) -> (&str, &str) {
    key.split_once(':').unwrap_or((key, ""))
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Region {
    pub identities: BTreeMap<String, Identity>,
    pub templates: BTreeMap<String, Template>,
    pub custom_verification_templates: BTreeMap<String, CustomVerificationTemplate>,
    pub configuration_sets: BTreeMap<String, ConfigurationSet>,
    pub rule_sets: BTreeMap<String, RuleSet>,
    pub active_rule_set: Option<String>,
    pub receipt_filters: Vec<t1::ReceiptFilter>,
    pub account: Account,
    /// The account-level suppression list, by lower-cased address.
    pub suppressed: BTreeMap<String, Suppressed>,
    pub contact_lists: BTreeMap<String, ContactList>,
    pub dedicated_ip_pools: BTreeMap<String, DedicatedIpPool>,
    pub dashboard: Dashboard,
    pub test_reports: BTreeMap<String, TestReport>,
    pub import_jobs: BTreeMap<String, ImportJob>,
    pub export_jobs: BTreeMap<String, ExportJob>,
    pub multi_region_endpoints: BTreeMap<String, MultiRegionEndpoint>,
    pub tenants: BTreeMap<String, Tenant>,
    /// Customer-set reputation entity settings, by `TYPE/reference`.
    pub reputation_entities: BTreeMap<String, ReputationEntity>,
    /// What was sent and what became of it, for statistics, quotas,
    /// message insights and metrics.
    pub sends: Vec<SendRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Identity {
    pub name: String,
    /// `EMAIL_ADDRESS` or `DOMAIN`.
    pub kind: String,
    pub created: DateTime<Utc>,
    /// v1 wording: `Pending`, `Success`, `Failed`, `TemporaryFailure`,
    /// `NotStarted`.
    pub verification_status: String,
    /// The `_amazonses` TXT token of a domain verified the v1 way.
    pub verification_token: Option<String>,
    pub verification_started: DateTime<Utc>,
    pub last_checked: Option<DateTime<Utc>>,
    pub last_success: Option<DateTime<Utc>>,
    /// Whether the address was added with the legacy `VerifyEmailAddress`.
    pub legacy: bool,
    pub dkim_enabled: bool,
    pub dkim_tokens: Vec<String>,
    /// v2 wording: `NOT_STARTED`, `PENDING`, `SUCCESS`, `FAILED`,
    /// `TEMPORARY_FAILURE`.
    pub dkim_status: String,
    /// `AWS_SES` (Easy DKIM) or `EXTERNAL` (BYODKIM).
    pub dkim_origin: String,
    pub dkim_selector: Option<String>,
    pub dkim_key_length: String,
    pub dkim_next_key_length: String,
    pub dkim_key_generated: Option<DateTime<Utc>>,
    pub mail_from_domain: Option<String>,
    /// `Pending`, `Success`, `Failed`, `TemporaryFailure`.
    pub mail_from_status: String,
    /// `UseDefaultValue` or `RejectMessage`.
    pub behavior_on_mx_failure: String,
    pub bounce_topic: Option<String>,
    pub complaint_topic: Option<String>,
    pub delivery_topic: Option<String>,
    pub headers_in_bounce: bool,
    pub headers_in_complaint: bool,
    pub headers_in_delivery: bool,
    pub feedback_forwarding: bool,
    pub policies: BTreeMap<String, String>,
    pub tags: BTreeMap<String, String>,
    pub configuration_set: Option<String>,
    /// S/MIME certificates, by from address (empty for the identity).
    pub certificates: BTreeMap<String, String>,
}

impl Default for Identity {
    fn default() -> Self {
        Self {
            name: String::new(),
            kind: "EMAIL_ADDRESS".into(),
            created: DateTime::<Utc>::UNIX_EPOCH,
            verification_status: "Pending".into(),
            verification_token: None,
            verification_started: DateTime::<Utc>::UNIX_EPOCH,
            last_checked: None,
            last_success: None,
            legacy: false,
            dkim_enabled: false,
            dkim_tokens: Vec::new(),
            dkim_status: "NOT_STARTED".into(),
            dkim_origin: "AWS_SES".into(),
            dkim_selector: None,
            dkim_key_length: "RSA_2048_BIT".into(),
            dkim_next_key_length: "RSA_2048_BIT".into(),
            dkim_key_generated: None,
            mail_from_domain: None,
            mail_from_status: "Pending".into(),
            behavior_on_mx_failure: "UseDefaultValue".into(),
            bounce_topic: None,
            complaint_topic: None,
            delivery_topic: None,
            headers_in_bounce: false,
            headers_in_complaint: false,
            headers_in_delivery: false,
            feedback_forwarding: true,
            policies: BTreeMap::new(),
            tags: BTreeMap::new(),
            configuration_set: None,
            certificates: BTreeMap::new(),
        }
    }
}

impl Identity {
    pub fn is_domain(&self) -> bool {
        self.kind == "DOMAIN"
    }

    pub fn verified(&self) -> bool {
        self.verification_status == "Success"
    }

    /// The identity's sending authorization policies as one document.
    pub fn policy_document(&self) -> Option<String> {
        if self.policies.is_empty() {
            return None;
        }
        let mut statements = Vec::new();
        for doc in self.policies.values() {
            let Ok(v) = serde_json::from_str::<serde_json::Value>(doc) else { continue };
            match v.get("Statement") {
                Some(serde_json::Value::Array(a)) => statements.extend(a.iter().cloned()),
                Some(s) => statements.push(s.clone()),
                None => {}
            }
        }
        Some(serde_json::json!({ "Version": "2012-10-17", "Statement": statements }).to_string())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Template {
    pub name: String,
    pub subject: Option<String>,
    pub text: Option<String>,
    pub html: Option<String>,
    pub created: DateTime<Utc>,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomVerificationTemplate {
    pub name: String,
    pub from: String,
    pub subject: String,
    pub content: String,
    pub success_url: String,
    pub failure_url: String,
    pub created: DateTime<Utc>,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ConfigurationSet {
    pub name: String,
    pub created: DateTime<Utc>,
    pub event_destinations: Vec<EventDestination>,
    /// Custom redirect domain and HTTPS policy; `None` until set.
    pub tracking: Option<t2::TrackingOptions>,
    /// `REQUIRE` or `OPTIONAL`.
    pub tls_policy: String,
    pub sending_pool_name: Option<String>,
    pub max_delivery_seconds: Option<i64>,
    pub reputation_metrics_enabled: bool,
    pub last_fresh_start: Option<DateTime<Utc>>,
    pub sending_enabled: bool,
    pub suppression: Option<t2::SuppressionOptions>,
    pub vdm: Option<t2::VdmOptions>,
    pub archive_arn: Option<String>,
    pub message_security: Option<t2::MessageSecurityOptions>,
    pub tags: BTreeMap<String, String>,
}

impl Default for ConfigurationSet {
    fn default() -> Self {
        Self {
            name: String::new(),
            created: DateTime::<Utc>::UNIX_EPOCH,
            event_destinations: Vec::new(),
            tracking: None,
            tls_policy: "OPTIONAL".into(),
            sending_pool_name: None,
            max_delivery_seconds: None,
            reputation_metrics_enabled: false,
            last_fresh_start: None,
            sending_enabled: true,
            suppression: None,
            vdm: None,
            archive_arn: None,
            message_security: None,
            tags: BTreeMap::new(),
        }
    }
}

/// An event destination; event types in v2 wording (`SEND`, `DELIVERY`,
/// `RENDERING_FAILURE`, ...).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EventDestination {
    pub name: String,
    pub enabled: bool,
    pub matching_event_types: Vec<String>,
    pub firehose: Option<t2::KinesisFirehoseDestination>,
    pub cloudwatch: Option<t2::CloudWatchDestination>,
    pub sns: Option<String>,
    pub eventbridge: Option<String>,
    pub pinpoint: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RuleSet {
    pub name: String,
    pub created: DateTime<Utc>,
    pub rules: Vec<t1::ReceiptRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Account {
    pub sending_enabled: bool,
    pub production_access: bool,
    pub details: Option<t2::AccountDetails>,
    pub suppressed_reasons: Vec<String>,
    pub suppression_validation: Option<t2::SuppressionValidationAttributes>,
    pub dedicated_ip_auto_warmup: bool,
    pub vdm: Option<t2::VdmAttributes>,
    pub pricing_plan: Option<String>,
    /// When the pending production access review (the support case opened
    /// by `PutAccountDetails`) was opened; it is decided 24 hours later on
    /// the emulated clock.
    pub review_opened: Option<DateTime<Utc>>,
}

impl Default for Account {
    fn default() -> Self {
        Self {
            sending_enabled: true,
            production_access: false,
            details: None,
            suppressed_reasons: vec!["BOUNCE".into(), "COMPLAINT".into()],
            suppression_validation: None,
            dedicated_ip_auto_warmup: true,
            vdm: None,
            pricing_plan: None,
            review_opened: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Suppressed {
    pub email: String,
    /// `BOUNCE` or `COMPLAINT`.
    pub reason: String,
    pub last_update: DateTime<Utc>,
    pub message_id: Option<String>,
    pub feedback_id: Option<String>,
    pub tenant: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ContactList {
    pub name: String,
    pub topics: Vec<t2::Topic>,
    pub description: Option<String>,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub tags: BTreeMap<String, String>,
    pub contacts: BTreeMap<String, Contact>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Contact {
    pub email: String,
    pub topic_preferences: Vec<t2::TopicPreference>,
    pub unsubscribe_all: bool,
    pub attributes: Option<String>,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DedicatedIpPool {
    pub name: String,
    pub scaling_mode: String,
    pub created: DateTime<Utc>,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Dashboard {
    pub enabled: bool,
    pub subscription_expiry: Option<DateTime<Utc>>,
    pub domains: Vec<t2::DomainDeliverabilityTrackingOption>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TestReport {
    pub id: String,
    pub name: Option<String>,
    pub subject: String,
    pub from: String,
    pub created: DateTime<Utc>,
    pub status: String,
    pub raw: String,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ImportJob {
    pub id: String,
    pub destination: t2::ImportDestination,
    pub source: t2::ImportDataSource,
    pub status: String,
    pub created: DateTime<Utc>,
    pub completed: Option<DateTime<Utc>>,
    pub processed: i32,
    pub failed: i32,
    pub failure: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ExportJob {
    pub id: String,
    pub source_type: String,
    pub source: t2::ExportDataSource,
    pub destination: t2::ExportDestination,
    pub status: String,
    pub created: DateTime<Utc>,
    pub completed: Option<DateTime<Utc>>,
    pub processed: i32,
    pub exported: i32,
    pub failure: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MultiRegionEndpoint {
    pub name: String,
    pub id: String,
    pub regions: Vec<String>,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Tenant {
    pub name: String,
    pub id: String,
    pub arn: String,
    pub created: DateTime<Utc>,
    pub tags: BTreeMap<String, String>,
    pub sending_status: String,
    pub suppression: Option<t2::TenantSuppressionAttributes>,
    /// Associated resources: ARN to association time.
    pub resources: BTreeMap<String, DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ReputationEntity {
    pub customer_status: Option<String>,
    pub customer_updated: Option<DateTime<Utc>>,
    pub policy: Option<String>,
}

/// One message SES accepted, and what happened to it per recipient.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SendRecord {
    pub message_id: String,
    pub timestamp: DateTime<Utc>,
    pub from: String,
    pub subject: String,
    pub identity: String,
    pub configuration_set: Option<String>,
    pub tenant: Option<String>,
    pub tags: BTreeMap<String, Vec<String>>,
    pub recipients: Vec<String>,
    /// `(recipient, event type (v2 wording), time, bounce type or
    /// complaint type)`.
    pub events: Vec<(String, String, DateTime<Utc>, Option<String>)>,
    pub rejected: bool,
}

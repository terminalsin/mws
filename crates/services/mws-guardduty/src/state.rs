//! GuardDuty's state: one [`Account`] per account and Region.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::common::Tags;
use crate::generated::types;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// Keyed by `account/region`.
    pub accounts: BTreeMap<String, Account>,
    /// The GuardDuty delegated administrator of each organization in each
    /// Region, keyed by `org-id/region`.
    pub org_admins: BTreeMap<String, OrgAdmin>,
    /// Each account's password policy as GuardDuty last saw it set
    /// (`UpdateAccountPasswordPolicy` parameters), to tell when a change
    /// weakens it.
    pub password_policies: BTreeMap<String, serde_json::Value>,
}

impl State {
    pub fn key(account: &str, region: &str) -> String {
        format!("{account}/{region}")
    }

    pub fn account(&self, account: &str, region: &str) -> Option<&Account> {
        self.accounts.get(&Self::key(account, region))
    }

    pub fn account_mut(&mut self, account: &str, region: &str) -> &mut Account {
        self.accounts.entry(Self::key(account, region)).or_default()
    }

    pub fn detector(&self, account: &str, region: &str) -> Option<&Detector> {
        self.account(account, region).and_then(|a| a.detector.as_ref())
    }

    pub fn detector_mut(&mut self, account: &str, region: &str) -> Option<&mut Detector> {
        self.accounts.get_mut(&Self::key(account, region)).and_then(|a| a.detector.as_mut())
    }
}

/// One account's GuardDuty in one Region.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Account {
    pub detector: Option<Detector>,
    /// Invitations received, by inviting (administrator) account.
    pub invitations: BTreeMap<String, Invite>,
    /// The administrator this account is a member of.
    pub administrator: Option<AdminLink>,
    pub malware_plans: BTreeMap<String, MalwarePlan>,
    pub malware_scans: BTreeMap<String, MalwareScan>,
    pub rule_associations: BTreeMap<String, RuleAssociation>,
    /// Organization-wide custom rule configurations, by `rule/mode`.
    pub rule_org_configs: BTreeMap<String, RuleOrgConfig>,
    /// Ids of client tokens already used for creates, mapped to the id
    /// they created (idempotency).
    pub client_tokens: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    pub invitation_id: String,
    pub invited_at: DateTime<Utc>,
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminLink {
    pub account: String,
    pub invitation_id: Option<String>,
    pub invited_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Feature {
    pub status: String,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub additional: BTreeMap<String, (String, DateTime<Utc>)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Detector {
    pub id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub enabled: bool,
    pub frequency: String,
    pub features: BTreeMap<String, Feature>,
    pub tags: Tags,
    pub filters: BTreeMap<String, Filter>,
    pub ip_sets: BTreeMap<String, ThreatList>,
    pub threat_intel_sets: BTreeMap<String, ThreatList>,
    pub threat_entity_sets: BTreeMap<String, ThreatList>,
    pub trusted_entity_sets: BTreeMap<String, ThreatList>,
    pub destinations: BTreeMap<String, Destination>,
    pub members: BTreeMap<String, MemberRec>,
    /// Findings by id, generated in this account.
    pub findings: BTreeMap<String, types::Finding>,
    pub scan_settings: types::UpdateMalwareScanSettingsRequest,
    pub org_config: OrgConfig,
    pub investigations: BTreeMap<String, Investigation>,
    /// Detected findings waiting to be published, with when they are due.
    pub publish_due: BTreeMap<String, DateTime<Utc>>,
    /// When each detected finding was last published.
    pub published_at: BTreeMap<String, DateTime<Utc>>,
}

impl Default for Detector {
    fn default() -> Self {
        Self {
            id: String::new(),
            created_at: DateTime::<Utc>::UNIX_EPOCH,
            updated_at: DateTime::<Utc>::UNIX_EPOCH,
            enabled: true,
            frequency: "SIX_HOURS".into(),
            features: BTreeMap::new(),
            tags: Tags::new(),
            filters: BTreeMap::new(),
            ip_sets: BTreeMap::new(),
            threat_intel_sets: BTreeMap::new(),
            threat_entity_sets: BTreeMap::new(),
            trusted_entity_sets: BTreeMap::new(),
            destinations: BTreeMap::new(),
            members: BTreeMap::new(),
            findings: BTreeMap::new(),
            scan_settings: Default::default(),
            org_config: OrgConfig::default(),
            investigations: BTreeMap::new(),
            publish_due: BTreeMap::new(),
            published_at: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Filter {
    pub name: String,
    pub description: Option<String>,
    pub action: String,
    pub rank: i32,
    pub criteria: types::FindingCriteria,
    pub tags: Tags,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub version: i64,
}

/// An IP set, threat intel set, threat entity set or trusted entity set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatList {
    pub name: String,
    pub format: String,
    pub location: String,
    pub status: String,
    pub expected_bucket_owner: Option<String>,
    pub tags: Tags,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// While `ACTIVATING`: when GuardDuty reads the file and the list
    /// becomes `ACTIVE` (or `ERROR`).
    #[serde(default)]
    pub ready_at: Option<DateTime<Utc>>,
    /// The IP addresses and CIDR ranges (and, for entity sets, domains)
    /// read from the file.
    #[serde(default)]
    pub entries: Vec<String>,
    /// Why the file could not be used, when `ERROR`.
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Destination {
    pub id: String,
    pub ty: String,
    pub properties: types::DestinationProperties,
    pub status: String,
    /// When publishing started failing (epoch millis), 0 if it has not.
    pub failure_since: i64,
    pub tags: Tags,
    /// The last finding update exported, so each export sends what changed.
    #[serde(default)]
    pub exported_through: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberRec {
    pub account: String,
    pub email: String,
    /// `Created`, `Invited`, `Enabled`, `Disabled`, `Removed`, `Resigned`.
    pub status: String,
    pub invited_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    pub invitation_id: Option<String>,
    /// Added through the organization (no invitation needed).
    #[serde(default)]
    pub via_organization: bool,
}

/// The delegated administrator's organization configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OrgConfig {
    /// `NEW`, `ALL` or `NONE`.
    pub auto_enable_members: String,
    /// Feature name → (`NEW`/`ALL`/`NONE`, additional configuration).
    pub features: BTreeMap<String, (String, BTreeMap<String, String>)>,
    /// When `auto_enable_members` last changed: `NEW` only takes accounts
    /// that join after this.
    pub since: Option<DateTime<Utc>>,
}

impl Default for OrgConfig {
    fn default() -> Self {
        Self { auto_enable_members: "NONE".into(), features: BTreeMap::new(), since: None }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgAdmin {
    pub account: String,
    pub status: String,
    pub since: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwarePlan {
    pub id: String,
    pub role: String,
    pub protected_resource: types::CreateProtectedResource,
    pub actions: Option<types::MalwareProtectionPlanActions>,
    pub created_at: DateTime<Utc>,
    pub status: String,
    pub tags: Tags,
    /// `(code, message)` of an `ERROR` or `WARNING` status.
    #[serde(default)]
    pub status_reasons: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MalwareScan {
    pub id: String,
    pub detector_id: Option<String>,
    pub resource_arn: String,
    pub resource_type: String,
    pub scan_type: String,
    pub status: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub result: String,
    pub finding_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleAssociation {
    pub id: String,
    pub rule_id: String,
    pub mode: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub tags: Tags,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleOrgConfig {
    pub rule_id: String,
    pub mode: String,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Investigation {
    pub id: String,
    pub prompt: String,
    pub started_at: DateTime<Utc>,
}

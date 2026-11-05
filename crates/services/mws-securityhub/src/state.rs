//! Security Hub's state: one hub per account and Region, plus the
//! relationships between accounts (members and administrators,
//! organization delegated administrators).

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::generated::types;

pub type Tags = BTreeMap<String, String>;

/// `account/region`.
pub fn key(account: &str, region: &str) -> String {
    format!("{account}/{region}")
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct State {
    /// Enabled hubs by `account/region`.
    #[serde(default)]
    pub hubs: BTreeMap<String, Hub>,
    /// Security Hub (the newer, OCSF-based service) by `account/region`.
    #[serde(default)]
    pub hubs_v2: BTreeMap<String, HubV2>,
    /// Members of each administrator, by the administrator's `account/region`.
    #[serde(default)]
    pub members: BTreeMap<String, BTreeMap<String, MemberRec>>,
    /// Delegated administrators by the management account's
    /// `account/region`.
    #[serde(default)]
    pub org_admins: BTreeMap<String, String>,
    /// Organization configuration of each delegated administrator, by
    /// its `account/region`.
    #[serde(default)]
    pub org_configs: BTreeMap<String, OrgConfig>,
    /// Pending connector V2 OAuth registrations: auth state -> `account/region` and connector id.
    #[serde(default)]
    pub pending_oauth: BTreeMap<String, (String, String)>,
}

impl State {
    pub fn hub(&self, account: &str, region: &str) -> Option<&Hub> {
        self.hubs.get(&key(account, region))
    }

    pub fn hub_mut(&mut self, account: &str, region: &str) -> Option<&mut Hub> {
        self.hubs.get_mut(&key(account, region))
    }

    /// The administrator `account` is an enabled member of in `region`.
    pub fn administrator_of(&self, account: &str, region: &str) -> Option<String> {
        self.members.iter().find_map(|(admin_key, members)| {
            let (admin, r) = admin_key.split_once('/')?;
            (r == region && members.get(account).is_some_and(|m| m.status == "Enabled")).then(|| admin.to_string())
        })
    }

    /// Administrators that have invited `account` in `region`, with the record.
    pub fn invitations_for(&self, account: &str, region: &str) -> Vec<(String, MemberRec)> {
        self.members
            .iter()
            .filter_map(|(admin_key, members)| {
                let (admin, r) = admin_key.split_once('/')?;
                let m = members.get(account)?;
                (r == region && m.status == "Invited").then(|| (admin.to_string(), m.clone()))
            })
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hub {
    pub account: String,
    pub region: String,
    pub arn: String,
    pub subscribed_at: DateTime<Utc>,
    pub auto_enable_controls: bool,
    /// `SECURITY_CONTROL` (consolidated findings) or `STANDARD_CONTROL`.
    pub control_finding_generator: String,
    #[serde(default)]
    pub tags: Tags,
    /// Enabled standards by subscription ARN.
    #[serde(default)]
    pub standards: BTreeMap<String, StandardsSub>,
    /// Standards control status overrides by standards control ARN
    /// (`UpdateStandardsControl`) or `standards_arn|control_id`
    /// (`BatchUpdateStandardsControlAssociations`); both views share them.
    #[serde(default)]
    pub control_overrides: BTreeMap<String, ControlOverride>,
    /// Customized security control parameters and status by control id.
    #[serde(default)]
    pub security_controls: BTreeMap<String, SecurityControlRec>,
    /// Products enabled for import, by product ARN.
    #[serde(default)]
    pub products: BTreeSet<String>,
    #[serde(default)]
    pub action_targets: BTreeMap<String, ActionTargetRec>,
    #[serde(default)]
    pub insights: BTreeMap<String, InsightRec>,
    /// Findings by `product ARN` + `\n` + finding id.
    #[serde(default)]
    pub findings: BTreeMap<String, FindingRec>,
    #[serde(default)]
    pub automation_rules: BTreeMap<String, RuleRec>,
    #[serde(default)]
    pub automation_rules_v2: BTreeMap<String, RuleV2Rec>,
    #[serde(default)]
    pub finding_aggregator: Option<AggregatorRec>,
    #[serde(default)]
    pub configuration_policies: BTreeMap<String, ConfigurationPolicyRec>,
    /// Configuration policy associations by target id (account, OU or root).
    #[serde(default)]
    pub policy_associations: BTreeMap<String, AssociationRec>,
    #[serde(default)]
    pub connectors: BTreeMap<String, ConnectorRec>,
    /// Tags on other resources (action targets cannot be tagged; automation
    /// rules, policies, aggregators, connectors can), by ARN.
    #[serde(default)]
    pub resource_tags: BTreeMap<String, Tags>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StandardsSub {
    pub standards_arn: String,
    #[serde(default)]
    pub input: BTreeMap<String, String>,
    /// When it was enabled; it reads `PENDING` on the call that enables it
    /// and `READY` afterwards.
    pub enabled_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlOverride {
    /// `ENABLED` or `DISABLED`.
    pub status: String,
    pub reason: Option<String>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityControlRec {
    #[serde(default)]
    pub parameters: BTreeMap<String, types::ParameterConfiguration>,
    pub last_update_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionTargetRec {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsightRec {
    pub name: String,
    /// The filters as ASFF filter JSON.
    pub filters: Value,
    pub group_by_attribute: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingRec {
    /// The finding in ASFF JSON, as `GetFindings` returns it.
    pub finding: Value,
    #[serde(default)]
    pub history: Vec<HistoryRec>,
    /// Fields the customer changed with `BatchUpdateFindings` (or
    /// automation rules); later imports by the provider leave them alone.
    #[serde(default)]
    pub customer_fields: BTreeSet<String>,
    /// Security Hub V2 (OCSF) changes: severity id, status id, comment.
    #[serde(default)]
    pub v2: V2Overlay,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct V2Overlay {
    pub severity_id: Option<i32>,
    pub status_id: Option<i32>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryRec {
    pub time: DateTime<Utc>,
    pub created: bool,
    /// `BATCH_IMPORT_FINDINGS` or `BATCH_UPDATE_FINDINGS`.
    pub source_type: String,
    pub identity: String,
    /// `(field, old, new)`.
    #[serde(default)]
    pub updates: Vec<(String, Option<String>, Option<String>)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleRec {
    pub config: types::AutomationRulesConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleV2Rec {
    pub arn: String,
    pub id: String,
    pub name: String,
    pub status: String,
    pub description: String,
    pub order: f32,
    pub criteria: types::Criteria,
    pub actions: Vec<types::AutomationRulesActionV2>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatorRec {
    pub arn: String,
    pub region_linking_mode: String,
    #[serde(default)]
    pub regions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigurationPolicyRec {
    pub id: String,
    pub arn: String,
    pub name: String,
    pub description: Option<String>,
    pub policy: types::Policy,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssociationRec {
    /// A configuration policy id or `SELF_MANAGED_SECURITY_HUB`.
    pub policy_id: String,
    /// `ACCOUNT`, `ORGANIZATIONAL_UNIT` or `ROOT`.
    pub target_type: String,
    pub updated_at: DateTime<Utc>,
}

/// A connector (Jira Cloud, ServiceNow or Azure), V1 or V2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectorRec {
    pub id: String,
    pub arn: String,
    pub name: String,
    pub description: Option<String>,
    /// Whether it was created through the V2 API.
    pub v2: bool,
    pub kms_key_arn: Option<String>,
    /// `JIRA_CLOUD`, `SERVICENOW` or `AZURE`.
    pub provider_name: String,
    pub provider: types::ProviderDetail,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub created_by: String,
    /// Tickets opened by `CreateTicketV2`, by ticket id: finding metadata uid.
    #[serde(default)]
    pub tickets: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberRec {
    pub email: Option<String>,
    /// `Created`, `Invited`, `Enabled`, `Removed`, `Resigned`, `Deleted`.
    pub status: String,
    pub invitation_id: Option<String>,
    pub invited_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    /// Added through the organization rather than by invitation.
    #[serde(default)]
    pub organization: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgConfig {
    pub auto_enable: bool,
    /// `DEFAULT` or `NONE`.
    pub auto_enable_standards: String,
    /// `LOCAL` or `CENTRAL`.
    pub configuration_type: String,
}

impl Default for OrgConfig {
    fn default() -> Self {
        Self { auto_enable: false, auto_enable_standards: "DEFAULT".into(), configuration_type: "LOCAL".into() }
    }
}

/// Security Hub V2 in one account and Region.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HubV2 {
    pub arn: String,
    pub subscribed_at: DateTime<Utc>,
    #[serde(default)]
    pub tags: Tags,
    /// Optional features (`SecurityHubAdvanced`, ...) and their status.
    #[serde(default)]
    pub features: BTreeMap<String, String>,
    #[serde(default)]
    pub aggregators: BTreeMap<String, AggregatorRec>,
    #[serde(default)]
    pub export_jobs: BTreeMap<String, ExportJobRec>,
    /// Client tokens already used, so retried creates return the same resource.
    #[serde(default)]
    pub client_tokens: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportJobRec {
    pub id: String,
    pub name: Option<String>,
    pub status: String,
    pub data_type: String,
    pub output: types::ExportOutput,
    pub scopes: Option<types::ExportScopes>,
    pub destination: types::ExportDestination,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub failure_code: Option<String>,
    pub failure_message: Option<String>,
}

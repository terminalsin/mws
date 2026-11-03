//! EventBridge state, one [`Region`] per account and Region keyed
//! `"{account}/{region}"`. Records reuse the generated wire types where
//! they fit; they already derive serde.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::generated::types;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub regions: BTreeMap<String, Region>,
}

impl State {
    pub fn region(&self, account: &str, region: &str) -> Option<&Region> {
        self.regions.get(&format!("{account}/{region}"))
    }

    /// The Region's state, created with its default event bus on first use.
    pub fn region_mut(&mut self, partition: &str, account: &str, region: &str, now: DateTime<Utc>) -> &mut Region {
        self.regions.entry(format!("{account}/{region}")).or_insert_with(|| {
            let mut r = Region::default();
            let arn = format!("arn:{partition}:events:{region}:{account}:event-bus/default");
            r.buses.insert(
                "default".into(),
                Bus { name: "default".into(), arn, creation_time: now, last_modified_time: now, ..Bus::default() },
            );
            r
        })
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Region {
    pub buses: BTreeMap<String, Bus>,
    pub archives: BTreeMap<String, Archive>,
    pub replays: BTreeMap<String, Replay>,
    pub connections: BTreeMap<String, Connection>,
    pub api_destinations: BTreeMap<String, ApiDestination>,
    pub endpoints: BTreeMap<String, Endpoint>,
    /// Event sources SaaS partners created for this account.
    pub event_sources: BTreeMap<String, EventSource>,
    /// Partner event sources this account created as a partner.
    pub partner_sources: BTreeMap<String, PartnerSource>,
    /// Resource tags by ARN.
    pub tags: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Bus {
    pub name: String,
    pub arn: String,
    pub description: Option<String>,
    pub kms_key_identifier: Option<String>,
    pub dead_letter_config: Option<types::DeadLetterConfig>,
    pub log_config: Option<types::LogConfig>,
    pub policy: Option<String>,
    pub event_source_name: Option<String>,
    pub creation_time: DateTime<Utc>,
    pub last_modified_time: DateTime<Utc>,
    pub rules: BTreeMap<String, Rule>,
}

impl Default for Bus {
    fn default() -> Self {
        Self {
            name: String::new(),
            arn: String::new(),
            description: None,
            kms_key_identifier: None,
            dead_letter_config: None,
            log_config: None,
            policy: None,
            event_source_name: None,
            creation_time: DateTime::<Utc>::UNIX_EPOCH,
            last_modified_time: DateTime::<Utc>::UNIX_EPOCH,
            rules: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Rule {
    pub name: String,
    pub arn: String,
    pub event_pattern: Option<String>,
    pub schedule_expression: Option<String>,
    pub state: String,
    pub description: Option<String>,
    pub role_arn: Option<String>,
    pub managed_by: Option<String>,
    /// The account that created the rule, when not the bus owner.
    pub created_by: Option<String>,
    pub targets: Vec<types::Target>,
    pub created_at: DateTime<Utc>,
    /// When a scheduled rule last fired (or was last checked).
    pub schedule_checked: Option<DateTime<Utc>>,
}

impl Default for Rule {
    fn default() -> Self {
        Self {
            name: String::new(),
            arn: String::new(),
            event_pattern: None,
            schedule_expression: None,
            state: "ENABLED".into(),
            description: None,
            role_arn: None,
            managed_by: None,
            created_by: None,
            targets: Vec::new(),
            created_at: DateTime::<Utc>::UNIX_EPOCH,
            schedule_checked: None,
        }
    }
}

impl Rule {
    pub fn enabled(&self) -> bool {
        self.state.starts_with("ENABLED")
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ArchivedEvent {
    pub time: Option<DateTime<Utc>>,
    pub ingested: Option<DateTime<Utc>>,
    pub event: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Archive {
    pub name: String,
    pub arn: String,
    pub event_source_arn: String,
    pub description: Option<String>,
    pub event_pattern: Option<String>,
    pub state: String,
    pub state_reason: Option<String>,
    pub retention_days: i32,
    pub kms_key_identifier: Option<String>,
    pub creation_time: Option<DateTime<Utc>>,
    pub events: Vec<ArchivedEvent>,
}

impl Archive {
    pub fn size_bytes(&self) -> i64 {
        self.events.iter().map(|e| e.event.len() as i64).sum()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Replay {
    pub name: String,
    pub arn: String,
    pub description: Option<String>,
    pub state: String,
    pub state_reason: Option<String>,
    pub event_source_arn: String,
    pub destination: types::ReplayDestination,
    pub event_start_time: Option<DateTime<Utc>>,
    pub event_end_time: Option<DateTime<Utc>>,
    pub event_last_replayed_time: Option<DateTime<Utc>>,
    pub replay_start_time: Option<DateTime<Utc>>,
    pub replay_end_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Connection {
    pub name: String,
    pub arn: String,
    pub description: Option<String>,
    pub state: String,
    pub state_reason: Option<String>,
    pub authorization_type: String,
    /// The authorization parameters with their secrets, which AWS keeps in
    /// a Secrets Manager secret.
    pub auth: types::CreateConnectionAuthRequestParameters,
    pub invocation_connectivity_parameters: Option<types::ConnectivityResourceParameters>,
    pub kms_key_identifier: Option<String>,
    pub secret_arn: String,
    pub creation_time: Option<DateTime<Utc>>,
    pub last_modified_time: Option<DateTime<Utc>>,
    pub last_authorized_time: Option<DateTime<Utc>>,
    /// The OAuth access token, once fetched.
    pub oauth_token: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiDestination {
    pub name: String,
    pub arn: String,
    pub description: Option<String>,
    pub state: String,
    pub connection_arn: String,
    pub invocation_endpoint: String,
    pub http_method: String,
    pub invocation_rate_limit_per_second: Option<i32>,
    pub creation_time: Option<DateTime<Utc>>,
    pub last_modified_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Endpoint {
    pub name: String,
    pub arn: String,
    pub description: Option<String>,
    pub routing_config: Option<types::RoutingConfig>,
    pub replication_config: Option<types::ReplicationConfig>,
    pub event_buses: Vec<types::EndpointEventBus>,
    pub role_arn: Option<String>,
    pub endpoint_id: String,
    pub endpoint_url: String,
    pub state: String,
    pub creation_time: Option<DateTime<Utc>>,
    pub last_modified_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EventSource {
    pub name: String,
    pub arn: String,
    /// The partner account that created it.
    pub created_by: String,
    pub creation_time: Option<DateTime<Utc>>,
    pub expiration_time: Option<DateTime<Utc>>,
    /// `PENDING`, `ACTIVE` or `DELETED`.
    pub state: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PartnerSource {
    pub name: String,
    pub arn: String,
    /// Customer accounts the source was created for.
    pub accounts: BTreeMap<String, PartnerAccount>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PartnerAccount {
    pub creation_time: Option<DateTime<Utc>>,
    pub expiration_time: Option<DateTime<Utc>>,
}

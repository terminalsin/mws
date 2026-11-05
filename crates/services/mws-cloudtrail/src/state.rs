//! What CloudTrail keeps, per account.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::generated::types;

/// How many events of history (`LookupEvents`) each account keeps per
/// Region. AWS keeps 90 days; the oldest go first once this many are kept.
pub const HISTORY_LIMIT: usize = 20_000;

/// How many events an event data store keeps before dropping the oldest.
pub const EDS_EVENT_LIMIT: usize = 100_000;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub accounts: BTreeMap<String, Account>,
}

impl State {
    pub fn account(&mut self, id: &str) -> &mut Account {
        self.accounts.entry(id.to_string()).or_default()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Account {
    /// By trail ARN.
    pub trails: BTreeMap<String, Trail>,
    /// Event history by Region, oldest first.
    pub history: BTreeMap<String, Vec<HistoryEvent>>,
    /// By ARN.
    pub event_data_stores: BTreeMap<String, EventDataStore>,
    /// By ARN.
    pub channels: BTreeMap<String, Channel>,
    /// By ARN.
    pub dashboards: BTreeMap<String, Dashboard>,
    /// Lake queries by id.
    pub queries: BTreeMap<String, Query>,
    /// Lake imports by id.
    pub imports: BTreeMap<String, Import>,
    /// Resource policies by resource ARN.
    pub resource_policies: BTreeMap<String, String>,
    /// Delegated administrator accounts (in a management account).
    pub delegated_admins: BTreeSet<String>,
    /// Insights events by Region, oldest first.
    pub insights: BTreeMap<String, Vec<HistoryEvent>>,
    /// Per-minute call and error counts that Insights watch, by
    /// `region|source|name|insight type|error code`.
    pub rates: BTreeMap<String, Rate>,
}

/// Calls per minute of one API (or one API error), and the Insight open on
/// it, if any.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Rate {
    /// Counts by minute (Unix seconds / 60).
    pub counts: BTreeMap<i64, u32>,
    /// The last minute evaluated.
    pub evaluated: i64,
    pub open: Option<OpenInsight>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OpenInsight {
    pub shared_event_id: String,
    pub start_minute: i64,
    pub baseline: f64,
    pub baseline_minutes: i64,
    pub total: u64,
}

/// One event in the event history.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HistoryEvent {
    pub event_id: String,
    pub event_name: String,
    pub event_source: String,
    pub event_time: DateTime<Utc>,
    pub read_only: bool,
    pub access_key_id: Option<String>,
    pub username: Option<String>,
    /// `(type, name)` pairs.
    pub resources: Vec<(String, String)>,
    /// The whole record, as JSON text.
    pub record: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Trail {
    pub name: String,
    pub arn: String,
    pub account: String,
    pub home_region: String,
    pub s3_bucket_name: String,
    pub s3_key_prefix: Option<String>,
    pub sns_topic_name: Option<String>,
    pub sns_topic_arn: Option<String>,
    pub include_global_service_events: bool,
    pub is_multi_region_trail: bool,
    pub log_file_validation_enabled: bool,
    pub cloud_watch_logs_log_group_arn: Option<String>,
    pub cloud_watch_logs_role_arn: Option<String>,
    pub kms_key_id: Option<String>,
    pub is_organization_trail: bool,
    /// The organization an organization trail collects events from.
    pub organization_id: Option<String>,
    pub tags: Vec<types::Tag>,
    /// Basic selectors; `None` means the default (all management events).
    pub event_selectors: Option<Vec<types::EventSelector>>,
    pub advanced_event_selectors: Option<Vec<types::AdvancedEventSelector>>,
    pub insight_selectors: Vec<types::InsightSelector>,
    pub max_event_size: Option<String>,
    pub context_key_selectors: Option<Vec<types::ContextKeySelector>>,
    pub aggregation_configurations: Option<Vec<types::AggregationConfiguration>>,
    pub is_logging: bool,
    pub start_logging_time: Option<DateTime<Utc>>,
    pub stop_logging_time: Option<DateTime<Utc>>,
    pub status: TrailStatus,
    /// Records waiting for the next log file, with the account each came
    /// from.
    pub pending: Vec<(String, Value)>,
    /// Insights events waiting for delivery.
    pub insight_pending: Vec<Value>,
    /// The Insights events this trail logged (`ListInsightsData`).
    pub insight_events: Vec<HistoryEvent>,
    pub digest: DigestChain,
}

impl Trail {
    pub fn has_custom_event_selectors(&self) -> bool {
        self.event_selectors.is_some() || self.advanced_event_selectors.is_some()
    }
}

/// What `GetTrailStatus` reports.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TrailStatus {
    pub latest_delivery_time: Option<DateTime<Utc>>,
    pub latest_delivery_error: Option<String>,
    pub latest_delivery_attempt_time: Option<DateTime<Utc>>,
    pub latest_delivery_attempt_succeeded: Option<DateTime<Utc>>,
    pub latest_notification_time: Option<DateTime<Utc>>,
    pub latest_notification_error: Option<String>,
    pub latest_notification_attempt_time: Option<DateTime<Utc>>,
    pub latest_notification_attempt_succeeded: Option<DateTime<Utc>>,
    pub latest_cloud_watch_logs_delivery_time: Option<DateTime<Utc>>,
    pub latest_cloud_watch_logs_delivery_error: Option<String>,
    pub latest_digest_delivery_time: Option<DateTime<Utc>>,
    pub latest_digest_delivery_error: Option<String>,
}

/// Log file integrity validation: the files delivered since the last
/// digest, and the last digest (each digest names the one before).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DigestChain {
    pub files: Vec<DeliveredFile>,
    pub previous_key: Option<String>,
    pub previous_signature: Option<String>,
    pub last_digest_end: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DeliveredFile {
    pub bucket: String,
    pub key: String,
    /// SHA-256 of the file as stored (compressed), hex.
    pub hash: String,
    pub newest: Option<DateTime<Utc>>,
    pub oldest: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EventDataStore {
    pub arn: String,
    pub name: String,
    pub home_region: String,
    /// `CREATED`, `ENABLED`, `PENDING_DELETION`, `STOPPED_INGESTION`, ...
    pub status: String,
    pub advanced_event_selectors: Vec<types::AdvancedEventSelector>,
    pub multi_region_enabled: bool,
    pub organization_enabled: bool,
    pub organization_id: Option<String>,
    pub retention_period: i32,
    pub termination_protection_enabled: bool,
    pub kms_key_id: Option<String>,
    pub billing_mode: String,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted_at: Option<DateTime<Utc>>,
    /// The status before deletion, restored by `RestoreEventDataStore`.
    pub status_before_deletion: Option<String>,
    pub federation_status: Option<String>,
    pub federation_role_arn: Option<String>,
    pub tags: Vec<types::Tag>,
    pub insight_selectors: Vec<types::InsightSelector>,
    pub insights_destination: Option<String>,
    pub max_event_size: Option<String>,
    pub context_key_selectors: Option<Vec<types::ContextKeySelector>>,
    pub aggregation_configurations: Option<Vec<types::AggregationConfiguration>>,
    /// Stored events, oldest first.
    pub events: Vec<Value>,
}

impl EventDataStore {
    pub fn id(&self) -> &str {
        self.arn.rsplit('/').next().unwrap_or(&self.arn)
    }

    /// The event category its selectors collect (`Management`, `Data`,
    /// `ActivityAuditLog` for channels, `ConfigurationItem`, ...).
    pub fn category(&self) -> Option<String> {
        self.advanced_event_selectors.iter().flat_map(|s| &s.field_selectors).find_map(|f| {
            (f.field == "eventCategory").then(|| f.equals.as_ref().and_then(|e| e.first().cloned())).flatten()
        })
    }

    pub fn ingesting(&self) -> bool {
        self.status == "ENABLED"
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Channel {
    pub arn: String,
    pub name: String,
    pub source: String,
    pub destinations: Vec<types::Destination>,
    pub tags: Vec<types::Tag>,
    pub apply_to_all_regions: bool,
    pub advanced_event_selectors: Vec<types::AdvancedEventSelector>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Dashboard {
    pub arn: String,
    pub name: String,
    pub kind: String,
    pub status: String,
    pub widgets: Vec<types::Widget>,
    pub refresh_schedule: Option<types::RefreshSchedule>,
    pub termination_protection_enabled: bool,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub last_refresh_id: Option<String>,
    pub last_refresh_failure_reason: Option<String>,
    pub tags: Vec<types::Tag>,
    /// Query ids of each refresh, by refresh id.
    pub refreshes: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Query {
    pub id: String,
    pub statement: String,
    pub status: String,
    /// The event data stores the query reads.
    pub event_data_stores: Vec<String>,
    pub created: DateTime<Utc>,
    pub error_message: Option<String>,
    pub columns: Vec<String>,
    /// Each row's values, in column order (`None` is SQL NULL).
    pub rows: Vec<Vec<Option<String>>>,
    pub events_scanned: i64,
    pub events_matched: i64,
    pub bytes_scanned: i64,
    pub execution_time_ms: i32,
    pub delivery_s3_uri: Option<String>,
    pub delivery_status: Option<String>,
    pub alias: Option<String>,
    pub prompt: Option<String>,
    pub refresh_id: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Import {
    pub id: String,
    pub destinations: Vec<String>,
    pub source: types::ImportSource,
    pub start_event_time: Option<DateTime<Utc>>,
    pub end_event_time: Option<DateTime<Utc>>,
    pub status: String,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub statistics: types::ImportStatistics,
    pub failures: Vec<types::ImportFailureListItem>,
}

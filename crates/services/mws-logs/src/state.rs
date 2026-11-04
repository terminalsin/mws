//! CloudWatch Logs state. Everything lives in a [`Region`] per account and
//! Region, keyed `"{account}/{region}"`. Most records reuse the generated
//! wire types, which already derive serde.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::generated::types;

/// One stored log event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub timestamp: i64,
    pub ingestion_time: i64,
    pub message: String,
    /// Unique per Region, in ingestion order; the base of `eventId`.
    pub seq: u64,
    /// The event as the log group's transformer left it (JSON), kept
    /// beside the original as CloudWatch Logs does. Logs Insights sees
    /// this version; filters opt in with `applyOnTransformedLogs`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transformed: Option<String>,
}

impl Event {
    /// What CloudWatch Logs bills and reports as stored bytes: the UTF-8
    /// message plus 26 bytes of overhead.
    pub fn size(&self) -> i64 {
        self.message.len() as i64 + 26
    }

    /// The message a feature sees: the transformed version when it asks
    /// for it and there is one, the original otherwise.
    pub fn message_for(&self, transformed: bool) -> &str {
        match (&self.transformed, transformed) {
            (Some(t), true) => t,
            _ => &self.message,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LogStream {
    pub name: String,
    pub creation_time: i64,
    pub first_event_timestamp: Option<i64>,
    pub last_event_timestamp: Option<i64>,
    pub last_ingestion_time: Option<i64>,
    /// Bumped by every `PutLogEvents`; `uploadSequenceToken` is derived
    /// from it.
    pub sequence: u64,
    /// Ordered by timestamp, then ingestion order.
    pub events: Vec<Event>,
}

impl LogStream {
    pub fn stored_bytes(&self) -> i64 {
        self.events.iter().map(Event::size).sum()
    }

    /// Insert keeping timestamp order (stable for equal timestamps).
    pub fn insert(&mut self, e: Event) {
        let at = self.events.partition_point(|x| x.timestamp <= e.timestamp);
        self.events.insert(at, e);
    }

    /// Drop events older than `cutoff` (retention).
    pub fn expire(&mut self, cutoff: i64) {
        let n = self.events.partition_point(|x| x.timestamp < cutoff);
        if n > 0 {
            self.events.drain(..n);
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Transformer {
    pub processors: Vec<types::Processor>,
    pub creation_time: i64,
    pub last_modified_time: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LogGroup {
    pub name: String,
    pub creation_time: i64,
    pub retention_in_days: Option<i32>,
    pub kms_key_id: Option<String>,
    /// `STANDARD`, `INFREQUENT_ACCESS` or `DELIVERY`.
    pub class: String,
    pub tags: BTreeMap<String, String>,
    pub deletion_protection: bool,
    pub bearer_token_authentication: bool,
    pub streams: BTreeMap<String, LogStream>,
    pub metric_filters: BTreeMap<String, types::MetricFilter>,
    pub subscription_filters: BTreeMap<String, types::SubscriptionFilter>,
    /// Document and last update.
    pub data_protection_policy: Option<(String, i64)>,
    pub index_policy: Option<types::IndexPolicy>,
    pub transformer: Option<Transformer>,
    pub syslog: Vec<types::SyslogConfiguration>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Destination {
    pub record: types::Destination,
    pub tags: BTreeMap<String, String>,
}

/// A resource policy: account-wide (`policyScope` ACCOUNT) or attached to
/// one log group (RESOURCE).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ResourcePolicy {
    pub name: Option<String>,
    pub resource_arn: Option<String>,
    pub document: String,
    pub last_updated_time: i64,
    pub revision_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Query {
    pub id: String,
    pub language: String,
    pub query_string: String,
    pub status: String,
    pub create_time: i64,
    pub log_groups: Vec<String>,
    pub results: Vec<Vec<types::ResultField>>,
    pub statistics: types::QueryStatistics,
    pub duration_ms: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AnomalyDetector {
    pub record: types::AnomalyDetector,
    pub tags: BTreeMap<String, String>,
    pub anomalies: Vec<types::Anomaly>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LookupTable {
    pub arn: String,
    pub name: String,
    pub description: Option<String>,
    pub body: String,
    pub kms_key_id: Option<String>,
    pub last_updated_time: i64,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ScheduledQuery {
    pub record: types::GetScheduledQueryResponse,
    pub tags: BTreeMap<String, String>,
    pub history: Vec<types::TriggerHistoryRecord>,
    /// Firings up to this time (epoch ms) have been looked at.
    pub evaluated_until: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Integration {
    pub name: String,
    pub integration_type: String,
    pub status: String,
    pub details: Option<types::IntegrationDetails>,
    pub config: Option<types::ResourceConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ImportTask {
    pub record: types::Import,
    pub batches: Vec<types::ImportBatch>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Region {
    pub log_groups: BTreeMap<String, LogGroup>,
    pub destinations: BTreeMap<String, Destination>,
    /// In creation order (ids sort by creation time).
    pub export_tasks: BTreeMap<String, types::ExportTask>,
    pub import_tasks: BTreeMap<String, ImportTask>,
    pub queries: BTreeMap<String, Query>,
    pub query_definitions: BTreeMap<String, types::QueryDefinition>,
    /// By name (account scope) or by `name@arn` (resource scope).
    pub resource_policies: BTreeMap<String, ResourcePolicy>,
    /// By `type/name`.
    pub account_policies: BTreeMap<String, types::AccountPolicy>,
    pub delivery_sources: BTreeMap<String, types::DeliverySource>,
    pub delivery_destinations: BTreeMap<String, types::DeliveryDestination>,
    pub delivery_destination_policies: BTreeMap<String, String>,
    pub deliveries: BTreeMap<String, types::Delivery>,
    /// By ARN.
    pub anomaly_detectors: BTreeMap<String, AnomalyDetector>,
    pub integrations: BTreeMap<String, Integration>,
    /// By name.
    pub lookup_tables: BTreeMap<String, LookupTable>,
    /// By ARN.
    pub scheduled_queries: BTreeMap<String, ScheduledQuery>,
    pub storage_tier: Option<(String, i64)>,
    /// Sources associated with S3 Tables integrations, by integration ARN.
    pub s3_table_sources: BTreeMap<String, Vec<types::S3TableIntegrationSource>>,
    /// KMS key for Logs Insights query results.
    pub query_result_kms_key: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// By `"{account}/{region}"`.
    pub regions: BTreeMap<String, Region>,
    /// Next event sequence number.
    pub next_seq: u64,
}

impl State {
    pub fn region(&mut self, account: &str, region: &str) -> &mut Region {
        self.regions.entry(format!("{account}/{region}")).or_default()
    }

    pub fn region_ref(&self, account: &str, region: &str) -> Option<&Region> {
        self.regions.get(&format!("{account}/{region}"))
    }
}

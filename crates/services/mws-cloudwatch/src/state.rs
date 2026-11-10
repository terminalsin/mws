//! CloudWatch state: a [`Region`] per account and Region, keyed
//! `"{account}/{region}"`.

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
    pub fn region(&mut self, account: &str, region: &str) -> &mut Region {
        self.regions.entry(format!("{account}/{region}")).or_default()
    }

    pub fn region_ref(&self, account: &str, region: &str) -> Option<&Region> {
        self.regions.get(&format!("{account}/{region}"))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Region {
    /// By [`MetricKey::key`].
    pub metrics: BTreeMap<String, Series>,
    pub alarms: BTreeMap<String, Alarm>,
    /// Oldest first.
    pub history: Vec<types::AlarmHistoryItem>,
    pub dashboards: BTreeMap<String, Dashboard>,
    pub insight_rules: BTreeMap<String, InsightRule>,
    pub anomaly_detectors: Vec<types::AnomalyDetector>,
    pub metric_streams: BTreeMap<String, MetricStream>,
    pub mute_rules: BTreeMap<String, MuteRule>,
    pub resource_metrics: BTreeMap<String, types::ResourceMetricsConfiguration>,
    pub otel: Option<OTelEnrichment>,
    /// Dataset id to its KMS key ARN, if any.
    pub datasets: BTreeMap<String, Option<String>>,
    /// Tags by resource ARN.
    pub tags: BTreeMap<String, BTreeMap<String, String>>,
}

/// A metric's identity: namespace, name and dimensions (sorted by name).
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricKey {
    pub namespace: String,
    pub name: String,
    pub dimensions: Vec<(String, String)>,
}

impl MetricKey {
    pub fn new(namespace: &str, name: &str, dimensions: Option<&[types::Dimension]>) -> Self {
        let mut dimensions: Vec<(String, String)> =
            dimensions.unwrap_or_default().iter().map(|d| (d.name.clone(), d.value.clone())).collect();
        dimensions.sort();
        dimensions.dedup_by(|a, b| a.0 == b.0);
        Self { namespace: namespace.to_string(), name: name.to_string(), dimensions }
    }

    pub fn key(&self) -> String {
        let mut k = format!("{}\u{1}{}", self.namespace, self.name);
        for (n, v) in &self.dimensions {
            k.push('\u{1}');
            k.push_str(n);
            k.push('=');
            k.push_str(v);
        }
        k
    }

    pub fn dimensions(&self) -> Vec<types::Dimension> {
        self.dimensions.iter().map(|(n, v)| types::Dimension { name: n.clone(), value: v.clone() }).collect()
    }

    pub fn to_metric(&self) -> types::Metric {
        types::Metric {
            namespace: Some(self.namespace.clone()),
            metric_name: Some(self.name.clone()),
            dimensions: Some(self.dimensions()),
        }
    }
}

/// One metric's stored data.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Series {
    pub key: MetricKey,
    /// Ordered by time.
    pub samples: Vec<Sample>,
    /// When data was last put, for `RecentlyActive`.
    pub last_put: Option<DateTime<Utc>>,
}

/// One `MetricDatum` as stored.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Sample {
    pub t: DateTime<Utc>,
    pub unit: String,
    pub resolution: i32,
    /// `(value, count)` pairs; empty for statistic sets.
    pub values: Vec<(f64, f64)>,
    pub stats: Option<StatSet>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct StatSet {
    pub count: f64,
    pub sum: f64,
    pub min: f64,
    pub max: f64,
}

/// An alarm of any type.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Alarm {
    pub arn: String,
    /// `MetricAlarm`, `CompositeAlarm` or `LogAlarm`.
    pub alarm_type: String,
    pub state_value: String,
    pub state_reason: String,
    pub state_reason_data: Option<String>,
    pub state_updated: DateTime<Utc>,
    pub state_transitioned: DateTime<Utc>,
    pub config_updated: DateTime<Utc>,
    pub evaluation_state: Option<String>,
    pub actions_suppressed_by: Option<String>,
    pub actions_suppressed_reason: Option<String>,
    /// While a composite alarm's suppressor waits or extends.
    pub suppressed_until: Option<DateTime<Utc>>,
    pub last_evaluated: Option<DateTime<Utc>>,
    /// The configuration as put (tags moved to the region's tag map).
    pub metric: Option<types::PutMetricAlarmInput>,
    pub composite: Option<types::PutCompositeAlarmInput>,
    pub log: Option<types::PutLogAlarmInput>,
    /// Contributors of multi-time-series alarms, by contributor id.
    pub contributors: BTreeMap<String, Contributor>,
    /// A log alarm's latest query results, oldest first (`None` when a
    /// run returned nothing).
    pub log_results: Vec<Option<f64>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Contributor {
    pub attributes: BTreeMap<String, String>,
    pub state_value: String,
    pub state_reason: String,
    pub transitioned: Option<DateTime<Utc>>,
}

impl Alarm {
    pub fn name(&self) -> &str {
        self.arn.rsplit_once(":alarm:").map(|(_, n)| n).unwrap_or_default()
    }

    pub fn actions_enabled(&self) -> bool {
        match (&self.metric, &self.composite, &self.log) {
            (Some(m), _, _) => m.actions_enabled.unwrap_or(true),
            (_, Some(c), _) => c.actions_enabled.unwrap_or(true),
            (_, _, Some(l)) => l.actions_enabled.unwrap_or(true),
            _ => true,
        }
    }

    pub fn set_actions_enabled(&mut self, enabled: bool) {
        if let Some(m) = &mut self.metric {
            m.actions_enabled = Some(enabled);
        }
        if let Some(c) = &mut self.composite {
            c.actions_enabled = Some(enabled);
        }
        if let Some(l) = &mut self.log {
            l.actions_enabled = Some(enabled);
        }
    }

    pub fn description(&self) -> Option<&str> {
        match (&self.metric, &self.composite, &self.log) {
            (Some(m), _, _) => m.alarm_description.as_deref(),
            (_, Some(c), _) => c.alarm_description.as_deref(),
            (_, _, Some(l)) => l.alarm_description.as_deref(),
            _ => None,
        }
    }

    /// `(OK, ALARM, INSUFFICIENT_DATA)` actions.
    pub fn actions(&self) -> (Vec<String>, Vec<String>, Vec<String>) {
        let o = |v: &Option<Vec<String>>| v.clone().unwrap_or_default();
        match (&self.metric, &self.composite, &self.log) {
            (Some(m), _, _) => (o(&m.ok_actions), o(&m.alarm_actions), o(&m.insufficient_data_actions)),
            (_, Some(c), _) => (o(&c.ok_actions), o(&c.alarm_actions), o(&c.insufficient_data_actions)),
            (_, _, Some(l)) => (o(&l.ok_actions), o(&l.alarm_actions), o(&l.insufficient_data_actions)),
            _ => Default::default(),
        }
    }

    pub fn actions_for(&self, state: &str) -> Vec<String> {
        let (ok, alarm, insufficient) = self.actions();
        match state {
            "OK" => ok,
            "ALARM" => alarm,
            _ => insufficient,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Dashboard {
    pub arn: String,
    pub body: String,
    pub last_modified: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct InsightRule {
    pub arn: String,
    pub state: String,
    pub definition: String,
    pub managed: bool,
    pub apply_on_transformed_logs: Option<bool>,
    /// For managed rules: the template and the resource.
    pub template_name: Option<String>,
    pub resource_arn: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MetricStream {
    pub arn: String,
    pub config: types::PutMetricStreamInput,
    pub state: String,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    /// The end of the last minute delivered to Firehose.
    pub delivered_until: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MuteRule {
    pub arn: String,
    pub config: types::PutAlarmMuteRuleInput,
    pub updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OTelEnrichment {
    pub running: bool,
    pub include_filters: Option<Vec<types::OTelEnrichmentMetricSelector>>,
    pub exclude_filters: Option<Vec<types::OTelEnrichmentMetricSelector>>,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
}

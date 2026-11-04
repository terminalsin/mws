//! Metric filters that publish: every event written to a log group is
//! matched against the group's metric filters, and each match publishes
//! the filter's metric value (a number, or the `$field` / `$.selector` the
//! pattern extracted) with its dimensions, to CloudWatch through the
//! [`MetricPublisher`] the `mws` crate registers. A batch with no match
//! publishes the transformation's `defaultValue`, when it has one.
//!
//! Also here: the read access CloudWatch has to log data (log alarms'
//! scheduled queries, Contributor Insights rules).

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::events::parse_pattern;
use crate::insights;
use crate::names::GroupRef;
use crate::state::Event;
use crate::Logs;

/// One metric datum a metric filter publishes.
#[derive(Debug, Clone)]
pub struct FilterMetric {
    pub account: String,
    pub region: String,
    pub namespace: String,
    pub metric_name: String,
    pub dimensions: Vec<(String, String)>,
    pub unit: Option<String>,
    /// Milliseconds since the epoch.
    pub timestamp: i64,
    pub value: f64,
}

/// Where metric filters publish (CloudWatch).
pub trait MetricPublisher: Send + Sync {
    fn publish(&self, metrics: Vec<FilterMetric>);
}

/// `$name` / `$.selector` values a pattern extracted, by the name the
/// metric transformation uses.
/// JSON events also resolve `$.selector`s the pattern does not mention, as
/// CloudWatch Logs does.
fn resolve(spec: &str, values: &BTreeMap<String, String>, doc: Option<&serde_json::Value>) -> Option<String> {
    let s = spec.trim();
    if !s.starts_with('$') {
        return Some(s.to_string());
    }
    values.get(s).or_else(|| values.get(s.trim_start_matches('$'))).cloned().or_else(|| {
        let v = crate::filter::select(doc?, s)?;
        (!v.is_null()).then(|| crate::filter::scalar_text(&v))
    })
}

impl Logs {
    /// Publish metric filter matches through `publisher`.
    pub fn set_metric_publisher(&self, publisher: Arc<dyn MetricPublisher>) {
        *self.metric_publisher.write().expect("Logs publisher lock poisoned") = Some(publisher);
    }

    /// Run the group's metric filters over newly stored events.
    pub(crate) fn publish_metrics(&self, g: &GroupRef, stored: &[Event]) {
        if stored.is_empty() {
            return;
        }
        let Some(publisher) = self.metric_publisher.read().expect("Logs publisher lock poisoned").clone() else {
            return;
        };
        let filters = {
            let st = self.lock();
            let Some(group) = st.region_ref(&g.account, &g.region).and_then(|r| r.log_groups.get(&g.name)) else {
                return;
            };
            group.metric_filters.values().cloned().collect::<Vec<_>>()
        };
        let mut out = Vec::new();
        for f in filters {
            let Ok(pattern) = parse_pattern(f.filter_pattern.as_deref()) else { continue };
            for t in f.metric_transformations.iter().flatten() {
                let mut matched = false;
                for e in stored {
                    let Some(values) = pattern.extract(&e.message) else { continue };
                    matched = true;
                    let doc: Option<serde_json::Value> = if e.message.trim_start().starts_with('{') {
                        serde_json::from_str(e.message.trim()).ok()
                    } else {
                        None
                    };
                    let Some(value) =
                        resolve(&t.metric_value, &values, doc.as_ref()).and_then(|v| v.parse::<f64>().ok())
                    else {
                        continue;
                    };
                    let mut dimensions = Vec::new();
                    let mut complete = true;
                    for (name, spec) in t.dimensions.iter().flatten() {
                        match resolve(spec, &values, doc.as_ref()) {
                            Some(v) if !v.is_empty() => dimensions.push((name.clone(), v)),
                            _ => complete = false,
                        }
                    }
                    if !complete {
                        continue;
                    }
                    out.push(FilterMetric {
                        account: g.account.clone(),
                        region: g.region.clone(),
                        namespace: t.metric_namespace.clone(),
                        metric_name: t.metric_name.clone(),
                        dimensions,
                        unit: t.unit.clone(),
                        timestamp: e.timestamp,
                        value,
                    });
                }
                if let (false, Some(default)) = (matched, t.default_value) {
                    out.push(FilterMetric {
                        account: g.account.clone(),
                        region: g.region.clone(),
                        namespace: t.metric_namespace.clone(),
                        metric_name: t.metric_name.clone(),
                        dimensions: Vec::new(),
                        unit: t.unit.clone(),
                        timestamp: stored.iter().map(|e| e.timestamp).max().unwrap_or_default(),
                        value: default,
                    });
                }
            }
        }
        if !out.is_empty() {
            publisher.publish(out);
        }
    }

    /// The events of log groups (names or ARNs) in `[start_ms, end_ms]`,
    /// read by an AWS service for the account that owns them. Missing
    /// groups are skipped.
    pub fn events_as_service(
        &self,
        account: &str,
        region: &str,
        log_groups: &[String],
        start_ms: i64,
        end_ms: i64,
    ) -> Vec<(String, String, i64, String)> {
        let st = self.lock();
        let mut out = Vec::new();
        let Some(r) = st.region_ref(account, region) else { return out };
        for id in log_groups {
            let name = group_name(id);
            let Some(group) = r.log_groups.get(name) else { continue };
            for s in group.streams.values() {
                for e in s.events.iter().filter(|e| e.timestamp >= start_ms && e.timestamp <= end_ms) {
                    out.push((name.to_string(), s.name.clone(), e.timestamp, e.message.clone()));
                }
            }
        }
        out.sort_by_key(|e| e.2);
        out
    }

    /// Run a Logs Insights query over log groups (names or ARNs) of
    /// `account`, as a service would for it (log alarms' scheduled
    /// queries). Returns the result rows.
    pub fn query_as_service(
        &self,
        account: &str,
        region: &str,
        log_groups: &[String],
        query: &str,
        start_ms: i64,
        end_ms: i64,
    ) -> Result<Vec<Vec<(String, String)>>, String> {
        let q = insights::parse(query)?;
        let records: Vec<insights::Record> = {
            let st = self.lock();
            let mut records = Vec::new();
            if let Some(r) = st.region_ref(account, region) {
                for id in log_groups {
                    let name = group_name(id);
                    let Some(group) = r.log_groups.get(name) else { continue };
                    let g = GroupRef {
                        partition: "aws".into(),
                        account: account.to_string(),
                        region: region.to_string(),
                        name: name.to_string(),
                    };
                    for s in group.streams.values() {
                        for e in s.events.iter().filter(|e| e.timestamp >= start_ms && e.timestamp <= end_ms) {
                            records.push(crate::queries::record(&g, &s.name, e));
                        }
                    }
                }
            }
            records
        };
        Ok(insights::execute(&q, records, 10_000).rows)
    }
}

/// The name in a log group name or ARN (`arn:...:log-group:NAME[:*]`).
fn group_name(id: &str) -> &str {
    match id.split_once(":log-group:") {
        Some((_, rest)) => rest.strip_suffix(":*").unwrap_or(rest),
        None => id,
    }
}

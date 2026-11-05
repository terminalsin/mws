//! CloudWatch metrics ELB publishes: `AWS/ApplicationELB`,
//! `AWS/NetworkELB`, `AWS/GatewayELB` and `AWS/ELB` (Classic). MWS wires a
//! [`MetricSink`] to CloudWatch.

use chrono::{DateTime, Utc};

/// One data point.
#[derive(Debug, Clone)]
pub struct ElbMetric {
    pub account: String,
    pub region: String,
    pub namespace: &'static str,
    pub metric_name: &'static str,
    pub dimensions: Vec<(String, String)>,
    pub unit: &'static str,
    pub value: f64,
    pub timestamp: DateTime<Utc>,
}

/// Where ELB metrics go.
pub trait MetricSink: Send + Sync {
    fn publish(&self, metrics: Vec<ElbMetric>);
}

pub(crate) fn namespace(lb_type: &str) -> &'static str {
    match lb_type {
        "network" => "AWS/NetworkELB",
        "gateway" => "AWS/GatewayELB",
        "classic" => "AWS/ELB",
        _ => "AWS/ApplicationELB",
    }
}

/// Collects data points for one event and publishes them together.
pub(crate) struct Batch {
    pub account: String,
    pub region: String,
    pub namespace: &'static str,
    pub timestamp: DateTime<Utc>,
    pub points: Vec<ElbMetric>,
}

impl Batch {
    pub fn new(account: &str, region: &str, namespace: &'static str) -> Self {
        Self { account: account.into(), region: region.into(), namespace, timestamp: Utc::now(), points: Vec::new() }
    }

    /// Add `metric` under each dimension set.
    pub fn add(
        &mut self,
        metric: &'static str,
        unit: &'static str,
        value: f64,
        dimension_sets: &[Vec<(String, String)>],
    ) {
        for dims in dimension_sets {
            self.points.push(ElbMetric {
                account: self.account.clone(),
                region: self.region.clone(),
                namespace: self.namespace,
                metric_name: metric,
                dimensions: dims.clone(),
                unit,
                value,
                timestamp: self.timestamp,
            });
        }
    }

    pub fn send(self, sink: Option<&std::sync::Arc<dyn MetricSink>>) {
        if let Some(sink) = sink {
            if !self.points.is_empty() {
                sink.publish(self.points);
            }
        }
    }
}

pub(crate) fn dims(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

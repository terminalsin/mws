//! The CloudWatch metrics Kinesis publishes in the `AWS/Kinesis`
//! namespace: stream-level metrics (dimension `StreamName`) for every
//! `PutRecord`, `PutRecords` and `GetRecords`, enhanced fan-out metrics
//! (dimensions `StreamName` and `ConsumerName`) for `SubscribeToShard`,
//! and, for the metrics enabled with `EnableEnhancedMonitoring`,
//! shard-level metrics (dimensions `StreamName` and `ShardId`).
//!
//! The `mws` crate registers the [`MetricPublisher`] that stores them in
//! CloudWatch. Without one, nothing is published.

use std::sync::Arc;

use crate::state::Stream;
use crate::Kinesis;

pub const NAMESPACE: &str = "AWS/Kinesis";

/// One data point Kinesis publishes into the stream owner's account.
#[derive(Debug, Clone, PartialEq)]
pub struct KinesisMetric {
    pub account: String,
    pub region: String,
    pub namespace: String,
    pub metric_name: String,
    pub dimensions: Vec<(String, String)>,
    /// `Bytes`, `Count` or `Milliseconds`.
    pub unit: String,
    /// Epoch milliseconds on the emulated clock.
    pub timestamp: i64,
    pub value: f64,
}

/// Where Kinesis metrics go (CloudWatch, wired by the `mws` crate).
pub trait MetricPublisher: Send + Sync {
    fn publish(&self, metrics: Vec<KinesisMetric>);
}

/// Collects one call's data points for a stream.
pub(crate) struct Batch {
    account: String,
    region: String,
    stream: String,
    shard_metrics: Vec<String>,
    now: i64,
    out: Vec<KinesisMetric>,
}

impl Batch {
    pub fn new(s: &Stream, now: i64) -> Self {
        Self {
            account: s.account.clone(),
            region: s.region.clone(),
            stream: s.name.clone(),
            shard_metrics: s.shard_level_metrics.clone(),
            now,
            out: Vec::new(),
        }
    }

    /// An empty batch for the same stream.
    pub fn new_like(other: &Batch) -> Self {
        Self {
            account: other.account.clone(),
            region: other.region.clone(),
            stream: other.stream.clone(),
            shard_metrics: other.shard_metrics.clone(),
            now: other.now,
            out: Vec::new(),
        }
    }

    fn push(&mut self, name: &str, dims: Vec<(String, String)>, unit: &str, value: f64) {
        self.out.push(KinesisMetric {
            account: self.account.clone(),
            region: self.region.clone(),
            namespace: NAMESPACE.into(),
            metric_name: name.into(),
            dimensions: dims,
            unit: unit.into(),
            timestamp: self.now,
            value,
        });
    }

    /// A stream-level data point.
    pub fn stream(&mut self, name: &str, unit: &str, value: f64) {
        let dims = vec![("StreamName".to_string(), self.stream.clone())];
        self.push(name, dims, unit, value);
    }

    /// An enhanced fan-out data point for a consumer.
    pub fn consumer(&mut self, consumer: &str, name: &str, unit: &str, value: f64) {
        let dims = vec![("StreamName".to_string(), self.stream.clone()), ("ConsumerName".to_string(), consumer.into())];
        self.push(name, dims, unit, value);
    }

    /// A shard-level data point, when enhanced monitoring enabled it.
    pub fn shard(&mut self, shard: &str, name: &str, unit: &str, value: f64) {
        if !self.shard_metrics.iter().any(|m| m == name) {
            return;
        }
        let dims = vec![("StreamName".to_string(), self.stream.clone()), ("ShardId".to_string(), shard.into())];
        self.push(name, dims, unit, value);
    }
}

impl Kinesis {
    /// Send metrics to CloudWatch through `publisher`.
    pub fn set_metric_publisher(&self, publisher: Arc<dyn MetricPublisher>) {
        *self.metric_publisher.write().expect("Kinesis metric publisher lock") = Some(publisher);
    }

    pub(crate) fn publish(&self, batch: Batch) {
        if batch.out.is_empty() {
            return;
        }
        let publisher = self.metric_publisher.read().expect("Kinesis metric publisher lock").clone();
        if let Some(p) = publisher {
            p.publish(batch.out);
        }
    }
}

/// Elapsed wall time of a call, in milliseconds, for the `*.Latency`
/// metrics.
pub(crate) fn latency_ms(started: std::time::Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

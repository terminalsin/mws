//! Metric data points services publish about their own resources (the
//! `AWS/*` CloudWatch namespaces in AWS). A service keeps a
//! [`MetricOutlet`]; whichever crate wires services together connects it
//! to a metrics store with [`MetricOutlet::connect`]. Until then,
//! publishing does nothing.

use std::sync::{Arc, OnceLock};

use chrono::{DateTime, Utc};

/// One data point (or a set of values for one timestamp).
#[derive(Debug, Clone, PartialEq)]
pub struct MetricDatum {
    pub account: String,
    pub region: String,
    pub namespace: &'static str,
    pub metric_name: &'static str,
    pub dimensions: Vec<(String, String)>,
    /// `Count`, `Milliseconds`, `Bytes`, `Seconds`, `Percent`, ...
    pub unit: &'static str,
    pub timestamp: DateTime<Utc>,
    /// `(value, count)` pairs.
    pub values: Vec<(f64, f64)>,
}

impl MetricDatum {
    /// A single value.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account: &str,
        region: &str,
        namespace: &'static str,
        metric_name: &'static str,
        dimensions: Vec<(String, String)>,
        unit: &'static str,
        timestamp: DateTime<Utc>,
        value: f64,
    ) -> Self {
        Self {
            account: account.to_string(),
            region: region.to_string(),
            namespace,
            metric_name,
            dimensions,
            unit,
            timestamp,
            values: vec![(value, 1.0)],
        }
    }
}

/// Where published metrics go.
pub trait MetricPublisher: Send + Sync {
    fn publish(&self, data: Vec<MetricDatum>);
}

/// A service's connection to the metrics store.
#[derive(Default)]
pub struct MetricOutlet(OnceLock<Arc<dyn MetricPublisher>>);

impl MetricOutlet {
    /// Send this service's metrics to `publisher`. Later calls are ignored.
    pub fn connect(&self, publisher: Arc<dyn MetricPublisher>) {
        let _ = self.0.set(publisher);
    }

    /// Whether anything receives the metrics (so callers can skip work).
    pub fn connected(&self) -> bool {
        self.0.get().is_some()
    }

    pub fn publish(&self, data: Vec<MetricDatum>) {
        if data.is_empty() {
            return;
        }
        if let Some(p) = self.0.get() {
            p.publish(data);
        }
    }
}

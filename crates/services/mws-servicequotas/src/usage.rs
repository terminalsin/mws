//! Quota usage: the `AWS/Usage` metrics.
//!
//! - `CallCount` (`Type=API`, `Resource=<operation>`, `Class=None`) for
//!   every API call the gateway answers.
//! - `ResourceCount` for quotas with an `AWS/Usage` usage metric (EC2 vCPUs
//!   by instance class), after every call to the quota's service and once a
//!   minute of emulated time for every account and Region seen.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;
use std::time::Duration;

use chrono::{DateTime, Utc};
use mws_core::{ApiCall, RequestObserver};

use crate::{catalog, Inner, ServiceQuotas};

/// Measures resource usage for quotas. Implemented over the services that
/// own the resources; must not call back into Service Quotas.
pub trait UsageSource: Send + Sync {
    /// Current usage of `service`/`code` in `account` and `region`, or
    /// `None` when not measured.
    fn usage(&self, account: &str, region: &str, service: &str, code: &str) -> Option<f64>;
}

/// One metric data point.
#[derive(Debug, Clone)]
pub struct UsageDatum {
    pub account: String,
    pub region: String,
    pub namespace: String,
    pub metric_name: String,
    pub dimensions: Vec<(String, String)>,
    pub value: f64,
    pub unit: String,
    pub timestamp: DateTime<Utc>,
}

/// Receives `AWS/Usage` metrics (CloudWatch).
pub trait MetricPublisher: Send + Sync {
    fn publish(&self, data: Vec<UsageDatum>);
}

const TICK: Duration = Duration::from_secs(5);

#[derive(Default)]
pub(crate) struct Monitor {
    inner: Mutex<MonitorState>,
    started: std::sync::OnceLock<()>,
}

#[derive(Default)]
struct MonitorState {
    /// Emulated minus wall clock, in milliseconds, as last seen.
    offset_ms: i64,
    /// Last minute (epoch minutes) `ResourceCount` was published, by
    /// account and Region.
    published: BTreeMap<(String, String), i64>,
    /// Metrics published with a non-zero value, so a drop to zero is
    /// published too.
    nonzero: BTreeSet<(String, String, &'static str, &'static str)>,
}

impl ServiceQuotas {
    /// Publish `ResourceCount` for the quotas of `service` (all quotas when
    /// `None`).
    fn publish_resource_counts(&self, account: &str, region: &str, service: Option<&str>, at: DateTime<Utc>) {
        let (Some(publisher), Some(source)) = (self.inner.metrics.get(), self.inner.usage.get()) else { return };
        let mut data = Vec::new();
        for def in catalog::QUOTAS {
            let Some(metric) = def.usage.filter(|u| u.namespace == "AWS/Usage") else { continue };
            if service.is_some_and(|s| s != def.service) {
                continue;
            }
            let Some(value) = source.usage(account, region, def.service, def.code) else { continue };
            let key = (account.to_string(), region.to_string(), def.service, def.code);
            {
                let mut m = self.inner.monitor.inner.lock().expect("Service Quotas monitor lock poisoned");
                if value == 0.0 && !m.nonzero.remove(&key) {
                    continue;
                }
                if value != 0.0 {
                    m.nonzero.insert(key);
                }
            }
            data.push(UsageDatum {
                account: account.into(),
                region: region.into(),
                namespace: metric.namespace.into(),
                metric_name: metric.name.into(),
                dimensions: metric.dimensions.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
                value,
                unit: "None".into(),
                timestamp: at,
            });
        }
        if !data.is_empty() {
            publisher.publish(data);
        }
    }

    fn start_monitor(&self) {
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        self.inner.monitor.started.get_or_init(|| {
            let weak = std::sync::Arc::downgrade(&self.inner);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(TICK).await;
                    let Some(inner) = weak.upgrade() else { return };
                    ServiceQuotas { inner }.minute_tick();
                }
            });
        });
    }

    fn minute_tick(&self) {
        let due: Vec<(String, String, DateTime<Utc>)> = {
            let mut m = self.inner.monitor.inner.lock().expect("Service Quotas monitor lock poisoned");
            let now = Utc::now() + chrono::Duration::milliseconds(m.offset_ms);
            let minute = now.timestamp() / 60;
            m.published
                .iter_mut()
                .filter(|(_, last)| **last < minute)
                .map(|((a, r), last)| {
                    *last = minute;
                    (a.clone(), r.clone(), now)
                })
                .collect()
        };
        for (account, region, now) in due {
            self.publish_resource_counts(&account, &region, None, now);
            self.auto_adjust(&account, &region, now);
        }
    }
}

impl Inner {
    fn note(&self, call: &ApiCall) {
        let mut m = self.monitor.inner.lock().expect("Service Quotas monitor lock poisoned");
        m.offset_ms = (call.at - Utc::now()).num_milliseconds();
        m.published.entry((call.account.clone(), call.region.clone())).or_insert(call.at.timestamp() / 60);
    }
}

impl RequestObserver for ServiceQuotas {
    fn observe(&self, call: &ApiCall) {
        if call.account.is_empty() {
            return;
        }
        self.inner.note(call);
        self.start_monitor();
        let Some(publisher) = self.inner.metrics.get() else { return };
        if let (Some(service), Some(operation)) = (catalog::usage_service_dimension(call.service), call.operation()) {
            publisher.publish(vec![UsageDatum {
                account: call.account.clone(),
                region: call.region.clone(),
                namespace: "AWS/Usage".into(),
                metric_name: "CallCount".into(),
                dimensions: vec![
                    ("Class".into(), "None".into()),
                    ("Resource".into(), operation.into()),
                    ("Service".into(), service.into()),
                    ("Type".into(), "API".into()),
                ],
                value: 1.0,
                unit: "None".into(),
                timestamp: call.at,
            }]);
        }
        if call.succeeded() {
            self.publish_resource_counts(&call.account, &call.region, Some(call.service), call.at);
        }
    }
}

//! The `AWS/EC2` CloudWatch metrics.
//!
//! Every running instance reports `CPUUtilization`, `NetworkIn`,
//! `NetworkOut`, `NetworkPacketsIn`, `NetworkPacketsOut`, the `Disk*`
//! metrics and (burstable types) `CPUCreditUsage` and `CPUCreditBalance`
//! once per period: 5 minutes with basic monitoring, 1 minute with detailed
//! monitoring (`Monitoring.Enabled`, `MonitorInstances`). The status check
//! metrics (`StatusCheckFailed`, `StatusCheckFailed_Instance`,
//! `StatusCheckFailed_System`) come every minute either way, as on AWS.
//! Data points carry the `InstanceId` dimension and, for instances in an
//! Auto Scaling group, `AutoScalingGroupName` (what target tracking on
//! `ASGAverageCPUUtilization` reads); instances with detailed monitoring
//! also report under `ImageId`, `InstanceType` and no dimension at all.
//!
//! Periods close on the emulated clock: moving `/_mws/clock` forward
//! publishes the periods it skipped (up to an hour of them).
//!
//! What the numbers are: with the Docker backend, the container's CPU
//! (`docker stats`, divided by the instance's vCPUs) and network counters
//! (`/proc/net/dev`), sampled every 10 seconds. With the metadata backend,
//! nothing runs: CPU is a low deterministic figure (0.5 to 3 %) and the
//! rest are zero. Tests can set any of these metrics for an instance with
//! the unsigned side channel `POST /_aws/ec2/metrics/<instance-id>`
//! (`{"CPUUtilization": 85}`; `null` removes a value, `DELETE` removes
//! them all, `GET` shows them).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, OnceLock};

use bytes::Bytes;
use chrono::{DateTime, TimeZone, Utc};
use mws_core::{HttpRequest, HttpResponse};
use serde_json::{json, Value};

use crate::catalog;
use crate::Ec2;

/// The unsigned side channel that sets an instance's metrics.
pub const PREFIX: &str = "/_aws/ec2/metrics";

/// One `AWS/EC2` data point.
#[derive(Debug, Clone, PartialEq)]
pub struct InstanceMetric {
    pub account: String,
    pub region: String,
    pub metric_name: &'static str,
    pub dimensions: Vec<(String, String)>,
    /// `Percent`, `Bytes` or `Count`.
    pub unit: &'static str,
    /// The start of the period.
    pub timestamp: DateTime<Utc>,
    pub value: f64,
}

/// Where `AWS/EC2` metrics go (CloudWatch, in MWS).
pub trait MetricSink: Send + Sync {
    fn publish(&self, metrics: Vec<InstanceMetric>);
}

/// The metrics published once per monitoring period, with their units.
const PERIOD_METRICS: &[(&str, &str)] = &[
    ("CPUUtilization", "Percent"),
    ("NetworkIn", "Bytes"),
    ("NetworkOut", "Bytes"),
    ("NetworkPacketsIn", "Count"),
    ("NetworkPacketsOut", "Count"),
    ("DiskReadOps", "Count"),
    ("DiskWriteOps", "Count"),
    ("DiskReadBytes", "Bytes"),
    ("DiskWriteBytes", "Bytes"),
];

/// The status check metrics, published every minute.
const STATUS_METRICS: &[&str] = &["StatusCheckFailed", "StatusCheckFailed_Instance", "StatusCheckFailed_System"];

/// The burstable credit metrics (per instance only).
const CREDIT_METRICS: &[&str] = &["CPUCreditUsage", "CPUCreditBalance"];

/// The most periods one clock jump publishes.
const MAX_CATCH_UP: i64 = 60;

/// What the backend reported about a running instance.
#[derive(Debug, Clone, Default)]
pub(crate) struct Sample {
    /// Percent of the instance's vCPUs.
    cpu: f64,
    rx_bytes: f64,
    tx_bytes: f64,
    rx_packets: f64,
    tx_packets: f64,
}

#[derive(Debug, Default)]
struct InstanceMeter {
    /// The start of the next period to publish (epoch ms).
    next: i64,
    period: i64,
    next_status: i64,
    credit_balance: f64,
    /// The sample the last published period ended with.
    base: Option<Sample>,
}

#[derive(Default)]
pub(crate) struct Meter {
    sink: OnceLock<Arc<dyn MetricSink>>,
    instances: Mutex<HashMap<String, InstanceMeter>>,
    samples: Mutex<HashMap<String, Sample>>,
    /// Values set through the side channel, by instance id.
    synthetic: Mutex<HashMap<String, BTreeMap<String, f64>>>,
}

/// A running instance to report.
struct Metered {
    account: String,
    region: String,
    id: String,
    image_id: String,
    instance_type: String,
    group: Option<String>,
    detailed: bool,
    since: i64,
    vcpus: f64,
    burstable: bool,
    handle: Option<String>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().expect("EC2 meter lock poisoned")
}

/// A stable, low CPU figure for an idle instance: 0.5 to 3 %.
fn idle_cpu(id: &str, period: i64) -> f64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for b in id.bytes().chain(period.to_le_bytes()) {
        h = (h ^ b as u64).wrapping_mul(0x100000001b3);
    }
    0.5 + (h % 251) as f64 / 100.0
}

/// The baseline utilization per vCPU of a burstable type, in percent.
fn credit_baseline(instance_type: &str) -> f64 {
    let (family, size) = instance_type.split_once('.').unwrap_or((instance_type, ""));
    let t2 = family == "t2";
    match size {
        "nano" => 5.0,
        "micro" => 10.0,
        "small" => 20.0,
        "medium" if t2 => 20.0,
        "medium" => 20.0,
        "large" if t2 => 30.0,
        "large" => 30.0,
        "xlarge" if t2 => 22.5,
        "xlarge" => 40.0,
        "2xlarge" if t2 => 17.0,
        "2xlarge" => 40.0,
        _ => 20.0,
    }
}

impl Ec2 {
    /// Publish `AWS/EC2` metrics through `sink`.
    pub fn set_metric_sink(&self, sink: Arc<dyn MetricSink>) {
        let _ = self.inner.signals.meter.sink.set(sink);
    }

    pub(crate) fn metrics_wanted(&self) -> bool {
        self.inner.signals.meter.sink.get().is_some()
    }

    fn metered(&self) -> Vec<Metered> {
        let state = self.lock();
        let mut out = Vec::new();
        for (key, r) in &state.regions {
            let (account, region) = key.split_once('/').unwrap_or((key, ""));
            for (id, rec) in &r.instances {
                if crate::ops::instance::state_name(rec) != "running" {
                    continue;
                }
                let i = &rec.instance;
                let instance_type = i.instance_type.clone().unwrap_or_default();
                let itype = catalog::instance_type(&instance_type);
                let tag = |k: &str| {
                    i.tags.iter().flatten().find(|t| t.key.as_deref() == Some(k)).and_then(|t| t.value.clone())
                };
                out.push(Metered {
                    account: account.to_string(),
                    region: region.to_string(),
                    id: id.clone(),
                    image_id: i.image_id.clone().unwrap_or_default(),
                    instance_type,
                    group: tag("aws:autoscaling:groupName"),
                    detailed: matches!(
                        i.monitoring.as_ref().and_then(|m| m.state.as_deref()),
                        Some("enabled" | "pending")
                    ),
                    since: i.launch_time.map(|t| t.timestamp_millis()).unwrap_or_default(),
                    vcpus: itype.map_or(1.0, |t| t.vcpus as f64),
                    burstable: itype.is_some_and(|t| t.burstable),
                    handle: rec.handle.clone(),
                });
            }
        }
        out
    }

    /// Read every running instance's usage from the backend.
    pub(crate) async fn sample_usage(&self) {
        let instances = self.metered();
        let backend = self.backend();
        let mut fresh = HashMap::new();
        for m in &instances {
            let Some(h) = &m.handle else { continue };
            if let Ok(Some(u)) = backend.usage(h).await {
                fresh.insert(
                    m.id.clone(),
                    Sample {
                        cpu: u.cpu_percent / m.vcpus.max(1.0),
                        rx_bytes: u.rx_bytes as f64,
                        tx_bytes: u.tx_bytes as f64,
                        rx_packets: u.rx_packets as f64,
                        tx_packets: u.tx_packets as f64,
                    },
                );
            }
        }
        let mut samples = lock(&self.inner.signals.meter.samples);
        samples.retain(|k, _| instances.iter().any(|m| &m.id == k));
        samples.extend(fresh);
    }

    /// Publish every period that ended by `now`.
    pub(crate) fn publish_metrics(&self, now: DateTime<Utc>) {
        let meter = &self.inner.signals.meter;
        let Some(sink) = meter.sink.get().cloned() else { return };
        let now = now.timestamp_millis();
        let instances = self.metered();
        let samples = lock(&meter.samples).clone();
        let synthetic = lock(&meter.synthetic).clone();
        let mut out = Vec::new();
        {
            let mut meters = lock(&meter.instances);
            meters.retain(|k, _| instances.iter().any(|m| &m.id == k));
            for m in &instances {
                let period: i64 = if m.detailed { 60_000 } else { 300_000 };
                let since = m.since.max(now - MAX_CATCH_UP * period);
                let e = meters.entry(m.id.clone()).or_insert_with(|| InstanceMeter {
                    next: since.div_euclid(period) * period,
                    period,
                    next_status: since.div_euclid(60_000) * 60_000,
                    ..Default::default()
                });
                if e.period != period {
                    // Monitoring changed: carry on at the next boundary.
                    e.next = (e.next + period - 1).div_euclid(period) * period;
                    e.period = period;
                }
                let set = synthetic.get(&m.id);
                let fixed = |name: &str| set.and_then(|s| s.get(name)).copied();
                let latest = samples.get(&m.id);
                let point = |out: &mut Vec<InstanceMetric>, name: &'static str, unit, at: i64, value: f64, all| {
                    let mut dims = vec![vec![("InstanceId".to_string(), m.id.clone())]];
                    if all {
                        if let Some(g) = &m.group {
                            dims.push(vec![("AutoScalingGroupName".into(), g.clone())]);
                        }
                        if m.detailed {
                            dims.push(vec![("ImageId".into(), m.image_id.clone())]);
                            dims.push(vec![("InstanceType".into(), m.instance_type.clone())]);
                            dims.push(Vec::new());
                        }
                    }
                    for d in dims {
                        out.push(InstanceMetric {
                            account: m.account.clone(),
                            region: m.region.clone(),
                            metric_name: name,
                            dimensions: d,
                            unit,
                            timestamp: Utc.timestamp_millis_opt(at).single().unwrap_or_default(),
                            value: if value.is_finite() { value.max(0.0) } else { 0.0 },
                        });
                    }
                };
                // Periods that ended.
                let mut n = 0;
                while e.next + period <= now && n < MAX_CATCH_UP {
                    let at = e.next;
                    e.next += period;
                    n += 1;
                    let last = e.next + period > now || n == MAX_CATCH_UP;
                    // Counters measured since the last period all land in
                    // the last one a clock jump publishes.
                    let base = e.base.as_ref();
                    let delta = |f: fn(&Sample) -> f64| match (latest, base) {
                        _ if !last => 0.0,
                        (Some(l), Some(b)) if f(l) >= f(b) => f(l) - f(b),
                        (Some(l), _) => f(l),
                        (None, _) => 0.0,
                    };
                    let cpu = fixed("CPUUtilization")
                        .or_else(|| latest.map(|l| l.cpu))
                        .unwrap_or_else(|| idle_cpu(&m.id, at / period));
                    for (name, unit) in PERIOD_METRICS {
                        let measured = match *name {
                            "CPUUtilization" => cpu,
                            "NetworkIn" => delta(|s| s.rx_bytes),
                            "NetworkOut" => delta(|s| s.tx_bytes),
                            "NetworkPacketsIn" => delta(|s| s.rx_packets),
                            "NetworkPacketsOut" => delta(|s| s.tx_packets),
                            _ => 0.0,
                        };
                        point(&mut out, name, unit, at, fixed(name).unwrap_or(measured), true);
                    }
                    if m.burstable {
                        let minutes = period as f64 / 60_000.0;
                        let usage = cpu / 100.0 * m.vcpus * minutes;
                        let earned = credit_baseline(&m.instance_type) / 100.0 * m.vcpus * minutes;
                        let max = credit_baseline(&m.instance_type) / 100.0 * m.vcpus * 60.0 * 24.0;
                        e.credit_balance = (e.credit_balance + earned - usage).clamp(0.0, max);
                        let usage = fixed(CREDIT_METRICS[0]).unwrap_or(usage);
                        let balance = fixed(CREDIT_METRICS[1]).unwrap_or(e.credit_balance);
                        point(&mut out, CREDIT_METRICS[0], "Count", at, usage, false);
                        point(&mut out, CREDIT_METRICS[1], "Count", at, balance, false);
                    }
                    if last {
                        if let Some(l) = latest {
                            e.base = Some(l.clone());
                        }
                    }
                }
                if n == MAX_CATCH_UP {
                    e.next = now.div_euclid(period) * period;
                }
                // Status checks, every minute.
                let mut k = 0;
                while e.next_status + 60_000 <= now && k < MAX_CATCH_UP {
                    let at = e.next_status;
                    e.next_status += 60_000;
                    k += 1;
                    let instance = fixed("StatusCheckFailed_Instance").unwrap_or(0.0);
                    let system = fixed("StatusCheckFailed_System").unwrap_or(0.0);
                    let any =
                        fixed("StatusCheckFailed").unwrap_or(if instance > 0.0 || system > 0.0 { 1.0 } else { 0.0 });
                    for (name, v) in STATUS_METRICS.iter().zip([any, instance, system]) {
                        point(&mut out, name, "Count", at, v, true);
                    }
                }
                if k == MAX_CATCH_UP {
                    e.next_status = now.div_euclid(60_000) * 60_000;
                }
            }
        }
        if !out.is_empty() {
            sink.publish(out);
        }
    }

    /// `/_aws/ec2/metrics/<instance-id>`: the values an instance reports
    /// instead of measured ones.
    pub(crate) fn serve_metrics_channel(&self, request: &HttpRequest) -> HttpResponse {
        let path = request.uri().path().trim_end_matches('/');
        let id = path.strip_prefix(PREFIX).unwrap_or_default().trim_start_matches('/');
        let respond = |status: u16, body: Value| {
            http::Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(Bytes::from(body.to_string()))
                .expect("valid response")
        };
        if id.is_empty() || id.contains('/') {
            return respond(404, json!({"message": format!("No MWS EC2 endpoint at {path}.")}));
        }
        let exists = self.lock().regions.values().any(|r| r.instances.contains_key(id));
        if !exists {
            return respond(404, json!({"message": format!("The instance ID '{id}' does not exist")}));
        }
        let meter = &self.inner.signals.meter;
        let known = |name: &str| {
            PERIOD_METRICS.iter().any(|(n, _)| *n == name)
                || STATUS_METRICS.contains(&name)
                || CREDIT_METRICS.contains(&name)
        };
        match *request.method() {
            http::Method::GET => {}
            http::Method::DELETE => {
                lock(&meter.synthetic).remove(id);
            }
            http::Method::POST | http::Method::PUT => {
                let Ok(Value::Object(body)) = serde_json::from_slice::<Value>(request.body()) else {
                    return respond(400, json!({"message": "Expected a JSON object of metric names and values."}));
                };
                let mut set = lock(&meter.synthetic);
                let entry = set.entry(id.to_string()).or_default();
                for (name, v) in body {
                    if !known(&name) {
                        return respond(
                            400,
                            json!({"message": format!("{name} is not an AWS/EC2 metric MWS publishes.")}),
                        );
                    }
                    match v {
                        Value::Null => {
                            entry.remove(&name);
                        }
                        Value::Number(n) => {
                            entry.insert(name, n.as_f64().unwrap_or_default());
                        }
                        _ => {
                            return respond(
                                400,
                                json!({"message": format!("The value of {name} must be a number or null.")}),
                            )
                        }
                    }
                }
            }
            _ => return respond(405, json!({"message": "Use GET, POST, PUT or DELETE."})),
        }
        let current = lock(&meter.synthetic).get(id).cloned().unwrap_or_default();
        respond(200, json!({"instanceId": id, "metrics": current}))
    }
}

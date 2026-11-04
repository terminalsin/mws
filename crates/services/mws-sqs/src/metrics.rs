//! The `AWS/SQS` CloudWatch metrics SQS publishes for each active queue,
//! one data point per queue per minute (dimension `QueueName`):
//! the `ApproximateNumberOfMessages*` gauges, `ApproximateAgeOfOldestMessage`,
//! and the counts of messages sent, received and deleted, empty receives,
//! FIFO deduplicated sends and the sizes of sent messages.
//!
//! Minutes close on the emulated clock: whenever SQS is called, and once a
//! second in the background. SQS learns the clock's offset from the
//! requests it serves. A queue's state cannot change without a request, so
//! minutes that pass in one clock jump are filled in with what the queue
//! held then.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use crate::state::Queue;
use crate::Sqs;

/// One metric data point SQS publishes.
#[derive(Debug, Clone, PartialEq)]
pub struct QueueMetric {
    pub account: String,
    pub region: String,
    pub queue_name: String,
    pub metric_name: &'static str,
    /// `Count`, `Bytes` or `Seconds`.
    pub unit: &'static str,
    /// Epoch milliseconds: the start of the minute.
    pub timestamp: i64,
    /// `(value, count)` pairs.
    pub values: Vec<(f64, f64)>,
}

/// Where SQS metrics go (CloudWatch, in MWS).
pub trait MetricPublisher: Send + Sync {
    fn publish(&self, metrics: Vec<QueueMetric>);
}

/// How long a queue without messages or traffic stays active.
const ACTIVE_FOR_MS: i64 = 6 * 3600 * 1000;
/// At most this many missed minutes are filled in per queue.
const BACKFILL_MINUTES: i64 = 60;

/// What happened to a queue in one minute.
#[derive(Debug, Clone, Default)]
pub(crate) struct Counts {
    pub sent: u64,
    pub sent_sizes: Vec<f64>,
    pub received: u64,
    pub empty_receives: u64,
    pub deleted: u64,
    pub deduplicated: u64,
}

#[derive(Debug, Default)]
struct QueueMeter {
    /// The first minute (epoch minutes) not yet published.
    next_minute: i64,
    last_activity: i64,
    counts: BTreeMap<i64, Counts>,
}

#[derive(Default)]
pub(crate) struct Meter {
    publisher: Mutex<Option<Arc<dyn MetricPublisher>>>,
    offset_ms: AtomicI64,
    scheduler: AtomicBool,
    queues: Mutex<HashMap<String, QueueMeter>>,
}

impl Meter {
    fn enabled(&self) -> bool {
        self.publisher.lock().expect("SQS meter lock poisoned").is_some()
    }

    /// Record an event on a queue at `now`.
    pub fn count(&self, arn: &str, now: i64, f: impl FnOnce(&mut Counts)) {
        if !self.enabled() {
            return;
        }
        let mut queues = self.queues.lock().expect("SQS meter lock poisoned");
        let m = queues
            .entry(arn.to_string())
            .or_insert_with(|| QueueMeter { next_minute: now.div_euclid(60_000), ..Default::default() });
        m.last_activity = m.last_activity.max(now);
        f(m.counts.entry(now.div_euclid(60_000)).or_default());
    }

    fn reset(&self) {
        self.queues.lock().expect("SQS meter lock poisoned").clear();
    }
}

fn point(q: &Queue, name: &'static str, unit: &'static str, minute: i64, values: Vec<(f64, f64)>) -> QueueMetric {
    QueueMetric {
        account: q.account.clone(),
        region: q.region.clone(),
        queue_name: q.name.clone(),
        metric_name: name,
        unit,
        timestamp: minute * 60_000,
        values,
    }
}

/// The data points of one queue for one minute, with gauges sampled at
/// the minute's end.
fn minute_points(q: &Queue, minute: i64, counts: Counts, out: &mut Vec<QueueMetric>) {
    let sample = (minute + 1) * 60_000 - 1;
    let present = q.messages.iter().filter(|m| m.sent_at <= sample);
    let (mut visible, mut in_flight, mut delayed, mut oldest) = (0, 0, 0, None::<i64>);
    for m in present {
        if m.in_flight(sample) {
            in_flight += 1;
        } else if m.delayed(sample) {
            delayed += 1;
        } else {
            visible += 1;
        }
        oldest = Some(oldest.map_or(m.sent_at, |o: i64| o.min(m.sent_at)));
    }
    let one = |v: f64| vec![(v, 1.0)];
    let age = oldest.map_or(0, |t| (sample - t) / 1000);
    out.push(point(q, "ApproximateNumberOfMessagesVisible", "Count", minute, one(visible as f64)));
    out.push(point(q, "ApproximateNumberOfMessagesNotVisible", "Count", minute, one(in_flight as f64)));
    out.push(point(q, "ApproximateNumberOfMessagesDelayed", "Count", minute, one(delayed as f64)));
    out.push(point(q, "ApproximateAgeOfOldestMessage", "Seconds", minute, one(age as f64)));
    out.push(point(q, "NumberOfMessagesSent", "Count", minute, one(counts.sent as f64)));
    out.push(point(q, "NumberOfMessagesReceived", "Count", minute, one(counts.received as f64)));
    out.push(point(q, "NumberOfMessagesDeleted", "Count", minute, one(counts.deleted as f64)));
    out.push(point(q, "NumberOfEmptyReceives", "Count", minute, one(counts.empty_receives as f64)));
    if q.fifo {
        out.push(point(q, "NumberOfDeduplicatedSentMessages", "Count", minute, one(counts.deduplicated as f64)));
    }
    if !counts.sent_sizes.is_empty() {
        let sizes = counts.sent_sizes.iter().map(|s| (*s, 1.0)).collect();
        out.push(point(q, "SentMessageSize", "Bytes", minute, sizes));
    }
}

impl Sqs {
    /// Publish `AWS/SQS` metrics through `publisher`.
    pub fn set_metric_publisher(&self, publisher: Arc<dyn MetricPublisher>) {
        *self.meter.publisher.lock().expect("SQS meter lock poisoned") = Some(publisher);
    }

    /// Note the emulated time of a request and publish the minutes that
    /// ended before it, before the request changes anything.
    pub(crate) fn observe_clock(&self, received_at: chrono::DateTime<chrono::Utc>) {
        if !self.meter.enabled() {
            return;
        }
        let offset = (received_at - chrono::Utc::now()).num_milliseconds().max(0);
        self.meter.offset_ms.store(offset, Ordering::Relaxed);
        if tokio::runtime::Handle::try_current().is_ok() && !self.meter.scheduler.swap(true, Ordering::SeqCst) {
            let me = self.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    let now = chrono::Utc::now().timestamp_millis() + me.meter.offset_ms.load(Ordering::Relaxed);
                    me.publish_metrics(now);
                }
            });
        }
        self.publish_metrics(received_at.timestamp_millis());
    }

    /// Publish every minute that ended by `now`.
    pub fn publish_metrics(&self, now: i64) {
        let Some(publisher) = self.meter.publisher.lock().expect("SQS meter lock poisoned").clone() else { return };
        let current = now.div_euclid(60_000);
        let mut out = Vec::new();
        {
            let st = self.lock();
            let mut meters = self.meter.queues.lock().expect("SQS meter lock poisoned");
            meters.retain(|arn, _| st.queues.contains_key(arn));
            for (arn, q) in &st.queues {
                let m = meters.entry(arn.clone()).or_insert_with(|| QueueMeter {
                    next_minute: q.created_at.div_euclid(60_000).max(current - 1),
                    last_activity: q.created_at,
                    ..Default::default()
                });
                m.next_minute = m.next_minute.max(current - BACKFILL_MINUTES);
                while m.next_minute < current {
                    let minute = m.next_minute;
                    m.next_minute += 1;
                    let counts = m.counts.remove(&minute).unwrap_or_default();
                    let end = (minute + 1) * 60_000;
                    let active = q.messages.iter().any(|x| x.sent_at < end)
                        || m.last_activity.max(q.created_at) + ACTIVE_FOR_MS > minute * 60_000;
                    if active && q.created_at < end {
                        minute_points(q, minute, counts, &mut out);
                    }
                }
                m.counts.retain(|k, _| *k >= current);
            }
        }
        if !out.is_empty() {
            publisher.publish(out);
        }
    }

    pub(crate) fn reset_metrics(&self) {
        self.meter.reset();
    }
}

/// Count one send: a message enqueued with its size, or a FIFO duplicate.
pub(crate) fn count_send(c: &mut Counts, size: usize, duplicate: bool) {
    if duplicate {
        c.deduplicated += 1;
    } else {
        c.sent += 1;
        c.sent_sizes.push(size as f64);
    }
}

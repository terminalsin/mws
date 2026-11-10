//! Event notifications: S3 sends an event message to the topics, queues
//! and functions a bucket's notification configuration names (checking
//! with each destination when the configuration is put, and sending it an
//! `s3:TestEvent`), and hands every object event of buckets with
//! EventBridge enabled to EventBridge.
//!
//! The destination services implement [`NotificationDestination`] and
//! [`EventBridgeSink`]; the composition root registers them.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use chrono::{DateTime, Utc};
use mws_core::{CallerKind, RequestContext, ServiceError};
use serde_json::json;

use crate::generated::types;
use crate::{errors, Call, S3};

/// One object event.
#[derive(Debug, Clone)]
pub struct ObjectEvent {
    /// The notification event name without `s3:`, e.g. `ObjectCreated:Put`.
    pub event_name: String,
    /// The API call behind it, e.g. `PutObject` (EventBridge's `reason`).
    pub reason: String,
    pub partition: String,
    pub region: String,
    pub bucket: String,
    /// The bucket owner's account.
    pub bucket_owner: String,
    pub key: String,
    pub size: Option<i64>,
    pub etag: Option<String>,
    pub version_id: Option<String>,
    pub sequencer: String,
    /// The requester's principal id (`AWS:AIDA...`, or the account for
    /// root).
    pub requester: String,
    pub source_ip: String,
    pub request_id: String,
    pub host_id: String,
    pub time: DateTime<Utc>,
    /// For removals: `Permanently Deleted` or `Delete Marker Created`.
    pub deletion_type: Option<String>,
    /// An extra member of the notification record, such as
    /// `lifecycleEventData`, `glacierEventData` or `replicationEventData`.
    pub record_data: Option<(&'static str, serde_json::Value)>,
    /// Extra members of the EventBridge `detail`, such as
    /// `destination-storage-class` or `restore-expiry-time`.
    pub eventbridge_detail: Option<serde_json::Value>,
}

/// The bucket a notification is about, as destinations judge access
/// (`aws:SourceArn`, `aws:SourceAccount`).
#[derive(Debug, Clone)]
pub struct NotificationSource<'a> {
    pub bucket_arn: &'a str,
    pub bucket_owner: &'a str,
}

/// A service S3 sends notification messages to.
pub trait NotificationDestination: Send + Sync {
    /// The service in the ARNs it takes: `sns`, `sqs` or `lambda`.
    fn service(&self) -> &'static str;
    /// Whether S3 (`s3.amazonaws.com`) may send to `arn` for the bucket.
    /// The error says why not.
    fn check(&self, ctx: &RequestContext, arn: &str, source: &NotificationSource<'_>) -> Result<(), String>;
    /// Send an event message.
    fn deliver(&self, ctx: &RequestContext, arn: &str, source: &NotificationSource<'_>, message: String);
}

/// Where buckets with EventBridge enabled send every object event.
pub trait EventBridgeSink: Send + Sync {
    fn object_event(&self, ctx: &RequestContext, event: &ObjectEvent);
}

#[derive(Default)]
pub(crate) struct Sinks {
    destinations: Mutex<Vec<Arc<dyn NotificationDestination>>>,
    eventbridge: OnceLock<Arc<dyn EventBridgeSink>>,
}

const EVENTS: &[&str] = &[
    "s3:TestEvent",
    "s3:ObjectCreated:*",
    "s3:ObjectCreated:Put",
    "s3:ObjectCreated:Post",
    "s3:ObjectCreated:Copy",
    "s3:ObjectCreated:CompleteMultipartUpload",
    "s3:ObjectRemoved:*",
    "s3:ObjectRemoved:Delete",
    "s3:ObjectRemoved:DeleteMarkerCreated",
    "s3:ObjectRestore:*",
    "s3:ObjectRestore:Post",
    "s3:ObjectRestore:Completed",
    "s3:ObjectRestore:Delete",
    "s3:ReducedRedundancyLostObject",
    "s3:Replication:*",
    "s3:Replication:OperationFailedReplication",
    "s3:Replication:OperationNotTracked",
    "s3:Replication:OperationMissedThreshold",
    "s3:Replication:OperationReplicatedAfterThreshold",
    "s3:LifecycleExpiration:*",
    "s3:LifecycleExpiration:Delete",
    "s3:LifecycleExpiration:DeleteMarkerCreated",
    "s3:LifecycleTransition",
    "s3:IntelligentTiering",
    "s3:ObjectTagging:*",
    "s3:ObjectTagging:Put",
    "s3:ObjectTagging:Delete",
    "s3:ObjectAcl:Put",
];

static SEQUENCER: AtomicU64 = AtomicU64::new(0);

fn sequencer(now: &DateTime<Utc>) -> String {
    let base = now.timestamp_nanos_opt().unwrap_or(0) as u64;
    let next = SEQUENCER.fetch_max(base, Ordering::SeqCst).max(base) + 1;
    SEQUENCER.store(next, Ordering::SeqCst);
    format!("{next:016X}")
}

/// Whether a configured event (`s3:ObjectCreated:*`) covers `name`
/// (`ObjectCreated:Put`).
fn covers(configured: &str, name: &str) -> bool {
    let c = configured.strip_prefix("s3:").unwrap_or(configured);
    match c.strip_suffix('*') {
        Some(prefix) => name.starts_with(prefix),
        None => c == name,
    }
}

/// `(prefix, suffix)` of a filter.
fn key_filter(f: Option<&types::NotificationConfigurationFilter>) -> (String, String) {
    let mut prefix = String::new();
    let mut suffix = String::new();
    for r in f.and_then(|f| f.key.as_ref()).and_then(|k| k.filter_rules.as_ref()).into_iter().flatten() {
        match r.name.as_deref().map(str::to_ascii_lowercase).as_deref() {
            Some("prefix") => prefix = r.value.clone().unwrap_or_default(),
            Some("suffix") => suffix = r.value.clone().unwrap_or_default(),
            _ => {}
        }
    }
    (prefix, suffix)
}

/// One destination of a configuration, flattened.
struct Target<'a> {
    id: &'a str,
    arn: &'a str,
    service: &'static str,
    events: &'a [String],
    filter: Option<&'a types::NotificationConfigurationFilter>,
}

fn targets(config: &types::NotificationConfiguration) -> Vec<Target<'_>> {
    let mut out = Vec::new();
    for t in config.topic_configurations.iter().flatten() {
        out.push(Target {
            id: t.id.as_deref().unwrap_or(""),
            arn: &t.topic_arn,
            service: "sns",
            events: &t.events,
            filter: t.filter.as_ref(),
        });
    }
    for q in config.queue_configurations.iter().flatten() {
        out.push(Target {
            id: q.id.as_deref().unwrap_or(""),
            arn: &q.queue_arn,
            service: "sqs",
            events: &q.events,
            filter: q.filter.as_ref(),
        });
    }
    for l in config.lambda_function_configurations.iter().flatten() {
        out.push(Target {
            id: l.id.as_deref().unwrap_or(""),
            arn: &l.lambda_function_arn,
            service: "lambda",
            events: &l.events,
            filter: l.filter.as_ref(),
        });
    }
    out
}

fn overlap(a: &str, b: &str, suffix: bool) -> bool {
    if suffix {
        a.ends_with(b) || b.ends_with(a)
    } else {
        a.starts_with(b) || b.starts_with(a)
    }
}

fn shares_event(a: &[String], b: &[String]) -> bool {
    let strip = |e: &String| e.strip_prefix("s3:").unwrap_or(e).to_string();
    a.iter().any(|x| {
        b.iter().any(|y| {
            let (x, y) = (strip(x), strip(y));
            let (xp, yp) = (x.trim_end_matches('*'), y.trim_end_matches('*'));
            x == y || (x.ends_with('*') && y.starts_with(xp)) || (y.ends_with('*') && x.starts_with(yp))
        })
    })
}

impl S3 {
    /// Send event messages for `service` ARNs to `destination`.
    pub fn add_notification_destination(&self, destination: Arc<dyn NotificationDestination>) {
        if let Ok(mut d) = self.notifications.destinations.lock() {
            d.retain(|x| x.service() != destination.service());
            d.push(destination);
        }
    }

    /// Hand object events of buckets with EventBridge enabled to `sink`.
    pub fn set_eventbridge_sink(&self, sink: Arc<dyn EventBridgeSink>) {
        let _ = self.notifications.eventbridge.set(sink);
    }

    fn destination(&self, service: &str) -> Option<Arc<dyn NotificationDestination>> {
        self.notifications.destinations.lock().ok()?.iter().find(|d| d.service() == service).cloned()
    }

    /// Check a configuration as S3 does before storing it: known events,
    /// valid filters, no overlapping rules, and (unless skipped) every
    /// destination accepting S3's messages. Sends `s3:TestEvent` to the
    /// destinations after a successful check.
    pub(crate) fn validate_notification(
        &self,
        ctx: &RequestContext,
        bucket: &str,
        owner: &str,
        config: &types::NotificationConfiguration,
        skip_validation: bool,
    ) -> Result<(), ServiceError> {
        let all = targets(config);
        for t in &all {
            for e in t.events {
                if !EVENTS.contains(&e.as_str()) {
                    return Err(errors::invalid_argument("The event is not supported for notifications", e, ""));
                }
            }
            for r in t.filter.and_then(|f| f.key.as_ref()).and_then(|k| k.filter_rules.as_ref()).into_iter().flatten() {
                let name = r.name.as_deref().unwrap_or("").to_ascii_lowercase();
                if name != "prefix" && name != "suffix" {
                    return Err(errors::invalid_argument(
                        "filter rule name must be either prefix or suffix",
                        "FilterRule.Name",
                        r.name.as_deref().unwrap_or(""),
                    ));
                }
            }
        }
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                let (ap, asx) = key_filter(a.filter);
                let (bp, bsx) = key_filter(b.filter);
                if shares_event(a.events, b.events) && overlap(&ap, &bp, false) && overlap(&asx, &bsx, true) {
                    return Err(errors::invalid_argument(
                        "Configurations overlap. Configurations on the same bucket cannot share a common event type.",
                        "Event",
                        "",
                    ));
                }
            }
        }
        if skip_validation {
            return Ok(());
        }
        let bucket_arn = format!("arn:{}:s3:::{bucket}", ctx.partition);
        let source = NotificationSource { bucket_arn: &bucket_arn, bucket_owner: owner };
        let mut failures = Vec::new();
        for t in &all {
            if let Some(d) = self.destination(t.service) {
                if let Err(why) = d.check(ctx, t.arn, &source) {
                    failures.push((t.arn.to_string(), why));
                }
            }
        }
        if let Some((arn, why)) = failures.into_iter().next() {
            return Err(errors::invalid_argument(
                "Unable to validate the following destination configurations",
                &arn,
                &why,
            ));
        }
        let test = json!({
            "Service": "Amazon S3",
            "Event": "s3:TestEvent",
            "Time": ctx.received_at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            "Bucket": bucket,
            "RequestId": ctx.request_id,
            "HostId": crate::host_id(&ctx.request_id),
        })
        .to_string();
        for t in &all {
            // Lambda functions get no test event.
            if t.service == "lambda" {
                continue;
            }
            if let Some(d) = self.destination(t.service) {
                d.deliver(ctx, t.arn, &source, test.clone());
            }
        }
        Ok(())
    }
}

/// An event about an object, before it is addressed to destinations.
#[derive(Debug, Clone, Default)]
pub(crate) struct Emit {
    pub bucket: String,
    pub key: String,
    pub version_id: Option<String>,
    /// The notification event name without `s3:`.
    pub event_name: String,
    /// The API call behind it (EventBridge's `reason`).
    pub reason: String,
    pub deletion_type: Option<String>,
    pub size: Option<i64>,
    pub etag: Option<String>,
    /// S3 itself caused the event (lifecycle, replication, a restore
    /// finishing): the requester is `s3.amazonaws.com`.
    pub by_s3: bool,
    /// An extra member of the event record, e.g. `lifecycleEventData`.
    pub record_data: Option<(&'static str, serde_json::Value)>,
    /// Extra members of the EventBridge `detail`.
    pub eventbridge_detail: Option<serde_json::Value>,
}

/// The principal and source address S3 reports for events it causes.
pub(crate) const S3_PRINCIPAL: &str = "s3.amazonaws.com";

impl Call {
    /// Emit an object event for `key` in `bucket`, looking up its size and
    /// ETag. `version_id` names the version (none for unversioned).
    /// `what` is the event name, the API call behind it (`reason`) and,
    /// for removals, the deletion type.
    pub(crate) fn object_event(
        &self,
        ctx: &RequestContext,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        what: (&str, &str, Option<&str>),
    ) {
        let (event_name, reason, deletion_type) = what;
        let (size, etag) = {
            let st = self.read();
            let Some(b) = st.buckets.get(bucket) else { return };
            let v = match version_id {
                Some(id) => b.version(key, id),
                None => b.latest(key),
            };
            match v {
                Some(v) if !v.delete_marker && deletion_type.is_none() => {
                    (Some(v.data.len() as i64), Some(v.etag.trim_matches('"').to_string()))
                }
                _ => (None, None),
            }
        };
        self.emit(
            ctx,
            Emit {
                bucket: bucket.to_string(),
                key: key.to_string(),
                version_id: version_id.map(str::to_string),
                event_name: event_name.to_string(),
                reason: reason.to_string(),
                deletion_type: deletion_type.map(str::to_string),
                size,
                etag,
                ..Emit::default()
            },
        );
    }
}

impl S3 {
    /// Send an object event to the bucket's destinations and, with
    /// EventBridge enabled, to EventBridge.
    pub(crate) fn emit(&self, ctx: &RequestContext, e: Emit) {
        let (config, region, owner, eventbridge) = {
            let st = self.read();
            let Some(b) = st.buckets.get(&e.bucket) else { return };
            let has_targets = !targets(&b.notification).is_empty();
            let eventbridge = b.notification.event_bridge_configuration.is_some();
            if !has_targets && !eventbridge {
                return;
            }
            (b.notification.clone(), b.region.clone(), b.owner.clone(), eventbridge)
        };
        let requester = if e.by_s3 {
            S3_PRINCIPAL.to_string()
        } else {
            match ctx.caller.kind {
                CallerKind::Root => ctx.caller.account_id.clone(),
                CallerKind::Anonymous => "Anonymous".to_string(),
                _ => format!("AWS:{}", ctx.caller.user_id),
            }
        };
        let source_ip = if e.by_s3 {
            S3_PRINCIPAL.to_string()
        } else {
            ctx.source_ip.clone().unwrap_or_else(|| "127.0.0.1".to_string())
        };
        let event = ObjectEvent {
            event_name: e.event_name.clone(),
            reason: e.reason.clone(),
            partition: ctx.partition.clone(),
            region,
            bucket: e.bucket.clone(),
            bucket_owner: owner,
            key: e.key.clone(),
            size: e.size,
            etag: e.etag.clone(),
            version_id: e.version_id.clone().filter(|v| v != "null"),
            sequencer: sequencer(&ctx.received_at),
            requester,
            source_ip,
            request_id: ctx.request_id.clone(),
            host_id: crate::host_id(&ctx.request_id),
            time: ctx.received_at,
            deletion_type: e.deletion_type.clone(),
            record_data: e.record_data.clone(),
            eventbridge_detail: e.eventbridge_detail.clone(),
        };
        if eventbridge {
            if let Some(sink) = self.notifications.eventbridge.get() {
                sink.object_event(ctx, &event);
            }
        }
        let bucket_arn = format!("arn:{}:s3:::{}", ctx.partition, e.bucket);
        let source = NotificationSource { bucket_arn: &bucket_arn, bucket_owner: &event.bucket_owner };
        for t in targets(&config) {
            if !t.events.iter().any(|c| covers(c, &e.event_name)) {
                continue;
            }
            let (prefix, suffix) = key_filter(t.filter);
            if !e.key.starts_with(&prefix) || !e.key.ends_with(&suffix) {
                continue;
            }
            let Some(d) = self.destination(t.service) else { continue };
            d.deliver(ctx, t.arn, &source, event_message(&event, t.id));
        }
    }
}

/// The record `eventVersion` of an event: 2.2 for replication events, 2.3
/// for the lifecycle, Intelligent-Tiering, ACL, tagging and restore-expiry
/// events added with it, 2.1 for the rest.
fn event_version(name: &str) -> &'static str {
    let group = name.split(':').next().unwrap_or(name);
    match group {
        "Replication" => "2.2",
        "LifecycleExpiration" | "LifecycleTransition" | "IntelligentTiering" | "ObjectTagging" | "ObjectAcl" => "2.3",
        "ObjectRestore" if name == "ObjectRestore:Delete" => "2.3",
        _ => "2.1",
    }
}

/// The event message S3 sends to notification destinations.
pub fn event_message(e: &ObjectEvent, configuration_id: &str) -> String {
    let mut object = serde_json::Map::new();
    // Keys are form-encoded (spaces become `+`), but `/` stays as is.
    let key = e
        .key
        .split('/')
        .map(|seg| form_urlencoded::byte_serialize(seg.as_bytes()).collect::<String>())
        .collect::<Vec<_>>()
        .join("/");
    object.insert("key".into(), json!(key));
    if let Some(s) = e.size {
        object.insert("size".into(), json!(s));
    }
    if let Some(t) = &e.etag {
        object.insert("eTag".into(), json!(t));
    }
    if let Some(v) = &e.version_id {
        object.insert("versionId".into(), json!(v));
    }
    object.insert("sequencer".into(), json!(e.sequencer));
    let mut record = json!({
            "eventVersion": event_version(&e.event_name),
            "eventSource": "aws:s3",
            "awsRegion": e.region,
            "eventTime": e.time.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            "eventName": e.event_name,
            "userIdentity": { "principalId": e.requester },
            "requestParameters": { "sourceIPAddress": e.source_ip },
            "responseElements": { "x-amz-request-id": e.request_id, "x-amz-id-2": e.host_id },
            "s3": {
                "s3SchemaVersion": "1.0",
                "configurationId": configuration_id,
                "bucket": {
                    "name": e.bucket,
                    "ownerIdentity": { "principalId": e.bucket_owner },
                    "arn": format!("arn:{}:s3:::{}", e.partition, e.bucket),
                },
                "object": object,
            }
    });
    if let Some((name, data)) = &e.record_data {
        record[*name] = data.clone();
    }
    json!({ "Records": [record] }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_and_overlaps() {
        assert!(covers("s3:ObjectCreated:*", "ObjectCreated:Put"));
        assert!(!covers("s3:ObjectCreated:Put", "ObjectCreated:Copy"));
        assert!(shares_event(&["s3:ObjectCreated:*".into()], &["s3:ObjectCreated:Put".into()]));
        assert!(!shares_event(&["s3:ObjectCreated:*".into()], &["s3:ObjectRemoved:*".into()]));
        assert!(overlap("images/", "", false));
        assert!(!overlap("images/", "docs/", false));
    }
}

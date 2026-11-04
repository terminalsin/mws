//! Subscription filters that deliver: events written to a log group that
//! match one of its subscription filters are sent to the filter's
//! destination as CloudWatch Logs does, a gzipped `DATA_MESSAGE`
//! (base64-encoded in `{"awslogs":{"data":...}}` for Lambda, the record
//! data for Kinesis and Firehose).
//!
//! Destinations are other services, reached through
//! [`SubscriptionTarget`]s the `mws` crate registers (Lambda, Kinesis,
//! Firehose), directly or through a CloudWatch Logs destination
//! (`PutDestination`, possibly in another account), whose target and role
//! are used. `PutSubscriptionFilter` asks the target first, so a function
//! whose policy does not let CloudWatch Logs invoke it, or a role CloudWatch
//! Logs cannot assume, is refused as in AWS.

use std::io::Write;
use std::sync::Arc;

use base64::Engine;
use mws_core::RequestContext;
use serde_json::json;

use crate::events::{event_id, parse_pattern};
use crate::names::GroupRef;
use crate::state::Event;
use crate::Logs;

/// The log group a delivery comes from.
#[derive(Debug, Clone)]
pub struct SubscriptionSource<'a> {
    /// `arn:...:log-group:<name>:*`, the `aws:SourceArn` CloudWatch Logs
    /// presents.
    pub log_group_arn: &'a str,
    pub account: &'a str,
    /// The role CloudWatch Logs assumes to write to the destination
    /// (Kinesis and Firehose), from the filter or the Logs destination.
    pub role_arn: Option<&'a str>,
    /// The log stream the events were written to (empty for test
    /// messages).
    pub log_stream: &'a str,
    /// `ByLogStream` or `Random`: how records are spread over Kinesis
    /// shards.
    pub distribution: &'a str,
}

/// A service subscription filters can deliver to.
pub trait SubscriptionTarget: Send + Sync {
    /// The service in destination ARNs this target handles, e.g. `lambda`.
    fn service(&self) -> &'static str;
    /// Whether CloudWatch Logs may deliver to `destination_arn`. The error
    /// is the message `PutSubscriptionFilter` fails with.
    fn check(&self, ctx: &RequestContext, destination_arn: &str, source: &SubscriptionSource<'_>)
        -> Result<(), String>;
    /// Deliver one gzipped message (JSON `DATA_MESSAGE`).
    fn deliver(&self, ctx: &RequestContext, destination_arn: &str, source: &SubscriptionSource<'_>, gzipped: Vec<u8>);
}

fn service_of(arn: &str) -> &str {
    arn.split(':').nth(2).unwrap_or_default()
}

impl Logs {
    /// Deliver subscription filter matches through `target`.
    pub fn add_subscription_target(&self, target: Arc<dyn SubscriptionTarget>) {
        self.targets.write().expect("Logs target lock poisoned").push(target);
    }

    fn target_for(&self, arn: &str) -> Option<Arc<dyn SubscriptionTarget>> {
        let service = service_of(arn);
        self.targets.read().expect("Logs target lock poisoned").iter().find(|t| t.service() == service).cloned()
    }

    /// Remember a request's context: deliveries for writes that arrive
    /// without one (other services' logs) use it.
    pub(crate) fn observe(&self, ctx: &RequestContext) {
        let offset = ctx.received_at - chrono::Utc::now();
        *self.template.lock().expect("Logs template lock poisoned") = Some((ctx.clone(), offset));
    }

    /// The target and role a destination ARN delivers to: a CloudWatch
    /// Logs destination stands for its target, with its role.
    fn resolve_destination(&self, destination_arn: &str, role_arn: Option<&str>) -> Option<(String, Option<String>)> {
        let parts: Vec<&str> = destination_arn.splitn(6, ':').collect();
        if parts.len() == 6 && parts[2] == "logs" {
            let name = parts[5].strip_prefix("destination:")?;
            let st = self.lock();
            let d = st.region_ref(parts[4], parts[3])?.destinations.get(name)?;
            return Some((d.record.target_arn.clone()?, d.record.role_arn.clone()));
        }
        Some((destination_arn.to_string(), role_arn.map(str::to_string)))
    }

    /// `PutSubscriptionFilter`'s check of a destination another service
    /// owns.
    pub(crate) fn check_subscription_target(
        &self,
        ctx: &RequestContext,
        g: &GroupRef,
        destination_arn: &str,
        role_arn: Option<&str>,
    ) -> Result<(), mws_core::ServiceError> {
        // A Logs destination's owner set up its target; only direct
        // destinations are tested.
        if service_of(destination_arn) == "logs" {
            return Ok(());
        }
        let Some((target_arn, role)) = self.resolve_destination(destination_arn, role_arn) else { return Ok(()) };
        let Some(target) = self.target_for(&target_arn) else { return Ok(()) };
        let arn = format!("{}:*", g.arn());
        let source = SubscriptionSource {
            log_group_arn: &arn,
            account: &g.account,
            role_arn: role.as_deref(),
            log_stream: "",
            distribution: "ByLogStream",
        };
        target.check(ctx, &target_arn, &source).map_err(crate::generated::errors::invalid_parameter)
    }

    /// Send newly stored events to the group's subscription filters.
    pub(crate) fn forward(&self, ctx: Option<&RequestContext>, g: &GroupRef, stream: &str, stored: &[Event]) {
        if stored.is_empty() {
            return;
        }
        let filters = {
            let st = self.lock();
            let Some(group) = st.region_ref(&g.account, &g.region).and_then(|r| r.log_groups.get(&g.name)) else {
                return;
            };
            group.subscription_filters.values().cloned().collect::<Vec<_>>()
        };
        if filters.is_empty() {
            return;
        }
        let ctx = match ctx {
            Some(c) => c.clone(),
            None => {
                let Some((mut c, offset)) = self.template.lock().expect("Logs template lock poisoned").clone() else {
                    return;
                };
                c.received_at = chrono::Utc::now() + offset;
                c.region = g.region.clone();
                c
            }
        };
        let arn = format!("{}:*", g.arn());
        for f in filters {
            let (Some(name), Some(destination)) = (&f.filter_name, &f.destination_arn) else { continue };
            let Some((destination, role)) = self.resolve_destination(destination, f.role_arn.as_deref()) else {
                continue;
            };
            let Some(target) = self.target_for(&destination) else { continue };
            let Ok(pattern) = parse_pattern(f.filter_pattern.as_deref()) else { continue };
            let transformed = f.apply_on_transformed_logs;
            let events: Vec<_> = stored
                .iter()
                .filter(|e| pattern.matches(e.message_for(transformed)))
                .map(
                    |e| json!({"id": event_id(e.seq), "timestamp": e.timestamp, "message": e.message_for(transformed)}),
                )
                .collect();
            if events.is_empty() {
                continue;
            }
            let message = json!({
                "messageType": "DATA_MESSAGE",
                "owner": g.account,
                "logGroup": g.name,
                "logStream": stream,
                "subscriptionFilters": [name],
                "logEvents": events,
            });
            let source = SubscriptionSource {
                log_group_arn: &arn,
                account: &g.account,
                role_arn: role.as_deref(),
                log_stream: stream,
                distribution: f.distribution.as_deref().unwrap_or("ByLogStream"),
            };
            target.deliver(&ctx, &destination, &source, gzip(&message));
        }
    }
}

/// How CloudWatch Logs packs subscription data: gzipped JSON.
pub fn gzip(message: &serde_json::Value) -> Vec<u8> {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(message.to_string().as_bytes()).expect("writing to memory");
    gz.finish().expect("writing to memory")
}

/// The `{"awslogs":{"data":...}}` event Lambda functions get.
pub fn lambda_event(gzipped: &[u8]) -> Vec<u8> {
    json!({"awslogs": {"data": base64::engine::general_purpose::STANDARD.encode(gzipped)}}).to_string().into_bytes()
}

/// The `CONTROL_MESSAGE` CloudWatch Logs writes to a new Kinesis or
/// Firehose destination to check its health.
pub fn control_message(now_ms: i64, what: &str) -> Vec<u8> {
    gzip(&json!({
        "messageType": "CONTROL_MESSAGE",
        "owner": "CloudwatchLogs",
        "logGroup": "",
        "logStream": "",
        "subscriptionFilters": [],
        "logEvents": [{
            "id": "",
            "timestamp": now_ms,
            "message": format!("CWL CONTROL MESSAGE: Checking health of destination {what}."),
        }],
    }))
}

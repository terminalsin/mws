//! Subscription filters that deliver: events written to a log group that
//! match one of its subscription filters are sent to the filter's
//! destination as CloudWatch Logs does, a gzipped, base64-encoded
//! `DATA_MESSAGE` (`{"awslogs":{"data":...}}` for Lambda).
//!
//! Destinations are other services, reached through
//! [`SubscriptionTarget`]s the `mws` crate registers (Lambda, which already
//! depends on this crate). `PutSubscriptionFilter` asks the target first,
//! so a function whose policy does not let CloudWatch Logs invoke it is
//! refused as in AWS.

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
}

/// A service subscription filters can deliver to.
pub trait SubscriptionTarget: Send + Sync {
    /// The service in destination ARNs this target handles, e.g. `lambda`.
    fn service(&self) -> &'static str;
    /// Whether CloudWatch Logs may deliver to `destination_arn`. The error
    /// is the message `PutSubscriptionFilter` fails with.
    fn check(&self, ctx: &RequestContext, destination_arn: &str, source: &SubscriptionSource<'_>)
        -> Result<(), String>;
    /// Deliver one encoded message.
    fn deliver(&self, ctx: &RequestContext, destination_arn: &str, source: &SubscriptionSource<'_>, payload: Vec<u8>);
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

    /// `PutSubscriptionFilter`'s check of a destination another service
    /// owns.
    pub(crate) fn check_subscription_target(
        &self,
        ctx: &RequestContext,
        g: &GroupRef,
        destination_arn: &str,
    ) -> Result<(), mws_core::ServiceError> {
        let Some(target) = self.target_for(destination_arn) else { return Ok(()) };
        let arn = format!("{}:*", g.arn());
        let source = SubscriptionSource { log_group_arn: &arn, account: &g.account };
        target.check(ctx, destination_arn, &source).map_err(crate::generated::errors::invalid_parameter)
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
            let Some(target) = self.target_for(destination) else { continue };
            let Ok(pattern) = parse_pattern(f.filter_pattern.as_deref()) else { continue };
            let events: Vec<_> = stored
                .iter()
                .filter(|e| pattern.matches(&e.message))
                .map(|e| json!({"id": event_id(e.seq), "timestamp": e.timestamp, "message": e.message}))
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
            let payload = json!({"awslogs": {"data": encode(&message)}});
            let source = SubscriptionSource { log_group_arn: &arn, account: &g.account };
            target.deliver(&ctx, destination, &source, payload.to_string().into_bytes());
        }
    }
}

/// gzip, then base64: how CloudWatch Logs packs subscription data.
pub fn encode(message: &serde_json::Value) -> String {
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(message.to_string().as_bytes()).expect("writing to memory");
    base64::engine::general_purpose::STANDARD.encode(gz.finish().expect("writing to memory"))
}

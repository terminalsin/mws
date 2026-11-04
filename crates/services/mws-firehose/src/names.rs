//! Delivery stream ARNs, errors and authorization.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::errors;
use crate::state::{DeliveryStream, State};

pub fn now_ms(ctx: &RequestContext) -> i64 {
    ctx.received_at.timestamp_millis()
}

pub fn stream_arn(partition: &str, region: &str, account: &str, name: &str) -> String {
    format!("arn:{partition}:firehose:{region}:{account}:deliverystream/{name}")
}

pub fn invalid_argument(message: impl Into<String>) -> ServiceError {
    errors::invalid_argument(message)
}

pub fn not_found(name: &str, account: &str) -> ServiceError {
    errors::resource_not_found(format!("Firehose {name} under account {account} not found."))
}

/// Firehose answers denials with `AccessDeniedException` and status 400.
pub fn firehose_denial(e: ServiceError) -> ServiceError {
    if e.code == "AccessDenied" {
        ServiceError::client("AccessDeniedException", 400, e.message)
    } else {
        e
    }
}

pub fn tag_context(tags: &std::collections::BTreeMap<String, String>) -> ConditionContext {
    tags.iter().map(|(k, v)| (format!("aws:ResourceTag/{k}"), vec![v.clone()])).collect()
}

pub fn request_tag_context(tags: &std::collections::BTreeMap<String, String>) -> ConditionContext {
    let mut c: ConditionContext = tags.iter().map(|(k, v)| (format!("aws:RequestTag/{k}"), vec![v.clone()])).collect();
    if !tags.is_empty() {
        c.insert("aws:TagKeys".into(), tags.keys().cloned().collect());
    }
    c
}

/// A delivery stream a request names, in the caller's account and Region.
pub struct StreamRef {
    pub name: String,
    pub arn: String,
    pub account: String,
}

impl StreamRef {
    pub fn new(ctx: &RequestContext, name: &str) -> Self {
        let account = ctx.caller.account_id.clone();
        Self { arn: stream_arn(&ctx.partition, &ctx.region, &account, name), name: name.to_string(), account }
    }

    pub fn get<'a>(&self, st: &'a State) -> Result<&'a DeliveryStream, ServiceError> {
        st.streams.get(&self.arn).ok_or_else(|| not_found(&self.name, &self.account))
    }

    pub fn get_mut<'a>(&self, st: &'a mut State) -> Result<&'a mut DeliveryStream, ServiceError> {
        st.streams.get_mut(&self.arn).ok_or_else(|| not_found(&self.name, &self.account))
    }
}

/// Authorize `firehose:<action>` on a delivery stream.
pub fn authorize(
    ctx: &RequestContext,
    st: &State,
    action: &str,
    r: &StreamRef,
    mut extra: ConditionContext,
) -> Result<(), ServiceError> {
    if let Some(s) = st.streams.get(&r.arn) {
        extra.extend(tag_context(&s.tags));
    }
    ctx.authorize(&format!("firehose:{action}"), &r.arn, extra).map_err(firehose_denial)
}

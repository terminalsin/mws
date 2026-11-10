//! ARNs, name resolution, pagination and the authorization helpers the
//! operations share.

use std::collections::BTreeMap;

use base64::Engine;
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::state::{Bus, State};
use crate::Events;

pub fn validation(message: impl Into<String>) -> ServiceError {
    ServiceError::client("ValidationException", 400, message)
}

pub fn not_found(message: impl Into<String>) -> ServiceError {
    crate::generated::errors::resource_not_found(message)
}

/// An event bus addressed by name or ARN.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BusRef {
    pub partition: String,
    pub account: String,
    pub region: String,
    pub name: String,
}

impl BusRef {
    pub fn own(ctx: &RequestContext, name: &str) -> Self {
        Self {
            partition: ctx.partition.clone(),
            account: ctx.caller.account_id.clone(),
            region: ctx.region.clone(),
            name: name.to_string(),
        }
    }

    /// `EventBusName` as the operations take it: a name or a bus ARN,
    /// defaulting to `default`.
    pub fn parse(ctx: &RequestContext, raw: Option<&str>) -> Result<Self, ServiceError> {
        let raw = raw.filter(|s| !s.is_empty()).unwrap_or("default");
        if !raw.starts_with("arn:") {
            return Ok(Self::own(ctx, raw));
        }
        Self::from_arn(raw).ok_or_else(|| {
            validation(format!("Parameter {raw} is not valid. Reason: Provided Arn is not in correct format."))
        })
    }

    pub fn from_arn(arn: &str) -> Option<Self> {
        let parts: Vec<&str> = arn.splitn(6, ':').collect();
        if parts.len() != 6 || parts[0] != "arn" || parts[2] != "events" {
            return None;
        }
        let name = parts[5].strip_prefix("event-bus/")?;
        if name.is_empty() {
            return None;
        }
        Some(Self {
            partition: parts[1].to_string(),
            account: parts[4].to_string(),
            region: parts[3].to_string(),
            name: name.to_string(),
        })
    }

    pub fn arn(&self) -> String {
        format!("arn:{}:events:{}:{}:event-bus/{}", self.partition, self.region, self.account, self.name)
    }

    pub fn rule_arn(&self, rule: &str) -> String {
        if self.name == "default" {
            format!("arn:{}:events:{}:{}:rule/{rule}", self.partition, self.region, self.account)
        } else {
            format!("arn:{}:events:{}:{}:rule/{}/{rule}", self.partition, self.region, self.account, self.name)
        }
    }

    pub fn missing(&self) -> ServiceError {
        not_found(format!("Event bus {} does not exist.", self.name))
    }
}

/// An ARN in the caller's account and Region.
pub fn arn(ctx: &RequestContext, resource: &str) -> String {
    format!("arn:{}:events:{}:{}:{resource}", ctx.partition, ctx.region, ctx.caller.account_id)
}

/// The pieces of any ARN: (partition, service, region, account, resource).
pub fn split_arn(arn: &str) -> Option<(&str, &str, &str, &str, &str)> {
    let parts: Vec<&str> = arn.splitn(6, ':').collect();
    if parts.len() != 6 || parts[0] != "arn" || parts[2].is_empty() {
        return None;
    }
    Some((parts[1], parts[2], parts[3], parts[4], parts[5]))
}

/// One page of `items` from an opaque `NextToken`.
pub fn paginate<T>(
    items: Vec<T>,
    next_token: Option<&str>,
    limit: Option<i32>,
    default: usize,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match next_token {
        Some(t) => base64::engine::general_purpose::STANDARD
            .decode(t)
            .ok()
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| s.strip_prefix("mws:").and_then(|n| n.parse::<usize>().ok()))
            .ok_or_else(|| validation("The NextToken provided is invalid."))?,
        None => 0,
    };
    let limit = limit.map(|l| l.max(1) as usize).unwrap_or(default);
    let total = items.len();
    let page: Vec<T> = items.into_iter().skip(start).take(limit).collect();
    let next = (start + limit < total)
        .then(|| base64::engine::general_purpose::STANDARD.encode(format!("mws:{}", start + limit)));
    Ok((page, next))
}

/// `aws:ResourceTag/...` for a resource.
pub fn resource_tags(tags: Option<&BTreeMap<String, String>>) -> ConditionContext {
    let mut c = ConditionContext::new();
    for (k, v) in tags.into_iter().flatten() {
        c.insert(format!("aws:ResourceTag/{k}"), vec![v.clone()]);
    }
    c
}

/// `aws:RequestTag/...` and `aws:TagKeys` for tags a request adds.
pub fn request_tags<'a>(tags: impl IntoIterator<Item = (&'a String, &'a String)>) -> ConditionContext {
    let mut c = ConditionContext::new();
    let mut keys = Vec::new();
    for (k, v) in tags {
        c.insert(format!("aws:RequestTag/{k}"), vec![v.clone()]);
        keys.push(k.clone());
    }
    if !keys.is_empty() {
        c.insert("aws:TagKeys".into(), keys);
    }
    c
}

impl Events {
    /// Authorize `action` on a bus (or a rule on it) with the bus policy
    /// as the resource policy, so other accounts can act where it allows.
    pub(crate) fn authorize_on_bus(
        &self,
        ctx: &RequestContext,
        action: &str,
        bus: &BusRef,
        resource: &str,
        mut extra: ConditionContext,
    ) -> Result<(), ServiceError> {
        let (policy, tags) = {
            let st = self.lock();
            let region = st.region(&bus.account, &bus.region);
            let policy = region.and_then(|r| r.buses.get(&bus.name)).and_then(|b| b.policy.clone());
            let tags = region.and_then(|r| r.tags.get(resource)).cloned();
            (policy, tags)
        };
        extra.extend(resource_tags(tags.as_ref()));
        if bus.account != ctx.caller.account_id {
            extra.insert("events:creatorAccount".into(), vec![ctx.caller.account_id.clone()]);
        }
        ctx.authorize_with_resource_policy(action, resource, policy.as_deref(), extra)
    }

    /// Authorize `action` on a resource in the caller's account, with its
    /// tags as `aws:ResourceTag` conditions.
    pub(crate) fn authorize_own(
        &self,
        ctx: &RequestContext,
        action: &str,
        resource: &str,
        mut extra: ConditionContext,
    ) -> Result<(), ServiceError> {
        let tags = {
            let st = self.lock();
            st.region(&ctx.caller.account_id, &ctx.region).and_then(|r| r.tags.get(resource)).cloned()
        };
        extra.extend(resource_tags(tags.as_ref()));
        ctx.authorize(action, resource, extra)
    }

    /// Run `f` on the bus, creating the Region's default bus on first use.
    pub(crate) fn with_bus<T>(
        &self,
        ctx: &RequestContext,
        bus: &BusRef,
        f: impl FnOnce(&mut Bus) -> Result<T, ServiceError>,
    ) -> Result<T, ServiceError> {
        let mut st = self.lock();
        let region = st.region_mut(&bus.partition, &bus.account, &bus.region, ctx.received_at);
        let b = region.buses.get_mut(&bus.name).ok_or_else(|| bus.missing())?;
        f(b)
    }

    pub(crate) fn bus_exists(&self, ctx: &RequestContext, bus: &BusRef) -> bool {
        let mut st = self.lock();
        st.region_mut(&bus.partition, &bus.account, &bus.region, ctx.received_at).buses.contains_key(&bus.name)
    }
}

pub fn own_region<'a>(st: &'a mut State, ctx: &RequestContext) -> &'a mut crate::state::Region {
    st.region_mut(&ctx.partition, &ctx.caller.account_id, &ctx.region, ctx.received_at)
}

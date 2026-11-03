//! ARNs, identifiers, pagination tokens and authorization shared by the
//! operations.

use std::collections::BTreeMap;

use base64::Engine;
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::errors;
use crate::state::{LogGroup, Region, State};
use crate::Logs;

pub fn now_ms(ctx: &RequestContext) -> i64 {
    ctx.received_at.timestamp_millis()
}

pub fn arn(ctx: &RequestContext, resource: &str) -> String {
    format!("arn:{}:logs:{}:{}:{resource}", ctx.partition, ctx.region, ctx.caller.account_id)
}

/// A log group addressed by name or ARN, resolved to its account and Region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupRef {
    pub partition: String,
    pub account: String,
    pub region: String,
    pub name: String,
}

impl GroupRef {
    pub fn own(ctx: &RequestContext, name: &str) -> Self {
        Self {
            partition: ctx.partition.clone(),
            account: ctx.caller.account_id.clone(),
            region: ctx.region.clone(),
            name: name.to_string(),
        }
    }

    /// A log group name, or a log group ARN with or without the trailing
    /// `:*`.
    pub fn parse(ctx: &RequestContext, identifier: &str) -> Result<Self, ServiceError> {
        if !identifier.starts_with("arn:") {
            return Ok(Self::own(ctx, identifier));
        }
        let parts: Vec<&str> = identifier.splitn(6, ':').collect();
        let bad = || errors::invalid_parameter(format!("Invalid log group ARN: {identifier}"));
        if parts.len() != 6 || parts[2] != "logs" {
            return Err(bad());
        }
        let rest = parts[5].strip_prefix("log-group:").ok_or_else(bad)?;
        let name = rest.strip_suffix(":*").unwrap_or(rest);
        if name.is_empty() || name.contains(':') {
            return Err(bad());
        }
        Ok(Self {
            partition: parts[1].to_string(),
            account: parts[4].to_string(),
            region: parts[3].to_string(),
            name: name.to_string(),
        })
    }

    /// `logGroupArn`: the ARN without `:*`.
    pub fn arn(&self) -> String {
        format!("arn:{}:logs:{}:{}:log-group:{}", self.partition, self.region, self.account, self.name)
    }

    /// The resource CloudWatch Logs authorizes log group and log stream
    /// actions against: `...:log-group:NAME:log-stream:STREAM`, with an
    /// empty stream for actions on the group itself.
    pub fn resource(&self, stream: Option<&str>) -> String {
        format!("{}:log-stream:{}", self.arn(), stream.unwrap_or(""))
    }

    pub fn stream_arn(&self, stream: &str) -> String {
        self.resource(Some(stream))
    }
}

pub fn group_not_found() -> ServiceError {
    errors::resource_not_found("The specified log group does not exist.")
}

pub fn stream_not_found() -> ServiceError {
    errors::resource_not_found("The specified log stream does not exist.")
}

impl Region {
    pub fn group(&self, name: &str) -> Result<&LogGroup, ServiceError> {
        self.log_groups.get(name).ok_or_else(group_not_found)
    }

    pub fn group_mut(&mut self, name: &str) -> Result<&mut LogGroup, ServiceError> {
        self.log_groups.get_mut(name).ok_or_else(group_not_found)
    }
}

impl State {
    pub fn group(&self, g: &GroupRef) -> Result<&LogGroup, ServiceError> {
        self.region_ref(&g.account, &g.region).ok_or_else(group_not_found)?.group(&g.name)
    }

    pub fn group_mut(&mut self, g: &GroupRef) -> Result<&mut LogGroup, ServiceError> {
        self.region(&g.account, &g.region).group_mut(&g.name)
    }
}

/// One `{"Version": ..., "Statement": [...]}` document holding every
/// statement of `docs`.
pub fn merge_policies<'a>(docs: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let mut statements = Vec::new();
    for doc in docs {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(doc) else { continue };
        match v.get("Statement") {
            Some(serde_json::Value::Array(a)) => statements.extend(a.iter().cloned()),
            Some(s @ serde_json::Value::Object(_)) => statements.push(s.clone()),
            _ => {}
        }
    }
    (!statements.is_empty()).then(|| serde_json::json!({"Version": "2012-10-17", "Statement": statements}).to_string())
}

pub fn tag_conditions(tags: &BTreeMap<String, String>) -> ConditionContext {
    tags.iter().map(|(k, v)| (format!("aws:ResourceTag/{k}"), vec![v.clone()])).collect()
}

pub fn request_tag_conditions(tags: &BTreeMap<String, String>) -> ConditionContext {
    let mut c: ConditionContext = tags.iter().map(|(k, v)| (format!("aws:RequestTag/{k}"), vec![v.clone()])).collect();
    c.insert("aws:TagKeys".into(), tags.keys().cloned().collect());
    c
}

impl Logs {
    /// The resource policies that apply to a log group: the account's
    /// account-wide ones and any attached to the group.
    pub(crate) fn policies_for(&self, st: &State, g: &GroupRef) -> Option<String> {
        let region = st.region_ref(&g.account, &g.region)?;
        let arn = g.arn();
        merge_policies(
            region
                .resource_policies
                .values()
                .filter(|p| p.resource_arn.as_deref().is_none_or(|r| r.trim_end_matches(":*") == arn))
                .map(|p| p.document.as_str()),
        )
    }

    /// Authorize `logs:{action}` on a log group (or one of its streams),
    /// with its tags as `aws:ResourceTag` and its resource policies.
    pub(crate) fn authorize_group(
        &self,
        ctx: &RequestContext,
        action: &str,
        g: &GroupRef,
        stream: Option<&str>,
        mut extra: ConditionContext,
    ) -> Result<(), ServiceError> {
        let policy = {
            let st = self.lock();
            if let Ok(group) = st.group(g) {
                extra.extend(tag_conditions(&group.tags));
            }
            self.policies_for(&st, g)
        };
        ctx.authorize_with_resource_policy(&format!("logs:{action}"), &g.resource(stream), policy.as_deref(), extra)
    }

    /// Authorize `logs:{action}` on any other resource (or `*`).
    pub(crate) fn authorize(
        &self,
        ctx: &RequestContext,
        action: &str,
        resource: &str,
        extra: ConditionContext,
    ) -> Result<(), ServiceError> {
        ctx.authorize(&format!("logs:{action}"), resource, extra)
    }
}

// ---- pagination -------------------------------------------------------------

fn encode_token(offset: usize) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!("mws:{offset}"))
}

fn decode_token(token: &str) -> Option<usize> {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(token).ok()?;
    String::from_utf8(raw).ok()?.strip_prefix("mws:")?.parse().ok()
}

pub fn invalid_token() -> ServiceError {
    errors::invalid_parameter("The specified nextToken is invalid.")
}

/// One page of `items` starting at `token`, at most `limit` long, and the
/// token for the next page.
pub fn page<T>(items: Vec<T>, token: Option<&str>, limit: usize) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match token {
        Some(t) => decode_token(t).ok_or_else(invalid_token)?,
        None => 0,
    };
    if start > items.len() {
        return Err(invalid_token());
    }
    let limit = limit.max(1);
    let end = (start + limit).min(items.len());
    let next = (end < items.len()).then(|| encode_token(end));
    Ok((items.into_iter().skip(start).take(end - start).collect(), next))
}

pub fn random_hex(n: usize) -> String {
    use rand::Rng;
    let mut r = rand::thread_rng();
    (0..n).map(|_| char::from(b"0123456789abcdef"[r.gen_range(0..16)])).collect()
}

pub fn random_alnum(n: usize) -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut r = rand::thread_rng();
    (0..n).map(|_| char::from(CHARS[r.gen_range(0..CHARS.len())])).collect()
}

pub fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Tag keys and values as CloudWatch Logs validates them in `TagResource`.
pub fn check_tags(existing: usize, tags: &BTreeMap<String, String>) -> Result<(), ServiceError> {
    if existing + tags.len() > 50 {
        return Err(errors::too_many_tags("A resource can have no more than 50 tags."));
    }
    for k in tags.keys() {
        if k.starts_with("aws:") {
            return Err(errors::invalid_parameter("Tag keys prefixed with 'aws:' are reserved."));
        }
    }
    Ok(())
}

//! ARNs, the emulated clock, pagination tokens and tag condition keys.

use base64::Engine;
use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};

pub fn now(ctx: &RequestContext) -> DateTime<Utc> {
    ctx.received_at
}

pub fn alarm_arn(ctx: &RequestContext, name: &str) -> String {
    format!("arn:{}:cloudwatch:{}:{}:alarm:{name}", ctx.partition, ctx.region, ctx.caller.account_id)
}

pub fn dashboard_arn(ctx: &RequestContext, name: &str) -> String {
    format!("arn:{}:cloudwatch::{}:dashboard/{name}", ctx.partition, ctx.caller.account_id)
}

pub fn insight_rule_arn(ctx: &RequestContext, name: &str) -> String {
    format!("arn:{}:cloudwatch:{}:{}:insight-rule/{name}", ctx.partition, ctx.region, ctx.caller.account_id)
}

pub fn metric_stream_arn(ctx: &RequestContext, name: &str) -> String {
    format!("arn:{}:cloudwatch:{}:{}:metric-stream/{name}", ctx.partition, ctx.region, ctx.caller.account_id)
}

pub fn mute_rule_arn(ctx: &RequestContext, name: &str) -> String {
    format!("arn:{}:cloudwatch:{}:{}:alarm-mute-rule:{name}", ctx.partition, ctx.region, ctx.caller.account_id)
}

pub fn dataset_arn(ctx: &RequestContext, id: &str) -> String {
    format!("arn:{}:cloudwatch:{}:{}:dataset/{id}", ctx.partition, ctx.region, ctx.caller.account_id)
}

/// `cloudwatch:*` resources that are not tied to one resource.
pub fn any(_ctx: &RequestContext) -> String {
    "*".to_string()
}

/// `aws:RequestTag/*` and `aws:TagKeys` for tags a request sets.
pub fn request_tag_conditions(tags: &[types::Tag]) -> ConditionContext {
    let mut c = ConditionContext::new();
    let mut keys = Vec::new();
    for t in tags {
        c.insert(format!("aws:RequestTag/{}", t.key), vec![t.value.clone()]);
        keys.push(t.key.clone());
    }
    if !keys.is_empty() {
        c.insert("aws:TagKeys".into(), keys);
    }
    c
}

/// `aws:ResourceTag/*` for a resource's tags.
pub fn resource_tag_conditions(tags: Option<&std::collections::BTreeMap<String, String>>) -> ConditionContext {
    tags.into_iter().flatten().map(|(k, v)| (format!("aws:ResourceTag/{k}"), vec![v.clone()])).collect()
}

// ---- pagination -------------------------------------------------------------

fn encode_token(offset: usize) -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("mws-cloudwatch:{offset}"))
}

fn decode_token(token: &str) -> Option<usize> {
    let raw = base64::engine::general_purpose::STANDARD.decode(token).ok()?;
    String::from_utf8(raw).ok()?.strip_prefix("mws-cloudwatch:")?.parse().ok()
}

/// One page of `items` starting at `token`, and the token for the next.
pub fn page<T>(items: Vec<T>, token: Option<&str>, size: usize) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match token {
        None => 0,
        Some(t) => decode_token(t)
            .filter(|o| *o <= items.len())
            .ok_or_else(|| errors::invalid_next_token("The service returned an invalid next token."))?,
    };
    let size = size.max(1);
    let end = (start + size).min(items.len());
    let next = (end < items.len()).then(|| encode_token(end));
    Ok((items.into_iter().skip(start).take(end - start).collect(), next))
}

/// A Region's display name, as alarm notifications spell it.
pub fn region_display_name(region: &str) -> String {
    let name = match region {
        "us-east-1" => "US East (N. Virginia)",
        "us-east-2" => "US East (Ohio)",
        "us-west-1" => "US West (N. California)",
        "us-west-2" => "US West (Oregon)",
        "af-south-1" => "Africa (Cape Town)",
        "ap-east-1" => "Asia Pacific (Hong Kong)",
        "ap-south-1" => "Asia Pacific (Mumbai)",
        "ap-northeast-1" => "Asia Pacific (Tokyo)",
        "ap-northeast-2" => "Asia Pacific (Seoul)",
        "ap-northeast-3" => "Asia Pacific (Osaka)",
        "ap-southeast-1" => "Asia Pacific (Singapore)",
        "ap-southeast-2" => "Asia Pacific (Sydney)",
        "ca-central-1" => "Canada (Central)",
        "eu-central-1" => "EU (Frankfurt)",
        "eu-west-1" => "EU (Ireland)",
        "eu-west-2" => "EU (London)",
        "eu-west-3" => "EU (Paris)",
        "eu-north-1" => "EU (Stockholm)",
        "eu-south-1" => "EU (Milan)",
        "me-south-1" => "Middle East (Bahrain)",
        "sa-east-1" => "South America (Sao Paulo)",
        other => other,
    };
    name.to_string()
}

/// ISO 8601 with milliseconds and a `+0000` offset, as alarm history and
/// notifications write times.
pub fn history_time(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.3f+0000").to_string()
}

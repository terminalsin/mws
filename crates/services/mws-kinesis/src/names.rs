//! Stream and consumer ARNs, how requests name streams, the errors
//! Kinesis answers with, and authorization.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::errors;
use crate::state::{State, Stream};

pub fn now_ms(ctx: &RequestContext) -> i64 {
    ctx.received_at.timestamp_millis()
}

pub fn stream_arn(partition: &str, region: &str, account: &str, name: &str) -> String {
    format!("arn:{partition}:kinesis:{region}:{account}:stream/{name}")
}

/// `(partition, region, account, resource)` of a Kinesis ARN.
pub fn split_arn(arn: &str) -> Option<(&str, &str, &str, &str)> {
    let mut p = arn.splitn(6, ':');
    let (Some("arn"), Some(partition), Some("kinesis"), Some(region), Some(account), Some(resource)) =
        (p.next(), p.next(), p.next(), p.next(), p.next(), p.next())
    else {
        return None;
    };
    Some((partition, region, account, resource))
}

pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 128 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}

pub fn invalid_argument(message: impl Into<String>) -> ServiceError {
    errors::invalid_argument(message)
}

pub fn stream_not_found(name: &str, account: &str) -> ServiceError {
    errors::resource_not_found(format!("Stream {name} under account {account} not found."))
}

pub fn not_active(s: &Stream) -> ServiceError {
    errors::resource_in_use(format!(
        "Stream {} under account {} not ACTIVE, instead in state {}",
        s.name, s.account, s.status
    ))
}

/// A stream a request names, by `StreamName` and/or `StreamARN`.
#[derive(Debug, Clone)]
pub struct StreamRef {
    pub arn: String,
    pub name: String,
    pub account: String,
}

impl StreamRef {
    pub fn resolve(ctx: &RequestContext, name: Option<&str>, arn: Option<&str>) -> Result<Self, ServiceError> {
        match (name, arn) {
            (_, Some(arn)) => {
                let Some((_, _, account, resource)) = split_arn(arn) else {
                    return Err(invalid_argument(format!("Invalid StreamARN {arn}.")));
                };
                let Some(stream) = resource.strip_prefix("stream/").filter(|s| !s.contains('/')) else {
                    return Err(invalid_argument(format!("Invalid StreamARN {arn}.")));
                };
                if let Some(name) = name {
                    if name != stream {
                        return Err(invalid_argument(format!(
                            "StreamARN {arn} and StreamName {name} do not refer to the same stream."
                        )));
                    }
                }
                Ok(Self { arn: arn.to_string(), name: stream.to_string(), account: account.to_string() })
            }
            (Some(name), None) => {
                let account = ctx.caller.account_id.clone();
                Ok(Self {
                    arn: stream_arn(&ctx.partition, &ctx.region, &account, name),
                    name: name.to_string(),
                    account,
                })
            }
            (None, None) => Err(invalid_argument("Either StreamName or StreamARN should be provided.")),
        }
    }

    pub fn from_arn(arn: &str) -> Result<Self, ServiceError> {
        let Some((_, _, account, resource)) = split_arn(arn) else {
            return Err(invalid_argument(format!("Invalid StreamARN {arn}.")));
        };
        let Some(name) = resource.strip_prefix("stream/").filter(|s| !s.contains('/')) else {
            return Err(invalid_argument(format!("Invalid StreamARN {arn}.")));
        };
        Ok(Self { arn: arn.to_string(), name: name.to_string(), account: account.to_string() })
    }

    pub fn get<'a>(&self, st: &'a State) -> Result<&'a Stream, ServiceError> {
        st.streams.get(&self.arn).ok_or_else(|| stream_not_found(&self.name, &self.account))
    }

    pub fn get_mut<'a>(&self, st: &'a mut State) -> Result<&'a mut Stream, ServiceError> {
        st.streams.get_mut(&self.arn).ok_or_else(|| stream_not_found(&self.name, &self.account))
    }

    /// The stream, which must be `ACTIVE`.
    pub fn active_mut<'a>(&self, st: &'a mut State) -> Result<&'a mut Stream, ServiceError> {
        let s = self.get_mut(st)?;
        if s.status != "ACTIVE" {
            return Err(not_active(s));
        }
        Ok(s)
    }
}

/// `aws:ResourceTag/*` for a resource's tags.
pub fn tag_context(tags: &std::collections::BTreeMap<String, String>) -> ConditionContext {
    tags.iter().map(|(k, v)| (format!("aws:ResourceTag/{k}"), vec![v.clone()])).collect()
}

/// `aws:RequestTag/*` and `aws:TagKeys` for tags in a request.
pub fn request_tag_context(tags: &std::collections::BTreeMap<String, String>) -> ConditionContext {
    let mut c: ConditionContext = tags.iter().map(|(k, v)| (format!("aws:RequestTag/{k}"), vec![v.clone()])).collect();
    if !tags.is_empty() {
        c.insert("aws:TagKeys".into(), tags.keys().cloned().collect());
    }
    c
}

/// Kinesis answers denials with `AccessDeniedException` and status 400.
pub fn kinesis_denial(e: ServiceError) -> ServiceError {
    if e.code == "AccessDenied" {
        errors::access_denied(e.message)
    } else {
        e
    }
}

/// Authorize `action` on a resource with its policy (stream and consumer
/// resource policies grant cross-account access) and tags.
pub fn authorize(
    ctx: &RequestContext,
    action: &str,
    resource: &str,
    policy: Option<&str>,
    tags: &std::collections::BTreeMap<String, String>,
    mut extra: ConditionContext,
) -> Result<(), ServiceError> {
    extra.extend(tag_context(tags));
    let account = split_arn(resource).map(|(_, _, a, _)| a.to_string()).unwrap_or_default();
    extra.insert("aws:ResourceAccount".into(), vec![account]);
    ctx.authorize_with_resource_policy(action, resource, policy, extra).map_err(kinesis_denial)
}

/// Authorize `action` on a stream, as the request's caller.
pub fn authorize_stream(
    ctx: &RequestContext,
    st: &State,
    action: &str,
    r: &StreamRef,
    extra: ConditionContext,
) -> Result<(), ServiceError> {
    let (policy, tags) = match st.streams.get(&r.arn) {
        Some(s) => (s.policy.clone(), s.tags.clone()),
        None => (None, Default::default()),
    };
    authorize(ctx, &format!("kinesis:{action}"), &r.arn, policy.as_deref(), &tags, extra)
}

pub fn validate_tags(tags: &std::collections::BTreeMap<String, String>) -> Result<(), ServiceError> {
    for (k, v) in tags {
        if k.is_empty() || k.chars().count() > 128 {
            return Err(invalid_argument("Tag key must be between 1 and 128 characters long."));
        }
        if v.chars().count() > 256 {
            return Err(invalid_argument("Tag value must be between 0 and 256 characters long."));
        }
        if k.to_ascii_lowercase().starts_with("aws:") {
            return Err(invalid_argument("Tag keys may not start with the reserved prefix aws:."));
        }
    }
    Ok(())
}

//! Queue names, URLs and ARNs, receipt handles, the errors SQS answers
//! without a modeled shape, and authorization helpers.

use base64::Engine;
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, SERVICE_INFO};
use crate::state::{Queue, State};

pub fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

pub fn invalid_parameter_value(message: impl Into<String>) -> ServiceError {
    ServiceError::client("InvalidParameterValue", 400, message)
}

pub fn invalid_parameter(name: &str, value: impl std::fmt::Display, reason: &str) -> ServiceError {
    invalid_parameter_value(format!("Value {value} for parameter {name} is invalid. Reason: {reason}"))
}

pub fn missing_parameter(name: &str) -> ServiceError {
    ServiceError::client("MissingParameter", 400, format!("The request must contain the parameter {name}."))
}

pub fn queue_does_not_exist() -> ServiceError {
    errors::queue_does_not_exist("The specified queue does not exist.")
}

/// The code SDKs see for an error: the awsQuery code of a modeled error
/// (`AWS.SimpleQueueService.NonExistentQueue`), otherwise the code itself.
/// Batch result entries carry it.
pub fn wire_code(e: &ServiceError) -> String {
    SERVICE_INFO
        .query_compatible
        .and_then(|q| q.codes.iter().find(|(shape, _)| *shape == e.code).map(|(_, code)| code.to_string()))
        .unwrap_or_else(|| e.code.to_string())
}

pub fn now_ms(ctx: &RequestContext) -> i64 {
    ctx.received_at.timestamp_millis()
}

/// Standard queue names: 1-80 alphanumerics, hyphens and underscores; FIFO
/// queue names add the `.fifo` suffix within those 80.
pub fn valid_queue_name(name: &str, fifo: bool) -> bool {
    let stem = if fifo {
        match name.strip_suffix(".fifo") {
            Some(s) => s,
            None => return false,
        }
    } else {
        name
    };
    !stem.is_empty() && name.len() <= 80 && stem.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub fn queue_arn(partition: &str, region: &str, account: &str, name: &str) -> String {
    format!("arn:{partition}:sqs:{region}:{account}:{name}")
}

/// `(region, account, name)` of a queue ARN.
pub fn parse_queue_arn(arn: &str) -> Option<(&str, &str, &str)> {
    let mut parts = arn.splitn(6, ':');
    let (Some("arn"), Some(_), Some("sqs"), Some(region), Some(account), Some(name)) =
        (parts.next(), parts.next(), parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    Some((region, account, name))
}

/// The URL SQS hands out for a queue: this emulator's endpoint (or the
/// Regional SQS endpoint when not serving), then `/{account}/{name}`.
pub fn queue_url(ctx: &RequestContext, account: &str, name: &str) -> String {
    let base = ctx
        .endpoint
        .clone()
        .unwrap_or_else(|| format!("https://sqs.{}.amazonaws.com", ctx.region))
        .trim_end_matches('/')
        .to_string();
    format!("{base}/{account}/{name}")
}

/// `(account, name)` from a queue URL. Any host is accepted: SDKs send the
/// URL a queue was created with, whichever endpoint that was.
pub fn parse_queue_url(url: &str) -> Result<(String, String), ServiceError> {
    let invalid = || errors::invalid_address(format!("The address {url} is not valid for this endpoint."));
    let path = match url.find("://") {
        Some(i) => {
            let rest = &url[i + 3..];
            rest.find('/').map(|j| &rest[j..]).ok_or_else(invalid)?
        }
        None => url,
    };
    let path = path.split(['?', '#']).next().unwrap_or_default();
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match segments.as_slice() {
        [account, name] if account.len() == 12 && account.bytes().all(|b| b.is_ascii_digit()) => {
            Ok((account.to_string(), name.to_string()))
        }
        _ => Err(invalid()),
    }
}

impl State {
    pub fn queue(&self, arn: &str) -> Result<&Queue, ServiceError> {
        self.queues.get(arn).ok_or_else(queue_does_not_exist)
    }

    pub fn queue_mut(&mut self, arn: &str) -> Result<&mut Queue, ServiceError> {
        self.queues.get_mut(arn).ok_or_else(queue_does_not_exist)
    }
}

/// The ARN a queue URL addresses, in the request's Region.
pub fn arn_for_url(ctx: &RequestContext, url: &str) -> Result<String, ServiceError> {
    let (account, name) = parse_queue_url(url)?;
    Ok(queue_arn(&ctx.partition, &ctx.region, &account, &name))
}

/// `aws:ResourceTag/*` for a queue.
pub fn resource_tags(q: &Queue) -> ConditionContext {
    q.tags.iter().map(|(k, v)| (format!("aws:ResourceTag/{k}"), vec![v.clone()])).collect()
}

/// Authorize `action` on a queue: identity policies or the queue policy
/// may grant it.
pub fn authorize_queue(ctx: &RequestContext, action: &str, q: &Queue) -> Result<(), ServiceError> {
    authorize_queue_with(ctx, action, q, ConditionContext::new())
}

pub fn authorize_queue_with(
    ctx: &RequestContext,
    action: &str,
    q: &Queue,
    extra: ConditionContext,
) -> Result<(), ServiceError> {
    let mut context = resource_tags(q);
    context.extend(extra);
    ctx.authorize_with_resource_policy(action, &q.arn, q.policy(), context)
}

/// A receipt handle names the queue and message it was issued for, plus a
/// nonce, so each receive hands out a different one.
pub fn new_receipt_handle(queue_arn: &str, message_id: &str) -> String {
    let nonce: [u8; 24] = rand::random();
    let raw = format!("{queue_arn}\n{message_id}\n{}", hex::encode(nonce));
    b64().encode(raw)
}

/// `(queue ARN, message id)` of a receipt handle.
pub fn parse_receipt_handle(handle: &str) -> Result<(String, String), ServiceError> {
    let invalid = || {
        errors::receipt_handle_is_invalid(format!(
            "The input receipt handle \"{handle}\" is not a valid receipt handle."
        ))
    };
    let raw = b64().decode(handle).map_err(|_| invalid())?;
    let raw = String::from_utf8(raw).map_err(|_| invalid())?;
    let mut parts = raw.split('\n');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(arn), Some(id), Some(_), None) if arn.starts_with("arn:") => Ok((arn.to_string(), id.to_string())),
        _ => Err(invalid()),
    }
}

/// Batch entry ids: 1-80 alphanumerics, hyphens and underscores, distinct.
pub fn check_batch<'a>(entry_type: &str, ids: impl ExactSizeIterator<Item = &'a str>) -> Result<(), ServiceError> {
    if ids.len() == 0 {
        return Err(errors::empty_batch_request(format!("There should be at least one {entry_type} in the request.")));
    }
    if ids.len() > 10 {
        return Err(errors::too_many_entries_in_batch_request(format!(
            "Maximum number of entries per request are 10. You have sent {}.",
            ids.len()
        )));
    }
    let mut seen = std::collections::BTreeSet::new();
    for id in ids {
        let valid =
            !id.is_empty() && id.len() <= 80 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !valid {
            return Err(errors::invalid_batch_entry_id(
                "A batch entry id can only contain alphanumeric characters, hyphens and underscores. It can be at most 80 letters long.",
            ));
        }
        if !seen.insert(id) {
            return Err(errors::batch_entry_ids_not_distinct(format!("Id {id} repeated.")));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_and_handles_round_trip() {
        assert_eq!(
            parse_queue_url("http://127.0.0.1:4566/123456789012/jobs").unwrap(),
            ("123456789012".to_string(), "jobs".to_string())
        );
        assert_eq!(parse_queue_url("https://sqs.us-east-1.amazonaws.com/123456789012/a.fifo").unwrap().1, "a.fifo");
        assert!(parse_queue_url("http://localhost:4566/jobs").is_err());
        let h = new_receipt_handle("arn:aws:sqs:us-east-1:123456789012:q", "m-1");
        assert_eq!(parse_receipt_handle(&h).unwrap().1, "m-1");
        assert!(parse_receipt_handle("garbage").is_err());
        assert!(valid_queue_name("a-b_c", false));
        assert!(!valid_queue_name("a.fifo", false));
        assert!(valid_queue_name("a.fifo", true));
        assert!(!valid_queue_name(".fifo", true));
    }
}

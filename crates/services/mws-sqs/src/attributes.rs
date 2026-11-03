//! Queue attributes: defaults, validation of the settable ones, and the
//! read-only ones `GetQueueAttributes` computes.

use std::collections::BTreeMap;

use mws_core::ServiceError;
use mws_iam_policy::{Policy, PolicyKind};

use crate::generated::errors;
use crate::names::{invalid_parameter, parse_queue_arn};
use crate::state::{Queue, State};

/// Attributes every queue reports, with the values new queues get.
pub fn defaults(fifo: bool) -> BTreeMap<String, String> {
    let mut a: BTreeMap<String, String> = [
        ("DelaySeconds", "0"),
        ("MaximumMessageSize", "1048576"),
        ("MessageRetentionPeriod", "345600"),
        ("ReceiveMessageWaitTimeSeconds", "0"),
        ("VisibilityTimeout", "30"),
        ("SqsManagedSseEnabled", "true"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect();
    if fifo {
        for (k, v) in [
            ("FifoQueue", "true"),
            ("ContentBasedDeduplication", "false"),
            ("DeduplicationScope", "queue"),
            ("FifoThroughputLimit", "perQueue"),
        ] {
            a.insert(k.to_string(), v.to_string());
        }
    }
    a
}

const FIFO_ONLY: &[&str] = &["ContentBasedDeduplication", "DeduplicationScope", "FifoThroughputLimit"];

/// Attributes `GetQueueAttributes` computes.
pub const READ_ONLY: &[&str] = &[
    "ApproximateNumberOfMessages",
    "ApproximateNumberOfMessagesNotVisible",
    "ApproximateNumberOfMessagesDelayed",
    "CreatedTimestamp",
    "LastModifiedTimestamp",
    "QueueArn",
];

pub fn unknown_attribute(name: &str) -> ServiceError {
    errors::invalid_attribute_name(format!("Unknown Attribute {name}."))
}

fn invalid_value(name: &str) -> ServiceError {
    errors::invalid_attribute_value(format!("Invalid value for the parameter {name}."))
}

fn int_in(name: &str, value: &str, min: i64, max: i64) -> Result<String, ServiceError> {
    match value.trim().parse::<i64>() {
        Ok(n) if (min..=max).contains(&n) => Ok(n.to_string()),
        _ => Err(invalid_value(name)),
    }
}

fn boolean(name: &str, value: &str) -> Result<String, ServiceError> {
    match value.to_ascii_lowercase().as_str() {
        "true" => Ok("true".into()),
        "false" => Ok("false".into()),
        _ => Err(invalid_value(name)),
    }
}

/// Check one settable attribute and normalize its value. `creating` allows
/// `FifoQueue`, which only `CreateQueue` may set.
pub fn validate(name: &str, value: &str, fifo: bool, creating: bool) -> Result<String, ServiceError> {
    if FIFO_ONLY.contains(&name) && !fifo {
        return Err(unknown_attribute(name));
    }
    match name {
        "DelaySeconds" => int_in(name, value, 0, 900),
        "MaximumMessageSize" => int_in(name, value, 1024, 1_048_576),
        "MessageRetentionPeriod" => int_in(name, value, 60, 1_209_600),
        "ReceiveMessageWaitTimeSeconds" => int_in(name, value, 0, 20),
        "VisibilityTimeout" => int_in(name, value, 0, 43_200),
        "KmsDataKeyReusePeriodSeconds" => int_in(name, value, 60, 86_400),
        "KmsMasterKeyId" => Ok(value.to_string()),
        "SqsManagedSseEnabled" | "ContentBasedDeduplication" => boolean(name, value),
        "FifoQueue" if creating => boolean(name, value),
        "DeduplicationScope" => match value {
            "messageGroup" | "queue" => Ok(value.to_string()),
            _ => Err(invalid_value(name)),
        },
        "FifoThroughputLimit" => match value {
            "perQueue" | "perMessageGroupId" => Ok(value.to_string()),
            _ => Err(invalid_value(name)),
        },
        "Policy" => {
            if value.is_empty() {
                return Ok(String::new());
            }
            Policy::parse(value, PolicyKind::Resource).map_err(|_| invalid_value(name))?;
            Ok(value.to_string())
        }
        "RedrivePolicy" => redrive_policy(value),
        "RedriveAllowPolicy" => redrive_allow_policy(value),
        _ => Err(unknown_attribute(name)),
    }
}

fn redrive_policy(value: &str) -> Result<String, ServiceError> {
    if value.is_empty() {
        return Ok(String::new());
    }
    let bad = |reason: &str| invalid_parameter("RedrivePolicy", value, reason);
    let v: serde_json::Value =
        serde_json::from_str(value).map_err(|_| bad("Redrive policy is not a valid JSON map."))?;
    let obj = v.as_object().ok_or_else(|| bad("Redrive policy is not a valid JSON map."))?;
    for key in obj.keys() {
        if key != "deadLetterTargetArn" && key != "maxReceiveCount" {
            return Err(bad(&format!(
                "Only following attributes are supported: [deadLetterTargetArn, maxReceiveCount], but {key} was found."
            )));
        }
    }
    let arn = obj
        .get("deadLetterTargetArn")
        .and_then(|a| a.as_str())
        .ok_or_else(|| bad("Redrive policy does not contain mandatory attribute: deadLetterTargetArn."))?;
    let max = match obj.get("maxReceiveCount") {
        Some(serde_json::Value::Number(n)) => n.as_i64(),
        Some(serde_json::Value::String(s)) => s.parse().ok(),
        None => return Err(bad("Redrive policy does not contain mandatory attribute: maxReceiveCount.")),
        _ => None,
    };
    let max =
        max.ok_or_else(|| bad("Invalid value for maxReceiveCount, valid values are from 1 to 1000 both inclusive."))?;
    if !(1..=1000).contains(&max) {
        return Err(bad(&format!(
            "Invalid value for maxReceiveCount: {max}, valid values are from 1 to 1000 both inclusive."
        )));
    }
    if parse_queue_arn(arn).is_none() {
        return Err(bad("Invalid value for deadLetterTargetArn."));
    }
    Ok(serde_json::json!({ "deadLetterTargetArn": arn, "maxReceiveCount": max }).to_string())
}

fn redrive_allow_policy(value: &str) -> Result<String, ServiceError> {
    if value.is_empty() {
        return Ok(String::new());
    }
    let bad = |reason: &str| invalid_parameter("RedriveAllowPolicy", value, reason);
    let v: serde_json::Value =
        serde_json::from_str(value).map_err(|_| bad("Redrive allow policy is not a valid JSON map."))?;
    let obj = v.as_object().ok_or_else(|| bad("Redrive allow policy is not a valid JSON map."))?;
    let permission = obj
        .get("redrivePermission")
        .and_then(|p| p.as_str())
        .ok_or_else(|| bad("Redrive allow policy does not contain mandatory attribute: redrivePermission."))?;
    let sources = obj.get("sourceQueueArns");
    match permission {
        "allowAll" | "denyAll" => {
            if sources.is_some() {
                return Err(bad(&format!(
                    "Redrive allow policy can contain sourceQueueArns only when redrivePermission is byQueue, but {permission} was found."
                )));
            }
        }
        "byQueue" => {
            let arns = sources.and_then(|s| s.as_array()).filter(|a| !a.is_empty()).ok_or_else(|| {
                bad("Redrive allow policy must contain sourceQueueArns when redrivePermission is byQueue.")
            })?;
            if arns.len() > 10 {
                return Err(bad("Redrive allow policy can contain at most 10 sourceQueueArns."));
            }
            if arns.iter().any(|a| a.as_str().and_then(parse_queue_arn).is_none()) {
                return Err(bad("Invalid value for sourceQueueArns."));
            }
        }
        other => return Err(bad(&format!("Invalid value for redrivePermission: {other}."))),
    }
    Ok(value.to_string())
}

/// Checks that need other queues: the dead-letter target exists in the same
/// account and Region, has the same type, and lets this queue use it.
pub fn check_redrive_target(st: &State, source_arn: &str, fifo: bool, policy: &str) -> Result<(), ServiceError> {
    if policy.is_empty() {
        return Ok(());
    }
    let bad = |reason: &str| invalid_parameter("RedrivePolicy", policy, reason);
    let v: serde_json::Value = serde_json::from_str(policy).unwrap_or_default();
    let target = v["deadLetterTargetArn"].as_str().unwrap_or_default();
    let (Some((sr, sa, _)), Some((tr, ta, _))) = (parse_queue_arn(source_arn), parse_queue_arn(target)) else {
        return Err(bad("Dead letter target does not exist."));
    };
    if sr != tr || sa != ta {
        return Err(bad("Dead-letter target must be in the same account and Region as the source queue."));
    }
    let dlq = st.queues.get(target).ok_or_else(|| bad("Dead letter target does not exist."))?;
    if dlq.fifo != fifo {
        return Err(bad("Dead-letter queue must be same type of queue as the source."));
    }
    if !redrive_allowed(dlq, source_arn) {
        return Err(bad("Dead-letter target queue does not allow this queue to use it as a dead-letter queue."));
    }
    Ok(())
}

/// Whether the dead-letter queue's redrive allow policy admits `source`.
pub fn redrive_allowed(dlq: &Queue, source: &str) -> bool {
    let Some(policy) = dlq.attr("RedriveAllowPolicy").filter(|p| !p.is_empty()) else { return true };
    let v: serde_json::Value = serde_json::from_str(policy).unwrap_or_default();
    match v["redrivePermission"].as_str() {
        Some("denyAll") => false,
        Some("byQueue") => {
            v["sourceQueueArns"].as_array().is_some_and(|a| a.iter().any(|x| x.as_str() == Some(source)))
        }
        _ => true,
    }
}

/// The value of one attribute for `GetQueueAttributes`, if the queue has it.
pub fn get(q: &Queue, name: &str, now: i64) -> Option<String> {
    let (visible, in_flight, delayed) = q.counts(now);
    let v = match name {
        "ApproximateNumberOfMessages" => visible.to_string(),
        "ApproximateNumberOfMessagesNotVisible" => in_flight.to_string(),
        "ApproximateNumberOfMessagesDelayed" => delayed.to_string(),
        "CreatedTimestamp" => (q.created_at / 1000).to_string(),
        "LastModifiedTimestamp" => (q.last_modified_at / 1000).to_string(),
        "QueueArn" => q.arn.clone(),
        other => return q.attr(other).filter(|v| !v.is_empty()).map(str::to_string),
    };
    Some(v)
}

/// Every attribute name `GetQueueAttributes` accepts.
pub fn known(name: &str) -> bool {
    crate::generated::types::QUEUE_ATTRIBUTE_NAME.contains(&name)
}

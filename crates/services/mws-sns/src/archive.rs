//! FIFO message archiving and replay.
//!
//! A FIFO topic with an `ArchivePolicy` keeps every message published to it
//! for `MessageRetentionPeriod` days (against the emulated clock). Setting
//! a subscription's `ReplayPolicy` (on `Subscribe` or
//! `SetSubscriptionAttributes`) redelivers the archived messages published
//! between `StartingPoint` and `EndingPoint` to that subscription, through
//! its filter policy, with the original message id and timestamp and
//! `"Replayed": true` in the envelope. A policy with an `EndingPoint`
//! pauses the subscription: new messages are not delivered to it until a
//! policy without one is set. `ReplayStatus` reads `Completed` once the
//! replay has run (replays happen at once in MWS).
//!
//! Spec: <https://docs.aws.amazon.com/sns/latest/dg/message-archiving-and-replay-subscriber.html>

use chrono::{DateTime, Duration, Utc};
use mws_core::{RequestContext, ServiceError};
use serde_json::Value;

use crate::publish::Outgoing;
use crate::state::{Subscription, Topic};
use crate::{errors, filter, Sns};

/// The archive retention of a topic, if it archives.
fn retention(topic: &Topic) -> Option<Duration> {
    let doc: Value = serde_json::from_str(topic.attributes.get("ArchivePolicy")?).ok()?;
    let days = match doc.get("MessageRetentionPeriod")? {
        Value::String(s) => s.parse::<i64>().ok()?,
        Value::Number(n) => n.as_i64()?,
        _ => return None,
    };
    Some(Duration::days(days))
}

/// A parsed `ReplayPolicy`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Replay {
    pub start: DateTime<Utc>,
    pub end: Option<DateTime<Utc>>,
}

fn timestamp(v: &Value, what: &str) -> Result<DateTime<Utc>, ServiceError> {
    v.as_str()
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|t| t.with_timezone(&Utc))
        .ok_or_else(|| errors::invalid(format!("ReplayPolicy: {what} must be a valid ISO 8601 timestamp")))
}

/// Parse and check a `ReplayPolicy` document.
pub(crate) fn parse_replay_policy(value: &str) -> Result<Replay, ServiceError> {
    let doc: Value = serde_json::from_str(value).map_err(|_| errors::invalid("ReplayPolicy: failed to parse JSON."))?;
    if doc.get("PointType").and_then(Value::as_str) != Some("Timestamp") {
        return Err(errors::invalid("ReplayPolicy: PointType must be Timestamp"));
    }
    let start = timestamp(
        doc.get("StartingPoint").ok_or_else(|| errors::invalid("ReplayPolicy: StartingPoint is required"))?,
        "StartingPoint",
    )?;
    let end = doc.get("EndingPoint").map(|e| timestamp(e, "EndingPoint")).transpose()?;
    if end.is_some_and(|e| e <= start) {
        return Err(errors::invalid("ReplayPolicy: EndingPoint must be later than StartingPoint"));
    }
    Ok(Replay { start, end })
}

/// Whether a replay with an `EndingPoint` has paused the subscription.
pub(crate) fn paused(sub: &Subscription) -> bool {
    sub.attributes.get("ReplayPolicy").and_then(|p| parse_replay_policy(p).ok()).is_some_and(|r| r.end.is_some())
}

impl Topic {
    /// Start or stop archiving after the topic's attributes changed.
    pub(crate) fn sync_archive(&mut self, now: DateTime<Utc>) {
        if retention(self).is_some() {
            self.archive_since.get_or_insert(now);
        } else {
            self.archive_since = None;
            self.archive.clear();
        }
    }

    /// Keep a published message, dropping those past retention.
    pub(crate) fn archive_message(&mut self, msg: &Outgoing, now: DateTime<Utc>) {
        let Some(keep) = retention(self) else { return };
        self.archive.retain(|m| m.timestamp + keep > now);
        self.archive.push(msg.clone());
    }
}

impl Sns {
    /// Check that `topic_arn` archives, for a new `ReplayPolicy`.
    pub(crate) fn check_replay_target(topic: &Topic) -> Result<(), ServiceError> {
        if topic.archive_since.is_none() {
            return Err(errors::invalid("ReplayPolicy: Message archiving is not enabled on the topic"));
        }
        Ok(())
    }

    /// Replay archived messages to a subscription whose `ReplayPolicy` was
    /// just set.
    pub(crate) fn replay(&self, ctx: &RequestContext, subscription_arn: &str) {
        let (sub, topic) = {
            let mut st = self.lock();
            let Some(sub) = st.subscriptions.get(subscription_arn).cloned() else { return };
            let Some(topic) = st.topics.get_mut(&sub.topic_arn) else { return };
            if let Some(keep) = retention(topic) {
                topic.archive.retain(|m| m.timestamp + keep > ctx.received_at);
            }
            (sub, topic.clone())
        };
        let Some(replay) = sub.attributes.get("ReplayPolicy").and_then(|p| parse_replay_policy(p).ok()) else {
            return;
        };
        let messages: Vec<Outgoing> = topic
            .archive
            .iter()
            .filter(|m| m.timestamp >= replay.start && replay.end.is_none_or(|e| m.timestamp <= e))
            .cloned()
            .collect();
        for mut msg in messages {
            if let Some(policy) = sub.attributes.get("FilterPolicy").filter(|p| !p.is_empty()) {
                let body_scope = sub.attributes.get("FilterPolicyScope").is_some_and(|s| s == "MessageBody");
                let parsed: Value = serde_json::from_str(policy).unwrap_or(Value::Null);
                if !filter::matches(&parsed, body_scope, &msg.attributes, msg.message_for(&sub.protocol)) {
                    continue;
                }
            }
            msg.replayed = true;
            self.deliver_one(ctx, &topic, &sub, &msg);
        }
        if let Some(s) = self.lock().subscriptions.get_mut(subscription_arn) {
            s.attributes.insert("ReplayStatus".into(), "Completed".into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_policies() {
        let r = parse_replay_policy(
            r#"{"PointType":"Timestamp","StartingPoint":"2023-10-01T10:00:00.000Z","EndingPoint":"2023-10-01T12:00:00.000Z"}"#,
        )
        .unwrap();
        assert!(r.end.is_some());
        assert!(parse_replay_policy(r#"{"PointType":"Sequence","StartingPoint":"x"}"#).is_err());
        assert!(parse_replay_policy(r#"{"PointType":"Timestamp"}"#).is_err());
        assert!(parse_replay_policy(
            r#"{"PointType":"Timestamp","StartingPoint":"2023-10-01T12:00:00Z","EndingPoint":"2023-10-01T10:00:00Z"}"#
        )
        .is_err());
    }
}

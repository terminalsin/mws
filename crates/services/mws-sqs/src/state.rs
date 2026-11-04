//! SQS state: queues by ARN, each holding its messages, plus recently
//! deleted queue names and message move tasks. Times are epoch milliseconds
//! on the emulated clock.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::generated::types;

/// A message attribute (user or system) as stored.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Attr {
    pub data_type: String,
    pub string_value: Option<String>,
    pub binary_value: Option<Vec<u8>>,
}

impl From<&types::MessageAttributeValue> for Attr {
    fn from(v: &types::MessageAttributeValue) -> Self {
        Attr {
            data_type: v.data_type.clone(),
            string_value: v.string_value.clone(),
            binary_value: v.binary_value.clone(),
        }
    }
}

impl From<&types::MessageSystemAttributeValue> for Attr {
    fn from(v: &types::MessageSystemAttributeValue) -> Self {
        Attr {
            data_type: v.data_type.clone(),
            string_value: v.string_value.clone(),
            binary_value: v.binary_value.clone(),
        }
    }
}

impl Attr {
    pub fn to_wire(&self) -> types::MessageAttributeValue {
        types::MessageAttributeValue {
            data_type: self.data_type.clone(),
            string_value: self.string_value.clone(),
            binary_value: self.binary_value.clone(),
            ..Default::default()
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Message {
    pub id: String,
    pub body: String,
    pub attributes: BTreeMap<String, Attr>,
    /// `AWSTraceHeader`, the only system attribute senders may set.
    pub trace_header: Option<String>,
    pub md5_of_body: String,
    pub md5_of_system_attributes: Option<String>,
    pub sender_id: String,
    /// When it was first enqueued (`SentTimestamp`); retention counts
    /// from here, also after a move to a dead-letter queue.
    pub sent_at: i64,
    /// When retention starts counting, if not `sent_at`: FIFO queues
    /// reset it when a message moves to a dead-letter queue.
    pub enqueued_at: Option<i64>,
    /// Hidden until then: the send delay, then each visibility timeout.
    pub visible_at: i64,
    pub receive_count: u32,
    pub first_receive_at: Option<i64>,
    /// The handle of the latest receive; older handles no longer act.
    pub receipt_handle: Option<String>,
    pub group_id: Option<String>,
    pub deduplication_id: Option<String>,
    pub sequence_number: Option<String>,
    /// Set on messages a redrive policy moved here.
    pub dead_letter_source_arn: Option<String>,
    /// The SSE-KMS data key the message was encrypted under.
    pub kms_data_key: Option<String>,
}

impl Message {
    pub fn in_flight(&self, now: i64) -> bool {
        self.receipt_handle.is_some() && self.visible_at > now
    }

    pub fn delayed(&self, now: i64) -> bool {
        self.receipt_handle.is_none() && self.visible_at > now
    }

    pub fn visible(&self, now: i64) -> bool {
        self.visible_at <= now
    }
}

pub fn attributes_size(attrs: &BTreeMap<String, Attr>) -> usize {
    attrs
        .iter()
        .map(|(k, v)| {
            k.len()
                + v.data_type.len()
                + v.string_value.as_ref().map_or(0, String::len)
                + v.binary_value.as_ref().map_or(0, Vec::len)
        })
        .sum()
}

/// A FIFO deduplication record: a send with the same id within five
/// minutes is accepted but not enqueued again.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Dedup {
    pub message_id: String,
    pub sequence_number: String,
    pub at: i64,
}

/// A FIFO `ReceiveRequestAttemptId`: retries within five minutes get the
/// same messages back.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ReceiveAttempt {
    pub message_ids: Vec<String>,
    pub handles: Vec<String>,
    pub at: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DataKey {
    pub key_arn: String,
    pub ciphertext: String,
    pub generated_at: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Queue {
    pub name: String,
    pub arn: String,
    pub account: String,
    pub region: String,
    pub fifo: bool,
    pub created_at: i64,
    pub last_modified_at: i64,
    /// Settable attributes as given (normalized), by name.
    pub attributes: BTreeMap<String, String>,
    pub tags: BTreeMap<String, String>,
    /// In send order.
    pub messages: Vec<Message>,
    pub dedup: BTreeMap<String, Dedup>,
    pub receive_attempts: BTreeMap<String, ReceiveAttempt>,
    pub next_sequence: u64,
    pub last_purge_at: Option<i64>,
    /// SSE-KMS data keys in use, by the principal they were generated for.
    pub data_keys: BTreeMap<String, DataKey>,
}

impl Queue {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attributes.get(name).map(String::as_str)
    }

    pub fn int_attr(&self, name: &str) -> i64 {
        self.attr(name).and_then(|v| v.parse().ok()).unwrap_or(0)
    }

    pub fn bool_attr(&self, name: &str) -> bool {
        self.attr(name).is_some_and(|v| v.eq_ignore_ascii_case("true"))
    }

    pub fn policy(&self) -> Option<&str> {
        self.attr("Policy").filter(|p| !p.is_empty())
    }

    /// `(deadLetterTargetArn, maxReceiveCount)` of the redrive policy.
    pub fn redrive(&self) -> Option<(String, u32)> {
        let v: serde_json::Value = serde_json::from_str(self.attr("RedrivePolicy")?).ok()?;
        let arn = v.get("deadLetterTargetArn")?.as_str()?.to_string();
        let max = match v.get("maxReceiveCount")? {
            serde_json::Value::Number(n) => n.as_u64()?,
            serde_json::Value::String(s) => s.parse().ok()?,
            _ => return None,
        };
        Some((arn, max as u32))
    }

    /// Drop messages past the retention period and stale FIFO records.
    pub fn expire(&mut self, now: i64) {
        let retention = self.int_attr("MessageRetentionPeriod") * 1000;
        self.messages.retain(|m| m.enqueued_at.unwrap_or(m.sent_at) + retention > now);
        self.dedup.retain(|_, d| d.at + 300_000 > now);
        self.receive_attempts.retain(|_, a| a.at + 300_000 > now);
    }

    pub fn counts(&self, now: i64) -> (usize, usize, usize) {
        let mut visible = 0;
        let mut in_flight = 0;
        let mut delayed = 0;
        for m in &self.messages {
            if m.in_flight(now) {
                in_flight += 1;
            } else if m.delayed(now) {
                delayed += 1;
            } else {
                visible += 1;
            }
        }
        (visible, in_flight, delayed)
    }
}

/// A message move task (redrive out of a dead-letter queue).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct MoveTask {
    pub task_handle: String,
    pub source_arn: String,
    pub destination_arn: Option<String>,
    pub max_per_second: Option<i32>,
    /// `RUNNING`, `COMPLETED`, `CANCELLING`, `CANCELLED` or `FAILED`.
    pub status: String,
    pub moved: i64,
    pub to_move: i64,
    pub failure_reason: Option<String>,
    pub started_at: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// By queue ARN.
    pub queues: BTreeMap<String, Queue>,
    /// When queues were deleted, by ARN; the name is blocked for 60 s.
    pub deleted: BTreeMap<String, i64>,
    /// In start order.
    pub move_tasks: Vec<MoveTask>,
}

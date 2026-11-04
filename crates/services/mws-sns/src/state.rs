//! Everything SNS remembers. Resources are keyed by ARN, which carries the
//! account and region they live in.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::generated::types;
use crate::outbox::Outbox;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    pub topics: BTreeMap<String, Topic>,
    pub subscriptions: BTreeMap<String, Subscription>,
    pub applications: BTreeMap<String, PlatformApplication>,
    pub endpoints: BTreeMap<String, PlatformEndpoint>,
    /// SMS settings, opt-outs and sandbox numbers by account.
    pub sms: BTreeMap<String, SmsAccount>,
    /// Phone numbers that replied STOP.
    pub opted_out: BTreeSet<String>,
    pub outbox: Outbox,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Topic {
    pub arn: String,
    pub name: String,
    pub account: String,
    pub region: String,
    /// Attributes the caller set (or that were set at creation), including
    /// `Policy`.
    pub attributes: BTreeMap<String, String>,
    pub tags: Vec<types::Tag>,
    pub data_protection_policy: Option<String>,
    /// Last FIFO sequence number handed out.
    pub sequence: u64,
    /// FIFO deduplication ids seen in the last five minutes.
    pub dedup: BTreeMap<String, Dedup>,
    pub subscriptions_deleted: u64,
    /// When archiving started (`BeginningArchiveTime`), while the topic
    /// has an `ArchivePolicy`.
    pub archive_since: Option<chrono::DateTime<chrono::Utc>>,
    /// Archived messages, oldest first.
    pub archive: Vec<crate::publish::Outgoing>,
}

impl Topic {
    pub fn is_fifo(&self) -> bool {
        self.attributes.get("FifoTopic").is_some_and(|v| v.eq_ignore_ascii_case("true"))
    }

    pub fn policy(&self) -> Option<&str> {
        self.attributes.get("Policy").map(String::as_str)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Dedup {
    pub at_ms: i64,
    pub message_id: String,
    pub sequence_number: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Subscription {
    pub arn: String,
    pub topic_arn: String,
    /// The account that subscribed.
    pub owner: String,
    pub protocol: String,
    pub endpoint: String,
    pub attributes: BTreeMap<String, String>,
    pub pending: bool,
    /// The confirmation token sent to the endpoint, while pending.
    pub token: Option<String>,
    /// Whether the subscription was confirmed by a signed request, so that
    /// unsubscribing needs one too.
    pub authenticated: bool,
    /// When the confirmation token expires (three days after it was sent).
    pub token_expires_ms: i64,
    /// The principal that subscribed.
    pub principal: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PlatformApplication {
    pub arn: String,
    pub name: String,
    pub platform: String,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PlatformEndpoint {
    pub arn: String,
    pub application_arn: String,
    pub attributes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SmsAccount {
    pub attributes: BTreeMap<String, String>,
    pub sandbox_numbers: BTreeMap<String, SandboxNumber>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SandboxNumber {
    pub status: String,
    pub one_time_password: String,
    pub language_code: Option<String>,
}

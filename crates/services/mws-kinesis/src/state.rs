//! Kinesis state: streams with their shards and records, enhanced fan-out
//! consumers, channels and account settings. Times are epoch milliseconds
//! on the emulated clock.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// How long a stream or consumer stays `CREATING` (or `UPDATING`,
/// `DELETING`) before it settles, in milliseconds.
pub const TRANSITION_MS: i64 = 500;

/// Record payloads serialize as base64 in saved state.
pub mod b64 {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD.decode(s).map_err(serde::de::Error::custom)
    }
}

/// Hash keys are 128-bit; they serialize as decimal strings.
pub mod u128_str {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StoredRecord {
    /// Position within the shard; the sequence number encodes it.
    pub counter: u64,
    #[serde(with = "b64")]
    pub data: Vec<u8>,
    pub partition_key: String,
    pub arrival: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Shard {
    pub index: u32,
    pub parent: Option<u32>,
    pub adjacent_parent: Option<u32>,
    #[serde(with = "u128_str")]
    pub start_hash: u128,
    #[serde(with = "u128_str")]
    pub end_hash: u128,
    pub created_at: i64,
    /// Set once the shard was split, merged or rescaled away.
    pub closed_at: Option<i64>,
    /// The counter the next record gets.
    pub next_counter: u64,
    pub records: Vec<StoredRecord>,
}

impl Shard {
    pub fn id(&self) -> String {
        shard_id(self.index)
    }

    pub fn open(&self) -> bool {
        self.closed_at.is_none()
    }

    pub fn contains(&self, hash: u128) -> bool {
        self.start_hash <= hash && hash <= self.end_hash
    }
}

pub fn shard_id(index: u32) -> String {
    format!("shardId-{index:012}")
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Consumer {
    pub name: String,
    pub arn: String,
    pub stream_arn: String,
    pub created_at: i64,
    /// `CREATING`, `ACTIVE` or `DELETING`.
    pub status: String,
    pub settles_at: i64,
    pub policy: Option<String>,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Stream {
    pub name: String,
    pub arn: String,
    pub id: String,
    pub account: String,
    pub region: String,
    pub created_at: i64,
    /// `CREATING`, `ACTIVE`, `UPDATING` or `DELETING`.
    pub status: String,
    /// When the current transition ends.
    pub settles_at: i64,
    /// `PROVISIONED` or `ON_DEMAND`.
    pub mode: String,
    pub retention_hours: i32,
    pub shards: Vec<Shard>,
    pub next_shard_index: u32,
    /// Shards an `UpdateShardCount` is moving to, applied when it settles.
    pub pending_shard_count: Option<i32>,
    pub shard_level_metrics: Vec<String>,
    /// `NONE` or `KMS`.
    pub encryption_type: String,
    pub key_id: Option<String>,
    /// The KMS data key ciphertext puts were made under (decrypt checks
    /// use it).
    #[serde(with = "b64")]
    pub data_key: Vec<u8>,
    pub tags: BTreeMap<String, String>,
    pub policy: Option<String>,
    pub warm_throughput_mibps: Option<i32>,
    pub max_record_size_kib: i32,
    /// `USER_PARTITION_KEY` or `AUTO`.
    pub distribution: String,
    /// For `AUTO` distribution: the next shard round-robin picks.
    pub round_robin: u64,
    /// When the capacity mode changed (twice per 24 hours at most).
    pub mode_changes: Vec<i64>,
    /// When `UpdateShardCount` was called (ten per 24 hours at most).
    pub shard_count_updates: Vec<i64>,
}

impl Stream {
    pub fn open_shards(&self) -> impl Iterator<Item = &Shard> {
        self.shards.iter().filter(|s| s.open())
    }

    pub fn shard(&self, id: &str) -> Option<&Shard> {
        self.shards.iter().find(|s| s.id() == id)
    }

    pub fn shard_mut(&mut self, id: &str) -> Option<&mut Shard> {
        self.shards.iter_mut().find(|s| s.id() == id)
    }

    pub fn encrypted(&self) -> bool {
        self.encryption_type == "KMS"
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Channel {
    pub arn: String,
    pub account: String,
    pub region: String,
    pub created_at: i64,
    pub settles_at: i64,
    /// `CREATING`, `ACTIVE`, `UPDATING`, `DELETING`.
    pub status: String,
    /// The description as last stored, with the current status applied
    /// when read.
    pub description: crate::generated::types::ChannelDescription,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AccountSettings {
    /// `ENABLED`, `DISABLED` or `ENABLED_UNTIL_EARLIEST_ALLOWED_END`.
    pub commitment_status: Option<String>,
    pub started_at: Option<i64>,
    pub ended_at: Option<i64>,
    pub earliest_allowed_end_at: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// By stream ARN.
    pub streams: BTreeMap<String, Stream>,
    /// By consumer ARN.
    pub consumers: BTreeMap<String, Consumer>,
    /// By channel ARN.
    pub channels: BTreeMap<String, Channel>,
    /// By account.
    pub accounts: BTreeMap<String, AccountSettings>,
}

impl State {
    /// Finish the transitions that are due at `now`.
    pub fn settle(&mut self, now: i64) {
        let mut gone = Vec::new();
        for (arn, s) in self.streams.iter_mut() {
            if s.status == "ACTIVE" || s.settles_at > now {
                continue;
            }
            match s.status.as_str() {
                "DELETING" => gone.push(arn.clone()),
                "UPDATING" => {
                    if let Some(target) = s.pending_shard_count.take() {
                        crate::shards::rescale(s, target, s.settles_at);
                    }
                    s.status = "ACTIVE".into();
                }
                _ => s.status = "ACTIVE".into(),
            }
        }
        for arn in gone {
            self.streams.remove(&arn);
            self.consumers.retain(|_, c| c.stream_arn != arn);
        }
        self.consumers.retain(|_, c| !(c.status == "DELETING" && c.settles_at <= now));
        for c in self.consumers.values_mut() {
            if c.status == "CREATING" && c.settles_at <= now {
                c.status = "ACTIVE".into();
            }
        }
        self.channels.retain(|_, c| !(c.status == "DELETING" && c.settles_at <= now));
        for c in self.channels.values_mut() {
            if matches!(c.status.as_str(), "CREATING" | "UPDATING") && c.settles_at <= now {
                c.status = "ACTIVE".into();
            }
        }
        // Retention: records older than the stream's retention period go.
        for s in self.streams.values_mut() {
            let horizon = now - i64::from(s.retention_hours) * 3_600_000;
            for shard in &mut s.shards {
                let keep = shard.records.partition_point(|r| r.arrival < horizon);
                if keep > 0 {
                    shard.records.drain(..keep);
                }
            }
            // Closed shards disappear once their retention has passed.
            s.shards.retain(|sh| sh.closed_at.is_none_or(|c| c >= horizon));
        }
    }
}

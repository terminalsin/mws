//! Firehose state: delivery streams with their destinations (kept as the
//! configuration the caller gave, with updates merged in) and the records
//! buffered for delivery. Times are epoch milliseconds on the emulated
//! clock.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// How long a stream stays `CREATING` / `DELETING`, and encryption
/// `ENABLING` / `DISABLING`, in milliseconds.
pub const TRANSITION_MS: i64 = 500;

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

/// A record waiting in a destination's buffer.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Buffered {
    pub record_id: String,
    #[serde(with = "b64")]
    pub data: Vec<u8>,
    pub arrival: i64,
    /// For Kinesis sources: where the record came from.
    pub kinesis: Option<KinesisOrigin>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct KinesisOrigin {
    pub shard_id: String,
    pub partition_key: String,
    pub sequence_number: String,
    pub arrival: i64,
}

/// One destination: its kind (`extended_s3`, `http_endpoint`, ...) and its
/// configuration as JSON in the generated types' serde form.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Destination {
    pub id: String,
    pub kind: String,
    /// Created from `S3DestinationConfiguration` (described both ways).
    pub plain_s3: bool,
    pub config: serde_json::Value,
    pub buffer: Vec<Buffered>,
    /// When delivery of the current buffer first failed.
    pub failing_since: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Encryption {
    pub key_type: Option<String>,
    pub key_arn: Option<String>,
    /// `ENABLED`, `ENABLING`, `DISABLED`, `DISABLING`.
    pub status: String,
    pub settles_at: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DeliveryStream {
    pub name: String,
    pub arn: String,
    pub account: String,
    pub region: String,
    pub partition: String,
    /// `DirectPut`, `KinesisStreamAsSource`, `MSKAsSource`,
    /// `DatabaseAsSource`.
    pub kind: String,
    /// `CREATING`, `ACTIVE`, `DELETING`.
    pub status: String,
    pub settles_at: i64,
    pub version: u64,
    pub created_at: i64,
    pub updated_at: i64,
    /// The source configuration as given (`direct_put`, `kinesis`, ...).
    pub source: serde_json::Value,
    pub destinations: Vec<Destination>,
    pub encryption: Option<Encryption>,
    pub tags: BTreeMap<String, String>,
    /// For Kinesis sources: the next counter (as a sequence number) to
    /// read per shard id.
    pub kinesis_positions: BTreeMap<String, String>,
    /// Kinesis sources read from this time on.
    pub delivery_start: Option<i64>,
}

impl DeliveryStream {
    pub fn active(&self) -> bool {
        self.status == "ACTIVE"
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// By delivery stream ARN.
    pub streams: BTreeMap<String, DeliveryStream>,
}

impl State {
    pub fn settle(&mut self, now: i64) {
        self.streams.retain(|_, s| !(s.status == "DELETING" && s.settles_at <= now));
        for s in self.streams.values_mut() {
            if s.status == "CREATING" && s.settles_at <= now {
                s.status = "ACTIVE".into();
            }
            if let Some(e) = &mut s.encryption {
                if e.settles_at <= now {
                    match e.status.as_str() {
                        "ENABLING" => e.status = "ENABLED".into(),
                        "DISABLING" => e.status = "DISABLED".into(),
                        _ => {}
                    }
                }
            }
        }
    }
}

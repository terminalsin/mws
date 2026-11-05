//! What Metering has recorded.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// Every accepted metering record, oldest first.
    pub records: Vec<MeteringRecord>,
    /// MeterUsage `ClientToken`s and the record each produced.
    pub client_tokens: BTreeMap<String, String>,
    /// RegisterUsage calls.
    pub registrations: Vec<Registration>,
    /// The PKCS#8 RSA key RegisterUsage signs with (public key version 1),
    /// base64. Made on first use.
    pub signing_key: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Allocation {
    pub allocated_usage_quantity: i32,
    pub tags: Vec<(String, String)>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct MeteringRecord {
    pub metering_record_id: String,
    /// `MeterUsage` or `BatchMeterUsage`.
    pub operation: String,
    pub product_code: String,
    pub customer_identifier: Option<String>,
    #[serde(rename = "customerAWSAccountId")]
    pub customer_aws_account_id: String,
    pub license_arn: Option<String>,
    pub dimension: String,
    pub quantity: i32,
    /// The usage time as reported.
    pub timestamp: DateTime<Utc>,
    pub usage_allocations: Vec<Allocation>,
    /// The principal that reported it (the instance role session, task
    /// role, or the seller's SaaS identity).
    pub reported_by: String,
    pub client_token: Option<String>,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Registration {
    pub product_code: String,
    #[serde(rename = "customerAWSAccountId")]
    pub customer_aws_account_id: String,
    pub customer_identifier: Option<String>,
    pub nonce: Option<String>,
    pub registered_by: String,
    pub registered_at: DateTime<Utc>,
}

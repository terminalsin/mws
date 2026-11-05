//! Cost Explorer state: the cost and usage ledger and what users configured
//! over it. Times are epoch milliseconds on the emulated clock.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One line of cost and usage data: a usage amount and its cost over a
/// time span (normally one hour), with the dimensions Cost Explorer groups
/// and filters by.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct CostRecord {
    /// The account that pays (the organization's management account, or
    /// the usage account itself).
    pub payer: String,
    /// The usage (linked) account.
    pub account: String,
    pub start: i64,
    pub end: i64,
    /// Dimension values by Cost Explorer dimension name (`SERVICE`,
    /// `REGION`, `USAGE_TYPE`, `OPERATION`, `RECORD_TYPE`,
    /// `INSTANCE_TYPE`, `RESOURCE_ID`, ...). `LINKED_ACCOUNT` is
    /// [`CostRecord::account`].
    pub dimensions: BTreeMap<String, String>,
    pub tags: BTreeMap<String, String>,
    pub unit: String,
    pub usage_quantity: f64,
    pub normalized_usage_amount: f64,
    pub unblended_cost: f64,
    pub blended_cost: f64,
    pub amortized_cost: f64,
    pub net_unblended_cost: f64,
    pub net_amortized_cost: f64,
}

impl CostRecord {
    pub fn dimension(&self, name: &str) -> Option<&str> {
        match name {
            "LINKED_ACCOUNT" => Some(&self.account),
            "PAYER_ACCOUNT" => Some(&self.payer),
            _ => self.dimensions.get(name).map(String::as_str),
        }
    }

    pub fn metric(&self, metric: &str) -> f64 {
        match metric {
            "UsageQuantity" => self.usage_quantity,
            "NormalizedUsageAmount" => self.normalized_usage_amount,
            "BlendedCost" => self.blended_cost,
            "AmortizedCost" => self.amortized_cost,
            "NetUnblendedCost" => self.net_unblended_cost,
            "NetAmortizedCost" => self.net_amortized_cost,
            _ => self.unblended_cost,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CostCategory {
    pub arn: String,
    pub name: String,
    pub effective_start: String,
    pub effective_end: Option<String>,
    pub rule_version: String,
    /// The rules as given, in the generated types' serde form.
    pub rules: serde_json::Value,
    pub split_charge_rules: serde_json::Value,
    pub default_value: Option<String>,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Monitor {
    pub arn: String,
    /// The monitor as given (serde form of `AnomalyMonitor`).
    pub spec: serde_json::Value,
    pub created: String,
    pub updated: String,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Subscription {
    pub arn: String,
    /// The subscription as given (serde form of `AnomalySubscription`).
    pub spec: serde_json::Value,
    pub tags: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TagStatus {
    /// `Active` or `Inactive`.
    pub status: String,
    pub updated: i64,
    /// When the tag was last activated.
    pub activated: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Backfill {
    pub from: i64,
    pub requested: i64,
    pub completes: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Generation {
    pub id: String,
    pub started: i64,
    pub completes: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Analysis {
    pub id: String,
    pub started: i64,
    pub completes: i64,
    /// `CommitmentPurchaseAnalysisConfiguration` in serde form.
    pub config: serde_json::Value,
    /// `AnalysisDetails` in serde form, computed at the start.
    pub details: serde_json::Value,
}

/// What one payer account configured.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Account {
    pub cost_categories: BTreeMap<String, CostCategory>,
    pub monitors: BTreeMap<String, Monitor>,
    pub subscriptions: BTreeMap<String, Subscription>,
    /// Feedback by anomaly id.
    pub feedback: BTreeMap<String, String>,
    /// Anomalies already sent to immediate subscribers.
    pub notified: Vec<String>,
    pub tag_status: BTreeMap<String, TagStatus>,
    pub backfills: Vec<Backfill>,
    pub generations: Vec<Generation>,
    pub analyses: BTreeMap<String, Analysis>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// Seeded records.
    pub records: Vec<CostRecord>,
    /// Request charges MWS derived from API calls, aggregated by hour and
    /// line item.
    pub derived: BTreeMap<String, CostRecord>,
    pub accounts: BTreeMap<String, Account>,
}

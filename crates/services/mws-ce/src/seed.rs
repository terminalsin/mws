//! Seeding the ledger with cost and usage records.
//!
//! - `POST /_aws/ce/records` with `{"records": [...]}` adds records.
//! - `GET /_aws/ce/records[?account=...]` lists them.
//! - `DELETE /_aws/ce/records` removes the seeded ones.
//! - Scenario files call the `MwsPutCostRecords` operation with the same
//!   body.

use std::collections::BTreeMap;

use mws_core::{HttpRequest, HttpResponse, RequestContext, ServiceError};
use serde::{Deserialize, Serialize};

use crate::query::{parse_time, validation};
use crate::state::CostRecord;
use crate::CostExplorer;

pub const PREFIX: &str = "/_aws/ce/";
pub const SCENARIO_OPERATION: &str = "MwsPutCostRecords";

/// A record as tests write it. Only `account`, `start`, `service` and a
/// cost are needed; the other cost metrics default to the unblended cost.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct SeedRecord {
    pub account: String,
    /// `2026-10-01` or `2026-10-01T05:00:00Z`.
    pub start: String,
    /// Defaults to an hour after `start`.
    pub end: Option<String>,
    /// The Cost Explorer service name, e.g.
    /// `Amazon Elastic Compute Cloud - Compute`.
    pub service: String,
    pub region: Option<String>,
    pub usage_type: Option<String>,
    pub operation: Option<String>,
    /// `Usage` (default), `Credit`, `Refund`, `Tax`, ...
    pub record_type: Option<String>,
    pub instance_type: Option<String>,
    pub availability_zone: Option<String>,
    pub resource_id: Option<String>,
    pub purchase_type: Option<String>,
    pub unit: Option<String>,
    pub usage_quantity: Option<f64>,
    pub normalized_usage_amount: Option<f64>,
    /// Alias for `unblendedCost`.
    pub cost: Option<f64>,
    pub unblended_cost: Option<f64>,
    pub blended_cost: Option<f64>,
    pub amortized_cost: Option<f64>,
    pub net_unblended_cost: Option<f64>,
    pub net_amortized_cost: Option<f64>,
    pub tags: BTreeMap<String, String>,
    /// Any other dimension, by Cost Explorer name (`PLATFORM`,
    /// `DATABASE_ENGINE`, ...).
    pub dimensions: BTreeMap<String, String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct SeedBody {
    records: Vec<SeedRecord>,
}

impl SeedRecord {
    pub fn into_record(self) -> Result<CostRecord, ServiceError> {
        if self.account.len() != 12 || !self.account.bytes().all(|b| b.is_ascii_digit()) {
            return Err(validation(format!("Invalid account {:?}: records need a 12-digit account.", self.account)));
        }
        if self.service.is_empty() {
            return Err(validation("Records need a service."));
        }
        let start = parse_time(&self.start)?;
        let end = match &self.end {
            Some(e) => parse_time(e)?,
            None => start + chrono::Duration::hours(1),
        };
        if end <= start {
            return Err(validation("A record's end must be after its start."));
        }
        let mut dimensions = self.dimensions;
        let mut set = |k: &str, v: Option<String>| {
            if let Some(v) = v {
                dimensions.insert(k.to_string(), v);
            }
        };
        set("SERVICE", Some(self.service.clone()));
        set("SERVICE_CODE", crate::pricing::service_code(&self.service).map(str::to_string));
        set("REGION", Some(self.region.unwrap_or_else(|| "us-east-1".into())));
        set("USAGE_TYPE", self.usage_type);
        set("OPERATION", self.operation);
        set("RECORD_TYPE", Some(self.record_type.unwrap_or_else(|| "Usage".into())));
        set("INSTANCE_TYPE_FAMILY", self.instance_type.as_ref().and_then(|i| i.split('.').next()).map(str::to_string));
        set("INSTANCE_TYPE", self.instance_type);
        set("AZ", self.availability_zone);
        set("RESOURCE_ID", self.resource_id);
        set("PURCHASE_TYPE", self.purchase_type);
        let cost = self.unblended_cost.or(self.cost).unwrap_or(0.0);
        let quantity = self.usage_quantity.unwrap_or(0.0);
        Ok(CostRecord {
            payer: String::new(),
            account: self.account,
            start: start.timestamp_millis(),
            end: end.timestamp_millis(),
            dimensions,
            tags: self.tags,
            unit: self.unit.unwrap_or_else(|| "N/A".into()),
            usage_quantity: quantity,
            normalized_usage_amount: self.normalized_usage_amount.unwrap_or(quantity),
            unblended_cost: cost,
            blended_cost: self.blended_cost.unwrap_or(cost),
            amortized_cost: self.amortized_cost.unwrap_or(cost),
            net_unblended_cost: self.net_unblended_cost.unwrap_or(cost),
            net_amortized_cost: self.net_amortized_cost.or(self.amortized_cost).unwrap_or(cost),
        })
    }
}

fn json(status: u16, body: serde_json::Value) -> HttpResponse {
    http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(bytes::Bytes::from(body.to_string()))
        .expect("valid response")
}

impl CostExplorer {
    fn seed(&self, ctx: &RequestContext, body: SeedBody) -> Result<usize, ServiceError> {
        let records = body.records.into_iter().map(SeedRecord::into_record).collect::<Result<Vec<_>, _>>()?;
        let n = records.len();
        self.put_records(records);
        self.alert_new_anomalies(ctx);
        Ok(n)
    }

    pub(crate) fn seed_from_scenario(
        &self,
        ctx: &RequestContext,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        let body: SeedBody = serde_json::from_value(input).map_err(|e| validation(format!("Invalid records: {e}")))?;
        let n = self.seed(ctx, body)?;
        Ok(serde_json::json!({ "Added": n }))
    }

    pub(crate) fn serve_seed(&self, ctx: &RequestContext, request: &HttpRequest) -> HttpResponse {
        if request.uri().path().trim_end_matches('/') != "/_aws/ce/records" {
            return json(404, serde_json::json!({"message": "Not found. Use /_aws/ce/records."}));
        }
        match *request.method() {
            http::Method::POST => {
                let body: SeedBody = match serde_json::from_slice(request.body()) {
                    Ok(b) => b,
                    Err(e) => return json(400, serde_json::json!({"message": format!("Invalid records: {e}")})),
                };
                match self.seed(ctx, body) {
                    Ok(n) => json(200, serde_json::json!({ "added": n })),
                    Err(e) => json(400, serde_json::json!({"message": e.message})),
                }
            }
            http::Method::GET => {
                let account = request
                    .uri()
                    .query()
                    .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("account=")))
                    .map(str::to_string);
                let records: Vec<CostRecord> =
                    self.records().into_iter().filter(|r| account.as_ref().is_none_or(|a| &r.account == a)).collect();
                json(200, serde_json::json!({ "records": records }))
            }
            http::Method::DELETE => {
                self.lock().records.clear();
                json(200, serde_json::json!({}))
            }
            _ => json(405, serde_json::json!({"message": "Use GET, POST or DELETE."})),
        }
    }
}

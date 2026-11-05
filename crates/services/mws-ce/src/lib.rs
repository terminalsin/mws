//! AWS Cost Explorer for MWS.
//!
//! Cost Explorer reads a ledger of cost and usage records:
//!
//! - **Seeded** records, for tests that need a bill to look at: posted to
//!   `POST /_aws/ce/records` (no signature needed, like SNS's outbox), put
//!   by scenario files with the `MwsPutCostRecords` operation, or from Rust
//!   with [`CostExplorer::put_records`].
//! - **Derived** request charges: the gateway reports every API call
//!   ([`mws_core::RequestObserver`]) and calls AWS bills per request (KMS,
//!   Secrets Manager, SQS, SNS, Lambda, S3, CloudWatch, EventBridge,
//!   Kinesis, Cost Explorer itself) are charged at their public on-demand
//!   price, aggregated per hour.
//!
//! Over it: GetCostAndUsage (with resources, comparisons and drivers),
//! dimension/tag/cost category values, forecasts, cost categories with
//! rules, cost allocation tags with activation and backfills, anomaly
//! monitors whose anomalies are detected from the data (and sent to SNS
//! subscribers), reservation and Savings Plans coverage of the on-demand
//! usage, and commitment analyses. Consolidated billing follows
//! Organizations: a management account sees its member accounts' costs.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/ce_generated.rs"));
}

mod anomaly;
mod commitments;
mod costs;
mod handler;
mod pricing;
mod query;
mod seed;
mod settings;
mod state;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use mws_core::{ApiCall, HttpRequest, HttpResponse, RequestContext, RequestObserver, Service, ServiceError};

pub use seed::SeedRecord;
pub use state::CostRecord;

use state::State;

/// Who pays for an account and what it is called (Organizations).
pub trait AccountDirectory: Send + Sync {
    /// The organization's management account, when `account` is in one.
    fn payer(&self, account: &str) -> Option<String>;
    fn name(&self, account: &str) -> Option<String>;
}

/// Sends anomaly alerts to SNS topics, as `costalerts.amazonaws.com`.
pub trait AnomalyNotifier: Send + Sync {
    fn notify(&self, ctx: &RequestContext, alert: AnomalyAlert) -> Result<(), String>;
}

/// One anomaly alert for one SNS subscriber.
#[derive(Debug, Clone)]
pub struct AnomalyAlert {
    pub topic_arn: String,
    pub subject: String,
    /// The JSON alert body.
    pub message: String,
    /// The account that owns the subscription.
    pub account: String,
    /// The anomaly subscription, as `aws:SourceArn`.
    pub subscription_arn: String,
}

#[derive(Default)]
pub(crate) struct Inner {
    state: Mutex<State>,
    directory: OnceLock<Arc<dyn AccountDirectory>>,
    notifier: OnceLock<Arc<dyn AnomalyNotifier>>,
}

/// The Cost Explorer service. Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct CostExplorer {
    inner: Arc<Inner>,
}

impl CostExplorer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Organizations, for consolidated billing and account names.
    pub fn set_account_directory(&self, directory: Arc<dyn AccountDirectory>) {
        let _ = self.inner.directory.set(directory);
    }

    /// SNS, for immediate anomaly alerts.
    pub fn set_anomaly_notifier(&self, notifier: Arc<dyn AnomalyNotifier>) {
        let _ = self.inner.notifier.set(notifier);
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().expect("Cost Explorer state lock poisoned")
    }

    pub(crate) fn payer_of(&self, account: &str) -> String {
        self.inner.directory.get().and_then(|d| d.payer(account)).unwrap_or_else(|| account.to_string())
    }

    /// Account names for the accounts in `records`.
    pub(crate) fn names<'a>(&self, records: impl IntoIterator<Item = &'a CostRecord>) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for r in records {
            if !out.contains_key(&r.account) {
                let name =
                    self.inner.directory.get().and_then(|d| d.name(&r.account)).unwrap_or_else(|| r.account.clone());
                out.insert(r.account.clone(), name);
            }
        }
        out
    }

    /// Every record `account` may see: its own, and as a payer its
    /// organization's.
    pub(crate) fn visible(st: &State, account: &str) -> Vec<CostRecord> {
        st.records
            .iter()
            .chain(st.derived.values())
            .filter(|r| r.payer == account || r.account == account)
            .cloned()
            .collect()
    }

    /// Add records to the ledger. Each record's payer is the account's
    /// management account at the time.
    pub fn put_records(&self, mut records: Vec<CostRecord>) {
        for r in &mut records {
            if r.payer.is_empty() {
                r.payer = self.payer_of(&r.account);
            }
        }
        self.lock().records.extend(records);
    }

    /// Every record in the ledger, seeded and derived.
    pub fn records(&self) -> Vec<CostRecord> {
        let st = self.lock();
        st.records.iter().chain(st.derived.values()).cloned().collect()
    }
}

impl RequestObserver for CostExplorer {
    fn observe(&self, call: &ApiCall) {
        if call.account.is_empty() || !call.succeeded() {
            return;
        }
        let Some(charge) = pricing::charge(call) else { return };
        let payer = self.payer_of(&call.account);
        let hour = call.at.timestamp_millis() - call.at.timestamp_millis().rem_euclid(3_600_000);
        let key = format!(
            "{hour}|{}|{}|{}|{}|{}",
            call.account, call.region, charge.service, charge.usage_type, charge.operation
        );
        let mut st = self.lock();
        let r = st.derived.entry(key).or_insert_with(|| {
            let mut dimensions = BTreeMap::new();
            dimensions.insert("SERVICE".to_string(), charge.service.to_string());
            dimensions.insert("SERVICE_CODE".to_string(), charge.service_code.to_string());
            dimensions.insert("REGION".to_string(), call.region.clone());
            dimensions.insert("USAGE_TYPE".to_string(), charge.usage_type.clone());
            dimensions.insert("OPERATION".to_string(), charge.operation.clone());
            dimensions.insert("RECORD_TYPE".to_string(), "Usage".to_string());
            CostRecord {
                payer,
                account: call.account.clone(),
                start: hour,
                end: hour + 3_600_000,
                dimensions,
                unit: "Requests".into(),
                ..Default::default()
            }
        });
        r.usage_quantity += 1.0;
        r.normalized_usage_amount += 1.0;
        for v in [
            &mut r.unblended_cost,
            &mut r.blended_cost,
            &mut r.amortized_cost,
            &mut r.net_unblended_cost,
            &mut r.net_amortized_cost,
        ] {
            *v += charge.price;
        }
    }
}

#[async_trait::async_trait]
impl Service for CostExplorer {
    fn recognizes(&self, request: &HttpRequest) -> bool {
        mws_proto_json::targets(&generated::SERVICE_INFO, request) || request.uri().path().starts_with(seed::PREFIX)
    }

    fn signing_name(&self) -> &'static str {
        "ce"
    }

    fn accepts_unsigned(&self, request: &HttpRequest) -> bool {
        request.uri().path().starts_with(seed::PREFIX)
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        if request.uri().path().starts_with(seed::PREFIX) {
            return self.serve_seed(&ctx, &request);
        }
        generated::dispatch(self, &ctx, &request).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_json::error_response(&generated::SERVICE_INFO, request_id, error)
    }

    async fn invoke(
        &self,
        ctx: RequestContext,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        if operation == seed::SCENARIO_OPERATION {
            return self.seed_from_scenario(&ctx, input);
        }
        generated::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        let state = self.lock().clone();
        Some(serde_json::to_value(state).expect("Cost Explorer state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid Cost Explorer state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}

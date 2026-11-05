//! AWS Marketplace Metering Service for MWS.
//!
//! * `ResolveCustomer` turns a SaaS registration token into the buyer's
//!   customer identifier, account, license ARN and agreement id, for the
//!   seller that listed the product only.
//! * `BatchMeterUsage` takes a seller's SaaS usage records (by
//!   `CustomerIdentifier`, or `CustomerAWSAccountId` with an optional
//!   `LicenseArn`), checks dimensions, timestamps (24 hours back, and the
//!   billing month's 06:00 UTC cut-off) and allocations for the whole batch,
//!   and reports each record `Success`, `CustomerNotSubscribed` or
//!   `DuplicateRecord` (one record per customer, dimension and hour).
//! * `MeterUsage` takes hourly usage from software in the buyer's account
//!   (AMI or container products), once per reporting principal, dimension
//!   and hour, with `ClientToken` idempotency and `DryRun`.
//! * `RegisterUsage` checks a container buyer's subscription and answers a
//!   JWT signed with MWS's Marketplace key (PS256, public key version 1).
//!
//! Products, subscriptions and entitlements live in the Marketplace
//! catalog that `mws-marketplace-entitlement` owns and seeds. What Metering
//! accepted is readable, unsigned, at `/_aws/marketplace-metering/`
//! ([`control`]).
//!
//! Both Marketplace services sign as `aws-marketplace`; this one claims
//! requests whose `X-Amz-Target` names `AWSMPMeteringService`.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/metering_generated.rs"));
}

pub mod control;
mod handler;
mod signing;
pub mod state;

use std::sync::{Arc, Mutex, MutexGuard};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use mws_marketplace_entitlement::Entitlement;

use state::State;
pub use state::{MeteringRecord, Registration};

/// The Metering Service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct Metering {
    state: Arc<Mutex<State>>,
    catalog: Entitlement,
}

impl Metering {
    /// Metering reads products and subscriptions from `catalog`.
    pub fn new(catalog: Entitlement) -> Self {
        Self { state: Arc::default(), catalog }
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("Marketplace Metering state lock poisoned")
    }

    /// Every metering record accepted so far.
    pub fn records(&self) -> Vec<MeteringRecord> {
        self.lock().records.clone()
    }
}

#[async_trait::async_trait]
impl Service for Metering {
    fn signing_name(&self) -> &'static str {
        "aws-marketplace"
    }

    fn name(&self) -> &'static str {
        "marketplace-metering"
    }

    fn claims(&self, request: &HttpRequest) -> bool {
        mws_proto_json::targets(&generated::SERVICE_INFO, request)
    }

    fn recognizes(&self, request: &HttpRequest) -> bool {
        mws_proto_json::targets(&generated::SERVICE_INFO, request)
    }

    fn accepts_unsigned(&self, request: &HttpRequest) -> bool {
        request.uri().path().starts_with(control::PREFIX)
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        if let Some(response) = self.serve_control(&request) {
            return response;
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
        generated::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        let state = self.lock().clone();
        Some(serde_json::to_value(state).expect("Marketplace Metering state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State =
            serde_json::from_value(state).map_err(|e| format!("invalid Marketplace Metering state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}

//! AWS Private CA (ACM PCA) for MWS.
//!
//! Certificate authorities hold real private keys and issue real X.509
//! certificates: create a CA, fetch its CSR, issue its root certificate (or
//! have a parent CA sign it), import it, then issue and revoke end-entity
//! certificates. Every operation is authorized through IAM; CA resource
//! policies (`PutPolicy`) are evaluated as resource-based policies.
//!
//! CAs with revocation enabled publish CRLs and answer OCSP, and audit
//! reports can be generated. CRLs and audit reports are written into MWS's
//! S3 as the service principal `acm-pca.amazonaws.com`, so the bucket policy
//! must allow it, as in AWS.
//!
//! Certificate templates, including the API/CSR passthrough and blank
//! variants, decide which extensions come from the template, the request's
//! `ApiPassthrough` and the CSR. Time runs on MWS's emulated clock: CAs
//! expire, deleted CAs disappear after their restoration period, and CRLs
//! are regenerated before they lapse (see `lifecycle`). CAs belong to their
//! account and region.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/acmpca_generated.rs"));
}

mod acm;
mod audit;
mod der;
mod extensions;
mod handler;
mod lifecycle;
mod ops;
mod public;
mod publish;
mod revocation;
mod shared;
mod state;
mod x509;

use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

pub use acm::{AcmCaSummary, AcmIssued, AcmIssuer};
pub use generated::types::ApiPassthrough;
pub use shared::{CaInfo, CaPolicyListener, ServiceIssue, ServiceIssueError, ServiceIssued};
use state::State;

/// The Private CA service. Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct PrivateCa {
    state: Arc<Mutex<State>>,
    s3: Option<mws_s3::S3>,
    policy_listener: Arc<RwLock<Option<Arc<dyn CaPolicyListener>>>>,
}

impl PrivateCa {
    pub fn new() -> Self {
        Self::default()
    }

    /// Publish CRLs and audit reports into `s3` buckets.
    pub fn with_s3(mut self, s3: mws_s3::S3) -> Self {
        self.s3 = Some(s3);
        self
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("Private CA state lock poisoned")
    }
}

#[async_trait::async_trait]
impl Service for PrivateCa {
    fn recognizes(&self, request: &HttpRequest) -> bool {
        mws_proto_json::targets(&generated::SERVICE_INFO, request)
    }

    fn signing_name(&self) -> &'static str {
        "acm-pca"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        self.advance(ctx.received_at);
        if ctx.caller.kind == mws_core::CallerKind::Anonymous {
            if let Some(response) = self.public_response(&request, ctx.received_at) {
                return response;
            }
        }
        generated::dispatch(self, &ctx, &request).await
    }

    fn accepts_unsigned(&self, request: &HttpRequest) -> bool {
        self.is_public_request(request)
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
        self.advance(ctx.received_at);
        // Scenario steps (and other in-process callers) wait out the
        // settle window like an SDK waiter would, so a scenario can fetch
        // the CSR or certificate the step before it asked for.
        let mut ctx = ctx;
        let mut waited = chrono::Duration::zero();
        loop {
            match generated::invoke(self, &ctx, operation, input.clone()).await {
                Err(e) if e.code == "RequestInProgressException" && waited <= mws_core::settle::delay() => {
                    let step = chrono::Duration::milliseconds(50);
                    tokio::time::sleep(step.to_std().expect("positive")).await;
                    waited += step;
                    ctx.received_at += step;
                    self.advance(ctx.received_at);
                }
                r => return r,
            }
        }
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        let state = self.lock().clone();
        Some(serde_json::to_value(state).expect("Private CA state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid Private CA state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}

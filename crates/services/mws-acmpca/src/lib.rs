//! AWS Private CA (ACM PCA) for MWS.
//!
//! Certificate authorities hold real private keys and issue real X.509
//! certificates: create a CA, fetch its CSR, issue its root certificate (or
//! have a parent CA sign it), import it, then issue and revoke end-entity
//! certificates. Every operation is authorized through IAM; CA resource
//! policies (`PutPolicy`) are evaluated as resource-based policies.
//!
//! CAs with revocation enabled publish CRLs and answer OCSP, and audit
//! reports can be generated; see [`revocation`] and [`audit`] for where
//! MWS serves what ACM PCA would write to S3.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/acmpca_generated.rs"));
}

mod audit;
mod der;
mod handler;
mod ops;
mod public;
mod revocation;
mod state;
mod x509;

use std::sync::{Arc, Mutex, MutexGuard};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

use state::State;

/// The Private CA service. Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct PrivateCa {
    state: Arc<Mutex<State>>,
}

impl PrivateCa {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("Private CA state lock poisoned")
    }
}

#[async_trait::async_trait]
impl Service for PrivateCa {
    fn signing_name(&self) -> &'static str {
        "acm-pca"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        if ctx.caller.kind == mws_core::CallerKind::Anonymous {
            if let Some(response) = self.public_response(&request) {
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
}

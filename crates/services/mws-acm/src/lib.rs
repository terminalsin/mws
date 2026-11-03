//! AWS Certificate Manager for MWS.
//!
//! Certificates are real X.509 with real keys:
//!
//! * Public (Amazon-issued) certificates are signed by issuing CAs MWS makes
//!   for itself (`Amazon RSA 2048 M01` and friends under `MWS Root CA 1`).
//!   DNS validation is real: ACM hands out the CNAME record to create and
//!   issues the certificate once that record exists in a public hosted zone
//!   in MWS's Route 53. Email validation is approved through the link in
//!   the "validation email", which MWS logs (see [`approval`]).
//! * Private certificates are issued by MWS's Private CA with the
//!   requester's permissions, and renewed by ACM's service principal when
//!   the CA grants it (`CreatePermission`).
//! * Imported certificates are checked against their private key.
//! * Exports return the key encrypted under the passphrase (PKCS#8, PBES2).
//! * Managed ACME endpoints run a real RFC 8555 server under
//!   `/_acme/<endpoint id>/directory` (see [`acme_server`]): accounts
//!   register with external account binding credentials, and orders for
//!   prevalidated domains are issued by the same public CA.
//!
//! Validation, expiry, managed renewal and timeouts follow MWS's emulated
//! clock and happen when the account next calls ACM. Every operation is
//! authorized through IAM with ACM's condition keys and `aws:ResourceTag`.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/acm_generated.rs"));
}

mod acme;
pub mod acme_server;
pub mod approval;
mod certs;
mod common;
mod handler;
mod jws;
mod pki;
mod search;
mod state;
mod validation;

use std::sync::{Arc, Mutex, MutexGuard};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

use state::State;

/// The ACM service. Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct Acm {
    state: Arc<Mutex<State>>,
    pca: Option<mws_acmpca::PrivateCa>,
    route53: Option<mws_route53::Route53>,
    sts: Option<mws_sts::Sts>,
}

impl Acm {
    pub fn new() -> Self {
        Self::default()
    }

    /// Issue private certificates from this Private CA.
    pub fn with_private_ca(mut self, pca: mws_acmpca::PrivateCa) -> Self {
        self.pca = Some(pca);
        self
    }

    /// Validate domains against this Route 53's public hosted zones.
    pub fn with_route53(mut self, route53: mws_route53::Route53) -> Self {
        self.route53 = Some(route53);
        self
    }

    /// Assume the roles of ACME external account bindings through this STS.
    pub fn with_sts(mut self, sts: mws_sts::Sts) -> Self {
        self.sts = Some(sts);
        self
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("ACM state lock poisoned")
    }
}

#[async_trait::async_trait]
impl Service for Acm {
    fn signing_name(&self) -> &'static str {
        "acm"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        if ctx.caller.kind == mws_core::CallerKind::Anonymous {
            if acme_server::is_acme_request(&request) {
                return self.acme_http(&ctx, &request).await;
            }
            if approval::is_approval_request(&request) {
                return self.approval_http(&ctx, &request).await;
            }
        }
        generated::dispatch(self, &ctx, &request).await
    }

    fn accepts_unsigned(&self, request: &HttpRequest) -> bool {
        acme_server::is_acme_request(request) || approval::is_approval_request(request)
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
        Some(serde_json::to_value(state).expect("ACM state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid ACM state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}

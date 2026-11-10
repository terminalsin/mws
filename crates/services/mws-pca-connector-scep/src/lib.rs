//! AWS Private CA Connector for SCEP for MWS.
//!
//! A connector puts a real SCEP (RFC 8894) endpoint in front of a Private
//! CA the caller owns. Devices fetch the CA chain (`GetCACert`), its
//! capabilities (`GetCACaps`) and enroll (`PKIOperation`): they encrypt a
//! certificate request carrying a challenge password to the connector's
//! registration authority certificate, sign it, and get back a `CertRep`
//! with a certificate the CA issued.
//!
//! As in AWS, the connector issues as the service principal
//! `pca-connector-scep.amazonaws.com`, so the CA must be shared with it
//! through AWS RAM (or a CA policy allowing it, for the connector's
//! account). Without that access the connector fails with
//! `PRIVATECA_ACCESS_DENIED`. The SCEP endpoint is served at
//! `/_aws/pca-connector-scep/<connector id>` on MWS's own address.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/pca_connector_scep_generated.rs"));
}

mod cms;
mod der;
mod handler;
mod ops;
mod scep;
mod state;

use std::sync::{Arc, Mutex, MutexGuard};

use mws_acmpca::PrivateCa;
use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

use state::State;

/// The service principal connectors issue certificates as.
pub const SERVICE_PRINCIPAL: &str = "pca-connector-scep.amazonaws.com";

/// The Connector for SCEP service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct ScepConnector {
    state: Arc<Mutex<State>>,
    pca: PrivateCa,
}

impl ScepConnector {
    pub fn new(pca: PrivateCa) -> Self {
        Self { state: Arc::default(), pca }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("Connector for SCEP state lock poisoned")
    }
}

#[async_trait::async_trait]
impl Service for ScepConnector {
    fn recognizes(&self, request: &HttpRequest) -> bool {
        scep::is_scep_path(request.uri().path())
    }

    fn signing_name(&self) -> &'static str {
        "pca-connector-scep"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        self.advance(ctx.received_at);
        if scep::is_scep_path(request.uri().path()) {
            return self.serve_scep(&ctx, &request);
        }
        generated::dispatch(self, &ctx, &request).await
    }

    fn accepts_unsigned(&self, request: &HttpRequest) -> bool {
        scep::is_scep_path(request.uri().path())
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_restjson::error_response(&generated::SERVICE_INFO, request_id, error)
    }

    async fn invoke(
        &self,
        ctx: RequestContext,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        self.advance(ctx.received_at);
        generated::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        let state = self.lock().clone();
        Some(serde_json::to_value(state).expect("Connector for SCEP state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State =
            serde_json::from_value(state).map_err(|e| format!("invalid Connector for SCEP state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}

//! AWS Security Hub for MWS.
//!
//! Hubs are per account and Region. Findings are stored in the AWS
//! Security Finding Format (ASFF) exactly as imported, then shaped the way
//! Security Hub shapes them: product names, `aws/securityhub/*` product
//! fields, severity labels and normalized scores kept consistent, workflow
//! state, finding history and automation rules applied in order. Filters,
//! sorting, insights and their results are evaluated over the stored
//! findings. Standards, controls and their parameters come from a built-in
//! catalogue (see [`catalog`]); Security Hub does not evaluate resources
//! itself, so control findings only appear when something imports them.
//!
//! Accounts relate the way AWS relates them: administrators invite
//! members or, as an organization's delegated administrator (set through
//! Organizations, see [`OrganizationLink`]), add organization accounts
//! directly and apply central configuration policies. Administrators see
//! and update their members' findings, and a finding aggregator brings
//! findings from linked Regions into the aggregation Region.
//!
//! Every new or updated finding is published as a "Security Hub Findings -
//! Imported" event (see [`FindingEventSink`]); other services (GuardDuty)
//! send findings in with [`SecurityHub::import_findings_as_service`].
//!
//! The Security Hub V2 API (OCSF findings, resources, connectors) works on
//! the same findings, converted to OCSF.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/securityhub_generated.rs"));
}

mod automation;
pub mod catalog;
mod common;
mod config_policies;
mod connectors;
mod filters;
mod findings;
mod handler;
mod hub;
mod members;
mod ocsf;
mod standards;
mod state;
mod v2;

use std::sync::{Arc, OnceLock, RwLock, RwLockReadGuard, RwLockWriteGuard};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

use state::State;

pub use findings::ServiceImportResult;

/// An organization as Security Hub sees it.
#[derive(Debug, Clone)]
pub struct OrgInfo {
    pub id: String,
    pub management_account: String,
    pub accounts: Vec<OrgAccount>,
}

#[derive(Debug, Clone)]
pub struct OrgAccount {
    pub id: String,
    pub email: String,
    /// `o-.../r-.../ou-.../<account>/`.
    pub path: String,
    pub active: bool,
}

/// AWS Organizations, as Security Hub uses it for delegated
/// administration. Implementations must not call back into Security Hub.
pub trait OrganizationLink: Send + Sync {
    /// The organization `account` belongs to.
    fn organization(&self, account: &str) -> Option<OrgInfo>;
    /// Enable trusted access for `securityhub.amazonaws.com` and register
    /// `admin` as its delegated administrator, as `management` would.
    /// The error is the message to return.
    fn register_delegated_administrator(&self, management: &str, admin: &str) -> Result<(), String>;
    /// Remove `admin` as Security Hub's delegated administrator.
    fn deregister_delegated_administrator(&self, management: &str, admin: &str);
}

/// An event for the account's default EventBridge bus.
#[derive(Debug, Clone)]
pub struct FindingEvent {
    pub partition: String,
    pub account: String,
    pub region: String,
    /// `Security Hub Findings - Imported`.
    pub detail_type: String,
    pub resources: Vec<String>,
    pub detail: serde_json::Value,
    pub time: chrono::DateTime<chrono::Utc>,
}

/// Where Security Hub's EventBridge events go.
pub trait FindingEventSink: Send + Sync {
    fn finding_event(&self, ctx: &RequestContext, event: FindingEvent);
}

/// Where V2 export jobs write their files (S3, written as
/// `securityhub.amazonaws.com`). The error is the failure message.
pub trait ExportSink: Send + Sync {
    fn put_object(
        &self,
        ctx: &RequestContext,
        bucket: &str,
        key: &str,
        body: Vec<u8>,
        kms_key_arn: Option<&str>,
    ) -> Result<(), String>;
}

pub(crate) struct Inner {
    state: RwLock<State>,
    organizations: OnceLock<Arc<dyn OrganizationLink>>,
    events: OnceLock<Arc<dyn FindingEventSink>>,
    exports: OnceLock<Arc<dyn ExportSink>>,
}

/// The Security Hub service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct SecurityHub {
    inner: Arc<Inner>,
}

impl Default for SecurityHub {
    fn default() -> Self {
        Self::new()
    }
}

impl SecurityHub {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                state: RwLock::new(State::default()),
                organizations: OnceLock::new(),
                events: OnceLock::new(),
                exports: OnceLock::new(),
            }),
        }
    }

    /// Use Organizations for delegated administration and organization
    /// members.
    pub fn set_organizations(&self, link: Arc<dyn OrganizationLink>) {
        let _ = self.inner.organizations.set(link);
    }

    /// Publish findings events to EventBridge.
    pub fn set_event_sink(&self, sink: Arc<dyn FindingEventSink>) {
        let _ = self.inner.events.set(sink);
    }

    /// Write V2 export jobs to S3.
    pub fn set_export_sink(&self, sink: Arc<dyn ExportSink>) {
        let _ = self.inner.exports.set(sink);
    }

    pub(crate) fn organizations(&self) -> Option<&Arc<dyn OrganizationLink>> {
        self.inner.organizations.get()
    }

    pub(crate) fn read(&self) -> RwLockReadGuard<'_, State> {
        self.inner.state.read().expect("Security Hub state lock poisoned")
    }

    pub(crate) fn write(&self) -> RwLockWriteGuard<'_, State> {
        self.inner.state.write().expect("Security Hub state lock poisoned")
    }
}

#[async_trait::async_trait]
impl Service for SecurityHub {
    fn signing_name(&self) -> &'static str {
        "securityhub"
    }

    fn recognizes(&self, request: &HttpRequest) -> bool {
        // `/tags/{ResourceArn}` is shared with other REST services.
        !request.uri().path().starts_with("/tags/") && generated::operation_for(request).is_some()
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        generated::dispatch(self, &ctx, &request).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        // Security Hub's error bodies repeat the error code as `Code`.
        let mut error = error.clone();
        if error.json_auth_equivalent().is_none() && !error.fields.iter().any(|f| f.name == "Code") {
            let code =
                if error.code == "AccessDenied" { "AccessDeniedException".to_string() } else { error.code.to_string() };
            error = error.with_field("Code", mws_core::ErrorValue::String(code));
        }
        mws_proto_restjson::error_response(&generated::SERVICE_INFO, request_id, &error)
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
        Some(serde_json::to_value(&*self.read()).expect("Security Hub state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid Security Hub state: {e}"))?;
        *self.write() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.write() = State::default();
    }
}

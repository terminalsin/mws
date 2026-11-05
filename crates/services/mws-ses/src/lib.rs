//! Amazon Simple Email Service (v1 and v2) for MWS.
//!
//! Both APIs share one state, as in AWS: identities, templates and
//! configuration sets made through one are visible through the other. SES
//! v1 speaks awsQuery (`Action=SendEmail`), SES v2 restJson1 under
//! `/v2/email/`; both sign as `ses`, so the v2 API is a second gateway
//! service ([`SesV2`]) that claims its paths.
//!
//! * **Sending** runs every check SES makes (verified identities, the
//!   sandbox, sending authorization policies, suppression, quotas) and then
//!   keeps the message in an outbox tests read at `/_aws/ses` instead of
//!   handing it to a remote mail server. The mailbox simulator addresses
//!   (`success@`, `bounce@`, `complaint@`, `ooto@`,
//!   `suppressionlist@simulator.amazonses.com`) behave as in SES, and mail
//!   to an address this emulator receives for is delivered to it.
//! * **Events** from configuration sets go to their event destinations
//!   (SNS, EventBridge, Firehose, CloudWatch), and identity notifications
//!   to their SNS topics.
//! * **Receiving**: active receipt rule sets act on mail arriving over SMTP
//!   ([`serve_smtp`]) or through `POST /_aws/ses/inbound`, writing to S3,
//!   invoking Lambda functions, publishing to SNS, bouncing, adding headers
//!   and stopping as configured. The same SMTP listener accepts
//!   authenticated submissions with SES SMTP credentials.
//!
//! AWS couples SES to S3, SNS, Lambda, EventBridge, Firehose, CloudWatch
//! and Route 53 (domain verification); those calls go through [`Links`],
//! implemented where the services are composed.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/ses_generated.rs"));
}

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod v2 {
    include!(concat!(env!("OUT_DIR"), "/sesv2_generated.rs"));
}

mod account;
mod config_sets;
mod contacts;
mod events;
mod handler;
mod identities;
mod mime;
mod misc;
mod names;
mod outbox;
mod public;
mod receipt;
mod receive;
mod send;
mod smtp;
mod state;
mod templates;

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use mws_core::{Authorizer, CredentialStore, HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

pub use public::{BusEvent, Links, Metric, NoLinks, S3Put, SERVICE_PRINCIPAL};
pub use smtp::{serve_smtp, smtp_password};
use state::State;

pub(crate) struct Inner {
    state: Mutex<State>,
    links: OnceLock<Arc<dyn Links>>,
    credentials: OnceLock<Vec<Arc<dyn CredentialStore>>>,
    /// The latest request (and its clock offset), for work that happens
    /// outside a request: mail arriving over SMTP.
    template: Mutex<Option<(RequestContext, chrono::Duration)>>,
    /// The authorizer for background work before any request arrived.
    authorizer: OnceLock<Arc<dyn Authorizer>>,
    auto_verify: bool,
}

/// The SES service (v1 API). Cheap to clone; clones share state.
#[derive(Clone)]
pub struct Ses {
    inner: Arc<Inner>,
}

impl Default for Ses {
    fn default() -> Self {
        Self::new()
    }
}

impl Ses {
    pub fn new() -> Self {
        Self::build(false)
    }

    /// Treat every identity as verified as soon as it is created, instead
    /// of waiting for a click on the verification link or DNS records
    /// (`MWS_SES_AUTO_VERIFY`). AWS never does this.
    pub fn with_auto_verify() -> Self {
        Self::build(true)
    }

    fn build(auto_verify: bool) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::default()),
                links: OnceLock::new(),
                credentials: OnceLock::new(),
                template: Mutex::new(None),
                authorizer: OnceLock::new(),
                auto_verify,
            }),
        }
    }

    /// The services SES reaches into (S3, SNS, Lambda, ...).
    pub fn set_links(&self, links: Arc<dyn Links>) {
        let _ = self.inner.links.set(links);
    }

    /// Where SMTP submissions look up the access keys SMTP credentials are
    /// derived from.
    pub fn set_credentials(&self, stores: Vec<Arc<dyn CredentialStore>>) {
        let _ = self.inner.credentials.set(stores);
    }

    /// The authorizer SMTP submissions use until a request has shown one.
    pub fn set_authorizer(&self, authorizer: Arc<dyn Authorizer>) {
        let _ = self.inner.authorizer.set(authorizer);
    }

    /// The v2 API over the same state.
    pub fn v2(&self) -> SesV2 {
        SesV2(self.clone())
    }

    pub(crate) fn links(&self) -> Arc<dyn Links> {
        self.inner.links.get().cloned().unwrap_or_else(|| Arc::new(NoLinks))
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().expect("SES state lock poisoned")
    }

    /// Remember `ctx` as the template for background work.
    pub(crate) fn observe(&self, ctx: &RequestContext) {
        let offset = ctx.received_at - chrono::Utc::now();
        *self.inner.template.lock().expect("SES template lock poisoned") = Some((ctx.clone(), offset));
    }

    /// A context for work outside a request, at the emulated time now,
    /// as the root of `account`.
    pub(crate) fn background_context(&self, account: &str, region: &str) -> RequestContext {
        let template = self.inner.template.lock().expect("SES template lock poisoned").clone();
        let (mut ctx, offset) = template.unwrap_or_else(|| {
            let authorizer = self.inner.authorizer.get().cloned().unwrap_or_else(|| Arc::new(mws_core::AllowAll));
            let ctx = RequestContext {
                request_id: String::new(),
                region: region.to_string(),
                partition: "aws".into(),
                received_at: chrono::Utc::now(),
                caller: mws_core::Caller {
                    account_id: account.to_string(),
                    arn: String::new(),
                    user_id: String::new(),
                    access_key_id: String::new(),
                    kind: mws_core::CallerKind::Root,
                    session: None,
                },
                source_ip: None,
                secure_transport: false,
                authorizer,
                endpoint: None,
            };
            (ctx, chrono::Duration::zero())
        });
        ctx.request_id = uuid::Uuid::new_v4().to_string();
        ctx.region = region.to_string();
        ctx.received_at = chrono::Utc::now() + offset;
        ctx.source_ip = None;
        ctx.caller = mws_core::Caller {
            account_id: account.to_string(),
            arn: format!("arn:{}:iam::{account}:root", ctx.partition),
            user_id: account.to_string(),
            access_key_id: String::new(),
            kind: mws_core::CallerKind::Root,
            session: None,
        };
        ctx
    }
}

#[async_trait::async_trait]
impl Service for Ses {
    fn signing_name(&self) -> &'static str {
        "ses"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        if let Some(response) = self.serve_side_channel(&ctx, &request).await {
            return response;
        }
        self.observe(&ctx);
        let params = mws_proto_query::read_params(&request);
        v1::dispatch(self, &ctx, &params).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_query::error_response(&v1::SERVICE_INFO, request_id, error)
    }

    /// MWS's outbox pages, and the verification links SES mails, work
    /// without a signature.
    fn accepts_unsigned(&self, request: &HttpRequest) -> bool {
        let path = request.uri().path();
        path.starts_with(outbox::PREFIX) || path == outbox::ROOT
    }

    async fn invoke(
        &self,
        ctx: RequestContext,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        v1::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        Some(serde_json::to_value(&*self.lock()).expect("SES state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid SES state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}

/// The SES v2 API (`/v2/email/...`), over the same state as [`Ses`].
#[derive(Clone)]
pub struct SesV2(pub Ses);

#[async_trait::async_trait]
impl Service for SesV2 {
    fn signing_name(&self) -> &'static str {
        "ses"
    }

    fn name(&self) -> &'static str {
        "sesv2"
    }

    fn claims(&self, request: &HttpRequest) -> bool {
        request.uri().path().starts_with("/v2/email")
    }

    fn recognizes(&self, request: &HttpRequest) -> bool {
        self.claims(request)
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        self.0.observe(&ctx);
        v2::dispatch(&self.0, &ctx, &request).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_restjson::error_response(&v2::SERVICE_INFO, request_id, error)
    }

    async fn invoke(
        &self,
        ctx: RequestContext,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        v2::invoke(&self.0, &ctx, operation, input).await
    }
}

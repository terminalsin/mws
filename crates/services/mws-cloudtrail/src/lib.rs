//! AWS CloudTrail for MWS.
//!
//! CloudTrail watches every API call the gateway hands to a service (it is
//! a [`mws_core::ApiCallObserver`]): each becomes a CloudTrail record with
//! the caller's `userIdentity`, the parameters and response elements the
//! generated dispatcher rendered, and the error, if any ([`record`]).
//! Management events go into the event history that `LookupEvents`
//! searches (90 days, per account and Region). Trails that are logging take
//! the events their (basic or advanced) selectors match ([`selectors`]) and
//! deliver them every second ([`deliver`]): gzipped log files in their S3
//! bucket (SSE-KMS when the trail names a key), signed digest files when
//! log file validation is on, SNS notifications, and CloudWatch Logs
//! through the trail's role. Write management events (and data events a
//! trail logs) go to the account's default EventBridge bus as "AWS API Call
//! via CloudTrail". Organization trails and event data stores collect the
//! organization's member accounts too.
//!
//! CloudTrail Lake event data stores keep the events their advanced
//! selectors match; `StartQuery` runs SQL over them ([`sql`]), and imports
//! read trail log files back from S3. Channels, dashboards, federation,
//! resource policies, event configuration and Insights selectors are kept
//! and validated; Insights events are not generated.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/cloudtrail_generated.rs"));
}

mod deliver;
mod handler;
mod lake;
mod lookup;
mod names;
pub mod record;
mod resources;
pub mod selectors;
pub mod sql;
mod state;
mod trails;

use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock};

use mws_core::trail::{ApiCall, HttpFacts};
use mws_core::{ApiCallObserver, HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

use state::State;

/// The CloudTrail service. Cheap to clone; clones share state.
#[derive(Clone, Default)]
pub struct CloudTrail {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    state: Mutex<State>,
    keys: Mutex<deliver::SigningKeys>,
    s3: OnceLock<mws_s3::S3>,
    logs: OnceLock<mws_logs::Logs>,
    sts: OnceLock<mws_sts::Sts>,
    kms: OnceLock<mws_kms::Kms>,
    sns: OnceLock<mws_sns::Sns>,
    events: OnceLock<mws_events::Events>,
    organizations: RwLock<Option<Arc<dyn mws_iam::OrganizationView>>>,
    /// A request context to act from in the background, and how far the
    /// emulated clock ran ahead of the wall clock when it was taken.
    template: Mutex<Option<(RequestContext, i64)>>,
    /// Events waiting for EventBridge.
    bus: Mutex<Vec<(RequestContext, mws_events::ServiceEvent)>>,
    started: OnceLock<()>,
}

impl CloudTrail {
    pub fn new() -> Self {
        Self::default()
    }

    /// Deliver log and digest files to S3 buckets.
    pub fn with_s3(self, s3: mws_s3::S3) -> Self {
        let _ = self.inner.s3.set(s3);
        self
    }

    /// Deliver to CloudWatch Logs.
    pub fn with_logs(self, logs: mws_logs::Logs) -> Self {
        let _ = self.inner.logs.set(logs);
        self
    }

    /// Assume trails' CloudWatch Logs roles and import roles.
    pub fn with_sts(self, sts: mws_sts::Sts) -> Self {
        let _ = self.inner.sts.set(sts);
        self
    }

    /// Encrypt log files with trails' KMS keys.
    pub fn with_kms(self, kms: mws_kms::Kms) -> Self {
        let _ = self.inner.kms.set(kms);
        self
    }

    /// Notify trails' SNS topics of new log files.
    pub fn with_sns(self, sns: mws_sns::Sns) -> Self {
        let _ = self.inner.sns.set(sns);
        self
    }

    /// Send "AWS API Call via CloudTrail" events to EventBridge.
    pub fn with_events(self, events: mws_events::Events) -> Self {
        let _ = self.inner.events.set(events);
        self
    }

    /// Organization trails and event data stores, and delegated
    /// administrators, need the organization.
    pub fn set_organizations(&self, view: Arc<dyn mws_iam::OrganizationView>) {
        *self.inner.organizations.write().expect("CloudTrail organizations lock poisoned") = Some(view);
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().expect("CloudTrail state lock poisoned")
    }

    fn organization(&self, account: &str) -> Option<mws_iam::AccountOrganization> {
        let view = self.inner.organizations.read().expect("CloudTrail organizations lock poisoned").clone()?;
        view.account(account)
    }

    /// The trails' delivery loop and EventBridge forwarding run in the
    /// background once the first call is observed.
    fn ensure_started(&self) {
        if self.inner.started.set(()).is_err() {
            return;
        }
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                me.tick();
            }
        });
    }

    /// One round of background work: deliver pending events.
    pub fn tick(&self) {
        let Some((template, offset)) = self.inner.template.lock().expect("template lock poisoned").clone() else {
            return;
        };
        let now = chrono::Utc::now() + chrono::Duration::milliseconds(offset);
        let ctx = RequestContext { received_at: now, ..template };
        let bus: Vec<_> = std::mem::take(&mut *self.inner.bus.lock().expect("bus lock poisoned"));
        if let Some(events) = self.inner.events.get() {
            for (ctx, e) in bus {
                events.put_service_event(&ctx, e);
            }
        }
        self.deliver_trails(&ctx);
    }
}

impl ApiCallObserver for CloudTrail {
    fn observe(&self, ctx: &RequestContext, call: &ApiCall, http: &HttpFacts) {
        let offset = (ctx.received_at - chrono::Utc::now()).num_milliseconds();
        *self.inner.template.lock().expect("template lock poisoned") = Some((ctx.clone(), offset.max(0)));
        if let Some(e) = record::build(ctx, call, http) {
            self.ingest(ctx, e);
        }
        self.ensure_started();
    }
}

#[async_trait::async_trait]
impl Service for CloudTrail {
    fn recognizes(&self, request: &HttpRequest) -> bool {
        mws_proto_json::targets(&generated::SERVICE_INFO, request)
    }

    fn signing_name(&self) -> &'static str {
        "cloudtrail"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
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
        let mut v = serde_json::to_value(state).expect("CloudTrail state serializes");
        v["signingKeys"] = serde_json::to_value(&*self.inner.keys.lock().expect("keys lock poisoned"))
            .expect("CloudTrail keys serialize");
        Some(v)
    }

    fn import_state(&self, mut state: serde_json::Value) -> Result<(), String> {
        let keys = state.as_object_mut().and_then(|m| m.remove("signingKeys")).unwrap_or_default();
        let keys: deliver::SigningKeys = if keys.is_null() {
            Default::default()
        } else {
            serde_json::from_value(keys).map_err(|e| format!("invalid CloudTrail keys: {e}"))?
        };
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid CloudTrail state: {e}"))?;
        *self.lock() = state;
        *self.inner.keys.lock().expect("keys lock poisoned") = keys;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
        self.inner.bus.lock().expect("bus lock poisoned").clear();
    }
}

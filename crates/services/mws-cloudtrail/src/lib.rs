//! AWS CloudTrail for MWS.
//!
//! CloudTrail watches every API call the gateway hands to a service (it is
//! a [`mws_core::ApiCallObserver`]): each becomes a CloudTrail record with
//! the caller's `userIdentity`, the parameters and response elements the
//! generated dispatcher rendered, and the error, if any ([`record`]).
//! Management events go into the event history that `LookupEvents`
//! searches (90 days, per account and Region). Trails that are logging take
//! the events their (basic or advanced) selectors match ([`selectors`]) and
//! deliver them in batches on the emulated clock, as AWS does
//! ([`deliver`]): a gzipped log file in their S3 bucket (SSE-KMS when the
//! trail names a key) and its SNS notification about every five minutes,
//! CloudWatch Logs through the trail's role about every minute, and signed
//! hourly digest files when log file validation is on. Write management events (and data events a
//! trail logs) go to the account's default EventBridge bus as "AWS API Call
//! via CloudTrail". Organization trails and event data stores collect the
//! organization's member accounts too.
//!
//! CloudTrail Lake event data stores keep the events their advanced
//! selectors match; `StartQuery` queues SQL that runs over them in the
//! background (`QUEUED`, `RUNNING`, then `FINISHED` within about a
//! second, [`sql`]), and imports
//! read trail log files back from S3. Channels, dashboards, federation,
//! resource policies, event configuration and Insights selectors are kept
//! and validated; Insights events are not generated.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/cloudtrail_generated.rs"));
}

mod audit;
mod deliver;
mod handler;
mod insights;
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

pub use audit::{AuditError, AuditEvent, AuditResult};
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
    /// Who else wants every event as it is recorded.
    subscribers: RwLock<Vec<Arc<dyn EventSubscriber>>>,
}

/// Something that wants every CloudTrail event as it is recorded, such as
/// GuardDuty, which analyses management events for threats. It is called
/// on the request's task after the event is in the event history, with no
/// CloudTrail lock held: do slow work elsewhere.
pub trait EventSubscriber: Send + Sync {
    fn on_event(&self, ctx: &RequestContext, event: &record::Recorded);
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

    /// Hand every recorded event to `subscriber` too.
    pub fn add_event_subscriber(&self, subscriber: Arc<dyn EventSubscriber>) {
        self.inner.subscribers.write().expect("CloudTrail subscribers lock poisoned").push(subscriber);
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

    /// One round of background work: Insights, EventBridge, Lake queries,
    /// and the trails' batches that are due.
    pub fn tick(&self) {
        let Some((template, offset)) = self.inner.template.lock().expect("template lock poisoned").clone() else {
            return;
        };
        let now = chrono::Utc::now() + chrono::Duration::milliseconds(offset);
        let ctx = RequestContext { received_at: now, ..template };
        self.evaluate_insights(&ctx);
        let bus: Vec<_> = std::mem::take(&mut *self.inner.bus.lock().expect("bus lock poisoned"));
        if let Some(events) = self.inner.events.get() {
            for (ctx, e) in bus {
                events.put_service_event(&ctx, e);
            }
        }
        self.progress_queries(&ctx.partition, None, now);
        self.deliver_trails(&ctx);
    }
}

impl ApiCallObserver for CloudTrail {
    fn observe(&self, ctx: &RequestContext, call: &ApiCall, http: &HttpFacts) {
        let offset = (ctx.received_at - chrono::Utc::now()).num_milliseconds();
        *self.inner.template.lock().expect("template lock poisoned") = Some((ctx.clone(), offset.max(0)));
        if let Some(e) = record::build(ctx, call, http) {
            let subscribers = self.inner.subscribers.read().expect("CloudTrail subscribers lock poisoned").clone();
            if subscribers.is_empty() {
                self.ingest(ctx, e);
            } else {
                self.ingest(ctx, e.clone());
                for s in &subscribers {
                    s.on_event(ctx, &e);
                }
            }
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

/// An event data store's stored events, as another service reads them
/// (CloudWatch Logs import tasks).
#[derive(Debug, Clone, Default)]
pub struct EventDataStoreData {
    /// `ENABLED`, `STOPPED_INGESTION`, `PENDING_DELETION`, ...
    pub status: String,
    pub kms_key_id: Option<String>,
    /// The event records, oldest first.
    pub events: Vec<serde_json::Value>,
}

impl CloudTrail {
    /// The events of the event data store with this ARN, read by an AWS
    /// service for the store's account; `None` when there is no such
    /// store. The caller authorizes the read.
    pub fn event_data_store_data(&self, arn: &str) -> Option<EventDataStoreData> {
        let account = arn.split(':').nth(4)?;
        let st = self.lock();
        let eds = st.accounts.get(account)?.event_data_stores.get(arn)?;
        Some(EventDataStoreData {
            status: eds.status.clone(),
            kms_key_id: eds.kms_key_id.clone(),
            events: eds.events.clone(),
        })
    }
}

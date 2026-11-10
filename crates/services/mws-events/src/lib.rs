//! Amazon EventBridge for MWS.
//!
//! Event buses (the default bus of every account and Region, custom buses
//! and partner event buses) take events from `PutEvents`,
//! `PutPartnerEvents`, other MWS services and schedules, match them against
//! their rules' event patterns with EventBridge's full pattern language (see
//! [`pattern`]), and deliver them to the rules' targets after applying
//! `Input`, `InputPath` or `InputTransformer` ([`transform`]):
//!
//! - Lambda functions, invoked asynchronously as `events.amazonaws.com`
//!   and allowed by the function's resource policy;
//! - CloudWatch Logs log groups, written as `events.amazonaws.com` and
//!   allowed by the account's Logs resource policies;
//! - other event buses, in the same or other accounts and Regions, through
//!   a target role or the receiving bus's policy;
//! - API destinations: real HTTP requests with the connection's basic,
//!   API key or OAuth client credentials authorization;
//! - services registered with [`Events::register_target_sink`] (SQS, SNS).
//!
//! Failed deliveries are retried with the target's retry policy and then
//! sent to its dead-letter queue. Archives keep the events that match
//! them, and replays send them back through the bus. Scheduled rules fire
//! on `rate()` and `cron()` expressions against the emulated clock. Every
//! call is authorized through IAM, with event bus policies as resource
//! policies.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/events_generated.rs"));
}

mod archives;
mod buses;
mod connections;
mod deliver;
mod endpoints;
mod handler;
mod http_client;
mod ingest;
mod names;
mod partners;
pub use mws_event_pattern as pattern;
mod public;
mod rules;
pub mod schedule;
mod state;
mod tags;
pub mod transform;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

pub use deliver::{TargetError, TargetInvocation, TargetSink};
pub use public::{ClockSource, HealthChecks, ServiceEvent};
use state::State;

pub(crate) struct Inner {
    state: Mutex<State>,
    logs: OnceLock<mws_logs::Logs>,
    sts: OnceLock<mws_sts::Sts>,
    sinks: RwLock<BTreeMap<String, Arc<dyn TargetSink>>>,
    clock_sources: RwLock<Vec<Arc<dyn ClockSource>>>,
    health_checks: OnceLock<Arc<dyn HealthChecks>>,
    /// The most recent request's context, for work that happens later
    /// (deliveries, schedules, replays): its authorizer and endpoint.
    template: Mutex<Option<RequestContext>>,
    /// Emulated clock minus wall clock, in milliseconds, as last seen.
    clock_offset_ms: AtomicI64,
    scheduler: AtomicBool,
    /// Where the `AWS/Events` metrics go.
    pub(crate) metrics: mws_core::metrics::MetricOutlet,
    /// Retries target deliveries on the emulated clock (the shared queue
    /// once wired in, else a private one).
    jobs: OnceLock<mws_core::ServiceClient>,
    /// The authorizer schedules and clock sources use before EventBridge
    /// has seen a request (after restoring saved state).
    authorizer: OnceLock<Arc<dyn mws_core::Authorizer>>,
}

/// The EventBridge service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct Events {
    inner: Arc<Inner>,
}

impl Default for Events {
    fn default() -> Self {
        Self::new()
    }
}

impl Events {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::default()),
                logs: OnceLock::new(),
                sts: OnceLock::new(),
                sinks: RwLock::new(BTreeMap::new()),
                clock_sources: RwLock::new(Vec::new()),
                health_checks: OnceLock::new(),
                template: Mutex::new(None),
                clock_offset_ms: AtomicI64::new(0),
                scheduler: AtomicBool::new(false),
                metrics: Default::default(),
                jobs: OnceLock::new(),
                authorizer: OnceLock::new(),
            }),
        }
    }

    /// CloudWatch Logs log groups as targets.
    pub fn with_logs(self, logs: mws_logs::Logs) -> Self {
        let _ = self.inner.logs.set(logs);
        self
    }

    /// Retry target deliveries through the shared delivery queue, so they
    /// follow the emulated clock and are kept in snapshots.
    pub fn set_service_client(&self, client: mws_core::ServiceClient) {
        client.register_retrier(deliver::RETRIER, Arc::new(self.clone()));
        let _ = self.inner.jobs.set(client);
    }

    pub(crate) fn jobs(&self) -> &mws_core::ServiceClient {
        self.inner.jobs.get_or_init(|| {
            let client = mws_core::ServiceClient::new();
            client.register_retrier(deliver::RETRIER, Arc::new(self.clone()));
            client
        })
    }

    /// STS, for targets that EventBridge reaches through a role.
    pub fn with_sts(self, sts: mws_sts::Sts) -> Self {
        let _ = self.inner.sts.set(sts);
        self
    }

    /// Deliver to targets whose ARN names `service` (`sqs`, `sns`, ...)
    /// through `sink`. Dead-letter queues go through the `sqs` sink.
    pub fn register_target_sink(&self, service: &str, sink: Arc<dyn TargetSink>) {
        self.inner.sinks.write().expect("sink lock poisoned").insert(service.to_string(), sink);
    }

    /// Let `source` put events on default buses as the emulated clock
    /// reaches them.
    pub fn register_clock_source(&self, source: Arc<dyn ClockSource>) {
        self.inner.clock_sources.write().expect("clock source lock poisoned").push(source);
    }

    /// Publish the `AWS/Events` metrics (`MatchedEvents`, `TriggeredRules`,
    /// `Invocations`, `FailedInvocations`, ...) through `publisher`.
    pub fn set_metric_publisher(&self, publisher: Arc<dyn mws_core::metrics::MetricPublisher>) {
        self.inner.metrics.connect(publisher);
    }

    /// Route global endpoints on these health checks.
    pub fn set_health_checks(&self, checks: Arc<dyn HealthChecks>) {
        let _ = self.inner.health_checks.set(checks);
    }

    pub(crate) fn health_checks(&self) -> Option<&Arc<dyn HealthChecks>> {
        self.inner.health_checks.get()
    }

    pub(crate) fn sink(&self, service: &str) -> Option<Arc<dyn TargetSink>> {
        self.inner.sinks.read().expect("sink lock poisoned").get(service).cloned()
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().expect("EventBridge state lock poisoned")
    }

    /// The emulated time now.
    pub(crate) fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now() + chrono::Duration::milliseconds(self.inner.clock_offset_ms.load(Ordering::Relaxed))
    }

    /// Remember the request's context for background work, and start the
    /// scheduler once there is a runtime to run it on.
    pub(crate) fn observe(&self, ctx: &RequestContext) {
        let offset = (ctx.received_at - chrono::Utc::now()).num_milliseconds();
        // Requests carry the emulated clock; small negative offsets are
        // just the time the request took to get here.
        self.inner.clock_offset_ms.store(if offset < 0 { 0 } else { offset }, Ordering::Relaxed);
        *self.inner.template.lock().expect("template lock poisoned") = Some(ctx.clone());
        self.start_scheduler();
    }

    /// Start the scheduler (scheduled rules, clock sources) once there is
    /// a runtime to run it on.
    fn start_scheduler(&self) {
        if tokio::runtime::Handle::try_current().is_ok() && !self.inner.scheduler.swap(true, Ordering::SeqCst) {
            let me = self.clone();
            tokio::spawn(async move { me.run_scheduler().await });
        }
    }

    /// The authorizer background work uses before EventBridge has seen a
    /// request, as after restoring saved state.
    pub fn set_authorizer(&self, authorizer: Arc<dyn mws_core::Authorizer>) {
        let _ = self.inner.authorizer.set(authorizer);
    }

    /// The last request's context, or (before any request) one made from
    /// the authorizer set with [`Events::set_authorizer`].
    pub(crate) fn template(&self) -> Option<RequestContext> {
        if let Some(t) = self.inner.template.lock().expect("template lock poisoned").clone() {
            return Some(t);
        }
        let authorizer = self.inner.authorizer.get()?.clone();
        Some(RequestContext {
            request_id: String::new(),
            region: String::new(),
            partition: "aws".into(),
            received_at: self.now(),
            caller: mws_core::Caller::anonymous(),
            source_ip: None,
            secure_transport: true,
            authorizer,
            endpoint: None,
        })
    }
}

#[async_trait::async_trait]
impl Service for Events {
    fn recognizes(&self, request: &HttpRequest) -> bool {
        mws_proto_json::targets(&generated::SERVICE_INFO, request)
    }

    fn signing_name(&self) -> &'static str {
        "events"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        self.observe(&ctx);
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
        self.observe(&ctx);
        generated::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        let state = self.lock().clone();
        Some(serde_json::to_value(state).expect("EventBridge state serializes"))
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid EventBridge state: {e}"))?;
        *self.lock() = state;
        // Schedules keep firing after a restart from saved state.
        self.start_scheduler();
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}

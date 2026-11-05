//! Amazon RDS (including Aurora) for MWS.
//!
//! The RDS API contract lives here: DB instances and their state machine,
//! Aurora and Multi-AZ DB clusters with their writer, readers and
//! endpoints, subnet, parameter and option groups, snapshots and restores,
//! events and event subscriptions, and tags. What actually runs a database
//! is a pluggable [`backend::DatabaseBackend`]: [`backend::DockerBackend`]
//! runs real PostgreSQL, MySQL and MariaDB containers you connect to at the
//! endpoint RDS reports, and [`backend::MetadataBackend`] runs nothing.
//!
//! Storage encryption uses KMS keys (`aws/rds` by default) through
//! [`mws_kms::Kms`], and `ManageMasterUserPassword` keeps the master
//! password in a Secrets Manager secret (`rds!db-...`) that RDS rotates.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/rds_generated.rs"));
}

pub mod backend;
mod catalog;
mod handler;
mod ops;
mod state;
mod util;

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use chrono::{DateTime, Utc};
use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use mws_kms::Kms;
use mws_secretsmanager::SecretsManager;

pub use backend::{BackendChoice, DatabaseBackend, DockerBackend, MetadataBackend};
use state::{RegionState, State};

/// A VPC subnet, as RDS reads it from EC2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subnet {
    pub subnet_id: String,
    pub vpc_id: String,
    pub availability_zone: String,
}

/// The caller's VPC networking, which MWS wires to EC2. Without it, RDS
/// accepts any subnet and security group id and places the default subnet
/// group in a stand-in default VPC.
pub trait Network: Send + Sync {
    /// The subnets among `ids` that exist.
    fn subnets(&self, ctx: &RequestContext, ids: &[String]) -> Vec<Subnet>;
    /// The default VPC's subnets.
    fn default_subnets(&self, ctx: &RequestContext) -> Vec<Subnet>;
    /// The VPC of a security group, if it exists.
    fn security_group_vpc(&self, ctx: &RequestContext, group_id: &str) -> Option<String>;
    /// A VPC's `default` security group.
    fn default_security_group(&self, ctx: &RequestContext, vpc_id: &str) -> Option<String>;
}

/// An RDS event, as RDS sends it to EventBridge and to event
/// subscriptions' SNS topics.
#[derive(Debug, Clone)]
pub struct RdsEvent {
    pub account: String,
    pub region: String,
    pub source_type: String,
    pub source_identifier: String,
    pub source_arn: String,
    pub categories: Vec<String>,
    pub message: String,
    pub event_id: String,
    pub time: DateTime<Utc>,
}

/// Where RDS events go, besides `DescribeEvents`. MWS wires this to
/// EventBridge and SNS.
pub trait EventSink: Send + Sync {
    /// Whether RDS may publish to `topic_arn` (`Err` carries the error
    /// code: `SNSTopicArnNotFound`, `SNSNoAuthorization` or
    /// `SNSInvalidTopic`).
    fn check_topic(&self, ctx: &RequestContext, topic_arn: &str) -> Result<(), String>;
    /// Publish an event subscription's notification.
    /// `source_arn` is the event's source (the topic policy's
    /// `aws:SourceArn`).
    fn notify_topic(&self, ctx: &RequestContext, topic_arn: &str, source_arn: &str, subject: &str, message: &str);
    /// Put the event on the account's default event bus.
    fn put_event(&self, ctx: &RequestContext, event: &RdsEvent);
}

pub(crate) struct Inner {
    state: Mutex<State>,
    backend: Arc<dyn DatabaseBackend>,
    kms: Kms,
    secrets: SecretsManager,
    network: OnceLock<Arc<dyn Network>>,
    events: OnceLock<Arc<dyn EventSink>>,
    /// Emulated clock minus wall clock, as last seen in a request.
    clock_offset: Mutex<chrono::Duration>,
}

/// The RDS service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct Rds {
    inner: Arc<Inner>,
}

impl Rds {
    pub fn new(backend: Arc<dyn DatabaseBackend>, kms: Kms, secrets: SecretsManager) -> Self {
        let rds = Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::default()),
                backend,
                kms,
                secrets: secrets.clone(),
                network: OnceLock::new(),
                events: OnceLock::new(),
                clock_offset: Mutex::new(chrono::Duration::zero()),
            }),
        };
        secrets.set_managed_rotation("rds", Arc::new(ops::secret::Rotator(rds.clone())));
        rds
    }

    /// Read VPC networking from EC2.
    pub fn set_network(&self, network: Arc<dyn Network>) {
        let _ = self.inner.network.set(network);
    }

    /// Send events to EventBridge and SNS.
    pub fn set_event_sink(&self, sink: Arc<dyn EventSink>) {
        let _ = self.inner.events.set(sink);
    }

    pub fn backend_name(&self) -> &'static str {
        self.inner.backend.name()
    }

    pub(crate) fn backend(&self) -> Arc<dyn DatabaseBackend> {
        self.inner.backend.clone()
    }

    pub(crate) fn kms(&self) -> &Kms {
        &self.inner.kms
    }

    pub(crate) fn secrets(&self) -> &SecretsManager {
        &self.inner.secrets
    }

    pub(crate) fn network(&self) -> Option<&Arc<dyn Network>> {
        self.inner.network.get()
    }

    pub(crate) fn event_sink(&self) -> Option<&Arc<dyn EventSink>> {
        self.inner.events.get()
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().expect("RDS state lock poisoned")
    }

    /// Remember how far the emulated clock is from the wall clock.
    fn observe(&self, ctx: &RequestContext) {
        *self.inner.clock_offset.lock().expect("clock lock") = ctx.received_at - Utc::now();
    }

    /// Now on the emulated clock (for background tasks).
    pub(crate) fn now(&self) -> DateTime<Utc> {
        Utc::now() + *self.inner.clock_offset.lock().expect("clock lock")
    }

    /// Run `f` on the caller's account and Region.
    pub(crate) fn with_region<R>(&self, ctx: &RequestContext, f: impl FnOnce(&mut RegionState) -> R) -> R {
        let mut state = self.lock();
        let r = state.regions.entry(State::key(&util::account_of(ctx), &ctx.region)).or_default();
        f(r)
    }

    pub(crate) fn with_region_of<R>(&self, account: &str, region: &str, f: impl FnOnce(&mut RegionState) -> R) -> R {
        let mut state = self.lock();
        let r = state.regions.entry(State::key(account, region)).or_default();
        f(r)
    }
}

#[async_trait::async_trait]
impl Service for Rds {
    fn signing_name(&self) -> &'static str {
        "rds"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        self.observe(&ctx);
        let params = mws_proto_query::read_params(&request);
        generated::dispatch(self, &ctx, &params).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_query::error_response(&generated::SERVICE_INFO, request_id, error)
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
        serde_json::to_value(&*self.lock()).ok()
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid RDS state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}

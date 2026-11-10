//! Amazon EC2 Auto Scaling for MWS.
//!
//! Groups launch, replace and terminate real MWS EC2 instances: this crate
//! depends on `mws-ec2`'s public API, the way Auto Scaling itself calls
//! EC2 with its service-linked role. A background loop on the emulated
//! clock keeps each group at its desired capacity, honouring suspended
//! processes, lifecycle hooks, health checks, scale-in protection,
//! termination policies, warm pools, scheduled actions and instance
//! refreshes.
//!
//! What Auto Scaling sends elsewhere goes through traits wired in the
//! `mws` crate: [`NotificationSink`] (SNS topics and SQS queues),
//! [`EventSink`] (EventBridge), [`MetricSink`] (group metrics to
//! CloudWatch), [`AlarmManager`] (target tracking alarms) and
//! [`TrafficSink`] (registering instances with load balancers).

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/autoscaling_generated.rs"));
}

mod ec2;
mod engine;
mod handler;
mod ops;
mod state;
mod util;

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use chrono::{DateTime, Duration, Utc};
use mws_core::{Caller, CallerKind, HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use mws_ec2::Ec2;

use state::{RegionState, State};

/// Delivers notifications (`PutNotificationConfiguration` topics and
/// lifecycle hook targets) as `autoscaling.amazonaws.com`.
pub trait NotificationSink: Send + Sync {
    /// Send `message` to `target_arn` (an SNS topic or SQS queue). `role_arn`
    /// is the role a lifecycle hook names for the delivery, if any.
    fn send(
        &self,
        ctx: &RequestContext,
        target_arn: &str,
        role_arn: Option<&str>,
        subject: Option<&str>,
        message: &str,
        source_arn: &str,
    ) -> Result<(), String>;
}

/// An event for EventBridge's default bus.
#[derive(Debug, Clone)]
pub struct AutoScalingEvent {
    pub account: String,
    pub region: String,
    pub detail_type: String,
    pub resources: Vec<String>,
    pub detail: serde_json::Value,
    pub time: DateTime<Utc>,
}

pub trait EventSink: Send + Sync {
    fn put(&self, ctx: &RequestContext, event: AutoScalingEvent);
}

/// One `AWS/AutoScaling` datapoint.
#[derive(Debug, Clone)]
pub struct GroupMetric {
    pub account: String,
    pub region: String,
    pub group: String,
    pub metric_name: String,
    pub value: f64,
    pub timestamp: DateTime<Utc>,
}

pub trait MetricSink: Send + Sync {
    fn publish(&self, metrics: Vec<GroupMetric>);
}

/// A CloudWatch metric alarm a target tracking policy owns.
#[derive(Debug, Clone)]
pub struct ManagedAlarm {
    pub name: String,
    pub description: String,
    pub namespace: String,
    pub metric_name: String,
    pub dimensions: Vec<(String, String)>,
    pub statistic: String,
    pub unit: Option<String>,
    pub period: i32,
    pub evaluation_periods: i32,
    pub datapoints_to_alarm: i32,
    pub threshold: f64,
    pub comparison_operator: String,
    pub alarm_actions: Vec<String>,
    /// A metric math alarm's queries (`CustomizedMetricSpecification.Metrics`);
    /// when set, the single-metric fields above are unused.
    pub metrics: Vec<AlarmQuery>,
}

/// One metric data query of a metric math alarm.
#[derive(Debug, Clone, Default)]
pub struct AlarmQuery {
    pub id: String,
    pub expression: Option<String>,
    pub label: Option<String>,
    pub return_data: Option<bool>,
    /// A metric query's metric: namespace, name, dimensions, statistic,
    /// unit and period.
    pub metric: Option<AlarmQueryMetric>,
}

#[derive(Debug, Clone, Default)]
pub struct AlarmQueryMetric {
    pub namespace: String,
    pub metric_name: String,
    pub dimensions: Vec<(String, String)>,
    pub stat: String,
    pub unit: Option<String>,
    pub period: i32,
}

/// Creates and deletes target tracking alarms in CloudWatch.
#[async_trait::async_trait]
pub trait AlarmManager: Send + Sync {
    /// Create or replace the alarm; returns its ARN.
    async fn put_alarm(&self, ctx: &RequestContext, alarm: &ManagedAlarm) -> Result<String, String>;
    async fn delete_alarms(&self, ctx: &RequestContext, names: &[String]);
}

/// Where a group's instances receive traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrafficTarget {
    /// A Classic Load Balancer, by name.
    ClassicLoadBalancer(String),
    /// An Elastic Load Balancing v2 target group, by ARN.
    TargetGroup(String),
    /// A VPC Lattice target group, by ARN.
    LatticeTargetGroup(String),
}

/// What Auto Scaling reads about a traffic source: enough to check an
/// attachment, to wait for deregistration (connection draining) and to
/// follow ELB health checks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrafficSourceInfo {
    pub vpc_id: Option<String>,
    /// Targets are instances (target type `instance`; always for a
    /// Classic Load Balancer).
    pub instance_targets: bool,
    /// A load balancer sends it traffic (so deregistration drains).
    pub in_use: bool,
    /// How long deregistration takes: the target group's deregistration
    /// delay, or the Classic Load Balancer's connection draining timeout.
    pub drain_seconds: i64,
    /// Registered instances failing their health checks (`unhealthy`, or
    /// `OutOfService` for a Classic Load Balancer).
    pub unhealthy: Vec<String>,
}

/// Registers group instances with load balancers (as Auto Scaling's
/// service-linked role), and reports on them.
pub trait TrafficSink: Send + Sync {
    fn register(&self, ctx: &RequestContext, target: &TrafficTarget, instance_ids: &[String]) -> Result<(), String>;
    fn deregister(&self, ctx: &RequestContext, target: &TrafficTarget, instance_ids: &[String]) -> Result<(), String>;
    /// The source in `account` and `region`; `None` when it does not exist.
    fn describe(&self, account: &str, region: &str, target: &TrafficTarget) -> Option<TrafficSourceInfo>;
}

/// A CloudWatch alarm action naming a scaling policy.
#[derive(Debug, Clone)]
pub struct AlarmTrigger {
    pub policy_arn: String,
    pub alarm_name: String,
    pub alarm_arn: String,
    pub account: String,
    pub region: String,
    /// The alarm threshold, and the latest metric value it saw.
    pub threshold: Option<f64>,
    pub metric_value: Option<f64>,
}

#[derive(Default)]
struct Links {
    notifications: OnceLock<Arc<dyn NotificationSink>>,
    events: OnceLock<Arc<dyn EventSink>>,
    metrics: OnceLock<Arc<dyn MetricSink>>,
    alarms: OnceLock<Arc<dyn AlarmManager>>,
    traffic: OnceLock<Arc<dyn TrafficSink>>,
}

pub(crate) struct Inner {
    state: Mutex<State>,
    ec2: Ec2,
    links: Links,
    clock_offset_ms: AtomicI64,
    template: Mutex<Option<RequestContext>>,
    scheduler: AtomicBool,
    /// Serializes reconciliation passes.
    reconciling: tokio::sync::Mutex<()>,
    /// Service Quotas: groups and launch configurations per Region.
    quotas: mws_servicequotas::QuotaLink,
}

/// The Auto Scaling service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct AutoScaling {
    inner: Arc<Inner>,
}

impl AutoScaling {
    pub fn new(ec2: Ec2) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::default()),
                ec2,
                links: Links::default(),
                clock_offset_ms: AtomicI64::new(0),
                template: Mutex::new(None),
                scheduler: AtomicBool::new(false),
                reconciling: tokio::sync::Mutex::new(()),
                quotas: Default::default(),
            }),
        }
    }

    /// Service Quotas, whose applied values limit groups and launch
    /// configurations.
    pub fn set_service_quotas(&self, quotas: mws_servicequotas::ServiceQuotas) {
        self.inner.quotas.set(quotas);
    }

    /// The applied value of an Auto Scaling quota for the caller.
    pub(crate) fn quota(&self, ctx: &RequestContext, code: &str) -> usize {
        self.inner.quotas.limit(&ctx.caller.account_id, &ctx.region, "autoscaling", code, ctx.received_at)
    }

    pub fn set_notification_sink(&self, sink: Arc<dyn NotificationSink>) {
        let _ = self.inner.links.notifications.set(sink);
    }

    pub fn set_event_sink(&self, sink: Arc<dyn EventSink>) {
        let _ = self.inner.links.events.set(sink);
    }

    pub fn set_metric_sink(&self, sink: Arc<dyn MetricSink>) {
        let _ = self.inner.links.metrics.set(sink);
    }

    pub fn set_alarm_manager(&self, alarms: Arc<dyn AlarmManager>) {
        let _ = self.inner.links.alarms.set(alarms);
    }

    pub fn set_traffic_sink(&self, sink: Arc<dyn TrafficSink>) {
        let _ = self.inner.links.traffic.set(sink);
    }

    pub(crate) fn traffic(&self) -> Option<&Arc<dyn TrafficSink>> {
        self.inner.links.traffic.get()
    }

    pub(crate) fn ec2(&self) -> &Ec2 {
        &self.inner.ec2
    }

    pub(crate) fn notifications(&self) -> Option<&Arc<dyn NotificationSink>> {
        self.inner.links.notifications.get()
    }

    pub(crate) fn events(&self) -> Option<&Arc<dyn EventSink>> {
        self.inner.links.events.get()
    }

    pub(crate) fn metrics(&self) -> Option<&Arc<dyn MetricSink>> {
        self.inner.links.metrics.get()
    }

    pub(crate) fn alarms(&self) -> Option<&Arc<dyn AlarmManager>> {
        self.inner.links.alarms.get()
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().expect("Auto Scaling state lock poisoned")
    }

    pub(crate) fn with_region<R>(&self, ctx: &RequestContext, f: impl FnOnce(&mut RegionState) -> R) -> R {
        let account = account_of(ctx);
        let mut state = self.lock();
        f(state.regions.entry(State::key(&account, &ctx.region)).or_default())
    }

    /// The emulated clock's current time.
    pub(crate) fn now(&self) -> DateTime<Utc> {
        Utc::now() + Duration::milliseconds(self.inner.clock_offset_ms.load(Ordering::Relaxed))
    }

    /// Learn the emulated clock and start the background loop (once).
    pub(crate) fn observe(&self, ctx: &RequestContext) {
        let offset = (ctx.received_at - Utc::now()).num_milliseconds();
        self.inner.clock_offset_ms.store(offset.max(0), Ordering::Relaxed);
        *self.inner.template.lock().expect("template lock poisoned") = Some(ctx.clone());
        if tokio::runtime::Handle::try_current().is_ok() && !self.inner.scheduler.swap(true, Ordering::SeqCst) {
            let me = self.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    me.tick().await;
                }
            });
        }
    }

    pub(crate) fn template(&self) -> Option<RequestContext> {
        self.inner.template.lock().expect("template lock poisoned").clone()
    }

    /// Run one reconciliation pass over every group now.
    pub async fn tick(&self) {
        let Some(template) = self.template() else { return };
        let _guard = self.inner.reconciling.lock().await;
        let now = self.now();
        let keys: Vec<String> = self.lock().regions.keys().cloned().collect();
        for key in keys {
            let Some((account, region)) = key.split_once('/') else { continue };
            self.reconcile_region(&template, account, region, now).await;
        }
    }

    /// Reconcile one group soon, outside the request.
    pub(crate) fn kick(&self) {
        if tokio::runtime::Handle::try_current().is_ok() {
            let me = self.clone();
            tokio::spawn(async move { me.tick().await });
        }
    }

    /// A scaling policy named by a CloudWatch alarm action.
    pub async fn alarm_triggered(&self, trigger: AlarmTrigger) -> Result<(), String> {
        self.run_alarm_policy(trigger).await
    }

    /// The context Auto Scaling calls other services with: its
    /// service-linked role in `account`.
    pub(crate) fn service_ctx(&self, template: &RequestContext, account: &str, region: &str) -> RequestContext {
        RequestContext {
            region: region.to_string(),
            received_at: self.now(),
            caller: Caller {
                account_id: account.to_string(),
                arn: format!(
                    "arn:{}:sts::{account}:assumed-role/AWSServiceRoleForAutoScaling/AutoScaling",
                    template.partition
                ),
                user_id: "AROAAUTOSCALINGSERVICE:AutoScaling".into(),
                access_key_id: String::new(),
                kind: CallerKind::AssumedRole {
                    role_name: "AWSServiceRoleForAutoScaling".into(),
                    session_name: "AutoScaling".into(),
                },
                session: None,
            },
            // The service decides, but explicit denies and KMS key policies
            // still apply to its service-linked role.
            authorizer: mws_core::ServiceLinkedRoleAuthorizer::wrap(template.authorizer.clone()),
            request_id: uuid::Uuid::new_v4().to_string(),
            ..template.clone()
        }
    }
}

/// The account a request works in.
pub(crate) fn account_of(ctx: &RequestContext) -> String {
    match ctx.caller.account_id.as_str() {
        "" => "000000000000".to_string(),
        a => a.to_string(),
    }
}

#[async_trait::async_trait]
impl Service for AutoScaling {
    fn signing_name(&self) -> &'static str {
        "autoscaling"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        self.observe(&ctx);
        let params = mws_proto_query::read_params(&request);
        let response = generated::dispatch(self, &ctx, &params).await;
        self.kick();
        response
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
        let out = generated::invoke(self, &ctx, operation, input).await;
        self.kick();
        out
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        serde_json::to_value(&*self.lock()).ok()
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid Auto Scaling state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}

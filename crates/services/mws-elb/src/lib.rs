//! Elastic Load Balancing for MWS: the ELBv2 API (Application, Network
//! and Gateway Load Balancers, `2015-12-01`) and the Classic Load Balancer
//! API (`2012-06-01`).
//!
//! Both APIs are one AWS service: one endpoint, one SigV4 signing name
//! (`elasticloadbalancing`) and one IAM prefix, told apart by the query
//! `Version`. They also share one data plane, so they live in one crate:
//! [`Elb`] serves ELBv2 and [`ClassicElb`] the Classic API.
//!
//! Load balancers really serve. Every listener binds a local socket (see
//! [`ElbConfig`]) and also answers on MWS's own endpoint when a request's
//! `Host` is the load balancer's DNS name. Application Load Balancers
//! evaluate listener rules and proxy HTTP to instance, IP and Lambda
//! targets; Network Load Balancers proxy TCP, TLS and UDP; HTTPS and TLS
//! listeners terminate TLS with their ACM certificates. Health checks probe
//! targets for real and the results drive routing, `DescribeTargetHealth`
//! and the `AWS/ApplicationELB`, `AWS/NetworkELB` and `AWS/ELB` CloudWatch
//! metrics.
//!
//! AWS couples ELB to EC2 (subnets, security groups, instances), ACM
//! (listener certificates), Lambda (Lambda targets) and S3 (trust store
//! bundles), so this crate uses their public APIs.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod v2 {
    include!(concat!(env!("OUT_DIR"), "/elbv2_generated.rs"));
}
#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod classic_api {
    include!(concat!(env!("OUT_DIR"), "/elb_generated.rs"));
}

mod catalog;
mod classic;
mod data;
mod health;
mod metrics;
mod names;
mod ops;
mod state;

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

pub use data::ListenerAddress;

/// A load balancer as other services see it ([`Elb::load_balancer`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadBalancerInfo {
    pub arn: String,
    pub name: String,
    /// `application`, `network`, `gateway` or `classic`.
    pub lb_type: String,
    pub scheme: String,
    /// `provisioning`, `active`, `active_impaired` or `failed`.
    pub state: String,
    pub dns_name: String,
    pub canonical_hosted_zone_id: Option<String>,
    /// Targets passing (`healthy`, or `InService` for Classic) and failing
    /// their health checks.
    pub healthy_targets: usize,
    pub unhealthy_targets: usize,
}
pub use metrics::{ElbMetric, MetricSink};
use state::State;

/// Where listeners bind.
#[derive(Debug, Clone)]
pub struct ElbConfig {
    /// The address listener sockets bind (`MWS_ELB_BIND`, default
    /// `127.0.0.1`; `0.0.0.0` lets EC2 containers reach load balancers).
    pub bind_host: String,
    /// Bind each listener on its own port (`MWS_ELB_LISTENER_PORTS=listener`)
    /// when that port is free, instead of an ephemeral port (the default).
    pub use_listener_ports: bool,
}

impl Default for ElbConfig {
    fn default() -> Self {
        Self { bind_host: "127.0.0.1".into(), use_listener_ports: false }
    }
}

impl ElbConfig {
    /// Read `MWS_ELB_BIND` and `MWS_ELB_LISTENER_PORTS`.
    pub fn from_env() -> Self {
        let mut c = Self::default();
        if let Ok(v) = std::env::var("MWS_ELB_BIND") {
            if !v.is_empty() {
                c.bind_host = v;
            }
        }
        c.use_listener_ports = std::env::var("MWS_ELB_LISTENER_PORTS").is_ok_and(|v| v == "listener");
        c
    }
}

pub(crate) struct Inner {
    state: Mutex<State>,
    config: ElbConfig,
    ec2: OnceLock<mws_ec2::Ec2>,
    acm: OnceLock<mws_acm::Acm>,
    lambda: OnceLock<mws_lambda::Lambda>,
    s3: OnceLock<mws_s3::S3>,
    metrics: OnceLock<Arc<dyn MetricSink>>,
    /// The last request's context: background work (health checks, Lambda
    /// targets) borrows its authorizer, endpoint and clock offset.
    template: Mutex<Option<(RequestContext, chrono::DateTime<chrono::Utc>)>>,
    data: data::Runtime,
    health: health::Health,
}

/// Elastic Load Balancing (ELBv2). Cheap to clone; clones share state.
#[derive(Clone)]
pub struct Elb {
    inner: Arc<Inner>,
}

/// The Classic Load Balancer API, sharing [`Elb`]'s state and data plane.
#[derive(Clone)]
pub struct ClassicElb {
    elb: Elb,
}

impl Default for Elb {
    fn default() -> Self {
        Self::new(ElbConfig::default())
    }
}

impl Elb {
    pub fn new(config: ElbConfig) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::default()),
                config,
                ec2: OnceLock::new(),
                acm: OnceLock::new(),
                lambda: OnceLock::new(),
                s3: OnceLock::new(),
                metrics: OnceLock::new(),
                template: Mutex::new(None),
                data: data::Runtime::default(),
                health: health::Health::default(),
            }),
        }
    }

    pub fn with_ec2(self, ec2: mws_ec2::Ec2) -> Self {
        let _ = self.inner.ec2.set(ec2);
        self
    }

    pub fn with_acm(self, acm: mws_acm::Acm) -> Self {
        let _ = self.inner.acm.set(acm);
        self
    }

    pub fn with_lambda(self, lambda: mws_lambda::Lambda) -> Self {
        let _ = self.inner.lambda.set(lambda);
        self
    }

    pub fn with_s3(self, s3: mws_s3::S3) -> Self {
        let _ = self.inner.s3.set(s3);
        self
    }

    /// Publish `AWS/ApplicationELB`, `AWS/NetworkELB` and `AWS/ELB`
    /// metrics.
    pub fn set_metric_sink(&self, sink: Arc<dyn MetricSink>) {
        let _ = self.inner.metrics.set(sink);
    }

    /// The Classic Load Balancer API over the same state.
    pub fn classic(&self) -> ClassicElb {
        ClassicElb { elb: self.clone() }
    }

    /// Where every listener is served locally.
    pub fn listener_addresses(&self) -> Vec<ListenerAddress> {
        self.inner.data.addresses()
    }

    /// The local address of an ELBv2 listener (by ARN) or a Classic Load
    /// Balancer listener (`<name>:<port>`).
    pub fn listener_address(&self, listener: &str) -> Option<std::net::SocketAddr> {
        self.inner.data.addresses().into_iter().find(|a| a.listener == listener).map(|a| a.address)
    }

    /// A load balancer by ARN (ELBv2, or `...:loadbalancer/<name>` for a
    /// Classic one), for services AWS couples to ELB such as Global
    /// Accelerator endpoints: its state and how many of its targets pass
    /// their health checks.
    pub fn load_balancer(&self, account: &str, region: &str, arn: &str) -> Option<LoadBalancerInfo> {
        let st = self.lock();
        let region_key = State::key(account, region);
        let r = st.regions.get(&region_key)?;
        if let Some(lb) = r.load_balancers.get(arn) {
            let (mut healthy, mut unhealthy) = (0, 0);
            for tg in r.target_groups.values() {
                if !crate::ops::tg_load_balancers(r, tg.arn()).iter().any(|l| l == arn) {
                    continue;
                }
                for target in &tg.targets {
                    match health::classify(self, r, account, region, tg, target).state {
                        "healthy" => healthy += 1,
                        "unhealthy" => unhealthy += 1,
                        _ => {}
                    }
                }
            }
            return Some(LoadBalancerInfo {
                arn: arn.to_string(),
                name: lb.name().to_string(),
                lb_type: lb.ty().to_string(),
                scheme: lb.lb.scheme.clone().unwrap_or_default(),
                state: lb.lb.state.as_ref().and_then(|s| s.code.clone()).unwrap_or_else(|| "active".into()),
                dns_name: lb.lb.dns_name.clone().unwrap_or_default(),
                canonical_hosted_zone_id: lb.lb.canonical_hosted_zone_id.clone(),
                healthy_targets: healthy,
                unhealthy_targets: unhealthy,
            });
        }
        let name = arn.rsplit_once(":loadbalancer/")?.1;
        let c = r.classic.get(name).filter(|_| classic::lb_arn(&region_key, name) == arn)?;
        let (mut healthy, mut unhealthy) = (0, 0);
        for id in &c.instances {
            if classic::instance_health(self, account, region, &region_key, name, id).0 == "InService" {
                healthy += 1;
            } else {
                unhealthy += 1;
            }
        }
        Some(LoadBalancerInfo {
            arn: arn.to_string(),
            name: name.to_string(),
            lb_type: "classic".into(),
            scheme: c.description.scheme.clone().unwrap_or_default(),
            state: "active".into(),
            dns_name: c.description.dns_name.clone().unwrap_or_default(),
            canonical_hosted_zone_id: c.description.canonical_hosted_zone_name_id.clone(),
            healthy_targets: healthy,
            unhealthy_targets: unhealthy,
        })
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().expect("ELB state lock poisoned")
    }

    pub(crate) fn ec2(&self) -> Option<&mws_ec2::Ec2> {
        self.inner.ec2.get()
    }

    pub(crate) fn acm(&self) -> Option<&mws_acm::Acm> {
        self.inner.acm.get()
    }

    pub(crate) fn lambda(&self) -> Option<&mws_lambda::Lambda> {
        self.inner.lambda.get()
    }

    pub(crate) fn s3(&self) -> Option<&mws_s3::S3> {
        self.inner.s3.get()
    }

    pub(crate) fn metrics(&self) -> Option<&Arc<dyn MetricSink>> {
        self.inner.metrics.get()
    }

    /// Remember `ctx` for background work and make sure the data plane
    /// serves what the state describes.
    pub(crate) fn observe(&self, ctx: &RequestContext) {
        *self.inner.template.lock().expect("ELB template lock poisoned") = Some((ctx.clone(), chrono::Utc::now()));
        self.reconcile();
    }

    /// A context for work MWS does on its own (Lambda targets, health
    /// checks): the last request's, at the emulated time now.
    pub(crate) fn background_context(&self, account: &str, region: &str) -> Option<RequestContext> {
        let guard = self.inner.template.lock().expect("ELB template lock poisoned");
        let (template, wall) = guard.as_ref()?;
        let offset = template.received_at - *wall;
        let mut ctx = template.clone();
        ctx.request_id = uuid::Uuid::new_v4().to_string();
        ctx.received_at = chrono::Utc::now() + offset;
        ctx.region = region.to_string();
        ctx.caller = mws_core::Caller::anonymous();
        ctx.caller.account_id = account.to_string();
        Some(ctx)
    }

    /// Bind sockets for new listeners, close removed ones, and start the
    /// health checker.
    pub(crate) fn reconcile(&self) {
        data::reconcile(self);
        health::ensure_running(self);
    }

    fn host_routed(&self, request: &HttpRequest) -> Option<data::HostRoute> {
        data::host_route(self, request)
    }
}

/// The account a request works in.
pub(crate) fn account_of(ctx: &RequestContext) -> String {
    match ctx.caller.account_id.as_str() {
        "" => "000000000000".to_string(),
        a => a.to_string(),
    }
}

fn version_of(request: &HttpRequest) -> Option<String> {
    mws_proto_query::read_params(request).get("Version").map(str::to_string)
}

#[async_trait::async_trait]
impl Service for Elb {
    fn signing_name(&self) -> &'static str {
        "elasticloadbalancing"
    }

    fn name(&self) -> &'static str {
        "elbv2"
    }

    fn claims(&self, request: &HttpRequest) -> bool {
        version_of(request).as_deref() != Some(classic_api::SERVICE_INFO.version)
    }

    fn recognizes(&self, request: &HttpRequest) -> bool {
        self.host_routed(request).is_some()
    }

    fn accepts_unsigned(&self, request: &HttpRequest) -> bool {
        self.host_routed(request).is_some()
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        if let Some(route) = self.host_routed(&request) {
            return data::serve_host_routed(self, &ctx, route, request).await;
        }
        self.observe(&ctx);
        let params = mws_proto_query::read_params(&request);
        v2::dispatch(self, &ctx, &params).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_query::error_response(&v2::SERVICE_INFO, request_id, error)
    }

    async fn invoke(
        &self,
        ctx: RequestContext,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        self.observe(&ctx);
        v2::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        serde_json::to_value(&*self.lock()).ok()
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid ELB state: {e}"))?;
        *self.lock() = state;
        self.inner.health.clear();
        self.reconcile();
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
        self.inner.health.clear();
        self.reconcile();
    }
}

#[async_trait::async_trait]
impl Service for ClassicElb {
    fn signing_name(&self) -> &'static str {
        "elasticloadbalancing"
    }

    fn name(&self) -> &'static str {
        "elb"
    }

    fn claims(&self, request: &HttpRequest) -> bool {
        version_of(request).as_deref() == Some(classic_api::SERVICE_INFO.version)
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        self.elb.observe(&ctx);
        let params = mws_proto_query::read_params(&request);
        classic_api::dispatch(self, &ctx, &params).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_query::error_response(&classic_api::SERVICE_INFO, request_id, error)
    }

    async fn invoke(
        &self,
        ctx: RequestContext,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        self.elb.observe(&ctx);
        classic_api::invoke(self, &ctx, operation, input).await
    }

    // Classic Load Balancers are part of the ELBv2 service's state.
}

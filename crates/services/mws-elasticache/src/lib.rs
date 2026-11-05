//! Amazon ElastiCache for MWS.
//!
//! The ElastiCache API contract lives here: cache clusters, replication
//! groups (cluster mode disabled and enabled), parameter and subnet groups,
//! users and user groups (RBAC), snapshots, serverless caches, global
//! datastores, reserved nodes, service updates and events. What actually
//! runs a cache node is a pluggable [`backend::EngineBackend`]:
//! [`backend::DockerBackend`] runs real Redis OSS, Valkey and Memcached
//! containers, and [`backend::MetadataBackend`] runs nothing.
//!
//! With real engines MWS drives them the way ElastiCache does: replicas
//! replicate from their primary, cluster-mode shards own their slot ranges,
//! AUTH tokens and RBAC users become engine passwords and ACLs, failovers
//! promote a replica, snapshots hold the data (`DUMP`/`RESTORE`), and
//! parameter group changes reach the nodes (`CONFIG SET`). The primary,
//! reader and configuration endpoints are TCP proxies that follow the
//! current primary (see [`proxy`]).

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/elasticache_generated.rs"));
}

pub mod backend;
mod catalog;
mod discovery;
mod engine;
mod handler;
pub mod logdelivery;
pub mod metrics;
mod ops;
pub mod proxy;
pub mod resp;
mod schedule;
mod state;
pub mod tls;

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

pub use backend::{BackendChoice, DockerBackend, EngineBackend, EngineKind, MetadataBackend};
pub use logdelivery::{LogBatch, LogDelivery};
pub use metrics::{CacheMetric, MetricPublisher};
use state::{RegionState, State};

/// A VPC subnet, as ElastiCache sees it.
#[derive(Debug, Clone)]
pub struct SubnetInfo {
    pub subnet_id: String,
    pub vpc_id: String,
    pub availability_zone: String,
    pub ipv6: bool,
}

/// What ElastiCache reads from EC2 (subnet groups, security groups). MWS
/// wires this to its EC2 service; without it any well-formed id is
/// accepted.
pub trait NetworkView: Send + Sync {
    fn subnet(&self, account: &str, region: &str, subnet_id: &str) -> Option<SubnetInfo>;
    /// The default VPC's subnets.
    fn default_subnets(&self, account: &str, region: &str) -> Vec<SubnetInfo>;
    /// The VPC a security group belongs to.
    fn security_group_vpc(&self, account: &str, region: &str, group_id: &str) -> Option<String>;
    /// A VPC's default security group.
    fn default_security_group(&self, account: &str, region: &str, vpc_id: &str) -> Option<String>;
    /// The Docker network a VPC's EC2 instances run on, which nodes join
    /// so that instances in the VPC reach them.
    fn docker_network(&self, _vpc_id: &str) -> Option<String> {
        None
    }
}

/// Where snapshots are exported to and seeded from (S3), as the
/// `elasticache.amazonaws.com` service principal.
pub trait SnapshotBucket: Send + Sync {
    fn export(
        &self,
        ctx: &RequestContext,
        bucket: &str,
        key: &str,
        body: Vec<u8>,
        source_arn: &str,
    ) -> Result<(), ServiceError>;
    /// An object named by `arn:aws:s3:::bucket/key`.
    fn read(&self, s3_arn: &str) -> Option<Vec<u8>>;
}

/// Delivers ElastiCache events to clusters' notification topics (SNS).
pub trait EventNotifier: Send + Sync {
    fn notify(&self, ctx: &RequestContext, topic_arn: &str, source_arn: &str, message: &str);
}

/// How ElastiCache publishes endpoints.
#[derive(Debug, Clone)]
pub struct Options {
    /// The address clients reach nodes and endpoints at
    /// (`MWS_ELASTICACHE_HOST`, default `127.0.0.1`).
    pub advertise_host: String,
    /// The host address node ports and endpoint proxies listen on.
    pub bind_address: String,
}

impl Default for Options {
    fn default() -> Self {
        Self { advertise_host: "127.0.0.1".into(), bind_address: "127.0.0.1".into() }
    }
}

/// Where the CA certificate for encryption in transit is served.
pub const CA_PATH: &str = "/_aws/elasticache/ca.pem";

pub(crate) struct Inner {
    state: Mutex<State>,
    backend: Arc<dyn EngineBackend>,
    options: Options,
    network: OnceLock<Arc<dyn NetworkView>>,
    bucket: OnceLock<Arc<dyn SnapshotBucket>>,
    notifier: OnceLock<Arc<dyn EventNotifier>>,
    proxies: proxy::Proxies,
    /// The CA node certificates come from (generated on first use).
    pki: Mutex<tls::Pki>,
    /// A TLS client trusting `pki`'s CA, for that CA's certificate.
    tls_client: Mutex<Option<(String, Arc<rustls::ClientConfig>)>>,
    meter: metrics::Meter,
    log_delivery: OnceLock<Arc<dyn logdelivery::LogDelivery>>,
    log_cursors: logdelivery::Cursors,
}

/// The ElastiCache service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct ElastiCache {
    inner: Arc<Inner>,
}

impl Default for ElastiCache {
    fn default() -> Self {
        Self::new(Arc::new(MetadataBackend))
    }
}

impl ElastiCache {
    pub fn new(backend: Arc<dyn EngineBackend>) -> Self {
        Self::with_options(backend, Options::default())
    }

    pub fn with_options(backend: Arc<dyn EngineBackend>, options: Options) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::default()),
                backend,
                options,
                network: OnceLock::new(),
                bucket: OnceLock::new(),
                notifier: OnceLock::new(),
                proxies: Default::default(),
                pki: Mutex::new(tls::Pki::default()),
                tls_client: Mutex::new(None),
                meter: Default::default(),
                log_delivery: OnceLock::new(),
                log_cursors: Default::default(),
            }),
        }
    }

    pub fn set_network(&self, network: Arc<dyn NetworkView>) {
        let _ = self.inner.network.set(network);
    }

    pub fn set_snapshot_bucket(&self, bucket: Arc<dyn SnapshotBucket>) {
        let _ = self.inner.bucket.set(bucket);
    }

    pub fn set_event_notifier(&self, notifier: Arc<dyn EventNotifier>) {
        let _ = self.inner.notifier.set(notifier);
    }

    pub fn backend_name(&self) -> &'static str {
        self.inner.backend.name()
    }

    pub(crate) fn backend(&self) -> Arc<dyn EngineBackend> {
        self.inner.backend.clone()
    }

    pub(crate) fn runs_engines(&self) -> bool {
        self.inner.backend.runs_engines()
    }

    pub(crate) fn options(&self) -> &Options {
        &self.inner.options
    }

    pub(crate) fn network(&self) -> Option<&Arc<dyn NetworkView>> {
        self.inner.network.get()
    }

    pub(crate) fn bucket(&self) -> Option<&Arc<dyn SnapshotBucket>> {
        self.inner.bucket.get()
    }

    pub(crate) fn notifier(&self) -> Option<&Arc<dyn EventNotifier>> {
        self.inner.notifier.get()
    }

    pub(crate) fn proxies(&self) -> &proxy::Proxies {
        &self.inner.proxies
    }

    /// The CA and server certificate of nodes with encryption in transit.
    pub(crate) fn pki(&self) -> tls::Pki {
        let mut pki = self.inner.pki.lock().expect("ElastiCache PKI lock poisoned");
        if pki.ca_cert_pem.is_empty() {
            let names = tls::server_names(&self.options().advertise_host, &engine::connect_host(self));
            match tls::Pki::generate(&names) {
                Ok(p) => *pki = tls::Pki { command_suffix: std::mem::take(&mut pki.command_suffix), ..p },
                Err(e) => tracing::error!("ElastiCache: generating the TLS CA failed: {e}"),
            }
        }
        pki.clone()
    }

    /// The PEM certificate of the CA that signs node certificates (served
    /// at `/_aws/elasticache/ca.pem`). Clients connecting to caches with
    /// encryption in transit trust it.
    pub fn ca_certificate_pem(&self) -> String {
        self.pki().ca_cert_pem
    }

    /// A TLS client for nodes listening on `port` with encryption in
    /// transit, or `None` for plain nodes.
    pub(crate) fn tls_client_for(&self, port: u16) -> Option<Arc<rustls::ClientConfig>> {
        let tls = {
            let st = self.lock();
            st.regions.values().any(|r| {
                r.clusters.values().any(|c| {
                    c.info.transit_encryption_enabled == Some(true) && c.nodes.values().any(|n| n.port == port)
                }) || r.serverless.values().any(|s| s.node.port == port)
            })
        };
        if !tls {
            return None;
        }
        let ca = self.ca_certificate_pem();
        let mut cached = self.inner.tls_client.lock().expect("ElastiCache TLS lock poisoned");
        if let Some((pem, config)) = cached.as_ref() {
            if *pem == ca {
                return Some(config.clone());
            }
        }
        match tls::client_config(&ca) {
            Ok(config) => {
                *cached = Some((ca, config.clone()));
                Some(config)
            }
            Err(e) => {
                tracing::error!("ElastiCache: TLS client: {e}");
                None
            }
        }
    }

    pub(crate) fn meter(&self) -> &metrics::Meter {
        &self.inner.meter
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().expect("ElastiCache state lock poisoned")
    }

    /// Run `f` on the caller's account and Region.
    pub(crate) fn with_region<R>(&self, ctx: &RequestContext, f: impl FnOnce(&mut RegionState) -> R) -> R {
        let key = State::key(&account_of(ctx), &ctx.region);
        self.with_key(&key, ctx, f)
    }

    /// The suffix of renamed restricted commands, generated on first use.
    pub(crate) fn command_suffix(&self) -> String {
        let mut pki = self.inner.pki.lock().expect("ElastiCache PKI lock poisoned");
        if pki.command_suffix.is_empty() {
            pki.command_suffix = format!("{:016x}", rand::random::<u64>());
        }
        pki.command_suffix.clone()
    }

    /// Run `f` on a Region's state if it exists (for background tasks,
    /// which have no request to initialize a Region from).
    pub(crate) fn with_existing<R>(&self, key: &str, f: impl FnOnce(&mut RegionState) -> R) -> Option<R> {
        self.lock().regions.get_mut(key).map(f)
    }

    pub(crate) fn with_key<R>(&self, key: &str, ctx: &RequestContext, f: impl FnOnce(&mut RegionState) -> R) -> R {
        let mut state = self.lock();
        let r = state.regions.entry(key.to_string()).or_default();
        if !r.initialized {
            let (account, region) = key.split_once('/').unwrap_or((key, ""));
            ops::users::init_region(r, &ctx.partition, account, region);
            r.initialized = true;
        }
        f(r)
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
impl Service for ElastiCache {
    fn signing_name(&self) -> &'static str {
        "elasticache"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        if request.uri().path() == CA_PATH {
            return http::Response::builder()
                .status(200)
                .header(http::header::CONTENT_TYPE, "application/x-pem-file")
                .body(bytes::Bytes::from(self.ca_certificate_pem()))
                .expect("static response parts are valid");
        }
        self.observe_clock(&ctx);
        let params = mws_proto_query::read_params(&request);
        generated::dispatch(self, &ctx, &params).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_query::error_response(&generated::SERVICE_INFO, request_id, error)
    }

    /// The CA certificate for encryption in transit is public.
    fn accepts_unsigned(&self, request: &HttpRequest) -> bool {
        request.method() == http::Method::GET && request.uri().path() == CA_PATH
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
        let mut v = serde_json::to_value(&*self.lock()).ok()?;
        let pki = self.inner.pki.lock().expect("ElastiCache PKI lock poisoned").clone();
        if let (false, Some(o)) = (pki.is_empty(), v.as_object_mut()) {
            o.insert("pki".into(), serde_json::to_value(pki).ok()?);
        }
        Some(v)
    }

    fn import_state(&self, mut state: serde_json::Value) -> Result<(), String> {
        let pki = state.as_object_mut().and_then(|o| o.remove("pki"));
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid ElastiCache state: {e}"))?;
        if let Some(p) = pki {
            let p: tls::Pki =
                serde_json::from_value(p).map_err(|e| format!("invalid ElastiCache certificates: {e}"))?;
            *self.inner.pki.lock().expect("ElastiCache PKI lock poisoned") = p;
        }
        *self.lock() = state;
        engine::reattach(self);
        Ok(())
    }

    fn reset_state(&self) {
        let old = std::mem::take(&mut *self.lock());
        self.proxies().close_all();
        let backend = self.backend();
        let handles: Vec<String> = old
            .regions
            .values()
            .flat_map(|r| {
                r.clusters
                    .values()
                    .flat_map(|c| c.nodes.values().filter_map(|n| n.handle.clone()))
                    .chain(r.serverless.values().filter_map(|s| s.node.handle.clone()))
                    .collect::<Vec<_>>()
            })
            .collect();
        if !handles.is_empty() && backend.runs_engines() {
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(async move {
                    let _ = backend.terminate_all(&handles).await;
                });
            }
        }
    }
}

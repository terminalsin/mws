//! EC2 Image Builder for MWS.
//!
//! Components, image and container recipes, infrastructure and
//! distribution configurations, pipelines, workflows and lifecycle
//! policies, with Image Builder's versioning (`1.2.x` wildcards, build
//! numbers, latest-version references), resource policies and client-token
//! idempotency.
//!
//! Builds are real: an image build runs its workflows (the AWS-managed
//! `build-image` and `test-image`, or your own) step by step. It launches
//! the build instance in MWS's EC2 with the infrastructure configuration,
//! runs the recipe's AWSTOE component documents on it (inside the
//! instance's container when EC2 uses the Docker backend), creates the AMI
//! with EC2 `CreateImage`, tests it on a second instance and distributes it
//! (copies to other Regions and accounts, launch permissions, tags, SSM
//! parameters). The AMIs it outputs are ordinary EC2 images you can
//! `RunInstances` from.
//!
//! AWS couples Image Builder to EC2 (instances, AMIs), so this crate uses
//! EC2's public API. S3 (component documents and logs), Systems Manager
//! (`ssm:` parent images, output parameters) and SNS (build notifications)
//! are reached through their generic [`mws_core::Service`] interface, as
//! Image Builder's service-linked role.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/imagebuilder_generated.rs"));
}

mod components;
mod container;
mod distribution;
mod ec2link;
mod engine;
mod handler;
mod images;
mod infra;
mod lifecycle;
mod managed;
mod pipelines;
mod recipes;
mod state;
mod tags;
mod toe;
mod util;
mod workflows;
mod yaml;

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use mws_core::{Caller, CallerKind, HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::Digest;

use state::{Idempotent, Region, State};

/// An image changed state. MWS turns this into the EventBridge event
/// "EC2 Image Builder Image State Change".
#[derive(Debug, Clone)]
pub struct ImageStateChange {
    pub partition: String,
    pub account: String,
    pub region: String,
    pub image_build_version_arn: String,
    pub previous_status: Option<String>,
    pub status: String,
    pub reason: Option<String>,
    pub time: chrono::DateTime<chrono::Utc>,
}

/// Where image state changes go (EventBridge, in MWS).
pub trait ImageEvents: Send + Sync {
    fn image_state_changed(&self, ctx: &RequestContext, change: &ImageStateChange);
}

/// What a build instance acts as when it pushes container images or
/// uploads its logs: its instance profile's role, as instance metadata
/// hands it to the instance. MWS wires this to IAM and STS.
pub trait InstanceRoles: Send + Sync {
    /// `base` acting as the role of `instance_profile` (a name or ARN) in
    /// `account`, assumed by EC2 for instance `instance_id`. An error says
    /// why the instance has no credentials.
    fn instance_context(
        &self,
        base: &RequestContext,
        account: &str,
        instance_profile: &str,
        instance_id: &str,
    ) -> Result<RequestContext, String>;
}

pub(crate) struct Inner {
    state: Mutex<State>,
    ec2: Option<mws_ec2::Ec2>,
    s3: OnceLock<Arc<dyn Service>>,
    ssm: OnceLock<Arc<dyn Service>>,
    sns: OnceLock<Arc<dyn Service>>,
    logs: OnceLock<Arc<dyn Service>>,
    ecr: OnceLock<Arc<dyn Service>>,
    events: OnceLock<Arc<dyn ImageEvents>>,
    instance_roles: OnceLock<Arc<dyn InstanceRoles>>,
    /// Emulated clock minus wall clock, in milliseconds.
    clock_offset_ms: AtomicI64,
    scheduler: AtomicBool,
    template: Mutex<Option<RequestContext>>,
}

/// The EC2 Image Builder service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct ImageBuilder {
    inner: Arc<Inner>,
}

impl Default for ImageBuilder {
    fn default() -> Self {
        Self::build(None)
    }
}

impl ImageBuilder {
    /// Image Builder without EC2: resources work, builds fail.
    pub fn new() -> Self {
        Self::build(None)
    }

    /// Image Builder that builds AMIs in `ec2`.
    pub fn with_ec2(ec2: mws_ec2::Ec2) -> Self {
        Self::build(Some(ec2))
    }

    fn build(ec2: Option<mws_ec2::Ec2>) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::default()),
                ec2,
                s3: OnceLock::new(),
                ssm: OnceLock::new(),
                sns: OnceLock::new(),
                logs: OnceLock::new(),
                ecr: OnceLock::new(),
                events: OnceLock::new(),
                instance_roles: OnceLock::new(),
                clock_offset_ms: AtomicI64::new(0),
                scheduler: AtomicBool::new(false),
                template: Mutex::new(None),
            }),
        }
    }

    /// S3, for component documents given by `uri` and build logs.
    pub fn set_s3(&self, s3: Arc<dyn Service>) {
        let _ = self.inner.s3.set(s3);
    }

    /// Systems Manager, for `ssm:` parent images and the parameters
    /// distributions write.
    pub fn set_ssm(&self, ssm: Arc<dyn Service>) {
        let _ = self.inner.ssm.set(ssm);
    }

    /// SNS, for the infrastructure configuration's notification topic.
    pub fn set_sns(&self, sns: Arc<dyn Service>) {
        let _ = self.inner.sns.set(sns);
    }

    /// CloudWatch Logs, for build logs in `/aws/imagebuilder/<name>`.
    pub fn set_logs(&self, logs: Arc<dyn Service>) {
        let _ = self.inner.logs.set(logs);
    }

    /// Amazon ECR, where container recipes push the images they build.
    pub fn set_ecr(&self, ecr: Arc<dyn Service>) {
        let _ = self.inner.ecr.set(ecr);
    }

    /// Where image state change events go.
    pub fn set_events(&self, events: Arc<dyn ImageEvents>) {
        let _ = self.inner.events.set(events);
    }

    /// Build instances act as their instance profile's role through this.
    /// Without it they act as Image Builder's service-linked role.
    pub fn set_instance_roles(&self, roles: Arc<dyn InstanceRoles>) {
        let _ = self.inner.instance_roles.set(roles);
    }

    pub(crate) fn instance_roles(&self) -> Option<&Arc<dyn InstanceRoles>> {
        self.inner.instance_roles.get()
    }

    pub(crate) fn ec2(&self) -> Option<&mws_ec2::Ec2> {
        self.inner.ec2.as_ref()
    }

    pub(crate) fn s3(&self) -> Option<&Arc<dyn Service>> {
        self.inner.s3.get()
    }

    pub(crate) fn ssm(&self) -> Option<&Arc<dyn Service>> {
        self.inner.ssm.get()
    }

    pub(crate) fn sns(&self) -> Option<&Arc<dyn Service>> {
        self.inner.sns.get()
    }

    pub(crate) fn logs(&self) -> Option<&Arc<dyn Service>> {
        self.inner.logs.get()
    }

    pub(crate) fn ecr(&self) -> Option<&Arc<dyn Service>> {
        self.inner.ecr.get()
    }

    pub(crate) fn events(&self) -> Option<&Arc<dyn ImageEvents>> {
        self.inner.events.get()
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().expect("Image Builder state lock poisoned")
    }

    /// Run `f` on the caller's account and Region.
    pub(crate) fn with_region<R>(&self, ctx: &RequestContext, f: impl FnOnce(&mut Region) -> R) -> R {
        self.with_region_of(&util::account_of(ctx), &ctx.region, f)
    }

    pub(crate) fn with_region_of<R>(&self, account: &str, region: &str, f: impl FnOnce(&mut Region) -> R) -> R {
        let mut state = self.lock();
        f(state.regions.entry(State::key(account, region)).or_default())
    }

    /// The emulated time now.
    pub(crate) fn now(&self) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc::now() + chrono::Duration::milliseconds(self.inner.clock_offset_ms.load(Ordering::Relaxed))
    }

    /// Remember the request's clock and context for background work, and
    /// start the scheduler once there is a runtime to run it on.
    pub(crate) fn observe(&self, ctx: &RequestContext) {
        let offset = (ctx.received_at - chrono::Utc::now()).num_milliseconds();
        self.inner.clock_offset_ms.store(offset.max(0), Ordering::Relaxed);
        *self.inner.template.lock().expect("template lock poisoned") = Some(ctx.clone());
        if tokio::runtime::Handle::try_current().is_ok() && !self.inner.scheduler.swap(true, Ordering::SeqCst) {
            let me = self.clone();
            tokio::spawn(async move { me.run_scheduler().await });
        }
    }

    pub(crate) fn template(&self) -> Option<RequestContext> {
        self.inner.template.lock().expect("template lock poisoned").clone()
    }

    /// A context acting as Image Builder's service-linked role in
    /// `account` and `region` (what AWS uses to launch instances, create
    /// AMIs and so on for you).
    pub(crate) fn service_ctx(&self, base: &RequestContext, account: &str, region: &str) -> RequestContext {
        RequestContext {
            request_id: uuid::Uuid::new_v4().to_string(),
            region: region.to_string(),
            partition: base.partition.clone(),
            received_at: self.now().max(base.received_at),
            caller: Caller {
                account_id: account.to_string(),
                arn: format!(
                    "arn:{}:sts::{account}:assumed-role/AWSServiceRoleForImageBuilder/ImageBuilder",
                    base.partition
                ),
                user_id: "AROAIMAGEBUILDERSLR00:ImageBuilder".into(),
                access_key_id: String::new(),
                kind: CallerKind::AssumedRole {
                    role_name: "AWSServiceRoleForImageBuilder".into(),
                    session_name: "ImageBuilder".into(),
                },
                session: None,
            },
            source_ip: None,
            secure_transport: true,
            authorizer: mws_core::ServiceLinkedRoleAuthorizer::wrap(base.authorizer.clone()),
            endpoint: base.endpoint.clone(),
        }
    }

    /// Run a create/update call once per client token: a repeat with the
    /// same token and parameters gets the first response, a repeat with
    /// other parameters an `IdempotentParameterMismatchException`.
    pub(crate) async fn idempotent<I, O, F>(
        &self,
        ctx: &RequestContext,
        operation: &str,
        token: &str,
        input: &I,
        f: F,
    ) -> Result<O, ServiceError>
    where
        I: Serialize,
        O: Serialize + DeserializeOwned,
        F: std::future::Future<Output = Result<O, ServiceError>>,
    {
        let mut request = serde_json::to_value(input).unwrap_or_default();
        if let Some(obj) = request.as_object_mut() {
            obj.remove("client_token");
            obj.remove("dry_run");
        }
        let digest = hex::encode(sha2::Sha256::digest(request.to_string().as_bytes()));
        let key = format!("{}/{}/{operation}/{token}", util::account_of(ctx), ctx.region);
        if let Some(prev) = self.lock().idempotency.get(&key) {
            if prev.request != digest {
                return Err(util::idempotent_mismatch(token));
            }
            if let Ok(out) = serde_json::from_value(prev.response.clone()) {
                return Ok(out);
            }
        }
        let out = f.await?;
        let mut st = self.lock();
        if st.idempotency.len() >= 10_000 {
            if let Some(first) = st.idempotency.keys().next().cloned() {
                st.idempotency.remove(&first);
            }
        }
        st.idempotency
            .insert(key, Idempotent { request: digest, response: serde_json::to_value(&out).unwrap_or_default() });
        Ok(out)
    }

    async fn run_scheduler(&self) {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            if let Some(template) = self.template() {
                self.fire_pipeline_schedules(&template).await;
                self.run_lifecycle_policies(&template).await;
            }
        }
    }
}

#[async_trait::async_trait]
impl Service for ImageBuilder {
    fn signing_name(&self) -> &'static str {
        "imagebuilder"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        self.observe(&ctx);
        generated::dispatch(self, &ctx, &request).await
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
        self.observe(&ctx);
        generated::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        serde_json::to_value(&*self.lock()).ok()
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid Image Builder state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
    }
}

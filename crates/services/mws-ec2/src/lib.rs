//! Amazon EC2 (and VPC) for MWS.
//!
//! The EC2 API contract lives here: VPC networking (VPCs, subnets, security
//! groups, route tables, gateways, network ACLs, DHCP options, ENIs,
//! Elastic IPs), key pairs, AMIs, EBS volumes and snapshots, and instances
//! with their state machine. What actually runs an instance is a pluggable
//! [`backend::ComputeBackend`]: [`backend::DockerBackend`] runs each
//! instance as a container on a per-VPC network, and
//! [`backend::MetadataBackend`] runs nothing (a pure control plane for
//! machines without a container runtime).
//!
//! Instances reach MWS itself through the SDK endpoint variables MWS
//! injects, and their instance metadata (IMDSv1/v2, including instance
//! profile credentials from STS) at `/_aws/ec2/metadata/<instance-id>/`
//! (see [`imds`]).

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/ec2_generated.rs"));
}

pub mod backend;
mod catalog;
mod console;
mod firewall;
mod handler;
pub mod imds;
mod keys;
pub mod network;
mod ops;
mod pricing;
mod public;
mod quotas;
mod service_eni;
mod state;
mod util;
mod volumes;

use std::sync::{Arc, Mutex, MutexGuard, OnceLock, RwLock};

use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

pub use backend::{
    BackendChoice, CommandOutput, ComputeBackend, DockerBackend, ExecStream, HostMount, LaunchExtension, LaunchExtras,
    MetadataBackend, VolumeMount,
};
pub use ops::launch_template::ResolvedLaunchTemplate;
pub use public::{
    availability_zones, InstanceInfo, InstanceNetwork, SecurityGroupInfo, ServiceInterface, ServiceInterfaceError,
    ServiceInterfaceRequest, SubnetInfo, VpcInfo,
};
pub use service_eni::TaskInterface;
use state::{RegionState, State};

/// Credentials for an instance profile's role, as instance metadata serves
/// them. MWS wires this to STS (EC2 assumes the role as
/// `ec2.amazonaws.com`).
pub trait InstanceRoleCredentials: Send + Sync {
    /// The instance profile in `account` (by name or ARN): its ARN, id and
    /// role ARN.
    fn instance_profile(&self, account: &str, name_or_arn: &str) -> Option<InstanceProfile>;

    /// Temporary credentials for `role_arn`, assumed by EC2 for
    /// `instance_arn`.
    fn credentials(
        &self,
        role_arn: &str,
        instance_arn: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<RoleCredentials>;
}

#[derive(Debug, Clone)]
pub struct InstanceProfile {
    pub arn: String,
    pub id: String,
    pub role_arn: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RoleCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: chrono::DateTime<chrono::Utc>,
}

pub(crate) struct Inner {
    state: Mutex<State>,
    backend: Arc<dyn ComputeBackend>,
    roles: OnceLock<Arc<dyn InstanceRoleCredentials>>,
    quotas: OnceLock<mws_servicequotas::ServiceQuotas>,
    imds: imds::ImdsState,
    firewalls: firewall::Applied,
    volume_jobs: volumes::VolumeQueue,
    extensions: RwLock<Vec<Arc<dyn LaunchExtension>>>,
    load_balancers: OnceLock<Arc<dyn LoadBalancers>>,
}

/// The load balancers VPC endpoint services front: MWS wires this to
/// Elastic Load Balancing.
pub trait LoadBalancers: Send + Sync {
    /// A load balancer's type (`network`, `gateway`, ...) and the
    /// Availability Zones it is enabled in.
    fn load_balancer(&self, account: &str, region: &str, arn: &str) -> Option<(String, Vec<String>)>;
}

/// The EC2 service. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct Ec2 {
    inner: Arc<Inner>,
}

impl Default for Ec2 {
    fn default() -> Self {
        Self::new(Arc::new(MetadataBackend))
    }
}

impl Ec2 {
    pub fn new(backend: Arc<dyn ComputeBackend>) -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State::default()),
                backend,
                roles: OnceLock::new(),
                quotas: OnceLock::new(),
                imds: Default::default(),
                firewalls: Default::default(),
                volume_jobs: Default::default(),
                extensions: RwLock::default(),
                load_balancers: OnceLock::new(),
            }),
        }
    }

    /// Look up the load balancers endpoint services are created for.
    pub fn set_load_balancers(&self, lbs: Arc<dyn LoadBalancers>) {
        let _ = self.inner.load_balancers.set(lbs);
    }

    pub(crate) fn load_balancers(&self) -> Option<&Arc<dyn LoadBalancers>> {
        self.inner.load_balancers.get()
    }

    /// Hand instance profile credentials out through instance metadata.
    pub fn set_instance_roles(&self, roles: Arc<dyn InstanceRoleCredentials>) {
        let _ = self.inner.roles.set(roles);
    }

    /// Let another service add mounts, boot hooks and the like to every
    /// instance launch.
    pub fn add_launch_extension(&self, extension: Arc<dyn LaunchExtension>) {
        self.inner.extensions.write().expect("EC2 extensions lock poisoned").push(extension);
    }

    /// What the launch extensions add to `spec`.
    pub(crate) fn extend_launch(&self, spec: &mut backend::LaunchSpec) {
        let extensions = self.inner.extensions.read().expect("EC2 extensions lock poisoned").clone();
        for e in extensions {
            let extras = e.extend(spec);
            spec.extras.merge(extras);
        }
    }

    pub fn backend_name(&self) -> &'static str {
        self.inner.backend.name()
    }

    /// Run a shell script as root inside a running instance, the way the
    /// SSM agent runs commands for other services (EC2 Image Builder runs
    /// its build components this way). `Ok(None)` when the compute backend
    /// runs nothing (metadata only); an error when the instance does not
    /// exist or is not running.
    pub async fn run_command_on_instance(
        &self,
        account: &str,
        region: &str,
        instance_id: &str,
        script: &str,
    ) -> Result<Option<CommandOutput>, String> {
        let handle = {
            let state = self.lock();
            let inst = state
                .regions
                .get(&State::key(account, region))
                .and_then(|r| r.instances.get(instance_id))
                .ok_or_else(|| format!("instance {instance_id} does not exist"))?;
            let running = inst.instance.state.as_ref().and_then(|s| s.name.as_deref()) == Some("running");
            if !running {
                return Err(format!("instance {instance_id} is not running"));
            }
            inst.handle.clone().ok_or_else(|| format!("instance {instance_id} has not started"))?
        };
        self.backend().exec(&handle, script).await.map_err(|e| e.to_string())
    }

    /// Start `script` on a running instance with its input and output
    /// streamed (Session Manager). `None` when the backend runs nothing.
    pub async fn stream_on_instance(
        &self,
        account: &str,
        region: &str,
        instance_id: &str,
        script: &str,
    ) -> Result<Option<ExecStream>, String> {
        let handle = {
            let state = self.lock();
            let inst = state
                .regions
                .get(&State::key(account, region))
                .and_then(|r| r.instances.get(instance_id))
                .ok_or_else(|| format!("instance {instance_id} does not exist"))?;
            if inst.instance.state.as_ref().and_then(|s| s.name.as_deref()) != Some("running") {
                return Err(format!("instance {instance_id} is not running"));
            }
            inst.handle.clone().ok_or_else(|| format!("instance {instance_id} has not started"))?
        };
        self.backend().exec_stream(&handle, script).await.map_err(|e| e.to_string())
    }

    /// Build a container image on a running instance (`docker build` with
    /// `files` as the context). The image comes back as a `docker save`
    /// archive, or `None` when the backend runs nothing.
    pub async fn build_image_on_instance(
        &self,
        account: &str,
        region: &str,
        instance_id: &str,
        dockerfile: &str,
        files: &[(String, Vec<u8>)],
    ) -> Result<Option<Vec<u8>>, String> {
        let handle = {
            let state = self.lock();
            let inst = state
                .regions
                .get(&State::key(account, region))
                .and_then(|r| r.instances.get(instance_id))
                .ok_or_else(|| format!("instance {instance_id} does not exist"))?;
            inst.handle.clone().ok_or_else(|| format!("instance {instance_id} has not started"))?
        };
        self.backend().build_image(&handle, dockerfile, files).await.map_err(|e| e.to_string())
    }

    pub(crate) fn backend(&self) -> Arc<dyn ComputeBackend> {
        self.inner.backend.clone()
    }

    /// An instance profile in `account` (by name or ARN), as instances
    /// launched with it would get it. `None` when it does not exist or no
    /// IAM is wired in.
    pub fn instance_profile(&self, account: &str, name_or_arn: &str) -> Option<InstanceProfile> {
        self.roles()?.instance_profile(account, name_or_arn)
    }

    /// Whether instance profiles can be looked up (IAM is wired in).
    pub fn knows_instance_profiles(&self) -> bool {
        self.roles().is_some()
    }

    pub(crate) fn roles(&self) -> Option<&Arc<dyn InstanceRoleCredentials>> {
        self.inner.roles.get()
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().expect("EC2 state lock poisoned")
    }

    /// Run `f` on the caller's account and Region, creating the default VPC
    /// there first if this is the first use.
    pub(crate) fn with_region<R>(&self, ctx: &RequestContext, f: impl FnOnce(&mut RegionState) -> R) -> R {
        let account = account_of(ctx);
        self.with_region_of(&account, &ctx.region, ctx, f)
    }

    pub(crate) fn with_region_of<R>(
        &self,
        account: &str,
        region: &str,
        ctx: &RequestContext,
        f: impl FnOnce(&mut RegionState) -> R,
    ) -> R {
        let mut state = self.lock();
        let r = state.regions.entry(State::key(account, region)).or_default();
        if !r.initialized {
            ops::vpc::init_region(r, account, region, &ctx.partition, ctx.received_at);
            r.initialized = true;
        }
        ops::instance::expire_terminated(r, ctx.received_at);
        ops::vpc::expire_deleted(r, ctx.received_at);
        ops::gateways::expire_deleted(r, ctx.received_at);
        f(r)
    }
}

/// What other services may read about an instance (Global Accelerator
/// endpoints, for one).
#[derive(Debug, Clone)]
pub struct InstanceSummary {
    pub instance_id: String,
    /// `pending`, `running`, `stopping`, `stopped`, `shutting-down`,
    /// `terminated`.
    pub state: String,
    pub private_ip: Option<String>,
    pub public_ip: Option<String>,
    pub subnet_id: Option<String>,
    pub vpc_id: Option<String>,
}

/// What Systems Manager reads about an instance to manage it.
#[derive(Debug, Clone, Default)]
pub struct InstanceDetails {
    pub instance_id: String,
    pub state: String,
    pub private_ip: Option<String>,
    pub private_dns_name: Option<String>,
    pub image_id: Option<String>,
    /// The AMI's name, when it is still known.
    pub image_name: Option<String>,
    /// `Linux/UNIX`, `Windows`, ...
    pub platform_details: Option<String>,
    pub iam_instance_profile_arn: Option<String>,
    pub launch_time: Option<chrono::DateTime<chrono::Utc>>,
    pub tags: std::collections::BTreeMap<String, String>,
}

/// An Elastic IP address allocation.
#[derive(Debug, Clone)]
pub struct AddressSummary {
    pub allocation_id: String,
    pub public_ip: Option<String>,
    pub instance_id: Option<String>,
    pub network_interface_id: Option<String>,
}

/// A VPC subnet.
#[derive(Debug, Clone)]
pub struct SubnetSummary {
    pub subnet_id: String,
    pub vpc_id: Option<String>,
    pub cidr_block: Option<String>,
    pub availability_zone: Option<String>,
}

impl Ec2 {
    fn read_region<R>(&self, account: &str, region: &str, f: impl FnOnce(&RegionState) -> Option<R>) -> Option<R> {
        let state = self.lock();
        state.regions.get(&State::key(account, region)).and_then(f)
    }

    /// Instance `id` in `account` and `region`.
    pub fn instance_summary(&self, account: &str, region: &str, id: &str) -> Option<InstanceSummary> {
        self.read_region(account, region, |r| {
            let i = &r.instances.get(id)?.instance;
            Some(InstanceSummary {
                instance_id: id.to_string(),
                state: i.state.as_ref().and_then(|s| s.name.clone()).unwrap_or_default(),
                private_ip: i.private_ip_address.clone(),
                public_ip: i.public_ip_address.clone(),
                subnet_id: i.subnet_id.clone(),
                vpc_id: i.vpc_id.clone(),
            })
        })
    }

    /// Every instance in `account` and `region` that is not terminated.
    pub fn instances(&self, account: &str, region: &str) -> Vec<InstanceDetails> {
        let state = self.lock();
        let Some(r) = state.regions.get(&State::key(account, region)) else { return Vec::new() };
        r.instances
            .iter()
            .filter_map(|(id, rec)| {
                let i = &rec.instance;
                let st = i.state.as_ref().and_then(|s| s.name.clone()).unwrap_or_default();
                if st == "terminated" {
                    return None;
                }
                let image_id = i.image_id.clone();
                let image_name = image_id.as_deref().and_then(|ami| {
                    catalog::public_image(region, ami)
                        .map(|p| p.name.to_string())
                        .or_else(|| r.images.get(ami).and_then(|x| x.image.name.clone()))
                });
                Some(InstanceDetails {
                    instance_id: id.clone(),
                    state: st,
                    private_ip: i.private_ip_address.clone(),
                    private_dns_name: i.private_dns_name.clone(),
                    image_id,
                    image_name,
                    platform_details: i.platform_details.clone(),
                    iam_instance_profile_arn: r
                        .iam_associations
                        .values()
                        .find(|a| {
                            a.instance_id.as_deref() == Some(id.as_str()) && a.state.as_deref() == Some("associated")
                        })
                        .and_then(|a| a.iam_instance_profile.as_ref())
                        .and_then(|p| p.arn.clone())
                        .or_else(|| i.iam_instance_profile.as_ref().and_then(|p| p.arn.clone())),
                    launch_time: i.launch_time,
                    tags: i
                        .tags
                        .iter()
                        .flatten()
                        .filter_map(|t| Some((t.key.clone()?, t.value.clone().unwrap_or_default())))
                        .collect(),
                })
            })
            .collect()
    }

    /// Elastic IP allocation `allocation_id` in `account` and `region`.
    pub fn address_summary(&self, account: &str, region: &str, allocation_id: &str) -> Option<AddressSummary> {
        self.read_region(account, region, |r| {
            let a = r.addresses.get(allocation_id)?;
            Some(AddressSummary {
                allocation_id: allocation_id.to_string(),
                public_ip: a.public_ip.clone(),
                instance_id: a.instance_id.clone(),
                network_interface_id: a.network_interface_id.clone(),
            })
        })
    }

    /// Subnet `id` in `account` and `region`.
    pub fn subnet_summary(&self, account: &str, region: &str, id: &str) -> Option<SubnetSummary> {
        self.read_region(account, region, |r| {
            let s = r.subnets.get(id)?;
            Some(SubnetSummary {
                subnet_id: id.to_string(),
                vpc_id: s.vpc_id.clone(),
                cidr_block: s.cidr_block.clone(),
                availability_zone: s.availability_zone.clone(),
            })
        })
    }
}

impl Ec2 {
    /// After a call that may have changed VPC state, keep instances'
    /// traffic filtering in line with it.
    fn after_action(&self, ctx: &RequestContext, action: &str) {
        if action.starts_with("Describe") || action.starts_with("Get") {
            return;
        }
        self.note_endpoint(ctx.endpoint.as_deref());
        self.sync_firewalls();
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
impl Service for Ec2 {
    fn signing_name(&self) -> &'static str {
        "ec2"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        if request.uri().path().starts_with(imds::PREFIX) {
            return imds::serve(self, &ctx, &request).await;
        }
        if request.uri().path().starts_with(console::PREFIX) {
            return console::serve(self, &ctx, &request).await;
        }
        let params = mws_proto_ec2::read_params(&request);
        let action = params.get("Action").unwrap_or_default().to_string();
        let response = generated::dispatch(self, &ctx, &params).await;
        self.after_action(&ctx, &action);
        response
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        // EC2 names authentication failures its own way.
        let mut e = error.clone();
        if e.code == "InvalidClientTokenId" {
            e.code = "AuthFailure".into();
            e.message = "AWS was not able to validate the provided access credentials".into();
        }
        mws_proto_ec2::error_response(request_id, &e)
    }

    fn accepts_unsigned(&self, request: &HttpRequest) -> bool {
        request.uri().path().starts_with(imds::PREFIX)
    }

    async fn invoke(
        &self,
        ctx: RequestContext,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        let out = generated::invoke(self, &ctx, operation, input).await;
        self.after_action(&ctx, operation);
        out
    }

    fn export_state(&self) -> Option<serde_json::Value> {
        serde_json::to_value(&*self.lock()).ok()
    }

    fn import_state(&self, state: serde_json::Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid EC2 state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        let old = std::mem::take(&mut *self.lock());
        // Tear down what the backend runs for the old state.
        let backend = self.backend();
        let handles: Vec<String> =
            old.regions.values().flat_map(|r| r.instances.values().filter_map(|i| i.handle.clone())).collect();
        let vpcs: Vec<String> = old.regions.values().flat_map(|r| r.vpcs.keys().cloned()).collect();
        if !handles.is_empty() || backend.name() != "metadata" {
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(async move {
                    for h in handles {
                        let _ = backend.terminate(&h).await;
                    }
                    for v in vpcs {
                        let _ = backend.delete_network(&v).await;
                    }
                });
            }
        }
    }
}

impl Ec2 {
    /// Set tags on a resource for another AWS service, which may use the
    /// reserved `aws:` prefix (`aws:autoscaling:groupName`). `None` values
    /// remove the tag.
    pub fn set_tags_as_service(&self, ctx: &RequestContext, resource_id: &str, tags: &[(String, Option<String>)]) {
        self.with_region(ctx, |r| {
            if let Some(slot) = r.tags_mut(resource_id) {
                let list = slot.get_or_insert_with(Vec::new);
                for (k, v) in tags {
                    list.retain(|t| t.key.as_deref() != Some(k.as_str()));
                    if let Some(v) = v {
                        list.push(generated::types::Tag { key: Some(k.clone()), value: Some(v.clone()) });
                    }
                }
                if list.is_empty() {
                    *slot = None;
                }
            }
        });
    }
}

//! What ECS needs from other services, where AWS couples them: network
//! interfaces in EC2 subnets for `awsvpc` tasks, role credentials from STS
//! for task and execution roles, secrets from Secrets Manager and Parameter
//! Store, and CloudWatch Logs for the `awslogs` log driver. MWS wires these
//! to its own services; without them ECS makes up network details and runs
//! tasks without credentials, secrets or logs.

use chrono::{DateTime, Utc};
use mws_core::{RequestContext, ServiceError};

/// A network interface EC2 made for a task.
#[derive(Debug, Clone, Default)]
pub struct TaskInterface {
    pub eni_id: String,
    pub private_ip: String,
    pub mac_address: String,
    pub private_dns_name: String,
    pub subnet_id: String,
    pub vpc_id: String,
    /// The VPC's primary CIDR block.
    pub vpc_cidr: String,
    pub availability_zone: String,
}

/// Temporary credentials for a role ECS assumed.
#[derive(Debug, Clone)]
pub struct RoleCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: DateTime<Utc>,
}

/// One awslogs event.
#[derive(Debug, Clone)]
pub struct LogEvent {
    pub timestamp_ms: i64,
    pub message: String,
}

/// The load balancer an Express service is reached through.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ExpressIngress {
    pub load_balancer_arn: String,
    pub listener_arn: String,
    pub target_group_arn: String,
    pub dns_name: String,
    pub subnets: Vec<String>,
    pub security_groups: Vec<String>,
}

/// An Auto Scaling group as ECS sees it through a capacity provider.
#[derive(Debug, Clone, Default)]
pub struct ScalingGroup {
    pub desired_capacity: i32,
    pub min_size: i32,
    pub max_size: i32,
    pub instances: Vec<ScalingGroupInstance>,
}

#[derive(Debug, Clone, Default)]
pub struct ScalingGroupInstance {
    pub instance_id: String,
    /// `Pending`, `InService`, `Terminating`, ...
    pub lifecycle_state: String,
    pub instance_type: String,
    pub availability_zone: String,
}

/// A container image ECS pulled from MWS's own ECR registry: everything a
/// backend needs to load it without a registry login.
#[derive(Debug, Clone, Default)]
pub struct RegistryImage {
    /// The digest the image reference resolved to (an index's, for
    /// multi-platform images): the digest the task reports.
    pub resolved_digest: String,
    /// The digest of the platform manifest below.
    pub digest: String,
    pub manifest: bytes::Bytes,
    pub manifest_media_type: String,
    pub config_digest: String,
    pub config: bytes::Bytes,
    /// `(digest, content)` of each layer, base layer first.
    pub layers: Vec<(String, bytes::Bytes)>,
}

/// Why an image could not be pulled from ECR.
#[derive(Debug, Clone)]
pub enum RegistryPullError {
    /// `ecr:GetAuthorizationToken` was denied (the registry login fails).
    Auth(ServiceError),
    /// `ecr:BatchGetImage` or `ecr:GetDownloadUrlForLayer` was denied by
    /// identity or repository policy (`403 Forbidden`).
    Denied,
    /// No such repository or image.
    NotFound,
    /// Not a runnable image (an artifact, or no manifest for the platform).
    Unsupported,
}

/// What ECS needs to know about an Elastic Load Balancing target group
/// to check a service's `loadBalancers`.
#[derive(Debug, Clone, Default)]
pub struct TargetGroupInfo {
    pub target_group_arn: String,
    /// `instance`, `ip`, `lambda` or `alb`.
    pub target_type: String,
    pub load_balancer_arns: Vec<String>,
}

#[async_trait::async_trait]
pub trait TaskPlatform: Send + Sync {
    /// Create a requester-managed network interface for a task in one of
    /// `subnets` with `security_groups` (the VPC's default group when
    /// empty). Errors are EC2's.
    #[allow(clippy::too_many_arguments)]
    fn create_interface(
        &self,
        ctx: &RequestContext,
        account: &str,
        subnets: &[String],
        security_groups: &[String],
        assign_public_ip: bool,
        description: &str,
    ) -> Result<TaskInterface, ServiceError>;

    /// Delete a task's network interface.
    fn delete_interface(&self, ctx: &RequestContext, account: &str, eni_id: &str);

    /// Assume `role_arn` as `ecs-tasks.amazonaws.com` for a task; the error
    /// says why the role cannot be assumed.
    fn assume_task_role(
        &self,
        role_arn: &str,
        task_arn: &str,
        account: &str,
        now: DateTime<Utc>,
    ) -> Result<RoleCredentials, String>;

    /// A request context whose caller is the session `credentials` belong
    /// to, with `base`'s other facts.
    fn role_context(&self, base: &RequestContext, credentials: &RoleCredentials) -> Option<RequestContext>;

    /// Read a container secret (`valueFrom`: a Secrets Manager secret ARN,
    /// optionally with `:json-key:version-stage:version-id`, or a Parameter
    /// Store parameter name or ARN) as `ctx`'s caller.
    async fn read_secret(&self, ctx: &RequestContext, value_from: &str) -> Result<String, ServiceError>;

    /// Write `awslogs` events as `ctx`'s caller, creating the stream (and
    /// the group, when `create_group`) first.
    fn write_logs(
        &self,
        ctx: &RequestContext,
        log_group: &str,
        log_stream: &str,
        create_group: bool,
        events: Vec<LogEvent>,
    ) -> Result<(), ServiceError>;

    /// The default VPC's subnets in `account` and `ctx`'s Region, for
    /// Express services created without a network configuration.
    fn default_subnets(&self, _ctx: &RequestContext, _account: &str) -> Vec<String> {
        Vec::new()
    }

    /// Register (or deregister) a task's targets with an Elastic Load
    /// Balancing target group, as ECS's service-linked role does.
    async fn update_targets(
        &self,
        _ctx: &RequestContext,
        _target_group_arn: &str,
        _targets: &[(String, i32)],
        _register: bool,
    ) -> Result<(), ServiceError> {
        Ok(())
    }

    /// A target's health in its target group (`healthy`, `unhealthy`,
    /// `initial`, ...), if Elastic Load Balancing knows it.
    async fn target_health(
        &self,
        _ctx: &RequestContext,
        _target_group_arn: &str,
        _id: &str,
        _port: i32,
    ) -> Option<String> {
        None
    }

    /// A target group, if it exists (looked up as ECS's service-linked
    /// role).
    async fn target_group(&self, _ctx: &RequestContext, _target_group_arn: &str) -> Option<TargetGroupInfo> {
        None
    }

    /// Whether `image` names a repository of MWS's own ECR registry
    /// (`<account>.dkr.ecr.<region>.amazonaws.com/...`, or the registry
    /// host MWS names repositories with). Other images are pulled by the
    /// container backend from their registry.
    fn is_registry_image(&self, _image: &str, _account: &str, _region: &str) -> bool {
        false
    }

    /// Pull an ECR image, as `ctx`'s caller (the execution role) when
    /// given: `ecr:GetAuthorizationToken`, then `ecr:BatchGetImage` and
    /// `ecr:GetDownloadUrlForLayer` under identity and repository policy.
    /// `architecture` is `amd64` or `arm64`.
    fn pull_registry_image(
        &self,
        _ctx: Option<&RequestContext>,
        _image: &str,
        _account: &str,
        _region: &str,
        _architecture: &str,
    ) -> Result<RegistryImage, RegistryPullError> {
        Err(RegistryPullError::NotFound)
    }

    /// The Auto Scaling group (by name) behind a capacity provider.
    async fn scaling_group(&self, _ctx: &RequestContext, _name: &str) -> Option<ScalingGroup> {
        None
    }

    /// Change a group's desired capacity (managed scaling).
    async fn set_desired_capacity(
        &self,
        _ctx: &RequestContext,
        _name: &str,
        _desired: i32,
    ) -> Result<(), ServiceError> {
        Ok(())
    }

    /// An instance type's vCPUs and memory (MiB).
    async fn instance_type_resources(&self, _ctx: &RequestContext, _instance_type: &str) -> Option<(i32, i32)> {
        None
    }

    /// Create the Application Load Balancer, target group and listener an
    /// Express service is reached through. `None` when no load balancing
    /// service is wired in.
    #[allow(clippy::too_many_arguments)]
    async fn create_express_ingress(
        &self,
        _ctx: &RequestContext,
        _name: &str,
        _subnets: &[String],
        _security_groups: &[String],
        _port: i32,
        _health_check_path: &str,
    ) -> Result<Option<ExpressIngress>, ServiceError> {
        Ok(None)
    }

    /// Delete what [`TaskPlatform::create_express_ingress`] made.
    async fn delete_express_ingress(&self, _ctx: &RequestContext, _ingress: &ExpressIngress) {}

    /// A task's `lastStatus` or `desiredStatus` changed: `detail` is the
    /// task as `DescribeTasks` renders it, for an `ECS Task State Change`
    /// event (EventBridge). Called with no ECS lock held.
    fn task_state_change(
        &self,
        _ctx: &RequestContext,
        _account: &str,
        _task_arn: &str,
        _detail: serde_json::Value,
        _time: chrono::DateTime<chrono::Utc>,
    ) {
    }
}

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
}

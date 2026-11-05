//! ECS state, one [`Region`] per account and Region. Resources are kept as
//! the generated wire types where ECS describes them that way; tags live
//! apart, by ARN, because ECS returns them only when asked to.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::generated::types as t;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// By `account/region`.
    pub regions: BTreeMap<String, Region>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Region {
    /// By name. Deleted clusters stay, `INACTIVE`.
    pub clusters: BTreeMap<String, t::Cluster>,
    /// Revisions by family, in order (revision `n` at index `n - 1`).
    pub task_definitions: BTreeMap<String, Vec<t::TaskDefinition>>,
    /// By task ARN.
    pub tasks: BTreeMap<String, TaskRecord>,
    /// By service ARN.
    pub services: BTreeMap<String, ServiceRecord>,
    /// By container instance ARN.
    pub container_instances: BTreeMap<String, InstanceRecord>,
    /// Custom capacity providers by name (`FARGATE` and `FARGATE_SPOT` are
    /// built in).
    pub capacity_providers: BTreeMap<String, t::CapacityProvider>,
    /// Custom attributes: (cluster name, target id) -> name -> attribute.
    pub attributes: BTreeMap<String, BTreeMap<String, t::Attribute>>,
    /// Account settings by principal ARN (the root ARN holds the account
    /// defaults), then by setting name.
    pub account_settings: BTreeMap<String, BTreeMap<String, String>>,
    /// Tags of every taggable resource, by ARN.
    pub tags: BTreeMap<String, Vec<t::Tag>>,
    /// By service deployment ARN.
    pub service_deployments: BTreeMap<String, t::ServiceDeployment>,
    /// By service revision ARN.
    pub service_revisions: BTreeMap<String, t::ServiceRevision>,
    /// Daemon task definition revisions by family.
    pub daemon_task_definitions: BTreeMap<String, Vec<t::DaemonTaskDefinition>>,
    /// By daemon ARN.
    pub daemons: BTreeMap<String, DaemonRecord>,
    pub daemon_deployments: BTreeMap<String, t::DaemonDeployment>,
    pub daemon_revisions: BTreeMap<String, t::DaemonRevision>,
    /// By gateway ARN.
    pub gateways: BTreeMap<String, t::Gateway>,
    /// (gateway ARN, cluster ARN) -> status.
    pub gateway_associations: BTreeMap<String, GatewayAssociation>,
    /// By gateway route ARN.
    pub gateway_routes: BTreeMap<String, GatewayRouteRecord>,
    /// Express gateway services by service ARN.
    pub express_services: BTreeMap<String, t::ECSExpressGatewayService>,
    /// Idempotency tokens: token -> (what it created, ARN).
    pub client_tokens: BTreeMap<String, (String, String)>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskRecord {
    pub task: t::Task,
    /// The task definition the task runs, as it was when the task started
    /// (with overrides applied to the containers).
    pub definition: t::TaskDefinition,
    pub cluster: String,
    /// The service that started it, if any.
    pub service_arn: Option<String>,
    /// The service deployment (`ecs-svc/...`) or task set it belongs to.
    pub deployment_id: Option<String>,
    /// The network interface EC2 made for an `awsvpc` task.
    pub eni_id: Option<String>,
    /// The VPC network an `awsvpc` task joined, as `(vpc id, VPC CIDR,
    /// private IP)`.
    pub vpc: Option<(String, String, String)>,
    /// What the backend runs, once it runs.
    pub handle: Option<String>,
    /// Container runtime ids by container name.
    pub runtime_ids: BTreeMap<String, String>,
    /// Whether the task ever reached `RUNNING`.
    pub reached_running: bool,
    pub protection: Option<Protection>,
    /// Credentials handed to the task's containers, if it has a task role.
    pub credentials: Option<TaskCredentials>,
    /// When a stopped task disappears from `DescribeTasks`.
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Protection {
    pub enabled: bool,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskCredentials {
    pub role_arn: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ServiceRecord {
    pub service: t::Service,
    pub cluster: String,
    /// The latest service deployment ARN and the revision it targets.
    pub current_deployment_arn: Option<String>,
    /// Deployment ids (`ecs-svc/...`) to the service revision ARN each runs.
    pub deployment_revisions: BTreeMap<String, String>,
    /// Failed task launches of the primary deployment, for the circuit
    /// breaker.
    pub failed_launches: i32,
    /// The idempotency token CreateService was called with.
    pub client_token: Option<String>,
    /// When a deleted (`DRAINING`) service goes `INACTIVE`.
    pub inactive_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct InstanceRecord {
    pub instance: t::ContainerInstance,
    pub cluster: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DaemonRecord {
    pub arn: String,
    pub name: String,
    pub cluster_arn: String,
    pub status: String,
    pub revision_arn: String,
    pub deployment_arn: String,
    pub capacity_provider_arns: Vec<String>,
    pub created_at: Option<DateTime<Utc>>,
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GatewayAssociation {
    pub gateway_arn: String,
    pub cluster_arn: String,
    pub status: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct GatewayRouteRecord {
    pub route: t::GatewayRoute,
    pub gateway_arn: String,
    pub cluster_arn: String,
}

impl State {
    pub fn region(&mut self, key: &str) -> &mut Region {
        self.regions.entry(key.to_string()).or_default()
    }
}

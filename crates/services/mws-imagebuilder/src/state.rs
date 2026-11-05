//! Image Builder state, per account and Region.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::generated::types as t;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// Keyed by `{account}/{region}`.
    pub regions: BTreeMap<String, Region>,
    /// Responses to calls with a client token, by
    /// `{account}/{region}/{operation}/{token}`.
    pub idempotency: BTreeMap<String, Idempotent>,
}

impl State {
    pub fn key(account: &str, region: &str) -> String {
        format!("{account}/{region}")
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Idempotent {
    /// A digest of the request, without its token.
    pub request: String,
    pub response: serde_json::Value,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Region {
    /// By build version ARN.
    pub components: BTreeMap<String, Versioned<t::Component>>,
    /// By ARN (`.../image-recipe/name/1.0.0`).
    pub image_recipes: BTreeMap<String, Versioned<t::ImageRecipe>>,
    pub container_recipes: BTreeMap<String, Versioned<t::ContainerRecipe>>,
    pub infrastructure: BTreeMap<String, t::InfrastructureConfiguration>,
    pub distributions: BTreeMap<String, t::DistributionConfiguration>,
    pub pipelines: BTreeMap<String, Pipeline>,
    /// By build version ARN.
    pub images: BTreeMap<String, ImageRecord>,
    /// By build version ARN.
    pub workflows: BTreeMap<String, t::Workflow>,
    pub workflow_executions: BTreeMap<String, WorkflowExecution>,
    pub step_executions: BTreeMap<String, StepExecution>,
    pub lifecycle_policies: BTreeMap<String, t::LifecyclePolicy>,
    pub lifecycle_executions: BTreeMap<String, LifecycleExecution>,
}

/// A shareable resource and its resource policy.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Versioned<T> {
    pub resource: T,
    pub policy: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Pipeline {
    pub pipeline: t::ImagePipeline,
    /// When the schedule was last checked (emulated time).
    pub schedule_checked: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ImageRecord {
    pub image: t::Image,
    pub policy: Option<String>,
    /// What the build resolved its inputs to (parent AMI, component build
    /// versions), so a scheduled pipeline can tell whether anything changed.
    pub resolved_inputs: Vec<String>,
    pub packages: Vec<t::ImagePackage>,
    /// Workflow execution ids, in order.
    pub workflow_executions: Vec<String>,
    /// `CancelImageCreation` was called.
    pub cancel_requested: bool,
    /// The AMI the build created, in the build Region, before distribution.
    pub build_ami: Option<String>,
    /// Instances the build launched and has not terminated yet.
    pub live_instances: Vec<String>,
    /// The client token of the call that created this build.
    pub client_token: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WorkflowExecution {
    pub metadata: t::WorkflowExecutionMetadata,
    pub image_build_version_arn: String,
    pub steps: Vec<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StepExecution {
    pub metadata: t::WorkflowStepMetadata,
    pub workflow_execution_id: String,
    pub workflow_build_version_arn: String,
    pub image_build_version_arn: String,
    pub on_failure: Option<String>,
    pub timeout_seconds: Option<i32>,
    /// `SendWorkflowStepAction` sent to a waiting step: `RESUME` or `STOP`.
    pub action_received: Option<String>,
    pub action_reason: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LifecycleExecution {
    pub execution: t::LifecycleExecution,
    /// The resource a `StartResourceStateUpdate` call changed, or the
    /// policy's ARN.
    pub resource_arn: String,
    pub resources: Vec<t::LifecycleExecutionResource>,
}

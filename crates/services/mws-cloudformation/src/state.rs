//! Stored stacks, resources, events and change sets.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::parameters::StackParameter;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// Every stack by id, deleted ones included (AWS shows them for 90
    /// days).
    pub stacks: BTreeMap<String, Stack>,
    pub drift_detections: BTreeMap<String, DriftDetection>,
    pub stack_sets: BTreeMap<String, crate::stacksets::StackSet>,
    pub registry: crate::registry::Registry,
    pub scans: BTreeMap<String, crate::iac::ResourceScan>,
    pub generated: BTreeMap<String, crate::iac::GeneratedTemplate>,
    pub refactors: BTreeMap<String, crate::refactor::StackRefactor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Tag {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Stack {
    pub id: String,
    pub name: String,
    pub account: String,
    pub region: String,
    pub status: String,
    pub status_reason: Option<String>,
    pub created: DateTime<Utc>,
    pub updated: Option<DateTime<Utc>>,
    pub deleted: Option<DateTime<Utc>>,
    pub description: Option<String>,
    pub template_body: String,
    pub parameters: Vec<StackParameter>,
    pub tags: Vec<Tag>,
    pub capabilities: Vec<String>,
    pub notification_arns: Vec<String>,
    pub role_arn: Option<String>,
    pub timeout_in_minutes: Option<i32>,
    pub disable_rollback: bool,
    pub termination_protection: bool,
    pub retain_except_on_create: bool,
    pub on_failure: Option<String>,
    pub outputs: Vec<StackOutput>,
    /// Resources in template order.
    pub resources: Vec<Resource>,
    /// Oldest first.
    pub events: Vec<Event>,
    pub change_sets: BTreeMap<String, ChangeSet>,
    pub policy: Option<String>,
    pub parent_id: Option<String>,
    pub root_id: Option<String>,
    pub drift_status: Option<String>,
    pub drift_checked: Option<DateTime<Utc>>,
    /// The change set the stack was last created or updated from.
    pub change_set_id: Option<String>,
    pub last_operation: Option<(String, String)>,
    /// Client request tokens of operations, for idempotent retries.
    pub request_tokens: Vec<String>,
    /// The previous deployment, kept while an update can still roll back.
    pub previous: Option<Box<Snapshot>>,
    /// Old physical resources an update replaced, deleted in its cleanup.
    pub replaced: Vec<Resource>,
    /// Export names the stack imports.
    pub imports: Vec<String>,
}

impl Default for Stack {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            account: String::new(),
            region: String::new(),
            status: String::new(),
            status_reason: None,
            created: DateTime::<Utc>::UNIX_EPOCH,
            updated: None,
            deleted: None,
            description: None,
            template_body: String::new(),
            parameters: Vec::new(),
            tags: Vec::new(),
            capabilities: Vec::new(),
            notification_arns: Vec::new(),
            role_arn: None,
            timeout_in_minutes: None,
            disable_rollback: false,
            termination_protection: false,
            retain_except_on_create: false,
            on_failure: None,
            outputs: Vec::new(),
            resources: Vec::new(),
            events: Vec::new(),
            change_sets: BTreeMap::new(),
            policy: None,
            parent_id: None,
            root_id: None,
            drift_status: None,
            drift_checked: None,
            change_set_id: None,
            last_operation: None,
            request_tokens: Vec::new(),
            previous: None,
            replaced: Vec::new(),
            imports: Vec::new(),
        }
    }
}

/// What an update replaced, to roll back to.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Snapshot {
    pub template_body: String,
    pub parameters: Vec<StackParameter>,
    pub resources: Vec<Resource>,
    pub outputs: Vec<StackOutput>,
    pub tags: Vec<Tag>,
}

impl Stack {
    pub fn is_deleted(&self) -> bool {
        self.status == "DELETE_COMPLETE"
    }

    pub fn resource(&self, logical_id: &str) -> Option<&Resource> {
        self.resources.iter().find(|r| r.logical_id == logical_id)
    }

    pub fn resource_mut(&mut self, logical_id: &str) -> Option<&mut Resource> {
        self.resources.iter_mut().find(|r| r.logical_id == logical_id)
    }

    pub fn in_progress(&self) -> bool {
        self.status.ends_with("_IN_PROGRESS")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct StackOutput {
    pub key: String,
    pub value: String,
    pub description: Option<String>,
    pub export_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Resource {
    pub logical_id: String,
    pub resource_type: String,
    pub physical_id: Option<String>,
    pub status: String,
    pub status_reason: Option<String>,
    pub updated: DateTime<Utc>,
    /// Properties as last applied (intrinsics resolved).
    pub properties: Map<String, Value>,
    /// `Fn::GetAtt` values.
    pub attributes: Map<String, Value>,
    pub metadata: Option<Value>,
    pub description: Option<String>,
    pub drift_status: Option<String>,
    pub drift_checked: Option<DateTime<Utc>>,
}

impl Default for Resource {
    fn default() -> Self {
        Self {
            logical_id: String::new(),
            resource_type: String::new(),
            physical_id: None,
            status: String::new(),
            status_reason: None,
            updated: DateTime::<Utc>::UNIX_EPOCH,
            properties: Map::new(),
            attributes: Map::new(),
            metadata: None,
            description: None,
            drift_status: None,
            drift_checked: None,
        }
    }
}

impl Resource {
    /// Whether the resource exists (was created and not deleted).
    pub fn exists(&self) -> bool {
        self.physical_id.is_some()
            && !matches!(self.status.as_str(), "DELETE_COMPLETE" | "CREATE_FAILED" | "DELETE_SKIPPED" | "")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Event {
    pub id: String,
    pub logical_id: String,
    pub physical_id: Option<String>,
    pub resource_type: String,
    pub timestamp: DateTime<Utc>,
    pub status: String,
    pub reason: Option<String>,
    pub properties: Option<String>,
    pub client_request_token: Option<String>,
    pub operation_id: Option<String>,
    pub hook_type: Option<String>,
    pub hook_status: Option<String>,
    pub hook_status_reason: Option<String>,
    pub hook_invocation_point: Option<String>,
    pub hook_invocation_id: Option<String>,
    pub hook_failure_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ChangeSet {
    pub id: String,
    pub name: String,
    pub stack_id: String,
    pub change_set_type: String,
    pub description: Option<String>,
    pub status: String,
    pub status_reason: Option<String>,
    pub execution_status: String,
    pub created: DateTime<Utc>,
    pub template_body: String,
    pub parameters: Vec<StackParameter>,
    pub tags: Option<Vec<Tag>>,
    pub capabilities: Vec<String>,
    pub notification_arns: Option<Vec<String>>,
    pub role_arn: Option<String>,
    pub changes: Vec<Value>,
    pub on_stack_failure: Option<String>,
    pub resources_to_import: BTreeMap<String, BTreeMap<String, String>>,
    pub import_existing_resources: bool,
    /// The operation that created the change set, and the one that
    /// executed it.
    pub operation_id: String,
    pub execution_operation_id: Option<String>,
}

impl Default for ChangeSet {
    fn default() -> Self {
        Self {
            id: String::new(),
            name: String::new(),
            stack_id: String::new(),
            change_set_type: "UPDATE".into(),
            description: None,
            status: String::new(),
            status_reason: None,
            execution_status: String::new(),
            created: DateTime::<Utc>::UNIX_EPOCH,
            template_body: String::new(),
            parameters: Vec::new(),
            tags: None,
            capabilities: Vec::new(),
            notification_arns: None,
            role_arn: None,
            changes: Vec::new(),
            on_stack_failure: None,
            resources_to_import: BTreeMap::new(),
            import_existing_resources: false,
            operation_id: uuid::Uuid::new_v4().to_string(),
            execution_operation_id: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DriftDetection {
    pub id: String,
    pub stack_id: String,
    pub status: String,
    pub status_reason: Option<String>,
    pub stack_drift_status: Option<String>,
    pub drifted_count: i32,
    pub timestamp: DateTime<Utc>,
    pub results: Vec<ResourceDrift>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct ResourceDrift {
    pub logical_id: String,
    pub physical_id: Option<String>,
    pub resource_type: String,
    pub expected: Option<String>,
    pub actual: Option<String>,
    pub differences: Vec<(String, String, String, String)>,
    pub status: String,
    pub timestamp: DateTime<Utc>,
}

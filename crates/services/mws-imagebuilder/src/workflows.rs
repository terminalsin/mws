//! Workflows: the steps a build, test or distribution runs, and their
//! executions.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::Value;

use crate::generated::types as t;
use crate::state::State;
use crate::util::{
    account_of, already_exists_component, arn, arn_not_found, authorize, filters_match, invalid_parameter_value,
    invalid_request, latest_references, not_found, paginate, request_tags, resource_tags, s, slug, Arn, Version,
    VersionPattern,
};
use crate::yaml;
use crate::{managed, ImageBuilder};

pub const STEP_ACTIONS: &[&str] = &[
    "ApplyImageConfigurations",
    "BootstrapInstanceForContainer",
    "CollectImageMetadata",
    "CollectImageScanFindings",
    "CreateImage",
    "DistributeImage",
    "ExecuteComponents",
    "ExecuteStateMachine",
    "LaunchInstance",
    "ModifyImageAttributes",
    "RegisterImage",
    "RunCommand",
    "RunSysPrepScript",
    "SanitizeInstance",
    "TerminateInstance",
    "WaitForAction",
    "WaitForSSMAgent",
];

/// One step of a workflow document.
#[derive(Debug, Clone)]
pub struct StepDef {
    pub name: String,
    pub action: String,
    pub description: Option<String>,
    pub on_failure: String,
    pub timeout_seconds: Option<i32>,
    pub inputs: Value,
    pub condition: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct WorkflowDocument {
    pub steps: Vec<StepDef>,
    pub parameters: Vec<t::WorkflowParameterDetail>,
}

impl WorkflowDocument {
    pub fn parse(text: &str) -> Result<WorkflowDocument, String> {
        let doc = yaml::parse(text).map_err(|e| format!("The document is not valid YAML: {e}"))?;
        if doc.get("schemaVersion").and_then(yaml::text).is_none() {
            return Err("The document is missing the required property 'schemaVersion'.".into());
        }
        let steps = doc
            .get("steps")
            .and_then(Value::as_array)
            .filter(|s| !s.is_empty())
            .ok_or("The document must contain at least one step.")?;
        let mut out = Vec::new();
        for st in steps {
            let name = st.get("name").and_then(yaml::text).ok_or("Every step must have a name.")?;
            if out.iter().any(|s: &StepDef| s.name == name) {
                return Err(format!("The step name '{name}' is used more than once."));
            }
            let action = st
                .get("action")
                .and_then(Value::as_str)
                .ok_or_else(|| format!("The step '{name}' must have an action."))?;
            if !STEP_ACTIONS.contains(&action) {
                return Err(format!("The action '{action}' of step '{name}' is not a valid step action."));
            }
            let on_failure = st.get("onFailure").and_then(Value::as_str).unwrap_or("Abort");
            if !matches!(on_failure, "Abort" | "Continue") {
                return Err(format!("The onFailure value '{on_failure}' of step '{name}' is not valid."));
            }
            out.push(StepDef {
                name,
                action: action.to_string(),
                description: st.get("description").and_then(yaml::text),
                on_failure: on_failure.to_string(),
                timeout_seconds: st.get("timeoutSeconds").and_then(Value::as_i64).map(|v| v as i32),
                inputs: st.get("inputs").cloned().unwrap_or(Value::Null),
                condition: st.get("if").cloned(),
            });
        }
        let mut parameters = Vec::new();
        for p in doc.get("parameters").and_then(Value::as_array).into_iter().flatten() {
            let name = p.get("name").and_then(yaml::text).ok_or("Every parameter must have a name.")?;
            let ty = p.get("type").and_then(Value::as_str).unwrap_or("string");
            if !matches!(ty, "string" | "integer" | "boolean" | "stringList") {
                return Err(format!("The type '{ty}' of parameter '{name}' is not valid."));
            }
            parameters.push(t::WorkflowParameterDetail {
                name,
                r#type: ty.to_string(),
                default_value: p.get("default").map(|d| match d {
                    Value::Array(a) => a.iter().filter_map(yaml::text).collect(),
                    other => yaml::text(other).into_iter().collect(),
                }),
                description: p.get("description").and_then(yaml::text),
            });
        }
        Ok(WorkflowDocument { steps: out, parameters })
    }
}

fn version_of(w: &t::Workflow) -> Version {
    w.version.as_deref().and_then(Version::parse).unwrap_or(Version(0, 0, 0))
}

fn build_of(w: &t::Workflow) -> u32 {
    w.arn.as_deref().and_then(Arn::parse).and_then(|a| a.build).unwrap_or(1)
}

impl ImageBuilder {
    fn workflow_builds(&self, a: &Arn) -> Vec<t::Workflow> {
        if a.account == "aws" {
            return managed::workflows(&a.partition, &a.region)
                .into_iter()
                .filter(|w| {
                    w.name.as_deref() == Some(a.name.as_str())
                        && Arn::parse(w.arn.as_deref().unwrap_or_default()).is_some_and(|x| x.kind == a.kind)
                })
                .collect();
        }
        let st = self.lock();
        let Some(r) = st.regions.get(&State::key(&a.account, &a.region)) else { return Vec::new() };
        r.workflows
            .values()
            .filter(|w| w.arn.as_deref().and_then(Arn::parse).is_some_and(|x| x.name == a.name && x.kind == a.kind))
            .cloned()
            .collect()
    }

    /// Resolve a workflow ARN (build version, version or wildcard).
    pub(crate) fn resolve_workflow(&self, arn_text: &str) -> Option<t::Workflow> {
        let a = Arn::parse(arn_text).filter(|a| a.kind.starts_with("workflow/"))?;
        let pattern = VersionPattern::parse(a.version.as_deref()?)?;
        self.workflow_builds(&a)
            .into_iter()
            .filter(|w| pattern.matches(version_of(w)))
            .filter(|w| a.build.is_none_or(|b| b == build_of(w)))
            .max_by_key(|w| (version_of(w), build_of(w)))
    }

    fn latest_workflow_references(&self, w: &t::Workflow) -> Option<t::LatestVersionReferences> {
        let a = Arn::parse(w.arn.as_deref()?)?;
        let builds: Vec<(Version, u32)> =
            self.workflow_builds(&a).iter().map(|w| (version_of(w), build_of(w))).collect();
        Some(latest_references(&a.base(), version_of(w), builds.into_iter()))
    }

    pub(crate) async fn create_workflow_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateWorkflowRequest,
    ) -> Result<t::CreateWorkflowResponse, ServiceError> {
        let account = account_of(ctx);
        let kind = input.r#type.to_lowercase();
        let target = arn(ctx, &account, &format!("workflow/{kind}/{}/{}/1", slug(&input.name), input.semantic_version));
        authorize(ctx, "CreateWorkflow", &target, request_tags(&input.tags))?;
        if input.dry_run {
            return Err(crate::util::dry_run_ok());
        }
        let token = input.client_token.clone();
        self.idempotent(ctx, "CreateWorkflow", &token, &input.clone(), async {
            let v = Version::for_create(&input.semantic_version)?;
            let text = match (&input.data, &input.uri) {
                (Some(d), None) => d.clone(),
                (None, Some(u)) => self.document_from_uri(ctx, u).await?,
                _ => {
                    return Err(crate::util::invalid_combination(
                        "You must specify either 'data' or 'uri', but not both.",
                    ))
                }
            };
            let doc = WorkflowDocument::parse(&text).map_err(|e| {
                invalid_parameter_value(format!("The value supplied for parameter 'data' is not valid. {e}"))
            })?;
            let build_arn = arn(ctx, &account, &format!("workflow/{kind}/{}/{v}/1", slug(&input.name)));
            let workflow = t::Workflow {
                arn: Some(build_arn.clone()),
                name: Some(input.name.clone()),
                version: Some(v.to_string()),
                description: input.description.clone(),
                change_description: input.change_description.clone(),
                r#type: Some(input.r#type.clone()),
                state: Some(t::WorkflowState { status: Some("ACTIVE".into()), reason: None }),
                owner: Some(account.clone()),
                data: Some(text),
                kms_key_id: input.kms_key_id.clone(),
                date_created: Some(crate::util::now(ctx)),
                tags: Some(input.tags.clone().unwrap_or_default()),
                parameters: (!doc.parameters.is_empty()).then_some(doc.parameters),
            };
            self.with_region(ctx, |r| {
                if r.workflows.contains_key(&build_arn) {
                    return Err(already_exists_component(
                        &Arn::parse(&build_arn).map(|a| a.version_arn()).unwrap_or_default(),
                    ));
                }
                r.workflows.insert(build_arn.clone(), workflow.clone());
                Ok(())
            })?;
            Ok(t::CreateWorkflowResponse {
                client_token: Some(token.clone()),
                workflow_build_version_arn: Some(build_arn),
                latest_version_references: self.latest_workflow_references(&workflow),
            })
        })
        .await
    }

    pub(crate) fn get_workflow_op(
        &self,
        ctx: &RequestContext,
        input: t::GetWorkflowRequest,
    ) -> Result<t::GetWorkflowResponse, ServiceError> {
        let target = input.workflow_build_version_arn.clone();
        let found = self.resolve_workflow(&target);
        let tags = found.as_ref().and_then(|w| w.tags.clone());
        authorize(
            ctx,
            "GetWorkflow",
            found.as_ref().and_then(|w| w.arn.as_deref()).unwrap_or(&target),
            resource_tags(&tags),
        )?;
        let w = found.ok_or_else(|| arn_not_found(&target))?;
        if Arn::parse(&target).is_some_and(|a| a.account != "aws" && a.account != account_of(ctx)) {
            return Err(arn_not_found(&target));
        }
        let latest = self.latest_workflow_references(&w);
        Ok(t::GetWorkflowResponse { workflow: Some(w), latest_version_references: latest })
    }

    pub(crate) fn list_workflows_op(
        &self,
        ctx: &RequestContext,
        input: t::ListWorkflowsRequest,
    ) -> Result<t::ListWorkflowsResponse, ServiceError> {
        authorize(ctx, "ListWorkflows", &arn(ctx, &account_of(ctx), "workflow/*"), ConditionContext::new())?;
        let owner = input.owner.clone().unwrap_or_else(|| "Self".into());
        let all: Vec<t::Workflow> = match owner.as_str() {
            "Amazon" => managed::workflows(&ctx.partition, &ctx.region),
            "Self" => self.with_region(ctx, |r| r.workflows.values().cloned().collect()),
            _ => Vec::new(),
        };
        let mut by_version: BTreeMap<String, t::Workflow> = BTreeMap::new();
        for w in all {
            let ok = filters_match(&input.filters, &["name", "version", "type"], |n| match n {
                "name" => s(&w.name),
                "version" => s(&w.version),
                _ => s(&w.r#type),
            })?;
            if !ok {
                continue;
            }
            let key = Arn::parse(w.arn.as_deref().unwrap_or_default()).map(|a| a.version_arn()).unwrap_or_default();
            if by_version.get(&key).is_none_or(|p| build_of(p) < build_of(&w)) {
                by_version.insert(key, w);
            }
        }
        let mut list: Vec<(String, t::Workflow)> = by_version.into_iter().collect();
        if input.by_name {
            let mut latest: BTreeMap<String, (String, t::Workflow)> = BTreeMap::new();
            for (k, w) in list {
                let base = Arn::parse(&k).map(|a| a.base()).unwrap_or_default();
                if latest.get(&base).is_none_or(|(_, p)| version_of(p) < version_of(&w)) {
                    latest.insert(base, (k, w));
                }
            }
            list = latest.into_values().collect();
        }
        list.sort_by(|a, b| a.0.cmp(&b.0));
        let versions = list
            .into_iter()
            .map(|(k, w)| t::WorkflowVersion {
                arn: Some(k),
                name: w.name,
                version: w.version,
                description: w.description,
                r#type: w.r#type,
                owner: w.owner,
                date_created: w.date_created,
            })
            .collect();
        let (page, next_token) = paginate(versions, input.max_results, &input.next_token)?;
        Ok(t::ListWorkflowsResponse { workflow_version_list: Some(page), next_token })
    }

    pub(crate) fn list_workflow_build_versions_op(
        &self,
        ctx: &RequestContext,
        input: t::ListWorkflowBuildVersionsRequest,
    ) -> Result<t::ListWorkflowBuildVersionsResponse, ServiceError> {
        let target = input
            .workflow_version_arn
            .clone()
            .ok_or_else(|| invalid_request("The workflowVersionArn parameter is required."))?;
        authorize(ctx, "ListWorkflowBuildVersions", &target, ConditionContext::new())?;
        let a = Arn::parse(&target).ok_or_else(|| arn_not_found(&target))?;
        let pattern = a.version.as_deref().and_then(VersionPattern::parse).ok_or_else(|| arn_not_found(&target))?;
        let mut builds: Vec<t::Workflow> =
            self.workflow_builds(&a).into_iter().filter(|w| pattern.matches(version_of(w))).collect();
        builds.sort_by_key(|w| (version_of(w), build_of(w)));
        let summaries = builds
            .into_iter()
            .map(|w| t::WorkflowSummary {
                arn: w.arn,
                name: w.name,
                version: w.version,
                description: w.description,
                change_description: w.change_description,
                r#type: w.r#type,
                owner: w.owner,
                state: w.state,
                date_created: w.date_created,
                tags: w.tags,
            })
            .collect();
        let (page, next_token) = paginate(summaries, input.max_results, &input.next_token)?;
        Ok(t::ListWorkflowBuildVersionsResponse { workflow_summary_list: Some(page), next_token })
    }

    pub(crate) fn delete_workflow_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteWorkflowRequest,
    ) -> Result<t::DeleteWorkflowResponse, ServiceError> {
        let target = input.workflow_build_version_arn.clone();
        let tags = self.with_region(ctx, |r| r.workflows.get(&target).map(|w| w.tags.clone()));
        authorize(ctx, "DeleteWorkflow", &target, resource_tags(&tags.clone().flatten()))?;
        if tags.is_none() {
            return Err(arn_not_found(&target));
        }
        let users: Vec<String> = self.with_region(ctx, |r| {
            r.pipelines
                .iter()
                .filter(|(_, p)| p.pipeline.workflows.iter().flatten().any(|w| self_resolves(&w.workflow_arn, &target)))
                .map(|(k, _)| k.clone())
                .collect()
        });
        if !users.is_empty() {
            return Err(crate::util::dependency(format!(
                "Resource dependency error: The resource ARN '{target}' has the following dependencies: {}.",
                users.join(", ")
            )));
        }
        self.with_region(ctx, |r| r.workflows.remove(&target));
        Ok(t::DeleteWorkflowResponse { workflow_build_version_arn: Some(target) })
    }

    // ---- executions ------------------------------------------------------------

    pub(crate) fn get_workflow_execution_op(
        &self,
        ctx: &RequestContext,
        input: t::GetWorkflowExecutionRequest,
    ) -> Result<t::GetWorkflowExecutionResponse, ServiceError> {
        let id = input.workflow_execution_id.clone();
        let found = self.with_region(ctx, |r| r.workflow_executions.get(&id).cloned());
        authorize(
            ctx,
            "GetWorkflowExecution",
            found.as_ref().map(|e| e.image_build_version_arn.as_str()).unwrap_or("*"),
            ConditionContext::new(),
        )?;
        let e = found.ok_or_else(|| not_found(format!("The workflow execution '{id}' does not exist.")))?;
        let m = e.metadata;
        Ok(t::GetWorkflowExecutionResponse {
            request_id: Some(ctx.request_id.clone()),
            workflow_build_version_arn: m.workflow_build_version_arn,
            workflow_execution_id: m.workflow_execution_id,
            image_build_version_arn: Some(e.image_build_version_arn),
            r#type: m.r#type,
            status: m.status,
            message: m.message,
            total_step_count: m.total_step_count,
            total_steps_succeeded: m.total_steps_succeeded,
            total_steps_failed: m.total_steps_failed,
            total_steps_skipped: m.total_steps_skipped,
            start_time: m.start_time,
            end_time: m.end_time,
            parallel_group: m.parallel_group,
        })
    }

    pub(crate) fn get_workflow_step_execution_op(
        &self,
        ctx: &RequestContext,
        input: t::GetWorkflowStepExecutionRequest,
    ) -> Result<t::GetWorkflowStepExecutionResponse, ServiceError> {
        let id = input.step_execution_id.clone();
        let found = self.with_region(ctx, |r| r.step_executions.get(&id).cloned());
        authorize(
            ctx,
            "GetWorkflowStepExecution",
            found.as_ref().map(|e| e.image_build_version_arn.as_str()).unwrap_or("*"),
            ConditionContext::new(),
        )?;
        let st = found.ok_or_else(|| not_found(format!("The workflow step execution '{id}' does not exist.")))?;
        let m = st.metadata;
        Ok(t::GetWorkflowStepExecutionResponse {
            request_id: Some(ctx.request_id.clone()),
            step_execution_id: m.step_execution_id,
            workflow_build_version_arn: Some(st.workflow_build_version_arn),
            workflow_execution_id: Some(st.workflow_execution_id),
            image_build_version_arn: Some(st.image_build_version_arn),
            name: m.name,
            description: m.description,
            action: m.action,
            status: m.status,
            rollback_status: m.rollback_status,
            message: m.message,
            inputs: m.inputs,
            outputs: m.outputs,
            start_time: m.start_time,
            end_time: m.end_time,
            on_failure: st.on_failure,
            timeout_seconds: st.timeout_seconds,
            attempt_number: m.attempt_number,
            max_attempts: m.max_attempts,
        })
    }

    pub(crate) fn list_workflow_executions_op(
        &self,
        ctx: &RequestContext,
        input: t::ListWorkflowExecutionsRequest,
    ) -> Result<t::ListWorkflowExecutionsResponse, ServiceError> {
        let image = input.image_build_version_arn.clone();
        authorize(ctx, "ListWorkflowExecutions", &image, ConditionContext::new())?;
        let (ids, message, all) = self
            .with_region(ctx, |r| {
                let rec = r.images.get(&image)?;
                Some((
                    rec.workflow_executions.clone(),
                    rec.image.state.as_ref().and_then(|s| s.reason.clone()),
                    r.workflow_executions.clone(),
                ))
            })
            .ok_or_else(|| arn_not_found(&image))?;
        let list: Vec<t::WorkflowExecutionMetadata> =
            ids.iter().filter_map(|id| all.get(id).map(|e| e.metadata.clone())).collect();
        let (page, next_token) = paginate(list, input.max_results, &input.next_token)?;
        Ok(t::ListWorkflowExecutionsResponse {
            request_id: Some(ctx.request_id.clone()),
            workflow_executions: Some(page),
            image_build_version_arn: Some(image),
            message,
            next_token,
        })
    }

    pub(crate) fn list_workflow_step_executions_op(
        &self,
        ctx: &RequestContext,
        input: t::ListWorkflowStepExecutionsRequest,
    ) -> Result<t::ListWorkflowStepExecutionsResponse, ServiceError> {
        let id = input.workflow_execution_id.clone();
        let found = self.with_region(ctx, |r| {
            let e = r.workflow_executions.get(&id)?.clone();
            let steps: Vec<t::WorkflowStepMetadata> =
                e.steps.iter().filter_map(|s| r.step_executions.get(s).map(|x| x.metadata.clone())).collect();
            Some((e, steps))
        });
        authorize(
            ctx,
            "ListWorkflowStepExecutions",
            found.as_ref().map(|(e, _)| e.image_build_version_arn.as_str()).unwrap_or("*"),
            ConditionContext::new(),
        )?;
        let (e, steps) = found.ok_or_else(|| not_found(format!("The workflow execution '{id}' does not exist.")))?;
        let (page, next_token) = paginate(steps, input.max_results, &input.next_token)?;
        Ok(t::ListWorkflowStepExecutionsResponse {
            request_id: Some(ctx.request_id.clone()),
            steps: Some(page),
            workflow_build_version_arn: e.metadata.workflow_build_version_arn,
            workflow_execution_id: Some(id),
            image_build_version_arn: Some(e.image_build_version_arn),
            message: e.metadata.message,
            next_token,
        })
    }

    pub(crate) fn list_waiting_workflow_steps_op(
        &self,
        ctx: &RequestContext,
        input: t::ListWaitingWorkflowStepsRequest,
    ) -> Result<t::ListWaitingWorkflowStepsResponse, ServiceError> {
        authorize(ctx, "ListWaitingWorkflowSteps", "*", ConditionContext::new())?;
        let steps: Vec<t::WorkflowStepExecution> = self.with_region(ctx, |r| {
            r.step_executions
                .values()
                .filter(|s| {
                    s.metadata.action.as_deref() == Some("WaitForAction")
                        && s.metadata.status.as_deref() == Some("RUNNING")
                        && s.action_received.is_none()
                })
                .map(|s| t::WorkflowStepExecution {
                    step_execution_id: s.metadata.step_execution_id.clone(),
                    image_build_version_arn: Some(s.image_build_version_arn.clone()),
                    workflow_execution_id: Some(s.workflow_execution_id.clone()),
                    workflow_build_version_arn: Some(s.workflow_build_version_arn.clone()),
                    name: s.metadata.name.clone(),
                    action: s.metadata.action.clone(),
                    start_time: s.metadata.start_time.clone(),
                })
                .collect()
        });
        let (page, next_token) = paginate(steps, input.max_results, &input.next_token)?;
        Ok(t::ListWaitingWorkflowStepsResponse { steps: Some(page), next_token })
    }

    pub(crate) async fn send_workflow_step_action_op(
        &self,
        ctx: &RequestContext,
        input: t::SendWorkflowStepActionRequest,
    ) -> Result<t::SendWorkflowStepActionResponse, ServiceError> {
        authorize(ctx, "SendWorkflowStepAction", &input.image_build_version_arn, ConditionContext::new())?;
        let token = input.client_token.clone();
        self.idempotent(ctx, "SendWorkflowStepAction", &token, &input.clone(), async {
            let id = input.step_execution_id.clone();
            self.with_region(ctx, |r| {
                let st = r
                    .step_executions
                    .get_mut(&id)
                    .filter(|s| s.image_build_version_arn == input.image_build_version_arn)
                    .ok_or_else(|| not_found(format!("The workflow step execution '{id}' does not exist.")))?;
                let waiting = st.metadata.action.as_deref() == Some("WaitForAction")
                    && st.metadata.status.as_deref() == Some("RUNNING")
                    && st.action_received.is_none();
                if !waiting {
                    return Err(crate::util::in_use(format!(
                        "The workflow step execution '{id}' is not waiting for an action."
                    )));
                }
                st.action_received = Some(input.action.clone());
                st.action_reason = input.reason.clone();
                Ok(())
            })?;
            Ok(t::SendWorkflowStepActionResponse {
                step_execution_id: Some(id.clone()),
                image_build_version_arn: Some(input.image_build_version_arn.clone()),
                client_token: Some(token.clone()),
            })
        })
        .await
    }
}

/// Whether workflow reference `reference` (possibly a wildcard) covers the
/// build version `build_arn`.
fn self_resolves(reference: &str, build_arn: &str) -> bool {
    let (Some(r), Some(b)) = (Arn::parse(reference), Arn::parse(build_arn)) else { return false };
    r.account == b.account
        && r.kind == b.kind
        && r.name == b.name
        && r.version
            .as_deref()
            .and_then(VersionPattern::parse)
            .is_some_and(|p| b.version.as_deref().and_then(Version::parse).is_some_and(|v| p.matches(v)))
}

/// Check a build's workflow configuration: each workflow exists, and its
/// parameters are declared.
pub fn check_workflow_parameters(w: &t::Workflow, config: &t::WorkflowConfiguration) -> Result<(), ServiceError> {
    let declared = w.parameters.clone().unwrap_or_default();
    for p in config.parameters.iter().flatten() {
        if !declared.iter().any(|d| d.name == p.name) {
            return Err(invalid_parameter_value(format!(
                "The parameter '{}' is not defined in workflow '{}'.",
                p.name,
                w.arn.clone().unwrap_or_default()
            )));
        }
    }
    if let Some(f) = &config.on_failure {
        if !matches!(f.as_str(), "CONTINUE" | "ABORT") {
            return Err(invalid_parameter_value(format!("The onFailure value '{f}' is not valid.")));
        }
    }
    Ok(())
}

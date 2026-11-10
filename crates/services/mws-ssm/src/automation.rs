//! Systems Manager Automation: runbooks (Automation documents) run step by
//! step ([`crate::engine`]) as the caller or the runbook's assume role,
//! calling the other MWS services' APIs through an [`AutomationRuntime`]
//! the composition root provides. Rate control fans an execution out over
//! targets, target locations run it in other accounts and Regions, Change
//! Manager change requests wait for approval and their scheduled time
//! before running their runbooks, and execution previews say what a
//! runbook would touch.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::documents::{parse_content, pick_version};
use crate::generated::{errors, types};
use crate::names::{now, page, pass_role, request_tag_conditions};
use crate::Ssm;

/// Credentials code that runs for an execution signs with
/// (`aws:executeScript`).
#[derive(Debug, Clone)]
pub struct ScriptCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

/// How Automation reaches the rest of MWS.
#[async_trait::async_trait]
pub trait AutomationRuntime: Send + Sync {
    /// The identity (and credentials) `role_arn` gives when
    /// `ssm.amazonaws.com` assumes it for `source_arn`, in `ctx`'s account
    /// and Region.
    fn assume_role(
        &self,
        ctx: &RequestContext,
        role_arn: &str,
        source_arn: &str,
    ) -> Result<(RequestContext, ScriptCredentials), String>;

    /// The identity `ctx`'s caller gets by assuming `role_arn` through STS
    /// `AssumeRole` (role chaining: the Automation administration role
    /// assuming execution roles in target accounts).
    async fn chain_role(
        &self,
        ctx: &RequestContext,
        role_arn: &str,
        session_name: &str,
    ) -> Result<RequestContext, String>;

    /// Credentials of `ctx`'s caller, for scripts of executions without an
    /// assume role. `None` when they cannot be handed out.
    fn credentials_of(&self, ctx: &RequestContext) -> Option<ScriptCredentials>;

    /// Run `operation` of the service AWS SDKs call `service` (`ec2`,
    /// `s3`, `cloudwatch`, ...), with its input and output keyed by Smithy
    /// member names, as `ctx`'s caller.
    async fn call(
        &self,
        ctx: &RequestContext,
        service: &str,
        operation: &str,
        input: Value,
    ) -> Result<Value, ServiceError>;
}

/// A signal sent to a running execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Signal {
    pub signal_type: String,
    pub payload: BTreeMap<String, Vec<String>>,
    /// Who sent it.
    pub sender: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct AutomationRecord {
    pub execution: types::AutomationExecution,
    /// `Local` or `CrossAccount`.
    pub automation_type: String,
    pub tags: Vec<types::Tag>,
    pub client_token: Option<String>,
    /// Signals the engine has not consumed yet.
    pub signals: Vec<Signal>,
    /// `Cancel` or `Complete` once `StopAutomationExecution` asked.
    pub stop: Option<String>,
    pub change_details: Option<String>,
    pub scheduled_end_time: Option<DateTime<Utc>>,
    pub auto_approve: bool,
    /// The execution status last reported to EventBridge.
    pub reported: String,
    /// Each step's status last reported, by position.
    pub reported_steps: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct PreviewRecord {
    pub result: types::GetExecutionPreviewResponse,
}

/// What a new execution runs.
#[derive(Debug, Clone, Default)]
pub(crate) struct StartSpec {
    pub document_name: String,
    pub document_version: Option<String>,
    pub parameters: BTreeMap<String, Vec<String>>,
    pub mode: Option<String>,
    pub target_parameter_name: Option<String>,
    pub targets: Vec<types::Target>,
    pub target_maps: Vec<BTreeMap<String, Vec<String>>>,
    pub max_concurrency: Option<String>,
    pub max_errors: Option<String>,
    pub target_locations: Vec<types::TargetLocation>,
    pub tags: Vec<types::Tag>,
    pub alarm_configuration: Option<types::AlarmConfiguration>,
    pub client_token: Option<String>,
    pub parent: Option<String>,
    /// The single target value of a rate-control child.
    pub target: Option<String>,
    pub automation_type: Option<String>,
    pub change: Option<ChangeSpec>,
    /// Whether the caller must be able to pass the roles the execution
    /// assumes (`iam:PassRole`): set for executions a caller starts, not
    /// for those Systems Manager starts itself.
    pub pass_roles: bool,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ChangeSpec {
    pub name: Option<String>,
    pub scheduled_time: Option<DateTime<Utc>>,
    pub scheduled_end_time: Option<DateTime<Utc>>,
    pub runbooks: Vec<types::Runbook>,
    pub auto_approve: bool,
    pub change_details: Option<String>,
}

pub(crate) const TERMINAL: &[&str] = &[
    "Success",
    "Failed",
    "Cancelled",
    "TimedOut",
    "Rejected",
    "CompletedWithSuccess",
    "CompletedWithFailure",
    "Exited",
];

pub(crate) fn execution_arn(partition: &str, region: &str, account: &str, id: &str) -> String {
    format!("arn:{partition}:ssm:{region}:{account}:automation-execution/{id}")
}

fn definition_arn(ctx: &RequestContext, name: &str) -> String {
    if name.starts_with("arn:") {
        return name.replace(":document/", ":automation-definition/");
    }
    format!("arn:{}:ssm:{}:{}:automation-definition/{name}", ctx.partition, ctx.region, ctx.caller.account_id)
}

fn not_found(id: &str) -> ServiceError {
    errors::automation_execution_not_found(format!("Automation execution {id} could not be found."))
}

/// A document parameter's value as the type it declares.
pub(crate) fn typed_value(name: &str, kind: &str, values: &[String]) -> Result<Value, ServiceError> {
    let bad = |what: &str| {
        errors::invalid_automation_execution_parameters(format!(
            "Parameter \"{name}\" has value {values:?} not of type {what}."
        ))
    };
    let first = values.first().cloned().unwrap_or_default();
    Ok(match kind {
        "StringList" => Value::Array(values.iter().cloned().map(Value::String).collect()),
        "Integer" => Value::from(first.trim().parse::<i64>().map_err(|_| bad("Integer"))?),
        "Boolean" => Value::Bool(match first.trim().to_ascii_lowercase().as_str() {
            "true" => true,
            "false" => false,
            _ => return Err(bad("Boolean")),
        }),
        "StringMap" => match serde_json::from_str::<Value>(&first) {
            Ok(v @ Value::Object(_)) => v,
            _ => return Err(bad("StringMap")),
        },
        "MapList" => {
            if values.len() == 1 && first.trim_start().starts_with('[') {
                match serde_json::from_str::<Value>(&first) {
                    Ok(v @ Value::Array(_)) => v,
                    _ => return Err(bad("MapList")),
                }
            } else {
                let mut out = Vec::new();
                for v in values {
                    match serde_json::from_str::<Value>(v) {
                        Ok(m @ Value::Object(_)) => out.push(m),
                        _ => return Err(bad("MapList")),
                    }
                }
                Value::Array(out)
            }
        }
        _ => Value::String(first),
    })
}

pub(crate) type TypedParams = BTreeMap<String, Value>;
pub(crate) type StringParams = BTreeMap<String, Vec<String>>;

/// A value as the strings the API reports it with.
pub(crate) fn strings_of(v: &Value) -> Vec<String> {
    match v {
        Value::Null => Vec::new(),
        Value::String(s) => vec![s.clone()],
        Value::Array(items) => items
            .iter()
            .map(|i| match i {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            })
            .collect(),
        other => vec![other.to_string()],
    }
}

/// The role an Automation document assumes (its `assumeRole`, usually
/// `{{ AutomationAssumeRole }}`) with `given` parameters and defaults
/// filled in; `None` when it assumes none.
pub(crate) fn assume_role_of(content: &Value, given: &StringParams) -> Option<String> {
    let raw = content.get("assumeRole")?;
    let typed = match resolve_parameters(content, given, None) {
        Ok((typed, _)) => typed,
        Err(_) => given.iter().map(|(k, v)| (k.clone(), Value::String(v.join(",")))).collect(),
    };
    let role = strings_of(&crate::engine::substitute(raw, &typed)).join("");
    let role = role.trim().to_string();
    (!role.is_empty() && !role.contains("{{")).then_some(role)
}

/// The document's parameters with the given values and defaults, typed,
/// and as strings; `skip` may be missing (the target parameter of a
/// rate-control parent).
pub(crate) fn resolve_parameters(
    content: &Value,
    given: &BTreeMap<String, Vec<String>>,
    skip: Option<&str>,
) -> Result<(TypedParams, StringParams), ServiceError> {
    let declared = content.get("parameters").and_then(Value::as_object).cloned().unwrap_or_default();
    let unknown: Vec<&String> = given.keys().filter(|k| !declared.contains_key(*k)).collect();
    if !unknown.is_empty() {
        return Err(errors::invalid_automation_execution_parameters(format!(
            "Parameters {unknown:?} are not defined in the Automation document."
        )));
    }
    let mut typed = BTreeMap::new();
    let mut strings = BTreeMap::new();
    let mut missing = Vec::new();
    for (name, spec) in &declared {
        let kind = spec.get("type").and_then(Value::as_str).unwrap_or("String");
        let values = match given.get(name) {
            Some(v) => v.clone(),
            None => match spec.get("default") {
                Some(Value::String(s)) => vec![s.clone()],
                Some(Value::Array(a)) => strings_of(&Value::Array(a.clone())),
                Some(Value::Null) | None => {
                    if skip != Some(name.as_str()) {
                        missing.push(name.clone());
                    }
                    continue;
                }
                Some(Value::Object(_)) => vec![spec["default"].to_string()],
                Some(other) => vec![match other {
                    Value::String(s) => s.clone(),
                    o => o.to_string(),
                }],
            },
        };
        if let Some(allowed) = spec.get("allowedValues").and_then(Value::as_array) {
            let allowed: Vec<String> = strings_of(&Value::Array(allowed.clone()));
            if let Some(v) = values.iter().find(|v| !allowed.contains(v)) {
                return Err(errors::invalid_automation_execution_parameters(format!(
                    "Parameter \"{name}\" has value \"{v}\" not in {allowed:?}."
                )));
            }
        }
        if let Some(pattern) = spec.get("allowedPattern").and_then(Value::as_str) {
            if let Ok(re) = regex::Regex::new(&format!("^(?:{pattern})$")) {
                if let Some(v) = values.iter().find(|v| !re.is_match(v)) {
                    return Err(errors::invalid_automation_execution_parameters(format!(
                        "Parameter \"{name}\" has value \"{v}\" not matching \"{pattern}\"."
                    )));
                }
            }
        }
        typed.insert(name.clone(), typed_value(name, kind, &values)?);
        strings.insert(name.clone(), values);
    }
    if !missing.is_empty() {
        return Err(errors::invalid_automation_execution_parameters(format!(
            "Parameters {missing:?} are required but were not specified."
        )));
    }
    Ok((typed, strings))
}

/// `MaxConcurrency` / `MaxErrors` (a number or a percentage) for `total`
/// targets.
pub(crate) fn rate(value: Option<&str>, total: usize, default: usize) -> usize {
    match value.map(str::trim) {
        Some(v) if v.ends_with('%') => {
            let pct: usize = v.trim_end_matches('%').parse().unwrap_or(100);
            ((total * pct).div_ceil(100)).max(if pct > 0 { 1 } else { 0 })
        }
        Some(v) => v.parse().unwrap_or(default),
        None => default,
    }
}

impl Ssm {
    pub fn set_automation_runtime(&self, runtime: Arc<dyn AutomationRuntime>) {
        *self.automation.write().expect("SSM automation lock poisoned") = Some(runtime);
    }

    pub(crate) fn runtime(&self) -> Option<Arc<dyn AutomationRuntime>> {
        self.automation.read().expect("SSM automation lock poisoned").clone()
    }

    pub(crate) fn update_automation<R>(
        &self,
        account: &str,
        region: &str,
        id: &str,
        f: impl FnOnce(&mut AutomationRecord) -> R,
    ) -> Option<R> {
        let mut st = self.lock();
        st.region(account, region).automations.get_mut(id).map(f)
    }

    /// Report execution and step status changes since the last call:
    /// "EC2 Automation Execution Status-change Notification" and "EC2
    /// Automation Step Status-change Notification" events.
    pub(crate) fn report_automation(&self, account: &str, region: &str, id: &str) {
        let mut out = Vec::new();
        {
            let mut st = self.lock();
            let Some(r) = st.region(account, region).automations.get_mut(id) else { return };
            let e = &r.execution;
            let status = e.automation_execution_status.clone().unwrap_or_default();
            let steps = e.step_executions.clone().unwrap_or_default();
            r.reported_steps.resize(steps.len(), String::new());
            for (i, s) in steps.iter().enumerate() {
                let st = s.step_status.clone().unwrap_or_default();
                if st.is_empty() || st == "Pending" || r.reported_steps[i] == st {
                    continue;
                }
                r.reported_steps[i] = st.clone();
                out.push((
                    true,
                    st,
                    s.step_name.clone(),
                    s.action.clone(),
                    s.execution_start_time,
                    s.execution_end_time,
                ));
            }
            if !status.is_empty() && r.reported != status {
                r.reported = status.clone();
                out.push((false, status, None, None, e.execution_start_time, e.execution_end_time));
            }
            if out.is_empty() {
                return;
            }
            let e = r.execution.clone();
            drop(st);
            let partition = self.partition();
            let name = e.document_name.clone().unwrap_or_default();
            let version = e.document_version.clone().unwrap_or_default();
            let resources = vec![
                execution_arn(&partition, region, account, id),
                format!("arn:{partition}:ssm:{region}:{account}:automation-definition/{name}:{version}"),
            ];
            let when = |t: Option<DateTime<Utc>>| t.map(crate::events::automation_time).unwrap_or_default();
            for (step, status, step_name, action, start, end) in out {
                let time = match (start, end) {
                    (Some(s), Some(e)) => (e - s).num_milliseconds().max(0) as f64,
                    _ => 0.0,
                };
                let mut detail = serde_json::json!({
                    "ExecutionId": id,
                    "Definition": name,
                    "DefinitionVersion": version.parse::<f64>().unwrap_or(1.0),
                    "Status": status,
                    "StartTime": when(start),
                    "EndTime": when(end),
                    "Time": time,
                });
                let kind = if step {
                    detail["StepName"] = Value::String(step_name.unwrap_or_default());
                    detail["Action"] = Value::String(action.unwrap_or_default());
                    "EC2 Automation Step Status-change Notification"
                } else {
                    detail["ExecutedBy"] = Value::String(e.executed_by.clone().unwrap_or_default());
                    "EC2 Automation Execution Status-change Notification"
                };
                self.emit(account, region, kind, resources.clone(), detail);
            }
        }
    }

    pub(crate) fn automation(&self, account: &str, region: &str, id: &str) -> Option<AutomationRecord> {
        self.lock().region_ref(account, region).and_then(|r| r.automations.get(id)).cloned()
    }

    /// Start an execution as `ctx`'s caller (already authorized), and run
    /// it in the background. Returns its id.
    pub(crate) fn start_automation(&self, ctx: &RequestContext, spec: StartSpec) -> Result<String, ServiceError> {
        let account = ctx.caller.account_id.clone();
        let region = ctx.region.clone();
        if let Some(token) = &spec.client_token {
            let st = self.lock();
            if let Some(r) = st.region_ref(&account, &region) {
                if let Some(existing) = r.automations.values().find(|a| a.client_token.as_ref() == Some(token)) {
                    if existing.execution.document_name.as_deref() != Some(spec.document_name.as_str()) {
                        return Err(errors::idempotent_parameter_mismatch(
                            "Error: Request parameters do not match original request parameters.",
                        ));
                    }
                    return Ok(existing.execution.automation_execution_id.clone().unwrap_or_default());
                }
            }
        }
        let found = self.find_document(ctx, &spec.document_name).ok_or_else(|| {
            errors::automation_definition_not_found(format!(
                "Document with name {} does not exist.",
                spec.document_name
            ))
        })?;
        let change = spec.change.is_some();
        let wanted = if change { "Automation.ChangeTemplate" } else { "Automation" };
        if found.doc.document_type != wanted {
            return Err(errors::automation_definition_not_found(format!(
                "Document {} is of type {} and not {wanted}.",
                spec.document_name, found.doc.document_type
            )));
        }
        let version = pick_version(&found.doc, spec.document_version.as_deref(), None).map_err(|_| {
            errors::automation_definition_version_not_found(format!(
                "Document version {} of document {} does not exist.",
                spec.document_version.clone().unwrap_or_default(),
                spec.document_name
            ))
        })?;
        let content = parse_content(&version.content, &version.format)?;
        let rate_control = !spec.targets.is_empty() || !spec.target_maps.is_empty();
        if !spec.targets.is_empty() && !spec.target_maps.is_empty() {
            return Err(errors::invalid_automation_execution_parameters(
                "Targets and TargetMaps cannot both be specified.",
            ));
        }
        if !spec.targets.is_empty() && spec.target_parameter_name.is_none() {
            return Err(errors::invalid_automation_execution_parameters(
                "TargetParameterName must be specified with Targets.",
            ));
        }
        if let Some(t) = &spec.target_parameter_name {
            if content.get("parameters").and_then(|p| p.get(t)).is_none() {
                return Err(errors::invalid_automation_execution_parameters(format!(
                    "TargetParameterName {t} is not a parameter of the document."
                )));
            }
        }
        let fan_out = rate_control || !spec.target_locations.is_empty();
        let (_, strings) = if change {
            resolve_parameters(&content, &spec.parameters, None).or_else(|e| {
                // Change templates often declare no parameters at all.
                if spec.parameters.is_empty() {
                    Ok((BTreeMap::new(), BTreeMap::new()))
                } else {
                    Err(e)
                }
            })?
        } else if !spec.target_maps.is_empty() {
            (BTreeMap::new(), spec.parameters.clone())
        } else {
            resolve_parameters(
                &content,
                &spec.parameters,
                if fan_out { spec.target_parameter_name.as_deref() } else { None },
            )?
        };
        if let Some(c) = &spec.change {
            if c.auto_approve && content.get("autoApprovable").and_then(Value::as_bool) != Some(true) {
                return Err(errors::invalid_automation_execution_parameters(
                    "The change template doesn't allow AutoApprove.",
                ));
            }
            for rb in &c.runbooks {
                let Some(f) = self.find_document(ctx, &rb.document_name) else {
                    return Err(errors::automation_definition_not_found(format!(
                        "Document with name {} does not exist.",
                        rb.document_name
                    )));
                };
                if f.doc.document_type != "Automation" {
                    return Err(errors::invalid_automation_execution_parameters(format!(
                        "Runbook {} is not an Automation document.",
                        rb.document_name
                    )));
                }
            }
        }
        if spec.pass_roles {
            if let Some(role) = assume_role_of(&content, &spec.parameters) {
                pass_role(ctx, &role)?;
            }
            for rb in spec.change.iter().flat_map(|c| &c.runbooks) {
                let Some(f) = self.find_document(ctx, &rb.document_name) else { continue };
                let Ok(v) = pick_version(&f.doc, rb.document_version.as_deref(), None) else { continue };
                let Ok(rb_content) = parse_content(&v.content, &v.format) else { continue };
                if let Some(role) = assume_role_of(&rb_content, &rb.parameters.clone().unwrap_or_default()) {
                    pass_role(ctx, &role)?;
                }
            }
        }
        let mode = spec.mode.clone().unwrap_or_else(|| "Auto".into());
        let id = uuid::Uuid::new_v4().to_string();
        let started = self.clock_now().max(now(ctx));
        let total_steps = content.get("mainSteps").and_then(Value::as_array).map_or(0, Vec::len) as i32;
        let execution = types::AutomationExecution {
            automation_execution_id: Some(id.clone()),
            document_name: Some(found.doc.name.clone()),
            document_version: Some(version.version.to_string()),
            execution_start_time: Some(started),
            automation_execution_status: Some(if change { "PendingApproval" } else { "Pending" }.into()),
            step_executions: Some(Vec::new()),
            parameters: Some(strings),
            outputs: Some(BTreeMap::new()),
            mode: Some(mode),
            parent_automation_execution_id: spec.parent.clone(),
            executed_by: Some(ctx.caller.arn.clone()),
            target_parameter_name: spec.target_parameter_name.clone(),
            targets: (!spec.targets.is_empty()).then(|| spec.targets.clone()),
            target_maps: (!spec.target_maps.is_empty()).then(|| spec.target_maps.clone()),
            max_concurrency: spec.max_concurrency.clone().or_else(|| fan_out.then(|| "1".into())),
            max_errors: spec.max_errors.clone().or_else(|| fan_out.then(|| "0".into())),
            target: spec.target.clone(),
            target_locations: (!spec.target_locations.is_empty()).then(|| spec.target_locations.clone()),
            progress_counters: Some(types::ProgressCounters { total_steps, ..Default::default() }),
            alarm_configuration: spec.alarm_configuration.clone(),
            automation_subtype: change.then(|| "ChangeRequest".into()),
            scheduled_time: spec.change.as_ref().and_then(|c| c.scheduled_time),
            runbooks: spec.change.as_ref().map(|c| c.runbooks.clone()),
            change_request_name: spec.change.as_ref().and_then(|c| c.name.clone()),
            variables: content.get("variables").and_then(Value::as_object).map(|vars| {
                vars.iter().map(|(k, v)| (k.clone(), v.get("default").map(strings_of).unwrap_or_default())).collect()
            }),
            ..Default::default()
        };
        let record = AutomationRecord {
            execution,
            automation_type: spec.automation_type.clone().unwrap_or_else(|| {
                if spec.target_locations.is_empty() {
                    "Local".into()
                } else {
                    "CrossAccount".into()
                }
            }),
            tags: spec.tags.clone(),
            client_token: spec.client_token.clone(),
            change_details: spec.change.as_ref().and_then(|c| c.change_details.clone()),
            scheduled_end_time: spec.change.as_ref().and_then(|c| c.scheduled_end_time),
            auto_approve: spec.change.as_ref().is_some_and(|c| c.auto_approve),
            ..Default::default()
        };
        self.lock().region(&account, &region).automations.insert(id.clone(), record);
        let ssm = self.clone();
        let run_ctx = ctx.clone();
        let run_id = id.clone();
        crate::commands::spawn(async move {
            if change {
                ssm.run_change_request(run_ctx, run_id, content, spec).await;
            } else if fan_out {
                ssm.run_fan_out(run_ctx, run_id, content, spec).await;
            } else {
                ssm.run_automation_execution(run_ctx, run_id, content).await;
            }
        });
        Ok(id)
    }

    pub(crate) fn start_automation_execution(
        &self,
        ctx: &RequestContext,
        input: types::StartAutomationExecutionRequest,
    ) -> Result<types::StartAutomationExecutionResult, ServiceError> {
        let tags: Vec<(String, String)> =
            input.tags.iter().flatten().map(|t| (t.key.clone(), t.value.clone())).collect();
        let cond: ConditionContext = request_tag_conditions(tags.iter().map(|(k, v)| (k, v)));
        ctx.authorize("ssm:StartAutomationExecution", &definition_arn(ctx, &input.document_name), cond)?;
        if input.target_locations_url.is_some() {
            return Err(errors::invalid_automation_execution_parameters(
                "TargetLocationsURL is not supported by MWS; pass TargetLocations.",
            ));
        }
        let id = self.start_automation(
            ctx,
            StartSpec {
                document_name: input.document_name,
                document_version: input.document_version,
                parameters: input.parameters.unwrap_or_default(),
                mode: input.mode,
                target_parameter_name: input.target_parameter_name,
                targets: input.targets.unwrap_or_default(),
                target_maps: input.target_maps.unwrap_or_default(),
                max_concurrency: input.max_concurrency,
                max_errors: input.max_errors,
                target_locations: input.target_locations.unwrap_or_default(),
                tags: input.tags.unwrap_or_default(),
                alarm_configuration: input.alarm_configuration,
                client_token: input.client_token,
                pass_roles: true,
                ..Default::default()
            },
        )?;
        Ok(types::StartAutomationExecutionResult { automation_execution_id: Some(id) })
    }

    pub(crate) fn start_change_request_execution(
        &self,
        ctx: &RequestContext,
        input: types::StartChangeRequestExecutionRequest,
    ) -> Result<types::StartChangeRequestExecutionResult, ServiceError> {
        let tags: Vec<(String, String)> =
            input.tags.iter().flatten().map(|t| (t.key.clone(), t.value.clone())).collect();
        let cond: ConditionContext = request_tag_conditions(tags.iter().map(|(k, v)| (k, v)));
        ctx.authorize("ssm:StartChangeRequestExecution", &definition_arn(ctx, &input.document_name), cond)?;
        if input.runbooks.is_empty() {
            return Err(errors::validation("Runbooks must contain at least one runbook."));
        }
        if let (Some(s), Some(e)) = (input.scheduled_time, input.scheduled_end_time) {
            if e <= s {
                return Err(errors::validation("ScheduledEndTime must be after ScheduledTime."));
            }
        }
        let id = self.start_automation(
            ctx,
            StartSpec {
                document_name: input.document_name,
                document_version: input.document_version,
                parameters: input.parameters.unwrap_or_default(),
                tags: input.tags.unwrap_or_default(),
                client_token: input.client_token,
                change: Some(ChangeSpec {
                    name: input.change_request_name,
                    scheduled_time: input.scheduled_time,
                    scheduled_end_time: input.scheduled_end_time,
                    runbooks: input.runbooks,
                    auto_approve: input.auto_approve,
                    change_details: input.change_details,
                }),
                pass_roles: true,
                ..Default::default()
            },
        )?;
        Ok(types::StartChangeRequestExecutionResult { automation_execution_id: Some(id) })
    }

    fn authorized_execution(
        &self,
        ctx: &RequestContext,
        action: &str,
        id: &str,
    ) -> Result<AutomationRecord, ServiceError> {
        let arn = execution_arn(&ctx.partition, &ctx.region, &ctx.caller.account_id, id);
        let rec = self.automation(&ctx.caller.account_id, &ctx.region, id);
        let mut cond = ConditionContext::new();
        if let Some(r) = &rec {
            for t in &r.tags {
                cond.insert(format!("aws:ResourceTag/{}", t.key), vec![t.value.clone()]);
            }
        }
        ctx.authorize(&format!("ssm:{action}"), &arn, cond)?;
        rec.ok_or_else(|| not_found(id))
    }

    pub(crate) fn get_automation_execution(
        &self,
        ctx: &RequestContext,
        input: types::GetAutomationExecutionRequest,
    ) -> Result<types::GetAutomationExecutionResult, ServiceError> {
        let rec = self.authorized_execution(ctx, "GetAutomationExecution", &input.automation_execution_id)?;
        let mut e = rec.execution;
        if let Some(steps) = &e.step_executions {
            if steps.len() > 100 {
                e.step_executions = Some(steps[..100].to_vec());
                e.step_executions_truncated = true;
            }
        }
        Ok(types::GetAutomationExecutionResult { automation_execution: Some(e) })
    }

    pub(crate) fn describe_automation_executions(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAutomationExecutionsRequest,
    ) -> Result<types::DescribeAutomationExecutionsResult, ServiceError> {
        ctx.authorize("ssm:DescribeAutomationExecutions", "*", ConditionContext::new())?;
        let filters = input.filters.unwrap_or_default();
        let time = |v: &str| {
            DateTime::parse_from_rfc3339(v).map(|t| t.with_timezone(&Utc)).map_err(|_| {
                errors::invalid_filter_value(format!("The value {v} is not a valid time (yyyy-MM-ddTHH:mm:ssZ)."))
            })
        };
        for f in &filters {
            const KEYS: &[&str] = &[
                "DocumentNamePrefix",
                "ExecutionStatus",
                "ExecutionId",
                "ParentExecutionId",
                "CurrentAction",
                "StartTimeBefore",
                "StartTimeAfter",
                "AutomationType",
                "TagKey",
                "TargetResourceGroup",
                "AutomationSubtype",
                "OpsItemId",
            ];
            if !KEYS.contains(&f.key.as_str()) {
                return Err(errors::invalid_filter_key(format!("The filter key {} isn't valid.", f.key)));
            }
            if f.key.starts_with("StartTime") {
                for v in &f.values {
                    time(v)?;
                }
            }
        }
        let mut list: Vec<AutomationRecord> = {
            let st = self.lock();
            st.region_ref(&ctx.caller.account_id, &ctx.region)
                .map(|r| r.automations.values().cloned().collect())
                .unwrap_or_default()
        };
        list.retain(|r| {
            let e = &r.execution;
            filters.iter().all(|f| {
                let any = |v: Option<&str>| f.values.iter().any(|x| Some(x.as_str()) == v);
                match f.key.as_str() {
                    "DocumentNamePrefix" => {
                        f.values.iter().any(|p| e.document_name.as_deref().unwrap_or_default().starts_with(p.as_str()))
                    }
                    "ExecutionStatus" => any(e.automation_execution_status.as_deref()),
                    "ExecutionId" => any(e.automation_execution_id.as_deref()),
                    "ParentExecutionId" => any(e.parent_automation_execution_id.as_deref()),
                    "CurrentAction" => any(e.current_action.as_deref()),
                    "StartTimeBefore" => {
                        f.values.iter().any(|v| time(v).ok().zip(e.execution_start_time).is_some_and(|(t, s)| s < t))
                    }
                    "StartTimeAfter" => {
                        f.values.iter().any(|v| time(v).ok().zip(e.execution_start_time).is_some_and(|(t, s)| s > t))
                    }
                    "AutomationType" => any(Some(&r.automation_type)),
                    "TagKey" => r.tags.iter().any(|t| f.values.contains(&t.key)),
                    "AutomationSubtype" => any(e.automation_subtype.as_deref()),
                    "OpsItemId" => any(e.ops_item_id.as_deref()),
                    _ => false,
                }
            })
        });
        list.sort_by_key(|r| std::cmp::Reverse(r.execution.execution_start_time));
        let metadata: Vec<types::AutomationExecutionMetadata> = list
            .into_iter()
            .map(|r| {
                let e = r.execution;
                types::AutomationExecutionMetadata {
                    automation_execution_id: e.automation_execution_id,
                    document_name: e.document_name,
                    document_version: e.document_version,
                    automation_execution_status: e.automation_execution_status,
                    execution_start_time: e.execution_start_time,
                    execution_end_time: e.execution_end_time,
                    executed_by: e.executed_by,
                    log_file: Some(String::new()),
                    outputs: e.outputs,
                    mode: e.mode,
                    parent_automation_execution_id: e.parent_automation_execution_id,
                    current_step_name: e.current_step_name,
                    current_action: e.current_action,
                    failure_message: e.failure_message,
                    target_parameter_name: e.target_parameter_name,
                    targets: e.targets,
                    target_maps: e.target_maps,
                    resolved_targets: e.resolved_targets,
                    max_concurrency: e.max_concurrency,
                    max_errors: e.max_errors,
                    target: e.target,
                    automation_type: Some(r.automation_type),
                    alarm_configuration: e.alarm_configuration,
                    triggered_alarms: e.triggered_alarms,
                    automation_subtype: e.automation_subtype,
                    scheduled_time: e.scheduled_time,
                    runbooks: e.runbooks,
                    ops_item_id: e.ops_item_id,
                    change_request_name: e.change_request_name,
                    ..Default::default()
                }
            })
            .collect();
        let limit = input.max_results.unwrap_or(25).clamp(1, 50) as usize;
        let (items, next) = page(metadata, input.next_token.as_deref(), limit)?;
        Ok(types::DescribeAutomationExecutionsResult {
            automation_execution_metadata_list: Some(items),
            next_token: next,
        })
    }

    pub(crate) fn describe_automation_step_executions(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAutomationStepExecutionsRequest,
    ) -> Result<types::DescribeAutomationStepExecutionsResult, ServiceError> {
        let rec = self.authorized_execution(ctx, "DescribeAutomationStepExecutions", &input.automation_execution_id)?;
        let filters = input.filters.unwrap_or_default();
        for f in &filters {
            const KEYS: &[&str] =
                &["StartTimeBefore", "StartTimeAfter", "StepExecutionStatus", "StepExecutionId", "StepName", "Action"];
            if !KEYS.contains(&f.key.as_str()) {
                return Err(errors::invalid_filter_key(format!("The filter key {} isn't valid.", f.key)));
            }
        }
        let time = |v: &str| DateTime::parse_from_rfc3339(v).ok().map(|t| t.with_timezone(&Utc));
        let mut steps: Vec<types::StepExecution> = rec
            .execution
            .step_executions
            .unwrap_or_default()
            .into_iter()
            .filter(|s| {
                filters.iter().all(|f| {
                    let any = |v: Option<&str>| f.values.iter().any(|x| Some(x.as_str()) == v);
                    match f.key.as_str() {
                        "StepExecutionStatus" => {
                            f.values.iter().any(|x| s.step_status.as_deref().is_some_and(|v| v.eq_ignore_ascii_case(x)))
                        }
                        "StepExecutionId" => any(s.step_execution_id.as_deref()),
                        "StepName" => any(s.step_name.as_deref()),
                        "Action" => any(s.action.as_deref()),
                        "StartTimeBefore" => {
                            f.values.iter().any(|v| time(v).zip(s.execution_start_time).is_some_and(|(t, st)| st < t))
                        }
                        "StartTimeAfter" => {
                            f.values.iter().any(|v| time(v).zip(s.execution_start_time).is_some_and(|(t, st)| st > t))
                        }
                        _ => false,
                    }
                })
            })
            .collect();
        if input.reverse_order == Some(true) {
            steps.reverse();
        }
        let limit = input.max_results.unwrap_or(50).clamp(1, 50) as usize;
        let (items, next) = page(steps, input.next_token.as_deref(), limit)?;
        Ok(types::DescribeAutomationStepExecutionsResult { step_executions: Some(items), next_token: next })
    }

    pub(crate) fn stop_automation_execution(
        &self,
        ctx: &RequestContext,
        input: types::StopAutomationExecutionRequest,
    ) -> Result<types::StopAutomationExecutionResult, ServiceError> {
        let id = input.automation_execution_id.clone();
        let rec = self.authorized_execution(ctx, "StopAutomationExecution", &id)?;
        let status = rec.execution.automation_execution_status.clone().unwrap_or_default();
        if TERMINAL.contains(&status.as_str()) {
            return Err(errors::invalid_automation_status_update(format!(
                "The execution {id} is already complete with status {status}."
            )));
        }
        let kind = input.r#type.unwrap_or_else(|| "Cancel".into());
        let children: Vec<String> = {
            let st = self.lock();
            st.region_ref(&ctx.caller.account_id, &ctx.region)
                .map(|r| {
                    r.automations
                        .values()
                        .filter(|a| a.execution.parent_automation_execution_id.as_deref() == Some(id.as_str()))
                        .filter_map(|a| a.execution.automation_execution_id.clone())
                        .collect()
                })
                .unwrap_or_default()
        };
        for target in std::iter::once(id.clone()).chain(children) {
            self.update_automation(&ctx.caller.account_id, &ctx.region, &target, |r| {
                let s = r.execution.automation_execution_status.clone().unwrap_or_default();
                if !TERMINAL.contains(&s.as_str()) {
                    r.stop = Some(kind.clone());
                    if kind == "Cancel" {
                        r.execution.automation_execution_status = Some("Cancelling".into());
                    }
                }
            });
        }
        Ok(types::StopAutomationExecutionResult::default())
    }

    pub(crate) fn send_automation_signal(
        &self,
        ctx: &RequestContext,
        input: types::SendAutomationSignalRequest,
    ) -> Result<types::SendAutomationSignalResult, ServiceError> {
        let id = input.automation_execution_id.clone();
        let rec = self.authorized_execution(ctx, "SendAutomationSignal", &id)?;
        let status = rec.execution.automation_execution_status.clone().unwrap_or_default();
        let signal = input.signal_type.clone();
        let waiting = match signal.as_str() {
            "Approve" | "Reject" => {
                matches!(status.as_str(), "Waiting" | "PendingApproval")
                    && rec.execution.current_action.as_deref() == Some("aws:approve")
            }
            "Resume" => status == "Waiting" && rec.execution.current_action.as_deref() == Some("aws:pause"),
            "StartStep" | "StopStep" => !TERMINAL.contains(&status.as_str()),
            "Revoke" => matches!(status.as_str(), "Scheduled" | "Approved" | "PendingApproval"),
            _ => false,
        };
        if !waiting {
            return Err(errors::invalid_automation_signal(format!(
                "Automation execution {id} is not waiting for signal {signal}."
            )));
        }
        let payload = input.payload.unwrap_or_default();
        if matches!(signal.as_str(), "StartStep" | "StopStep") {
            let step = payload.get("StepName").and_then(|v| v.first()).cloned().unwrap_or_default();
            let content_has =
                rec.execution.step_executions.iter().flatten().any(|s| s.step_name.as_deref() == Some(step.as_str()))
                    || rec.execution.current_step_name.as_deref() == Some(step.as_str())
                    || self.step_names(ctx, &rec).contains(&step);
            if !content_has {
                return Err(errors::automation_step_not_found(format!("Step {step} could not be found.")));
            }
        }
        if matches!(signal.as_str(), "Approve" | "Reject") && !self.may_approve(ctx, &rec) {
            return Err(errors::invalid_automation_signal(format!(
                "{} is not an approver for the current step of automation execution {id}.",
                ctx.caller.arn
            )));
        }
        self.update_automation(&ctx.caller.account_id, &ctx.region, &id, |r| {
            r.signals.push(Signal { signal_type: signal, payload, sender: ctx.caller.arn.clone() })
        });
        Ok(types::SendAutomationSignalResult::default())
    }

    /// The step names of an execution's runbook.
    fn step_names(&self, ctx: &RequestContext, rec: &AutomationRecord) -> Vec<String> {
        let Some(found) = self.find_document(ctx, rec.execution.document_name.as_deref().unwrap_or_default()) else {
            return Vec::new();
        };
        let Ok(v) = pick_version(&found.doc, rec.execution.document_version.as_deref(), None) else {
            return Vec::new();
        };
        let Ok(content) = parse_content(&v.content, &v.format) else { return Vec::new() };
        content
            .get("mainSteps")
            .and_then(Value::as_array)
            .map(|s| s.iter().filter_map(|s| s.get("name").and_then(Value::as_str).map(str::to_string)).collect())
            .unwrap_or_default()
    }

    /// Whether `ctx`'s caller is one of the approvers the waiting
    /// `aws:approve` step names.
    fn may_approve(&self, ctx: &RequestContext, rec: &AutomationRecord) -> bool {
        let Some(step) = rec
            .execution
            .step_executions
            .iter()
            .flatten()
            .rev()
            .find(|s| s.action.as_deref() == Some("aws:approve") && s.step_status.as_deref() == Some("Waiting"))
        else {
            return false;
        };
        let approvers: Vec<String> = step
            .inputs
            .as_ref()
            .and_then(|i| i.get("Approvers"))
            .and_then(|a| serde_json::from_str::<Value>(a).ok())
            .map(|v| match v {
                Value::Array(items) => items
                    .into_iter()
                    .filter_map(|i| match i {
                        Value::String(s) => Some(s),
                        Value::Object(o) => o.get("approver").and_then(Value::as_str).map(str::to_string),
                        _ => None,
                    })
                    .collect(),
                Value::String(s) => vec![s],
                _ => Vec::new(),
            })
            .unwrap_or_default();
        crate::engine::is_approver(&ctx.caller, &approvers)
    }

    pub(crate) fn start_execution_preview(
        &self,
        ctx: &RequestContext,
        input: types::StartExecutionPreviewRequest,
    ) -> Result<types::StartExecutionPreviewResponse, ServiceError> {
        ctx.authorize(
            "ssm:StartExecutionPreview",
            &definition_arn(ctx, &input.document_name),
            ConditionContext::new(),
        )?;
        let found = self.find_document(ctx, &input.document_name).ok_or_else(|| {
            errors::resource_not_found(format!("Document with name {} does not exist.", input.document_name))
        })?;
        if found.doc.document_type != "Automation" {
            return Err(errors::validation("Execution previews are only available for Automation runbooks."));
        }
        let version = pick_version(&found.doc, input.document_version.as_deref(), None)?;
        let content = parse_content(&version.content, &version.format)?;
        let types::ExecutionInputs::Automation(inputs) = input.execution_inputs.unwrap_or_default();
        let mut previews: BTreeMap<String, i32> = BTreeMap::new();
        for s in content.get("mainSteps").and_then(Value::as_array).into_iter().flatten() {
            *previews.entry(crate::engine::impact(s).into()).or_default() += 1;
        }
        let mut regions: Vec<String> = Vec::new();
        let mut accounts: Vec<String> = Vec::new();
        for l in inputs.target_locations.iter().flatten() {
            for r in l.regions.iter().flatten() {
                if !regions.contains(r) {
                    regions.push(r.clone());
                }
            }
            for a in l.accounts.iter().flatten() {
                if !accounts.contains(a) {
                    accounts.push(a.clone());
                }
            }
        }
        if regions.is_empty() {
            regions.push(ctx.region.clone());
        }
        let mut target_previews = Vec::new();
        let targets = inputs.targets.clone().unwrap_or_default();
        if !targets.is_empty() {
            let values = self.automation_target_values(ctx, &targets);
            let kind = if targets.iter().any(|t| t.key.as_deref() == Some("ParameterValues")) {
                "ParameterValues"
            } else {
                "AWS::EC2::Instance"
            };
            target_previews.push(types::TargetPreview { count: values.len() as i32, target_type: Some(kind.into()) });
        } else if let Some(maps) = &inputs.target_maps {
            target_previews
                .push(types::TargetPreview { count: maps.len() as i32, target_type: Some("TargetMap".into()) });
        }
        let id = uuid::Uuid::new_v4().to_string();
        let result = types::GetExecutionPreviewResponse {
            execution_preview_id: Some(id.clone()),
            ended_at: Some(now(ctx)),
            status: Some("Success".into()),
            status_message: Some(String::new()),
            execution_preview: Some(types::ExecutionPreview::Automation(types::AutomationExecutionPreview {
                step_previews: Some(previews),
                regions: Some(regions),
                target_previews: Some(target_previews),
                total_accounts: accounts.len().max(1) as i32,
            })),
        };
        self.lock().region(&ctx.caller.account_id, &ctx.region).previews.insert(id.clone(), PreviewRecord { result });
        Ok(types::StartExecutionPreviewResponse { execution_preview_id: Some(id) })
    }

    pub(crate) fn get_execution_preview(
        &self,
        ctx: &RequestContext,
        input: types::GetExecutionPreviewRequest,
    ) -> Result<types::GetExecutionPreviewResponse, ServiceError> {
        ctx.authorize("ssm:GetExecutionPreview", "*", ConditionContext::new())?;
        let st = self.lock();
        st.region_ref(&ctx.caller.account_id, &ctx.region)
            .and_then(|r| r.previews.get(&input.execution_preview_id))
            .map(|p| p.result.clone())
            .ok_or_else(|| {
                errors::resource_not_found(format!(
                    "Execution preview {} could not be found.",
                    input.execution_preview_id
                ))
            })
    }

    /// The values `targets` resolve to for a rate-control execution:
    /// `ParameterValues` as given, tags and resource groups as the EC2
    /// instances (managed or not) that carry them.
    pub(crate) fn automation_target_values(&self, ctx: &RequestContext, targets: &[types::Target]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let nodes = self.nodes_of(&ctx.caller.account_id, &ctx.region);
        for t in targets {
            let key = t.key.clone().unwrap_or_default();
            let values = t.values.clone().unwrap_or_default();
            let matched: Vec<String> = match key.as_str() {
                "ParameterValues" | "InstanceIds" => values,
                "tag-key" => nodes
                    .iter()
                    .filter(|n| values.iter().any(|v| n.tags.contains_key(v)))
                    .map(|n| n.instance_id.clone())
                    .collect(),
                k if k.starts_with("tag:") => nodes
                    .iter()
                    .filter(|n| n.tags.get(&k[4..]).is_some_and(|x| values.contains(x)))
                    .map(|n| n.instance_id.clone())
                    .collect(),
                "ResourceType" | "AWS::EC2::Instance" => nodes.iter().map(|n| n.instance_id.clone()).collect(),
                _ => Vec::new(),
            };
            for m in matched {
                if !out.contains(&m) {
                    out.push(m);
                }
            }
        }
        out
    }
}

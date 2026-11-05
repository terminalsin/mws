//! Stack refactors: move resources between stacks (or rename them) without
//! touching the resources themselves, and the operation-grouped event view
//! (`DescribeEvents`).

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use mws_core::{RequestContext, ServiceError};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::engine::STACK_TYPE;
use crate::generated::{errors, types};
use crate::ops::{find, page, validation};
use crate::parameters;
use crate::state::{Event, Resource, Stack};
use crate::template::Template;
use crate::CloudFormation;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StackRefactor {
    pub id: String,
    pub account: String,
    pub region: String,
    pub description: Option<String>,
    pub status: String,
    pub status_reason: Option<String>,
    pub execution_status: String,
    pub execution_status_reason: Option<String>,
    pub created: Option<DateTime<Utc>>,
    pub stacks: Vec<RefactorStack>,
    pub moves: Vec<Move>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RefactorStack {
    pub name: String,
    pub stack_id: String,
    /// Whether the refactor creates the stack.
    pub create: bool,
    pub template_body: String,
    /// When the stack last changed before the refactor was created: a later
    /// change makes the refactor obsolete.
    pub stamp: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Move {
    pub source_stack: String,
    pub source_logical: String,
    pub dest_stack: String,
    pub dest_logical: String,
    pub resource_type: String,
    pub physical_id: Option<String>,
    pub manual: bool,
}

fn not_found(id: &str) -> ServiceError {
    errors::stack_refactor_not_found(format!("Stack refactor {id} does not exist"))
}

fn stamp(s: &Stack) -> Option<DateTime<Utc>> {
    s.events.last().map(|e| e.timestamp).or(s.updated).or(Some(s.created))
}

fn has_intrinsics(v: &Value) -> bool {
    match v {
        Value::Object(o) => o.keys().any(|k| k == "Ref" || k.starts_with("Fn::")) || o.values().any(has_intrinsics),
        Value::Array(a) => a.iter().any(has_intrinsics),
        _ => false,
    }
}

/// Resource definitions without the parts a refactor may change.
fn comparable(def: &Map<String, Value>) -> (Option<&Value>, Option<&Value>) {
    (def.get("Type"), def.get("Properties"))
}

impl CloudFormation {
    fn refactor_view(&self, ctx: &RequestContext, id: &str) -> Result<StackRefactor, ServiceError> {
        let st = self.state();
        let r = st
            .refactors
            .get(id)
            .filter(|r| r.account == ctx.caller.account_id && r.region == ctx.region)
            .ok_or_else(|| not_found(id))?;
        let mut r = r.clone();
        // A stack updated since the refactor was planned makes it obsolete.
        if r.execution_status == "AVAILABLE" {
            let changed = r.stacks.iter().any(|d| match st.stacks.get(&d.stack_id) {
                Some(s) => d.create || stamp(s) != d.stamp,
                None => !d.create,
            }) || r.stacks.iter().any(|d| d.create && find(&st, ctx, &d.name).is_ok());
            if changed {
                r.execution_status = "OBSOLETE".into();
                r.execution_status_reason = Some("A stack in the refactor changed after it was created".into());
            }
        }
        Ok(r)
    }

    pub(crate) async fn create_stack_refactor_op(
        &self,
        ctx: &RequestContext,
        input: types::CreateStackRefactorInput,
    ) -> Result<types::CreateStackRefactorOutput, ServiceError> {
        if input.stack_definitions.is_empty() {
            return Err(validation("StackDefinitions must contain at least one stack"));
        }
        let mut names = BTreeSet::new();
        let mut defs: Vec<(String, String, Template)> = Vec::new();
        for d in &input.stack_definitions {
            let Some(name) = d.stack_name.clone() else {
                return Err(validation("StackName is required for each stack definition"));
            };
            if !names.insert(name.clone()) {
                return Err(validation(format!("Stack {name} is defined more than once")));
            }
            let body = self.template_text(ctx, d.template_body.as_deref(), d.template_url.as_deref()).await?;
            let template = Template::parse(&body).map_err(validation)?;
            self.check_template(ctx, &template)?;
            defs.push((name, body, template));
        }
        let enable = input.enable_stack_creation.unwrap_or(false);
        let mut stacks: Vec<RefactorStack> = Vec::new();
        let mut current: BTreeMap<String, Stack> = BTreeMap::new();
        let mut failure: Option<String> = None;
        {
            let st = self.state();
            for (name, body, _) in &defs {
                match find(&st, ctx, name) {
                    Ok(s) => {
                        ctx.authorize("cloudformation:CreateStackRefactor", &s.id, Default::default())?;
                        if s.in_progress() || s.status.contains("FAILED") || s.status == "REVIEW_IN_PROGRESS" {
                            failure.get_or_insert(format!(
                                "Stack {name} is in {} state and can not be refactored",
                                s.status
                            ));
                        }
                        stacks.push(RefactorStack {
                            name: name.clone(),
                            stack_id: s.id.clone(),
                            create: false,
                            template_body: body.clone(),
                            stamp: stamp(s),
                        });
                        current.insert(name.clone(), s.clone());
                    }
                    Err(_) => {
                        let id = crate::ops::new_stack_id(ctx, name);
                        ctx.authorize("cloudformation:CreateStackRefactor", &id, Default::default())?;
                        if !enable {
                            failure.get_or_insert(format!(
                                "Stack {name} does not exist. Set EnableStackCreation to create it."
                            ));
                        }
                        stacks.push(RefactorStack {
                            name: name.clone(),
                            stack_id: id,
                            create: true,
                            template_body: body.clone(),
                            stamp: None,
                        });
                    }
                }
            }
        }
        let moves = match failure {
            Some(f) => Err(f),
            None => plan(&defs, &current, input.resource_mappings.as_deref().unwrap_or_default()),
        };
        let id = format!(
            "arn:{}:cloudformation:{}:{}:stackRefactor/{}",
            ctx.partition,
            ctx.region,
            ctx.caller.account_id,
            uuid::Uuid::new_v4()
        );
        let (status, reason, exec, moves) = match moves {
            Ok(m) => ("CREATE_COMPLETE", None, "AVAILABLE", m),
            Err(r) => ("CREATE_FAILED", Some(r), "UNAVAILABLE", Vec::new()),
        };
        let r = StackRefactor {
            id: id.clone(),
            account: ctx.caller.account_id.clone(),
            region: ctx.region.clone(),
            description: input.description.clone(),
            status: status.into(),
            status_reason: reason,
            execution_status: exec.into(),
            execution_status_reason: None,
            created: Some(ctx.received_at),
            stacks,
            moves,
        };
        self.state().refactors.insert(id.clone(), r);
        Ok(types::CreateStackRefactorOutput { stack_refactor_id: id })
    }

    pub(crate) fn describe_stack_refactor_op(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStackRefactorInput,
    ) -> Result<types::DescribeStackRefactorOutput, ServiceError> {
        ctx.authorize("cloudformation:DescribeStackRefactor", "*", Default::default())?;
        let r = self.refactor_view(ctx, &input.stack_refactor_id)?;
        Ok(types::DescribeStackRefactorOutput {
            description: r.description.clone(),
            stack_refactor_id: Some(r.id.clone()),
            stack_ids: Some(r.stacks.iter().map(|s| s.stack_id.clone()).collect()),
            execution_status: Some(r.execution_status.clone()),
            execution_status_reason: r.execution_status_reason.clone(),
            status: Some(r.status.clone()),
            status_reason: r.status_reason.clone(),
        })
    }

    pub(crate) fn list_stack_refactors_op(
        &self,
        ctx: &RequestContext,
        input: types::ListStackRefactorsInput,
    ) -> Result<types::ListStackRefactorsOutput, ServiceError> {
        ctx.authorize("cloudformation:ListStackRefactors", "*", Default::default())?;
        let ids: Vec<String> = {
            let st = self.state();
            let mut v: Vec<&StackRefactor> = st
                .refactors
                .values()
                .filter(|r| r.account == ctx.caller.account_id && r.region == ctx.region)
                .collect();
            v.sort_by_key(|r| std::cmp::Reverse(r.created));
            v.into_iter().map(|r| r.id.clone()).collect()
        };
        let filter = input.execution_status_filter.unwrap_or_default();
        let mut all = Vec::new();
        for id in ids {
            let r = self.refactor_view(ctx, &id)?;
            if !filter.is_empty() && !filter.contains(&r.execution_status) {
                continue;
            }
            all.push(types::StackRefactorSummary {
                stack_refactor_id: Some(r.id),
                description: r.description,
                execution_status: Some(r.execution_status),
                execution_status_reason: r.execution_status_reason,
                status: Some(r.status),
                status_reason: r.status_reason,
            });
        }
        let (items, next_token) =
            page(&all, input.next_token.as_deref(), input.max_results.unwrap_or(100).clamp(1, 100) as usize)?;
        Ok(types::ListStackRefactorsOutput { stack_refactor_summaries: items, next_token })
    }

    pub(crate) fn list_stack_refactor_actions_op(
        &self,
        ctx: &RequestContext,
        input: types::ListStackRefactorActionsInput,
    ) -> Result<types::ListStackRefactorActionsOutput, ServiceError> {
        ctx.authorize("cloudformation:ListStackRefactorActions", "*", Default::default())?;
        let r = self.refactor_view(ctx, &input.stack_refactor_id)?;
        let mut all = Vec::new();
        for s in r.stacks.iter().filter(|s| s.create) {
            all.push(types::StackRefactorAction {
                action: Some("CREATE".into()),
                entity: Some("STACK".into()),
                description: Some(format!("Stack {} will be created", s.name)),
                detection: Some("MANUAL".into()),
                detection_reason: Some("EnableStackCreation was set".into()),
                ..Default::default()
            });
        }
        for m in &r.moves {
            let description = if m.source_stack == m.dest_stack {
                format!("Resource {} will be renamed to {} in stack {}", m.source_logical, m.dest_logical, m.dest_stack)
            } else {
                format!(
                    "Resource {} will be moved from stack {} to stack {}",
                    m.source_logical, m.source_stack, m.dest_stack
                )
            };
            all.push(types::StackRefactorAction {
                action: Some("MOVE".into()),
                entity: Some("RESOURCE".into()),
                physical_resource_id: m.physical_id.clone(),
                resource_identifier: m.physical_id.clone(),
                description: Some(description),
                detection: Some(if m.manual { "MANUAL" } else { "AUTO" }.into()),
                detection_reason: Some(if m.manual {
                    "Resource mapping provided".into()
                } else {
                    "Resource found with the same logical ID and type in another stack".into()
                }),
                resource_mapping: Some(types::ResourceMapping {
                    source: types::ResourceLocation {
                        stack_name: m.source_stack.clone(),
                        logical_resource_id: m.source_logical.clone(),
                    },
                    destination: types::ResourceLocation {
                        stack_name: m.dest_stack.clone(),
                        logical_resource_id: m.dest_logical.clone(),
                    },
                }),
                ..Default::default()
            });
        }
        let (items, next_token) =
            page(&all, input.next_token.as_deref(), input.max_results.unwrap_or(100).clamp(1, 100) as usize)?;
        Ok(types::ListStackRefactorActionsOutput { stack_refactor_actions: items, next_token })
    }

    pub(crate) async fn execute_stack_refactor_op(
        &self,
        ctx: &RequestContext,
        input: types::ExecuteStackRefactorInput,
    ) -> Result<(), ServiceError> {
        let r = self.refactor_view(ctx, &input.stack_refactor_id)?;
        for s in &r.stacks {
            ctx.authorize("cloudformation:ExecuteStackRefactor", &s.stack_id, Default::default())?;
        }
        if r.execution_status != "AVAILABLE" {
            return Err(validation(format!(
                "Stack refactor {} cannot be executed in its current state: {}",
                r.id, r.execution_status
            )));
        }
        {
            let mut st = self.state();
            if let Some(x) = st.refactors.get_mut(&r.id) {
                x.execution_status = "EXECUTE_IN_PROGRESS".into();
            }
        }
        let me = self.clone();
        let ctx = ctx.clone();
        for s in &r.stacks {
            self.start(&s.stack_id);
        }
        tokio::spawn(async move {
            let (status, reason) = match me.run_refactor(&ctx, &r).await {
                Ok(()) => ("EXECUTE_COMPLETE", None),
                Err(reason) => ("ROLLBACK_COMPLETE", Some(reason)),
            };
            {
                let mut st = me.state();
                if let Some(x) = st.refactors.get_mut(&r.id) {
                    x.execution_status = status.into();
                    x.execution_status_reason = reason;
                }
            }
            for s in &r.stacks {
                me.finished(&s.stack_id);
            }
        });
        Ok(())
    }

    async fn run_refactor(&self, ctx: &RequestContext, r: &StackRefactor) -> Result<(), String> {
        let operation_id = uuid::Uuid::new_v4().to_string();
        // What to restore if the refactor fails.
        let snapshots: BTreeMap<String, Stack> = {
            let st = self.state();
            r.stacks
                .iter()
                .filter_map(|d| st.stacks.get(&d.stack_id).map(|s| (d.stack_id.clone(), s.clone())))
                .collect()
        };
        let resource_of = |stack: &str, logical: &str| -> Option<Resource> {
            let d = r.stacks.iter().find(|d| d.name == stack)?;
            snapshots.get(&d.stack_id)?.resource(logical).cloned()
        };
        let mut templates = BTreeMap::new();
        for d in &r.stacks {
            let template = Template::parse(&d.template_body)?;
            let mut resources = Vec::new();
            for logical in template.resources().keys() {
                let moved = r.moves.iter().find(|m| m.dest_stack == d.name && &m.dest_logical == logical);
                let found = match moved {
                    Some(m) => resource_of(&m.source_stack, &m.source_logical),
                    None => resource_of(&d.name, logical),
                };
                let Some(mut res) = found else {
                    return Err(format!("Resource {logical} was not found in stack {}", d.name));
                };
                res.logical_id = logical.clone();
                res.updated = ctx.received_at;
                resources.push(res);
            }
            let (status, reason) = if d.create {
                ("CREATE_IN_PROGRESS", "User Initiated")
            } else {
                ("UPDATE_IN_PROGRESS", "Stack refactor")
            };
            {
                let mut st = self.state();
                let s = st.stacks.entry(d.stack_id.clone()).or_insert_with(|| Stack {
                    id: d.stack_id.clone(),
                    name: d.name.clone(),
                    account: ctx.caller.account_id.clone(),
                    region: ctx.region.clone(),
                    created: ctx.received_at,
                    ..Default::default()
                });
                s.status = status.into();
                s.status_reason = Some(reason.into());
                s.template_body = d.template_body.clone();
                s.description = template.description();
                s.resources = resources;
                s.updated = (!d.create).then_some(ctx.received_at);
                s.last_operation =
                    Some((if d.create { "CREATE_STACK" } else { "UPDATE_STACK" }.to_string(), operation_id.clone()));
                s.previous = None;
            }
            let deploy = self.deployment(ctx, ctx.clone(), &d.stack_id, None);
            deploy.event(&d.name, STACK_TYPE, Some(&d.stack_id), status, Some(reason), None).await;
            templates.insert(d.name.clone(), template);
        }
        for m in &r.moves {
            let Some(src) = r.stacks.iter().find(|d| d.name == m.source_stack) else { continue };
            let Some(dst) = r.stacks.iter().find(|d| d.name == m.dest_stack) else { continue };
            let reason = format!("Resource moved to stack {} as {}", m.dest_stack, m.dest_logical);
            let out = self.deployment(ctx, ctx.clone(), &src.stack_id, None);
            out.event(
                &m.source_logical,
                &m.resource_type,
                m.physical_id.as_deref(),
                "UPDATE_COMPLETE",
                Some(&reason),
                None,
            )
            .await;
            let reason = format!("Resource moved from stack {} ({})", m.source_stack, m.source_logical);
            let into = self.deployment(ctx, ctx.clone(), &dst.stack_id, None);
            into.event(
                &m.dest_logical,
                &m.resource_type,
                m.physical_id.as_deref(),
                "UPDATE_COMPLETE",
                Some(&reason),
                None,
            )
            .await;
        }
        // Resolve every stack again: exports one stack now provides may be
        // what another imports, so retry until nothing changes.
        let mut pending: Vec<&RefactorStack> = r.stacks.iter().collect();
        let mut last_error = String::new();
        let mut result = Ok(());
        while !pending.is_empty() {
            let before = pending.len();
            let mut later = Vec::new();
            for d in pending {
                match self.resolve_refactored(ctx, d, &templates[&d.name]).await {
                    Ok(()) => {}
                    Err((true, e)) => {
                        last_error = e;
                        later.push(d);
                    }
                    Err((false, e)) => {
                        result = Err(e);
                        later.clear();
                        break;
                    }
                }
            }
            if result.is_err() {
                break;
            }
            if later.len() == before {
                result = Err(last_error.clone());
                break;
            }
            pending = later;
        }
        match result {
            Ok(()) => {
                for d in &r.stacks {
                    let deploy = self.deployment(ctx, ctx.clone(), &d.stack_id, None);
                    deploy.stack_status(if d.create { "CREATE_COMPLETE" } else { "UPDATE_COMPLETE" }, None).await;
                }
                Ok(())
            }
            Err(reason) => {
                for d in &r.stacks {
                    let deploy = self.deployment(ctx, ctx.clone(), &d.stack_id, None);
                    if d.create {
                        self.state().stacks.remove(&d.stack_id);
                        continue;
                    }
                    deploy.stack_status("UPDATE_ROLLBACK_IN_PROGRESS", Some(&reason)).await;
                    if let Some(old) = snapshots.get(&d.stack_id) {
                        deploy.with(|s| {
                            s.template_body = old.template_body.clone();
                            s.description = old.description.clone();
                            s.resources = old.resources.clone();
                            s.outputs = old.outputs.clone();
                            s.imports = old.imports.clone();
                        });
                    }
                    deploy.stack_status("UPDATE_ROLLBACK_COMPLETE", None).await;
                }
                Err(reason)
            }
        }
    }

    /// Re-resolve one refactored stack's properties and outputs. Errors
    /// that another stack's outputs may fix (missing exports) are retried.
    async fn resolve_refactored(
        &self,
        ctx: &RequestContext,
        d: &RefactorStack,
        template: &Template,
    ) -> Result<(), (bool, String)> {
        let (previous, notifications) = {
            let st = self.state();
            let s = &st.stacks[&d.stack_id];
            (s.parameters.clone(), s.notification_arns.clone())
        };
        let params = parameters::assign(template, &[], &previous).map_err(|e| (false, e))?;
        let data = match self.eval_data(ctx, template, &params, &d.name, &d.stack_id, &notifications).await {
            Ok(x) => x,
            Err(e) if e.message.starts_with("No export named") => return Err((true, e.message)),
            Err(e) => return Err((false, e.message)),
        };
        let deploy = self.deployment(ctx, ctx.clone(), &d.stack_id, None);
        for logical in template.resources().keys() {
            if !data.included(template, logical) {
                continue;
            }
            let props = match deploy.properties(template, &data, logical).await {
                Ok(p) => p,
                Err(e) if e.contains("No export named") => return Err((true, e)),
                Err(e) => return Err((false, e)),
            };
            let same = deploy.with(|s| s.resource(logical).map(|r| r.properties == props).unwrap_or(true));
            if !same {
                return Err((
                    false,
                    format!("Resource {logical} in stack {} has properties that differ from the deployed resource. A stack refactor cannot modify resources.", d.name),
                ));
            }
        }
        let outputs = match deploy.outputs(template, &data) {
            Ok(o) => o,
            Err(e) if e.contains("No export named") => return Err((true, e)),
            Err(e) => return Err((false, e)),
        };
        deploy.with(|s| {
            s.parameters = params;
            s.outputs = outputs;
            s.imports = crate::ops::imports(template, &data);
        });
        Ok(())
    }

    pub(crate) fn describe_events_op(
        &self,
        ctx: &RequestContext,
        input: types::DescribeEventsInput,
    ) -> Result<types::DescribeEventsOutput, ServiceError> {
        if input.stack_name.is_none() && input.change_set_name.is_none() && input.operation_id.is_none() {
            return Err(validation("One of StackName, ChangeSetName or OperationId must be specified"));
        }
        let st = self.state();
        let mut out: Vec<types::OperationEvent> = Vec::new();
        let mut operation = input.operation_id.clone();
        let stacks: Vec<&Stack> = match (&input.change_set_name, &input.stack_name) {
            (Some(cs), stack) => {
                let (s, c) = crate::ops::change_sets::find_change_set(&st, ctx, cs, stack.as_deref())?;
                ctx.authorize("cloudformation:DescribeEvents", &s.id, Default::default())?;
                // The change set's creation, then (once executed) the
                // operation that executed it.
                let status = match c.status.as_str() {
                    "CREATE_COMPLETE" => "SUCCEEDED",
                    "FAILED" => "FAILED",
                    _ => "IN_PROGRESS",
                };
                if operation.as_ref().is_none_or(|o| o == &c.operation_id) {
                    out.push(types::OperationEvent {
                        event_id: Some(format!("{}-{}", c.operation_id, c.status)),
                        stack_id: Some(s.id.clone()),
                        operation_id: Some(c.operation_id.clone()),
                        operation_type: Some("CREATE_CHANGESET".into()),
                        operation_status: Some(status.into()),
                        event_type: Some(if status == "FAILED" { "VALIDATION_ERROR" } else { "STACK_EVENT" }.into()),
                        logical_resource_id: Some(s.name.clone()),
                        physical_resource_id: Some(s.id.clone()),
                        resource_type: Some(STACK_TYPE.into()),
                        timestamp: Some(c.created),
                        start_time: Some(c.created),
                        end_time: (status != "IN_PROGRESS").then_some(c.created),
                        resource_status: Some(c.status.clone()),
                        resource_status_reason: c.status_reason.clone(),
                        validation_status: (status == "FAILED").then(|| "FAILED".into()),
                        validation_status_reason: c.status_reason.clone().filter(|_| status == "FAILED"),
                        ..Default::default()
                    });
                }
                match &c.execution_operation_id {
                    Some(op) if operation.as_ref().is_none_or(|o| o == op) => {
                        operation = Some(op.clone());
                        vec![s]
                    }
                    _ => Vec::new(),
                }
            }
            (None, Some(name)) => {
                let s = find(&st, ctx, name)?;
                ctx.authorize("cloudformation:DescribeEvents", &s.id, Default::default())?;
                vec![s]
            }
            (None, None) => {
                let op = input.operation_id.clone().unwrap_or_default();
                let found: Vec<&Stack> = st
                    .stacks
                    .values()
                    .filter(|s| s.account == ctx.caller.account_id && s.region == ctx.region)
                    .filter(|s| s.events.iter().any(|e| e.operation_id.as_deref() == Some(op.as_str())))
                    .collect();
                for s in &found {
                    ctx.authorize("cloudformation:DescribeEvents", &s.id, Default::default())?;
                }
                found
            }
        };
        for s in stacks {
            let mut ops: BTreeMap<&str, Vec<&Event>> = BTreeMap::new();
            for e in &s.events {
                if let Some(op) = e.operation_id.as_deref() {
                    if operation.as_deref().is_none_or(|o| o == op) {
                        ops.entry(op).or_default().push(e);
                    }
                }
            }
            for (op, events) in ops {
                let stack_events: Vec<&&Event> =
                    events.iter().filter(|e| e.resource_type == STACK_TYPE && e.logical_id == s.name).collect();
                let first = stack_events.first().map(|e| e.status.as_str()).unwrap_or_default();
                let op_type = match (first, s.last_operation.as_ref().filter(|(_, id)| id == op)) {
                    (_, Some((t, _))) if t == "ROLLBACK" => "ROLLBACK",
                    ("CREATE_IN_PROGRESS", _) => "CREATE_STACK",
                    ("DELETE_IN_PROGRESS", _) => "DELETE_STACK",
                    ("UPDATE_ROLLBACK_IN_PROGRESS", _) => "CONTINUE_ROLLBACK",
                    ("ROLLBACK_IN_PROGRESS", _) => "ROLLBACK",
                    _ => "UPDATE_STACK",
                };
                let last = stack_events.last().map(|e| e.status.as_str()).unwrap_or_default();
                let op_status = if last.ends_with("_IN_PROGRESS") || last.is_empty() {
                    "IN_PROGRESS"
                } else if last.ends_with("FAILED") || last.contains("ROLLBACK") {
                    "FAILED"
                } else {
                    "SUCCEEDED"
                };
                let start = events.first().map(|e| e.timestamp);
                for e in events {
                    let is_stack = e.resource_type == STACK_TYPE && e.logical_id == s.name;
                    let failed_hook = e.hook_status.as_deref().is_some_and(|h| h.ends_with("FAILED"));
                    let event_type = if failed_hook {
                        "HOOK_INVOCATION_ERROR"
                    } else if e.status.ends_with("_FAILED") && !is_stack {
                        "PROVISIONING_ERROR"
                    } else if is_stack {
                        "STACK_EVENT"
                    } else {
                        "PROGRESS_EVENT"
                    };
                    let failed = e.status.ends_with("FAILED") || failed_hook;
                    if input.filters.as_ref().and_then(|f| f.failed_events) == Some(true) && !failed {
                        continue;
                    }
                    out.push(types::OperationEvent {
                        event_id: Some(e.id.clone()),
                        stack_id: Some(s.id.clone()),
                        operation_id: Some(op.to_string()),
                        operation_type: Some(op_type.into()),
                        operation_status: Some(op_status.into()),
                        event_type: Some(event_type.into()),
                        logical_resource_id: Some(e.logical_id.clone()),
                        physical_resource_id: e.physical_id.clone(),
                        resource_type: Some(e.resource_type.clone()),
                        timestamp: Some(e.timestamp),
                        start_time: if is_stack { start } else { None },
                        end_time: (is_stack && !e.status.ends_with("_IN_PROGRESS")).then_some(e.timestamp),
                        resource_status: Some(e.status.clone()),
                        resource_status_reason: e.reason.clone(),
                        resource_properties: e.properties.clone(),
                        client_request_token: e.client_request_token.clone(),
                        hook_type: e.hook_type.clone(),
                        hook_status: e.hook_status.clone(),
                        hook_status_reason: e.hook_status_reason.clone(),
                        hook_invocation_point: e.hook_invocation_point.clone(),
                        hook_failure_mode: e.hook_failure_mode.clone(),
                        ..Default::default()
                    });
                }
            }
        }
        // Newest first, like DescribeStackEvents.
        out.sort_by_key(|e| std::cmp::Reverse(e.timestamp));
        let (items, next_token) = page(&out, input.next_token.as_deref(), 100)?;
        Ok(types::DescribeEventsOutput { operation_events: Some(items), next_token })
    }
}

/// Work out which resources move where, or why the refactor can't run.
fn plan(
    defs: &[(String, String, Template)],
    current: &BTreeMap<String, Stack>,
    mappings: &[types::ResourceMapping],
) -> Result<Vec<Move>, String> {
    let old_template: BTreeMap<&str, Template> =
        current.iter().filter_map(|(n, s)| Template::parse(&s.template_body).ok().map(|t| (n.as_str(), t))).collect();
    let old_def = |stack: &str, logical: &str| -> Option<Map<String, Value>> {
        old_template.get(stack).and_then(|t| t.resource(logical)).cloned()
    };
    let new_def = |stack: &str, logical: &str| -> Option<&Map<String, Value>> {
        defs.iter().find(|(n, _, _)| n == stack).and_then(|(_, _, t)| t.resource(logical))
    };
    let mut moves: Vec<Move> = Vec::new();
    for m in mappings {
        let (src, dst) = (&m.source, &m.destination);
        if !defs.iter().any(|(n, _, _)| n == &src.stack_name) {
            return Err(format!("Source stack {} must be included in StackDefinitions", src.stack_name));
        }
        if old_def(&src.stack_name, &src.logical_resource_id).is_none() {
            return Err(format!("Resource {} does not exist in stack {}", src.logical_resource_id, src.stack_name));
        }
        if new_def(&dst.stack_name, &dst.logical_resource_id).is_none() {
            return Err(format!(
                "Resource {} is not defined in the template for stack {}",
                dst.logical_resource_id, dst.stack_name
            ));
        }
        if moves.iter().any(|x| {
            (x.source_stack == src.stack_name && x.source_logical == src.logical_resource_id)
                || (x.dest_stack == dst.stack_name && x.dest_logical == dst.logical_resource_id)
        }) {
            return Err(format!("Resource {} is mapped more than once", src.logical_resource_id));
        }
        moves.push(mv(
            current,
            &src.stack_name,
            &src.logical_resource_id,
            &dst.stack_name,
            &dst.logical_resource_id,
            true,
        ));
    }
    let mut added = Vec::new();
    for (name, _, t) in defs {
        for logical in t.resources().keys() {
            if moves.iter().any(|m| &m.dest_stack == name && &m.dest_logical == logical) {
                continue;
            }
            let moved_away = moves.iter().any(|m| &m.source_stack == name && &m.source_logical == logical);
            if old_def(name, logical).is_some() && !moved_away {
                continue;
            }
            // Auto-detect: the same logical id leaving another stack.
            let source = defs.iter().map(|(n, _, _)| n).find(|other| {
                *other != name
                    && old_def(other, logical).is_some()
                    && new_def(other, logical).is_none()
                    && !moves.iter().any(|m| &m.source_stack == *other && &m.source_logical == logical)
            });
            match source {
                Some(other) => moves.push(mv(current, other, logical, name, logical, false)),
                None => added.push(format!("{name}/{logical}")),
            }
        }
    }
    if !added.is_empty() {
        return Err(format!("Stack refactor does not support creating new resources: [{}]", added.join(", ")));
    }
    let mut removed = Vec::new();
    for (name, s) in current {
        for r in &s.resources {
            let kept = new_def(name, &r.logical_id).is_some()
                && !moves.iter().any(|m| &m.source_stack == name && m.source_logical == r.logical_id);
            let moved = moves.iter().any(|m| &m.source_stack == name && m.source_logical == r.logical_id);
            if !kept && !moved {
                removed.push(format!("{name}/{}", r.logical_id));
            }
        }
    }
    if !removed.is_empty() {
        return Err(format!("Stack refactor does not support deleting resources: [{}]", removed.join(", ")));
    }
    // Resources must arrive unchanged.
    let mut pairs: Vec<(String, String, String, String)> = Vec::new();
    for m in &moves {
        pairs.push((m.source_stack.clone(), m.source_logical.clone(), m.dest_stack.clone(), m.dest_logical.clone()));
    }
    for (name, s) in current {
        for r in &s.resources {
            if !moves.iter().any(|m| &m.source_stack == name && m.source_logical == r.logical_id) {
                pairs.push((name.clone(), r.logical_id.clone(), name.clone(), r.logical_id.clone()));
            }
        }
    }
    for (ss, sl, ds, dl) in pairs {
        let (Some(a), Some(b)) = (old_def(&ss, &sl), new_def(&ds, &dl)) else { continue };
        let ((ta, pa), (tb, pb)) = (comparable(&a), comparable(b));
        if ta != tb {
            return Err(format!(
                "Resource {dl} in stack {ds} must keep the type {}",
                ta.and_then(Value::as_str).unwrap_or("")
            ));
        }
        let literal = !pa.is_some_and(has_intrinsics) && !pb.is_some_and(has_intrinsics);
        if literal && pa != pb {
            return Err(format!(
                "Resource {dl} in stack {ds} has properties that differ from the deployed resource. A stack refactor cannot modify resources."
            ));
        }
    }
    if moves.is_empty() {
        return Err("Stack refactor did not find any resources to move".into());
    }
    Ok(moves)
}

fn mv(current: &BTreeMap<String, Stack>, ss: &str, sl: &str, ds: &str, dl: &str, manual: bool) -> Move {
    let r = current.get(ss).and_then(|s| s.resource(sl));
    Move {
        source_stack: ss.into(),
        source_logical: sl.into(),
        dest_stack: ds.into(),
        dest_logical: dl.into(),
        resource_type: r.map(|r| r.resource_type.clone()).unwrap_or_default(),
        physical_id: r.and_then(|r| r.physical_id.clone()),
        manual,
    }
}

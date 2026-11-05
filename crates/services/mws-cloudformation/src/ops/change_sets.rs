//! Change sets.

use mws_core::{RequestContext, ServiceError};
use serde_json::Value;

use super::stacks::{resource_types, tags_of};
use super::{convert, find, page, provided, stack_resource, validation};
use crate::changes::{self, ResourceChange};
use crate::engine::STACK_TYPE;
use crate::generated::{errors, types};
use crate::parameters::Provided;
use crate::state::{ChangeSet, Snapshot, Stack, State};
use crate::template::Template;
use crate::CloudFormation;

/// Find a change set by ARN, or by name within a stack.
pub(crate) fn find_change_set<'a>(
    st: &'a State,
    ctx: &RequestContext,
    name: &str,
    stack_name: Option<&str>,
) -> Result<(&'a Stack, &'a ChangeSet), ServiceError> {
    let missing = || errors::change_set_not_found(format!("ChangeSet [{name}] does not exist"));
    if name.starts_with("arn:") {
        for s in st.stacks.values() {
            if s.account != ctx.caller.account_id || s.region != ctx.region {
                continue;
            }
            if let Some(cs) = s.change_sets.get(name) {
                return Ok((s, cs));
            }
        }
        return Err(missing());
    }
    let Some(stack_name) = stack_name else {
        return Err(validation("StackName must be specified if ChangeSetName is not specified as an ARN."));
    };
    let s = find(st, ctx, stack_name).map_err(|_| missing())?;
    let cs = s.change_sets.values().find(|c| c.name == name).ok_or_else(missing)?;
    Ok((s, cs))
}

pub(crate) fn change_set_arn(ctx: &RequestContext, name: &str) -> String {
    format!(
        "arn:{}:cloudformation:{}:{}:changeSet/{name}/{}",
        ctx.partition,
        ctx.region,
        ctx.caller.account_id,
        uuid::Uuid::new_v4()
    )
}

impl CloudFormation {
    pub(crate) async fn create_change_set_op(
        &self,
        ctx: &RequestContext,
        input: types::CreateChangeSetInput,
    ) -> Result<types::CreateChangeSetOutput, ServiceError> {
        let kind = input.change_set_type.clone().unwrap_or_else(|| "UPDATE".into());
        if kind == "IMPORT" {
            return self.create_import_change_set(ctx, input).await;
        }
        let existing = { find(&self.state(), ctx, &input.stack_name).ok().cloned() };
        let body = if input.use_previous_template == Some(true) {
            match &existing {
                Some(s) if kind != "CREATE" => s.template_body.clone(),
                _ => return Err(validation("UsePreviousTemplate can only be used with an existing stack")),
            }
        } else {
            self.template_text(ctx, input.template_body.as_deref(), input.template_url.as_deref()).await?
        };
        let tags = tags_of(input.tags.clone());
        let resource =
            existing.as_ref().map(|s| s.id.clone()).unwrap_or_else(|| stack_resource(ctx, &input.stack_name));
        self.authorize_stack(
            ctx,
            "cloudformation:CreateChangeSet",
            &resource,
            input.template_url.as_deref(),
            input.role_arn.as_deref(),
            &resource_types(&body),
            tags.as_deref().unwrap_or_default(),
            None,
        )?;
        ctx.authorize(
            "cloudformation:CreateChangeSet",
            &resource,
            super::condition_keys(&[("cloudformation:ChangeSetName", vec![input.change_set_name.clone()])]),
        )?;
        let stack = match (kind.as_str(), existing) {
            ("CREATE", Some(s)) if s.status != "REVIEW_IN_PROGRESS" => {
                return Err(validation(format!(
                    "Stack [{}] already exists and cannot be created again with the changeSet [{}].",
                    input.stack_name, input.change_set_name
                )))
            }
            ("CREATE", Some(s)) => s,
            ("CREATE", None) => {
                let id = super::new_stack_id(ctx, &input.stack_name);
                let s = Stack {
                    id: id.clone(),
                    name: input.stack_name.clone(),
                    account: ctx.caller.account_id.clone(),
                    region: ctx.region.clone(),
                    status: "REVIEW_IN_PROGRESS".into(),
                    status_reason: Some("User Initiated".into()),
                    created: ctx.received_at,
                    ..Default::default()
                };
                self.state().stacks.insert(id.clone(), s.clone());
                let d = self.deployment(ctx, ctx.clone(), &id, None);
                d.event(&s.name, STACK_TYPE, Some(&id), "REVIEW_IN_PROGRESS", Some("User Initiated"), None).await;
                s
            }
            ("UPDATE", Some(s)) if s.status == "REVIEW_IN_PROGRESS" => {
                return Err(validation(format!("Stack [{}] does not exist", input.stack_name)))
            }
            ("UPDATE", Some(s)) => s,
            ("UPDATE", None) => return Err(validation(format!("Stack [{}] does not exist", input.stack_name))),
            (other, _) => return Err(validation(format!("ChangeSetType {other} is not valid"))),
        };
        if stack.change_sets.values().any(|c| c.name == input.change_set_name) {
            return Err(errors::already_exists(format!("ChangeSet {} already exists", input.change_set_name)));
        }
        let role = input.role_arn.clone().or_else(|| stack.role_arn.clone());
        let deploy = self.deploy_context(ctx, role.as_deref())?;
        let caps = input.capabilities.clone().unwrap_or_default();
        let notifications = input.notification_ar_ns.clone().unwrap_or_else(|| stack.notification_arns.clone());
        let (template, params, data) = self
            .prepare(
                ctx,
                &deploy,
                &stack.name,
                &stack.id,
                &body,
                &provided(input.parameters.clone()),
                &stack.parameters,
                &caps,
                &notifications,
            )
            .await?;
        let id = change_set_arn(ctx, &input.change_set_name);
        let mut cs = ChangeSet {
            id: id.clone(),
            name: input.change_set_name.clone(),
            stack_id: stack.id.clone(),
            change_set_type: kind.clone(),
            description: input.description.clone(),
            status: "CREATE_COMPLETE".into(),
            execution_status: "AVAILABLE".into(),
            created: ctx.received_at,
            template_body: body,
            parameters: params.clone(),
            tags,
            capabilities: caps,
            notification_arns: input.notification_ar_ns.clone(),
            role_arn: input.role_arn.clone(),
            on_stack_failure: input.on_stack_failure.clone(),
            ..Default::default()
        };
        match changes::compute(self, &stack, &template, &data) {
            Ok(list) => {
                let same_template =
                    Template::parse(&stack.template_body).map(|t| t.root == template.root).unwrap_or(false);
                let same_params = params.iter().map(|p| (&p.key, &p.value)).collect::<Vec<_>>()
                    == stack.parameters.iter().map(|p| (&p.key, &p.value)).collect::<Vec<_>>();
                let same_tags = cs.tags.as_ref().is_none_or(|t| {
                    t.iter().map(|x| (&x.key, &x.value)).collect::<Vec<_>>()
                        == stack.tags.iter().map(|x| (&x.key, &x.value)).collect::<Vec<_>>()
                });
                if kind == "UPDATE" && list.is_empty() && same_template && same_params && same_tags {
                    cs.status = "FAILED".into();
                    cs.execution_status = "UNAVAILABLE".into();
                    cs.status_reason = Some(
                        "The submitted information didn't contain changes. Submit different information to create a change set."
                            .into(),
                    );
                }
                cs.changes = list.iter().map(|c| serde_json::to_value(c).unwrap_or_default()).collect();
            }
            Err(reason) => {
                cs.status = "FAILED".into();
                cs.execution_status = "UNAVAILABLE".into();
                cs.status_reason = Some(reason);
            }
        }
        let stack_id = stack.id.clone();
        if let Some(s) = self.state().stacks.get_mut(&stack_id) {
            s.change_sets.insert(id.clone(), cs);
        }
        Ok(types::CreateChangeSetOutput { id: Some(id), stack_id: Some(stack_id) })
    }

    pub(crate) fn describe_change_set_op(
        &self,
        ctx: &RequestContext,
        input: types::DescribeChangeSetInput,
    ) -> Result<types::DescribeChangeSetOutput, ServiceError> {
        let st = self.state();
        let (s, cs) = find_change_set(&st, ctx, &input.change_set_name, input.stack_name.as_deref())?;
        ctx.authorize(
            "cloudformation:DescribeChangeSet",
            &s.id,
            super::condition_keys(&[("cloudformation:ChangeSetName", vec![cs.name.clone()])]),
        )?;
        let with_values = input.include_property_values.unwrap_or(false);
        let changes: Vec<types::Change> = cs
            .changes
            .iter()
            .filter_map(|c| serde_json::from_value::<ResourceChange>(c.clone()).ok())
            .map(|c| convert::change(&c, with_values))
            .collect();
        let (changes, next) = page(&changes, input.next_token.as_deref(), 100)?;
        Ok(types::DescribeChangeSetOutput {
            change_set_name: Some(cs.name.clone()),
            change_set_id: Some(cs.id.clone()),
            stack_id: Some(s.id.clone()),
            stack_name: Some(s.name.clone()),
            description: cs.description.clone(),
            parameters: convert::parameters(&cs.parameters),
            creation_time: Some(cs.created),
            execution_status: Some(cs.execution_status.clone()),
            status: Some(cs.status.clone()),
            status_reason: cs.status_reason.clone(),
            notification_ar_ns: Some(cs.notification_arns.clone().unwrap_or_else(|| s.notification_arns.clone())),
            rollback_configuration: Some(types::RollbackConfiguration::default()),
            capabilities: (!cs.capabilities.is_empty()).then(|| cs.capabilities.clone()),
            tags: convert::tags(cs.tags.as_deref().unwrap_or(&s.tags)),
            changes: Some(changes),
            next_token: next,
            include_nested_stacks: Some(false),
            on_stack_failure: cs.on_stack_failure.clone(),
            import_existing_resources: Some(cs.import_existing_resources),
            ..Default::default()
        })
    }

    pub(crate) fn list_change_sets_op(
        &self,
        ctx: &RequestContext,
        input: types::ListChangeSetsInput,
    ) -> Result<types::ListChangeSetsOutput, ServiceError> {
        let st = self.state();
        let s = find(&st, ctx, &input.stack_name)?;
        ctx.authorize("cloudformation:ListChangeSets", &s.id, Default::default())?;
        let mut v: Vec<&ChangeSet> = s.change_sets.values().collect();
        v.sort_by_key(|a| a.created);
        let all: Vec<types::ChangeSetSummary> = v
            .into_iter()
            .map(|cs| types::ChangeSetSummary {
                stack_id: Some(s.id.clone()),
                stack_name: Some(s.name.clone()),
                change_set_id: Some(cs.id.clone()),
                change_set_name: Some(cs.name.clone()),
                execution_status: Some(cs.execution_status.clone()),
                status: Some(cs.status.clone()),
                status_reason: cs.status_reason.clone(),
                creation_time: Some(cs.created),
                description: cs.description.clone(),
                include_nested_stacks: Some(false),
                import_existing_resources: Some(cs.import_existing_resources),
                ..Default::default()
            })
            .collect();
        let (items, next) = page(&all, input.next_token.as_deref(), 100)?;
        Ok(types::ListChangeSetsOutput { summaries: Some(items), next_token: next })
    }

    pub(crate) fn delete_change_set_op(
        &self,
        ctx: &RequestContext,
        input: types::DeleteChangeSetInput,
    ) -> Result<types::DeleteChangeSetOutput, ServiceError> {
        let mut st = self.state();
        let (stack_id, cs_id, status) = {
            let (s, cs) = find_change_set(&st, ctx, &input.change_set_name, input.stack_name.as_deref())?;
            (s.id.clone(), cs.id.clone(), cs.execution_status.clone())
        };
        ctx.authorize("cloudformation:DeleteChangeSet", &stack_id, Default::default())?;
        if status == "EXECUTE_IN_PROGRESS" {
            return Err(errors::invalid_change_set_status(format!("Cannot delete ChangeSet in status {status}")));
        }
        if let Some(s) = st.stacks.get_mut(&stack_id) {
            s.change_sets.remove(&cs_id);
        }
        Ok(types::DeleteChangeSetOutput::default())
    }

    pub(crate) async fn execute_change_set_op(
        &self,
        ctx: &RequestContext,
        input: types::ExecuteChangeSetInput,
    ) -> Result<types::ExecuteChangeSetOutput, ServiceError> {
        let (stack, cs) = {
            let st = self.state();
            let (s, cs) = find_change_set(&st, ctx, &input.change_set_name, input.stack_name.as_deref())?;
            (s.clone(), cs.clone())
        };
        ctx.authorize(
            "cloudformation:ExecuteChangeSet",
            &stack.id,
            super::condition_keys(&[("cloudformation:ChangeSetName", vec![cs.name.clone()])]),
        )?;
        if cs.status != "CREATE_COMPLETE" || cs.execution_status != "AVAILABLE" {
            return Err(errors::invalid_change_set_status(format!(
                "ChangeSet [{}] cannot be executed in its current execution status of [{}]",
                cs.id, cs.execution_status
            )));
        }
        if stack.in_progress() && stack.status != "REVIEW_IN_PROGRESS" {
            return Err(errors::invalid_change_set_status(format!(
                "ChangeSet [{}] cannot be executed in its current status of [{}]",
                cs.id, stack.status
            )));
        }
        if cs.change_set_type == "IMPORT" {
            return self.execute_import(ctx, &stack, &cs, input.client_request_token.clone()).await;
        }
        let role = cs.role_arn.clone().or_else(|| stack.role_arn.clone());
        let deploy = self.deploy_context(ctx, role.as_deref())?;
        let notifications = cs.notification_arns.clone().unwrap_or_else(|| stack.notification_arns.clone());
        let provided: Vec<Provided> = cs
            .parameters
            .iter()
            .map(|p| Provided { key: p.key.clone(), value: Some(p.value.clone()), use_previous: false })
            .collect();
        let (template, params, data) = self
            .prepare(
                ctx,
                &deploy,
                &stack.name,
                &stack.id,
                &cs.template_body,
                &provided,
                &[],
                &cs.capabilities,
                &notifications,
            )
            .await?;
        let operation_id = uuid::Uuid::new_v4().to_string();
        let creating = cs.change_set_type == "CREATE";
        {
            let mut st = self.state();
            let s = st.stacks.get_mut(&stack.id).expect("found above");
            if !creating {
                s.previous = Some(Box::new(Snapshot {
                    template_body: s.template_body.clone(),
                    parameters: s.parameters.clone(),
                    resources: s.resources.clone(),
                    outputs: s.outputs.clone(),
                    tags: s.tags.clone(),
                }));
                s.updated = Some(ctx.received_at);
            }
            s.template_body = cs.template_body.clone();
            s.description = template.description();
            s.parameters = params;
            if let Some(t) = &cs.tags {
                s.tags = t.clone();
            }
            s.capabilities = cs.capabilities.clone();
            s.notification_arns = notifications;
            s.role_arn = role;
            s.change_set_id = Some(cs.id.clone());
            s.imports = super::imports(&template, &data);
            if let Some(d) = input.disable_rollback {
                s.disable_rollback = d;
            }
            if let Some(r) = input.retain_except_on_create {
                s.retain_except_on_create = r;
            }
            if creating {
                s.on_failure = cs.on_stack_failure.clone().filter(|f| f != "ROLLBACK");
            }
            let status = if creating { "CREATE_IN_PROGRESS" } else { "UPDATE_IN_PROGRESS" };
            s.status = status.into();
            s.status_reason = Some("User Initiated".into());
            s.last_operation =
                Some((if creating { "CREATE_STACK".into() } else { "UPDATE_STACK".into() }, operation_id));
            // Executing a change set removes the stack's other change sets.
            s.change_sets.retain(|id, _| id == &cs.id);
            if let Some(c) = s.change_sets.get_mut(&cs.id) {
                c.execution_status = "EXECUTE_COMPLETE".into();
            }
        }
        let d = self.deployment(ctx, deploy, &stack.id, input.client_request_token.clone());
        let status = if creating { "CREATE_IN_PROGRESS" } else { "UPDATE_IN_PROGRESS" };
        d.event(&stack.name, STACK_TYPE, Some(&stack.id), status, Some("User Initiated"), None).await;
        self.start(&stack.id);
        if creating {
            tokio::spawn(d.create(template, data));
        } else {
            tokio::spawn(d.update(template, data, None));
        }
        Ok(types::ExecuteChangeSetOutput::default())
    }

    pub(crate) fn describe_change_set_hooks_op(
        &self,
        ctx: &RequestContext,
        input: types::DescribeChangeSetHooksInput,
    ) -> Result<types::DescribeChangeSetHooksOutput, ServiceError> {
        let st = self.state();
        let (s, cs) = find_change_set(&st, ctx, &input.change_set_name, input.stack_name.as_deref())?;
        ctx.authorize("cloudformation:DescribeChangeSetHooks", &s.id, Default::default())?;
        Ok(types::DescribeChangeSetHooksOutput {
            change_set_id: Some(cs.id.clone()),
            change_set_name: Some(cs.name.clone()),
            hooks: Some(Vec::new()),
            status: Some("UNAVAILABLE".into()),
            next_token: None,
            stack_id: Some(s.id.clone()),
            stack_name: Some(s.name.clone()),
        })
    }
}

impl CloudFormation {
    /// An IMPORT change set: existing resources the template describes,
    /// named by their identifiers, join the stack.
    async fn create_import_change_set(
        &self,
        ctx: &RequestContext,
        input: types::CreateChangeSetInput,
    ) -> Result<types::CreateChangeSetOutput, ServiceError> {
        let imports = input.resources_to_import.clone().unwrap_or_default();
        if imports.is_empty() {
            return Err(validation("ResourcesToImport must be specified for an IMPORT change set"));
        }
        let existing = { find(&self.state(), ctx, &input.stack_name).ok().cloned() };
        let body = self.template_text(ctx, input.template_body.as_deref(), input.template_url.as_deref()).await?;
        let resource =
            existing.as_ref().map(|s| s.id.clone()).unwrap_or_else(|| stack_resource(ctx, &input.stack_name));
        let tags = tags_of(input.tags.clone());
        self.authorize_stack(
            ctx,
            "cloudformation:CreateChangeSet",
            &resource,
            input.template_url.as_deref(),
            input.role_arn.as_deref(),
            &resource_types(&body),
            tags.as_deref().unwrap_or_default(),
            None,
        )?;
        let stack = match existing {
            Some(s) if s.in_progress() && s.status != "REVIEW_IN_PROGRESS" => {
                return Err(validation(format!("Stack:{} is in {} state and can not be updated.", s.id, s.status)))
            }
            Some(s) => s,
            None => {
                let id = super::new_stack_id(ctx, &input.stack_name);
                let s = Stack {
                    id: id.clone(),
                    name: input.stack_name.clone(),
                    account: ctx.caller.account_id.clone(),
                    region: ctx.region.clone(),
                    status: "REVIEW_IN_PROGRESS".into(),
                    status_reason: Some("User Initiated".into()),
                    created: ctx.received_at,
                    ..Default::default()
                };
                self.state().stacks.insert(id.clone(), s.clone());
                let d = self.deployment(ctx, ctx.clone(), &id, None);
                d.event(&s.name, STACK_TYPE, Some(&id), "REVIEW_IN_PROGRESS", Some("User Initiated"), None).await;
                s
            }
        };
        if stack.change_sets.values().any(|c| c.name == input.change_set_name) {
            return Err(errors::already_exists(format!("ChangeSet {} already exists", input.change_set_name)));
        }
        let role = input.role_arn.clone().or_else(|| stack.role_arn.clone());
        let deploy = self.deploy_context(ctx, role.as_deref())?;
        let caps = input.capabilities.clone().unwrap_or_default();
        let notifications = input.notification_ar_ns.clone().unwrap_or_else(|| stack.notification_arns.clone());
        let (template, params, _data) = self
            .prepare(
                ctx,
                &deploy,
                &stack.name,
                &stack.id,
                &body,
                &provided(input.parameters.clone()),
                &stack.parameters,
                &caps,
                &notifications,
            )
            .await?;
        // Template checks AWS makes before looking the resources up.
        let in_stack: Vec<String> =
            stack.resources.iter().filter(|r| r.exists()).map(|r| r.logical_id.clone()).collect();
        let importing: Vec<String> = imports.iter().map(|i| i.logical_resource_id.clone()).collect();
        for i in &imports {
            let Some(def) = template.resource(&i.logical_resource_id) else {
                return Err(validation(format!(
                    "Resource {} specified in ResourcesToImport does not exist in the template",
                    i.logical_resource_id
                )));
            };
            if def.get("Type").and_then(Value::as_str) != Some(i.resource_type.as_str()) {
                return Err(validation(format!(
                    "Resource type {} of {} in ResourcesToImport does not match the template",
                    i.resource_type, i.logical_resource_id
                )));
            }
            if def.get("DeletionPolicy").is_none() {
                return Err(validation(format!(
                    "The following resources to import [{}] must have DeletionPolicy attribute specified in the template.",
                    i.logical_resource_id
                )));
            }
            if in_stack.contains(&i.logical_resource_id) {
                return Err(validation(format!(
                    "Resource {} already exists in stack {}",
                    i.logical_resource_id, stack.id
                )));
            }
        }
        let added: Vec<String> =
            template.resources().keys().filter(|l| !in_stack.contains(l) && !importing.contains(l)).cloned().collect();
        if !added.is_empty() {
            return Err(validation(format!(
                "As part of the import operation, you cannot modify or add [{}]",
                added.join(", ")
            )));
        }
        let mut cs = ChangeSet {
            id: change_set_arn(ctx, &input.change_set_name),
            name: input.change_set_name.clone(),
            stack_id: stack.id.clone(),
            change_set_type: "IMPORT".into(),
            description: input.description.clone(),
            status: "CREATE_COMPLETE".into(),
            execution_status: "AVAILABLE".into(),
            created: ctx.received_at,
            template_body: body,
            parameters: params,
            tags,
            capabilities: caps,
            notification_arns: input.notification_ar_ns.clone(),
            role_arn: input.role_arn.clone(),
            ..Default::default()
        };
        let managed: Vec<(String, String, String)> = {
            let st = self.state();
            st.stacks
                .values()
                .filter(|s| s.account == stack.account && s.region == stack.region && !s.is_deleted())
                .flat_map(|s| {
                    s.resources
                        .iter()
                        .filter(|r| r.exists())
                        .filter_map(|r| Some((r.resource_type.clone(), r.physical_id.clone()?, s.name.clone())))
                        .collect::<Vec<_>>()
                })
                .collect()
        };
        let mut missing = Vec::new();
        for i in &imports {
            match self.find_existing(&deploy, &i.resource_type, &i.resource_identifier).await {
                Ok(Some(found)) => {
                    if let Some((_, _, owner)) =
                        managed.iter().find(|(t, p, _)| t == &i.resource_type && p == &found.physical_id)
                    {
                        cs.status = "FAILED".into();
                        cs.execution_status = "UNAVAILABLE".into();
                        cs.status_reason = Some(format!(
                            "Resource with identifier {:?} already exists in stack {owner}.",
                            i.resource_identifier
                        ));
                    }
                    cs.changes.push(
                        serde_json::to_value(ResourceChange {
                            action: "Import".into(),
                            logical_id: i.logical_resource_id.clone(),
                            physical_id: Some(found.physical_id.clone()),
                            resource_type: i.resource_type.clone(),
                            ..Default::default()
                        })
                        .unwrap_or_default(),
                    );
                    cs.resources_to_import.insert(i.logical_resource_id.clone(), i.resource_identifier.clone());
                }
                Ok(None) => missing.push(i.logical_resource_id.clone()),
                Err(reason) => {
                    cs.status = "FAILED".into();
                    cs.execution_status = "UNAVAILABLE".into();
                    cs.status_reason = Some(reason);
                }
            }
        }
        if !missing.is_empty() {
            cs.status = "FAILED".into();
            cs.execution_status = "UNAVAILABLE".into();
            cs.status_reason = Some(format!("Resources [{}] to import do not exist.", missing.join(", ")));
        }
        let id = cs.id.clone();
        let stack_id = stack.id.clone();
        if let Some(s) = self.state().stacks.get_mut(&stack_id) {
            s.change_sets.insert(id.clone(), cs);
        }
        Ok(types::CreateChangeSetOutput { id: Some(id), stack_id: Some(stack_id) })
    }

    async fn execute_import(
        &self,
        ctx: &RequestContext,
        stack: &Stack,
        cs: &ChangeSet,
        token: Option<String>,
    ) -> Result<types::ExecuteChangeSetOutput, ServiceError> {
        let role = cs.role_arn.clone().or_else(|| stack.role_arn.clone());
        let deploy = self.deploy_context(ctx, role.as_deref())?;
        let notifications = cs.notification_arns.clone().unwrap_or_else(|| stack.notification_arns.clone());
        let provided: Vec<Provided> = cs
            .parameters
            .iter()
            .map(|p| Provided { key: p.key.clone(), value: Some(p.value.clone()), use_previous: false })
            .collect();
        let (template, params, data) = self
            .prepare(
                ctx,
                &deploy,
                &stack.name,
                &stack.id,
                &cs.template_body,
                &provided,
                &[],
                &cs.capabilities,
                &notifications,
            )
            .await?;
        let mut imports = Vec::new();
        for (logical, identifier) in &cs.resources_to_import {
            let ty = template.resource_type(logical).unwrap_or_default().to_string();
            match self.find_existing(&deploy, &ty, identifier).await {
                Ok(Some(found)) => imports.push((logical.clone(), found)),
                _ => {
                    return Err(errors::invalid_change_set_status(format!(
                        "Resource {logical} to import no longer exists"
                    )))
                }
            }
        }
        let operation_id = uuid::Uuid::new_v4().to_string();
        {
            let mut st = self.state();
            let s = st.stacks.get_mut(&stack.id).expect("found above");
            s.previous = Some(Box::new(Snapshot {
                template_body: s.template_body.clone(),
                parameters: s.parameters.clone(),
                resources: s.resources.clone(),
                outputs: s.outputs.clone(),
                tags: s.tags.clone(),
            }));
            s.updated = Some(ctx.received_at);
            s.template_body = cs.template_body.clone();
            s.description = template.description();
            s.parameters = params;
            if let Some(t) = &cs.tags {
                s.tags = t.clone();
            }
            s.capabilities = cs.capabilities.clone();
            s.notification_arns = notifications;
            s.role_arn = role;
            s.change_set_id = Some(cs.id.clone());
            s.imports = super::imports(&template, &data);
            s.status = "IMPORT_IN_PROGRESS".into();
            s.status_reason = Some("User Initiated".into());
            s.last_operation = Some(("IMPORT".into(), operation_id));
            s.change_sets.retain(|id, _| id == &cs.id);
            if let Some(c) = s.change_sets.get_mut(&cs.id) {
                c.execution_status = "EXECUTE_COMPLETE".into();
            }
        }
        let d = self.deployment(ctx, deploy, &stack.id, token);
        d.event(&stack.name, STACK_TYPE, Some(&stack.id), "IMPORT_IN_PROGRESS", Some("User Initiated"), None).await;
        self.start(&stack.id);
        tokio::spawn(d.import(template, data, imports));
        Ok(types::ExecuteChangeSetOutput::default())
    }
}

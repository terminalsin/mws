//! Stack operations.

use std::collections::BTreeSet;

use chrono::Utc;
use mws_core::{RequestContext, ServiceError};

use super::{condition_keys, convert, find, find_id, not_found, page, provided, stack_resource, validation};
use crate::engine::{Deployment, STACK_TYPE};
use crate::generated::{errors, types};
use crate::state::{Stack, Tag};
use crate::template::Template;
use crate::CloudFormation;

pub(crate) const UPDATABLE: &[&str] = &[
    "CREATE_COMPLETE",
    "UPDATE_COMPLETE",
    "UPDATE_ROLLBACK_COMPLETE",
    "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE",
    "UPDATE_FAILED",
    "CREATE_FAILED",
];

pub(crate) fn tags_of(t: Option<Vec<types::Tag>>) -> Option<Vec<Tag>> {
    t.map(|t| t.into_iter().map(|t| Tag { key: t.key, value: t.value }).collect())
}

fn tag_keys(tags: &[Tag]) -> Vec<(String, Vec<String>)> {
    let mut out: Vec<(String, Vec<String>)> =
        tags.iter().map(|t| (format!("aws:RequestTag/{}", t.key), vec![t.value.clone()])).collect();
    if !tags.is_empty() {
        out.push(("aws:TagKeys".into(), tags.iter().map(|t| t.key.clone()).collect()));
    }
    out
}

impl CloudFormation {
    pub(crate) fn deployment(
        &self,
        ctx: &RequestContext,
        deploy: RequestContext,
        stack_id: &str,
        token: Option<String>,
    ) -> Deployment {
        Deployment {
            cfn: self.clone(),
            stack_id: stack_id.to_string(),
            ctx: deploy,
            token,
            offset: ctx.received_at - Utc::now(),
        }
    }

    /// Authorize a stack operation, with the condition keys AWS adds.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn authorize_stack(
        &self,
        ctx: &RequestContext,
        action: &str,
        resource: &str,
        template_url: Option<&str>,
        role_arn: Option<&str>,
        resource_types: &[String],
        tags: &[Tag],
        stack_policy_url: Option<&str>,
    ) -> Result<(), ServiceError> {
        let mut pairs: Vec<(String, Vec<String>)> = vec![
            ("cloudformation:TemplateUrl".into(), template_url.map(|u| vec![u.to_string()]).unwrap_or_default()),
            ("cloudformation:RoleArn".into(), role_arn.map(|u| vec![u.to_string()]).unwrap_or_default()),
            ("cloudformation:ResourceTypes".into(), resource_types.to_vec()),
            ("cloudformation:StackPolicyUrl".into(), stack_policy_url.map(|u| vec![u.to_string()]).unwrap_or_default()),
        ];
        pairs.extend(tag_keys(tags));
        let refs: Vec<(&str, Vec<String>)> = pairs.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        ctx.authorize(action, resource, condition_keys(&refs))?;
        if let Some(role) = role_arn {
            ctx.authorize(
                "iam:PassRole",
                role,
                condition_keys(&[("iam:PassedToService", vec!["cloudformation.amazonaws.com".into()])]),
            )?;
        }
        Ok(())
    }

    pub(crate) async fn stack_policy_text(
        &self,
        ctx: &RequestContext,
        body: Option<String>,
        url: Option<String>,
    ) -> Result<Option<String>, ServiceError> {
        let text = match (body, url) {
            (Some(_), Some(_)) => {
                return Err(validation("You cannot specify both StackPolicyURL and StackPolicyBody"));
            }
            (Some(b), None) => Some(b),
            (None, Some(u)) => Some(self.fetch_s3(ctx, &u).await?),
            (None, None) => None,
        };
        if let Some(t) = &text {
            crate::policy::validate(t).map_err(validation)?;
        }
        Ok(text)
    }

    pub(crate) async fn create_stack_op(
        &self,
        ctx: &RequestContext,
        input: types::CreateStackInput,
    ) -> Result<types::CreateStackOutput, ServiceError> {
        let name = input.stack_name.clone();
        let tags = tags_of(input.tags.clone()).unwrap_or_default();
        let body = self.template_text(ctx, input.template_body.as_deref(), input.template_url.as_deref()).await?;
        let types_used = resource_types(&body);
        self.authorize_stack(
            ctx,
            "cloudformation:CreateStack",
            &stack_resource(ctx, &name),
            input.template_url.as_deref(),
            input.role_arn.as_deref(),
            &types_used,
            &tags,
            input.stack_policy_url.as_deref(),
        )?;
        {
            let st = self.state();
            if let Ok(existing) = find(&st, ctx, &name) {
                if input.client_request_token.as_ref().is_some_and(|t| existing.request_tokens.contains(t)) {
                    return Ok(types::CreateStackOutput { stack_id: Some(existing.id.clone()), operation_id: None });
                }
                return Err(errors::already_exists(format!("Stack [{name}] already exists")));
            }
        }
        if input.disable_rollback.is_some() && input.on_failure.is_some() {
            return Err(validation("You may specify only one of DisableRollback and OnFailure"));
        }
        let policy =
            self.stack_policy_text(ctx, input.stack_policy_body.clone(), input.stack_policy_url.clone()).await?;
        let deploy = self.deploy_context(ctx, input.role_arn.as_deref())?;
        let id = super::new_stack_id(ctx, &name);
        let caps = input.capabilities.clone().unwrap_or_default();
        let notifications = input.notification_ar_ns.clone().unwrap_or_default();
        let (template, params, data) = self
            .prepare(
                ctx,
                &deploy,
                &name,
                &id,
                &body,
                &provided(input.parameters.clone()),
                &[],
                &caps,
                &notifications,
                true,
            )
            .await?;
        let operation_id = uuid::Uuid::new_v4().to_string();
        let stack = Stack {
            id: id.clone(),
            name: name.clone(),
            account: ctx.caller.account_id.clone(),
            region: ctx.region.clone(),
            status: "CREATE_IN_PROGRESS".into(),
            status_reason: Some("User Initiated".into()),
            created: ctx.received_at,
            description: template.description(),
            template_body: template.body(&body),
            original_template: template.original.clone(),
            rollback_configuration: convert::rollback_config_of(input.rollback_configuration.clone()),
            parameters: params,
            tags,
            capabilities: caps,
            notification_arns: notifications,
            role_arn: input.role_arn.clone(),
            timeout_in_minutes: input.timeout_in_minutes,
            disable_rollback: input.disable_rollback.unwrap_or(false),
            termination_protection: input.enable_termination_protection.unwrap_or(false),
            retain_except_on_create: input.retain_except_on_create.unwrap_or(false),
            on_failure: input.on_failure.clone(),
            policy,
            request_tokens: input.client_request_token.clone().into_iter().collect(),
            last_operation: Some(("CREATE_STACK".into(), operation_id.clone())),
            imports: super::imports(&template, &data),
            ..Default::default()
        };
        self.state().stacks.insert(id.clone(), stack);
        let d = self.deployment(ctx, deploy, &id, input.client_request_token.clone());
        d.event(&name, STACK_TYPE, Some(&id), "CREATE_IN_PROGRESS", Some("User Initiated"), None).await;
        self.start(&id);
        tokio::spawn(d.create(template, data));
        Ok(types::CreateStackOutput { stack_id: Some(id), operation_id: Some(operation_id) })
    }

    pub(crate) async fn update_stack_op(
        &self,
        ctx: &RequestContext,
        input: types::UpdateStackInput,
    ) -> Result<types::UpdateStackOutput, ServiceError> {
        let current = { find(&self.state(), ctx, &input.stack_name)?.clone() };
        let body = if input.use_previous_template == Some(true) {
            if input.template_body.is_some() || input.template_url.is_some() {
                return Err(validation("You cannot specify both usePreviousTemplate and Template Body/Template URL"));
            }
            current.original_template.clone().unwrap_or_else(|| current.template_body.clone())
        } else if input.template_body.is_none() && input.template_url.is_none() {
            return Err(validation("Either Template URL or Template Body must be specified."));
        } else {
            self.template_text(ctx, input.template_body.as_deref(), input.template_url.as_deref()).await?
        };
        let tags = tags_of(input.tags.clone()).unwrap_or_else(|| current.tags.clone());
        let role = input.role_arn.clone().or_else(|| current.role_arn.clone());
        self.authorize_stack(
            ctx,
            "cloudformation:UpdateStack",
            &current.id,
            input.template_url.as_deref(),
            input.role_arn.as_deref(),
            &resource_types(&body),
            &tags_of(input.tags.clone()).unwrap_or_default(),
            input.stack_policy_url.as_deref(),
        )?;
        if !UPDATABLE.contains(&current.status.as_str()) {
            return Err(validation(format!(
                "Stack:{} is in {} state and can not be updated.",
                current.id, current.status
            )));
        }
        let policy =
            self.stack_policy_text(ctx, input.stack_policy_body.clone(), input.stack_policy_url.clone()).await?;
        let during = self
            .stack_policy_text(
                ctx,
                input.stack_policy_during_update_body.clone(),
                input.stack_policy_during_update_url.clone(),
            )
            .await?;
        let deploy = self.deploy_context(ctx, role.as_deref())?;
        let caps = input.capabilities.clone().unwrap_or_default();
        let notifications = input.notification_ar_ns.clone().unwrap_or_else(|| current.notification_arns.clone());
        let (template, params, data) = self
            .prepare(
                ctx,
                &deploy,
                &current.name,
                &current.id,
                &body,
                &provided(input.parameters.clone()),
                &current.parameters,
                &caps,
                &notifications,
                true,
            )
            .await?;
        let same_template = Template::parse(&current.template_body).map(|t| t.root == template.root).unwrap_or(false);
        let same_params = params.iter().map(|p| (&p.key, &p.value)).collect::<Vec<_>>()
            == current.parameters.iter().map(|p| (&p.key, &p.value)).collect::<Vec<_>>();
        let same_tags = tags.iter().map(|t| (&t.key, &t.value)).collect::<Vec<_>>()
            == current.tags.iter().map(|t| (&t.key, &t.value)).collect::<Vec<_>>();
        if same_template && same_params && same_tags && notifications == current.notification_arns {
            // Values resolved from Parameter Store count as changes.
            let resolved_same = params.iter().zip(&current.parameters).all(|(a, b)| a.resolved == b.resolved);
            if resolved_same {
                return Err(validation("No updates are to be performed."));
            }
        }
        let operation_id = uuid::Uuid::new_v4().to_string();
        {
            let mut st = self.state();
            let s = st.stacks.get_mut(&current.id).expect("found above");
            s.keep_previous();
            s.template_body = template.body(&body);
            s.original_template = template.original.clone();
            if let Some(c) = convert::rollback_config_of(input.rollback_configuration.clone()) {
                s.rollback_configuration = Some(c);
            }
            s.description = template.description();
            s.parameters = params;
            s.tags = tags;
            s.capabilities = caps;
            s.notification_arns = notifications;
            s.role_arn = role;
            s.updated = Some(ctx.received_at);
            s.change_set_id = None;
            if let Some(p) = policy {
                s.policy = Some(p);
            }
            if let Some(d) = input.disable_rollback {
                s.disable_rollback = d;
            }
            if let Some(r) = input.retain_except_on_create {
                s.retain_except_on_create = r;
            }
            s.status = "UPDATE_IN_PROGRESS".into();
            s.status_reason = Some("User Initiated".into());
            s.last_operation = Some(("UPDATE_STACK".into(), operation_id.clone()));
            s.imports = super::imports(&template, &data);
            if let Some(t) = &input.client_request_token {
                s.request_tokens.push(t.clone());
            }
        }
        let d = self.deployment(ctx, deploy, &current.id, input.client_request_token.clone());
        d.event(&current.name, STACK_TYPE, Some(&current.id), "UPDATE_IN_PROGRESS", Some("User Initiated"), None).await;
        self.start(&current.id);
        tokio::spawn(d.update(template, data, during));
        Ok(types::UpdateStackOutput { stack_id: Some(current.id), operation_id: Some(operation_id) })
    }

    pub(crate) async fn delete_stack_op(
        &self,
        ctx: &RequestContext,
        input: types::DeleteStackInput,
    ) -> Result<(), ServiceError> {
        let current = {
            let st = self.state();
            match find(&st, ctx, &input.stack_name) {
                Ok(s) => s.clone(),
                // Deleting a stack that does not exist succeeds.
                Err(_) => {
                    drop(st);
                    ctx.authorize(
                        "cloudformation:DeleteStack",
                        &stack_resource(ctx, &input.stack_name),
                        Default::default(),
                    )?;
                    return Ok(());
                }
            }
        };
        ctx.authorize("cloudformation:DeleteStack", &current.id, Default::default())?;
        if input.role_arn.is_some() {
            self.authorize_stack(
                ctx,
                "cloudformation:DeleteStack",
                &current.id,
                None,
                input.role_arn.as_deref(),
                &[],
                &[],
                None,
            )?;
        }
        if current.is_deleted() || current.status == "DELETE_IN_PROGRESS" {
            return Ok(());
        }
        if current.termination_protection {
            return Err(validation(format!(
                "Stack [{}] cannot be deleted while TerminationProtection is enabled",
                current.name
            )));
        }
        if current.in_progress() {
            return Err(validation(format!(
                "Stack [{}] cannot be deleted while in status {}",
                current.name, current.status
            )));
        }
        let retain: BTreeSet<String> = input.retain_resources.clone().unwrap_or_default().into_iter().collect();
        if !retain.is_empty() && current.status != "DELETE_FAILED" {
            return Err(validation(format!(
                "Invalid operation on stack [{}]: RetainResources can only be specified when the stack is in the DELETE_FAILED state",
                current.id
            )));
        }
        let role = input.role_arn.clone().or_else(|| current.role_arn.clone());
        let deploy = self.deploy_context(ctx, role.as_deref())?;
        let operation_id = uuid::Uuid::new_v4().to_string();
        {
            let mut st = self.state();
            let s = st.stacks.get_mut(&current.id).expect("found above");
            s.status = "DELETE_IN_PROGRESS".into();
            s.status_reason = Some("User Initiated".into());
            s.last_operation = Some(("DELETE_STACK".into(), operation_id));
        }
        let d = self.deployment(ctx, deploy, &current.id, input.client_request_token.clone());
        d.event(&current.name, STACK_TYPE, Some(&current.id), "DELETE_IN_PROGRESS", Some("User Initiated"), None).await;
        self.start(&current.id);
        tokio::spawn(d.delete(retain));
        Ok(())
    }

    pub(crate) fn describe_stacks_op(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStacksInput,
    ) -> Result<types::DescribeStacksOutput, ServiceError> {
        let st = self.state();
        let stacks: Vec<types::Stack> = match &input.stack_name {
            Some(name) => {
                let s = find(&st, ctx, name)?;
                ctx.authorize("cloudformation:DescribeStacks", &s.id, Default::default())?;
                vec![convert::stack(s)]
            }
            None => {
                ctx.authorize("cloudformation:DescribeStacks", "*", Default::default())?;
                let mut v: Vec<&Stack> = st
                    .stacks
                    .values()
                    .filter(|s| !s.is_deleted() && s.account == ctx.caller.account_id && s.region == ctx.region)
                    .collect();
                v.sort_by_key(|b| std::cmp::Reverse(b.created));
                v.into_iter().map(convert::stack).collect()
            }
        };
        let (stacks, next) = page(&stacks, input.next_token.as_deref(), 100)?;
        Ok(types::DescribeStacksOutput { stacks: Some(stacks), next_token: next })
    }

    pub(crate) fn list_stacks_op(
        &self,
        ctx: &RequestContext,
        input: types::ListStacksInput,
    ) -> Result<types::ListStacksOutput, ServiceError> {
        ctx.authorize("cloudformation:ListStacks", "*", Default::default())?;
        let st = self.state();
        let filter = input.stack_status_filter.unwrap_or_default();
        let mut v: Vec<&Stack> = st
            .stacks
            .values()
            .filter(|s| s.account == ctx.caller.account_id && s.region == ctx.region)
            .filter(|s| filter.is_empty() || filter.contains(&s.status))
            .collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.created));
        let all: Vec<types::StackSummary> = v.into_iter().map(convert::summary).collect();
        let (items, next) = page(&all, input.next_token.as_deref(), 100)?;
        Ok(types::ListStacksOutput { stack_summaries: Some(items), next_token: next })
    }

    pub(crate) fn describe_stack_events_op(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStackEventsInput,
    ) -> Result<types::DescribeStackEventsOutput, ServiceError> {
        let st = self.state();
        let s = find(&st, ctx, &input.stack_name)?;
        ctx.authorize("cloudformation:DescribeStackEvents", &s.id, Default::default())?;
        let all: Vec<types::StackEvent> = s.events.iter().rev().map(|e| convert::event(s, e)).collect();
        let (items, next) = page(&all, input.next_token.as_deref(), 100)?;
        Ok(types::DescribeStackEventsOutput { stack_events: Some(items), next_token: next })
    }

    pub(crate) fn describe_stack_resources_op(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStackResourcesInput,
    ) -> Result<types::DescribeStackResourcesOutput, ServiceError> {
        let st = self.state();
        let s = match (&input.stack_name, &input.physical_resource_id) {
            (Some(name), _) => find(&st, ctx, name)?,
            (None, Some(physical)) => st
                .stacks
                .values()
                .filter(|s| s.account == ctx.caller.account_id && s.region == ctx.region && !s.is_deleted())
                .find(|s| s.resources.iter().any(|r| r.physical_id.as_deref() == Some(physical.as_str())))
                .ok_or_else(|| validation(format!("Stack for {physical} does not exist")))?,
            (None, None) => return Err(validation("Either StackName or PhysicalResourceId must be specified.")),
        };
        ctx.authorize("cloudformation:DescribeStackResources", &s.id, Default::default())?;
        let items = s
            .resources
            .iter()
            .filter(|r| input.logical_resource_id.as_ref().is_none_or(|l| &r.logical_id == l))
            .filter(|r| {
                input
                    .physical_resource_id
                    .as_ref()
                    .is_none_or(|p| input.stack_name.is_some() || r.physical_id.as_ref() == Some(p))
            })
            .map(|r| convert::resource(s, r))
            .collect();
        Ok(types::DescribeStackResourcesOutput { stack_resources: Some(items) })
    }

    pub(crate) fn describe_stack_resource_op(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStackResourceInput,
    ) -> Result<types::DescribeStackResourceOutput, ServiceError> {
        let st = self.state();
        let s = find(&st, ctx, &input.stack_name)?;
        ctx.authorize("cloudformation:DescribeStackResource", &s.id, Default::default())?;
        let r = s.resource(&input.logical_resource_id).ok_or_else(|| {
            validation(format!("Resource {} does not exist for stack {}", input.logical_resource_id, input.stack_name))
        })?;
        Ok(types::DescribeStackResourceOutput { stack_resource_detail: Some(convert::resource_detail(s, r)) })
    }

    pub(crate) fn list_stack_resources_op(
        &self,
        ctx: &RequestContext,
        input: types::ListStackResourcesInput,
    ) -> Result<types::ListStackResourcesOutput, ServiceError> {
        let st = self.state();
        let s = find(&st, ctx, &input.stack_name)?;
        ctx.authorize("cloudformation:ListStackResources", &s.id, Default::default())?;
        let all: Vec<types::StackResourceSummary> = s.resources.iter().map(convert::resource_summary).collect();
        let (items, next) = page(&all, input.next_token.as_deref(), 100)?;
        Ok(types::ListStackResourcesOutput { stack_resource_summaries: Some(items), next_token: next })
    }

    pub(crate) fn get_template_op(
        &self,
        ctx: &RequestContext,
        input: types::GetTemplateInput,
    ) -> Result<types::GetTemplateOutput, ServiceError> {
        let st = self.state();
        let stages = Some(vec!["Original".to_string(), "Processed".to_string()]);
        if let Some(cs) = &input.change_set_name {
            let (stack, change_set) = super::change_sets::find_change_set(&st, ctx, cs, input.stack_name.as_deref())?;
            ctx.authorize("cloudformation:GetTemplate", &stack.id, Default::default())?;
            let body = stage(&input.template_stage, &change_set.template_body, change_set.original_template.as_ref());
            return Ok(types::GetTemplateOutput { template_body: Some(body), stages_available: stages });
        }
        let name = input.stack_name.as_deref().ok_or_else(|| validation("StackName must be specified"))?;
        let s = find(&st, ctx, name)?;
        ctx.authorize("cloudformation:GetTemplate", &s.id, Default::default())?;
        let body = stage(&input.template_stage, &s.template_body, s.original_template.as_ref());
        Ok(types::GetTemplateOutput { template_body: Some(body), stages_available: stages })
    }

    pub(crate) fn update_termination_protection_op(
        &self,
        ctx: &RequestContext,
        input: types::UpdateTerminationProtectionInput,
    ) -> Result<types::UpdateTerminationProtectionOutput, ServiceError> {
        let mut st = self.state();
        let id = find_id(&st, ctx, &input.stack_name)?;
        ctx.authorize("cloudformation:UpdateTerminationProtection", &id, Default::default())?;
        let s = st.stacks.get_mut(&id).expect("found");
        if s.is_deleted() {
            return Err(not_found(&input.stack_name));
        }
        if s.parent_id.is_some() {
            return Err(validation(
                "Termination protection cannot be updated on nested stacks. Update the root stack instead.",
            ));
        }
        s.termination_protection = input.enable_termination_protection;
        Ok(types::UpdateTerminationProtectionOutput { stack_id: Some(id) })
    }

    pub(crate) async fn set_stack_policy_op(
        &self,
        ctx: &RequestContext,
        input: types::SetStackPolicyInput,
    ) -> Result<(), ServiceError> {
        let id = { find_id(&self.state(), ctx, &input.stack_name)? };
        ctx.authorize(
            "cloudformation:SetStackPolicy",
            &id,
            condition_keys(&[("cloudformation:StackPolicyUrl", input.stack_policy_url.clone().into_iter().collect())]),
        )?;
        let policy = self.stack_policy_text(ctx, input.stack_policy_body, input.stack_policy_url).await?;
        if let Some(s) = self.state().stacks.get_mut(&id) {
            s.policy = policy;
        }
        Ok(())
    }

    pub(crate) fn get_stack_policy_op(
        &self,
        ctx: &RequestContext,
        input: types::GetStackPolicyInput,
    ) -> Result<types::GetStackPolicyOutput, ServiceError> {
        let st = self.state();
        let s = find(&st, ctx, &input.stack_name)?;
        ctx.authorize("cloudformation:GetStackPolicy", &s.id, Default::default())?;
        Ok(types::GetStackPolicyOutput { stack_policy_body: s.policy.clone() })
    }

    pub(crate) fn signal_resource_op(
        &self,
        ctx: &RequestContext,
        input: types::SignalResourceInput,
    ) -> Result<(), ServiceError> {
        let (id, status) = {
            let st = self.state();
            let s = find(&st, ctx, &input.stack_name)?;
            (s.id.clone(), s.resource(&input.logical_resource_id).map(|r| r.status.clone()))
        };
        ctx.authorize("cloudformation:SignalResource", &id, Default::default())?;
        let Some(status) = status else {
            return Err(validation(format!(
                "Resource {} does not exist for stack {}",
                input.logical_resource_id, input.stack_name
            )));
        };
        if !status.ends_with("_IN_PROGRESS") {
            return Err(validation(format!(
                "Resource {} is in {status} state and cannot be signaled",
                input.logical_resource_id
            )));
        }
        self.signal(
            &crate::signal_key(&id, &input.logical_resource_id),
            serde_json::json!({"UniqueId": input.unique_id, "Status": input.status}),
        );
        Ok(())
    }

    pub(crate) fn list_exports_op(
        &self,
        ctx: &RequestContext,
        input: types::ListExportsInput,
    ) -> Result<types::ListExportsOutput, ServiceError> {
        ctx.authorize("cloudformation:ListExports", "*", Default::default())?;
        let st = self.state();
        let mut all = Vec::new();
        for s in st.stacks.values() {
            if s.is_deleted() || s.account != ctx.caller.account_id || s.region != ctx.region {
                continue;
            }
            for o in &s.outputs {
                if let Some(n) = &o.export_name {
                    all.push(types::Export {
                        exporting_stack_id: Some(s.id.clone()),
                        name: Some(n.clone()),
                        value: Some(o.value.clone()),
                    });
                }
            }
        }
        all.sort_by(|a, b| a.name.cmp(&b.name));
        let (items, next) = page(&all, input.next_token.as_deref(), 100)?;
        Ok(types::ListExportsOutput { exports: Some(items), next_token: next })
    }

    pub(crate) fn list_imports_op(
        &self,
        ctx: &RequestContext,
        input: types::ListImportsInput,
    ) -> Result<types::ListImportsOutput, ServiceError> {
        ctx.authorize("cloudformation:ListImports", "*", Default::default())?;
        let st = self.state();
        let mut names = crate::importers(&st, &ctx.caller.account_id, &ctx.region, &input.export_name);
        names.sort();
        if names.is_empty() {
            return Err(validation(format!("Export '{}' is not imported by any stack.", input.export_name)));
        }
        let (items, next) = page(&names, input.next_token.as_deref(), 100)?;
        Ok(types::ListImportsOutput { imports: Some(items), next_token: next })
    }

    pub(crate) fn cancel_update_stack_op(
        &self,
        ctx: &RequestContext,
        input: types::CancelUpdateStackInput,
    ) -> Result<(), ServiceError> {
        let st = self.state();
        let s = find(&st, ctx, &input.stack_name)?;
        ctx.authorize("cloudformation:CancelUpdateStack", &s.id, Default::default())?;
        if s.status != "UPDATE_IN_PROGRESS" {
            return Err(validation("CancelUpdateStack cannot be called from current stack status"));
        }
        let id = s.id.clone();
        drop(st);
        self.request_cancel(&id);
        Ok(())
    }

    pub(crate) async fn continue_update_rollback_op(
        &self,
        ctx: &RequestContext,
        input: types::ContinueUpdateRollbackInput,
    ) -> Result<types::ContinueUpdateRollbackOutput, ServiceError> {
        let current = { find(&self.state(), ctx, &input.stack_name)?.clone() };
        self.authorize_stack(
            ctx,
            "cloudformation:ContinueUpdateRollback",
            &current.id,
            None,
            input.role_arn.as_deref(),
            &[],
            &[],
            None,
        )?;
        if current.status != "UPDATE_ROLLBACK_FAILED" {
            return Err(validation("ContinueUpdateRollback cannot be called from current stack status"));
        }
        let role = input.role_arn.clone().or_else(|| current.role_arn.clone());
        let deploy = self.deploy_context(ctx, role.as_deref())?;
        let skip: BTreeSet<String> = input.resources_to_skip.unwrap_or_default().into_iter().collect();
        let d = self.deployment(ctx, deploy, &current.id, input.client_request_token.clone());
        self.start(&current.id);
        tokio::spawn(async move {
            d.rollback_update("Continue rollback requested by user.", &skip).await;
            d.cfn.finished(&d.stack_id);
        });
        Ok(types::ContinueUpdateRollbackOutput::default())
    }

    pub(crate) async fn rollback_stack_op(
        &self,
        ctx: &RequestContext,
        input: types::RollbackStackInput,
    ) -> Result<types::RollbackStackOutput, ServiceError> {
        let current = { find(&self.state(), ctx, &input.stack_name)?.clone() };
        self.authorize_stack(
            ctx,
            "cloudformation:RollbackStack",
            &current.id,
            None,
            input.role_arn.as_deref(),
            &[],
            &[],
            None,
        )?;
        if !matches!(
            current.status.as_str(),
            "CREATE_FAILED" | "UPDATE_FAILED" | "UPDATE_ROLLBACK_FAILED" | "IMPORT_ROLLBACK_FAILED"
        ) {
            return Err(validation(format!(
                "Stack {} is in {} state and cannot be rolled back.",
                current.id, current.status
            )));
        }
        let role = input.role_arn.clone().or_else(|| current.role_arn.clone());
        let deploy = self.deploy_context(ctx, role.as_deref())?;
        let operation_id = uuid::Uuid::new_v4().to_string();
        {
            let mut st = self.state();
            if let Some(s) = st.stacks.get_mut(&current.id) {
                s.last_operation = Some(("ROLLBACK".into(), operation_id.clone()));
                if let Some(r) = input.retain_except_on_create {
                    s.retain_except_on_create = r;
                }
            }
        }
        let d = self.deployment(ctx, deploy, &current.id, input.client_request_token.clone());
        self.start(&current.id);
        let created = current.status == "CREATE_FAILED";
        let template = Template::parse(&current.template_body).ok();
        tokio::spawn(async move {
            match (created, template) {
                (true, Some(t)) => d.rollback_create(&t, "Rollback requested by user.").await,
                _ => d.rollback_update("Rollback requested by user.", &BTreeSet::new()).await,
            }
            d.cfn.finished(&d.stack_id);
        });
        Ok(types::RollbackStackOutput { stack_id: Some(current.id), operation_id: Some(operation_id) })
    }
}

/// The template a `TemplateStage` asks for: the submitted one
/// (`Original`, the default) or the one transforms produced.
fn stage(stage: &Option<String>, processed: &str, original: Option<&String>) -> String {
    match (stage.as_deref(), original) {
        (Some("Processed"), _) | (_, None) => processed.to_string(),
        (_, Some(o)) => o.clone(),
    }
}

/// Resource types a template body declares (for `cloudformation:ResourceTypes`).
pub(crate) fn resource_types(body: &str) -> Vec<String> {
    let Ok(t) = Template::parse(body) else { return Vec::new() };
    let mut v: Vec<String> =
        t.resources().values().filter_map(|r| r.get("Type").and_then(|t| t.as_str())).map(str::to_string).collect();
    v.sort();
    v.dedup();
    v
}

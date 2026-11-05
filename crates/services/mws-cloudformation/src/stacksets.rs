//! StackSets: one template deployed as stacks ("stack instances") across
//! accounts and Regions.
//!
//! Each stack instance is an ordinary stack in its target account and
//! Region, created by [`CloudFormation`]'s own stack operations with the
//! identity AWS deploys it with: for self-managed stack sets, the
//! administration role (assumed as `cloudformation.amazonaws.com`)
//! assumes the target account's execution role through STS; for
//! service-managed ones, the member account's StackSets execution role.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use chrono::{DateTime, Utc};
use mws_core::{RequestContext, ServiceError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::generated::{errors, types};
use crate::ops::{page, validation};
use crate::CloudFormation;

/// The service principal Organizations trusted access names.
pub(crate) const ORG_PRINCIPAL: &str = "member.org.stacksets.cloudformation.amazonaws.com";
const DEFAULT_ADMIN_ROLE: &str = "AWSCloudFormationStackSetAdministrationRole";
const DEFAULT_EXECUTION_ROLE: &str = "AWSCloudFormationStackSetExecutionRole";
const ACCOUNT_GATE: &str = "AWSCloudFormationStackSetAccountGate";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StackSet {
    pub id: String,
    pub name: String,
    pub arn: String,
    /// The account that owns the stack set (the management account for
    /// service-managed ones, also when a delegated administrator made it).
    pub account: String,
    pub region: String,
    pub status: String,
    pub description: Option<String>,
    pub template_body: String,
    pub parameters: Vec<types::Parameter>,
    pub capabilities: Vec<String>,
    pub tags: Vec<types::Tag>,
    pub administration_role_arn: Option<String>,
    pub execution_role_name: Option<String>,
    pub permission_model: String,
    pub auto_deployment: Option<types::AutoDeployment>,
    pub managed_execution: bool,
    /// OUs instances were deployed to, with their Regions (auto-deployment
    /// targets).
    pub ou_regions: BTreeMap<String, BTreeSet<String>>,
    /// By `account/region`.
    pub instances: BTreeMap<String, Instance>,
    /// Oldest first.
    pub operations: Vec<Operation>,
    pub drift: Option<types::StackSetDriftDetectionDetails>,
    pub created: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Instance {
    pub account: String,
    pub region: String,
    pub stack_id: Option<String>,
    pub overrides: Vec<types::Parameter>,
    /// `CURRENT`, `OUTDATED` or `INOPERABLE`.
    pub status: String,
    /// `PENDING`, `RUNNING`, `SUCCEEDED`, `FAILED`, `CANCELLED`,
    /// `INOPERABLE`, `SKIPPED_SUSPENDED_ACCOUNT`, `FAILED_IMPORT`.
    pub detailed: String,
    pub reason: Option<String>,
    pub ou: Option<String>,
    pub drift_status: Option<String>,
    pub drift_checked: Option<DateTime<Utc>>,
    pub last_operation: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Operation {
    pub id: String,
    /// `CREATE`, `UPDATE`, `DELETE`, `DETECT_DRIFT`.
    pub action: String,
    pub status: String,
    pub status_reason: Option<String>,
    pub preferences: Option<types::StackSetOperationPreferences>,
    pub retain_stacks: Option<bool>,
    pub administration_role_arn: Option<String>,
    pub execution_role_name: Option<String>,
    pub targets: Option<types::DeploymentTargets>,
    pub created: DateTime<Utc>,
    pub ended: Option<DateTime<Utc>>,
    pub results: Vec<OpResult>,
    pub drift: Option<types::StackSetDriftDetectionDetails>,
    pub stop: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct OpResult {
    pub account: String,
    pub region: String,
    pub status: String,
    pub reason: Option<String>,
    pub gate: Option<(String, Option<String>)>,
    pub ou: Option<String>,
}

fn key(account: &str, region: &str) -> String {
    format!("{account}/{region}")
}

fn not_found(name: &str) -> ServiceError {
    errors::stack_set_not_found(format!("StackSet {name} not found"))
}

fn in_progress(arn: &str) -> ServiceError {
    errors::operation_in_progress(format!("Another Operation on StackSet {arn} is in progress"))
}

fn merged(base: &[types::Parameter], overrides: &[types::Parameter]) -> Vec<types::Parameter> {
    let mut out: Vec<types::Parameter> = base.to_vec();
    for o in overrides {
        match out.iter_mut().find(|p| p.parameter_key == o.parameter_key) {
            Some(p) => *p = o.clone(),
            None => out.push(o.clone()),
        }
    }
    out
}

/// What an operation does to each `(account, region)` it targets.
#[derive(Clone)]
enum Work {
    Create,
    Update,
    Delete { retain: bool },
    Drift,
}

impl CloudFormation {
    async fn set_account(&self, ctx: &RequestContext, call_as: Option<&str>) -> Result<String, ServiceError> {
        if call_as == Some("DELEGATED_ADMIN") {
            // Delegated administrators act on the management account's
            // stack sets.
            let org = self.org_info(ctx).await?;
            let admins = self.delegated_admins(ctx).await;
            if !admins.contains(&ctx.caller.account_id) {
                return Err(validation(format!(
                    "Account {} is not registered as a delegated administrator for {ORG_PRINCIPAL}",
                    ctx.caller.account_id
                )));
            }
            return Ok(org);
        }
        Ok(ctx.caller.account_id.clone())
    }

    /// The management account of the caller's organization.
    async fn org_info(&self, ctx: &RequestContext) -> Result<String, ServiceError> {
        let out = self
            .call(ctx, "organizations", "DescribeOrganization", json!({}))
            .await
            .map_err(|_| validation("The account is not a member of an organization"))?;
        Ok(out["Organization"]["MasterAccountId"].as_str().unwrap_or_default().to_string())
    }

    async fn delegated_admins(&self, ctx: &RequestContext) -> Vec<String> {
        self.call(ctx, "organizations", "ListDelegatedAdministrators", json!({"ServicePrincipal": ORG_PRINCIPAL}))
            .await
            .ok()
            .and_then(|o| o["DelegatedAdministrators"].as_array().cloned())
            .unwrap_or_default()
            .iter()
            .filter_map(|a| a["Id"].as_str().map(str::to_string))
            .collect()
    }

    fn find_set(&self, account: &str, region: &str, name: &str) -> Result<StackSet, ServiceError> {
        let st = self.state();
        st.stack_sets
            .values()
            .find(|s| {
                s.account == account
                    && s.region == region
                    && s.status != "DELETED"
                    && (s.name == name || s.id == name || s.arn == name)
            })
            .cloned()
            .ok_or_else(|| not_found(name))
    }

    fn with_set<R>(&self, id: &str, f: impl FnOnce(&mut StackSet) -> R) -> Option<R> {
        self.state().stack_sets.get_mut(id).map(f)
    }

    fn set_arn(ctx: &RequestContext, account: &str, id: &str) -> String {
        format!("arn:{}:cloudformation:{}:{account}:stackset/{id}", ctx.partition, ctx.region)
    }

    pub(crate) async fn create_stack_set_op(
        &self,
        ctx: &RequestContext,
        input: types::CreateStackSetInput,
    ) -> Result<types::CreateStackSetOutput, ServiceError> {
        let account = self.set_account(ctx, input.call_as.as_deref()).await?;
        let model = input.permission_model.clone().unwrap_or_else(|| "SELF_MANAGED".into());
        let id = format!("{}:{}", input.stack_set_name, uuid::Uuid::new_v4());
        let arn = Self::set_arn(ctx, &account, &id);
        ctx.authorize("cloudformation:CreateStackSet", &arn, Default::default())?;
        {
            let st = self.state();
            if st.stack_sets.values().any(|s| {
                s.account == account
                    && s.region == ctx.region
                    && s.name == input.stack_set_name
                    && s.status != "DELETED"
            }) {
                return Err(errors::name_already_exists(format!("StackSet {} already exists", input.stack_set_name)));
            }
        }
        let body = match (&input.stack_id, &input.template_body, &input.template_url) {
            (Some(stack), None, None) => {
                let st = self.state();
                crate::ops::find(&st, ctx, stack)?.template_body.clone()
            }
            (None, _, _) => {
                self.template_text(ctx, input.template_body.as_deref(), input.template_url.as_deref()).await?
            }
            _ => return Err(validation("Exactly one of TemplateBody, TemplateURL or StackId must be specified")),
        };
        let template = crate::template::Template::parse(&body).map_err(validation)?;
        self.check_template(ctx, &template)?;
        let caps = input.capabilities.clone().unwrap_or_default();
        crate::ops::check_capabilities(&template, &caps)?;
        match model.as_str() {
            "SERVICE_MANAGED" => {
                if input.administration_role_arn.is_some() || input.execution_role_name.is_some() {
                    return Err(validation(
                        "AdministrationRoleARN and ExecutionRoleName are not supported for SERVICE_MANAGED stack sets",
                    ));
                }
                if !self.org_access_enabled(ctx).await {
                    return Err(validation(
                        "You must enable organizations access to operate a service managed stack set",
                    ));
                }
                if input.auto_deployment.as_ref().and_then(|a| a.enabled).is_none() {
                    return Err(validation("AutoDeployment must be specified for SERVICE_MANAGED stack sets"));
                }
            }
            "SELF_MANAGED" => {
                if input.auto_deployment.is_some() {
                    return Err(validation("AutoDeployment is not supported for SELF_MANAGED stack sets"));
                }
                if let Some(role) = &input.administration_role_arn {
                    ctx.authorize(
                        "iam:PassRole",
                        role,
                        crate::ops::condition_keys(&[(
                            "iam:PassedToService",
                            vec!["cloudformation.amazonaws.com".into()],
                        )]),
                    )?;
                }
            }
            other => return Err(validation(format!("Invalid PermissionModel {other}"))),
        }
        let set = StackSet {
            id: id.clone(),
            name: input.stack_set_name.clone(),
            arn,
            account,
            region: ctx.region.clone(),
            status: "ACTIVE".into(),
            description: input.description.clone().or_else(|| template.description()),
            template_body: body,
            parameters: input.parameters.clone().unwrap_or_default(),
            capabilities: caps,
            tags: input.tags.clone().unwrap_or_default(),
            administration_role_arn: input.administration_role_arn.clone(),
            execution_role_name: input.execution_role_name.clone(),
            permission_model: model,
            auto_deployment: input.auto_deployment.clone(),
            managed_execution: input.managed_execution.as_ref().and_then(|m| m.active).unwrap_or(false),
            created: ctx.received_at,
            ..Default::default()
        };
        self.state().stack_sets.insert(id.clone(), set);
        Ok(types::CreateStackSetOutput { stack_set_id: Some(id) })
    }

    async fn org_access_enabled(&self, ctx: &RequestContext) -> bool {
        self.call(ctx, "organizations", "ListAWSServiceAccessForOrganization", json!({}))
            .await
            .ok()
            .and_then(|o| o["EnabledServicePrincipals"].as_array().cloned())
            .unwrap_or_default()
            .iter()
            .any(|p| p["ServicePrincipal"] == json!(ORG_PRINCIPAL))
    }

    pub(crate) async fn activate_organizations_access_op(&self, ctx: &RequestContext) -> Result<(), ServiceError> {
        ctx.authorize("cloudformation:ActivateOrganizationsAccess", "*", Default::default())?;
        self.call(ctx, "organizations", "EnableAWSServiceAccess", json!({"ServicePrincipal": ORG_PRINCIPAL}))
            .await
            .map_err(|e| errors::invalid_operation(e.message))?;
        Ok(())
    }

    pub(crate) async fn deactivate_organizations_access_op(&self, ctx: &RequestContext) -> Result<(), ServiceError> {
        ctx.authorize("cloudformation:DeactivateOrganizationsAccess", "*", Default::default())?;
        self.call(ctx, "organizations", "DisableAWSServiceAccess", json!({"ServicePrincipal": ORG_PRINCIPAL}))
            .await
            .map_err(|e| errors::invalid_operation(e.message))?;
        Ok(())
    }

    pub(crate) async fn describe_organizations_access_op(
        &self,
        ctx: &RequestContext,
        _input: types::DescribeOrganizationsAccessInput,
    ) -> Result<types::DescribeOrganizationsAccessOutput, ServiceError> {
        ctx.authorize("cloudformation:DescribeOrganizationsAccess", "*", Default::default())?;
        let out = self
            .call(ctx, "organizations", "ListAWSServiceAccessForOrganization", json!({}))
            .await
            .map_err(|e| errors::invalid_operation(e.message))?;
        let on = out["EnabledServicePrincipals"]
            .as_array()
            .is_some_and(|a| a.iter().any(|p| p["ServicePrincipal"] == json!(ORG_PRINCIPAL)));
        Ok(types::DescribeOrganizationsAccessOutput { status: Some(if on { "ENABLED" } else { "DISABLED" }.into()) })
    }

    pub(crate) async fn describe_stack_set_op(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStackSetInput,
    ) -> Result<types::DescribeStackSetOutput, ServiceError> {
        let account = self.set_account(ctx, input.call_as.as_deref()).await?;
        let set = self.find_set(&account, &ctx.region, &input.stack_set_name)?;
        ctx.authorize("cloudformation:DescribeStackSet", &set.arn, Default::default())?;
        self.reconcile_auto_deployment(ctx, &set.id).await;
        let set = self.find_set(&account, &ctx.region, &input.stack_set_name)?;
        let regions: BTreeSet<String> = set.instances.values().map(|i| i.region.clone()).collect();
        Ok(types::DescribeStackSetOutput {
            stack_set: Some(types::StackSet {
                stack_set_name: Some(set.name.clone()),
                stack_set_id: Some(set.id.clone()),
                description: set.description.clone(),
                status: Some(set.status.clone()),
                template_body: Some(set.template_body.clone()),
                parameters: Some(set.parameters.clone()),
                capabilities: Some(set.capabilities.clone()),
                tags: Some(set.tags.clone()),
                stack_set_arn: Some(set.arn.clone()),
                administration_role_arn: (set.permission_model == "SELF_MANAGED").then(|| self.admin_role(&set)),
                execution_role_name: (set.permission_model == "SELF_MANAGED")
                    .then(|| set.execution_role_name.clone().unwrap_or_else(|| DEFAULT_EXECUTION_ROLE.into())),
                stack_set_drift_detection_details: Some(set.drift.clone().unwrap_or_else(|| {
                    types::StackSetDriftDetectionDetails {
                        drift_status: Some("NOT_CHECKED".into()),
                        ..Default::default()
                    }
                })),
                auto_deployment: set.auto_deployment.clone(),
                permission_model: Some(set.permission_model.clone()),
                organizational_unit_ids: (!set.ou_regions.is_empty()).then(|| set.ou_regions.keys().cloned().collect()),
                managed_execution: Some(types::ManagedExecution { active: Some(set.managed_execution) }),
                regions: Some(regions.into_iter().collect()),
            }),
        })
    }

    fn admin_role(&self, set: &StackSet) -> String {
        set.administration_role_arn.clone().unwrap_or_else(|| {
            let partition = set.arn.split(':').nth(1).unwrap_or("aws");
            format!("arn:{partition}:iam::{}:role/{DEFAULT_ADMIN_ROLE}", set.account)
        })
    }

    pub(crate) async fn list_stack_sets_op(
        &self,
        ctx: &RequestContext,
        input: types::ListStackSetsInput,
    ) -> Result<types::ListStackSetsOutput, ServiceError> {
        let account = self.set_account(ctx, input.call_as.as_deref()).await?;
        ctx.authorize("cloudformation:ListStackSets", "*", Default::default())?;
        let st = self.state();
        let mut sets: Vec<&StackSet> = st
            .stack_sets
            .values()
            .filter(|s| s.account == account && s.region == ctx.region)
            .filter(|s| input.status.as_ref().is_none_or(|f| &s.status == f))
            .filter(|s| input.call_as.as_deref() != Some("DELEGATED_ADMIN") || s.permission_model == "SERVICE_MANAGED")
            .collect();
        sets.sort_by_key(|s| s.created);
        let all: Vec<types::StackSetSummary> = sets
            .into_iter()
            .map(|s| types::StackSetSummary {
                stack_set_name: Some(s.name.clone()),
                stack_set_id: Some(s.id.clone()),
                description: s.description.clone(),
                status: Some(s.status.clone()),
                auto_deployment: s.auto_deployment.clone(),
                permission_model: Some(s.permission_model.clone()),
                drift_status: Some(
                    s.drift.as_ref().and_then(|d| d.drift_status.clone()).unwrap_or_else(|| "NOT_CHECKED".into()),
                ),
                last_drift_check_timestamp: s.drift.as_ref().and_then(|d| d.last_drift_check_timestamp),
                managed_execution: Some(types::ManagedExecution { active: Some(s.managed_execution) }),
            })
            .collect();
        let (summaries, next_token) =
            page(&all, input.next_token.as_deref(), input.max_results.unwrap_or(100) as usize)?;
        Ok(types::ListStackSetsOutput { summaries: Some(summaries), next_token })
    }

    pub(crate) async fn update_stack_set_op(
        &self,
        ctx: &RequestContext,
        input: types::UpdateStackSetInput,
    ) -> Result<types::UpdateStackSetOutput, ServiceError> {
        let account = self.set_account(ctx, input.call_as.as_deref()).await?;
        let set = self.find_set(&account, &ctx.region, &input.stack_set_name)?;
        ctx.authorize("cloudformation:UpdateStackSet", &set.arn, Default::default())?;
        if input.permission_model.as_ref().is_some_and(|m| m != &set.permission_model) {
            return Err(validation("PermissionModel cannot be changed for an existing stack set"));
        }
        let body = if input.use_previous_template == Some(true) {
            set.template_body.clone()
        } else if input.template_body.is_some() || input.template_url.is_some() {
            self.template_text(ctx, input.template_body.as_deref(), input.template_url.as_deref()).await?
        } else {
            set.template_body.clone()
        };
        let template = crate::template::Template::parse(&body).map_err(validation)?;
        self.check_template(ctx, &template)?;
        let caps = input.capabilities.clone().unwrap_or_else(|| set.capabilities.clone());
        crate::ops::check_capabilities(&template, &caps)?;
        let parameters = match &input.parameters {
            Some(p) => p
                .iter()
                .map(|p| {
                    if p.use_previous_value == Some(true) {
                        set.parameters
                            .iter()
                            .find(|o| o.parameter_key == p.parameter_key)
                            .cloned()
                            .unwrap_or_else(|| p.clone())
                    } else {
                        p.clone()
                    }
                })
                .collect(),
            None => set.parameters.clone(),
        };
        // Which instances to update: the ones named, or all.
        let targets = self
            .resolve_targets(
                ctx,
                &set,
                input.accounts.clone(),
                input.deployment_targets.clone(),
                input.regions.clone(),
                true,
            )
            .await?;
        if let Some(op) = &input.operation_id {
            if set.operations.iter().any(|o| &o.id == op) {
                return Err(errors::operation_id_already_exists(format!("The operation id {op} already exists")));
            }
        }
        let op_id = input.operation_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        self.check_idle(&set)?;
        self.with_set(&set.id, |s| {
            s.template_body = body;
            s.parameters = parameters;
            s.capabilities = caps;
            if let Some(d) = &input.description {
                s.description = Some(d.clone());
            }
            if let Some(t) = &input.tags {
                s.tags = t.clone();
            }
            if let Some(r) = &input.administration_role_arn {
                s.administration_role_arn = Some(r.clone());
            }
            if let Some(r) = &input.execution_role_name {
                s.execution_role_name = Some(r.clone());
            }
            if let Some(a) = &input.auto_deployment {
                s.auto_deployment = Some(a.clone());
            }
            if let Some(m) = &input.managed_execution {
                s.managed_execution = m.active.unwrap_or(false);
            }
            for (_, k, _) in &targets {
                if let Some(i) = s.instances.get_mut(k) {
                    i.status = "OUTDATED".into();
                }
            }
        });
        let items: Vec<(String, String, Option<String>)> = targets.into_iter().map(|(a, _, ou)| a_r(a, ou)).collect();
        self.start_operation(
            ctx,
            &set.id,
            &op_id,
            "UPDATE",
            Work::Update,
            items,
            input.operation_preferences.clone(),
            input.deployment_targets.clone(),
            None,
        )?;
        Ok(types::UpdateStackSetOutput { operation_id: Some(op_id) })
    }

    pub(crate) async fn delete_stack_set_op(
        &self,
        ctx: &RequestContext,
        input: types::DeleteStackSetInput,
    ) -> Result<(), ServiceError> {
        let account = self.set_account(ctx, input.call_as.as_deref()).await?;
        let set = self.find_set(&account, &ctx.region, &input.stack_set_name)?;
        ctx.authorize("cloudformation:DeleteStackSet", &set.arn, Default::default())?;
        self.check_idle(&set)?;
        if !set.instances.is_empty() {
            return Err(errors::stack_set_not_empty(
                "StackSet is not empty. Please delete all stack instances before deleting the StackSet.",
            ));
        }
        self.with_set(&set.id, |s| s.status = "DELETED".into());
        Ok(())
    }

    /// The `(account/region key, ou)` pairs an operation covers.
    #[allow(clippy::type_complexity)]
    async fn resolve_targets(
        &self,
        ctx: &RequestContext,
        set: &StackSet,
        accounts: Option<Vec<String>>,
        targets: Option<types::DeploymentTargets>,
        regions: Option<Vec<String>>,
        existing_only: bool,
    ) -> Result<Vec<(String, String, Option<String>)>, ServiceError> {
        let named = accounts.is_some() || targets.is_some() || regions.is_some();
        if existing_only && !named {
            return Ok(set
                .instances
                .values()
                .map(|i| (key(&i.account, &i.region), key(&i.account, &i.region), i.ou.clone()))
                .collect());
        }
        let regions: Vec<String> = match regions {
            Some(r) if !r.is_empty() => r,
            _ if existing_only => {
                set.instances.values().map(|i| i.region.clone()).collect::<BTreeSet<_>>().into_iter().collect()
            }
            _ => return Err(validation("Regions must be specified")),
        };
        let pairs = self.target_accounts(ctx, set, accounts, targets).await?;
        let mut out = Vec::new();
        for (a, ou) in pairs {
            for r in &regions {
                let k = key(&a, r);
                if existing_only && !set.instances.contains_key(&k) {
                    return Err(errors::stack_instance_not_found(format!(
                        "Stack instance in account {a} and region {r} for StackSet {} not found",
                        set.name
                    )));
                }
                out.push((k.clone(), k, ou.clone()));
            }
        }
        Ok(out)
    }

    /// Target accounts (with the OU they were reached through).
    async fn target_accounts(
        &self,
        ctx: &RequestContext,
        set: &StackSet,
        accounts: Option<Vec<String>>,
        targets: Option<types::DeploymentTargets>,
    ) -> Result<Vec<(String, Option<String>)>, ServiceError> {
        if set.permission_model == "SELF_MANAGED" {
            let mut list = accounts.unwrap_or_default();
            if let Some(t) = &targets {
                if t.organizational_unit_ids.is_some() {
                    return Err(validation("OrganizationalUnitIds are not supported for SELF_MANAGED stack sets"));
                }
                list.extend(t.accounts.clone().unwrap_or_default());
                if let Some(url) = &t.accounts_url {
                    list.extend(self.accounts_from_url(ctx, url).await?);
                }
            }
            if list.is_empty() {
                return Err(validation("Accounts must be specified"));
            }
            for a in &list {
                if a.len() != 12 || !a.chars().all(|c| c.is_ascii_digit()) {
                    return Err(validation(format!("Account {a} is not a valid AWS account id")));
                }
            }
            let mut seen = BTreeSet::new();
            return Ok(list.into_iter().filter(|a| seen.insert(a.clone())).map(|a| (a, None)).collect());
        }
        if accounts.is_some() {
            return Err(validation("Accounts is not supported for SERVICE_MANAGED stack sets; use DeploymentTargets"));
        }
        let t =
            targets.ok_or_else(|| validation("DeploymentTargets must be specified for SERVICE_MANAGED stack sets"))?;
        let ous = t.organizational_unit_ids.clone().unwrap_or_default();
        if ous.is_empty() {
            return Err(validation("OrganizationalUnitIds must be specified for SERVICE_MANAGED stack sets"));
        }
        let mut from_ous: Vec<(String, Option<String>)> = Vec::new();
        for ou in &ous {
            for a in self.ou_accounts(ctx, ou).await? {
                if a != set.account && !from_ous.iter().any(|(x, _)| x == &a) {
                    from_ous.push((a, Some(ou.clone())));
                }
            }
        }
        let mut listed = t.accounts.clone().unwrap_or_default();
        if let Some(url) = &t.accounts_url {
            listed.extend(self.accounts_from_url(ctx, url).await?);
        }
        let filter = t.account_filter_type.clone().unwrap_or_else(|| "NONE".into());
        Ok(match filter.as_str() {
            "INTERSECTION" => from_ous.into_iter().filter(|(a, _)| listed.contains(a)).collect(),
            "DIFFERENCE" => from_ous.into_iter().filter(|(a, _)| !listed.contains(a)).collect(),
            "UNION" => {
                let mut v = from_ous;
                for a in listed {
                    if !v.iter().any(|(x, _)| x == &a) {
                        v.push((a, None));
                    }
                }
                v
            }
            _ => from_ous,
        })
    }

    async fn accounts_from_url(&self, ctx: &RequestContext, url: &str) -> Result<Vec<String>, ServiceError> {
        let text = self.fetch_s3(ctx, url).await?;
        let list: Vec<String> = if text.trim_start().starts_with('[') {
            serde_json::from_str(&text)
                .map_err(|_| validation("AccountsUrl must point to a JSON list or CSV of account ids"))?
        } else {
            text.split([',', '\n', '\r']).map(str::trim).filter(|s| !s.is_empty()).map(str::to_string).collect()
        };
        Ok(list)
    }

    /// Active accounts in an OU and the OUs under it (or the whole
    /// organization for a root id).
    async fn ou_accounts(&self, ctx: &RequestContext, ou: &str) -> Result<Vec<String>, ServiceError> {
        let mut out = Vec::new();
        let mut queue = vec![ou.to_string()];
        while let Some(parent) = queue.pop() {
            let accounts = self
                .call(ctx, "organizations", "ListAccountsForParent", json!({"ParentId": parent}))
                .await
                .map_err(|e| validation(e.message))?;
            for a in accounts["Accounts"].as_array().cloned().unwrap_or_default() {
                if a["Status"] == json!("ACTIVE") {
                    out.push(a["Id"].as_str().unwrap_or_default().to_string());
                }
            }
            let children = self
                .call(ctx, "organizations", "ListOrganizationalUnitsForParent", json!({"ParentId": parent}))
                .await
                .map_err(|e| validation(e.message))?;
            for c in children["OrganizationalUnits"].as_array().cloned().unwrap_or_default() {
                queue.push(c["Id"].as_str().unwrap_or_default().to_string());
            }
        }
        Ok(out)
    }

    fn check_idle(&self, set: &StackSet) -> Result<(), ServiceError> {
        if !set.managed_execution
            && set.operations.iter().any(|o| matches!(o.status.as_str(), "RUNNING" | "STOPPING" | "QUEUED"))
        {
            return Err(in_progress(&set.arn));
        }
        Ok(())
    }

    pub(crate) async fn create_stack_instances_op(
        &self,
        ctx: &RequestContext,
        input: types::CreateStackInstancesInput,
    ) -> Result<types::CreateStackInstancesOutput, ServiceError> {
        let account = self.set_account(ctx, input.call_as.as_deref()).await?;
        let set = self.find_set(&account, &ctx.region, &input.stack_set_name)?;
        ctx.authorize("cloudformation:CreateStackInstances", &set.arn, Default::default())?;
        if input.regions.is_empty() {
            return Err(validation("Regions must be specified"));
        }
        let accounts =
            self.target_accounts(ctx, &set, input.accounts.clone(), input.deployment_targets.clone()).await?;
        check_prefs(input.operation_preferences.as_ref())?;
        if let Some(op) = &input.operation_id {
            if set.operations.iter().any(|o| &o.id == op) {
                return Err(errors::operation_id_already_exists(format!("The operation id {op} already exists")));
            }
        }
        self.check_idle(&set)?;
        let op_id = input.operation_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let overrides = input.parameter_overrides.clone().unwrap_or_default();
        let mut items = Vec::new();
        self.with_set(&set.id, |s| {
            for (a, ou) in &accounts {
                for r in &input.regions {
                    let k = key(a, r);
                    let i = s.instances.entry(k).or_insert_with(|| Instance {
                        account: a.clone(),
                        region: r.clone(),
                        ..Default::default()
                    });
                    i.overrides = merged(&i.overrides, &overrides);
                    i.status = "OUTDATED".into();
                    i.detailed = "PENDING".into();
                    i.reason = None;
                    i.ou = ou.clone().or(i.ou.clone());
                    if let Some(ou) = ou {
                        s.ou_regions.entry(ou.clone()).or_default().insert(r.clone());
                    }
                    items.push((a.clone(), r.clone(), ou.clone()));
                }
            }
        });
        let work = Work::Create;
        self.start_operation(
            ctx,
            &set.id,
            &op_id,
            "CREATE",
            work,
            items,
            input.operation_preferences.clone(),
            input.deployment_targets.clone(),
            None,
        )?;
        Ok(types::CreateStackInstancesOutput { operation_id: Some(op_id) })
    }

    pub(crate) async fn update_stack_instances_op(
        &self,
        ctx: &RequestContext,
        input: types::UpdateStackInstancesInput,
    ) -> Result<types::UpdateStackInstancesOutput, ServiceError> {
        let account = self.set_account(ctx, input.call_as.as_deref()).await?;
        let set = self.find_set(&account, &ctx.region, &input.stack_set_name)?;
        ctx.authorize("cloudformation:UpdateStackInstances", &set.arn, Default::default())?;
        let targets = self
            .resolve_targets(
                ctx,
                &set,
                input.accounts.clone(),
                input.deployment_targets.clone(),
                Some(input.regions.clone()),
                true,
            )
            .await?;
        check_prefs(input.operation_preferences.as_ref())?;
        if let Some(op) = &input.operation_id {
            if set.operations.iter().any(|o| &o.id == op) {
                return Err(errors::operation_id_already_exists(format!("The operation id {op} already exists")));
            }
        }
        self.check_idle(&set)?;
        let op_id = input.operation_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let overrides = input.parameter_overrides.clone();
        let declared: Vec<String> = set.parameters.iter().filter_map(|p| p.parameter_key.clone()).collect();
        if let Some(o) = &overrides {
            for p in o {
                let k = p.parameter_key.clone().unwrap_or_default();
                if !declared.contains(&k) {
                    return Err(validation(format!(
                        "Parameter override {k} is not a parameter of the stack set; you can only override parameters the stack set specifies"
                    )));
                }
            }
        }
        self.with_set(&set.id, |s| {
            for (k, _, _) in &targets {
                if let Some(i) = s.instances.get_mut(k) {
                    if let Some(o) = &overrides {
                        // An empty list removes all overrides; others replace
                        // the named ones.
                        i.overrides = if o.is_empty() { Vec::new() } else { merged(&i.overrides, o) };
                    }
                    i.status = "OUTDATED".into();
                }
            }
        });
        let items = targets.into_iter().map(|(k, _, ou)| a_r(k, ou)).collect();
        self.start_operation(
            ctx,
            &set.id,
            &op_id,
            "UPDATE",
            Work::Update,
            items,
            input.operation_preferences.clone(),
            input.deployment_targets.clone(),
            None,
        )?;
        Ok(types::UpdateStackInstancesOutput { operation_id: Some(op_id) })
    }

    pub(crate) async fn delete_stack_instances_op(
        &self,
        ctx: &RequestContext,
        input: types::DeleteStackInstancesInput,
    ) -> Result<types::DeleteStackInstancesOutput, ServiceError> {
        let account = self.set_account(ctx, input.call_as.as_deref()).await?;
        let set = self.find_set(&account, &ctx.region, &input.stack_set_name)?;
        ctx.authorize("cloudformation:DeleteStackInstances", &set.arn, Default::default())?;
        if input.regions.is_empty() {
            return Err(validation("Regions must be specified"));
        }
        let accounts =
            self.target_accounts(ctx, &set, input.accounts.clone(), input.deployment_targets.clone()).await?;
        check_prefs(input.operation_preferences.as_ref())?;
        if let Some(op) = &input.operation_id {
            if set.operations.iter().any(|o| &o.id == op) {
                return Err(errors::operation_id_already_exists(format!("The operation id {op} already exists")));
            }
        }
        self.check_idle(&set)?;
        let op_id = input.operation_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let mut items = Vec::new();
        for (a, ou) in &accounts {
            for r in &input.regions {
                if set.instances.contains_key(&key(a, r)) {
                    items.push((a.clone(), r.clone(), ou.clone()));
                }
            }
        }
        if set.permission_model == "SERVICE_MANAGED" {
            // Deleting every instance under an OU stops deploying to it.
            let ous: Vec<String> =
                input.deployment_targets.as_ref().and_then(|t| t.organizational_unit_ids.clone()).unwrap_or_default();
            self.with_set(&set.id, |s| {
                for ou in &ous {
                    if let Some(regions) = s.ou_regions.get_mut(ou) {
                        for r in &input.regions {
                            regions.remove(r);
                        }
                        if regions.is_empty() {
                            s.ou_regions.remove(ou);
                        }
                    }
                }
            });
        }
        let work = Work::Delete { retain: input.retain_stacks };
        self.start_operation(
            ctx,
            &set.id,
            &op_id,
            "DELETE",
            work,
            items,
            input.operation_preferences.clone(),
            input.deployment_targets.clone(),
            Some(input.retain_stacks),
        )?;
        Ok(types::DeleteStackInstancesOutput { operation_id: Some(op_id) })
    }

    pub(crate) async fn describe_stack_instance_op(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStackInstanceInput,
    ) -> Result<types::DescribeStackInstanceOutput, ServiceError> {
        let account = self.set_account(ctx, input.call_as.as_deref()).await?;
        let set = self.find_set(&account, &ctx.region, &input.stack_set_name)?;
        ctx.authorize("cloudformation:DescribeStackInstance", &set.arn, Default::default())?;
        self.reconcile_auto_deployment(ctx, &set.id).await;
        let set = self.find_set(&account, &ctx.region, &input.stack_set_name)?;
        let i =
            set.instances.get(&key(&input.stack_instance_account, &input.stack_instance_region)).ok_or_else(|| {
                errors::stack_instance_not_found(format!(
                    "Stack instance in account {} and region {} for StackSet {} not found",
                    input.stack_instance_account, input.stack_instance_region, set.name
                ))
            })?;
        Ok(types::DescribeStackInstanceOutput {
            stack_instance: Some(types::StackInstance {
                stack_set_id: Some(set.id.clone()),
                region: Some(i.region.clone()),
                account: Some(i.account.clone()),
                stack_id: i.stack_id.clone(),
                parameter_overrides: Some(i.overrides.clone()),
                status: Some(i.status.clone()),
                stack_instance_status: Some(types::StackInstanceComprehensiveStatus {
                    detailed_status: Some(i.detailed.clone()),
                }),
                status_reason: i.reason.clone(),
                organizational_unit_id: i.ou.clone(),
                drift_status: Some(i.drift_status.clone().unwrap_or_else(|| "NOT_CHECKED".into())),
                last_drift_check_timestamp: i.drift_checked,
                last_operation_id: i.last_operation.clone(),
            }),
        })
    }

    pub(crate) async fn list_stack_instances_op(
        &self,
        ctx: &RequestContext,
        input: types::ListStackInstancesInput,
    ) -> Result<types::ListStackInstancesOutput, ServiceError> {
        let account = self.set_account(ctx, input.call_as.as_deref()).await?;
        let set = self.find_set(&account, &ctx.region, &input.stack_set_name)?;
        ctx.authorize("cloudformation:ListStackInstances", &set.arn, Default::default())?;
        self.reconcile_auto_deployment(ctx, &set.id).await;
        let set = self.find_set(&account, &ctx.region, &input.stack_set_name)?;
        let filters = input.filters.clone().unwrap_or_default();
        let all: Vec<types::StackInstanceSummary> = set
            .instances
            .values()
            .filter(|i| input.stack_instance_account.as_ref().is_none_or(|a| &i.account == a))
            .filter(|i| input.stack_instance_region.as_ref().is_none_or(|r| &i.region == r))
            .filter(|i| {
                filters.iter().all(|f| {
                    let v = f.values.clone().unwrap_or_default();
                    match f.name.as_deref() {
                        Some("DETAILED_STATUS") => i.detailed == v,
                        Some("LAST_OPERATION_ID") => i.last_operation.as_deref() == Some(v.as_str()),
                        Some("DRIFT_STATUS") => i.drift_status.clone().unwrap_or_else(|| "NOT_CHECKED".into()) == v,
                        _ => true,
                    }
                })
            })
            .map(|i| types::StackInstanceSummary {
                stack_set_id: Some(set.id.clone()),
                region: Some(i.region.clone()),
                account: Some(i.account.clone()),
                stack_id: i.stack_id.clone(),
                status: Some(i.status.clone()),
                status_reason: i.reason.clone(),
                stack_instance_status: Some(types::StackInstanceComprehensiveStatus {
                    detailed_status: Some(i.detailed.clone()),
                }),
                organizational_unit_id: i.ou.clone(),
                drift_status: Some(i.drift_status.clone().unwrap_or_else(|| "NOT_CHECKED".into())),
                last_drift_check_timestamp: i.drift_checked,
                last_operation_id: i.last_operation.clone(),
            })
            .collect();
        let (summaries, next_token) =
            page(&all, input.next_token.as_deref(), input.max_results.unwrap_or(100) as usize)?;
        Ok(types::ListStackInstancesOutput { summaries: Some(summaries), next_token })
    }

    fn find_operation(&self, set: &StackSet, id: &str) -> Result<Operation, ServiceError> {
        set.operations
            .iter()
            .find(|o| o.id == id)
            .cloned()
            .ok_or_else(|| errors::operation_not_found(format!("Operation {id} not found for StackSet {}", set.name)))
    }

    pub(crate) async fn describe_stack_set_operation_op(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStackSetOperationInput,
    ) -> Result<types::DescribeStackSetOperationOutput, ServiceError> {
        let account = self.set_account(ctx, input.call_as.as_deref()).await?;
        let set = self.find_set(&account, &ctx.region, &input.stack_set_name)?;
        ctx.authorize("cloudformation:DescribeStackSetOperation", &set.arn, Default::default())?;
        let o = self.find_operation(&set, &input.operation_id)?;
        let failed = o.results.iter().filter(|r| r.status == "FAILED").count() as i32;
        Ok(types::DescribeStackSetOperationOutput {
            stack_set_operation: Some(types::StackSetOperation {
                operation_id: Some(o.id.clone()),
                stack_set_id: Some(set.id.clone()),
                action: Some(o.action.clone()),
                status: Some(o.status.clone()),
                operation_preferences: o.preferences.clone(),
                retain_stacks: o.retain_stacks,
                administration_role_arn: o.administration_role_arn.clone(),
                execution_role_name: o.execution_role_name.clone(),
                creation_timestamp: Some(o.created),
                end_timestamp: o.ended,
                deployment_targets: o.targets.clone(),
                stack_set_drift_detection_details: o.drift.clone(),
                status_reason: o.status_reason.clone(),
                status_details: Some(types::StackSetOperationStatusDetails {
                    failed_stack_instances_count: Some(failed),
                }),
            }),
        })
    }

    pub(crate) async fn list_stack_set_operations_op(
        &self,
        ctx: &RequestContext,
        input: types::ListStackSetOperationsInput,
    ) -> Result<types::ListStackSetOperationsOutput, ServiceError> {
        let account = self.set_account(ctx, input.call_as.as_deref()).await?;
        let set = self.find_set(&account, &ctx.region, &input.stack_set_name)?;
        ctx.authorize("cloudformation:ListStackSetOperations", &set.arn, Default::default())?;
        self.reconcile_auto_deployment(ctx, &set.id).await;
        let set = self.find_set(&account, &ctx.region, &input.stack_set_name)?;
        let all: Vec<types::StackSetOperationSummary> =
            set.operations
                .iter()
                .rev()
                .map(|o| types::StackSetOperationSummary {
                    operation_id: Some(o.id.clone()),
                    action: Some(o.action.clone()),
                    status: Some(o.status.clone()),
                    creation_timestamp: Some(o.created),
                    end_timestamp: o.ended,
                    status_reason: o.status_reason.clone(),
                    status_details: Some(types::StackSetOperationStatusDetails {
                        failed_stack_instances_count: Some(
                            o.results.iter().filter(|r| r.status == "FAILED").count() as i32
                        ),
                    }),
                    operation_preferences: o.preferences.clone(),
                })
                .collect();
        let (summaries, next_token) =
            page(&all, input.next_token.as_deref(), input.max_results.unwrap_or(100) as usize)?;
        Ok(types::ListStackSetOperationsOutput { summaries: Some(summaries), next_token })
    }

    pub(crate) async fn list_stack_set_operation_results_op(
        &self,
        ctx: &RequestContext,
        input: types::ListStackSetOperationResultsInput,
    ) -> Result<types::ListStackSetOperationResultsOutput, ServiceError> {
        let account = self.set_account(ctx, input.call_as.as_deref()).await?;
        let set = self.find_set(&account, &ctx.region, &input.stack_set_name)?;
        ctx.authorize("cloudformation:ListStackSetOperationResults", &set.arn, Default::default())?;
        let o = self.find_operation(&set, &input.operation_id)?;
        let filters = input.filters.clone().unwrap_or_default();
        let all: Vec<types::StackSetOperationResultSummary> = o
            .results
            .iter()
            .filter(|r| {
                filters.iter().all(|f| match f.name.as_deref() {
                    Some("OPERATION_RESULT_STATUS") => f.values.as_deref() == Some(r.status.as_str()),
                    _ => true,
                })
            })
            .map(|r| types::StackSetOperationResultSummary {
                account: Some(r.account.clone()),
                region: Some(r.region.clone()),
                status: Some(r.status.clone()),
                status_reason: r.reason.clone(),
                account_gate_result: r
                    .gate
                    .clone()
                    .map(|(s, reason)| types::AccountGateResult { status: Some(s), status_reason: reason }),
                organizational_unit_id: r.ou.clone(),
            })
            .collect();
        let (summaries, next_token) =
            page(&all, input.next_token.as_deref(), input.max_results.unwrap_or(100) as usize)?;
        Ok(types::ListStackSetOperationResultsOutput { summaries: Some(summaries), next_token })
    }

    pub(crate) async fn stop_stack_set_operation_op(
        &self,
        ctx: &RequestContext,
        input: types::StopStackSetOperationInput,
    ) -> Result<(), ServiceError> {
        let account = self.set_account(ctx, input.call_as.as_deref()).await?;
        let set = self.find_set(&account, &ctx.region, &input.stack_set_name)?;
        ctx.authorize("cloudformation:StopStackSetOperation", &set.arn, Default::default())?;
        let o = self.find_operation(&set, &input.operation_id)?;
        if !matches!(o.status.as_str(), "RUNNING" | "QUEUED") {
            return Err(errors::invalid_operation(format!(
                "Operation {} cannot be stopped in its current status {}",
                o.id, o.status
            )));
        }
        self.with_set(&set.id, |s| {
            if let Some(op) = s.operations.iter_mut().find(|x| x.id == o.id) {
                op.stop = true;
                op.status = "STOPPING".into();
            }
        });
        Ok(())
    }

    pub(crate) async fn detect_stack_set_drift_op(
        &self,
        ctx: &RequestContext,
        input: types::DetectStackSetDriftInput,
    ) -> Result<types::DetectStackSetDriftOutput, ServiceError> {
        let account = self.set_account(ctx, input.call_as.as_deref()).await?;
        let set = self.find_set(&account, &ctx.region, &input.stack_set_name)?;
        ctx.authorize("cloudformation:DetectStackSetDrift", &set.arn, Default::default())?;
        check_prefs(input.operation_preferences.as_ref())?;
        self.check_idle(&set)?;
        let op_id = input.operation_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let items = set.instances.values().map(|i| (i.account.clone(), i.region.clone(), i.ou.clone())).collect();
        self.start_operation(
            ctx,
            &set.id,
            &op_id,
            "DETECT_DRIFT",
            Work::Drift,
            items,
            input.operation_preferences.clone(),
            None,
            None,
        )?;
        Ok(types::DetectStackSetDriftOutput { operation_id: Some(op_id) })
    }

    pub(crate) async fn list_stack_instance_resource_drifts_op(
        &self,
        ctx: &RequestContext,
        input: types::ListStackInstanceResourceDriftsInput,
    ) -> Result<types::ListStackInstanceResourceDriftsOutput, ServiceError> {
        let account = self.set_account(ctx, input.call_as.as_deref()).await?;
        let set = self.find_set(&account, &ctx.region, &input.stack_set_name)?;
        ctx.authorize("cloudformation:ListStackInstanceResourceDrifts", &set.arn, Default::default())?;
        self.find_operation(&set, &input.operation_id)?;
        let i =
            set.instances.get(&key(&input.stack_instance_account, &input.stack_instance_region)).ok_or_else(|| {
                errors::stack_instance_not_found(format!(
                    "Stack instance in account {} and region {} for StackSet {} not found",
                    input.stack_instance_account, input.stack_instance_region, set.name
                ))
            })?;
        let Some(stack_id) = &i.stack_id else {
            return Ok(types::ListStackInstanceResourceDriftsOutput { summaries: Some(vec![]), next_token: None });
        };
        let wanted = input.stack_instance_resource_drift_statuses.clone();
        let drifts: Vec<types::StackInstanceResourceDriftsSummary> = {
            let st = self.state();
            st.drift_detections
                .values()
                .filter(|d| &d.stack_id == stack_id)
                .max_by_key(|d| d.timestamp)
                .map(|d| {
                    d.results
                        .iter()
                        .filter(|r| wanted.as_ref().is_none_or(|w| w.contains(&r.status)))
                        .map(|r| types::StackInstanceResourceDriftsSummary {
                            stack_id: stack_id.clone(),
                            logical_resource_id: r.logical_id.clone(),
                            physical_resource_id: r.physical_id.clone(),
                            physical_resource_id_context: None,
                            resource_type: r.resource_type.clone(),
                            property_differences: Some(
                                r.differences
                                    .iter()
                                    .map(|(p, e, a, t)| types::PropertyDifference {
                                        property_path: p.clone(),
                                        expected_value: e.clone(),
                                        actual_value: a.clone(),
                                        difference_type: t.clone(),
                                    })
                                    .collect(),
                            ),
                            stack_resource_drift_status: r.status.clone(),
                            timestamp: r.timestamp,
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        let (summaries, next_token) =
            page(&drifts, input.next_token.as_deref(), input.max_results.unwrap_or(100) as usize)?;
        Ok(types::ListStackInstanceResourceDriftsOutput { summaries: Some(summaries), next_token })
    }

    pub(crate) async fn list_stack_set_auto_deployment_targets_op(
        &self,
        ctx: &RequestContext,
        input: types::ListStackSetAutoDeploymentTargetsInput,
    ) -> Result<types::ListStackSetAutoDeploymentTargetsOutput, ServiceError> {
        let account = self.set_account(ctx, input.call_as.as_deref()).await?;
        let set = self.find_set(&account, &ctx.region, &input.stack_set_name)?;
        ctx.authorize("cloudformation:ListStackSetAutoDeploymentTargets", &set.arn, Default::default())?;
        let auto = set.auto_deployment.as_ref().and_then(|a| a.enabled).unwrap_or(false);
        let all: Vec<types::StackSetAutoDeploymentTargetSummary> = if auto {
            set.ou_regions
                .iter()
                .map(|(ou, r)| types::StackSetAutoDeploymentTargetSummary {
                    organizational_unit_id: Some(ou.clone()),
                    regions: Some(r.iter().cloned().collect()),
                })
                .collect()
        } else {
            Vec::new()
        };
        let (summaries, next_token) =
            page(&all, input.next_token.as_deref(), input.max_results.unwrap_or(100) as usize)?;
        Ok(types::ListStackSetAutoDeploymentTargetsOutput { summaries: Some(summaries), next_token })
    }

    pub(crate) async fn import_stacks_to_stack_set_op(
        &self,
        ctx: &RequestContext,
        input: types::ImportStacksToStackSetInput,
    ) -> Result<types::ImportStacksToStackSetOutput, ServiceError> {
        let account = self.set_account(ctx, input.call_as.as_deref()).await?;
        let set = self.find_set(&account, &ctx.region, &input.stack_set_name)?;
        ctx.authorize("cloudformation:ImportStacksToStackSet", &set.arn, Default::default())?;
        let mut ids = input.stack_ids.clone().unwrap_or_default();
        if let Some(url) = &input.stack_ids_url {
            ids.extend(self.accounts_from_url(ctx, url).await?);
        }
        if ids.is_empty() {
            return Err(validation("StackIds or StackIdsUrl must be specified"));
        }
        let ous = input.organizational_unit_ids.clone().unwrap_or_default();
        if set.permission_model == "SERVICE_MANAGED" && ous.len() != ids.len() {
            return Err(validation("OrganizationalUnitIds must name one OU for each stack"));
        }
        let mut items = Vec::new();
        {
            let st = self.state();
            for (n, id) in ids.iter().enumerate() {
                let s = st
                    .stacks
                    .get(id)
                    .filter(|s| !s.is_deleted())
                    .ok_or_else(|| errors::stack_not_found(format!("Stack with id {id} does not exist")))?;
                if set.instances.contains_key(&key(&s.account, &s.region)) {
                    return Err(validation(format!(
                        "StackSet {} already has a stack instance in account {} and region {}",
                        set.name, s.account, s.region
                    )));
                }
                items.push((s.account.clone(), s.region.clone(), ous.get(n).cloned(), s.id.clone()));
            }
        }
        self.check_idle(&set)?;
        let op_id = input.operation_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        self.with_set(&set.id, |s| {
            for (a, r, ou, stack) in &items {
                s.instances.insert(
                    key(a, r),
                    Instance {
                        account: a.clone(),
                        region: r.clone(),
                        stack_id: Some(stack.clone()),
                        status: "OUTDATED".into(),
                        detailed: "PENDING".into(),
                        ou: ou.clone(),
                        ..Default::default()
                    },
                );
                if let Some(ou) = ou {
                    s.ou_regions.entry(ou.clone()).or_default().insert(r.clone());
                }
            }
        });
        let items = items.into_iter().map(|(a, r, ou, _)| (a, r, ou)).collect();
        // Importing brings each stack under the stack set's template.
        self.start_operation(
            ctx,
            &set.id,
            &op_id,
            "CREATE",
            Work::Update,
            items,
            input.operation_preferences.clone(),
            None,
            None,
        )?;
        Ok(types::ImportStacksToStackSetOutput { operation_id: Some(op_id) })
    }

    /// Deploy to accounts that joined an auto-deployment OU and remove
    /// instances from accounts that left, as AWS does when Organizations
    /// membership changes.
    async fn reconcile_auto_deployment(&self, ctx: &RequestContext, set_id: &str) {
        let Some(set) = self.state().stack_sets.get(set_id).cloned() else { return };
        let auto = set.auto_deployment.clone().unwrap_or_default();
        if set.permission_model != "SERVICE_MANAGED" || auto.enabled != Some(true) || set.ou_regions.is_empty() {
            return;
        }
        if set.operations.iter().any(|o| matches!(o.status.as_str(), "RUNNING" | "STOPPING" | "QUEUED")) {
            return;
        }
        let mut want: BTreeMap<String, (String, String, String)> = BTreeMap::new();
        for (ou, regions) in &set.ou_regions {
            let Ok(accounts) = self.ou_accounts(ctx, ou).await else { return };
            for a in accounts.into_iter().filter(|a| a != &set.account) {
                for r in regions {
                    want.insert(key(&a, r), (a.clone(), r.clone(), ou.clone()));
                }
            }
        }
        let added: Vec<(String, String, Option<String>)> = want
            .iter()
            .filter(|(k, _)| !set.instances.contains_key(*k))
            .map(|(_, (a, r, ou))| (a.clone(), r.clone(), Some(ou.clone())))
            .collect();
        let removed: Vec<(String, String, Option<String>)> = set
            .instances
            .iter()
            .filter(|(k, i)| i.ou.is_some() && !want.contains_key(*k))
            .map(|(_, i)| (i.account.clone(), i.region.clone(), i.ou.clone()))
            .collect();
        if !added.is_empty() {
            self.with_set(set_id, |s| {
                for (a, r, ou) in &added {
                    s.instances.insert(
                        key(a, r),
                        Instance {
                            account: a.clone(),
                            region: r.clone(),
                            status: "OUTDATED".into(),
                            detailed: "PENDING".into(),
                            ou: ou.clone(),
                            ..Default::default()
                        },
                    );
                }
            });
            let id = uuid::Uuid::new_v4().to_string();
            let _ = self.start_operation(ctx, set_id, &id, "CREATE", Work::Create, added, None, None, None);
        } else if !removed.is_empty() {
            let retain = auto.retain_stacks_on_account_removal.unwrap_or(false);
            let id = uuid::Uuid::new_v4().to_string();
            let _ = self.start_operation(
                ctx,
                set_id,
                &id,
                "DELETE",
                Work::Delete { retain },
                removed,
                None,
                None,
                Some(retain),
            );
        }
    }

    /// Record an operation and run it in the background.
    #[allow(clippy::too_many_arguments)]
    fn start_operation(
        &self,
        ctx: &RequestContext,
        set_id: &str,
        op_id: &str,
        action: &str,
        work: Work,
        items: Vec<(String, String, Option<String>)>,
        preferences: Option<types::StackSetOperationPreferences>,
        targets: Option<types::DeploymentTargets>,
        retain: Option<bool>,
    ) -> Result<(), ServiceError> {
        let queued = {
            let mut st = self.state();
            let set = st.stack_sets.get_mut(set_id).ok_or_else(|| not_found(set_id))?;
            let busy = set.operations.iter().any(|o| matches!(o.status.as_str(), "RUNNING" | "STOPPING" | "QUEUED"));
            let model_self = set.permission_model == "SELF_MANAGED";
            let admin = model_self.then(|| self.admin_role(set));
            let exec =
                model_self.then(|| set.execution_role_name.clone().unwrap_or_else(|| DEFAULT_EXECUTION_ROLE.into()));
            set.operations.push(Operation {
                id: op_id.to_string(),
                action: action.to_string(),
                status: if busy { "QUEUED".into() } else { "RUNNING".into() },
                preferences: Some(preferences.clone().unwrap_or_default()),
                retain_stacks: retain,
                administration_role_arn: admin,
                execution_role_name: exec,
                targets,
                created: ctx.received_at,
                results: items
                    .iter()
                    .map(|(a, r, ou)| OpResult {
                        account: a.clone(),
                        region: r.clone(),
                        status: "PENDING".into(),
                        ou: ou.clone(),
                        ..Default::default()
                    })
                    .collect(),
                ..Default::default()
            });
            for (a, r, _) in &items {
                if let Some(i) = set.instances.get_mut(&key(a, r)) {
                    i.last_operation = Some(op_id.to_string());
                }
            }
            busy
        };
        let me = self.clone();
        let ctx = ctx.clone();
        let set_id = set_id.to_string();
        let op_id = op_id.to_string();
        tokio::spawn(async move {
            if queued {
                // Managed execution: run once the operations ahead finish.
                loop {
                    let ahead = me
                        .state()
                        .stack_sets
                        .get(&set_id)
                        .map(|s| {
                            s.operations
                                .iter()
                                .take_while(|o| o.id != op_id)
                                .any(|o| matches!(o.status.as_str(), "RUNNING" | "STOPPING" | "QUEUED"))
                        })
                        .unwrap_or(false);
                    if !ahead {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                me.with_set(&set_id, |s| {
                    if let Some(o) = s.operations.iter_mut().find(|o| o.id == op_id) {
                        if o.status == "QUEUED" {
                            o.status = "RUNNING".into();
                        }
                    }
                });
            }
            me.run_operation(ctx, set_id, op_id, work, items, preferences.unwrap_or_default()).await;
        });
        Ok(())
    }

    async fn run_operation(
        &self,
        ctx: RequestContext,
        set_id: String,
        op_id: String,
        work: Work,
        items: Vec<(String, String, Option<String>)>,
        prefs: types::StackSetOperationPreferences,
    ) {
        // Regions in the requested order, then the rest.
        let mut regions: Vec<String> = prefs.region_order.clone().unwrap_or_default();
        for (_, r, _) in &items {
            if !regions.contains(r) {
                regions.push(r.clone());
            }
        }
        let per_region: Vec<Vec<(String, String, Option<String>)>> = regions
            .iter()
            .map(|r| items.iter().filter(|(_, x, _)| x == r).cloned().collect::<Vec<_>>())
            .filter(|v| !v.is_empty())
            .collect();
        let accounts = per_region.iter().map(|v| v.len()).max().unwrap_or(0).max(1);
        let tolerance = match (prefs.failure_tolerance_count, prefs.failure_tolerance_percentage) {
            (Some(c), _) => c as usize,
            (None, Some(p)) => (accounts * p as usize) / 100,
            _ => 0,
        };
        let max_concurrent = match (prefs.max_concurrent_count, prefs.max_concurrent_percentage) {
            (Some(c), _) => c.max(1) as usize,
            (None, Some(p)) => ((accounts * p as usize) / 100).max(1),
            _ => 1,
        };
        let parallel_regions = prefs.region_concurrency_type.as_deref() == Some("PARALLEL");
        let mut failed_total = 0usize;
        let mut cancelled = false;
        let run_region = |batch: Vec<(String, String, Option<String>)>| {
            let me = self.clone();
            let ctx = ctx.clone();
            let set_id = set_id.clone();
            let op_id = op_id.clone();
            let work = work.clone();
            async move {
                let mut failures = 0usize;
                let mut stopped = false;
                for chunk in batch.chunks(max_concurrent) {
                    if stopped || failures > tolerance || me.stop_requested(&set_id, &op_id) {
                        stopped = true;
                        for (a, r, _) in chunk {
                            me.finish_item(
                                &set_id,
                                &op_id,
                                a,
                                r,
                                "CANCELLED",
                                Some("Cancelled since failure tolerance has exceeded".into()),
                                None,
                            );
                        }
                        continue;
                    }
                    let mut set = tokio::task::JoinSet::new();
                    for (a, r, ou) in chunk.iter().cloned() {
                        let me = me.clone();
                        let ctx = ctx.clone();
                        let set_id = set_id.clone();
                        let op_id = op_id.clone();
                        let work = work.clone();
                        set.spawn(async move { me.run_item(&ctx, &set_id, &op_id, &work, &a, &r, ou).await });
                    }
                    while let Some(ok) = set.join_next().await {
                        if !ok.unwrap_or(false) {
                            failures += 1;
                        }
                    }
                }
                (failures, stopped)
            }
        };
        if parallel_regions {
            let results = {
                let mut handles = Vec::new();
                for batch in per_region {
                    handles.push(run_region(batch));
                }
                let mut out = Vec::new();
                for h in handles {
                    out.push(h.await);
                }
                out
            };
            for (f, s) in results {
                failed_total += f;
                cancelled |= s;
            }
        } else {
            for batch in per_region {
                if failed_total > tolerance || self.stop_requested(&set_id, &op_id) {
                    cancelled = true;
                    for (a, r, _) in &batch {
                        self.finish_item(
                            &set_id,
                            &op_id,
                            a,
                            r,
                            "CANCELLED",
                            Some("Cancelled since failure tolerance has exceeded".into()),
                            None,
                        );
                    }
                    continue;
                }
                let (f, s) = run_region(batch).await;
                failed_total += f;
                cancelled |= s;
            }
        }
        let stop = self.stop_requested(&set_id, &op_id);
        let now =
            Utc::now() + (ctx.received_at - Utc::now()).min(chrono::Duration::zero()).max(chrono::Duration::zero());
        let drift = matches!(work, Work::Drift).then(|| self.drift_summary(&set_id, &op_id));
        self.with_set(&set_id, |s| {
            if let Some(o) = s.operations.iter_mut().find(|o| o.id == op_id) {
                o.ended = Some(now);
                o.status = if stop {
                    "STOPPED".into()
                } else if failed_total > tolerance || cancelled {
                    o.status_reason =
                        Some("The Operation failed to complete because the failure tolerance was exceeded.".into());
                    "FAILED".into()
                } else {
                    "SUCCEEDED".into()
                };
                if let Some(d) = &drift {
                    o.drift = Some(d.clone());
                }
            }
            if let Some(d) = drift {
                s.drift = Some(d);
            }
            if stop {
                for i in s.instances.values_mut() {
                    if i.last_operation.as_deref() == Some(op_id.as_str())
                        && matches!(i.detailed.as_str(), "PENDING" | "RUNNING")
                    {
                        i.detailed = "CANCELLED".into();
                    }
                }
            }
        });
    }

    fn stop_requested(&self, set_id: &str, op_id: &str) -> bool {
        self.state()
            .stack_sets
            .get(set_id)
            .and_then(|s| s.operations.iter().find(|o| o.id == op_id))
            .is_some_and(|o| o.stop)
    }

    #[allow(clippy::too_many_arguments)]
    fn finish_item(
        &self,
        set_id: &str,
        op_id: &str,
        account: &str,
        region: &str,
        status: &str,
        reason: Option<String>,
        gate: Option<(String, Option<String>)>,
    ) {
        self.with_set(set_id, |s| {
            if let Some(o) = s.operations.iter_mut().find(|o| o.id == op_id) {
                if let Some(r) = o.results.iter_mut().find(|r| r.account == account && r.region == region) {
                    r.status = status.to_string();
                    r.reason = reason.clone();
                    if gate.is_some() {
                        r.gate = gate.clone();
                    }
                }
            }
            if status == "CANCELLED" {
                if let Some(i) = s.instances.get_mut(&key(account, region)) {
                    i.detailed = "CANCELLED".into();
                }
            }
        });
    }

    /// Run one `(account, region)` of an operation; whether it succeeded.
    #[allow(clippy::too_many_arguments)]
    async fn run_item(
        &self,
        ctx: &RequestContext,
        set_id: &str,
        op_id: &str,
        work: &Work,
        account: &str,
        region: &str,
        ou: Option<String>,
    ) -> bool {
        let k = key(account, region);
        self.with_set(set_id, |s| {
            if let Some(o) = s.operations.iter_mut().find(|o| o.id == op_id) {
                if let Some(r) = o.results.iter_mut().find(|r| r.account == account && r.region == region) {
                    r.status = "RUNNING".into();
                }
            }
            if let Some(i) = s.instances.get_mut(&k) {
                i.detailed = "RUNNING".into();
            }
        });
        let Some(set) = self.state().stack_sets.get(set_id).cloned() else { return false };
        if matches!(work, Work::Delete { retain: true }) {
            // Retaining only disassociates the stack; nothing is deployed.
            self.finish_item(set_id, op_id, account, region, "SUCCEEDED", None, None);
            self.with_set(set_id, |s| {
                s.instances.remove(&k);
            });
            return true;
        }
        let target = match self.target_context(ctx, &set, account, region).await {
            Ok(t) => t,
            Err(reason) => {
                self.finish_item(set_id, op_id, account, region, "FAILED", Some(reason.clone()), None);
                self.with_set(set_id, |s| {
                    if let Some(i) = s.instances.get_mut(&k) {
                        i.detailed = "FAILED".into();
                        i.status =
                            if matches!(work, Work::Delete { .. }) { "INOPERABLE".into() } else { "OUTDATED".into() };
                        i.reason = Some(reason);
                    }
                });
                return false;
            }
        };
        // The account gate: a Lambda function the target account can use to
        // stop deployments.
        let gate = if matches!(work, Work::Drift) { None } else { Some(self.account_gate(&target).await) };
        if let Some((status, reason)) = &gate {
            if status == "FAILED" {
                let why = reason.clone().unwrap_or_default();
                self.finish_item(
                    set_id,
                    op_id,
                    account,
                    region,
                    "FAILED",
                    Some(format!("Account gate check failed: {why}")),
                    gate.clone(),
                );
                self.with_set(set_id, |s| {
                    if let Some(i) = s.instances.get_mut(&k) {
                        i.detailed = "FAILED".into();
                        i.reason = Some(format!("Account gate check failed: {why}"));
                    }
                });
                return false;
            }
        }
        let instance = set.instances.get(&k).cloned().unwrap_or_default();
        let result = match work {
            Work::Create | Work::Update => self.deploy_instance(&target, &set, &instance).await,
            Work::Delete { retain } => self.remove_instance(&target, &instance, *retain).await.map(|_| None),
            Work::Drift => self.drift_instance(&target, set_id, &instance).await.map(|_| None),
        };
        match result {
            Ok(stack_id) => {
                self.finish_item(set_id, op_id, account, region, "SUCCEEDED", None, gate);
                self.with_set(set_id, |s| {
                    if matches!(work, Work::Delete { .. }) {
                        s.instances.remove(&k);
                        return;
                    }
                    if let Some(i) = s.instances.get_mut(&k) {
                        if let Some(id) = stack_id {
                            i.stack_id = Some(id);
                        }
                        if !matches!(work, Work::Drift) {
                            i.status = "CURRENT".into();
                            i.reason = None;
                        }
                        i.detailed = "SUCCEEDED".into();
                        if i.ou.is_none() {
                            i.ou = ou;
                        }
                    }
                });
                true
            }
            Err(reason) => {
                self.finish_item(set_id, op_id, account, region, "FAILED", Some(reason.clone()), gate);
                self.with_set(set_id, |s| {
                    if let Some(i) = s.instances.get_mut(&k) {
                        i.detailed = "FAILED".into();
                        i.reason = Some(reason);
                        if matches!(work, Work::Delete { .. }) {
                            i.status = "INOPERABLE".into();
                        }
                    }
                });
                false
            }
        }
    }

    /// The identity a stack instance deploys with.
    async fn target_context(
        &self,
        ctx: &RequestContext,
        set: &StackSet,
        account: &str,
        region: &str,
    ) -> Result<RequestContext, String> {
        let roles =
            self.role_assumer().ok_or_else(|| "StackSets cannot assume roles in this deployment".to_string())?;
        let now = ctx.received_at;
        let caller = if set.permission_model == "SERVICE_MANAGED" {
            roles.org_member(account, &set.account, now)?
        } else {
            let admin = self.admin_role(set);
            let exec = set.execution_role_name.clone().unwrap_or_else(|| DEFAULT_EXECUTION_ROLE.into());
            let admin_name = admin.rsplit('/').next().unwrap_or(&admin).to_string();
            let trust_error = || {
                format!("Account {account} should have '{exec}' role with trust relationship to Role '{admin_name}'.")
            };
            let admin_caller = roles
                .assume(&admin, "AWSCloudFormation-StackSets", now)
                .map_err(|_| format!("Role {admin} is invalid or cannot be assumed"))?;
            let mut admin_ctx = ctx.clone();
            admin_ctx.caller = admin_caller;
            let partition = &ctx.partition;
            let exec_arn = format!("arn:{partition}:iam::{account}:role/{exec}");
            let out = self
                .call(
                    &self.via(&admin_ctx),
                    "sts",
                    "AssumeRole",
                    json!({"RoleArn": exec_arn, "RoleSessionName": format!("stacksets-{}", &set.id.rsplit(':').next().unwrap_or("x")[..8])}),
                )
                .await
                .map_err(|_| trust_error())?;
            let c = &out["Credentials"];
            roles
                .resolve(c["AccessKeyId"].as_str().unwrap_or_default(), c["SessionToken"].as_str(), now)
                .ok_or_else(trust_error)?
        };
        let mut t = ctx.clone();
        t.caller = caller;
        t.region = region.to_string();
        Ok(self.via(&t))
    }

    /// Invoke the target's `AWSCloudFormationStackSetAccountGate`
    /// function, if it has one.
    async fn account_gate(&self, target: &RequestContext) -> (String, Option<String>) {
        let arn = format!(
            "arn:{}:lambda:{}:{}:function:{ACCOUNT_GATE}",
            target.partition, target.region, target.caller.account_id
        );
        match self.call(target, "lambda", "Invoke", json!({"FunctionName": ACCOUNT_GATE})).await {
            Err(e) if e.code.contains("ResourceNotFound") => {
                ("SKIPPED".into(), Some(format!("Function not found: {arn}")))
            }
            Err(e) => ("FAILED".into(), Some(e.message)),
            Ok(out) => {
                let payload = out["Payload"].as_str().and_then(|p| base64_decode(p)).unwrap_or_default();
                let v: Value = serde_json::from_str(&payload).unwrap_or(Value::Null);
                if out.get("FunctionError").is_some_and(|e| !e.is_null()) {
                    return ("FAILED".into(), Some("AccountGate function returned an error".into()));
                }
                match v["Status"].as_str() {
                    Some("SUCCEEDED") => ("SUCCEEDED".into(), None),
                    _ => ("FAILED".into(), Some(format!("AccountGate function returned status {}", v["Status"]))),
                }
            }
        }
    }

    /// Create or update an instance's stack; returns its id.
    async fn deploy_instance(
        &self,
        target: &RequestContext,
        set: &StackSet,
        instance: &Instance,
    ) -> Result<Option<String>, String> {
        let parameters = merged(&set.parameters, &instance.overrides);
        let existing = instance.stack_id.clone().filter(|id| {
            self.state().stacks.get(id).is_some_and(|s| !s.is_deleted() && s.status != "ROLLBACK_COMPLETE")
        });
        if let Some(id) = existing {
            let out = self
                .update_stack_op(
                    target,
                    types::UpdateStackInput {
                        stack_name: id.clone(),
                        template_body: Some(set.template_body.clone()),
                        parameters: Some(parameters),
                        capabilities: Some(set.capabilities.clone()),
                        tags: Some(set.tags.clone()),
                        ..Default::default()
                    },
                )
                .await;
            match out {
                Ok(_) => {}
                Err(e) if e.message == "No updates are to be performed." => return Ok(Some(id)),
                Err(e) => return Err(e.message),
            }
            let s = self.wait_stack(&id).await;
            return if s.status == "UPDATE_COMPLETE" { Ok(Some(id)) } else { Err(self.failure_reason(&s)) };
        }
        if let Some(old) = &instance.stack_id {
            // A failed create left a rolled-back stack; replace it.
            let _ = self
                .delete_stack_op(target, types::DeleteStackInput { stack_name: old.clone(), ..Default::default() })
                .await;
            self.wait_stack(old).await;
        }
        let name = format!("StackSet-{}-{}", set.name, uuid::Uuid::new_v4());
        let out = self
            .create_stack_op(
                target,
                types::CreateStackInput {
                    stack_name: name,
                    template_body: Some(set.template_body.clone()),
                    parameters: Some(parameters),
                    capabilities: Some(set.capabilities.clone()),
                    tags: Some(set.tags.clone()),
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| e.message)?;
        let id = out.stack_id.unwrap_or_default();
        let s = self.wait_stack(&id).await;
        if s.status == "CREATE_COMPLETE" {
            Ok(Some(id))
        } else {
            // Keep the id so the next attempt replaces the failed stack.
            self.with_set_instance(&set.id, &instance.account, &instance.region, |i| i.stack_id = Some(id.clone()));
            Err(self.failure_reason(&s))
        }
    }

    fn with_set_instance(&self, set_id: &str, account: &str, region: &str, f: impl FnOnce(&mut Instance)) {
        self.with_set(set_id, |s| {
            if let Some(i) = s.instances.get_mut(&key(account, region)) {
                f(i);
            }
        });
    }

    fn failure_reason(&self, s: &crate::state::Stack) -> String {
        let failed = s
            .events
            .iter()
            .rev()
            .find(|e| e.status.ends_with("_FAILED") && e.logical_id != s.name)
            .and_then(|e| e.reason.clone());
        format!(
            "ResourceLogicalId:{}, ResourceType:{}, ResourceStatusReason:{}.",
            s.events
                .iter()
                .rev()
                .find(|e| e.status.ends_with("_FAILED") && e.logical_id != s.name)
                .map(|e| e.logical_id.clone())
                .unwrap_or_default(),
            s.events
                .iter()
                .rev()
                .find(|e| e.status.ends_with("_FAILED") && e.logical_id != s.name)
                .map(|e| e.resource_type.clone())
                .unwrap_or_default(),
            failed.or_else(|| s.status_reason.clone()).unwrap_or_else(|| s.status.clone())
        )
    }

    async fn remove_instance(&self, target: &RequestContext, instance: &Instance, retain: bool) -> Result<(), String> {
        let Some(id) = &instance.stack_id else { return Ok(()) };
        if retain {
            return Ok(());
        }
        if self.state().stacks.get(id).is_none_or(|s| s.is_deleted()) {
            return Ok(());
        }
        self.delete_stack_op(target, types::DeleteStackInput { stack_name: id.clone(), ..Default::default() })
            .await
            .map_err(|e| e.message)?;
        let s = self.wait_stack(id).await;
        if s.status == "DELETE_COMPLETE" {
            Ok(())
        } else {
            Err(self.failure_reason(&s))
        }
    }

    async fn drift_instance(&self, target: &RequestContext, set_id: &str, instance: &Instance) -> Result<(), String> {
        let Some(id) = &instance.stack_id else { return Err("The stack instance has no stack".into()) };
        let out = self
            .detect_stack_drift_op(
                target,
                types::DetectStackDriftInput { stack_name: id.clone(), ..Default::default() },
            )
            .await
            .map_err(|e| e.message)?;
        let d = self.state().drift_detections.get(&out.stack_drift_detection_id).cloned();
        let Some(d) = d else { return Err("Drift detection failed".into()) };
        self.with_set_instance(set_id, &instance.account, &instance.region, |i| {
            i.drift_status = d.stack_drift_status.clone();
            i.drift_checked = Some(d.timestamp);
        });
        Ok(())
    }

    fn drift_summary(&self, set_id: &str, op_id: &str) -> types::StackSetDriftDetectionDetails {
        let st = self.state();
        let Some(s) = st.stack_sets.get(set_id) else { return Default::default() };
        let ids: BTreeSet<String> = s
            .operations
            .iter()
            .find(|o| o.id == op_id)
            .map(|o| o.results.iter().map(|r| key(&r.account, &r.region)).collect())
            .unwrap_or_default();
        let inst: Vec<&Instance> = s.instances.iter().filter(|(k, _)| ids.contains(*k)).map(|(_, i)| i).collect();
        let drifted = inst.iter().filter(|i| i.drift_status.as_deref() == Some("DRIFTED")).count() as i32;
        let in_sync = inst.iter().filter(|i| i.drift_status.as_deref() == Some("IN_SYNC")).count() as i32;
        let failed = inst.iter().filter(|i| i.detailed == "FAILED").count() as i32;
        types::StackSetDriftDetectionDetails {
            drift_status: Some(
                if drifted > 0 {
                    "DRIFTED"
                } else if in_sync > 0 {
                    "IN_SYNC"
                } else {
                    "NOT_CHECKED"
                }
                .into(),
            ),
            drift_detection_status: Some(
                if failed > 0 && failed as usize == inst.len() {
                    "FAILED"
                } else if failed > 0 {
                    "PARTIAL_SUCCESS"
                } else {
                    "COMPLETED"
                }
                .into(),
            ),
            last_drift_check_timestamp: Some(Utc::now()),
            total_stack_instances_count: Some(inst.len() as i32),
            drifted_stack_instances_count: Some(drifted),
            in_sync_stack_instances_count: Some(in_sync),
            in_progress_stack_instances_count: Some(0),
            failed_stack_instances_count: Some(failed),
        }
    }

    /// Wait until a stack is no longer in progress.
    pub(crate) async fn wait_stack(&self, id: &str) -> crate::state::Stack {
        loop {
            let s = self.state().stacks.get(id).cloned();
            match s {
                Some(s) if !s.status.ends_with("_IN_PROGRESS") => return s,
                None => return crate::state::Stack { status: "DELETE_COMPLETE".into(), ..Default::default() },
                _ => tokio::time::sleep(Duration::from_millis(25)).await,
            }
        }
    }
}

fn a_r(k: String, ou: Option<String>) -> (String, String, Option<String>) {
    let (a, r) = k.split_once('/').unwrap_or((&k, ""));
    (a.to_string(), r.to_string(), ou)
}

fn check_prefs(p: Option<&types::StackSetOperationPreferences>) -> Result<(), ServiceError> {
    let Some(p) = p else { return Ok(()) };
    if p.failure_tolerance_count.is_some() && p.failure_tolerance_percentage.is_some() {
        return Err(validation(
            "You can specify either FailureToleranceCount or FailureTolerancePercentage, but not both",
        ));
    }
    if p.max_concurrent_count.is_some() && p.max_concurrent_percentage.is_some() {
        return Err(validation("You can specify either MaxConcurrentCount or MaxConcurrentPercentage, but not both"));
    }
    if let (Some(f), Some(m)) = (p.failure_tolerance_count, p.max_concurrent_count) {
        if m > f + 1 {
            return Err(validation("MaxConcurrentCount must be at most one more than FailureToleranceCount"));
        }
    }
    Ok(())
}

fn base64_decode(s: &str) -> Option<String> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).ok().and_then(|b| String::from_utf8(b).ok())
}

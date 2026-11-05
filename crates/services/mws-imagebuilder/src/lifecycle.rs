//! Lifecycle policies and resource state updates: deprecating, disabling
//! and deleting old images and their AMIs.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::images::status_of;
use crate::state::LifecycleExecution;
use crate::util::{
    account_of, already_exists, arn, arn_not_found, authorize, filters_match, in_use, invalid_parameter_value,
    not_found, paginate, request_tags, resource_tags, s, slug, Version, VersionPattern,
};
use crate::{ec2link, ImageBuilder};

fn check_policy_fields(
    resource_type: &str,
    status: &Option<String>,
    details: &[t::LifecyclePolicyDetail],
    selection: &t::LifecyclePolicyResourceSelection,
) -> Result<(), ServiceError> {
    let bad = |p: &str, why: String| {
        invalid_parameter_value(format!("The value supplied for parameter '{p}' is not valid. {why}"))
    };
    if !matches!(resource_type, "AMI_IMAGE" | "CONTAINER_IMAGE") {
        return Err(bad("resourceType", format!("'{resource_type}' is not a resource type.")));
    }
    if let Some(st) = status {
        if !matches!(st.as_str(), "ENABLED" | "DISABLED") {
            return Err(bad("status", format!("'{st}' is not a status.")));
        }
    }
    if details.is_empty() || details.len() > 3 {
        return Err(bad("policyDetails", "Specify one to three policy details.".into()));
    }
    for d in details {
        if !matches!(d.action.r#type.as_str(), "DELETE" | "DEPRECATE" | "DISABLE") {
            return Err(bad("policyDetails.action.type", format!("'{}' is not an action.", d.action.r#type)));
        }
        if resource_type == "CONTAINER_IMAGE" && d.action.r#type != "DELETE" {
            return Err(bad("policyDetails.action.type", "Container images can only be deleted.".into()));
        }
        match d.filter.r#type.as_str() {
            "COUNT" => {}
            "AGE" => {
                let unit = d.filter.unit.as_deref().unwrap_or_default();
                if !matches!(unit, "DAYS" | "WEEKS" | "MONTHS" | "YEARS") {
                    return Err(bad(
                        "policyDetails.filter.unit",
                        "AGE filters need a unit of DAYS, WEEKS, MONTHS or YEARS.".into(),
                    ));
                }
            }
            other => return Err(bad("policyDetails.filter.type", format!("'{other}' is not a filter type."))),
        }
        if d.filter.value < 1 {
            return Err(bad("policyDetails.filter.value", "The value must be at least 1.".into()));
        }
    }
    let has_recipes = selection.recipes.as_ref().is_some_and(|r| !r.is_empty());
    let has_tags = selection.tag_map.as_ref().is_some_and(|t| !t.is_empty());
    if has_recipes == has_tags {
        return Err(bad("resourceSelection", "Specify either recipes or tagMap.".into()));
    }
    for r in selection.recipes.iter().flatten() {
        if VersionPattern::parse(&r.semantic_version).is_none() {
            return Err(bad(
                "resourceSelection.recipes.semanticVersion",
                format!("'{}' is not a version.", r.semantic_version),
            ));
        }
    }
    Ok(())
}

fn age_days(unit: &str, value: i32) -> i64 {
    let v = value as i64;
    match unit {
        "WEEKS" => v * 7,
        "MONTHS" => v * 30,
        "YEARS" => v * 365,
        _ => v,
    }
}

fn severity(action: &str) -> u8 {
    match action {
        "DELETE" => 3,
        "DISABLE" => 2,
        _ => 1,
    }
}

impl ImageBuilder {
    fn role_arn(ctx: &RequestContext, role: &str) -> String {
        if role.starts_with("arn:") {
            role.to_string()
        } else {
            format!("arn:{}:iam::{}:role/{role}", ctx.partition, account_of(ctx))
        }
    }

    pub(crate) async fn create_lifecycle_policy_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateLifecyclePolicyRequest,
    ) -> Result<t::CreateLifecyclePolicyResponse, ServiceError> {
        let target = arn(ctx, &account_of(ctx), &format!("lifecycle-policy/{}", slug(&input.name)));
        authorize(ctx, "CreateLifecyclePolicy", &target, request_tags(&input.tags))?;
        if input.dry_run {
            return Err(crate::util::dry_run_ok());
        }
        let token = input.client_token.clone();
        self.idempotent(ctx, "CreateLifecyclePolicy", &token, &input.clone(), async {
            check_policy_fields(&input.resource_type, &input.status, &input.policy_details, &input.resource_selection)?;
            self.pass_execution_role(ctx, &Some(input.execution_role.clone()))?;
            let policy = t::LifecyclePolicy {
                arn: Some(target.clone()),
                name: Some(input.name.clone()),
                description: input.description.clone(),
                status: Some(input.status.clone().unwrap_or_else(|| "ENABLED".into())),
                execution_role: Some(Self::role_arn(ctx, &input.execution_role)),
                resource_type: Some(input.resource_type.clone()),
                policy_details: Some(input.policy_details.clone()),
                resource_selection: Some(input.resource_selection.clone()),
                date_created: Some(ctx.received_at),
                date_updated: None,
                date_last_run: None,
                tags: Some(input.tags.clone().unwrap_or_default()),
            };
            self.with_region(ctx, |r| {
                if r.lifecycle_policies.contains_key(&target) {
                    return Err(already_exists(&target));
                }
                r.lifecycle_policies.insert(target.clone(), policy);
                Ok(())
            })?;
            Ok(t::CreateLifecyclePolicyResponse {
                client_token: Some(token.clone()),
                lifecycle_policy_arn: Some(target.clone()),
            })
        })
        .await
    }

    pub(crate) async fn update_lifecycle_policy_op(
        &self,
        ctx: &RequestContext,
        input: t::UpdateLifecyclePolicyRequest,
    ) -> Result<t::UpdateLifecyclePolicyResponse, ServiceError> {
        let target = input.lifecycle_policy_arn.clone();
        let existing = self.with_region(ctx, |r| r.lifecycle_policies.get(&target).cloned());
        authorize(
            ctx,
            "UpdateLifecyclePolicy",
            &target,
            resource_tags(&existing.as_ref().and_then(|p| p.tags.clone())),
        )?;
        let token = input.client_token.clone();
        self.idempotent(ctx, "UpdateLifecyclePolicy", &token, &input.clone(), async {
            let existing = existing.clone().ok_or_else(|| arn_not_found(&target))?;
            check_policy_fields(&input.resource_type, &input.status, &input.policy_details, &input.resource_selection)?;
            self.pass_execution_role(ctx, &Some(input.execution_role.clone()))?;
            let updated = t::LifecyclePolicy {
                description: input.description.clone(),
                status: Some(input.status.clone().unwrap_or_else(|| "ENABLED".into())),
                execution_role: Some(Self::role_arn(ctx, &input.execution_role)),
                resource_type: Some(input.resource_type.clone()),
                policy_details: Some(input.policy_details.clone()),
                resource_selection: Some(input.resource_selection.clone()),
                date_updated: Some(ctx.received_at),
                ..existing
            };
            self.with_region(ctx, |r| r.lifecycle_policies.insert(target.clone(), updated));
            Ok(t::UpdateLifecyclePolicyResponse { lifecycle_policy_arn: Some(target.clone()) })
        })
        .await
    }

    pub(crate) fn get_lifecycle_policy_op(
        &self,
        ctx: &RequestContext,
        input: t::GetLifecyclePolicyRequest,
    ) -> Result<t::GetLifecyclePolicyResponse, ServiceError> {
        let target = input.lifecycle_policy_arn.clone();
        let found = self.with_region(ctx, |r| r.lifecycle_policies.get(&target).cloned());
        authorize(ctx, "GetLifecyclePolicy", &target, resource_tags(&found.as_ref().and_then(|p| p.tags.clone())))?;
        Ok(t::GetLifecyclePolicyResponse { lifecycle_policy: Some(found.ok_or_else(|| arn_not_found(&target))?) })
    }

    pub(crate) fn list_lifecycle_policies_op(
        &self,
        ctx: &RequestContext,
        input: t::ListLifecyclePoliciesRequest,
    ) -> Result<t::ListLifecyclePoliciesResponse, ServiceError> {
        authorize(
            ctx,
            "ListLifecyclePolicies",
            &arn(ctx, &account_of(ctx), "lifecycle-policy/*"),
            ConditionContext::new(),
        )?;
        let all: Vec<t::LifecyclePolicy> = self.with_region(ctx, |r| r.lifecycle_policies.values().cloned().collect());
        let mut out = Vec::new();
        for p in all {
            if filters_match(&input.filters, &["name", "resourceType", "status"], |n| match n {
                "name" => s(&p.name),
                "resourceType" => s(&p.resource_type),
                _ => s(&p.status),
            })? {
                out.push(t::LifecyclePolicySummary {
                    arn: p.arn,
                    name: p.name,
                    description: p.description,
                    status: p.status,
                    execution_role: p.execution_role,
                    resource_type: p.resource_type,
                    date_created: p.date_created,
                    date_updated: p.date_updated,
                    date_last_run: p.date_last_run,
                    tags: p.tags,
                });
            }
        }
        let (page, next_token) = paginate(out, input.max_results, &input.next_token)?;
        Ok(t::ListLifecyclePoliciesResponse { lifecycle_policy_summary_list: Some(page), next_token })
    }

    pub(crate) fn delete_lifecycle_policy_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteLifecyclePolicyRequest,
    ) -> Result<t::DeleteLifecyclePolicyResponse, ServiceError> {
        let target = input.lifecycle_policy_arn.clone();
        let found = self.with_region(ctx, |r| r.lifecycle_policies.get(&target).map(|p| p.tags.clone()));
        authorize(ctx, "DeleteLifecyclePolicy", &target, resource_tags(&found.clone().flatten()))?;
        if found.is_none() {
            return Err(arn_not_found(&target));
        }
        self.with_region(ctx, |r| r.lifecycle_policies.remove(&target));
        Ok(t::DeleteLifecyclePolicyResponse { lifecycle_policy_arn: Some(target) })
    }

    pub(crate) fn get_lifecycle_execution_op(
        &self,
        ctx: &RequestContext,
        input: t::GetLifecycleExecutionRequest,
    ) -> Result<t::GetLifecycleExecutionResponse, ServiceError> {
        authorize(ctx, "GetLifecycleExecution", "*", ConditionContext::new())?;
        let id = input.lifecycle_execution_id.clone();
        let e = self
            .with_region(ctx, |r| r.lifecycle_executions.get(&id).cloned())
            .ok_or_else(|| not_found(format!("The lifecycle execution '{id}' does not exist.")))?;
        Ok(t::GetLifecycleExecutionResponse { lifecycle_execution: Some(e.execution) })
    }

    pub(crate) fn list_lifecycle_executions_op(
        &self,
        ctx: &RequestContext,
        input: t::ListLifecycleExecutionsRequest,
    ) -> Result<t::ListLifecycleExecutionsResponse, ServiceError> {
        authorize(ctx, "ListLifecycleExecutions", &input.resource_arn, ConditionContext::new())?;
        let mut list: Vec<LifecycleExecution> = self.with_region(ctx, |r| {
            r.lifecycle_executions.values().filter(|e| e.resource_arn == input.resource_arn).cloned().collect()
        });
        list.sort_by_key(|e| std::cmp::Reverse(e.execution.start_time));
        let (page, next_token) =
            paginate(list.into_iter().map(|e| e.execution).collect(), input.max_results, &input.next_token)?;
        Ok(t::ListLifecycleExecutionsResponse { lifecycle_executions: Some(page), next_token })
    }

    pub(crate) fn list_lifecycle_execution_resources_op(
        &self,
        ctx: &RequestContext,
        input: t::ListLifecycleExecutionResourcesRequest,
    ) -> Result<t::ListLifecycleExecutionResourcesResponse, ServiceError> {
        authorize(ctx, "ListLifecycleExecutionResources", "*", ConditionContext::new())?;
        let id = input.lifecycle_execution_id.clone();
        let e = self
            .with_region(ctx, |r| r.lifecycle_executions.get(&id).cloned())
            .ok_or_else(|| not_found(format!("The lifecycle execution '{id}' does not exist.")))?;
        let resources: Vec<t::LifecycleExecutionResource> = e
            .resources
            .into_iter()
            .filter(|r| input.parent_resource_id.is_none() || r.resource_id == input.parent_resource_id)
            .collect();
        let (page, next_token) = paginate(resources, input.max_results, &input.next_token)?;
        Ok(t::ListLifecycleExecutionResourcesResponse {
            lifecycle_execution_id: Some(id),
            lifecycle_execution_state: e.execution.state,
            resources: Some(page),
            next_token,
        })
    }

    pub(crate) async fn cancel_lifecycle_execution_op(
        &self,
        ctx: &RequestContext,
        input: t::CancelLifecycleExecutionRequest,
    ) -> Result<t::CancelLifecycleExecutionResponse, ServiceError> {
        authorize(ctx, "CancelLifecycleExecution", "*", ConditionContext::new())?;
        let id = input.lifecycle_execution_id.clone();
        let token = input.client_token.clone();
        self.idempotent(ctx, "CancelLifecycleExecution", &token, &input.clone(), async {
            self.with_region(ctx, |r| {
                let e = r
                    .lifecycle_executions
                    .get_mut(&id)
                    .ok_or_else(|| not_found(format!("The lifecycle execution '{id}' does not exist.")))?;
                let status = e.execution.state.as_ref().and_then(|s| s.status.clone()).unwrap_or_default();
                if status != "IN_PROGRESS" {
                    return Err(in_use(format!(
                        "The lifecycle execution '{id}' cannot be cancelled because its status is {status}."
                    )));
                }
                e.execution.state = Some(t::LifecycleExecutionState {
                    status: Some("CANCELLED".into()),
                    reason: Some("Cancelled by the user.".into()),
                });
                e.execution.end_time = Some(ctx.received_at);
                Ok(())
            })?;
            Ok(t::CancelLifecycleExecutionResponse { lifecycle_execution_id: Some(id.clone()) })
        })
        .await
    }

    pub(crate) async fn start_resource_state_update_op(
        &self,
        ctx: &RequestContext,
        input: t::StartResourceStateUpdateRequest,
    ) -> Result<t::StartResourceStateUpdateResponse, ServiceError> {
        let target = input.resource_arn.clone();
        authorize(ctx, "StartResourceStateUpdate", &target, ConditionContext::new())?;
        let token = input.client_token.clone();
        self.idempotent(ctx, "StartResourceStateUpdate", &token, &input.clone(), async {
            let status = input.state.status.clone().unwrap_or_default();
            if !matches!(status.as_str(), "AVAILABLE" | "DELETED" | "DEPRECATED" | "DISABLED") {
                return Err(invalid_parameter_value(format!(
                    "The value supplied for parameter 'state' is not valid: '{status}'."
                )));
            }
            self.pass_execution_role(ctx, &input.execution_role)?;
            let rec =
                self.with_region(ctx, |r| r.images.get(&target).cloned()).ok_or_else(|| arn_not_found(&target))?;
            let current = status_of(&rec.image).to_string();
            if crate::images::ACTIVE_STATES.contains(&current.as_str()) {
                return Err(in_use(format!("The image '{target}' is still being built.")));
            }
            let include = input.include_resources.clone().unwrap_or(t::ResourceStateUpdateIncludeResources {
                amis: true,
                snapshots: true,
                containers: false,
            });
            let id = format!("lce-{}", uuid::Uuid::new_v4());
            let excluded = input
                .exclusion_rules
                .as_ref()
                .and_then(|e| e.amis.as_ref())
                .is_some_and(|rules| amis_excluded(&rec.image, rules));
            let action = match status.as_str() {
                "DELETED" => "DELETE",
                "DEPRECATED" => "DEPRECATE",
                "DISABLED" => "DISABLE",
                _ => "AVAILABLE",
            };
            let resources = if excluded {
                Vec::new()
            } else {
                self.apply_action(ctx, &target, action, include.amis, include.snapshots).await
            };
            self.record_execution(ctx, &id, &target, None, resources);
            Ok(t::StartResourceStateUpdateResponse {
                lifecycle_execution_id: Some(id.clone()),
                resource_arn: Some(target.clone()),
            })
        })
        .await
    }

    fn record_execution(
        &self,
        ctx: &RequestContext,
        id: &str,
        resource_arn: &str,
        policy_arn: Option<String>,
        resources: Vec<t::LifecycleExecutionResource>,
    ) {
        let now = self.now().max(ctx.received_at);
        self.with_region(ctx, |r| {
            r.lifecycle_executions.insert(
                id.to_string(),
                LifecycleExecution {
                    execution: t::LifecycleExecution {
                        lifecycle_execution_id: Some(id.to_string()),
                        lifecycle_policy_arn: policy_arn,
                        resources_impacted_summary: Some(t::LifecycleExecutionResourcesImpactedSummary {
                            has_impacted_resources: !resources.is_empty(),
                        }),
                        state: Some(t::LifecycleExecutionState { status: Some("SUCCESS".into()), reason: None }),
                        start_time: Some(now),
                        end_time: Some(now),
                    },
                    resource_arn: resource_arn.to_string(),
                    resources,
                },
            );
            if let Some(rec) = r.images.get_mut(resource_arn) {
                rec.image.lifecycle_execution_id = Some(id.to_string());
            }
        });
    }

    /// Apply a lifecycle action to an image and its AMIs; returns the
    /// resources it touched.
    async fn apply_action(
        &self,
        ctx: &RequestContext,
        image_arn: &str,
        action: &str,
        amis: bool,
        snapshots: bool,
    ) -> Vec<t::LifecycleExecutionResource> {
        let account = account_of(ctx);
        let Some(rec) = self.with_region(ctx, |r| r.images.get(image_arn).cloned()) else { return Vec::new() };
        let now = self.now().max(ctx.received_at);
        let mut out = Vec::new();
        let outputs = rec.image.output_resources.as_ref().and_then(|o| o.amis.clone()).unwrap_or_default();
        for ami in outputs {
            let (Some(id), Some(region)) = (ami.image.clone(), ami.region.clone()) else { continue };
            let mut state = "SUCCESS";
            let mut reason = None;
            if action == "DELETE" && amis {
                if let Some(ec2) = self.ec2() {
                    let owner = ami.account_id.clone().unwrap_or_else(|| account.clone());
                    let sctx = self.service_ctx(ctx, &owner, &region);
                    if let Err(e) = ec2link::deregister(ec2, &sctx, &id).await {
                        state = "FAILED";
                        reason = Some(e.message);
                    }
                }
            }
            out.push(t::LifecycleExecutionResource {
                account_id: ami.account_id.clone(),
                resource_id: Some(id),
                state: Some(t::LifecycleExecutionResourceState { status: Some(state.into()), reason }),
                action: Some(t::LifecycleExecutionResourceAction { name: Some(action.into()), reason: None }),
                region: Some(region),
                snapshots: (action == "DELETE" && snapshots).then(Vec::new),
                image_uris: None,
                start_time: Some(now),
                end_time: Some(now),
            });
        }
        let new_status = match action {
            "DELETE" => "DELETED",
            "DEPRECATE" => "DEPRECATED",
            "DISABLE" => "DISABLED",
            _ => "AVAILABLE",
        };
        let previous = self.with_region(ctx, |r| {
            let rec = r.images.get_mut(image_arn)?;
            let prev = status_of(&rec.image).to_string();
            rec.image.state = Some(t::ImageState { status: Some(new_status.into()), ..Default::default() });
            rec.image.deprecation_time = (new_status == "DEPRECATED").then_some(now).or(rec.image.deprecation_time);
            Some(prev)
        });
        if let Some(prev) = previous {
            if prev != new_status {
                self.emit_state_change(ctx, &account, &ctx.region, image_arn, Some(prev), new_status, None);
            }
        }
        out
    }

    /// Run lifecycle policies that are due (each runs once a day on the
    /// emulated clock).
    pub(crate) async fn run_lifecycle_policies(&self, template: &RequestContext) {
        let now = self.now();
        let due: Vec<(String, String, t::LifecyclePolicy)> = {
            let st = self.lock();
            st.regions
                .iter()
                .flat_map(|(key, r)| {
                    let (account, region) = key.split_once('/').unwrap_or_default();
                    r.lifecycle_policies
                        .values()
                        .filter(|p| p.status.as_deref() == Some("ENABLED"))
                        .filter(|p| {
                            let last = p.date_last_run.or(p.date_created).unwrap_or(now);
                            now - last >= chrono::Duration::days(1)
                        })
                        .map(|p| (account.to_string(), region.to_string(), p.clone()))
                        .collect::<Vec<_>>()
                })
                .collect()
        };
        for (account, region, policy) in due {
            let ctx = self.service_ctx(template, &account, &region);
            self.run_policy(&ctx, &policy, now).await;
        }
    }

    async fn run_policy(&self, ctx: &RequestContext, policy: &t::LifecyclePolicy, now: chrono::DateTime<chrono::Utc>) {
        let policy_arn = policy.arn.clone().unwrap_or_default();
        let selection = policy.resource_selection.clone().unwrap_or_default();
        let want_type = if policy.resource_type.as_deref() == Some("CONTAINER_IMAGE") { "DOCKER" } else { "AMI" };
        let images: Vec<t::Image> = self.with_region(ctx, |r| {
            r.images
                .values()
                .map(|i| i.image.clone())
                .filter(|i| i.r#type.as_deref() == Some(want_type))
                .filter(|i| matches!(status_of(i), "AVAILABLE" | "DEPRECATED" | "DISABLED"))
                .filter(|i| {
                    let by_recipe = selection.recipes.iter().flatten().any(|r| {
                        let recipe_name = i
                            .image_recipe
                            .as_ref()
                            .and_then(|x| x.name.clone())
                            .or_else(|| i.container_recipe.as_ref().and_then(|x| x.name.clone()));
                        recipe_name.as_deref() == Some(r.name.as_str())
                            && VersionPattern::parse(&r.semantic_version).is_some_and(|p| {
                                i.version.as_deref().and_then(Version::parse).is_some_and(|v| p.matches(v))
                            })
                    });
                    let by_tags = selection.tag_map.as_ref().is_some_and(|m| {
                        !m.is_empty() && m.iter().all(|(k, v)| i.tags.as_ref().and_then(|t| t.get(k)) == Some(v))
                    });
                    by_recipe || by_tags
                })
                .collect()
        });
        // Decide each image's action: the most severe detail that matches.
        let mut decided: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
        let mut include = std::collections::BTreeMap::new();
        for detail in policy.policy_details.iter().flatten() {
            let mut groups: std::collections::BTreeMap<String, Vec<&t::Image>> = std::collections::BTreeMap::new();
            for i in &images {
                groups.entry(i.name.clone().unwrap_or_default()).or_default().push(i);
            }
            for (_, mut group) in groups {
                group.sort_by(|a, b| b.date_created.cmp(&a.date_created));
                let candidates: Vec<&t::Image> = match detail.filter.r#type.as_str() {
                    "COUNT" => group.iter().skip(detail.filter.value.max(0) as usize).copied().collect(),
                    _ => {
                        let keep = detail.filter.retain_at_least.unwrap_or(0).max(0) as usize;
                        let limit = chrono::Duration::days(age_days(
                            detail.filter.unit.as_deref().unwrap_or("DAYS"),
                            detail.filter.value,
                        ));
                        group
                            .iter()
                            .skip(keep)
                            .filter(|i| {
                                i.date_created
                                    .as_deref()
                                    .and_then(|d| chrono::DateTime::parse_from_rfc3339(d).ok())
                                    .is_some_and(|d| now - d.with_timezone(&chrono::Utc) > limit)
                            })
                            .copied()
                            .collect()
                    }
                };
                for i in candidates {
                    let excluded = detail.exclusion_rules.as_ref().is_some_and(|rules| {
                        rules.tag_map.as_ref().is_some_and(|m| {
                            !m.is_empty() && m.iter().all(|(k, v)| i.tags.as_ref().and_then(|t| t.get(k)) == Some(v))
                        }) || rules.amis.as_ref().is_some_and(|a| amis_excluded(i, a))
                    });
                    if excluded {
                        continue;
                    }
                    let arn = i.arn.clone().unwrap_or_default();
                    let action = detail.action.r#type.clone();
                    if decided.get(&arn).is_none_or(|prev| severity(prev) < severity(&action)) {
                        decided.insert(arn.clone(), action);
                        let inc = detail.action.include_resources.clone();
                        include.insert(
                            arn,
                            (inc.as_ref().is_none_or(|x| x.amis), inc.as_ref().is_none_or(|x| x.snapshots)),
                        );
                    }
                }
            }
        }
        let mut resources = Vec::new();
        for (arn, action) in &decided {
            let (amis, snaps) = include.get(arn).copied().unwrap_or((true, true));
            let current = self.with_region(ctx, |r| r.images.get(arn).map(|i| status_of(&i.image).to_string()));
            let already = matches!(
                (action.as_str(), current.as_deref()),
                ("DEPRECATE", Some("DEPRECATED")) | ("DISABLE", Some("DISABLED"))
            );
            if already {
                continue;
            }
            resources.extend(self.apply_action(ctx, arn, action, amis, snaps).await);
        }
        let id = format!("lce-{}", uuid::Uuid::new_v4());
        self.record_execution(ctx, &id, &policy_arn, Some(policy_arn.clone()), resources);
        self.with_region(ctx, |r| {
            if let Some(p) = r.lifecycle_policies.get_mut(&policy_arn) {
                p.date_last_run = Some(now);
            }
        });
    }
}

/// Whether AMI exclusion rules keep an image's AMIs.
fn amis_excluded(i: &t::Image, rules: &t::LifecyclePolicyDetailExclusionRulesAmis) -> bool {
    let amis = i.output_resources.as_ref().and_then(|o| o.amis.clone()).unwrap_or_default();
    if let Some(regions) = &rules.regions {
        if amis.iter().any(|a| a.region.as_ref().is_some_and(|r| regions.contains(r))) {
            return true;
        }
    }
    if let Some(accounts) = &rules.shared_accounts {
        if amis.iter().any(|a| a.account_id.as_ref().is_some_and(|x| accounts.contains(x))) {
            return true;
        }
    }
    false
}

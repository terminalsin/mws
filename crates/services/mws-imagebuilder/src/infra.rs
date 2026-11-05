//! Infrastructure configurations: where and how builds run.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::util::{
    account_of, already_exists, arn, arn_not_found, authorize, dependency, filters_match, invalid_parameter_value, now,
    paginate, request_tags, resource_tags, s, slug,
};
use crate::{ec2link, ImageBuilder};

/// The fields create and update share.
pub struct InfraFields<'a> {
    pub instance_types: &'a Option<Vec<String>>,
    pub instance_profile_name: &'a str,
    pub security_group_ids: &'a Option<Vec<String>>,
    pub subnet_id: &'a Option<String>,
    pub key_pair: &'a Option<String>,
    pub sns_topic_arn: &'a Option<String>,
    pub instance_metadata_options: &'a Option<t::InstanceMetadataOptions>,
}

impl ImageBuilder {
    /// Check what an infrastructure configuration refers to: the instance
    /// profile (and `iam:PassRole` on its role), subnet, security groups
    /// and key pair.
    async fn check_infra(&self, ctx: &RequestContext, f: &InfraFields<'_>) -> Result<(), ServiceError> {
        let bad = |param: &str, why: String| {
            invalid_parameter_value(format!("The value supplied for parameter '{param}' is not valid. {why}"))
        };
        let account = account_of(ctx);
        let Some(ec2) = self.ec2() else { return Ok(()) };
        if ec2.knows_instance_profiles() {
            let profile = ec2.instance_profile(&account, f.instance_profile_name).ok_or_else(|| {
                bad(
                    "instanceProfileName",
                    format!("The instance profile '{}' does not exist.", f.instance_profile_name),
                )
            })?;
            if let Some(role) = &profile.role_arn {
                let mut c = ConditionContext::new();
                c.insert("iam:PassedToService".into(), vec!["ec2.amazonaws.com".into()]);
                ctx.authorize("iam:PassRole", role, c)?;
            }
        }
        if f.instance_types.as_ref().is_some_and(|t| t.is_empty()) {
            return Err(bad("instanceTypes", "Specify at least one instance type.".into()));
        }
        let sctx = self.service_ctx(ctx, &account, &ctx.region);
        if let Some(subnet) = f.subnet_id {
            if !ec2link::subnet_exists(ec2, &sctx, subnet).await {
                return Err(bad("subnetId", format!("The subnet ID '{subnet}' does not exist.")));
            }
        }
        if let Some(sgs) = f.security_group_ids {
            if f.subnet_id.is_none() && !sgs.is_empty() {
                return Err(crate::util::invalid_combination(
                    "You must specify a subnetId when you specify securityGroupIds.",
                ));
            }
            if !ec2link::security_groups_exist(ec2, &sctx, sgs).await {
                return Err(bad("securityGroupIds", "One or more security groups do not exist.".into()));
            }
        }
        if let Some(key) = f.key_pair {
            if !ec2link::key_pair_exists(ec2, &sctx, key).await {
                return Err(bad("keyPair", format!("The key pair '{key}' does not exist.")));
            }
        }
        if let Some(topic) = f.sns_topic_arn {
            if !topic.starts_with("arn:") || topic.split(':').nth(2) != Some("sns") {
                return Err(bad("snsTopicArn", format!("'{topic}' is not an SNS topic ARN.")));
            }
        }
        if let Some(tokens) = f.instance_metadata_options.as_ref().and_then(|m| m.http_tokens.as_deref()) {
            if !matches!(tokens, "required" | "optional") {
                return Err(bad("instanceMetadataOptions.httpTokens", format!("'{tokens}' is not valid.")));
            }
        }
        Ok(())
    }

    pub(crate) async fn create_infrastructure_configuration_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateInfrastructureConfigurationRequest,
    ) -> Result<t::CreateInfrastructureConfigurationResponse, ServiceError> {
        let account = account_of(ctx);
        let target = arn(ctx, &account, &format!("infrastructure-configuration/{}", slug(&input.name)));
        authorize(ctx, "CreateInfrastructureConfiguration", &target, request_tags(&input.tags))?;
        if input.dry_run {
            return Err(crate::util::dry_run_ok());
        }
        let token = input.client_token.clone();
        self.idempotent(ctx, "CreateInfrastructureConfiguration", &token, &input.clone(), async {
            if self.with_region(ctx, |r| r.infrastructure.contains_key(&target)) {
                return Err(already_exists(&target));
            }
            self.check_infra(
                ctx,
                &InfraFields {
                    instance_types: &input.instance_types,
                    instance_profile_name: &input.instance_profile_name,
                    security_group_ids: &input.security_group_ids,
                    subnet_id: &input.subnet_id,
                    key_pair: &input.key_pair,
                    sns_topic_arn: &input.sns_topic_arn,
                    instance_metadata_options: &input.instance_metadata_options,
                },
            )
            .await?;
            let config = t::InfrastructureConfiguration {
                arn: Some(target.clone()),
                name: Some(input.name.clone()),
                description: input.description.clone(),
                instance_types: input.instance_types.clone(),
                instance_profile_name: Some(input.instance_profile_name.clone()),
                security_group_ids: input.security_group_ids.clone(),
                subnet_id: input.subnet_id.clone(),
                logging: input.logging.clone(),
                key_pair: input.key_pair.clone(),
                terminate_instance_on_failure: Some(input.terminate_instance_on_failure.unwrap_or(true)),
                sns_topic_arn: input.sns_topic_arn.clone(),
                date_created: Some(now(ctx)),
                date_updated: None,
                resource_tags: input.resource_tags.clone(),
                instance_metadata_options: input.instance_metadata_options.clone(),
                tags: Some(input.tags.clone().unwrap_or_default()),
                placement: input.placement.clone(),
                terminate_instance_on_completion: input.terminate_instance_on_completion,
                parent_instance: input.parent_instance.clone(),
            };
            self.with_region(ctx, |r| {
                if r.infrastructure.contains_key(&target) {
                    return Err(already_exists(&target));
                }
                r.infrastructure.insert(target.clone(), config);
                Ok(())
            })?;
            Ok(t::CreateInfrastructureConfigurationResponse {
                request_id: Some(ctx.request_id.clone()),
                client_token: Some(token.clone()),
                infrastructure_configuration_arn: Some(target.clone()),
            })
        })
        .await
    }

    pub(crate) async fn update_infrastructure_configuration_op(
        &self,
        ctx: &RequestContext,
        input: t::UpdateInfrastructureConfigurationRequest,
    ) -> Result<t::UpdateInfrastructureConfigurationResponse, ServiceError> {
        let target = input.infrastructure_configuration_arn.clone();
        let existing = self.with_region(ctx, |r| r.infrastructure.get(&target).cloned());
        authorize(
            ctx,
            "UpdateInfrastructureConfiguration",
            &target,
            resource_tags(&existing.as_ref().and_then(|e| e.tags.clone())),
        )?;
        let token = input.client_token.clone();
        self.idempotent(ctx, "UpdateInfrastructureConfiguration", &token, &input.clone(), async {
            let existing = existing.clone().ok_or_else(|| arn_not_found(&target))?;
            self.check_infra(
                ctx,
                &InfraFields {
                    instance_types: &input.instance_types,
                    instance_profile_name: &input.instance_profile_name,
                    security_group_ids: &input.security_group_ids,
                    subnet_id: &input.subnet_id,
                    key_pair: &input.key_pair,
                    sns_topic_arn: &input.sns_topic_arn,
                    instance_metadata_options: &input.instance_metadata_options,
                },
            )
            .await?;
            let updated = t::InfrastructureConfiguration {
                description: input.description.clone(),
                instance_types: input.instance_types.clone(),
                instance_profile_name: Some(input.instance_profile_name.clone()),
                security_group_ids: input.security_group_ids.clone(),
                subnet_id: input.subnet_id.clone(),
                logging: input.logging.clone(),
                key_pair: input.key_pair.clone(),
                terminate_instance_on_failure: Some(input.terminate_instance_on_failure.unwrap_or(true)),
                sns_topic_arn: input.sns_topic_arn.clone(),
                date_updated: Some(now(ctx)),
                resource_tags: input.resource_tags.clone(),
                instance_metadata_options: input.instance_metadata_options.clone(),
                placement: input.placement.clone(),
                terminate_instance_on_completion: input.terminate_instance_on_completion,
                parent_instance: input.parent_instance.clone(),
                ..existing
            };
            self.with_region(ctx, |r| r.infrastructure.insert(target.clone(), updated));
            Ok(t::UpdateInfrastructureConfigurationResponse {
                request_id: Some(ctx.request_id.clone()),
                client_token: Some(token.clone()),
                infrastructure_configuration_arn: Some(target.clone()),
            })
        })
        .await
    }

    pub(crate) fn get_infrastructure_configuration_op(
        &self,
        ctx: &RequestContext,
        input: t::GetInfrastructureConfigurationRequest,
    ) -> Result<t::GetInfrastructureConfigurationResponse, ServiceError> {
        let target = input.infrastructure_configuration_arn.clone();
        let found = self.with_region(ctx, |r| r.infrastructure.get(&target).cloned());
        authorize(
            ctx,
            "GetInfrastructureConfiguration",
            &target,
            resource_tags(&found.as_ref().and_then(|e| e.tags.clone())),
        )?;
        let config = found.ok_or_else(|| arn_not_found(&target))?;
        Ok(t::GetInfrastructureConfigurationResponse {
            request_id: Some(ctx.request_id.clone()),
            infrastructure_configuration: Some(config),
        })
    }

    pub(crate) fn list_infrastructure_configurations_op(
        &self,
        ctx: &RequestContext,
        input: t::ListInfrastructureConfigurationsRequest,
    ) -> Result<t::ListInfrastructureConfigurationsResponse, ServiceError> {
        authorize(
            ctx,
            "ListInfrastructureConfigurations",
            &arn(ctx, &account_of(ctx), "infrastructure-configuration/*"),
            ConditionContext::new(),
        )?;
        let all: Vec<t::InfrastructureConfiguration> =
            self.with_region(ctx, |r| r.infrastructure.values().cloned().collect());
        let mut out = Vec::new();
        for c in all {
            if filters_match(&input.filters, &["name"], |_| s(&c.name))? {
                out.push(t::InfrastructureConfigurationSummary {
                    arn: c.arn,
                    name: c.name,
                    description: c.description,
                    date_created: c.date_created,
                    date_updated: c.date_updated,
                    resource_tags: c.resource_tags,
                    tags: c.tags,
                    instance_types: c.instance_types,
                    instance_profile_name: c.instance_profile_name,
                    placement: c.placement,
                });
            }
        }
        let (page, next_token) = paginate(out, input.max_results, &input.next_token)?;
        Ok(t::ListInfrastructureConfigurationsResponse {
            request_id: Some(ctx.request_id.clone()),
            infrastructure_configuration_summary_list: Some(page),
            next_token,
        })
    }

    pub(crate) fn delete_infrastructure_configuration_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteInfrastructureConfigurationRequest,
    ) -> Result<t::DeleteInfrastructureConfigurationResponse, ServiceError> {
        let target = input.infrastructure_configuration_arn.clone();
        let found = self.with_region(ctx, |r| r.infrastructure.get(&target).map(|c| c.tags.clone()));
        authorize(ctx, "DeleteInfrastructureConfiguration", &target, resource_tags(&found.clone().flatten()))?;
        if found.is_none() {
            return Err(arn_not_found(&target));
        }
        let users: Vec<String> = self.with_region(ctx, |r| {
            r.pipelines
                .iter()
                .filter(|(_, p)| p.pipeline.infrastructure_configuration_arn.as_deref() == Some(target.as_str()))
                .map(|(k, _)| k.clone())
                .collect()
        });
        if !users.is_empty() {
            return Err(dependency(format!(
                "Resource dependency error: The resource ARN '{target}' has the following dependencies: {}.",
                users.join(", ")
            )));
        }
        self.with_region(ctx, |r| r.infrastructure.remove(&target));
        Ok(t::DeleteInfrastructureConfigurationResponse {
            request_id: Some(ctx.request_id.clone()),
            infrastructure_configuration_arn: Some(target),
        })
    }
}

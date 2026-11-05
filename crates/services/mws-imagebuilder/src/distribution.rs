//! Distribution configurations: where output AMIs go.

use std::collections::BTreeSet;

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::util::{
    account_of, already_exists, arn, arn_not_found, authorize, dependency, filters_match, invalid_parameter_value, now,
    paginate, request_tags, resource_tags, s, slug,
};
use crate::ImageBuilder;

fn check_distributions(distributions: &[t::Distribution]) -> Result<(), ServiceError> {
    let bad = |why: String| {
        invalid_parameter_value(format!("The value supplied for parameter 'distributions' is not valid. {why}"))
    };
    if distributions.is_empty() {
        return Err(bad("Specify at least one distribution.".into()));
    }
    let mut regions = BTreeSet::new();
    for d in distributions {
        let valid_region = d.region.split('-').count() >= 3
            && d.region.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
        if !valid_region {
            return Err(bad(format!("'{}' is not a valid Region.", d.region)));
        }
        if !regions.insert(d.region.clone()) {
            return Err(bad(format!("The Region '{}' is specified more than once.", d.region)));
        }
        if let Some(ami) = &d.ami_distribution_configuration {
            for a in ami.target_account_ids.iter().flatten() {
                if a.len() != 12 || !a.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(bad(format!("'{a}' is not a valid account ID.")));
                }
            }
            if let Some(name) = &ami.name {
                let rendered = render_ami_name(name, "2025-01-01T00-00-00.000Z", 1);
                let ok = (3..=128).contains(&rendered.chars().count())
                    && rendered.chars().all(|c| c.is_ascii_alphanumeric() || "()[] ./-'@_".contains(c));
                if !ok {
                    return Err(bad(format!(
                        "The AMI name '{name}' is not valid. AMI names must be between 3 and 128 characters long, and may contain letters, numbers, '(', ')', '.', '-', '/' and '_'."
                    )));
                }
            }
        }
        for p in d.ssm_parameter_configurations.iter().flatten() {
            if p.parameter_name.is_empty() {
                return Err(bad("An SSM parameter name is empty.".into()));
            }
            if let Some(dt) = &p.data_type {
                if !matches!(dt.as_str(), "text" | "aws:ec2:image") {
                    return Err(bad(format!("The SSM parameter data type '{dt}' is not valid.")));
                }
            }
        }
    }
    Ok(())
}

/// Fill in an AMI name's `{{ imagebuilder:buildDate }}` and
/// `{{ imagebuilder:buildVersion }}` placeholders.
pub fn render_ami_name(name: &str, build_date: &str, build_version: u32) -> String {
    let mut vars = std::collections::BTreeMap::new();
    vars.insert("imagebuilder:buildDate".to_string(), build_date.to_string());
    vars.insert("imagebuilder:buildVersion".to_string(), build_version.to_string());
    crate::toe::replace_vars(name, &vars)
}

impl ImageBuilder {
    pub(crate) async fn create_distribution_configuration_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateDistributionConfigurationRequest,
    ) -> Result<t::CreateDistributionConfigurationResponse, ServiceError> {
        let account = account_of(ctx);
        let target = arn(ctx, &account, &format!("distribution-configuration/{}", slug(&input.name)));
        authorize(ctx, "CreateDistributionConfiguration", &target, request_tags(&input.tags))?;
        if input.dry_run {
            return Err(crate::util::dry_run_ok());
        }
        let token = input.client_token.clone();
        self.idempotent(ctx, "CreateDistributionConfiguration", &token, &input.clone(), async {
            check_distributions(&input.distributions)?;
            let config = t::DistributionConfiguration {
                arn: Some(target.clone()),
                name: Some(input.name.clone()),
                description: input.description.clone(),
                distributions: Some(input.distributions.clone()),
                timeout_minutes: 720,
                date_created: Some(now(ctx)),
                date_updated: None,
                tags: Some(input.tags.clone().unwrap_or_default()),
            };
            self.with_region(ctx, |r| {
                if r.distributions.contains_key(&target) {
                    return Err(already_exists(&target));
                }
                r.distributions.insert(target.clone(), config);
                Ok(())
            })?;
            Ok(t::CreateDistributionConfigurationResponse {
                request_id: Some(ctx.request_id.clone()),
                client_token: Some(token.clone()),
                distribution_configuration_arn: Some(target.clone()),
            })
        })
        .await
    }

    pub(crate) async fn update_distribution_configuration_op(
        &self,
        ctx: &RequestContext,
        input: t::UpdateDistributionConfigurationRequest,
    ) -> Result<t::UpdateDistributionConfigurationResponse, ServiceError> {
        let target = input.distribution_configuration_arn.clone();
        let existing = self.with_region(ctx, |r| r.distributions.get(&target).cloned());
        authorize(
            ctx,
            "UpdateDistributionConfiguration",
            &target,
            resource_tags(&existing.as_ref().and_then(|e| e.tags.clone())),
        )?;
        let token = input.client_token.clone();
        self.idempotent(ctx, "UpdateDistributionConfiguration", &token, &input.clone(), async {
            let existing = existing.clone().ok_or_else(|| arn_not_found(&target))?;
            check_distributions(&input.distributions)?;
            let updated = t::DistributionConfiguration {
                description: input.description.clone(),
                distributions: Some(input.distributions.clone()),
                date_updated: Some(now(ctx)),
                ..existing
            };
            self.with_region(ctx, |r| r.distributions.insert(target.clone(), updated));
            Ok(t::UpdateDistributionConfigurationResponse {
                request_id: Some(ctx.request_id.clone()),
                client_token: Some(token.clone()),
                distribution_configuration_arn: Some(target.clone()),
            })
        })
        .await
    }

    pub(crate) fn get_distribution_configuration_op(
        &self,
        ctx: &RequestContext,
        input: t::GetDistributionConfigurationRequest,
    ) -> Result<t::GetDistributionConfigurationResponse, ServiceError> {
        let target = input.distribution_configuration_arn.clone();
        let found = self.with_region(ctx, |r| r.distributions.get(&target).cloned());
        authorize(
            ctx,
            "GetDistributionConfiguration",
            &target,
            resource_tags(&found.as_ref().and_then(|e| e.tags.clone())),
        )?;
        let config = found.ok_or_else(|| arn_not_found(&target))?;
        Ok(t::GetDistributionConfigurationResponse {
            request_id: Some(ctx.request_id.clone()),
            distribution_configuration: Some(config),
        })
    }

    pub(crate) fn list_distribution_configurations_op(
        &self,
        ctx: &RequestContext,
        input: t::ListDistributionConfigurationsRequest,
    ) -> Result<t::ListDistributionConfigurationsResponse, ServiceError> {
        authorize(
            ctx,
            "ListDistributionConfigurations",
            &arn(ctx, &account_of(ctx), "distribution-configuration/*"),
            ConditionContext::new(),
        )?;
        let all: Vec<t::DistributionConfiguration> =
            self.with_region(ctx, |r| r.distributions.values().cloned().collect());
        let mut out = Vec::new();
        for c in all {
            if filters_match(&input.filters, &["name"], |_| s(&c.name))? {
                out.push(t::DistributionConfigurationSummary {
                    arn: c.arn,
                    name: c.name,
                    description: c.description,
                    date_created: c.date_created,
                    date_updated: c.date_updated,
                    tags: c.tags,
                    regions: c.distributions.map(|d| d.into_iter().map(|x| x.region).collect()),
                });
            }
        }
        let (page, next_token) = paginate(out, input.max_results, &input.next_token)?;
        Ok(t::ListDistributionConfigurationsResponse {
            request_id: Some(ctx.request_id.clone()),
            distribution_configuration_summary_list: Some(page),
            next_token,
        })
    }

    pub(crate) fn delete_distribution_configuration_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteDistributionConfigurationRequest,
    ) -> Result<t::DeleteDistributionConfigurationResponse, ServiceError> {
        let target = input.distribution_configuration_arn.clone();
        let found = self.with_region(ctx, |r| r.distributions.get(&target).map(|c| c.tags.clone()));
        authorize(ctx, "DeleteDistributionConfiguration", &target, resource_tags(&found.clone().flatten()))?;
        if found.is_none() {
            return Err(arn_not_found(&target));
        }
        let users: Vec<String> = self.with_region(ctx, |r| {
            r.pipelines
                .iter()
                .filter(|(_, p)| p.pipeline.distribution_configuration_arn.as_deref() == Some(target.as_str()))
                .map(|(k, _)| k.clone())
                .collect()
        });
        if !users.is_empty() {
            return Err(dependency(format!(
                "Resource dependency error: The resource ARN '{target}' has the following dependencies: {}.",
                users.join(", ")
            )));
        }
        self.with_region(ctx, |r| r.distributions.remove(&target));
        Ok(t::DeleteDistributionConfigurationResponse {
            request_id: Some(ctx.request_id.clone()),
            distribution_configuration_arn: Some(target),
        })
    }
}

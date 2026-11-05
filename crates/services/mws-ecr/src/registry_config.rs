//! Registry-wide configuration: the registry policy, replication, scanning,
//! account settings, signing, pull-time update exclusions, pull through
//! cache rules and repository creation templates.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::names::{authorize_registry, dt, invalid_parameter, now_ms, registry_arn};
use crate::state::{Registry, Repo};
use crate::Ecr;

const SETTINGS: &[(&str, &[&str], &str)] = &[
    ("BASIC_SCAN_TYPE_VERSION", &["AWS_NATIVE", "CLAIR"], "AWS_NATIVE"),
    ("REGISTRY_POLICY_SCOPE", &["V1", "V2"], "V2"),
    ("BLOB_MOUNTING", &["ENABLED", "DISABLED"], "DISABLED"),
];

const PULL_THROUGH_LIMIT: usize = 50;
const EXCLUSION_LIMIT: usize = 20;

/// How a repository is scanned, as `BatchGetRepositoryScanningConfiguration`
/// reports it.
pub(crate) fn repository_scanning(reg: &Registry, repo: &Repo) -> types::RepositoryScanningConfiguration {
    let rules = reg.scanning.as_ref().and_then(|s| s.rules.clone()).unwrap_or_default();
    let matched = rules.iter().find_map(|r| {
        r.repository_filters
            .iter()
            .find(|f| crate::names::wildcard(&f.filter, &repo.name))
            .map(|f| (r.scan_frequency.clone(), f.clone()))
    });
    let (frequency, filters) = match matched {
        Some((freq, f)) => (freq, vec![f]),
        None if repo.scan_on_push => ("SCAN_ON_PUSH".to_string(), Vec::new()),
        None => ("MANUAL".to_string(), Vec::new()),
    };
    types::RepositoryScanningConfiguration {
        repository_arn: Some(repo.arn.clone()),
        repository_name: Some(repo.name.clone()),
        scan_on_push: frequency == "SCAN_ON_PUSH" || repo.scan_on_push,
        scan_frequency: Some(frequency),
        applied_scan_filters: Some(filters),
    }
}

fn upstream_registry_of(url: &str) -> Option<&'static str> {
    let host = url.trim_start_matches("https://").split('/').next().unwrap_or(url);
    Some(match host {
        "registry-1.docker.io" | "docker.io" => "docker-hub",
        "public.ecr.aws" => "ecr-public",
        "quay.io" => "quay",
        "registry.k8s.io" => "k8s",
        "ghcr.io" => "github-container-registry",
        "registry.gitlab.com" => "gitlab-container-registry",
        "cgr.dev" => "chainguard",
        h if h.ends_with(".azurecr.io") => "azure-container-registry",
        h if h.contains(".dkr.ecr.") && h.ends_with(".amazonaws.com") => "ecr",
        _ => return None,
    })
}

fn template_not_found(prefix: &str) -> ServiceError {
    errors::template_not_found(format!("The repository creation template with the prefix '{prefix}' does not exist."))
}

fn rule_not_found(prefix: &str, account: &str) -> ServiceError {
    errors::pull_through_cache_rule_not_found(format!(
        "The pull through cache rule with the ecr repository prefix '{prefix}' does not exist in the registry with id '{account}'."
    ))
}

fn check_template(
    applied_for: Option<&[String]>,
    repository_policy: Option<&str>,
    lifecycle_policy: Option<&str>,
    mutability: Option<&str>,
    filters: &[types::ImageTagMutabilityExclusionFilter],
) -> Result<(), ServiceError> {
    if applied_for.is_some_and(|a| a.is_empty()) {
        return Err(invalid_parameter(
            "Invalid parameter at 'appliedFor' failed to satisfy constraint: 'must contain at least one value'",
        ));
    }
    if let Some(p) = repository_policy {
        crate::repos::check_policy(p)?;
    }
    if let Some(l) = lifecycle_policy {
        crate::lifecycle::parse(l)?;
    }
    if let Some(m) = mutability {
        crate::repos::check_mutability(m, filters)?;
    }
    Ok(())
}

impl Ecr {
    fn registry_action(&self, ctx: &RequestContext, action: &str) -> Result<String, ServiceError> {
        let account = ctx.caller.account_id.clone();
        authorize_registry(ctx, action, &registry_arn(&ctx.partition, &ctx.region, &account))?;
        Ok(account)
    }

    pub(crate) fn put_registry_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutRegistryPolicyRequest,
    ) -> Result<types::PutRegistryPolicyResponse, ServiceError> {
        let account = self.registry_action(ctx, "ecr:PutRegistryPolicy")?;
        crate::repos::check_policy(&input.policy_text).map_err(|_| {
            invalid_parameter(
                "Invalid parameter at 'PolicyText' failed to satisfy constraint: 'Invalid registry policy provided'",
            )
        })?;
        self.lock().registry_mut(&account, &ctx.region).policy = Some(input.policy_text.clone());
        Ok(types::PutRegistryPolicyResponse { registry_id: Some(account), policy_text: Some(input.policy_text) })
    }

    fn registry_policy_not_found(account: &str) -> ServiceError {
        errors::registry_policy_not_found(format!("Registry policy does not exist in the registry with id '{account}'"))
    }

    pub(crate) fn get_registry_policy(
        &self,
        ctx: &RequestContext,
        _input: types::GetRegistryPolicyRequest,
    ) -> Result<types::GetRegistryPolicyResponse, ServiceError> {
        let account = self.registry_action(ctx, "ecr:GetRegistryPolicy")?;
        let policy = self.lock().registry(&account, &ctx.region).and_then(|r| r.policy.clone());
        let policy = policy.ok_or_else(|| Self::registry_policy_not_found(&account))?;
        Ok(types::GetRegistryPolicyResponse { registry_id: Some(account), policy_text: Some(policy) })
    }

    pub(crate) fn delete_registry_policy(
        &self,
        ctx: &RequestContext,
        _input: types::DeleteRegistryPolicyRequest,
    ) -> Result<types::DeleteRegistryPolicyResponse, ServiceError> {
        let account = self.registry_action(ctx, "ecr:DeleteRegistryPolicy")?;
        let policy = self.lock().registry_mut(&account, &ctx.region).policy.take();
        let policy = policy.ok_or_else(|| Self::registry_policy_not_found(&account))?;
        Ok(types::DeleteRegistryPolicyResponse { registry_id: Some(account), policy_text: Some(policy) })
    }

    pub(crate) fn describe_registry(
        &self,
        ctx: &RequestContext,
        _input: types::DescribeRegistryRequest,
    ) -> Result<types::DescribeRegistryResponse, ServiceError> {
        let account = self.registry_action(ctx, "ecr:DescribeRegistry")?;
        let replication = self.lock().registry(&account, &ctx.region).and_then(|r| r.replication.clone());
        Ok(types::DescribeRegistryResponse {
            registry_id: Some(account),
            replication_configuration: Some(replication.unwrap_or_default()),
        })
    }

    pub(crate) fn put_replication_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutReplicationConfigurationRequest,
    ) -> Result<types::PutReplicationConfigurationResponse, ServiceError> {
        let account = self.registry_action(ctx, "ecr:PutReplicationConfiguration")?;
        let config = input.replication_configuration;
        let total: usize = config.rules.iter().map(|r| r.destinations.len()).sum();
        if total > 25 {
            return Err(invalid_parameter(
                "Invalid parameter at 'replicationConfiguration' failed to satisfy constraint: 'The total number of destinations must not exceed 25'",
            ));
        }
        for rule in &config.rules {
            for d in &rule.destinations {
                if d.region == ctx.region && d.registry_id == account {
                    return Err(invalid_parameter(
                        "Invalid parameter at 'replicationConfiguration' failed to satisfy constraint: 'A destination cannot be the source registry'",
                    ));
                }
            }
        }
        self.lock().registry_mut(&account, &ctx.region).replication = Some(config.clone());
        Ok(types::PutReplicationConfigurationResponse { replication_configuration: Some(config) })
    }

    pub(crate) fn get_registry_scanning_configuration(
        &self,
        ctx: &RequestContext,
        _input: types::GetRegistryScanningConfigurationRequest,
    ) -> Result<types::GetRegistryScanningConfigurationResponse, ServiceError> {
        let account = self.registry_action(ctx, "ecr:GetRegistryScanningConfiguration")?;
        let config = self.lock().registry(&account, &ctx.region).and_then(|r| r.scanning.clone());
        Ok(types::GetRegistryScanningConfigurationResponse {
            registry_id: Some(account),
            scanning_configuration: Some(config.unwrap_or(types::RegistryScanningConfiguration {
                scan_type: Some("BASIC".into()),
                rules: Some(Vec::new()),
            })),
        })
    }

    pub(crate) fn put_registry_scanning_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutRegistryScanningConfigurationRequest,
    ) -> Result<types::PutRegistryScanningConfigurationResponse, ServiceError> {
        let account = self.registry_action(ctx, "ecr:PutRegistryScanningConfiguration")?;
        let scan_type = input.scan_type.unwrap_or_else(|| "BASIC".into());
        let rules = input.rules.unwrap_or_default();
        for r in &rules {
            if scan_type == "BASIC" && r.scan_frequency == "CONTINUOUS_SCAN" {
                return Err(errors::validation("CONTINUOUS_SCAN is only supported with ENHANCED scanning."));
            }
        }
        let config = types::RegistryScanningConfiguration { scan_type: Some(scan_type), rules: Some(rules) };
        self.lock().registry_mut(&account, &ctx.region).scanning = Some(config.clone());
        Ok(types::PutRegistryScanningConfigurationResponse { registry_scanning_configuration: Some(config) })
    }

    fn setting(name: &str) -> Result<(&'static [&'static str], &'static str), ServiceError> {
        SETTINGS.iter().find(|(n, _, _)| *n == name).map(|(_, v, d)| (*v, *d)).ok_or_else(|| {
            errors::validation(format!(
                "Invalid account setting name '{name}'. Valid names: {}",
                SETTINGS.iter().map(|(n, _, _)| *n).collect::<Vec<_>>().join(", ")
            ))
        })
    }

    pub(crate) fn get_account_setting(
        &self,
        ctx: &RequestContext,
        input: types::GetAccountSettingRequest,
    ) -> Result<types::GetAccountSettingResponse, ServiceError> {
        let account = self.registry_action(ctx, "ecr:GetAccountSetting")?;
        let (_, default) = Self::setting(&input.name)?;
        let value = self.lock().registry(&account, &ctx.region).and_then(|r| r.settings.get(&input.name).cloned());
        Ok(types::GetAccountSettingResponse {
            name: Some(input.name),
            value: Some(value.unwrap_or_else(|| default.into())),
        })
    }

    pub(crate) fn put_account_setting(
        &self,
        ctx: &RequestContext,
        input: types::PutAccountSettingRequest,
    ) -> Result<types::PutAccountSettingResponse, ServiceError> {
        let account = self.registry_action(ctx, "ecr:PutAccountSetting")?;
        let (values, _) = Self::setting(&input.name)?;
        if !values.contains(&input.value.as_str()) {
            return Err(errors::validation(format!(
                "Invalid value '{}' for account setting '{}'. Valid values: {}",
                input.value,
                input.name,
                values.join(", ")
            )));
        }
        self.lock().registry_mut(&account, &ctx.region).settings.insert(input.name.clone(), input.value.clone());
        Ok(types::PutAccountSettingResponse { name: Some(input.name), value: Some(input.value) })
    }

    pub(crate) fn put_signing_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutSigningConfigurationRequest,
    ) -> Result<types::PutSigningConfigurationResponse, ServiceError> {
        let account = self.registry_action(ctx, "ecr:PutSigningConfiguration")?;
        let config = input.signing_configuration;
        if config.rules.len() > 10 {
            return Err(errors::validation("A signing configuration can have at most 10 rules."));
        }
        for r in &config.rules {
            if !r.signing_profile_arn.starts_with("arn:") || !r.signing_profile_arn.contains(":signer:") {
                return Err(errors::validation(format!("Invalid signing profile ARN '{}'.", r.signing_profile_arn)));
            }
        }
        self.lock().registry_mut(&account, &ctx.region).signing = Some(config.clone());
        Ok(types::PutSigningConfigurationResponse { signing_configuration: Some(config) })
    }

    fn signing_not_found(account: &str) -> ServiceError {
        errors::signing_configuration_not_found(format!(
            "Signing configuration does not exist in the registry with id '{account}'"
        ))
    }

    pub(crate) fn get_signing_configuration(
        &self,
        ctx: &RequestContext,
        _input: types::GetSigningConfigurationRequest,
    ) -> Result<types::GetSigningConfigurationResponse, ServiceError> {
        let account = self.registry_action(ctx, "ecr:GetSigningConfiguration")?;
        let config = self.lock().registry(&account, &ctx.region).and_then(|r| r.signing.clone());
        let config = config.ok_or_else(|| Self::signing_not_found(&account))?;
        Ok(types::GetSigningConfigurationResponse { registry_id: Some(account), signing_configuration: Some(config) })
    }

    pub(crate) fn delete_signing_configuration(
        &self,
        ctx: &RequestContext,
        _input: types::DeleteSigningConfigurationRequest,
    ) -> Result<types::DeleteSigningConfigurationResponse, ServiceError> {
        let account = self.registry_action(ctx, "ecr:DeleteSigningConfiguration")?;
        let config = self.lock().registry_mut(&account, &ctx.region).signing.take();
        let config = config.ok_or_else(|| Self::signing_not_found(&account))?;
        Ok(types::DeleteSigningConfigurationResponse {
            registry_id: Some(account),
            signing_configuration: Some(config),
        })
    }

    fn check_principal_arn(arn: &str) -> Result<(), ServiceError> {
        let parts: Vec<&str> = arn.splitn(6, ':').collect();
        let ok = parts.len() == 6
            && parts[0] == "arn"
            && parts[2] == "iam"
            && parts[4].len() == 12
            && (parts[5].starts_with("user/") || parts[5].starts_with("role/"));
        if !ok {
            return Err(invalid_parameter(format!(
                "Invalid parameter at 'principalArn' failed to satisfy constraint: 'must be an IAM user or role ARN' ({arn})"
            )));
        }
        Ok(())
    }

    pub(crate) fn register_pull_time_update_exclusion(
        &self,
        ctx: &RequestContext,
        input: types::RegisterPullTimeUpdateExclusionRequest,
    ) -> Result<types::RegisterPullTimeUpdateExclusionResponse, ServiceError> {
        let account = self.registry_action(ctx, "ecr:RegisterPullTimeUpdateExclusion")?;
        Self::check_principal_arn(&input.principal_arn)?;
        let now = now_ms(ctx);
        let mut st = self.lock();
        let reg = st.registry_mut(&account, &ctx.region);
        if reg.pull_time_exclusions.contains_key(&input.principal_arn) {
            return Err(errors::exclusion_already_exists(format!(
                "The principal '{}' is already in the pull time update exclusion list.",
                input.principal_arn
            )));
        }
        if reg.pull_time_exclusions.len() >= EXCLUSION_LIMIT {
            return Err(errors::limit_exceeded(format!(
                "The pull time update exclusion list can have at most {EXCLUSION_LIMIT} principals."
            )));
        }
        reg.pull_time_exclusions.insert(input.principal_arn.clone(), now);
        Ok(types::RegisterPullTimeUpdateExclusionResponse {
            principal_arn: Some(input.principal_arn),
            created_at: Some(dt(now)),
        })
    }

    pub(crate) fn deregister_pull_time_update_exclusion(
        &self,
        ctx: &RequestContext,
        input: types::DeregisterPullTimeUpdateExclusionRequest,
    ) -> Result<types::DeregisterPullTimeUpdateExclusionResponse, ServiceError> {
        let account = self.registry_action(ctx, "ecr:DeregisterPullTimeUpdateExclusion")?;
        let removed = self.lock().registry_mut(&account, &ctx.region).pull_time_exclusions.remove(&input.principal_arn);
        if removed.is_none() {
            return Err(errors::exclusion_not_found(format!(
                "The principal '{}' is not in the pull time update exclusion list.",
                input.principal_arn
            )));
        }
        Ok(types::DeregisterPullTimeUpdateExclusionResponse { principal_arn: Some(input.principal_arn) })
    }

    pub(crate) fn list_pull_time_update_exclusions(
        &self,
        ctx: &RequestContext,
        input: types::ListPullTimeUpdateExclusionsRequest,
    ) -> Result<types::ListPullTimeUpdateExclusionsResponse, ServiceError> {
        let account = self.registry_action(ctx, "ecr:ListPullTimeUpdateExclusions")?;
        let all: Vec<String> = self
            .lock()
            .registry(&account, &ctx.region)
            .map(|r| r.pull_time_exclusions.keys().cloned().collect())
            .unwrap_or_default();
        let (items, next_token) = crate::names::page(&all, input.next_token.as_deref(), input.max_results, 100)?;
        Ok(types::ListPullTimeUpdateExclusionsResponse { pull_time_update_exclusions: Some(items), next_token })
    }

    pub(crate) fn create_pull_through_cache_rule(
        &self,
        ctx: &RequestContext,
        input: types::CreatePullThroughCacheRuleRequest,
    ) -> Result<types::CreatePullThroughCacheRuleResponse, ServiceError> {
        let account = Self::own_account(ctx, input.registry_id.as_deref())?;
        authorize_registry(
            ctx,
            "ecr:CreatePullThroughCacheRule",
            &registry_arn(&ctx.partition, &ctx.region, &account),
        )?;
        let upstream = match &input.upstream_registry {
            Some(u) => u.clone(),
            None => upstream_registry_of(&input.upstream_registry_url)
                .ok_or_else(|| {
                    errors::unsupported_upstream_registry("The specified upstream registry isn't supported.")
                })?
                .to_string(),
        };
        let needs_credentials = matches!(
            upstream.as_str(),
            "docker-hub" | "github-container-registry" | "azure-container-registry" | "gitlab-container-registry"
        );
        if needs_credentials && input.credential_arn.is_none() {
            return Err(invalid_parameter(format!(
                "Invalid parameter at 'credentialArn' failed to satisfy constraint: 'a credential is required for upstream registry {upstream}'"
            )));
        }
        if let Some(c) = &input.credential_arn {
            if !c.contains(":secretsmanager:") || !c.contains(":secret:ecr-pullthroughcache/") {
                return Err(invalid_parameter(
                    "Invalid parameter at 'credentialArn' failed to satisfy constraint: 'must be a Secrets Manager secret whose name starts with ecr-pullthroughcache/'",
                ));
            }
        }
        if upstream == "ecr" && input.custom_role_arn.is_none() {
            return Err(invalid_parameter(
                "Invalid parameter at 'customRoleArn' failed to satisfy constraint: 'customRoleArn is required when the upstream registry is ecr'",
            ));
        }
        let now = now_ms(ctx);
        let mut st = self.lock();
        let reg = st.registry_mut(&account, &ctx.region);
        if reg.pull_through.contains_key(&input.ecr_repository_prefix) {
            return Err(errors::pull_through_cache_rule_already_exists(format!(
                "A pull through cache rule with the ecr repository prefix '{}' already exists in the registry with id '{account}'.",
                input.ecr_repository_prefix
            )));
        }
        if reg.pull_through.len() >= PULL_THROUGH_LIMIT {
            return Err(errors::limit_exceeded(format!(
                "A registry can have at most {PULL_THROUGH_LIMIT} pull through cache rules."
            )));
        }
        let rule = types::PullThroughCacheRule {
            ecr_repository_prefix: Some(input.ecr_repository_prefix.clone()),
            upstream_registry_url: Some(input.upstream_registry_url.clone()),
            created_at: Some(dt(now)),
            registry_id: Some(account.clone()),
            credential_arn: input.credential_arn.clone(),
            custom_role_arn: input.custom_role_arn.clone(),
            upstream_repository_prefix: Some(input.upstream_repository_prefix.clone().unwrap_or_else(|| "ROOT".into())),
            upstream_registry: Some(upstream.clone()),
            updated_at: Some(dt(now)),
        };
        reg.pull_through.insert(input.ecr_repository_prefix.clone(), rule.clone());
        Ok(types::CreatePullThroughCacheRuleResponse {
            ecr_repository_prefix: rule.ecr_repository_prefix,
            upstream_registry_url: rule.upstream_registry_url,
            created_at: rule.created_at,
            registry_id: rule.registry_id,
            upstream_registry: rule.upstream_registry,
            credential_arn: rule.credential_arn,
            custom_role_arn: rule.custom_role_arn,
            upstream_repository_prefix: rule.upstream_repository_prefix,
        })
    }

    fn own_account(ctx: &RequestContext, registry_id: Option<&str>) -> Result<String, ServiceError> {
        let account = Ecr::target(ctx, registry_id);
        if account != ctx.caller.account_id {
            return Err(invalid_parameter(
                "Invalid parameter at 'registryId' failed to satisfy constraint: 'must be the caller's account id'",
            ));
        }
        Ok(account)
    }

    pub(crate) fn describe_pull_through_cache_rules(
        &self,
        ctx: &RequestContext,
        input: types::DescribePullThroughCacheRulesRequest,
    ) -> Result<types::DescribePullThroughCacheRulesResponse, ServiceError> {
        let account = Self::own_account(ctx, input.registry_id.as_deref())?;
        authorize_registry(
            ctx,
            "ecr:DescribePullThroughCacheRules",
            &registry_arn(&ctx.partition, &ctx.region, &account),
        )?;
        let st = self.lock();
        let empty = Registry::default();
        let reg = st.registry(&account, &ctx.region).unwrap_or(&empty);
        let rules: Vec<types::PullThroughCacheRule> = match &input.ecr_repository_prefixes {
            Some(prefixes) => prefixes
                .iter()
                .map(|p| reg.pull_through.get(p).cloned().ok_or_else(|| rule_not_found(p, &account)))
                .collect::<Result<_, _>>()?,
            None => reg.pull_through.values().cloned().collect(),
        };
        let (rules, next_token) = crate::names::page(&rules, input.next_token.as_deref(), input.max_results, 100)?;
        Ok(types::DescribePullThroughCacheRulesResponse { pull_through_cache_rules: Some(rules), next_token })
    }

    pub(crate) fn delete_pull_through_cache_rule(
        &self,
        ctx: &RequestContext,
        input: types::DeletePullThroughCacheRuleRequest,
    ) -> Result<types::DeletePullThroughCacheRuleResponse, ServiceError> {
        let account = Self::own_account(ctx, input.registry_id.as_deref())?;
        authorize_registry(
            ctx,
            "ecr:DeletePullThroughCacheRule",
            &registry_arn(&ctx.partition, &ctx.region, &account),
        )?;
        let rule = self.lock().registry_mut(&account, &ctx.region).pull_through.remove(&input.ecr_repository_prefix);
        let rule = rule.ok_or_else(|| rule_not_found(&input.ecr_repository_prefix, &account))?;
        Ok(types::DeletePullThroughCacheRuleResponse {
            ecr_repository_prefix: rule.ecr_repository_prefix,
            upstream_registry_url: rule.upstream_registry_url,
            created_at: rule.created_at,
            registry_id: rule.registry_id,
            credential_arn: rule.credential_arn,
            custom_role_arn: rule.custom_role_arn,
            upstream_repository_prefix: rule.upstream_repository_prefix,
        })
    }

    pub(crate) fn update_pull_through_cache_rule(
        &self,
        ctx: &RequestContext,
        input: types::UpdatePullThroughCacheRuleRequest,
    ) -> Result<types::UpdatePullThroughCacheRuleResponse, ServiceError> {
        let account = Self::own_account(ctx, input.registry_id.as_deref())?;
        authorize_registry(
            ctx,
            "ecr:UpdatePullThroughCacheRule",
            &registry_arn(&ctx.partition, &ctx.region, &account),
        )?;
        let now = now_ms(ctx);
        let mut st = self.lock();
        let rule = st
            .registry_mut(&account, &ctx.region)
            .pull_through
            .get_mut(&input.ecr_repository_prefix)
            .ok_or_else(|| rule_not_found(&input.ecr_repository_prefix, &account))?;
        if input.credential_arn.is_some() {
            rule.credential_arn = input.credential_arn.clone();
        }
        if input.custom_role_arn.is_some() {
            rule.custom_role_arn = input.custom_role_arn.clone();
        }
        rule.updated_at = Some(dt(now));
        Ok(types::UpdatePullThroughCacheRuleResponse {
            ecr_repository_prefix: rule.ecr_repository_prefix.clone(),
            registry_id: Some(account),
            updated_at: rule.updated_at,
            credential_arn: rule.credential_arn.clone(),
            custom_role_arn: rule.custom_role_arn.clone(),
            upstream_repository_prefix: rule.upstream_repository_prefix.clone(),
        })
    }

    pub(crate) fn validate_pull_through_cache_rule(
        &self,
        ctx: &RequestContext,
        input: types::ValidatePullThroughCacheRuleRequest,
    ) -> Result<types::ValidatePullThroughCacheRuleResponse, ServiceError> {
        let account = Self::own_account(ctx, input.registry_id.as_deref())?;
        authorize_registry(
            ctx,
            "ecr:ValidatePullThroughCacheRule",
            &registry_arn(&ctx.partition, &ctx.region, &account),
        )?;
        let st = self.lock();
        let rule = st
            .registry(&account, &ctx.region)
            .and_then(|r| r.pull_through.get(&input.ecr_repository_prefix))
            .cloned()
            .ok_or_else(|| rule_not_found(&input.ecr_repository_prefix, &account))?;
        Ok(types::ValidatePullThroughCacheRuleResponse {
            ecr_repository_prefix: rule.ecr_repository_prefix,
            registry_id: Some(account),
            upstream_registry_url: rule.upstream_registry_url,
            credential_arn: rule.credential_arn,
            custom_role_arn: rule.custom_role_arn,
            upstream_repository_prefix: rule.upstream_repository_prefix,
            is_valid: true,
            failure: None,
        })
    }

    pub(crate) fn create_repository_creation_template(
        &self,
        ctx: &RequestContext,
        input: types::CreateRepositoryCreationTemplateRequest,
    ) -> Result<types::CreateRepositoryCreationTemplateResponse, ServiceError> {
        let account = self.registry_action(ctx, "ecr:CreateRepositoryCreationTemplate")?;
        let filters = input.image_tag_mutability_exclusion_filters.clone().unwrap_or_default();
        check_template(
            Some(&input.applied_for),
            input.repository_policy.as_deref(),
            input.lifecycle_policy.as_deref(),
            input.image_tag_mutability.as_deref(),
            &filters,
        )?;
        if let Some(tags) = &input.resource_tags {
            crate::repos::check_tags(tags)?;
        }
        let now = now_ms(ctx);
        let mut st = self.lock();
        let reg = st.registry_mut(&account, &ctx.region);
        if reg.templates.contains_key(&input.prefix) {
            return Err(errors::template_already_exists(format!(
                "A repository creation template with the prefix '{}' already exists.",
                input.prefix
            )));
        }
        let template = types::RepositoryCreationTemplate {
            prefix: Some(input.prefix.clone()),
            description: input.description,
            encryption_configuration: Some(input.encryption_configuration.unwrap_or(
                types::EncryptionConfigurationForRepositoryCreationTemplate {
                    encryption_type: "AES256".into(),
                    kms_key: None,
                },
            )),
            resource_tags: Some(input.resource_tags.unwrap_or_default()),
            image_tag_mutability: Some(input.image_tag_mutability.unwrap_or_else(|| "MUTABLE".into())),
            image_tag_mutability_exclusion_filters: input.image_tag_mutability_exclusion_filters,
            repository_policy: input.repository_policy,
            lifecycle_policy: input.lifecycle_policy,
            applied_for: Some(input.applied_for),
            custom_role_arn: input.custom_role_arn,
            created_at: Some(dt(now)),
            updated_at: Some(dt(now)),
        };
        reg.templates.insert(input.prefix, template.clone());
        Ok(types::CreateRepositoryCreationTemplateResponse {
            registry_id: Some(account),
            repository_creation_template: Some(template),
        })
    }

    pub(crate) fn update_repository_creation_template(
        &self,
        ctx: &RequestContext,
        input: types::UpdateRepositoryCreationTemplateRequest,
    ) -> Result<types::UpdateRepositoryCreationTemplateResponse, ServiceError> {
        let account = self.registry_action(ctx, "ecr:UpdateRepositoryCreationTemplate")?;
        let filters = input.image_tag_mutability_exclusion_filters.clone().unwrap_or_default();
        check_template(
            input.applied_for.as_deref(),
            input.repository_policy.as_deref(),
            input.lifecycle_policy.as_deref(),
            input.image_tag_mutability.as_deref(),
            &filters,
        )?;
        let now = now_ms(ctx);
        let mut st = self.lock();
        let reg = st.registry_mut(&account, &ctx.region);
        let t = reg.templates.get_mut(&input.prefix).ok_or_else(|| template_not_found(&input.prefix))?;
        macro_rules! set {
            ($($field:ident),*) => { $( if input.$field.is_some() { t.$field = input.$field.clone(); } )* };
        }
        set!(
            description,
            encryption_configuration,
            resource_tags,
            image_tag_mutability,
            repository_policy,
            lifecycle_policy,
            applied_for,
            custom_role_arn
        );
        if input.image_tag_mutability.is_some() || input.image_tag_mutability_exclusion_filters.is_some() {
            t.image_tag_mutability_exclusion_filters = input.image_tag_mutability_exclusion_filters.clone();
        }
        t.updated_at = Some(dt(now));
        Ok(types::UpdateRepositoryCreationTemplateResponse {
            registry_id: Some(account),
            repository_creation_template: Some(t.clone()),
        })
    }

    pub(crate) fn delete_repository_creation_template(
        &self,
        ctx: &RequestContext,
        input: types::DeleteRepositoryCreationTemplateRequest,
    ) -> Result<types::DeleteRepositoryCreationTemplateResponse, ServiceError> {
        let account = self.registry_action(ctx, "ecr:DeleteRepositoryCreationTemplate")?;
        let t = self.lock().registry_mut(&account, &ctx.region).templates.remove(&input.prefix);
        let t = t.ok_or_else(|| template_not_found(&input.prefix))?;
        Ok(types::DeleteRepositoryCreationTemplateResponse {
            registry_id: Some(account),
            repository_creation_template: Some(t),
        })
    }

    pub(crate) fn describe_repository_creation_templates(
        &self,
        ctx: &RequestContext,
        input: types::DescribeRepositoryCreationTemplatesRequest,
    ) -> Result<types::DescribeRepositoryCreationTemplatesResponse, ServiceError> {
        let account = self.registry_action(ctx, "ecr:DescribeRepositoryCreationTemplates")?;
        let st = self.lock();
        let empty = Registry::default();
        let reg = st.registry(&account, &ctx.region).unwrap_or(&empty);
        let all: Vec<_> = match &input.prefixes {
            Some(p) => p.iter().filter_map(|p| reg.templates.get(p).cloned()).collect(),
            None => reg.templates.values().cloned().collect(),
        };
        let (templates, next_token) = crate::names::page(&all, input.next_token.as_deref(), input.max_results, 100)?;
        Ok(types::DescribeRepositoryCreationTemplatesResponse {
            registry_id: Some(account),
            repository_creation_templates: Some(templates),
            next_token,
        })
    }
}

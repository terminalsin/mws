//! Lambda Managed Instances: capacity providers (the VPC, operator role and
//! instance requirements managed instances use) and the scaling
//! configuration of functions that run on them. MWS runs those functions
//! like any other, locally; the capacity provider records where AWS would
//! place them and refuses deletion while function versions use it.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::functions::{paginate, tag_context, timestamp};
use crate::generated::{errors, types};
use crate::names;
use crate::state::CapacityProvider;
use crate::Lambda;

/// At most this many capacity providers per account and Region.
const MAX_PROVIDERS: usize = 1000;

fn provider_arn(ctx: &RequestContext, name: &str) -> String {
    format!("arn:{}:lambda:{}:{}:capacity-provider:{name}", ctx.partition, ctx.region, ctx.caller.account_id)
}

fn not_found(name: &str) -> ServiceError {
    errors::resource_not_found(format!("Capacity provider not found: {name}"))
}

fn validate_name(name: &str) -> Result<(), ServiceError> {
    let ok = !name.is_empty()
        && name.len() <= 140
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if !ok {
        return Err(errors::invalid_parameter_value(format!(
            "1 validation error detected: Value '{name}' at 'capacityProviderName' failed to satisfy constraint: Member must satisfy regular expression pattern: [a-zA-Z0-9-_]+"
        )));
    }
    Ok(())
}

/// The name an ARN or name names.
fn name_of(name_or_arn: &str) -> &str {
    name_or_arn.rsplit(':').next().unwrap_or(name_or_arn)
}

impl Lambda {
    /// The versions (`arn:...:function:name:N`) whose configuration uses
    /// the capacity provider `arn`.
    fn versions_using(st: &crate::state::State, arn: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for f in st.functions.values() {
            let uses = |c: &types::FunctionConfiguration| {
                c.capacity_provider_config
                    .as_ref()
                    .is_some_and(|p| p.lambda_managed_instances_capacity_provider_config.capacity_provider_arn == arn)
            };
            if uses(&f.latest.config) {
                out.push((format!("{}:$LATEST", f.arn), f.latest.config.state.clone().unwrap_or("Active".into())));
            }
            for (n, v) in &f.versions {
                if uses(&v.config) {
                    out.push((format!("{}:{n}", f.arn), v.config.state.clone().unwrap_or("Active".into())));
                }
            }
        }
        out
    }

    /// Check a function's capacity provider configuration names a provider
    /// of the caller's that exists.
    pub(crate) fn check_capacity_provider_config(
        &self,
        config: Option<&types::CapacityProviderConfig>,
    ) -> Result<(), ServiceError> {
        let Some(c) = config else { return Ok(()) };
        let c = &c.lambda_managed_instances_capacity_provider_config;
        if !self.read().capacity_providers.contains_key(&c.capacity_provider_arn) {
            return Err(errors::invalid_parameter_value(format!(
                "Capacity provider {} does not exist.",
                c.capacity_provider_arn
            )));
        }
        if let Some(n) = c.per_execution_environment_max_concurrency {
            if !(1..=1600).contains(&n) {
                return Err(errors::invalid_parameter_value(
                    "PerExecutionEnvironmentMaxConcurrency must be between 1 and 1600.",
                ));
            }
        }
        if let Some(r) = c.execution_environment_memory_gi_b_per_v_cpu {
            if ![2.0, 4.0, 8.0].contains(&r) {
                return Err(errors::invalid_parameter_value(
                    "ExecutionEnvironmentMemoryGiBPerVCpu must be one of 2.0, 4.0 or 8.0.",
                ));
            }
        }
        Ok(())
    }

    pub async fn create_capacity_provider(
        &self,
        ctx: &RequestContext,
        input: types::CreateCapacityProviderRequest,
    ) -> Result<types::CreateCapacityProviderResponse, ServiceError> {
        validate_name(&input.capacity_provider_name)?;
        let arn = provider_arn(ctx, &input.capacity_provider_name);
        let tags = input.tags.clone().unwrap_or_default();
        ctx.authorize("lambda:CreateCapacityProvider", &arn, tag_context(&tags))?;
        let role = &input.permissions_config.capacity_provider_operator_role_arn;
        ctx.authorize("iam:PassRole", role, ConditionContext::new())?;
        if input.vpc_config.subnet_ids.is_empty() {
            return Err(errors::invalid_parameter_value("VpcConfig must have at least one subnet."));
        }
        if input.vpc_config.subnet_ids.len() > 16 || input.vpc_config.security_group_ids.len() > 5 {
            return Err(errors::invalid_parameter_value("VpcConfig takes at most 16 subnets and 5 security groups."));
        }
        if let Some(r) = &input.instance_requirements {
            if r.allowed_instance_types.as_ref().is_some_and(|a| !a.is_empty())
                && r.excluded_instance_types.as_ref().is_some_and(|e| !e.is_empty())
            {
                return Err(errors::invalid_parameter_value(
                    "AllowedInstanceTypes and ExcludedInstanceTypes cannot both be specified.",
                ));
            }
        }
        let mut st = self.write();
        if st.capacity_providers.contains_key(&arn) {
            return Err(errors::resource_conflict(format!(
                "Capacity provider already exists: {}",
                input.capacity_provider_name
            )));
        }
        let owned = st
            .capacity_providers
            .values()
            .filter(|p| p.account_id == ctx.caller.account_id && p.region == ctx.region)
            .count();
        if owned >= MAX_PROVIDERS {
            return Err(errors::capacity_provider_limit_exceeded(
                "You have reached the maximum number of capacity providers.",
            ));
        }
        let mut scaling = input.capacity_provider_scaling_config.clone().unwrap_or_default();
        if scaling.scaling_mode.is_none() {
            scaling.scaling_mode = Some("Auto".into());
        }
        if scaling.max_v_cpu_count.is_none() {
            scaling.max_v_cpu_count = Some(400);
        }
        let mut requirements = input.instance_requirements.clone().unwrap_or_default();
        if requirements.architectures.is_none() {
            requirements.architectures = Some(vec!["x86_64".into()]);
        }
        let provider = types::CapacityProvider {
            capacity_provider_arn: arn.clone(),
            state: "Active".into(),
            vpc_config: input.vpc_config,
            permissions_config: input.permissions_config,
            instance_requirements: Some(requirements),
            capacity_provider_scaling_config: Some(scaling),
            kms_key_arn: input.kms_key_arn,
            last_modified: Some(timestamp(ctx.received_at)),
            propagate_tags: input.propagate_tags,
            telemetry_config: input.telemetry_config,
        };
        st.capacity_providers.insert(
            arn,
            CapacityProvider {
                account_id: ctx.caller.account_id.clone(),
                region: ctx.region.clone(),
                name: input.capacity_provider_name,
                provider: provider.clone(),
                tags,
            },
        );
        // The create call reports the provider while it is set up.
        let mut reported = provider;
        reported.state = "Pending".into();
        Ok(types::CreateCapacityProviderResponse { capacity_provider: reported })
    }

    pub async fn get_capacity_provider(
        &self,
        ctx: &RequestContext,
        input: types::GetCapacityProviderRequest,
    ) -> Result<types::GetCapacityProviderResponse, ServiceError> {
        let name = name_of(&input.capacity_provider_name);
        let arn = provider_arn(ctx, name);
        ctx.authorize("lambda:GetCapacityProvider", &arn, ConditionContext::new())?;
        let st = self.read();
        let p = st.capacity_providers.get(&arn).ok_or_else(|| not_found(name))?;
        Ok(types::GetCapacityProviderResponse { capacity_provider: p.provider.clone() })
    }

    pub async fn list_capacity_providers(
        &self,
        ctx: &RequestContext,
        input: types::ListCapacityProvidersRequest,
    ) -> Result<types::ListCapacityProvidersResponse, ServiceError> {
        ctx.authorize("lambda:ListCapacityProviders", "*", ConditionContext::new())?;
        let st = self.read();
        let all: Vec<types::CapacityProvider> = st
            .capacity_providers
            .values()
            .filter(|p| p.account_id == ctx.caller.account_id && p.region == ctx.region)
            .filter(|p| input.state.as_deref().is_none_or(|s| p.provider.state == s))
            .map(|p| p.provider.clone())
            .collect();
        let (page, next) = paginate(&all, input.marker.as_deref(), input.max_items, 50);
        Ok(types::ListCapacityProvidersResponse { capacity_providers: page, next_marker: next })
    }

    pub async fn update_capacity_provider(
        &self,
        ctx: &RequestContext,
        input: types::UpdateCapacityProviderRequest,
    ) -> Result<types::UpdateCapacityProviderResponse, ServiceError> {
        let name = name_of(&input.capacity_provider_name);
        let arn = provider_arn(ctx, name);
        ctx.authorize("lambda:UpdateCapacityProvider", &arn, ConditionContext::new())?;
        let mut st = self.write();
        let p = st.capacity_providers.get_mut(&arn).ok_or_else(|| not_found(name))?;
        if let Some(s) = input.capacity_provider_scaling_config {
            let current = p.provider.capacity_provider_scaling_config.get_or_insert_with(Default::default);
            if s.max_v_cpu_count.is_some() {
                current.max_v_cpu_count = s.max_v_cpu_count;
            }
            if s.scaling_mode.is_some() {
                current.scaling_mode = s.scaling_mode;
            }
            if s.scaling_policies.is_some() {
                current.scaling_policies = s.scaling_policies;
            }
        }
        if input.propagate_tags.is_some() {
            p.provider.propagate_tags = input.propagate_tags;
        }
        if input.telemetry_config.is_some() {
            p.provider.telemetry_config = input.telemetry_config;
        }
        p.provider.last_modified = Some(timestamp(ctx.received_at));
        Ok(types::UpdateCapacityProviderResponse { capacity_provider: p.provider.clone() })
    }

    pub async fn delete_capacity_provider(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCapacityProviderRequest,
    ) -> Result<types::DeleteCapacityProviderResponse, ServiceError> {
        let name = name_of(&input.capacity_provider_name);
        let arn = provider_arn(ctx, name);
        ctx.authorize("lambda:DeleteCapacityProvider", &arn, ConditionContext::new())?;
        let mut st = self.write();
        if !st.capacity_providers.contains_key(&arn) {
            return Err(not_found(name));
        }
        if !Self::versions_using(&st, &arn).is_empty() {
            return Err(errors::resource_conflict(format!(
                "Capacity provider {name} is in use by one or more function versions."
            )));
        }
        let mut p = st.capacity_providers.remove(&arn).expect("checked").provider;
        p.state = "Deleting".into();
        Ok(types::DeleteCapacityProviderResponse { capacity_provider: p })
    }

    pub async fn list_function_versions_by_capacity_provider(
        &self,
        ctx: &RequestContext,
        input: types::ListFunctionVersionsByCapacityProviderRequest,
    ) -> Result<types::ListFunctionVersionsByCapacityProviderResponse, ServiceError> {
        let name = name_of(&input.capacity_provider_name);
        let arn = provider_arn(ctx, name);
        ctx.authorize("lambda:ListFunctionVersionsByCapacityProvider", &arn, ConditionContext::new())?;
        let st = self.read();
        if !st.capacity_providers.contains_key(&arn) {
            return Err(not_found(name));
        }
        let all: Vec<types::FunctionVersionsByCapacityProviderListItem> = Self::versions_using(&st, &arn)
            .into_iter()
            .map(|(function_arn, state)| types::FunctionVersionsByCapacityProviderListItem { function_arn, state })
            .collect();
        let (page, next) = paginate(&all, input.marker.as_deref(), input.max_items, 50);
        Ok(types::ListFunctionVersionsByCapacityProviderResponse {
            capacity_provider_arn: arn,
            function_versions: page,
            next_marker: next,
        })
    }

    pub async fn put_function_scaling_config(
        &self,
        ctx: &RequestContext,
        input: types::PutFunctionScalingConfigRequest,
    ) -> Result<types::PutFunctionScalingConfigResponse, ServiceError> {
        let named = (input.qualifier != LATEST_PUBLISHED).then_some(input.qualifier.as_str());
        let f = names::parse_function(ctx, &input.function_name, named)?;
        self.authorize_function(ctx, "lambda:PutFunctionScalingConfig", &f, ConditionContext::new())?;
        let config = input.function_scaling_config.unwrap_or_default();
        if let (Some(min), Some(max)) = (config.min_execution_environments, config.max_execution_environments) {
            if min > max {
                return Err(errors::invalid_parameter_value(
                    "MinExecutionEnvironments must be less than or equal to MaxExecutionEnvironments.",
                ));
            }
        }
        if config.min_execution_environments.is_some_and(|m| m < 0)
            || config.max_execution_environments.is_some_and(|m| m < 0)
        {
            return Err(errors::invalid_parameter_value("Execution environment counts must not be negative."));
        }
        let mut st = self.write();
        let func = Self::function_mut(&mut st, &f)?;
        let qualifier = published_qualifier(func, &input.qualifier).ok_or_else(|| f.not_found())?;
        let version = func.version_for(Some(&qualifier)).ok_or_else(|| f.not_found())?;
        if version.config.capacity_provider_config.is_none() {
            return Err(errors::invalid_parameter_value(
                "Function scaling configuration is only supported for functions that use a capacity provider.",
            ));
        }
        let state = version.config.state.clone().unwrap_or_else(|| "Active".into());
        func.scaling_configs.insert(qualifier, config);
        Ok(types::PutFunctionScalingConfigResponse { function_state: Some(state) })
    }

    pub async fn get_function_scaling_config(
        &self,
        ctx: &RequestContext,
        input: types::GetFunctionScalingConfigRequest,
    ) -> Result<types::GetFunctionScalingConfigResponse, ServiceError> {
        let named = (input.qualifier != LATEST_PUBLISHED).then_some(input.qualifier.as_str());
        let f = names::parse_function(ctx, &input.function_name, named)?;
        self.authorize_function(ctx, "lambda:GetFunctionScalingConfig", &f, ConditionContext::new())?;
        let st = self.read();
        let func = Self::function(&st, &f)?;
        let qualifier = published_qualifier(func, &input.qualifier).ok_or_else(|| f.not_found())?;
        let version = func.version_for(Some(&qualifier)).ok_or_else(|| f.not_found())?;
        if version.config.capacity_provider_config.is_none() {
            return Err(errors::invalid_parameter_value(
                "Function scaling configuration is only supported for functions that use a capacity provider.",
            ));
        }
        let config = func.scaling_configs.get(&qualifier).cloned().unwrap_or(types::FunctionScalingConfig {
            min_execution_environments: Some(3),
            max_execution_environments: None,
        });
        Ok(types::GetFunctionScalingConfigResponse {
            function_arn: Some(format!("{}:{qualifier}", f.arn())),
            applied_function_scaling_config: Some(config.clone()),
            requested_function_scaling_config: Some(config),
        })
    }
}

/// `$LATEST.PUBLISHED`: the function's newest published version.
const LATEST_PUBLISHED: &str = "$LATEST.PUBLISHED";

fn published_qualifier(func: &crate::state::Function, qualifier: &str) -> Option<String> {
    if qualifier == LATEST_PUBLISHED {
        return func.versions.keys().next_back().map(|v| v.to_string());
    }
    Some(qualifier.to_string())
}

//! Aliases: named pointers to a version, with optional weighted routing to
//! a second one.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::functions::{check_revision, paginate, revision_id};
use crate::generated::{errors, types};
use crate::names::{self, FunctionRef};
use crate::state::Function;
use crate::Lambda;

fn check_target(func: &Function, f: &FunctionRef, version: &str) -> Result<(), ServiceError> {
    let exists = version == "$LATEST" || version.parse::<u64>().ok().is_some_and(|n| func.versions.contains_key(&n));
    if !exists {
        return Err(errors::resource_not_found(format!("Function not found: {}:{version}", f.arn())));
    }
    Ok(())
}

fn check_routing(
    func: &Function,
    f: &FunctionRef,
    primary: &str,
    routing: Option<&types::AliasRoutingConfiguration>,
) -> Result<(), ServiceError> {
    let Some(weights) = routing.and_then(|r| r.additional_version_weights.as_ref()) else { return Ok(()) };
    if weights.len() > 1 {
        return Err(errors::invalid_parameter_value(
            "Number of items in AdditionalVersionWeights cannot be greater than 1",
        ));
    }
    for (v, w) in weights {
        if v == primary {
            return Err(errors::invalid_parameter_value(
                "Invalid function version in routing config: the primary version and the additional version cannot be the same.",
            ));
        }
        if v == "$LATEST" || primary == "$LATEST" {
            return Err(errors::invalid_parameter_value(
                "$LATEST is not supported for an alias pointing to more than 1 version",
            ));
        }
        check_target(func, f, v)?;
        if !(0.0..=1.0).contains(w) {
            return Err(errors::invalid_parameter_value("Weight must be between 0.0 and 1.0"));
        }
    }
    Ok(())
}

impl Lambda {
    pub async fn create_alias(
        &self,
        ctx: &RequestContext,
        input: types::CreateAliasRequest,
    ) -> Result<types::AliasConfiguration, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, None)?;
        self.authorize_function(ctx, "lambda:CreateAlias", &f, ConditionContext::new())?;
        if input.name.bytes().all(|b| b.is_ascii_digit()) || input.name == "$LATEST" {
            return Err(errors::invalid_parameter_value(format!("Invalid alias name: {}", input.name)));
        }
        let mut st = self.write();
        let func = Self::function_mut(&mut st, &f)?;
        check_target(func, &f, &input.function_version)?;
        check_routing(func, &f, &input.function_version, input.routing_config.as_ref())?;
        let arn = format!("{}:{}", f.arn(), input.name);
        if func.aliases.contains_key(&input.name) {
            return Err(errors::resource_conflict(format!("Alias already exists: {arn}")));
        }
        let alias = types::AliasConfiguration {
            alias_arn: Some(arn),
            name: Some(input.name.clone()),
            function_version: Some(input.function_version),
            description: Some(input.description.unwrap_or_default()),
            routing_config: input.routing_config,
            revision_id: Some(revision_id()),
        };
        func.aliases.insert(input.name, alias.clone());
        Ok(alias)
    }

    fn alias_ref(ctx: &RequestContext, function_name: &str, alias: &str) -> Result<FunctionRef, ServiceError> {
        let f = names::parse_function(ctx, function_name, None)?;
        Ok(FunctionRef { qualifier: Some(alias.to_string()), ..f })
    }

    fn alias_not_found(f: &FunctionRef) -> ServiceError {
        errors::resource_not_found(format!("Cannot find alias arn: {}", f.qualified_arn()))
    }

    pub async fn get_alias(
        &self,
        ctx: &RequestContext,
        input: types::GetAliasRequest,
    ) -> Result<types::AliasConfiguration, ServiceError> {
        let f = Self::alias_ref(ctx, &input.function_name, &input.name)?;
        self.authorize_function(ctx, "lambda:GetAlias", &f, ConditionContext::new())?;
        let st = self.read();
        let func = Self::function(&st, &f)?;
        func.aliases.get(&input.name).cloned().ok_or_else(|| Self::alias_not_found(&f))
    }

    pub async fn update_alias(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAliasRequest,
    ) -> Result<types::AliasConfiguration, ServiceError> {
        let f = Self::alias_ref(ctx, &input.function_name, &input.name)?;
        self.authorize_function(ctx, "lambda:UpdateAlias", &f, ConditionContext::new())?;
        let mut st = self.write();
        let func = Self::function_mut(&mut st, &f)?;
        let current = func.aliases.get(&input.name).cloned().ok_or_else(|| Self::alias_not_found(&f))?;
        check_revision(current.revision_id.as_deref(), input.revision_id.as_deref())?;
        let version = input.function_version.clone().or(current.function_version.clone()).unwrap_or_default();
        check_target(func, &f, &version)?;
        let routing = input.routing_config.clone().or(current.routing_config.clone());
        check_routing(func, &f, &version, routing.as_ref())?;
        let alias = types::AliasConfiguration {
            function_version: Some(version),
            description: input.description.or(current.description.clone()),
            routing_config: routing,
            revision_id: Some(revision_id()),
            ..current
        };
        func.aliases.insert(input.name, alias.clone());
        drop(st);
        self.inner.runtimes.retire(&f.arn());
        Ok(alias)
    }

    pub async fn delete_alias(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAliasRequest,
    ) -> Result<(), ServiceError> {
        let f = Self::alias_ref(ctx, &input.function_name, &input.name)?;
        self.authorize_function(ctx, "lambda:DeleteAlias", &f, ConditionContext::new())?;
        let mut st = self.write();
        let func = Self::function_mut(&mut st, &f)?;
        // Deleting an alias that does not exist succeeds, as in Lambda.
        if func.aliases.remove(&input.name).is_some() {
            func.policies.remove(&input.name);
            func.event_invoke_configs.remove(&input.name);
            func.url_configs.remove(&input.name);
            func.provisioned.remove(&input.name);
        }
        Ok(())
    }

    pub async fn list_aliases(
        &self,
        ctx: &RequestContext,
        input: types::ListAliasesRequest,
    ) -> Result<types::ListAliasesResponse, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, None)?;
        self.authorize_function(ctx, "lambda:ListAliases", &f, ConditionContext::new())?;
        let st = self.read();
        let func = Self::function(&st, &f)?;
        let items: Vec<types::AliasConfiguration> = func
            .aliases
            .values()
            .filter(|a| {
                input.function_version.is_none()
                    || a.function_version == input.function_version
                    || a.routing_config
                        .as_ref()
                        .and_then(|r| r.additional_version_weights.as_ref())
                        .zip(input.function_version.as_ref())
                        .is_some_and(|(w, v)| w.contains_key(v))
            })
            .cloned()
            .collect();
        let (page, next) = paginate(&items, input.marker.as_deref(), input.max_items, 50);
        Ok(types::ListAliasesResponse { aliases: Some(page), next_marker: next })
    }
}

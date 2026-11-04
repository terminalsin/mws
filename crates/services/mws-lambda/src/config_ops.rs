//! Function settings and the smaller resources: concurrency, account
//! settings, tags, asynchronous invocation configs, function URLs,
//! provisioned concurrency, recursion and runtime management settings,
//! code signing configs and event source mappings.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::functions::{paginate, tag_context, timestamp};
use crate::generated::{errors, types};
use crate::names::{self, FunctionRef};
use crate::state::{CodeSigningConfig, EventSourceMapping, Provisioned, RuntimeManagement};
use crate::Lambda;

const ACCOUNT_CONCURRENCY: i32 = 1000;
const MIN_UNRESERVED: i32 = 100;

fn qualifier_key(f: &FunctionRef) -> String {
    f.qualifier.clone().unwrap_or_else(|| "$LATEST".into())
}

fn random_hex(n: usize) -> String {
    uuid::Uuid::new_v4().simple().to_string()[..n].to_string()
}

impl Lambda {
    // ---- concurrency and account settings ----------------------------------

    pub async fn put_function_concurrency(
        &self,
        ctx: &RequestContext,
        input: types::PutFunctionConcurrencyRequest,
    ) -> Result<types::Concurrency, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, None)?;
        self.authorize_function(ctx, "lambda:PutFunctionConcurrency", &f, ConditionContext::new())?;
        let mut st = self.write();
        let others: i32 = st
            .functions
            .values()
            .filter(|x| x.account_id == f.account && x.region == f.region && x.arn != f.arn())
            .filter_map(|x| x.reserved_concurrency)
            .sum();
        if ACCOUNT_CONCURRENCY - others - input.reserved_concurrent_executions < MIN_UNRESERVED {
            return Err(errors::invalid_parameter_value(format!(
                "Specified ReservedConcurrentExecutions for function decreases account's UnreservedConcurrentExecution below its minimum value of [{MIN_UNRESERVED}]."
            )));
        }
        let func = Self::function_mut(&mut st, &f)?;
        func.reserved_concurrency = Some(input.reserved_concurrent_executions);
        Ok(types::Concurrency { reserved_concurrent_executions: Some(input.reserved_concurrent_executions) })
    }

    pub async fn get_function_concurrency(
        &self,
        ctx: &RequestContext,
        input: types::GetFunctionConcurrencyRequest,
    ) -> Result<types::GetFunctionConcurrencyResponse, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, None)?;
        self.authorize_function(ctx, "lambda:GetFunctionConcurrency", &f, ConditionContext::new())?;
        let st = self.read();
        let func = Self::function(&st, &f)?;
        Ok(types::GetFunctionConcurrencyResponse { reserved_concurrent_executions: func.reserved_concurrency })
    }

    pub async fn delete_function_concurrency(
        &self,
        ctx: &RequestContext,
        input: types::DeleteFunctionConcurrencyRequest,
    ) -> Result<(), ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, None)?;
        self.authorize_function(ctx, "lambda:DeleteFunctionConcurrency", &f, ConditionContext::new())?;
        let mut st = self.write();
        Self::function_mut(&mut st, &f)?.reserved_concurrency = None;
        Ok(())
    }

    pub async fn get_account_settings(
        &self,
        ctx: &RequestContext,
        _input: types::GetAccountSettingsRequest,
    ) -> Result<types::GetAccountSettingsResponse, ServiceError> {
        ctx.authorize("lambda:GetAccountSettings", "*", ConditionContext::new())?;
        let account = names::account_of(ctx);
        let st = self.read();
        let funcs: Vec<_> =
            st.functions.values().filter(|f| f.account_id == account && f.region == ctx.region).collect();
        let reserved: i32 = funcs.iter().filter_map(|f| f.reserved_concurrency).sum();
        let total_code: i64 = funcs
            .iter()
            .flat_map(|f| std::iter::once(&f.latest).chain(f.versions.values()))
            .map(|v| v.config.code_size)
            .sum();
        Ok(types::GetAccountSettingsResponse {
            account_limit: Some(types::AccountLimit {
                total_code_size: 80_530_636_800,
                code_size_unzipped: 262_144_000,
                code_size_zipped: 52_428_800,
                concurrent_executions: ACCOUNT_CONCURRENCY,
                unreserved_concurrent_executions: Some(ACCOUNT_CONCURRENCY - reserved),
            }),
            account_usage: Some(types::AccountUsage {
                total_code_size: total_code,
                function_count: funcs.len() as i64,
            }),
        })
    }

    // ---- tags --------------------------------------------------------------

    /// The tags of a taggable resource ARN, for reading or writing.
    fn with_tags<R>(
        &self,
        resource: &str,
        f: impl FnOnce(&mut std::collections::BTreeMap<String, String>) -> R,
    ) -> Result<R, ServiceError> {
        let mut st = self.write();
        if let Some(func) = st.functions.get_mut(resource) {
            return Ok(f(&mut func.tags));
        }
        if let Some(c) = st.code_signing_configs.get_mut(resource) {
            return Ok(f(&mut c.tags));
        }
        if let Some(m) = st
            .event_source_mappings
            .values_mut()
            .find(|m| m.config.event_source_mapping_arn.as_deref() == Some(resource))
        {
            return Ok(f(&mut m.tags));
        }
        if resource.contains(":function:") && resource.split(':').count() > 7 {
            return Err(errors::invalid_parameter_value(
                "Tags on function aliases and versions are not supported. Please specify a function ARN.",
            ));
        }
        Err(errors::resource_not_found(format!("Function not found: {resource}")))
    }

    pub async fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<(), ServiceError> {
        ctx.authorize("lambda:TagResource", &input.resource, tag_context(&input.tags))?;
        let tags = input.tags;
        self.with_tags(&input.resource, |t| {
            if t.len() + tags.keys().filter(|k| !t.contains_key(*k)).count() > 50 {
                return Err(errors::invalid_parameter_value("Number of tags exceeds resource tag limit."));
            }
            t.extend(tags);
            Ok(())
        })?
    }

    pub async fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<(), ServiceError> {
        let mut c = ConditionContext::new();
        c.insert("aws:TagKeys".into(), input.tag_keys.clone());
        ctx.authorize("lambda:UntagResource", &input.resource, c)?;
        self.with_tags(&input.resource, |t| {
            for k in &input.tag_keys {
                t.remove(k);
            }
        })
    }

    pub async fn list_tags(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsRequest,
    ) -> Result<types::ListTagsResponse, ServiceError> {
        ctx.authorize("lambda:ListTags", &input.resource, ConditionContext::new())?;
        let tags = self.with_tags(&input.resource, |t| t.clone())?;
        Ok(types::ListTagsResponse { tags: Some(tags) })
    }

    // ---- asynchronous invocation configs -----------------------------------

    fn check_destinations(d: Option<&types::DestinationConfig>) -> Result<(), ServiceError> {
        let Some(d) = d else { return Ok(()) };
        for dest in [
            d.on_success.as_ref().and_then(|s| s.destination.as_ref()),
            d.on_failure.as_ref().and_then(|s| s.destination.as_ref()),
        ]
        .into_iter()
        .flatten()
        {
            let service = dest.split(':').nth(2).unwrap_or_default();
            if !matches!(service, "lambda" | "sqs" | "sns" | "events" | "s3") {
                return Err(errors::invalid_parameter_value(format!("The destination ARN {dest} is invalid.")));
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn put_invoke_config(
        &self,
        ctx: &RequestContext,
        function_name: &str,
        qualifier: Option<&str>,
        merge: bool,
        retries: Option<i32>,
        age: Option<i32>,
        destinations: Option<types::DestinationConfig>,
        action: &str,
    ) -> Result<types::FunctionEventInvokeConfig, ServiceError> {
        let f = names::parse_function(ctx, function_name, qualifier)?;
        self.authorize_function(ctx, action, &f, ConditionContext::new())?;
        Self::check_destinations(destinations.as_ref())?;
        let mut st = self.write();
        let func = Self::function_mut(&mut st, &f)?;
        let key = qualifier_key(&f);
        if !func.has_qualifier(&key) {
            return Err(f.not_found());
        }
        let existing = func.event_invoke_configs.get(&key).cloned();
        if merge && existing.is_none() {
            return Err(errors::resource_not_found(format!(
                "The function {} doesn't have an EventInvokeConfig",
                f.qualified_arn()
            )));
        }
        let base = if merge { existing.unwrap_or_default() } else { types::FunctionEventInvokeConfig::default() };
        let config = types::FunctionEventInvokeConfig {
            last_modified: Some(ctx.received_at),
            function_arn: Some(format!("{}:{key}", f.arn())),
            maximum_retry_attempts: retries.or(base.maximum_retry_attempts),
            maximum_event_age_in_seconds: age.or(base.maximum_event_age_in_seconds),
            destination_config: destinations.or(base.destination_config),
        };
        func.event_invoke_configs.insert(key, config.clone());
        Ok(config)
    }

    pub async fn put_function_event_invoke_config(
        &self,
        ctx: &RequestContext,
        input: types::PutFunctionEventInvokeConfigRequest,
    ) -> Result<types::FunctionEventInvokeConfig, ServiceError> {
        self.put_invoke_config(
            ctx,
            &input.function_name,
            input.qualifier.as_deref(),
            false,
            input.maximum_retry_attempts,
            input.maximum_event_age_in_seconds,
            input.destination_config,
            "lambda:PutFunctionEventInvokeConfig",
        )
    }

    pub async fn update_function_event_invoke_config(
        &self,
        ctx: &RequestContext,
        input: types::UpdateFunctionEventInvokeConfigRequest,
    ) -> Result<types::FunctionEventInvokeConfig, ServiceError> {
        self.put_invoke_config(
            ctx,
            &input.function_name,
            input.qualifier.as_deref(),
            true,
            input.maximum_retry_attempts,
            input.maximum_event_age_in_seconds,
            input.destination_config,
            "lambda:UpdateFunctionEventInvokeConfig",
        )
    }

    pub async fn get_function_event_invoke_config(
        &self,
        ctx: &RequestContext,
        input: types::GetFunctionEventInvokeConfigRequest,
    ) -> Result<types::FunctionEventInvokeConfig, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, input.qualifier.as_deref())?;
        self.authorize_function(ctx, "lambda:GetFunctionEventInvokeConfig", &f, ConditionContext::new())?;
        let st = self.read();
        let func = Self::function(&st, &f)?;
        func.event_invoke_configs.get(&qualifier_key(&f)).cloned().ok_or_else(|| {
            errors::resource_not_found(format!("The function {} doesn't have an EventInvokeConfig", f.qualified_arn()))
        })
    }

    pub async fn delete_function_event_invoke_config(
        &self,
        ctx: &RequestContext,
        input: types::DeleteFunctionEventInvokeConfigRequest,
    ) -> Result<(), ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, input.qualifier.as_deref())?;
        self.authorize_function(ctx, "lambda:DeleteFunctionEventInvokeConfig", &f, ConditionContext::new())?;
        let mut st = self.write();
        let func = Self::function_mut(&mut st, &f)?;
        func.event_invoke_configs.remove(&qualifier_key(&f)).map(|_| ()).ok_or_else(|| {
            errors::resource_not_found(format!("The function {} doesn't have an EventInvokeConfig", f.qualified_arn()))
        })
    }

    pub async fn list_function_event_invoke_configs(
        &self,
        ctx: &RequestContext,
        input: types::ListFunctionEventInvokeConfigsRequest,
    ) -> Result<types::ListFunctionEventInvokeConfigsResponse, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, None)?;
        self.authorize_function(ctx, "lambda:ListFunctionEventInvokeConfigs", &f, ConditionContext::new())?;
        let st = self.read();
        let items: Vec<_> = Self::function(&st, &f)?.event_invoke_configs.values().cloned().collect();
        let (page, next) = paginate(&items, input.marker.as_deref(), input.max_items, 50);
        Ok(types::ListFunctionEventInvokeConfigsResponse {
            function_event_invoke_configs: Some(page),
            next_marker: next,
        })
    }

    // ---- function URLs -----------------------------------------------------

    fn url_not_found() -> ServiceError {
        errors::resource_not_found("The resource you requested does not exist.")
    }

    pub async fn create_function_url_config(
        &self,
        ctx: &RequestContext,
        input: types::CreateFunctionUrlConfigRequest,
    ) -> Result<types::CreateFunctionUrlConfigResponse, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, input.qualifier.as_deref())?;
        let mut c = ConditionContext::new();
        c.insert("lambda:FunctionUrlAuthType".into(), vec![input.auth_type.clone()]);
        self.authorize_function(ctx, "lambda:CreateFunctionUrlConfig", &f, c)?;
        if f.qualifier.as_deref().is_some_and(|q| q == "$LATEST" || q.bytes().all(|b| b.is_ascii_digit())) {
            return Err(errors::invalid_parameter_value(
                "Function URLs can only be attached to the unqualified function or an alias.",
            ));
        }
        let mut st = self.write();
        let func = Self::function_mut(&mut st, &f)?;
        let key = f.qualifier.clone().unwrap_or_default();
        if !key.is_empty() && !func.aliases.contains_key(&key) {
            return Err(f.not_found());
        }
        if func.url_configs.contains_key(&key) {
            return Err(errors::resource_conflict(format!(
                "Failed to create function url config for [functionArn = {}]. Error message:  FunctionUrlConfig exists for this Lambda function",
                f.qualified_arn()
            )));
        }
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
        let url = format!("https://{}.lambda-url.{}.on.aws/", random_hex(32), f.region);
        let config = types::FunctionUrlConfig {
            function_url: url,
            function_arn: f.qualified_arn(),
            creation_time: now.clone(),
            last_modified_time: now,
            cors: input.cors.clone(),
            auth_type: input.auth_type.clone(),
            invoke_mode: Some(input.invoke_mode.clone().unwrap_or_else(|| "BUFFERED".into())),
        };
        func.url_configs.insert(key, config.clone());
        Ok(types::CreateFunctionUrlConfigResponse {
            function_url: config.function_url,
            function_arn: config.function_arn,
            auth_type: config.auth_type,
            cors: config.cors,
            creation_time: config.creation_time,
            invoke_mode: config.invoke_mode,
        })
    }

    pub async fn get_function_url_config(
        &self,
        ctx: &RequestContext,
        input: types::GetFunctionUrlConfigRequest,
    ) -> Result<types::GetFunctionUrlConfigResponse, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, input.qualifier.as_deref())?;
        self.authorize_function(ctx, "lambda:GetFunctionUrlConfig", &f, ConditionContext::new())?;
        let st = self.read();
        let c = Self::function(&st, &f)?
            .url_configs
            .get(f.qualifier.as_deref().unwrap_or(""))
            .cloned()
            .ok_or_else(Self::url_not_found)?;
        Ok(types::GetFunctionUrlConfigResponse {
            function_url: c.function_url,
            function_arn: c.function_arn,
            auth_type: c.auth_type,
            cors: c.cors,
            creation_time: c.creation_time,
            last_modified_time: c.last_modified_time,
            invoke_mode: c.invoke_mode,
        })
    }

    pub async fn update_function_url_config(
        &self,
        ctx: &RequestContext,
        input: types::UpdateFunctionUrlConfigRequest,
    ) -> Result<types::UpdateFunctionUrlConfigResponse, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, input.qualifier.as_deref())?;
        self.authorize_function(ctx, "lambda:UpdateFunctionUrlConfig", &f, ConditionContext::new())?;
        let mut st = self.write();
        let func = Self::function_mut(&mut st, &f)?;
        let c = func.url_configs.get_mut(f.qualifier.as_deref().unwrap_or("")).ok_or_else(Self::url_not_found)?;
        if let Some(a) = input.auth_type {
            c.auth_type = a;
        }
        if let Some(cors) = input.cors {
            c.cors = Some(cors);
        }
        if let Some(m) = input.invoke_mode {
            c.invoke_mode = Some(m);
        }
        c.last_modified_time = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string();
        let c = c.clone();
        Ok(types::UpdateFunctionUrlConfigResponse {
            function_url: c.function_url,
            function_arn: c.function_arn,
            auth_type: c.auth_type,
            cors: c.cors,
            creation_time: c.creation_time,
            last_modified_time: c.last_modified_time,
            invoke_mode: c.invoke_mode,
        })
    }

    pub async fn delete_function_url_config(
        &self,
        ctx: &RequestContext,
        input: types::DeleteFunctionUrlConfigRequest,
    ) -> Result<(), ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, input.qualifier.as_deref())?;
        self.authorize_function(ctx, "lambda:DeleteFunctionUrlConfig", &f, ConditionContext::new())?;
        let mut st = self.write();
        let func = Self::function_mut(&mut st, &f)?;
        func.url_configs.remove(f.qualifier.as_deref().unwrap_or("")).map(|_| ()).ok_or_else(Self::url_not_found)
    }

    pub async fn list_function_url_configs(
        &self,
        ctx: &RequestContext,
        input: types::ListFunctionUrlConfigsRequest,
    ) -> Result<types::ListFunctionUrlConfigsResponse, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, None)?;
        self.authorize_function(ctx, "lambda:ListFunctionUrlConfigs", &f, ConditionContext::new())?;
        let st = self.read();
        let items: Vec<_> = Self::function(&st, &f)?.url_configs.values().cloned().collect();
        let (page, next) = paginate(&items, input.marker.as_deref(), input.max_items, 50);
        Ok(types::ListFunctionUrlConfigsResponse { function_url_configs: page, next_marker: next })
    }

    // ---- provisioned concurrency -------------------------------------------

    fn provisioned_not_found(f: &FunctionRef) -> ServiceError {
        errors::provisioned_concurrency_config_not_found(format!(
            "No Provisioned Concurrency Config found for this function: {}",
            f.qualified_arn()
        ))
    }

    pub async fn put_provisioned_concurrency_config(
        &self,
        ctx: &RequestContext,
        input: types::PutProvisionedConcurrencyConfigRequest,
    ) -> Result<types::PutProvisionedConcurrencyConfigResponse, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, Some(&input.qualifier))?;
        self.authorize_function(ctx, "lambda:PutProvisionedConcurrencyConfig", &f, ConditionContext::new())?;
        if input.qualifier == "$LATEST" {
            return Err(errors::invalid_parameter_value(
                "Provisioned Concurrency Configs cannot be applied to unpublished function versions.",
            ));
        }
        let mut st = self.write();
        let func = Self::function_mut(&mut st, &f)?;
        if !func.has_qualifier(&input.qualifier) {
            return Err(f.not_found());
        }
        let now = timestamp(ctx.received_at);
        func.provisioned.insert(
            input.qualifier.clone(),
            Provisioned { requested: input.provisioned_concurrent_executions, last_modified: now.clone() },
        );
        Ok(types::PutProvisionedConcurrencyConfigResponse {
            requested_provisioned_concurrent_executions: Some(input.provisioned_concurrent_executions),
            allocated_provisioned_concurrent_executions: Some(0),
            available_provisioned_concurrent_executions: Some(0),
            status: Some("IN_PROGRESS".into()),
            status_reason: None,
            last_modified: Some(now),
        })
    }

    pub async fn get_provisioned_concurrency_config(
        &self,
        ctx: &RequestContext,
        input: types::GetProvisionedConcurrencyConfigRequest,
    ) -> Result<types::GetProvisionedConcurrencyConfigResponse, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, Some(&input.qualifier))?;
        self.authorize_function(ctx, "lambda:GetProvisionedConcurrencyConfig", &f, ConditionContext::new())?;
        let st = self.read();
        let p = Self::function(&st, &f)?
            .provisioned
            .get(&input.qualifier)
            .cloned()
            .ok_or_else(|| Self::provisioned_not_found(&f))?;
        Ok(types::GetProvisionedConcurrencyConfigResponse {
            requested_provisioned_concurrent_executions: Some(p.requested),
            available_provisioned_concurrent_executions: Some(p.requested),
            allocated_provisioned_concurrent_executions: Some(p.requested),
            status: Some("READY".into()),
            status_reason: None,
            last_modified: Some(p.last_modified),
        })
    }

    pub async fn delete_provisioned_concurrency_config(
        &self,
        ctx: &RequestContext,
        input: types::DeleteProvisionedConcurrencyConfigRequest,
    ) -> Result<(), ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, Some(&input.qualifier))?;
        self.authorize_function(ctx, "lambda:DeleteProvisionedConcurrencyConfig", &f, ConditionContext::new())?;
        let mut st = self.write();
        let func = Self::function_mut(&mut st, &f)?;
        func.provisioned.remove(&input.qualifier).map(|_| ()).ok_or_else(|| Self::provisioned_not_found(&f))
    }

    pub async fn list_provisioned_concurrency_configs(
        &self,
        ctx: &RequestContext,
        input: types::ListProvisionedConcurrencyConfigsRequest,
    ) -> Result<types::ListProvisionedConcurrencyConfigsResponse, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, None)?;
        self.authorize_function(ctx, "lambda:ListProvisionedConcurrencyConfigs", &f, ConditionContext::new())?;
        let st = self.read();
        let func = Self::function(&st, &f)?;
        let items: Vec<_> = func
            .provisioned
            .iter()
            .map(|(q, p)| types::ProvisionedConcurrencyConfigListItem {
                function_arn: Some(format!("{}:{q}", func.arn)),
                requested_provisioned_concurrent_executions: Some(p.requested),
                available_provisioned_concurrent_executions: Some(p.requested),
                allocated_provisioned_concurrent_executions: Some(p.requested),
                status: Some("READY".into()),
                status_reason: None,
                last_modified: Some(p.last_modified.clone()),
            })
            .collect();
        let (page, next) = paginate(&items, input.marker.as_deref(), input.max_items, 50);
        Ok(types::ListProvisionedConcurrencyConfigsResponse {
            provisioned_concurrency_configs: Some(page),
            next_marker: next,
        })
    }

    // ---- recursion and runtime management ----------------------------------

    pub async fn get_function_recursion_config(
        &self,
        ctx: &RequestContext,
        input: types::GetFunctionRecursionConfigRequest,
    ) -> Result<types::GetFunctionRecursionConfigResponse, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, None)?;
        self.authorize_function(ctx, "lambda:GetFunctionRecursionConfig", &f, ConditionContext::new())?;
        let st = self.read();
        let func = Self::function(&st, &f)?;
        Ok(types::GetFunctionRecursionConfigResponse {
            recursive_loop: Some(func.recursive_loop.clone().unwrap_or_else(|| "Terminate".into())),
        })
    }

    pub async fn put_function_recursion_config(
        &self,
        ctx: &RequestContext,
        input: types::PutFunctionRecursionConfigRequest,
    ) -> Result<types::PutFunctionRecursionConfigResponse, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, None)?;
        self.authorize_function(ctx, "lambda:PutFunctionRecursionConfig", &f, ConditionContext::new())?;
        let mut st = self.write();
        Self::function_mut(&mut st, &f)?.recursive_loop = Some(input.recursive_loop.clone());
        Ok(types::PutFunctionRecursionConfigResponse { recursive_loop: Some(input.recursive_loop) })
    }

    pub async fn get_runtime_management_config(
        &self,
        ctx: &RequestContext,
        input: types::GetRuntimeManagementConfigRequest,
    ) -> Result<types::GetRuntimeManagementConfigResponse, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, input.qualifier.as_deref())?;
        self.authorize_function(ctx, "lambda:GetRuntimeManagementConfig", &f, ConditionContext::new())?;
        let st = self.read();
        let func = Self::function(&st, &f)?;
        if func.version_for(f.qualifier.as_deref()).is_none() {
            return Err(f.not_found());
        }
        let r = func.runtime_management.get(&qualifier_key(&f)).cloned().unwrap_or_default();
        Ok(types::GetRuntimeManagementConfigResponse {
            update_runtime_on: Some(if r.update_runtime_on.is_empty() { "Auto".into() } else { r.update_runtime_on }),
            function_arn: Some(f.arn()),
            runtime_version_arn: r.runtime_version_arn,
        })
    }

    pub async fn put_runtime_management_config(
        &self,
        ctx: &RequestContext,
        input: types::PutRuntimeManagementConfigRequest,
    ) -> Result<types::PutRuntimeManagementConfigResponse, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, input.qualifier.as_deref())?;
        self.authorize_function(ctx, "lambda:PutRuntimeManagementConfig", &f, ConditionContext::new())?;
        if input.update_runtime_on == "Manual" && input.runtime_version_arn.is_none() {
            return Err(errors::invalid_parameter_value(
                "RuntimeVersionArn must be provided when UpdateRuntimeOn is Manual.",
            ));
        }
        if input.update_runtime_on != "Manual" && input.runtime_version_arn.is_some() {
            return Err(errors::invalid_parameter_value(
                "RuntimeVersionArn can only be provided when UpdateRuntimeOn is Manual.",
            ));
        }
        let mut st = self.write();
        let func = Self::function_mut(&mut st, &f)?;
        func.runtime_management.insert(
            qualifier_key(&f),
            RuntimeManagement {
                update_runtime_on: input.update_runtime_on.clone(),
                runtime_version_arn: input.runtime_version_arn.clone(),
            },
        );
        Ok(types::PutRuntimeManagementConfigResponse {
            update_runtime_on: input.update_runtime_on,
            function_arn: f.qualified_arn(),
            runtime_version_arn: input.runtime_version_arn,
        })
    }

    // ---- code signing configs ----------------------------------------------

    fn csc_not_found(arn: &str) -> ServiceError {
        errors::resource_not_found(format!("The code signing configuration cannot be found. Check that the provided configuration is not deleted: {arn}."))
    }

    pub async fn create_code_signing_config(
        &self,
        ctx: &RequestContext,
        input: types::CreateCodeSigningConfigRequest,
    ) -> Result<types::CreateCodeSigningConfigResponse, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        ctx.authorize("lambda:CreateCodeSigningConfig", "*", tag_context(&tags))?;
        let id = format!("csc-{}", random_hex(17));
        let account = names::account_of(ctx);
        let arn = format!("arn:{}:lambda:{}:{account}:code-signing-config:{id}", ctx.partition, ctx.region);
        let config = types::CodeSigningConfig {
            code_signing_config_id: id,
            code_signing_config_arn: arn.clone(),
            description: Some(input.description.unwrap_or_default()),
            allowed_publishers: input.allowed_publishers,
            code_signing_policies: input
                .code_signing_policies
                .unwrap_or(types::CodeSigningPolicies { untrusted_artifact_on_deployment: Some("Warn".into()) }),
            last_modified: timestamp(ctx.received_at),
        };
        self.write()
            .code_signing_configs
            .insert(arn, CodeSigningConfig { account_id: account, config: config.clone(), tags });
        Ok(types::CreateCodeSigningConfigResponse { code_signing_config: config })
    }

    pub async fn get_code_signing_config(
        &self,
        ctx: &RequestContext,
        input: types::GetCodeSigningConfigRequest,
    ) -> Result<types::GetCodeSigningConfigResponse, ServiceError> {
        ctx.authorize("lambda:GetCodeSigningConfig", &input.code_signing_config_arn, ConditionContext::new())?;
        let st = self.read();
        let c = st
            .code_signing_configs
            .get(&input.code_signing_config_arn)
            .ok_or_else(|| Self::csc_not_found(&input.code_signing_config_arn))?;
        Ok(types::GetCodeSigningConfigResponse { code_signing_config: c.config.clone() })
    }

    pub async fn update_code_signing_config(
        &self,
        ctx: &RequestContext,
        input: types::UpdateCodeSigningConfigRequest,
    ) -> Result<types::UpdateCodeSigningConfigResponse, ServiceError> {
        ctx.authorize("lambda:UpdateCodeSigningConfig", &input.code_signing_config_arn, ConditionContext::new())?;
        let mut st = self.write();
        let c = st
            .code_signing_configs
            .get_mut(&input.code_signing_config_arn)
            .ok_or_else(|| Self::csc_not_found(&input.code_signing_config_arn))?;
        if let Some(d) = input.description {
            c.config.description = Some(d);
        }
        if let Some(p) = input.allowed_publishers {
            c.config.allowed_publishers = p;
        }
        if let Some(p) = input.code_signing_policies {
            c.config.code_signing_policies = p;
        }
        c.config.last_modified = timestamp(ctx.received_at);
        Ok(types::UpdateCodeSigningConfigResponse { code_signing_config: c.config.clone() })
    }

    pub async fn delete_code_signing_config(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCodeSigningConfigRequest,
    ) -> Result<types::DeleteCodeSigningConfigResponse, ServiceError> {
        ctx.authorize("lambda:DeleteCodeSigningConfig", &input.code_signing_config_arn, ConditionContext::new())?;
        let mut st = self.write();
        if st
            .functions
            .values()
            .any(|f| f.code_signing_config_arn.as_deref() == Some(input.code_signing_config_arn.as_str()))
        {
            return Err(errors::resource_conflict(
                "The code signing configuration is in use by one or more functions.",
            ));
        }
        st.code_signing_configs
            .remove(&input.code_signing_config_arn)
            .map(|_| types::DeleteCodeSigningConfigResponse {})
            .ok_or_else(|| Self::csc_not_found(&input.code_signing_config_arn))
    }

    pub async fn list_code_signing_configs(
        &self,
        ctx: &RequestContext,
        input: types::ListCodeSigningConfigsRequest,
    ) -> Result<types::ListCodeSigningConfigsResponse, ServiceError> {
        ctx.authorize("lambda:ListCodeSigningConfigs", "*", ConditionContext::new())?;
        let account = names::account_of(ctx);
        let st = self.read();
        let items: Vec<_> =
            st.code_signing_configs.values().filter(|c| c.account_id == account).map(|c| c.config.clone()).collect();
        let (page, next) = paginate(&items, input.marker.as_deref(), input.max_items, 50);
        Ok(types::ListCodeSigningConfigsResponse { code_signing_configs: Some(page), next_marker: next })
    }

    pub async fn put_function_code_signing_config(
        &self,
        ctx: &RequestContext,
        input: types::PutFunctionCodeSigningConfigRequest,
    ) -> Result<types::PutFunctionCodeSigningConfigResponse, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, None)?;
        let mut c = ConditionContext::new();
        c.insert("lambda:CodeSigningConfigArn".into(), vec![input.code_signing_config_arn.clone()]);
        self.authorize_function(ctx, "lambda:PutFunctionCodeSigningConfig", &f, c)?;
        let mut st = self.write();
        if !st.code_signing_configs.contains_key(&input.code_signing_config_arn) {
            return Err(errors::code_signing_config_not_found(format!(
                "The code signing configuration cannot be found. Check that the provided configuration is not deleted: {}.",
                input.code_signing_config_arn
            )));
        }
        Self::function_mut(&mut st, &f)?.code_signing_config_arn = Some(input.code_signing_config_arn.clone());
        Ok(types::PutFunctionCodeSigningConfigResponse {
            code_signing_config_arn: input.code_signing_config_arn,
            function_name: f.name,
        })
    }

    pub async fn get_function_code_signing_config(
        &self,
        ctx: &RequestContext,
        input: types::GetFunctionCodeSigningConfigRequest,
    ) -> Result<types::GetFunctionCodeSigningConfigResponse, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, None)?;
        self.authorize_function(ctx, "lambda:GetFunctionCodeSigningConfig", &f, ConditionContext::new())?;
        let st = self.read();
        let func = Self::function(&st, &f)?;
        Ok(types::GetFunctionCodeSigningConfigResponse {
            code_signing_config_arn: func.code_signing_config_arn.clone().unwrap_or_default(),
            function_name: f.name.clone(),
        })
    }

    pub async fn delete_function_code_signing_config(
        &self,
        ctx: &RequestContext,
        input: types::DeleteFunctionCodeSigningConfigRequest,
    ) -> Result<(), ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, None)?;
        self.authorize_function(ctx, "lambda:DeleteFunctionCodeSigningConfig", &f, ConditionContext::new())?;
        let mut st = self.write();
        Self::function_mut(&mut st, &f)?.code_signing_config_arn = None;
        Ok(())
    }

    pub async fn list_functions_by_code_signing_config(
        &self,
        ctx: &RequestContext,
        input: types::ListFunctionsByCodeSigningConfigRequest,
    ) -> Result<types::ListFunctionsByCodeSigningConfigResponse, ServiceError> {
        ctx.authorize(
            "lambda:ListFunctionsByCodeSigningConfig",
            &input.code_signing_config_arn,
            ConditionContext::new(),
        )?;
        let st = self.read();
        if !st.code_signing_configs.contains_key(&input.code_signing_config_arn) {
            return Err(Self::csc_not_found(&input.code_signing_config_arn));
        }
        let items: Vec<String> = st
            .functions
            .values()
            .filter(|f| f.code_signing_config_arn.as_deref() == Some(input.code_signing_config_arn.as_str()))
            .map(|f| f.arn.clone())
            .collect();
        let (page, next) = paginate(&items, input.marker.as_deref(), input.max_items, 50);
        Ok(types::ListFunctionsByCodeSigningConfigResponse { function_arns: Some(page), next_marker: next })
    }

    // ---- event source mappings ---------------------------------------------

    fn esm_not_found(uuid: &str) -> ServiceError {
        errors::resource_not_found(format!(
            "The resource you requested does not exist. (Service: Lambda, Status Code: 404, Request ID: {uuid})"
        ))
    }

    pub async fn create_event_source_mapping(
        &self,
        ctx: &RequestContext,
        input: types::CreateEventSourceMappingRequest,
    ) -> Result<types::EventSourceMappingConfiguration, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, None)?;
        let mut c = tag_context(&input.tags.clone().unwrap_or_default());
        c.insert("lambda:FunctionArn".into(), vec![f.qualified_arn()]);
        ctx.authorize("lambda:CreateEventSourceMapping", "*", c)?;
        {
            let st = self.read();
            let func = Self::function(&st, &f)?;
            if let Some(q) = &f.qualifier {
                if !func.has_qualifier(q) {
                    return Err(f.not_found());
                }
            }
        }
        crate::esm::compile_filters(input.filter_criteria.as_ref())?;
        let sqs_source = input.event_source_arn.as_deref().filter(|a| a.split(':').nth(2) == Some("sqs"));
        let batch_size = input.batch_size.unwrap_or(if sqs_source.is_some() { 10 } else { 100 });
        if let Some(queue) = sqs_source {
            let window = input.maximum_batching_window_in_seconds.unwrap_or(0);
            self.check_queue_source(ctx, queue, &f.qualified_arn(), batch_size, window)?;
        }
        if let Some(stream) = input.event_source_arn.as_deref().filter(|a| crate::esm_stream::is_kinesis(a)) {
            if !(1..=10_000).contains(&batch_size) {
                return Err(errors::invalid_parameter_value(
                    "BatchSize must be between 1 and 10000 for Kinesis event sources.",
                ));
            }
            self.check_stream_source(
                ctx,
                stream,
                &f.qualified_arn(),
                input.starting_position.as_deref(),
                input.starting_position_timestamp,
            )?;
        }
        if let Some(source) = input.event_source_arn.as_deref() {
            let st = self.read();
            let existing = st.event_source_mappings.iter().find(|(_, m)| {
                m.config.event_source_arn.as_deref() == Some(source)
                    && m.config.function_arn.as_deref() == Some(f.qualified_arn().as_str())
            });
            if let Some((uuid, _)) = existing {
                return Err(errors::resource_conflict(format!(
                    "The event source arn (\" {source} \") and function (\" {} \") provided mapping already exists. Please update or delete the existing mapping with UUID {uuid}",
                    input.function_name
                )));
            }
        }
        let uuid = uuid::Uuid::new_v4().to_string();
        let account = names::account_of(ctx);
        let enabled = input.enabled.unwrap_or(true);
        let config = types::EventSourceMappingConfiguration {
            uuid: Some(uuid.clone()),
            starting_position: input.starting_position,
            starting_position_timestamp: input.starting_position_timestamp,
            batch_size: Some(batch_size),
            maximum_batching_window_in_seconds: Some(input.maximum_batching_window_in_seconds.unwrap_or(0)),
            parallelization_factor: input.parallelization_factor,
            event_source_arn: input.event_source_arn,
            filter_criteria: input.filter_criteria,
            kms_key_arn: input.kms_key_arn,
            metrics_config: input.metrics_config,
            logging_config: input.logging_config,
            scaling_config: input.scaling_config,
            function_arn: Some(f.qualified_arn()),
            last_modified: Some(ctx.received_at),
            last_processing_result: Some("No records processed".into()),
            state: Some(if enabled { "Creating".into() } else { "Disabled".into() }),
            state_transition_reason: Some("USER_INITIATED".into()),
            destination_config: input.destination_config,
            topics: input.topics,
            queues: input.queues,
            source_access_configurations: input.source_access_configurations,
            self_managed_event_source: input.self_managed_event_source,
            maximum_record_age_in_seconds: input.maximum_record_age_in_seconds,
            bisect_batch_on_function_error: input.bisect_batch_on_function_error,
            maximum_retry_attempts: input.maximum_retry_attempts,
            tumbling_window_in_seconds: input.tumbling_window_in_seconds,
            function_response_types: input.function_response_types,
            amazon_managed_kafka_event_source_config: input.amazon_managed_kafka_event_source_config,
            self_managed_kafka_event_source_config: input.self_managed_kafka_event_source_config,
            document_db_event_source_config: input.document_db_event_source_config,
            event_source_mapping_arn: Some(format!(
                "arn:{}:lambda:{}:{account}:event-source-mapping:{uuid}",
                ctx.partition, ctx.region
            )),
            provisioned_poller_config: input.provisioned_poller_config,
            ..Default::default()
        };
        let mut stored = config.clone();
        stored.state = Some(if enabled { "Enabled".into() } else { "Disabled".into() });
        self.write().event_source_mappings.insert(
            uuid,
            EventSourceMapping {
                account_id: account,
                region: ctx.region.clone(),
                config: stored,
                tags: input.tags.unwrap_or_default(),
                shards: Default::default(),
                created: Some(ctx.received_at),
            },
        );
        Ok(config)
    }

    pub async fn get_event_source_mapping(
        &self,
        ctx: &RequestContext,
        input: types::GetEventSourceMappingRequest,
    ) -> Result<types::EventSourceMappingConfiguration, ServiceError> {
        let arn = self.esm_arn(&input.uuid)?;
        ctx.authorize("lambda:GetEventSourceMapping", &arn, ConditionContext::new())?;
        let st = self.read();
        st.event_source_mappings
            .get(&input.uuid)
            .map(|m| m.config.clone())
            .ok_or_else(|| Self::esm_not_found(&input.uuid))
    }

    fn esm_arn(&self, uuid: &str) -> Result<String, ServiceError> {
        let st = self.read();
        st.event_source_mappings
            .get(uuid)
            .and_then(|m| m.config.event_source_mapping_arn.clone())
            .ok_or_else(|| Self::esm_not_found(uuid))
    }

    pub async fn update_event_source_mapping(
        &self,
        ctx: &RequestContext,
        input: types::UpdateEventSourceMappingRequest,
    ) -> Result<types::EventSourceMappingConfiguration, ServiceError> {
        let arn = self.esm_arn(&input.uuid)?;
        ctx.authorize("lambda:UpdateEventSourceMapping", &arn, ConditionContext::new())?;
        let function_arn = match &input.function_name {
            Some(n) => {
                let f = names::parse_function(ctx, n, None)?;
                let st = self.read();
                Self::function(&st, &f)?;
                Some(f.qualified_arn())
            }
            None => None,
        };
        crate::esm::compile_filters(input.filter_criteria.as_ref())?;
        let current = {
            let st = self.read();
            st.event_source_mappings.get(&input.uuid).map(|m| m.config.clone())
        };
        if let Some(cur) = current {
            if let Some(queue) = cur.event_source_arn.as_deref().filter(|a| a.split(':').nth(2) == Some("sqs")) {
                let function = function_arn.clone().or(cur.function_arn.clone()).unwrap_or_default();
                let batch_size = input.batch_size.or(cur.batch_size).unwrap_or(10);
                let window =
                    input.maximum_batching_window_in_seconds.or(cur.maximum_batching_window_in_seconds).unwrap_or(0);
                self.check_queue_source(ctx, queue, &function, batch_size, window)?;
            }
        }
        let mut st = self.write();
        let m = st.event_source_mappings.get_mut(&input.uuid).ok_or_else(|| Self::esm_not_found(&input.uuid))?;
        let c = &mut m.config;
        macro_rules! set {
            ($($field:ident),*) => { $( if let Some(v) = input.$field.clone() { c.$field = Some(v); } )* };
        }
        set!(
            batch_size,
            filter_criteria,
            kms_key_arn,
            metrics_config,
            logging_config,
            scaling_config,
            maximum_batching_window_in_seconds,
            parallelization_factor,
            destination_config,
            maximum_record_age_in_seconds,
            bisect_batch_on_function_error,
            maximum_retry_attempts,
            tumbling_window_in_seconds,
            source_access_configurations,
            function_response_types,
            amazon_managed_kafka_event_source_config,
            self_managed_kafka_event_source_config,
            document_db_event_source_config,
            provisioned_poller_config
        );
        if let Some(a) = function_arn {
            c.function_arn = Some(a);
        }
        let mut response_state = None;
        if let Some(e) = input.enabled {
            c.state = Some(if e { "Enabled".into() } else { "Disabled".into() });
            response_state = Some(if e { "Enabling" } else { "Disabling" });
        }
        c.last_modified = Some(ctx.received_at);
        let mut out = c.clone();
        out.state = Some(response_state.unwrap_or("Updating").into());
        Ok(out)
    }

    pub async fn delete_event_source_mapping(
        &self,
        ctx: &RequestContext,
        input: types::DeleteEventSourceMappingRequest,
    ) -> Result<types::EventSourceMappingConfiguration, ServiceError> {
        let arn = self.esm_arn(&input.uuid)?;
        ctx.authorize("lambda:DeleteEventSourceMapping", &arn, ConditionContext::new())?;
        let m =
            self.write().event_source_mappings.remove(&input.uuid).ok_or_else(|| Self::esm_not_found(&input.uuid))?;
        let mut out = m.config;
        out.state = Some("Deleting".into());
        Ok(out)
    }

    pub async fn list_event_source_mappings(
        &self,
        ctx: &RequestContext,
        input: types::ListEventSourceMappingsRequest,
    ) -> Result<types::ListEventSourceMappingsResponse, ServiceError> {
        ctx.authorize("lambda:ListEventSourceMappings", "*", ConditionContext::new())?;
        let account = names::account_of(ctx);
        let function = match &input.function_name {
            Some(n) => Some(names::parse_function(ctx, n, None)?),
            None => None,
        };
        let st = self.read();
        let items: Vec<_> = st
            .event_source_mappings
            .values()
            .filter(|m| m.account_id == account && m.region == ctx.region)
            .filter(|m| input.event_source_arn.is_none() || m.config.event_source_arn == input.event_source_arn)
            .filter(|m| {
                function.as_ref().is_none_or(|f| {
                    m.config.function_arn.as_deref().is_some_and(|a| {
                        a == f.qualified_arn() || a.starts_with(&format!("{}:", f.arn())) && f.qualifier.is_none()
                    })
                })
            })
            .map(|m| m.config.clone())
            .collect();
        let (page, next) = paginate(&items, input.marker.as_deref(), input.max_items, 100);
        Ok(types::ListEventSourceMappingsResponse { event_source_mappings: Some(page), next_marker: next })
    }
}

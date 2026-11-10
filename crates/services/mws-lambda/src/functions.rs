//! Functions and their versions: create, read, list, update, publish and
//! delete.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::names::{self, FunctionRef, DEPRECATED_RUNTIMES, RESERVED_ENV};
use crate::state::{Function, State, Version};
use crate::Lambda;

pub const DEFAULT_TIMEOUT: i32 = 3;
pub const DEFAULT_MEMORY: i32 = 128;
const ENV_LIMIT: usize = 4096;
const MAX_LAYERS: usize = 5;

/// Lambda's `LastModified` format: `2026-11-03T07:26:55.123+0000`.
pub fn timestamp(t: chrono::DateTime<chrono::Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.3f+0000").to_string()
}

pub fn revision_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// One page of `items` after `marker` (an offset), and the next marker.
pub fn paginate<T: Clone>(
    items: &[T],
    marker: Option<&str>,
    max: Option<i32>,
    default_max: usize,
) -> (Vec<T>, Option<String>) {
    let start = marker.and_then(|m| m.parse::<usize>().ok()).unwrap_or(0).min(items.len());
    let max = max.map(|m| m.clamp(1, 10_000) as usize).unwrap_or(default_max);
    let end = (start + max).min(items.len());
    let next = (end < items.len()).then(|| end.to_string());
    (items[start..end].to_vec(), next)
}

/// Tag condition keys for a request that sets `tags`.
pub fn tag_context(tags: &BTreeMap<String, String>) -> ConditionContext {
    let mut c = ConditionContext::new();
    if tags.is_empty() {
        return c;
    }
    for (k, v) in tags {
        c.insert(format!("aws:RequestTag/{k}"), vec![v.clone()]);
    }
    c.insert("aws:TagKeys".into(), tags.keys().cloned().collect());
    c
}

impl Lambda {
    /// The resource policy document for `qualifier` of a function, if it
    /// has statements.
    pub(crate) fn policy_document(f: &Function, qualifier: Option<&str>) -> Option<String> {
        let statements = f.policies.get(qualifier.unwrap_or(""))?;
        if statements.is_empty() {
            return None;
        }
        Some(serde_json::json!({ "Version": "2012-10-17", "Id": "default", "Statement": statements }).to_string())
    }

    /// Authorize `action` on a function (qualified when `f` is), evaluating
    /// its resource policy.
    pub(crate) fn authorize_function(
        &self,
        ctx: &RequestContext,
        action: &str,
        f: &FunctionRef,
        extra: ConditionContext,
    ) -> Result<(), ServiceError> {
        let policy = {
            let st = self.read();
            st.functions.get(&f.arn()).and_then(|func| Self::policy_document(func, f.qualifier.as_deref()))
        };
        ctx.authorize_with_resource_policy(action, &f.qualified_arn(), policy.as_deref(), extra)
    }

    pub(crate) fn function<'a>(st: &'a State, f: &FunctionRef) -> Result<&'a Function, ServiceError> {
        st.functions.get(&f.arn()).ok_or_else(|| FunctionRef { qualifier: None, ..f.clone() }.not_found())
    }

    pub(crate) fn function_mut<'a>(st: &'a mut State, f: &FunctionRef) -> Result<&'a mut Function, ServiceError> {
        st.functions.get_mut(&f.arn()).ok_or_else(|| FunctionRef { qualifier: None, ..f.clone() }.not_found())
    }

    /// The configuration a qualifier shows: the version's, with the ARN as
    /// addressed.
    pub(crate) fn configuration(
        func: &Function,
        f: &FunctionRef,
    ) -> Result<types::FunctionConfiguration, ServiceError> {
        let v = func.version_for(f.qualifier.as_deref()).ok_or_else(|| f.not_found())?;
        let mut c = v.config.clone();
        c.function_arn = Some(f.qualified_arn());
        Ok(c)
    }

    fn check_role(&self, ctx: &RequestContext, role: &str) -> Result<(), ServiceError> {
        let mut c = ConditionContext::new();
        c.insert("iam:PassedToService".into(), vec!["lambda.amazonaws.com".into()]);
        ctx.authorize("iam:PassRole", role, c)?;
        let Some(sts) = &self.inner.sts else { return Ok(()) };
        let probe = mws_sts::ServiceAssume {
            role_arn: role,
            service_principal: "lambda.amazonaws.com",
            session_name: "probe",
            duration_seconds: 900,
            source_account: Some(&ctx.caller.account_id),
            source_arn: None,
            now: ctx.received_at,
        };
        sts.service_can_assume(&probe).map_err(|_| {
            errors::invalid_parameter_value("The role defined for the function cannot be assumed by Lambda.")
        })
    }

    fn check_runtime(runtime: &str) -> Result<(), ServiceError> {
        if DEPRECATED_RUNTIMES.contains(&runtime) {
            return Err(errors::invalid_parameter_value(format!(
                "The runtime parameter of {runtime} is no longer supported for creating or updating AWS Lambda functions. We recommend you use the new runtime ({}) while creating or updating functions.",
                names::runtime_successor(runtime)
            )));
        }
        Ok(())
    }

    fn check_environment(env: Option<&types::Environment>) -> Result<(), ServiceError> {
        let Some(vars) = env.and_then(|e| e.variables.as_ref()) else { return Ok(()) };
        let reserved: Vec<&str> = vars.keys().map(String::as_str).filter(|k| RESERVED_ENV.contains(k)).collect();
        if !reserved.is_empty() {
            return Err(errors::invalid_parameter_value(format!(
                "Lambda was unable to configure your environment variables because the environment variables you have provided contains reserved keys that are currently not supported for modification. Reserved keys used in this request: {}",
                reserved.join(", ")
            )));
        }
        let measured = serde_json::to_string(vars).unwrap_or_default();
        if measured.len() > ENV_LIMIT {
            return Err(errors::invalid_parameter_value(format!(
                "Lambda was unable to configure your environment variables because the environment variables you have provided exceeded the 4KB limit. String measured: {measured}"
            )));
        }
        Ok(())
    }

    /// Resolve layer version ARNs, checking each exists and may be used.
    pub(crate) fn resolve_layers(
        &self,
        ctx: &RequestContext,
        arns: &[String],
    ) -> Result<Vec<types::Layer>, ServiceError> {
        if arns.len() > MAX_LAYERS {
            return Err(errors::invalid_parameter_value("Cannot reference more than 5 layers."));
        }
        let mut out = Vec::new();
        for arn in arns {
            let (code_size, policy) = {
                let st = self.read();
                let found = arn
                    .rsplit_once(':')
                    .and_then(|(layer, v)| Some((st.layers.get(layer)?, v.parse::<i64>().ok()?)))
                    .and_then(|(l, v)| l.versions.get(&v));
                let Some(v) = found else {
                    return Err(errors::invalid_parameter_value(format!("Layer version {arn} does not exist.")));
                };
                let policy = (!v.policy.is_empty()).then(|| {
                    serde_json::json!({"Version": "2012-10-17", "Id": "default", "Statement": v.policy}).to_string()
                });
                (v.code_size, policy)
            };
            ctx.authorize_with_resource_policy(
                "lambda:GetLayerVersion",
                arn,
                policy.as_deref(),
                ConditionContext::new(),
            )?;
            out.push(types::Layer { arn: Some(arn.clone()), code_size, ..Default::default() });
        }
        Ok(out)
    }

    /// Where a function's code comes from: a direct zip or an S3 object.
    async fn package(
        &self,
        ctx: &RequestContext,
        zip: Option<Vec<u8>>,
        s3: Option<(String, String, Option<String>)>,
    ) -> Result<crate::code::Stored, ServiceError> {
        let bytes = match (zip, &s3) {
            (Some(z), _) => Self::direct_zip(z)?,
            (None, Some((bucket, key, version))) => self.zip_from_s3(ctx, bucket, key, version.as_deref()).await?,
            (None, None) => return Err(errors::invalid_parameter_value("Please provide a source for function code.")),
        };
        self.store_zip(bytes)
    }

    fn check_code_signing(&self, func_csc: Option<&str>) -> Result<(), ServiceError> {
        let Some(arn) = func_csc else { return Ok(()) };
        let st = self.read();
        let enforce = st
            .code_signing_configs
            .get(arn)
            .and_then(|c| c.config.code_signing_policies.untrusted_artifact_on_deployment.clone())
            .is_some_and(|p| p == "Enforce");
        if enforce {
            return Err(errors::code_verification_failed(
                "Lambda cannot deploy the function. The function or layer might be signed using a signature that the client is not configured to accept. Check the provided signature for arn:aws:lambda: unsigned deployment package.",
            ));
        }
        Ok(())
    }

    pub async fn create_function(
        &self,
        ctx: &RequestContext,
        input: types::CreateFunctionRequest,
    ) -> Result<types::FunctionConfiguration, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, None)?;
        if f.qualifier.is_some() {
            return Err(errors::invalid_parameter_value("Function name cannot contain a qualifier."));
        }
        let tags = input.tags.clone().unwrap_or_default();
        let mut extra = tag_context(&tags);
        if let Some(l) = &input.layers {
            extra.insert("lambda:Layer".into(), l.clone());
        }
        if let Some(v) = &input.vpc_config {
            if let Some(s) = &v.subnet_ids {
                extra.insert("lambda:SubnetIds".into(), s.clone());
            }
            if let Some(s) = &v.security_group_ids {
                extra.insert("lambda:SecurityGroupIds".into(), s.clone());
            }
        }
        if let Some(c) = &input.code_signing_config_arn {
            extra.insert("lambda:CodeSigningConfigArn".into(), vec![c.clone()]);
        }
        ctx.authorize("lambda:CreateFunction", &f.arn(), extra)?;
        self.check_capacity_provider_config(input.capacity_provider_config.as_ref())?;
        self.check_role(ctx, &input.role)?;

        let package_type = input.package_type.clone().unwrap_or_else(|| "Zip".into());
        if package_type == "Zip" {
            if input.runtime.is_none() || input.handler.is_none() {
                return Err(errors::invalid_parameter_value(
                    "Runtime and Handler are mandatory parameters for functions created with deployment packages.",
                ));
            }
        } else if input.code.image_uri.is_none() {
            return Err(errors::invalid_parameter_value(
                "Please provide ImageUri when creating functions with PackageType Image.",
            ));
        }
        if let Some(r) = &input.runtime {
            Self::check_runtime(r)?;
        }
        Self::check_environment(input.environment.as_ref())?;
        if let Some(csc) = &input.code_signing_config_arn {
            if !self.read().code_signing_configs.contains_key(csc) {
                return Err(errors::code_signing_config_not_found(format!(
                    "The code signing configuration cannot be found. Check that the provided configuration is not deleted: {csc}."
                )));
            }
            self.check_code_signing(Some(csc))?;
        }
        let layers = self.resolve_layers(ctx, input.layers.as_deref().unwrap_or_default())?;
        if self.read().functions.contains_key(&f.arn()) {
            return Err(errors::resource_conflict(format!("Function already exist: {}", f.name)));
        }

        let mut version = Version::default();
        let (code_size, code_sha) = if package_type == "Zip" {
            let s3 = match (&input.code.s3_bucket, &input.code.s3_key) {
                (Some(b), Some(k)) => Some((b.clone(), k.clone(), input.code.s3_object_version.clone())),
                _ => None,
            };
            let stored = self.package(ctx, input.code.zip_file.clone(), s3.clone()).await?;
            version.code_hex = Some(stored.hex.clone());
            version.s3_source = s3;
            (stored.size, stored.sha256)
        } else {
            let uri = input.code.image_uri.clone().unwrap_or_default();
            let sha = self.set_image(ctx, &mut version, &uri, input.architectures.as_deref())?;
            (0, sha)
        };

        let now = timestamp(ctx.received_at);
        let log_group = input
            .logging_config
            .as_ref()
            .and_then(|l| l.log_group.clone())
            .unwrap_or_else(|| format!("/aws/lambda/{}", f.name));
        version.config = types::FunctionConfiguration {
            function_name: Some(f.name.clone()),
            function_arn: Some(f.arn()),
            runtime: input.runtime.clone(),
            role: Some(input.role.clone()),
            handler: input.handler.clone(),
            code_size,
            description: Some(input.description.clone().unwrap_or_default()),
            timeout: Some(input.timeout.unwrap_or(DEFAULT_TIMEOUT)),
            memory_size: Some(input.memory_size.unwrap_or(DEFAULT_MEMORY)),
            last_modified: Some(now),
            code_sha256: Some(code_sha),
            version: Some("$LATEST".into()),
            vpc_config: input.vpc_config.as_ref().map(vpc_response),
            dead_letter_config: input.dead_letter_config.clone(),
            environment: input
                .environment
                .as_ref()
                .map(|e| types::EnvironmentResponse { variables: e.variables.clone(), error: None }),
            kms_key_arn: input.kms_key_arn.clone(),
            tracing_config: Some(types::TracingConfigResponse {
                mode: Some(
                    input.tracing_config.as_ref().and_then(|t| t.mode.clone()).unwrap_or_else(|| "PassThrough".into()),
                ),
            }),
            revision_id: Some(revision_id()),
            layers: (!layers.is_empty()).then_some(layers),
            state: Some("Active".into()),
            last_update_status: Some("Successful".into()),
            file_system_configs: input.file_system_configs.clone(),
            package_type: Some(package_type.clone()),
            image_config_response: input
                .image_config
                .as_ref()
                .map(|c| types::ImageConfigResponse { image_config: Some(c.clone()), error: None }),
            architectures: Some(input.architectures.clone().unwrap_or_else(|| vec!["x86_64".into()])),
            ephemeral_storage: Some(input.ephemeral_storage.clone().unwrap_or(types::EphemeralStorage { size: 512 })),
            snap_start: Some(types::SnapStartResponse {
                apply_on: Some(
                    input.snap_start.as_ref().and_then(|s| s.apply_on.clone()).unwrap_or_else(|| "None".into()),
                ),
                optimization_status: Some("Off".into()),
            }),
            runtime_version_config: input.runtime.as_ref().map(|r| types::RuntimeVersionConfig {
                runtime_version_arn: Some(runtime_version_arn(ctx, &f.region, r)),
                error: None,
            }),
            logging_config: Some(types::LoggingConfig {
                log_format: Some(
                    input.logging_config.as_ref().and_then(|l| l.log_format.clone()).unwrap_or_else(|| "Text".into()),
                ),
                application_log_level: input.logging_config.as_ref().and_then(|l| l.application_log_level.clone()),
                system_log_level: input.logging_config.as_ref().and_then(|l| l.system_log_level.clone()),
                log_group: Some(log_group),
            }),
            tenancy_config: input.tenancy_config.clone(),
            durable_config: input.durable_config.clone(),
            capacity_provider_config: input.capacity_provider_config.clone(),
            ..Default::default()
        };

        let function = Function {
            account_id: f.account.clone(),
            region: f.region.clone(),
            name: f.name.clone(),
            arn: f.arn(),
            latest: version,
            tags,
            code_signing_config_arn: input.code_signing_config_arn.clone(),
            ..Default::default()
        };
        let mut response = function.latest.config.clone();
        {
            let mut st = self.write();
            if st.functions.contains_key(&f.arn()) {
                return Err(errors::resource_conflict(format!("Function already exist: {}", f.name)));
            }
            st.functions.insert(f.arn(), function);
            if input.publish {
                let func = st.functions.get_mut(&f.arn()).expect("just inserted");
                response = publish(func, None, None);
            }
        }
        // The create call reports the function while it is set up.
        response.state = Some("Pending".into());
        response.state_reason = Some("The function is being created.".into());
        response.state_reason_code = Some("Creating".into());
        Ok(response)
    }

    pub async fn get_function(
        &self,
        ctx: &RequestContext,
        input: types::GetFunctionRequest,
    ) -> Result<types::GetFunctionResponse, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, input.qualifier.as_deref())?;
        self.authorize_function(ctx, "lambda:GetFunction", &f, ConditionContext::new())?;
        let st = self.read();
        let func = Self::function(&st, &f)?;
        let config = Self::configuration(func, &f)?;
        let v = func.version_for(f.qualifier.as_deref()).ok_or_else(|| f.not_found())?;
        let code = match (&v.code_hex, &v.image_uri) {
            (Some(hex), _) => types::FunctionCodeLocation {
                repository_type: Some("S3".into()),
                location: Some(self.download_url(ctx, hex)),
                ..Default::default()
            },
            (None, Some(uri)) => types::FunctionCodeLocation {
                repository_type: Some("ECR".into()),
                image_uri: Some(uri.clone()),
                resolved_image_uri: Some(v.resolved_image_uri.clone().unwrap_or_else(|| uri.clone())),
                ..Default::default()
            },
            _ => types::FunctionCodeLocation::default(),
        };
        Ok(types::GetFunctionResponse {
            configuration: Some(config),
            code: Some(code),
            tags: (!func.tags.is_empty()).then(|| func.tags.clone()),
            concurrency: func
                .reserved_concurrency
                .map(|r| types::Concurrency { reserved_concurrent_executions: Some(r) }),
            ..Default::default()
        })
    }

    pub async fn get_function_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetFunctionConfigurationRequest,
    ) -> Result<types::FunctionConfiguration, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, input.qualifier.as_deref())?;
        self.authorize_function(ctx, "lambda:GetFunctionConfiguration", &f, ConditionContext::new())?;
        let st = self.read();
        Self::configuration(Self::function(&st, &f)?, &f)
    }

    pub async fn list_functions(
        &self,
        ctx: &RequestContext,
        input: types::ListFunctionsRequest,
    ) -> Result<types::ListFunctionsResponse, ServiceError> {
        let account = names::account_of(ctx);
        ctx.authorize("lambda:ListFunctions", "*", ConditionContext::new())?;
        let all = input.function_version.as_deref() == Some("ALL");
        let st = self.read();
        let mut items = Vec::new();
        for func in st.functions.values().filter(|f| f.account_id == account && f.region == ctx.region) {
            if all {
                let mut c = func.latest.config.clone();
                c.function_arn = Some(format!("{}:$LATEST", func.arn));
                items.push(c);
                items.extend(func.versions.values().map(|v| v.config.clone()));
            } else {
                items.push(func.latest.config.clone());
            }
        }
        let (page, next) = paginate(&items, input.marker.as_deref(), input.max_items, 50);
        Ok(types::ListFunctionsResponse { functions: Some(page), next_marker: next })
    }

    pub async fn list_versions_by_function(
        &self,
        ctx: &RequestContext,
        input: types::ListVersionsByFunctionRequest,
    ) -> Result<types::ListVersionsByFunctionResponse, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, None)?;
        self.authorize_function(ctx, "lambda:ListVersionsByFunction", &f, ConditionContext::new())?;
        let st = self.read();
        let func = Self::function(&st, &f)?;
        let mut items = vec![{
            let mut c = func.latest.config.clone();
            c.function_arn = Some(format!("{}:$LATEST", func.arn));
            c
        }];
        items.extend(func.versions.values().map(|v| v.config.clone()));
        let (page, next) = paginate(&items, input.marker.as_deref(), input.max_items, 50);
        Ok(types::ListVersionsByFunctionResponse { versions: Some(page), next_marker: next })
    }

    pub async fn delete_function(
        &self,
        ctx: &RequestContext,
        input: types::DeleteFunctionRequest,
    ) -> Result<types::DeleteFunctionResponse, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, input.qualifier.as_deref())?;
        self.authorize_function(ctx, "lambda:DeleteFunction", &f, ConditionContext::new())?;
        {
            let mut st = self.write();
            let func = Self::function_mut(&mut st, &f)?;
            match f.qualifier.as_deref() {
                // Like AWS, this leaves the function's event source
                // mappings in place: they are deleted on their own.
                None => {
                    st.functions.remove(&f.arn());
                }
                Some("$LATEST") => {
                    return Err(errors::invalid_parameter_value(
                        "$LATEST version cannot be deleted without deleting all versions of the function.",
                    ))
                }
                Some(q) => {
                    let Some(n) = q.parse::<u64>().ok().filter(|n| func.versions.contains_key(n)) else {
                        return Err(f.not_found());
                    };
                    let using: Vec<String> = func
                        .aliases
                        .values()
                        .filter(|a| {
                            a.function_version.as_deref() == Some(q)
                                || a.routing_config
                                    .as_ref()
                                    .and_then(|r| r.additional_version_weights.as_ref())
                                    .is_some_and(|w| w.contains_key(q))
                        })
                        .filter_map(|a| a.alias_arn.clone())
                        .collect();
                    if !using.is_empty() {
                        return Err(errors::resource_conflict(format!(
                            "Unable to delete version because the following aliases reference it: {using:?}"
                        )));
                    }
                    func.versions.remove(&n);
                    func.policies.remove(q);
                    func.provisioned.remove(q);
                    func.event_invoke_configs.remove(q);
                }
            }
        }
        self.inner.runtimes.retire(&f.arn());
        Ok(types::DeleteFunctionResponse { status_code: 204 })
    }

    pub async fn update_function_code(
        &self,
        ctx: &RequestContext,
        input: types::UpdateFunctionCodeRequest,
    ) -> Result<types::FunctionConfiguration, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, None)?;
        self.authorize_function(ctx, "lambda:UpdateFunctionCode", &f, ConditionContext::new())?;
        let (package_type, csc, architectures) = {
            let st = self.read();
            let func = Self::function(&st, &f)?;
            check_revision(func.latest.config.revision_id.as_deref(), input.revision_id.as_deref())?;
            (
                func.latest.config.package_type.clone().unwrap_or_else(|| "Zip".into()),
                func.code_signing_config_arn.clone(),
                func.latest.config.architectures.clone(),
            )
        };
        let mut new = Version::default();
        let (size, sha) = if package_type == "Image" {
            let uri = input.image_uri.clone().ok_or_else(|| {
                errors::invalid_parameter_value(
                    "Please provide ImageUri when updating a function with packageType Image.",
                )
            })?;
            let architectures = input.architectures.clone().or(architectures);
            let sha = self.set_image(ctx, &mut new, &uri, architectures.as_deref())?;
            (0, sha)
        } else {
            if input.image_uri.is_some() {
                return Err(errors::invalid_parameter_value(
                    "Please don't provide ImageUri when updating a function with packageType Zip.",
                ));
            }
            self.check_code_signing(csc.as_deref())?;
            let s3 = match (&input.s3_bucket, &input.s3_key) {
                (Some(b), Some(k)) => Some((b.clone(), k.clone(), input.s3_object_version.clone())),
                _ => None,
            };
            let stored = self.package(ctx, input.zip_file.clone(), s3.clone()).await?;
            new.code_hex = Some(stored.hex);
            new.s3_source = s3;
            (stored.size, stored.sha256)
        };
        let mut st = self.write();
        let func = Self::function_mut(&mut st, &f)?;
        if input.dry_run {
            let mut c = func.latest.config.clone();
            c.code_sha256 = Some(sha);
            c.code_size = size;
            return Ok(c);
        }
        let latest = &mut func.latest;
        latest.code_hex = new.code_hex;
        latest.image_uri = new.image_uri;
        latest.resolved_image_uri = new.resolved_image_uri;
        latest.image_run_config = new.image_run_config;
        latest.s3_source = new.s3_source;
        latest.config.code_sha256 = Some(sha);
        latest.config.code_size = size;
        if let Some(a) = &input.architectures {
            latest.config.architectures = Some(a.clone());
        }
        latest.config.last_modified = Some(timestamp(ctx.received_at));
        latest.config.revision_id = Some(revision_id());
        latest.config.last_update_status = Some("Successful".into());
        let mut response = latest.config.clone();
        if input.publish {
            response = publish(func, None, None);
        }
        drop(st);
        self.inner.runtimes.retire(&f.arn());
        response.last_update_status = Some("InProgress".into());
        response.last_update_status_reason = Some("The function is being created.".into());
        response.last_update_status_reason_code = Some("Creating".into());
        Ok(response)
    }

    pub async fn update_function_configuration(
        &self,
        ctx: &RequestContext,
        input: types::UpdateFunctionConfigurationRequest,
    ) -> Result<types::FunctionConfiguration, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, None)?;
        let mut extra = ConditionContext::new();
        if let Some(l) = &input.layers {
            extra.insert("lambda:Layer".into(), l.clone());
        }
        self.authorize_function(ctx, "lambda:UpdateFunctionConfiguration", &f, extra)?;
        {
            let st = self.read();
            let func = Self::function(&st, &f)?;
            check_revision(func.latest.config.revision_id.as_deref(), input.revision_id.as_deref())?;
        }
        if let Some(role) = &input.role {
            self.check_role(ctx, role)?;
        }
        if let Some(r) = &input.runtime {
            Self::check_runtime(r)?;
        }
        Self::check_environment(input.environment.as_ref())?;
        let layers = match &input.layers {
            Some(l) => Some(self.resolve_layers(ctx, l)?),
            None => None,
        };
        let mut st = self.write();
        let func = Self::function_mut(&mut st, &f)?;
        let c = &mut func.latest.config;
        macro_rules! set {
            ($field:ident) => {
                if let Some(v) = input.$field.clone() {
                    c.$field = Some(v);
                }
            };
        }
        set!(role);
        set!(handler);
        set!(description);
        set!(timeout);
        set!(memory_size);
        set!(dead_letter_config);
        set!(kms_key_arn);
        set!(file_system_configs);
        set!(ephemeral_storage);
        set!(durable_config);
        if let Some(r) = &input.runtime {
            c.runtime = Some(r.clone());
            c.runtime_version_config = Some(types::RuntimeVersionConfig {
                runtime_version_arn: Some(runtime_version_arn(ctx, &f.region, r)),
                error: None,
            });
        }
        if let Some(v) = &input.vpc_config {
            c.vpc_config = Some(vpc_response(v));
        }
        if let Some(e) = &input.environment {
            c.environment = Some(types::EnvironmentResponse { variables: e.variables.clone(), error: None });
        }
        if let Some(t) = &input.tracing_config {
            c.tracing_config = Some(types::TracingConfigResponse { mode: t.mode.clone() });
        }
        if let Some(l) = layers {
            c.layers = (!l.is_empty()).then_some(l);
        }
        if let Some(i) = &input.image_config {
            c.image_config_response = Some(types::ImageConfigResponse { image_config: Some(i.clone()), error: None });
        }
        if let Some(s) = &input.snap_start {
            c.snap_start = Some(types::SnapStartResponse {
                apply_on: s.apply_on.clone(),
                optimization_status: Some("Off".into()),
            });
        }
        if let Some(l) = &input.logging_config {
            let current = c.logging_config.clone().unwrap_or_default();
            c.logging_config = Some(types::LoggingConfig {
                log_format: l.log_format.clone().or(current.log_format),
                application_log_level: l.application_log_level.clone().or(current.application_log_level),
                system_log_level: l.system_log_level.clone().or(current.system_log_level),
                log_group: l.log_group.clone().or(current.log_group),
            });
        }
        c.last_modified = Some(timestamp(ctx.received_at));
        c.revision_id = Some(revision_id());
        c.last_update_status = Some("Successful".into());
        let mut response = c.clone();
        drop(st);
        self.inner.runtimes.retire(&f.arn());
        response.last_update_status = Some("InProgress".into());
        response.last_update_status_reason = Some("The function is being created.".into());
        response.last_update_status_reason_code = Some("Creating".into());
        Ok(response)
    }

    pub async fn publish_version(
        &self,
        ctx: &RequestContext,
        input: types::PublishVersionRequest,
    ) -> Result<types::FunctionConfiguration, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, None)?;
        self.authorize_function(ctx, "lambda:PublishVersion", &f, ConditionContext::new())?;
        let mut st = self.write();
        let func = Self::function_mut(&mut st, &f)?;
        check_revision(func.latest.config.revision_id.as_deref(), input.revision_id.as_deref())?;
        if let Some(sha) = &input.code_sha256 {
            let current = func.latest.config.code_sha256.clone().unwrap_or_default();
            if *sha != current {
                return Err(errors::invalid_parameter_value(format!(
                    "CodeSHA256 ({sha}) is different from current CodeSHA256 in $LATEST ({current}). Please try again with the current CodeSHA256."
                )));
            }
        }
        Ok(publish(func, input.description, Some(ctx.received_at)))
    }
}

/// Publish `$LATEST` as a new version, unless nothing changed since the
/// last one (Lambda then returns that version).
pub fn publish(
    func: &mut Function,
    description: Option<String>,
    now: Option<chrono::DateTime<chrono::Utc>>,
) -> types::FunctionConfiguration {
    if let Some(last) = func.versions.values().next_back() {
        let same = last.code_hex == func.latest.code_hex
            && last.image_uri == func.latest.image_uri
            && comparable(&last.config) == comparable(&func.latest.config);
        if same && description.as_ref().is_none_or(|d| Some(d) == last.config.description.as_ref()) {
            return last.config.clone();
        }
    }
    func.last_version += 1;
    let n = func.last_version;
    let mut v = func.latest.clone();
    v.config.version = Some(n.to_string());
    v.config.function_arn = Some(format!("{}:{n}", func.arn));
    v.config.revision_id = Some(revision_id());
    if let Some(d) = description {
        v.config.description = Some(d);
    }
    if let Some(t) = now {
        v.config.last_modified = Some(timestamp(t));
    }
    let config = v.config.clone();
    func.versions.insert(n, v);
    // Publishing changes $LATEST's revision too.
    func.latest.config.revision_id = Some(revision_id());
    config
}

/// The parts of a configuration that make a version different.
fn comparable(c: &types::FunctionConfiguration) -> types::FunctionConfiguration {
    types::FunctionConfiguration {
        function_arn: None,
        version: None,
        revision_id: None,
        last_modified: None,
        last_update_status: None,
        last_update_status_reason: None,
        last_update_status_reason_code: None,
        description: None,
        state: None,
        state_reason: None,
        state_reason_code: None,
        ..c.clone()
    }
}

pub fn check_revision(current: Option<&str>, given: Option<&str>) -> Result<(), ServiceError> {
    if let Some(g) = given {
        if Some(g) != current {
            return Err(errors::precondition_failed(
                "The Revision Id provided does not match the latest Revision Id. Call the GetFunction/GetAlias API to retrieve the latest Revision Id",
            ));
        }
    }
    Ok(())
}

fn vpc_response(v: &types::VpcConfig) -> types::VpcConfigResponse {
    let subnets = v.subnet_ids.clone().unwrap_or_default();
    let vpc_id = (!subnets.is_empty()).then(|| {
        use sha2::Digest;
        format!("vpc-{}", &hex::encode(sha2::Sha256::digest(subnets.join(",").as_bytes()))[..17])
    });
    types::VpcConfigResponse {
        subnet_ids: Some(subnets),
        security_group_ids: Some(v.security_group_ids.clone().unwrap_or_default()),
        vpc_id: Some(vpc_id.unwrap_or_default()),
        ipv6_allowed_for_dual_stack: Some(v.ipv6_allowed_for_dual_stack.unwrap_or(false)),
    }
}

fn runtime_version_arn(ctx: &RequestContext, region: &str, runtime: &str) -> String {
    use sha2::Digest;
    let digest = hex::encode(sha2::Sha256::digest(runtime.as_bytes()));
    format!("arn:{}:lambda:{region}::runtime:{digest}", ctx.partition)
}

impl Lambda {
    /// Point a version at an image, resolving it in ECR when ECR is wired
    /// in; returns the `CodeSha256` (the resolved digest's hex).
    fn set_image(
        &self,
        ctx: &RequestContext,
        version: &mut Version,
        uri: &str,
        architectures: Option<&[String]>,
    ) -> Result<String, ServiceError> {
        version.image_uri = Some(uri.to_string());
        Ok(match self.resolve_image(ctx, uri, architectures)? {
            Some(image) => {
                version.resolved_image_uri = Some(image.resolved_uri.clone());
                version.image_run_config = Some(image.run_config());
                image.resolved_digest.trim_start_matches("sha256:").to_string()
            }
            None => crate::code::image_digest(uri),
        })
    }
}

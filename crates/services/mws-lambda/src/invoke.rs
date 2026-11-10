//! Invoking functions: synchronously, asynchronously (with retries and
//! destinations), as a response stream, and as a dry run.

use std::collections::BTreeMap;
use std::time::Duration;

use base64::Engine;
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::destinations::DestinationMessage;
use crate::generated::{errors, types};
use crate::names::{self, FunctionRef};
use crate::runtime::{image_tag, ContainerLaunch, Job, LaunchError, LaunchSpec, Outcome};
use crate::Lambda;

/// Largest synchronous request payload (6 MB).
const MAX_SYNC_PAYLOAD: usize = 6_291_456;
/// Largest asynchronous request payload (1 MB).
pub(crate) const MAX_ASYNC_PAYLOAD: usize = 1_048_576;
/// `LogResult` carries the last 4 KB of the log.
const LOG_TAIL: usize = 4096;
/// Delays before the asynchronous retries, as in Lambda.
const RETRY_DELAYS: [Duration; 2] = [Duration::from_secs(60), Duration::from_secs(120)];

/// What a finished invocation produced.
pub struct Ran {
    pub outcome: Outcome,
    pub executed_version: String,
}

impl Lambda {
    /// The version an invocation runs: the qualifier's, or for an alias
    /// with weighted routing, one picked by weight.
    fn pick_version(func: &crate::state::Function, qualifier: Option<&str>) -> Option<String> {
        match qualifier {
            None | Some("$LATEST") => Some("$LATEST".into()),
            Some(q) if q.bytes().all(|b| b.is_ascii_digit()) => {
                func.versions.contains_key(&q.parse().ok()?).then(|| q.into())
            }
            Some(alias) => {
                let a = func.aliases.get(alias)?;
                let primary = a.function_version.clone()?;
                let weights = a.routing_config.as_ref().and_then(|r| r.additional_version_weights.clone());
                if let Some(w) = weights {
                    let roll: f64 = rand::random();
                    let mut acc = 0.0;
                    for (version, weight) in w {
                        acc += weight;
                        if roll < acc {
                            return Some(version);
                        }
                    }
                }
                Some(primary)
            }
        }
    }

    /// Payload checks every invocation type makes.
    fn check_payload(payload: &[u8], limit: usize, op: &str) -> Result<(), ServiceError> {
        if payload.len() > limit {
            return Err(errors::request_too_large(format!(
                "Request must be smaller than {limit} bytes for the {op} operation"
            )));
        }
        if !payload.iter().all(u8::is_ascii_whitespace) {
            if let Err(e) = serde_json::from_slice::<serde_json::Value>(payload) {
                return Err(errors::invalid_request_content(format!(
                    "Could not parse request body into json: Could not parse payload into json: {e}"
                )));
            }
        }
        Ok(())
    }

    /// Run a function and wait for it. The caller is already authorized.
    pub(crate) async fn run(
        &self,
        ctx: &RequestContext,
        f: &FunctionRef,
        payload: Vec<u8>,
        client_context: Option<String>,
    ) -> Result<Ran, ServiceError> {
        let (spec_parts, reserved, executed_version) = {
            let st = self.read();
            let func = Self::function(&st, f)?;
            let version = Self::pick_version(func, f.qualifier.as_deref()).ok_or_else(|| f.not_found())?;
            let v = func.version_for(Some(&version)).ok_or_else(|| f.not_found())?.clone();
            (v, func.reserved_concurrency, version)
        };
        let config = &spec_parts.config;
        let container = if config.package_type.as_deref() == Some("Image") {
            Some(self.prepare_container(f, &spec_parts).await?)
        } else {
            None
        };
        let code_dir = match (&container, &spec_parts.code_hex) {
            (Some(_), _) => self.inner.runtimes.base_dir().to_path_buf(),
            (None, Some(hex)) => self.extracted("code", hex)?,
            (None, None) => return Err(errors::service("The function has no deployment package.")),
        };
        let mut layer_dirs = Vec::new();
        for l in config.layers.iter().flatten().filter(|_| container.is_none()) {
            let Some(arn) = &l.arn else { continue };
            let hex = {
                let st = self.read();
                arn.rsplit_once(':').and_then(|(layer, v)| {
                    st.layers.get(layer)?.versions.get(&v.parse().ok()?).map(|v| v.code_hex.clone())
                })
            };
            if let Some(hex) = hex {
                layer_dirs.push(self.extracted("layers", &hex)?);
            }
        }
        let architecture = architecture(config.architectures.as_deref());
        let managed = match &container {
            Some(_) => None,
            None => {
                let runtime = config.runtime.as_deref().unwrap_or_default();
                match self.inner.runtimes.plan_managed(runtime, architecture).await {
                    Ok(m) => m,
                    Err(e) => {
                        self.publish_invocation_metrics(ctx, f, crate::metrics::Result::Failed);
                        return Err(launch_error(e));
                    }
                }
            }
        };
        let kind = match (&container, &managed) {
            (Some(_), _) => EnvKind::Image,
            (None, Some(_)) => EnvKind::BaseImage,
            (None, None) => EnvKind::Process,
        };
        let env = self.environment(ctx, f, config, &executed_version, kind)?;
        let log_target = (
            env.get("AWS_LAMBDA_LOG_GROUP_NAME").cloned(),
            env.get("AWS_LAMBDA_LOG_STREAM_NAME").cloned(),
            env.get("AWS_ACCESS_KEY_ID").cloned(),
            env.get("AWS_SESSION_TOKEN").cloned(),
        );
        let timeout = config.timeout.unwrap_or(crate::functions::DEFAULT_TIMEOUT).max(1) as u64;
        let spec = LaunchSpec {
            pool_key: format!("{}:{executed_version}:{}", f.arn(), config.revision_id.clone().unwrap_or_default()),
            function_arn: f.arn(),
            version: executed_version.clone(),
            runtime: config.runtime.clone().unwrap_or_default(),
            code_dir,
            layer_dirs,
            env,
            timeout: Duration::from_secs(timeout),
            memory_mb: config.memory_size.unwrap_or(crate::functions::DEFAULT_MEMORY),
            container,
            managed,
            ephemeral_mb: config.ephemeral_storage.as_ref().map_or(512, |e| e.size),
        };
        let job = Job {
            request_id: uuid::Uuid::new_v4().to_string(),
            payload: if payload.is_empty() { b"{}".to_vec() } else { payload },
            invoked_arn: f.qualified_arn(),
            client_context,
        };
        let started = std::time::Instant::now();
        match self.inner.runtimes.invoke(&spec, job, reserved).await {
            Ok(outcome) => {
                if let (Some(group), Some(stream), Some(key), token) = log_target {
                    self.deliver_logs(ctx, &group, &stream, &key, token.as_deref(), &outcome.logs);
                }
                let duration_ms = crate::metrics::reported_duration(&outcome.logs)
                    .unwrap_or_else(|| started.elapsed().as_secs_f64() * 1000.0);
                self.publish_invocation_metrics(
                    ctx,
                    f,
                    crate::metrics::Result::Ran {
                        executed_version: executed_version.clone(),
                        error: outcome.function_error.is_some(),
                        duration_ms,
                    },
                );
                Ok(Ran { outcome, executed_version })
            }
            Err(LaunchError::Throttled) => {
                self.publish_invocation_metrics(ctx, f, crate::metrics::Result::Throttled);
                Err(throttled())
            }
            Err(e) => {
                self.publish_invocation_metrics(ctx, f, crate::metrics::Result::Failed);
                Err(launch_error(e))
            }
        }
    }

    /// Load a container image function's image into the engine and work
    /// out how its container starts.
    async fn prepare_container(
        &self,
        f: &FunctionRef,
        v: &crate::state::Version,
    ) -> Result<ContainerLaunch, ServiceError> {
        let config = &v.config;
        let image = match (&v.resolved_image_uri, &v.image_run_config) {
            (Some(uri), Some(run)) => (uri, run),
            _ => {
                return Err(errors::service("MWS runs container image functions from images in its own ECR registry."))
            }
        };
        let tag = image_tag(config.code_sha256.as_deref().unwrap_or_default());
        let pulled = if self.inner.runtimes.image_loaded(&tag) {
            None
        } else {
            self.fetch_image(&f.account, &f.region, image.0, config.architectures.as_deref())
        };
        self.inner.runtimes.load_image(&tag, pulled.as_ref()).await.map_err(launch_error)?;
        let overrides = config.image_config_response.as_ref().and_then(|r| r.image_config.as_ref());
        let run = image.1;
        Ok(ContainerLaunch {
            image: tag,
            entrypoint: overrides.and_then(|o| o.entry_point.clone()).unwrap_or_else(|| run.entrypoint.clone()),
            command: overrides.and_then(|o| o.command.clone()).unwrap_or_else(|| run.command.clone()),
            working_dir: overrides.and_then(|o| o.working_directory.clone()).or_else(|| run.working_dir.clone()),
            ephemeral_mb: config.ephemeral_storage.as_ref().map_or(512, |e| e.size),
        })
    }

    /// The function's environment: Lambda's reserved variables, role
    /// credentials, the user's variables, and the MWS endpoint for SDKs.
    fn environment(
        &self,
        ctx: &RequestContext,
        f: &FunctionRef,
        config: &types::FunctionConfiguration,
        version: &str,
        kind: EnvKind,
    ) -> Result<BTreeMap<String, String>, ServiceError> {
        let mut env = BTreeMap::new();
        // A container keeps its image's own variables (PATH, ...).
        for key in ["PATH", "HOME", "SYSTEMROOT", "TMPDIR", "TEMP", "TMP"].iter().filter(|_| kind == EnvKind::Process) {
            if let Ok(v) = std::env::var(key) {
                env.insert(key.to_string(), v);
            }
        }
        env.insert("LANG".into(), "en_US.UTF-8".into());
        env.insert("TZ".into(), ":UTC".into());
        if let Some(endpoint) = &ctx.endpoint {
            env.insert("AWS_ENDPOINT_URL".into(), endpoint.clone());
            // Host prefixes (S3 WriteGetObjectResponse's request route) do
            // not resolve against a local endpoint.
            env.insert("AWS_DISABLE_HOST_PREFIX_INJECTION".into(), "true".into());
        }
        if let Some(vars) = config.environment.as_ref().and_then(|e| e.variables.as_ref()) {
            env.extend(vars.clone());
        }
        let memory = config.memory_size.unwrap_or(crate::functions::DEFAULT_MEMORY);
        let runtime = config.runtime.clone().unwrap_or_default();
        let log_group = config
            .logging_config
            .as_ref()
            .and_then(|l| l.log_group.clone())
            .unwrap_or_else(|| format!("/aws/lambda/{}", f.name));
        let stream = format!("{}/[{version}]{}", ctx.received_at.format("%Y/%m/%d"), uuid::Uuid::new_v4().simple());
        let reserved = [
            ("_HANDLER", config.handler.clone().unwrap_or_default()),
            ("AWS_REGION", f.region.clone()),
            ("AWS_DEFAULT_REGION", f.region.clone()),
            ("AWS_EXECUTION_ENV", format!("AWS_Lambda_{runtime}")),
            ("AWS_LAMBDA_FUNCTION_NAME", f.name.clone()),
            ("AWS_LAMBDA_FUNCTION_MEMORY_SIZE", memory.to_string()),
            ("AWS_LAMBDA_FUNCTION_VERSION", version.to_string()),
            ("AWS_LAMBDA_INITIALIZATION_TYPE", "on-demand".into()),
            ("AWS_LAMBDA_LOG_GROUP_NAME", log_group),
            ("AWS_LAMBDA_LOG_STREAM_NAME", stream),
        ];
        for (k, v) in reserved {
            // Images name their handler and execution environment themselves.
            if !(kind == EnvKind::Image && matches!(k, "_HANDLER" | "AWS_EXECUTION_ENV")) {
                env.insert(k.into(), v);
            }
        }
        if let Some(level) = config.logging_config.as_ref().and_then(|l| l.application_log_level.clone()) {
            env.insert("AWS_LAMBDA_LOG_LEVEL".into(), level);
        }
        if let (Some(sts), Some(role)) = (&self.inner.sts, &config.role) {
            let creds = sts
                .assume_role_as_service(&mws_sts::ServiceAssume {
                    role_arn: role,
                    service_principal: "lambda.amazonaws.com",
                    session_name: &f.name,
                    duration_seconds: 43_200,
                    source_account: Some(&f.account),
                    source_arn: Some(&f.arn()),
                    now: ctx.received_at,
                })
                .map_err(|_| {
                    errors::invalid_parameter_value("The role defined for the function cannot be assumed by Lambda.")
                })?;
            env.insert("AWS_ACCESS_KEY_ID".into(), creds.access_key_id);
            env.insert("AWS_SECRET_ACCESS_KEY".into(), creds.secret_access_key);
            env.insert("AWS_SESSION_TOKEN".into(), creds.session_token);
        }
        Ok(env)
    }

    /// Write an invocation's log lines to CloudWatch Logs as the execution
    /// role. Like AWS, a role without logging permissions loses the logs
    /// without failing the invocation.
    fn deliver_logs(
        &self,
        ctx: &RequestContext,
        group: &str,
        stream: &str,
        access_key_id: &str,
        session_token: Option<&str>,
        logs: &str,
    ) {
        let (Some(sink), Some(sts)) = (self.inner.logs.get(), &self.inner.sts) else { return };
        let Ok(Some(resolved)) = sts.credential_store().resolve(access_key_id, session_token, ctx.received_at) else {
            return;
        };
        let role_ctx = RequestContext { caller: resolved.caller, source_ip: None, ..ctx.clone() };
        let now = chrono::Utc::now().timestamp_millis().max(ctx.received_at.timestamp_millis());
        let events = logs
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| mws_logs::ServiceLogEvent { timestamp: now, message: format!("{l}\n") })
            .collect::<Vec<_>>();
        if events.is_empty() {
            return;
        }
        if let Err(e) = sink.put_log_events_as_caller(&role_ctx, group, stream, events) {
            tracing::debug!(%group, %stream, error = %e.message, "function logs not delivered");
        }
    }

    /// Authorize and run a synchronous invocation as `ctx`'s caller,
    /// returning the wire response.
    pub(crate) async fn invoke_sync(
        &self,
        ctx: &RequestContext,
        f: &FunctionRef,
        payload: Vec<u8>,
        client_context: Option<String>,
        tail: bool,
    ) -> Result<types::InvocationResponse, ServiceError> {
        let ran = self.run(ctx, f, payload, client_context).await?;
        Ok(types::InvocationResponse {
            status_code: 200,
            function_error: ran.outcome.function_error.clone(),
            log_result: tail.then(|| log_tail(&ran.outcome.logs)),
            payload: Some(ran.outcome.payload),
            executed_version: Some(ran.executed_version),
            durable_execution_arn: None,
        })
    }

    pub async fn invoke(
        &self,
        ctx: &RequestContext,
        input: types::InvocationRequest,
    ) -> Result<types::InvocationResponse, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, input.qualifier.as_deref())?;
        self.authorize_function(ctx, "lambda:InvokeFunction", &f, ConditionContext::new())?;
        {
            let st = self.read();
            let func = Self::function(&st, &f)?;
            if func.version_for(f.qualifier.as_deref()).is_none() {
                return Err(f.not_found());
            }
        }
        let payload = input.payload.unwrap_or_default();
        let kind = input.invocation_type.as_deref().unwrap_or("RequestResponse");
        let limit = if kind == "Event" { MAX_ASYNC_PAYLOAD } else { MAX_SYNC_PAYLOAD };
        Self::check_payload(&payload, limit, "Invoke")?;
        let client_context = match &input.client_context {
            Some(c) => Some(
                base64::engine::general_purpose::STANDARD
                    .decode(c)
                    .ok()
                    .and_then(|b| String::from_utf8(b).ok())
                    .ok_or_else(|| {
                        errors::invalid_parameter_value("Client context must be a valid Base64-encoded JSON object.")
                    })?,
            ),
            None => None,
        };
        if kind != "DryRun" && self.is_durable(&f) {
            return self.invoke_durable(ctx, &f, payload, kind, input.durable_execution_name.as_deref()).await;
        }
        match kind {
            "DryRun" => Ok(types::InvocationResponse { status_code: 204, ..Default::default() }),
            "Event" => {
                self.enqueue(ctx, &f, payload);
                Ok(types::InvocationResponse { status_code: 202, ..Default::default() })
            }
            _ => self.invoke_sync(ctx, &f, payload, client_context, input.log_type.as_deref() == Some("Tail")).await,
        }
    }

    pub async fn invoke_async(
        &self,
        ctx: &RequestContext,
        input: types::InvokeAsyncRequest,
    ) -> Result<types::InvokeAsyncResponse, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, None)?;
        self.authorize_function(ctx, "lambda:InvokeFunction", &f, ConditionContext::new())?;
        {
            let st = self.read();
            Self::function(&st, &f)?;
        }
        Self::check_payload(&input.invoke_args, MAX_ASYNC_PAYLOAD, "InvokeAsync")?;
        self.enqueue(ctx, &f, input.invoke_args);
        Ok(types::InvokeAsyncResponse { status: 202 })
    }

    pub async fn invoke_with_response_stream(
        &self,
        ctx: &RequestContext,
        input: types::InvokeWithResponseStreamRequest,
    ) -> Result<types::InvokeWithResponseStreamResponse, ServiceError> {
        let f = names::parse_function(ctx, &input.function_name, input.qualifier.as_deref())?;
        self.authorize_function(ctx, "lambda:InvokeFunction", &f, ConditionContext::new())?;
        let payload = input.payload.unwrap_or_default();
        Self::check_payload(&payload, MAX_SYNC_PAYLOAD, "InvokeWithResponseStream")?;
        if input.invocation_type.as_deref() == Some("DryRun") {
            return Ok(types::InvokeWithResponseStreamResponse { status_code: 204, ..Default::default() });
        }
        let client_context = input
            .client_context
            .as_deref()
            .and_then(|c| base64::engine::general_purpose::STANDARD.decode(c).ok())
            .and_then(|b| String::from_utf8(b).ok());
        let ran = self.run(ctx, &f, payload, client_context).await?;
        let tail = input.log_type.as_deref() == Some("Tail");
        let mut events = Vec::new();
        let (error_code, error_details) = match &ran.outcome.function_error {
            Some(_) => {
                let v: serde_json::Value = serde_json::from_slice(&ran.outcome.payload).unwrap_or_default();
                (
                    v.get("errorType").and_then(|t| t.as_str()).map(str::to_string).or(Some("Unhandled".into())),
                    v.get("errorMessage").and_then(|t| t.as_str()).map(str::to_string),
                )
            }
            None => {
                events.push(types::InvokeWithResponseStreamResponseEvent::PayloadChunk(
                    types::InvokeResponseStreamUpdate { payload: Some(ran.outcome.payload.clone()) },
                ));
                (None, None)
            }
        };
        events.push(types::InvokeWithResponseStreamResponseEvent::InvokeComplete(
            types::InvokeWithResponseStreamCompleteEvent {
                error_code,
                error_details,
                log_result: tail.then(|| log_tail(&ran.outcome.logs)),
            },
        ));
        Ok(types::InvokeWithResponseStreamResponse {
            status_code: 200,
            executed_version: Some(ran.executed_version),
            event_stream: events,
            response_stream_content_type: Some("application/octet-stream".into()),
        })
    }

    /// Queue an asynchronous invocation: run it in the background with the
    /// function's retry and destination settings.
    pub(crate) fn enqueue(&self, ctx: &RequestContext, f: &FunctionRef, payload: Vec<u8>) {
        let lambda = self.clone();
        let ctx = ctx.clone();
        let f = f.clone();
        tokio::spawn(async move { lambda.process_event(ctx, f, payload).await });
    }

    async fn process_event(&self, ctx: RequestContext, f: FunctionRef, payload: Vec<u8>) {
        let queued = std::time::Instant::now();
        let (config, dead_letter) = {
            let st = self.read();
            let func = st.functions.get(&f.arn());
            let q = f.qualifier.clone().unwrap_or_else(|| "$LATEST".into());
            (
                func.and_then(|func| func.event_invoke_configs.get(&q).cloned()),
                func.and_then(|func| func.version_for(f.qualifier.as_deref()))
                    .and_then(|v| v.config.dead_letter_config.as_ref())
                    .and_then(|d| d.target_arn.clone())
                    .filter(|a| !a.is_empty()),
            )
        };
        let retries = config.as_ref().and_then(|c| c.maximum_retry_attempts).unwrap_or(2).clamp(0, 2) as usize;
        let max_age =
            Duration::from_secs(config.as_ref().and_then(|c| c.maximum_event_age_in_seconds).unwrap_or(21_600) as u64);
        let mut attempts = 0;
        let mut last: Option<Ran> = None;
        let mut condition = "RetriesExhausted";
        loop {
            if queued.elapsed() > max_age {
                condition = "EventAgeExceeded";
                break;
            }
            attempts += 1;
            match self.run(&ctx, &f, payload.clone(), None).await {
                Ok(ran) if ran.outcome.function_error.is_none() => {
                    self.deliver(&ctx, &f, config.as_ref(), &payload, &ran, attempts, "Success").await;
                    return;
                }
                Ok(ran) => last = Some(ran),
                Err(e) => {
                    tracing::warn!(function = %f.qualified_arn(), "asynchronous invocation failed: {e}");
                    let error = serde_json::json!({ "errorType": e.code, "errorMessage": e.message });
                    last = Some(Ran {
                        outcome: Outcome {
                            payload: error.to_string().into_bytes(),
                            function_error: Some("Unhandled".into()),
                            logs: String::new(),
                        },
                        executed_version: f.qualifier.clone().unwrap_or_else(|| "$LATEST".into()),
                    });
                }
            }
            if attempts > retries {
                break;
            }
            tokio::time::sleep(RETRY_DELAYS[(attempts - 1).min(RETRY_DELAYS.len() - 1)]).await;
        }
        let Some(ran) = last else { return };
        self.deliver(&ctx, &f, config.as_ref(), &payload, &ran, attempts, condition).await;
        if let Some(queue) = dead_letter {
            self.send_dead_letter(&ctx, &f, &queue, &payload, &ran).await;
        }
    }

    /// Send an event the function failed to its dead-letter queue or
    /// topic: the event itself, with `RequestID`, `ErrorCode` and
    /// `ErrorMessage` attributes.
    async fn send_dead_letter(&self, ctx: &RequestContext, f: &FunctionRef, target: &str, request: &[u8], ran: &Ran) {
        let error: serde_json::Value = serde_json::from_slice(&ran.outcome.payload).unwrap_or_default();
        let mut error_message = error
            .get("errorMessage")
            .and_then(|m| m.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| String::from_utf8_lossy(&ran.outcome.payload).into_owned());
        if error_message.len() > 1024 {
            let mut cut = 1024;
            while !error_message.is_char_boundary(cut) {
                cut -= 1;
            }
            error_message.truncate(cut);
        }
        let message = DestinationMessage {
            body: String::from_utf8_lossy(request).into_owned(),
            string_attributes: vec![
                ("RequestID".into(), ctx.request_id.clone()),
                ("ErrorMessage".into(), error_message),
            ],
            number_attributes: vec![("ErrorCode".into(), "200".into())],
            detail_type: String::new(),
            function_arn: format!("{}:{}", f.arn(), ran.executed_version),
            s3_key: None,
        };
        self.send_to_destination(ctx, &f.qualified_arn(), target, &message).await;
    }

    /// Send an asynchronous invocation record to its destination.
    #[allow(clippy::too_many_arguments)]
    async fn deliver(
        &self,
        ctx: &RequestContext,
        f: &FunctionRef,
        config: Option<&types::FunctionEventInvokeConfig>,
        request: &[u8],
        ran: &Ran,
        attempts: usize,
        condition: &str,
    ) {
        let success = condition == "Success";
        let dest = config.and_then(|c| c.destination_config.as_ref()).and_then(|d| {
            if success {
                d.on_success.as_ref().and_then(|s| s.destination.clone())
            } else {
                d.on_failure.as_ref().and_then(|s| s.destination.clone())
            }
        });
        let Some(dest) = dest else { return };
        let record = invocation_record(ctx, f, request, ran, attempts, condition);
        let message = DestinationMessage {
            body: record.to_string(),
            detail_type: format!("Lambda Function Invocation Result - {}", if success { "Success" } else { "Failure" }),
            function_arn: format!("{}:{}", f.arn(), ran.executed_version),
            ..Default::default()
        };
        self.send_to_destination(ctx, &f.qualified_arn(), &dest, &message).await;
    }
}

/// The record an asynchronous invocation destination gets.
fn invocation_record(
    ctx: &RequestContext,
    f: &FunctionRef,
    request: &[u8],
    ran: &Ran,
    attempts: usize,
    condition: &str,
) -> serde_json::Value {
    let parse = |b: &[u8]| serde_json::from_slice::<serde_json::Value>(b).unwrap_or(serde_json::Value::Null);
    let mut response_context = serde_json::json!({ "statusCode": 200, "executedVersion": ran.executed_version });
    if let Some(e) = &ran.outcome.function_error {
        response_context["functionError"] = serde_json::Value::String(e.clone());
    }
    serde_json::json!({
        "version": "1.0",
        "timestamp": chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        "requestContext": {
            "requestId": ctx.request_id,
            "functionArn": format!("{}:{}", f.arn(), ran.executed_version),
            "condition": condition,
            "approximateInvokeCount": attempts,
        },
        "requestPayload": parse(request),
        "responseContext": response_context,
        "responsePayload": parse(&ran.outcome.payload),
    })
}

fn throttled() -> ServiceError {
    errors::too_many_requests("Rate Exceeded.")
        .with_field("Reason", mws_core::ErrorValue::String("ReservedFunctionConcurrentInvocationLimitExceeded".into()))
}

/// The base64 of the last 4 KB of an invocation's log.
pub fn log_tail(logs: &str) -> String {
    let bytes = logs.as_bytes();
    let start = bytes.len().saturating_sub(LOG_TAIL);
    base64::engine::general_purpose::STANDARD.encode(&bytes[start..])
}

/// Where an execution environment runs, which decides its variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnvKind {
    /// A local process, which needs the host's `PATH` and friends.
    Process,
    /// A container image function's own image, which names its handler.
    Image,
    /// A managed runtime's AWS base image.
    BaseImage,
}

/// The function's architecture (`x86_64` unless it says `arm64`).
pub(crate) fn architecture(architectures: Option<&[String]>) -> &'static str {
    match architectures.and_then(<[_]>::first).map(String::as_str) {
        Some("arm64") => "arm64",
        _ => "x86_64",
    }
}

impl Lambda {
    /// Start pulling the base image a function's runtime runs in, so its
    /// first invocation does not wait for the pull.
    pub(crate) fn prefetch_runtime(&self, config: &types::FunctionConfiguration) {
        let (Some(runtime), None) = (config.runtime.clone(), config.package_type.as_deref().filter(|p| *p == "Image"))
        else {
            return;
        };
        if self.inner.runtimes.executor() == crate::runtime::RuntimeExecutor::Local
            || crate::runtime::base_image(&runtime).is_none()
        {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else { return };
        let me = self.clone();
        let arch = architecture(config.architectures.as_deref());
        handle.spawn(async move {
            let _ = me.inner.runtimes.plan_managed(&runtime, arch).await;
        });
    }
}

fn launch_error(e: LaunchError) -> ServiceError {
    match e {
        LaunchError::Throttled => throttled(),
        LaunchError::Unsupported(m) => errors::service(m),
        LaunchError::InvalidEntrypoint(m) => errors::service(format!("Runtime.InvalidEntrypoint: {m}")),
        LaunchError::Io(m) => errors::service(format!("Starting the execution environment failed: {m}")),
    }
}

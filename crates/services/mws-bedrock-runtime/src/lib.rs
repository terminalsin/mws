//! Amazon Bedrock runtime for MWS: `InvokeModel`, `Converse` and their
//! streaming forms, `CountTokens`, `ApplyGuardrail`, and asynchronous
//! invocation; plus the batch inference jobs the control plane starts.
//!
//! Model identifiers (foundation models, inference profiles, Provisioned
//! Throughput, custom deployments, prompt routers) and guardrails resolve
//! through the control plane's public API (`mws-bedrock`). Answers come
//! from a pluggable [`backend::Backend`]: a deterministic echo by default,
//! or a real OpenAI-compatible or Anthropic endpoint.
//!
//! MWS side channel (unsigned): `POST /_aws/bedrock/responses` queues
//! scripted answers for the echo backend (a JSON object or array of
//! `{"modelId"?, "text"?, "toolUse"?: {"name", "input"}, "stopReason"?,
//! "error"?}`), `GET` shows how many are queued and `DELETE` clears them.

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/bedrock_runtime_generated.rs"));
}

pub mod backend;
mod batch;
mod client;
mod converse;
mod handler;
mod native;
pub mod prompt;

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use chrono::{DateTime, Utc};
use mws_bedrock::catalog::Family;
use mws_bedrock::guard::{self, Block, Source};
use mws_bedrock::{Bedrock, InvocationTarget};
use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};
use mws_s3::S3;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub use backend::BackendConfig;
use backend::{Backend, Script, Scripted};
use generated::types;
use prompt::{Completion, OutPart, Prompt, StopReason};

pub const SIDE_CHANNEL: &str = "/_aws/bedrock/";

/// An output object: name, body and content type.
type OutputFile = (String, Vec<u8>, &'static str);

/// Seconds an asynchronous invocation stays `InProgress`.
const ASYNC_SECS: i64 = 2;

pub(crate) fn validation(message: impl Into<String>) -> ServiceError {
    generated::errors::validation(message)
}

/// bedrock-runtime. Cheap to clone; clones share state.
#[derive(Clone)]
pub struct BedrockRuntime {
    inner: Arc<Inner>,
}

struct Inner {
    bedrock: Bedrock,
    s3: S3,
    backend: Arc<dyn Backend>,
    backend_name: &'static str,
    script: Script,
    state: Mutex<State>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct State {
    /// Asynchronous invocations by ARN.
    async_invokes: BTreeMap<String, AsyncInvoke>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
struct AsyncInvoke {
    account: String,
    region: String,
    record: types::GetAsyncInvokeResponse,
    tags: BTreeMap<String, String>,
    /// When it finishes, and as what (`Completed` or `Failed`).
    done_at: Option<DateTime<Utc>>,
    final_status: String,
    final_message: Option<String>,
}

impl AsyncInvoke {
    fn settle(&mut self, now: DateTime<Utc>) {
        if self.record.status == "InProgress" && self.done_at.is_some_and(|t| now >= t) {
            let t = self.done_at.take().expect("checked");
            self.record.status = self.final_status.clone();
            self.record.failure_message = self.final_message.clone();
            self.record.end_time = Some(t);
            self.record.last_modified_time = Some(t);
        }
    }
}

/// The guardrails taking part in an invocation.
struct Guards {
    list: Vec<mws_bedrock::generated::types::GetGuardrailResponse>,
    trace: bool,
}

/// What guardrails decided about an invocation.
#[derive(Default)]
struct Verdict {
    intervened: bool,
    input: BTreeMap<String, Value>,
    outputs: BTreeMap<String, Vec<Value>>,
    /// The model's own text, when a guardrail replaced it.
    model_output: Option<String>,
    reason: Option<String>,
}

impl Verdict {
    fn trace(&self) -> types::GuardrailTraceAssessment {
        let input =
            self.input.iter().filter_map(|(k, v)| Some((k.clone(), serde_json::from_value(v.clone()).ok()?))).collect();
        let outputs = self
            .outputs
            .iter()
            .map(|(k, v)| (k.clone(), v.iter().filter_map(|a| serde_json::from_value(a.clone()).ok()).collect()))
            .collect();
        types::GuardrailTraceAssessment {
            model_output: self.model_output.clone().map(|m| vec![m]),
            input_assessment: Some(input),
            output_assessments: Some(outputs),
            action_reason: self.reason.clone(),
        }
    }

    /// The `amazon-bedrock-trace` guardrail object of native responses.
    fn native_trace(&self) -> Value {
        json!({
            "input": self.input,
            "outputs": self.outputs.iter().map(|(k, v)| json!({ k: v.first() })).collect::<Vec<_>>(),
        })
    }
}

/// A completed chat invocation.
struct Run {
    completion: Completion,
    verdict: Verdict,
    latency_ms: i64,
}

fn scope_matches(i: &AsyncInvoke, ctx: &RequestContext) -> bool {
    i.account == ctx.caller.account_id && i.region == ctx.region
}

fn s3_location(uri: &str) -> Option<(String, String)> {
    let rest = uri.strip_prefix("s3://")?;
    let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
    (!bucket.is_empty()).then(|| (bucket.to_string(), key.trim_end_matches('/').to_string()))
}

fn join_key(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}/{name}")
    }
}

fn json_response(status: u16, body: Value) -> HttpResponse {
    http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(bytes::Bytes::from(body.to_string()))
        .expect("valid response")
}

fn not_chat_model() -> ServiceError {
    validation(
        "This action doesn't support the model that you provided. Try again with a supported text or chat model.",
    )
}

impl BedrockRuntime {
    /// bedrock-runtime over `bedrock`'s models and guardrails, writing
    /// batch and asynchronous output to `s3`.
    pub fn new(bedrock: Bedrock, s3: S3, config: &BackendConfig) -> Self {
        let script = Script::default();
        let backend_name = match config {
            BackendConfig::Echo => "echo",
            BackendConfig::OpenAi { .. } => "openai",
            BackendConfig::Anthropic { .. } => "anthropic",
        };
        let runtime = BedrockRuntime {
            inner: Arc::new(Inner {
                backend: backend::build(config, script.clone()),
                backend_name,
                script,
                bedrock: bedrock.clone(),
                s3,
                state: Mutex::new(State::default()),
            }),
        };
        let weak = Arc::downgrade(&runtime.inner);
        bedrock.set_job_runner(Arc::new(move |job| {
            let Some(inner) = weak.upgrade() else { return };
            let runtime = BedrockRuntime { inner };
            match tokio::runtime::Handle::try_current() {
                Ok(h) => {
                    h.spawn(async move { runtime.run_batch(job).await });
                }
                Err(_) => tracing::warn!("no async runtime to run batch inference job {}", job.job_arn),
            }
        }));
        runtime
    }

    /// Which backend answers (`echo`, `openai` or `anthropic`).
    pub fn backend_name(&self) -> &'static str {
        self.inner.backend_name
    }

    /// Queue a scripted answer for the echo backend.
    pub fn push_response(&self, s: Scripted) {
        self.inner.script.push(s);
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().expect("bedrock-runtime state lock poisoned")
    }

    fn bedrock(&self) -> &Bedrock {
        &self.inner.bedrock
    }

    /// Resolve a model identifier and authorize `action` on everything it
    /// can route to.
    fn target(&self, ctx: &RequestContext, model_id: &str, action: &str) -> Result<InvocationTarget, ServiceError> {
        let target = self.bedrock().resolve_invocation(ctx, model_id)?;
        for r in &target.resources {
            ctx.authorize(action, r, Default::default())?;
        }
        Ok(target)
    }

    fn guards(
        &self,
        ctx: &RequestContext,
        identifier: Option<&str>,
        version: Option<&str>,
        trace: bool,
    ) -> Result<Guards, ServiceError> {
        let mut list = Vec::new();
        match (identifier.filter(|s| !s.is_empty()), version.filter(|s| !s.is_empty())) {
            (Some(id), Some(v)) => list.push(self.bedrock().guardrail_for_invocation(ctx, id, v)?),
            (Some(_), None) => {
                return Err(validation("Guardrail version is required when a guardrail identifier is provided."))
            }
            (None, Some(_)) => {
                return Err(validation("Guardrail identifier is required when a guardrail version is provided."))
            }
            (None, None) => {}
        }
        for (id, v) in self.bedrock().enforced_guardrails(ctx) {
            if list.iter().any(|g| g.guardrail_id == id || g.guardrail_arn == id) {
                continue;
            }
            list.push(self.bedrock().guardrail_for_invocation(ctx, &id, &v)?);
        }
        Ok(Guards { list, trace })
    }

    /// Ask the backend, with guardrails on the way in and out.
    async fn run(&self, prompt: &Prompt, input: Vec<Block>, guards: &Guards) -> Result<Run, ServiceError> {
        let started = std::time::Instant::now();
        let mut verdict = Verdict::default();
        let mut blocked_in = None;
        for g in &guards.list {
            let o = guard::evaluate(g, Source::Input, &input);
            verdict.input.insert(g.guardrail_id.clone(), Value::Object(o.assessment.clone()));
            if o.intervened {
                verdict.intervened = true;
                verdict.reason = Some(format!("Guardrail {} intervened on the input.", g.guardrail_id));
            }
            if o.blocked && blocked_in.is_none() {
                blocked_in = Some(o.blocked_message.clone());
            }
        }
        if let Some(msg) = blocked_in {
            return Ok(Run {
                completion: converse::blocked(&msg, prompt.input_tokens()),
                verdict,
                latency_ms: started.elapsed().as_millis() as i64,
            });
        }
        let mut completion = self
            .inner
            .backend
            .complete(prompt)
            .await
            .map_err(|e| generated::errors::model_error(format!("{} (upstream status {})", e.message, e.status)))?;
        for g in &guards.list {
            let blocks: Vec<Block> = completion
                .parts
                .iter()
                .filter_map(|p| match p {
                    OutPart::Text(t) => Some(Block::text(t.clone())),
                    _ => None,
                })
                .collect();
            if blocks.is_empty() {
                continue;
            }
            let o = guard::evaluate(g, Source::Output, &blocks);
            verdict.outputs.entry(g.guardrail_id.clone()).or_default().push(Value::Object(o.assessment.clone()));
            if !o.intervened {
                continue;
            }
            verdict.intervened = true;
            verdict.reason = Some(format!("Guardrail {} intervened on the output.", g.guardrail_id));
            verdict.model_output.get_or_insert_with(|| completion.text());
            if o.blocked {
                completion.parts = vec![OutPart::Text(o.blocked_message.clone())];
                completion.stop_reason = StopReason::GuardrailIntervened;
                break;
            }
            let mut masked = o.masked.into_iter();
            for p in completion.parts.iter_mut() {
                if let OutPart::Text(t) = p {
                    if let Some(m) = masked.next() {
                        *t = m;
                    }
                }
            }
            completion.stop_reason = StopReason::GuardrailIntervened;
        }
        Ok(Run { completion, verdict, latency_ms: started.elapsed().as_millis().max(1) as i64 })
    }

    /// Answer a native request body. Returns the response body and, for
    /// chat models, the completion.
    async fn invoke_native(
        &self,
        family: Family,
        model_id: &str,
        body: &[u8],
        guards: &Guards,
    ) -> Result<(Value, Option<Run>), ServiceError> {
        match native::parse(family, model_id, body)? {
            native::Native::Chat(p) => {
                let blocks: Vec<Block> = p.texts().into_iter().map(Block::text).collect();
                let run = self.run(&p, blocks, guards).await?;
                let mut out = native::render(family, model_id, &run.completion);
                if !guards.list.is_empty() {
                    let trace = guards.trace.then(|| run.verdict.native_trace());
                    native::add_guardrail_fields(&mut out, run.verdict.intervened, trace);
                }
                Ok((out, Some(run)))
            }
            native::Native::Embed { texts, images, dimensions, normalize, cohere, input_type } => Ok((
                native::render_embedding(
                    model_id,
                    &texts,
                    images,
                    dimensions,
                    normalize,
                    cohere,
                    input_type.as_deref(),
                ),
                None,
            )),
            native::Native::Image { text, count, width, height } => {
                Ok((native::render_images(&text, count, width, height), None))
            }
            native::Native::Rerank { query, documents, top_n } => {
                Ok((native::render_rerank(&query, &documents, top_n), None))
            }
        }
    }

    fn trace_on(trace: Option<&str>) -> bool {
        matches!(trace.map(str::to_ascii_uppercase).as_deref(), Some("ENABLED") | Some("ENABLED_FULL"))
    }

    // InvokeModel -------------------------------------------------------------

    pub(crate) async fn invoke_model(
        &self,
        ctx: &RequestContext,
        input: types::InvokeModelRequest,
    ) -> Result<types::InvokeModelResponse, ServiceError> {
        let target = self.target(ctx, &input.model_id, "bedrock:InvokeModel")?;
        let guards = self.guards(
            ctx,
            input.guardrail_identifier.as_deref(),
            input.guardrail_version.as_deref(),
            Self::trace_on(input.trace.as_deref()),
        )?;
        let model = target.model;
        let body = input.body.unwrap_or_default();
        let (out, _) = self.invoke_native(model.family, &model.model_id, &body, &guards).await?;
        Ok(types::InvokeModelResponse {
            body: out.to_string().into_bytes(),
            content_type: "application/json".into(),
            performance_config_latency: Some(input.performance_config_latency),
            service_tier: input.service_tier,
        })
    }

    pub(crate) async fn invoke_model_with_response_stream(
        &self,
        ctx: &RequestContext,
        input: types::InvokeModelWithResponseStreamRequest,
    ) -> Result<types::InvokeModelWithResponseStreamResponse, ServiceError> {
        let target = self.target(ctx, &input.model_id, "bedrock:InvokeModelWithResponseStream")?;
        let model = target.model;
        if !model.response_streaming_supported || !model.family.conversational() {
            return Err(validation("The model is unsupported for streaming."));
        }
        let guards = self.guards(
            ctx,
            input.guardrail_identifier.as_deref(),
            input.guardrail_version.as_deref(),
            Self::trace_on(input.trace.as_deref()),
        )?;
        let native::Native::Chat(p) = native::parse(model.family, &model.model_id, &input.body.unwrap_or_default())?
        else {
            return Err(validation("The model is unsupported for streaming."));
        };
        let blocks: Vec<Block> = p.texts().into_iter().map(Block::text).collect();
        let run = self.run(&p, blocks, &guards).await?;
        let mut chunks = native::stream_chunks(model.family, &model.model_id, &run.completion, run.latency_ms);
        if !guards.list.is_empty() {
            if let Some(last) = chunks.last_mut() {
                let trace = guards.trace.then(|| run.verdict.native_trace());
                native::add_guardrail_fields(last, run.verdict.intervened, trace);
            }
        }
        Ok(types::InvokeModelWithResponseStreamResponse {
            body: chunks
                .into_iter()
                .map(|c| types::ResponseStream::Chunk(types::PayloadPart { bytes: Some(c.to_string().into_bytes()) }))
                .collect(),
            content_type: "application/json".into(),
            performance_config_latency: Some(input.performance_config_latency),
            service_tier: input.service_tier,
        })
    }

    // Converse ----------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    async fn converse_run(
        &self,
        ctx: &RequestContext,
        target: &InvocationTarget,
        input: converse::ConverseInput<'_>,
        guardrail: Option<(&str, &str, &str)>,
    ) -> Result<(Run, bool), ServiceError> {
        if !target.model.family.conversational() {
            return Err(not_chat_model());
        }
        let (prompt, guard_content) = converse::prompt(input)?;
        let (id, version, trace) = guardrail.unwrap_or_default();
        let trace = trace.eq_ignore_ascii_case("enabled") || trace.eq_ignore_ascii_case("enabled_full");
        let guards = self.guards(ctx, Some(id), Some(version), trace)?;
        let blocks = if guard_content.blocks.is_empty() {
            prompt
                .messages
                .iter()
                .flat_map(|m| m.parts.iter())
                .filter_map(|p| match p {
                    prompt::Part::Text(t) => Some(Block::text(t.clone())),
                    _ => None,
                })
                .collect()
        } else {
            guard_content.blocks
        };
        let run = self.run(&prompt, blocks, &guards).await?;
        Ok((run, trace && !guards.list.is_empty()))
    }

    fn router_trace(target: &InvocationTarget) -> Option<types::PromptRouterTrace> {
        target.routed_to.clone().map(|m| types::PromptRouterTrace { invoked_model_id: Some(m) })
    }

    pub(crate) async fn converse(
        &self,
        ctx: &RequestContext,
        input: types::ConverseRequest,
    ) -> Result<types::ConverseResponse, ServiceError> {
        let target = self.target(ctx, &input.model_id, "bedrock:InvokeModel")?;
        let model_id = target.model.model_id.clone();
        let guardrail = input
            .guardrail_config
            .as_ref()
            .map(|g| (g.guardrail_identifier.as_str(), g.guardrail_version.as_str(), g.trace.as_str()));
        let (run, trace) = self
            .converse_run(
                ctx,
                &target,
                converse::ConverseInput {
                    model_id: &model_id,
                    messages: input.messages.as_deref(),
                    system: input.system.as_deref(),
                    inference: input.inference_config.as_ref(),
                    tools: input.tool_config.as_ref(),
                    prompt_variables: input.prompt_variables.as_ref(),
                },
                guardrail,
            )
            .await?;
        let router = Self::router_trace(&target);
        let trace = (trace || router.is_some())
            .then(|| types::ConverseTrace { guardrail: trace.then(|| run.verdict.trace()), prompt_router: router });
        Ok(types::ConverseResponse {
            output: types::ConverseOutput::Message(converse::message(&run.completion)),
            stop_reason: run.completion.stop_reason.converse().into(),
            usage: converse::usage(&run.completion),
            metrics: types::ConverseMetrics { latency_ms: run.latency_ms },
            additional_model_response_fields: converse::additional_fields(
                input.additional_model_response_field_paths.as_deref(),
                &run.completion,
            ),
            trace,
            performance_config: input.performance_config,
            service_tier: input.service_tier,
        })
    }

    pub(crate) async fn converse_stream(
        &self,
        ctx: &RequestContext,
        input: types::ConverseStreamRequest,
    ) -> Result<types::ConverseStreamResponse, ServiceError> {
        let target = self.target(ctx, &input.model_id, "bedrock:InvokeModelWithResponseStream")?;
        if !target.model.response_streaming_supported {
            return Err(validation("The model is unsupported for streaming."));
        }
        let model_id = target.model.model_id.clone();
        let guardrail = input
            .guardrail_config
            .as_ref()
            .map(|g| (g.guardrail_identifier.as_str(), g.guardrail_version.as_str(), g.trace.as_str()));
        let (run, trace) = self
            .converse_run(
                ctx,
                &target,
                converse::ConverseInput {
                    model_id: &model_id,
                    messages: input.messages.as_deref(),
                    system: input.system.as_deref(),
                    inference: input.inference_config.as_ref(),
                    tools: input.tool_config.as_ref(),
                    prompt_variables: input.prompt_variables.as_ref(),
                },
                guardrail,
            )
            .await?;
        let router = Self::router_trace(&target);
        let trace = (trace || router.is_some()).then(|| types::ConverseStreamTrace {
            guardrail: trace.then(|| run.verdict.trace()),
            prompt_router: router,
        });
        Ok(types::ConverseStreamResponse {
            stream: converse::stream(&run.completion, run.latency_ms, trace, input.service_tier),
        })
    }

    // CountTokens -------------------------------------------------------------

    pub(crate) async fn count_tokens(
        &self,
        ctx: &RequestContext,
        input: types::CountTokensRequest,
    ) -> Result<types::CountTokensResponse, ServiceError> {
        let target = self.target(ctx, &input.model_id, "bedrock:CountTokens")?;
        let model = target.model;
        if model.family != Family::Anthropic {
            return Err(validation(format!("The provided model {} doesn't support counting tokens.", input.model_id)));
        }
        let n = match &input.input {
            types::CountTokensInput::InvokeModel(r) => match native::parse(model.family, &model.model_id, &r.body)? {
                native::Native::Chat(p) => p.input_tokens(),
                _ => prompt::tokens(&String::from_utf8_lossy(&r.body)),
            },
            types::CountTokensInput::Converse(r) => {
                let (p, _) = converse::prompt(converse::ConverseInput {
                    model_id: &model.model_id,
                    messages: r.messages.as_deref(),
                    system: r.system.as_deref(),
                    inference: None,
                    tools: r.tool_config.as_ref(),
                    prompt_variables: None,
                })?;
                p.input_tokens()
            }
        };
        Ok(types::CountTokensResponse { input_tokens: n as i32 })
    }

    // ApplyGuardrail ----------------------------------------------------------

    pub(crate) async fn apply_guardrail(
        &self,
        ctx: &RequestContext,
        input: types::ApplyGuardrailRequest,
    ) -> Result<types::ApplyGuardrailResponse, ServiceError> {
        let g = self.bedrock().guardrail_for_invocation(ctx, &input.guardrail_identifier, &input.guardrail_version)?;
        let mut images = 0;
        let blocks: Vec<Block> = input
            .content
            .iter()
            .filter_map(|c| match c {
                types::GuardrailContentBlock::Text(t) => {
                    Some(Block { text: t.text.clone(), qualifiers: t.qualifiers.clone().unwrap_or_default() })
                }
                types::GuardrailContentBlock::Image(_) => {
                    images += 1;
                    None
                }
            })
            .collect();
        let o = guard::evaluate(&g, Source::parse(&input.source), &blocks);
        let assessment: types::GuardrailAssessment =
            serde_json::from_value(Value::Object(o.assessment.clone())).unwrap_or_default();
        let usage: types::GuardrailUsage = serde_json::from_value(Value::Object(o.usage.clone())).unwrap_or_default();
        Ok(types::ApplyGuardrailResponse {
            usage,
            action: if o.intervened { "GUARDRAIL_INTERVENED" } else { "NONE" }.into(),
            action_reason: Some(o.action_reason().into()),
            outputs: o.outputs().into_iter().map(|t| types::GuardrailOutputContent { text: Some(t) }).collect(),
            assessments: vec![assessment],
            guardrail_coverage: Some(types::GuardrailCoverage {
                text_characters: Some(types::GuardrailTextCharactersCoverage {
                    guarded: Some(o.characters_guarded as i32),
                    total: Some(o.characters_total as i32),
                }),
                images: (images > 0).then_some(types::GuardrailImageCoverage { guarded: Some(0), total: Some(images) }),
            }),
        })
    }

    // Asynchronous invocation -------------------------------------------------

    pub(crate) async fn start_async_invoke(
        &self,
        ctx: &RequestContext,
        input: types::StartAsyncInvokeRequest,
    ) -> Result<types::StartAsyncInvokeResponse, ServiceError> {
        let target = self.target(ctx, &input.model_id, "bedrock:InvokeModel")?;
        if let Some(token) = input.client_request_token.as_deref() {
            let st = self.lock();
            if let Some(existing) = st
                .async_invokes
                .values()
                .find(|i| scope_matches(i, ctx) && i.record.client_request_token.as_deref() == Some(token))
            {
                return Ok(types::StartAsyncInvokeResponse { invocation_arn: existing.record.invocation_arn.clone() });
            }
        }
        let types::AsyncInvokeOutputDataConfig::S3OutputDataConfig(out) = &input.output_data_config;
        let (bucket, prefix) = s3_location(&out.s3_uri)
            .ok_or_else(|| validation(format!("The provided S3 URI {} is invalid.", out.s3_uri)))?;
        let id =
            backend::tool_use_id().trim_start_matches("tooluse_").chars().take(12).collect::<String>().to_lowercase();
        let invocation_arn =
            format!("arn:{}:bedrock:{}:{}:async-invoke/{id}", ctx.partition, ctx.region, ctx.caller.account_id);
        let model = target.model;
        let key_prefix = join_key(&prefix, &id);
        let (files, failure): (Vec<OutputFile>, Option<String>) = match model.family {
            Family::Video => {
                let task = input.model_input.as_str();
                let v: Value = serde_json::from_str(task).unwrap_or_default();
                if v.get("taskType").and_then(Value::as_str).is_none() {
                    return Err(native::malformed("#: required key [taskType] not found"));
                }
                let text = v.pointer("/textToVideoParams/text").and_then(Value::as_str).unwrap_or_default().to_string();
                (
                    vec![
                        ("output.mp4".into(), native::mp4(&text), "video/mp4"),
                        (
                            "manifest.json".into(),
                            json!({"schemaVersion": "1.0", "status": "Completed"}).to_string().into_bytes(),
                            "application/json",
                        ),
                    ],
                    None,
                )
            }
            family => {
                let guards = Guards { list: Vec::new(), trace: false };
                match self.invoke_native(family, &model.model_id, input.model_input.as_bytes(), &guards).await {
                    Ok((v, _)) => (vec![("output.json".into(), v.to_string().into_bytes(), "application/json")], None),
                    Err(e) => (Vec::new(), Some(e.message)),
                }
            }
        };
        let mut failure = failure;
        for (name, body, ct) in files {
            let key = join_key(&key_prefix, &name);
            if failure.is_some() {
                break;
            }
            if let Err(e) =
                ctx.authorize("s3:PutObject", &format!("arn:{}:s3:::{bucket}/{key}", ctx.partition), Default::default())
            {
                failure = Some(format!("Access denied writing to {}: {}", out.s3_uri, e.message));
                break;
            }
            if let Err(e) = self.inner.s3.put_object_with_role(&bucket, &key, body, ct) {
                failure = Some(format!("Unable to write to the output S3 location {}: {e}", out.s3_uri));
            }
        }
        let now = ctx.received_at;
        let record = types::GetAsyncInvokeResponse {
            invocation_arn: invocation_arn.clone(),
            model_arn: target.arn.clone(),
            client_request_token: input.client_request_token.clone(),
            status: "InProgress".into(),
            failure_message: None,
            submit_time: now,
            last_modified_time: Some(now),
            end_time: None,
            output_data_config: types::AsyncInvokeOutputDataConfig::S3OutputDataConfig(
                types::AsyncInvokeS3OutputDataConfig {
                    s3_uri: format!("s3://{}", join_key(&bucket, &key_prefix)),
                    kms_key_id: out.kms_key_id.clone(),
                    bucket_owner: out.bucket_owner.clone(),
                },
            ),
        };
        let tags = input.tags.unwrap_or_default().into_iter().map(|t| (t.key, t.value)).collect();
        self.lock().async_invokes.insert(
            invocation_arn.clone(),
            AsyncInvoke {
                account: ctx.caller.account_id.clone(),
                region: ctx.region.clone(),
                record,
                tags,
                done_at: Some(now + chrono::Duration::seconds(ASYNC_SECS)),
                final_status: if failure.is_some() { "Failed" } else { "Completed" }.into(),
                final_message: failure,
            },
        );
        Ok(types::StartAsyncInvokeResponse { invocation_arn })
    }

    pub(crate) async fn get_async_invoke(
        &self,
        ctx: &RequestContext,
        input: types::GetAsyncInvokeRequest,
    ) -> Result<types::GetAsyncInvokeResponse, ServiceError> {
        ctx.authorize("bedrock:GetAsyncInvoke", &input.invocation_arn, Default::default())?;
        let mut st = self.lock();
        let i = st
            .async_invokes
            .get_mut(&input.invocation_arn)
            .filter(|i| scope_matches(i, ctx))
            .ok_or_else(|| generated::errors::resource_not_found("The specified invocation ARN does not exist."))?;
        i.settle(ctx.received_at);
        Ok(i.record.clone())
    }

    pub(crate) async fn list_async_invokes(
        &self,
        ctx: &RequestContext,
        input: types::ListAsyncInvokesRequest,
    ) -> Result<types::ListAsyncInvokesResponse, ServiceError> {
        ctx.authorize("bedrock:ListAsyncInvokes", "*", Default::default())?;
        let mut st = self.lock();
        let mut items: Vec<types::GetAsyncInvokeResponse> = st
            .async_invokes
            .values_mut()
            .filter(|i| scope_matches(i, ctx))
            .map(|i| {
                i.settle(ctx.received_at);
                i.record.clone()
            })
            .filter(|r| input.status_equals.as_ref().is_none_or(|s| &r.status == s))
            .filter(|r| input.submit_time_after.is_none_or(|t| r.submit_time > t))
            .filter(|r| input.submit_time_before.is_none_or(|t| r.submit_time < t))
            .collect();
        drop(st);
        items.sort_by(|a, b| a.submit_time.cmp(&b.submit_time).then(a.invocation_arn.cmp(&b.invocation_arn)));
        if input.sort_order != "Ascending" {
            items.reverse();
        }
        let start = match input.next_token.as_deref() {
            None | Some("") => 0,
            Some(t) => t
                .strip_prefix("mws-offset-")
                .and_then(|n| n.parse::<usize>().ok())
                .ok_or_else(|| validation("The provided pagination token is invalid."))?,
        };
        let max = input.max_results.filter(|m| *m > 0).unwrap_or(1000) as usize;
        let total = items.len();
        let page: Vec<_> = items.into_iter().skip(start).take(max).collect();
        let next_token = (start + page.len() < total).then(|| format!("mws-offset-{}", start + page.len()));
        Ok(types::ListAsyncInvokesResponse {
            next_token,
            async_invoke_summaries: Some(
                page.into_iter()
                    .map(|r| types::AsyncInvokeSummary {
                        invocation_arn: r.invocation_arn,
                        model_arn: r.model_arn,
                        client_request_token: r.client_request_token,
                        status: Some(r.status),
                        failure_message: r.failure_message,
                        submit_time: r.submit_time,
                        last_modified_time: r.last_modified_time,
                        end_time: r.end_time,
                        output_data_config: r.output_data_config,
                    })
                    .collect(),
            ),
        })
    }

    // Side channel ------------------------------------------------------------

    fn side_channel(&self, request: &HttpRequest) -> HttpResponse {
        let path = request.uri().path();
        if path.trim_end_matches('/') != "/_aws/bedrock/responses" {
            return json_response(404, json!({"message": format!("No MWS Bedrock endpoint at {path}.")}));
        }
        match *request.method() {
            http::Method::GET => json_response(200, json!({"queued": self.inner.script.len()})),
            http::Method::DELETE => {
                self.inner.script.clear();
                json_response(200, json!({"queued": 0}))
            }
            http::Method::POST | http::Method::PUT => {
                let parsed: Result<Value, _> = serde_json::from_slice(request.body());
                let items = match parsed {
                    Ok(Value::Array(a)) => a,
                    Ok(v @ Value::Object(_)) => vec![v],
                    _ => {
                        return json_response(
                            400,
                            json!({"message": "Expected a JSON object or array of scripted responses."}),
                        )
                    }
                };
                for item in items {
                    match serde_json::from_value::<Scripted>(item) {
                        Ok(s) => self.inner.script.push(s),
                        Err(e) => {
                            return json_response(400, json!({"message": format!("Invalid scripted response: {e}")}))
                        }
                    }
                }
                json_response(200, json!({"queued": self.inner.script.len()}))
            }
            _ => json_response(405, json!({"message": "Use GET, POST or DELETE."})),
        }
    }
}

#[async_trait::async_trait]
impl Service for BedrockRuntime {
    fn signing_name(&self) -> &'static str {
        "bedrock"
    }

    fn name(&self) -> &'static str {
        "bedrock-runtime"
    }

    fn claims(&self, request: &HttpRequest) -> bool {
        mws_bedrock::is_runtime_path(request.uri().path())
    }

    fn recognizes(&self, request: &HttpRequest) -> bool {
        let path = request.uri().path();
        path.starts_with(SIDE_CHANNEL)
            || (path.starts_with("/model/")
                && ["/invoke", "/invoke-with-response-stream", "/converse", "/converse-stream", "/count-tokens"]
                    .iter()
                    .any(|s| path.ends_with(s)))
    }

    fn accepts_unsigned(&self, request: &HttpRequest) -> bool {
        request.uri().path().starts_with(SIDE_CHANNEL)
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        if request.uri().path().starts_with(SIDE_CHANNEL) {
            return self.side_channel(&request);
        }
        generated::dispatch(self, &ctx, &request).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_restjson::error_response(&generated::SERVICE_INFO, request_id, error)
    }

    async fn invoke(&self, ctx: RequestContext, operation: &str, input: Value) -> Result<Value, ServiceError> {
        generated::invoke(self, &ctx, operation, input).await
    }

    fn export_state(&self) -> Option<Value> {
        Some(serde_json::to_value(&*self.lock()).expect("bedrock-runtime state serializes"))
    }

    fn import_state(&self, state: Value) -> Result<(), String> {
        let state: State = serde_json::from_value(state).map_err(|e| format!("invalid bedrock-runtime state: {e}"))?;
        *self.lock() = state;
        Ok(())
    }

    fn reset_state(&self) {
        *self.lock() = State::default();
        self.inner.script.clear();
    }
}

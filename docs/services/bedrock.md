# Amazon Bedrock

> Crates: [`mws-bedrock`](../../crates/services/mws-bedrock) (control plane) and [`mws-bedrock-runtime`](../../crates/services/mws-bedrock-runtime) · Tests: [`bedrock.rs`](../../tests/e2e-rust/tests/e2e/bedrock.rs), [`bedrock_runtime.rs`](../../tests/e2e-rust/tests/e2e/bedrock_runtime.rs), [`bedrock_runtime_limits.rs`](../../tests/e2e-rust/tests/e2e/bedrock_runtime_limits.rs), [`bedrock_runtime_jobs.rs`](../../tests/e2e-rust/tests/e2e/bedrock_runtime_jobs.rs), [`bedrock_runtime_servicequotas.rs`](../../tests/e2e-rust/tests/e2e/bedrock_runtime_servicequotas.rs)

All 108 control plane operations (`bedrock`) and 10 of the 11 runtime operations (`bedrock-runtime`) are generated from the AWS models (restJson1) and implemented. Both sign as `bedrock`; MWS routes by path. Long-running work (Provisioned Throughput, customization and import jobs, Automated Reasoning builds, asynchronous invocations) moves on the emulated clock.

Answers come from a pluggable backend. The default **echo** backend is deterministic: it replays queued scripted answers, calls a tool the request forces (or whose name the user mentions) with an input built from its JSON schema, summarizes tool results, and otherwise echoes the last user message, honouring `maxTokens` and stop sequences. Model providers send chosen models to a real OpenAI-compatible server, the Anthropic API, or the local Claude Code or Codex CLI instead (see [model providers](#model-providers)).

✅ supported · 🟡 partial · ❌ not supported

## Models and inference profiles

| Feature | Status | Details |
| --- | :---: | --- |
| Foundation model catalog | ✅ | ~50 models (Claude, Nova, Titan, Llama, Mistral, Cohere, Jamba, DeepSeek, gpt-oss) with modalities, inference types, customizations and lifecycle; `ListFoundationModels` filters. Each model also carries what the runtime enforces: context window, largest `maxTokens`, tool use, forced `toolChoice`, system prompts and batch support (`maxOutputTokens`, `toolUse`, `toolChoice`, `systemPrompt`, `batchSupported` in `MWS_BEDROCK_MODELS` entries). Add models with `MWS_BEDROCK_MODELS`. |
| Model access | 🟡 | Availability, agreement offers and agreements, the use case form, account data retention. Access is reported but not enforced: Anthropic models answer without `PutUseCaseForModelAccess`, and `GetFoundationModelAvailability` always says `AUTHORIZED`. |
| Cross-Region (system) inference profiles | ✅ | `us.`, `eu.`, `apac.` and `global.` profiles for the models that have them; invoking a profile-only model directly fails with AWS's on-demand message. |
| Application inference profiles | ✅ | Copy a model or a system profile; tags for cost allocation; invocable by ARN. |
| Provisioned Throughput | ✅ | `Creating` to `InService`; invoking before then raises `ModelNotReadyException`. |
| Prompt routers | ✅ | Default and custom routers; requests go to the fallback model and the trace names it. |
| Regions | 🟡 | Every model is offered in every Region. |

## Runtime

| Feature | Status | Details |
| --- | :---: | --- |
| `InvokeModel` | ✅ | Each provider's native request and response format: Anthropic Messages, Nova, Titan Text, Llama, Mistral, DeepSeek, Cohere Command, OpenAI-style chat (Jamba, Pixtral, gpt-oss); embeddings (Titan, Cohere, deterministic vectors); images (Titan Image, Nova Canvas, real PNGs); Cohere Rerank. Malformed bodies fail with AWS's `Malformed input request` message. |
| `InvokeModelWithResponseStream` | ✅ | The provider's chunk sequence, ending with `amazon-bedrock-invocationMetrics`. |
| `Converse` and `ConverseStream` | ✅ | Text, images, documents, tools (`toolChoice` auto, any or a named tool), reasoning blocks, prompt variables, AWS's conversation validation, usage and latency. `toolResult` blocks must answer the `toolUse` blocks of the previous turn. `additionalModelRequestFields` reach the model (and the passthrough backends); Claude and Nova reject keys they don't know (`extraneous key [...] is not permitted`). With Claude's `thinking` enabled the echo backend answers with a reasoning block first; reasoning blocks (and native `thinking` blocks) carry a signature. |
| Model limits | ✅ | `ValidationException` with AWS's wording for tools on models without tool use, forced `toolChoice` on models that only take `auto`, system prompts on Titan Text and Mistral Instruct, image or video blocks a model can't read, `maxTokens` over the model's limit, input over its context window (`Input is too long for requested model.`) and Claude thinking budgets (at least 1024, below `max_tokens`). |
| Throughput quotas | ✅ | Requests and tokens per minute per model, from Service Quotas (`bedrock`: on-demand and cross-Region quotas for the main models, and a shared pair for the rest), counted per account, Region and model over a sliding minute on the emulated clock. Over either, calls fail with `ThrottlingException` (429): `Too many requests, please wait before trying again.` or `Too many tokens, please wait before trying again.` Raising a quota with `RequestServiceQuotaIncrease` takes effect once approved. Provisioned Throughput and custom deployments are not throttled. |
| `CountTokens` | 🟡 | Claude models; a count of a quarter of the characters, not the real tokenizer. |
| Authorization | ✅ | `bedrock:InvokeModel` (or `InvokeModelWithResponseStream`) on the profile or router and every model it can route to, with the condition keys `bedrock:GuardrailIdentifier` (the guardrail's ARN and version, `arn:aws:bedrock:<region>:<account>:guardrail/<id>:<version>`), `bedrock:InferenceProfileArn` and `bedrock:PromptRouterArn`, so policies can require a guardrail or a profile. |
| Asynchronous invocation | ✅ | `StartAsyncInvoke` writes its output (a placeholder MP4 for Nova Reel, JSON for other models) to S3 with the caller's own S3 permissions, idempotently by client token; `GetAsyncInvoke` and `ListAsyncInvokes` follow it to `Completed` or `Failed`. |
| Batch inference | ✅ | `CreateModelInvocationJob` checks `iam:PassRole` and that the model supports batch inference, then assumes the job role (its trust policy must allow `bedrock.amazonaws.com`) to read `.jsonl` records from S3 and write `<file>.out` and `manifest.json.out` under `<output>/<job id>/`. Jobs go `Submitted` → `Validating` → `Scheduled` → `InProgress` → done within about a second of emulated time. Fewer records than the "Minimum number of records per batch inference job" quota (100) fail validation. Failed records carry an error and make the job `PartiallyCompleted`; a role without S3 access fails the job. |
| Bidirectional streaming | ❌ | `InvokeModelWithBidirectionalStream` (Nova Sonic) answers `NotImplemented`. |
| Model invocation logging | ✅ | Every successful `InvokeModel`, `Converse` and streaming call becomes a `ModelInvocationLog` (schema 1.0) record. Records go to the CloudWatch Logs group as the configured role (stream `aws/bedrock/modelinvocations`) and to S3 as `bedrock.amazonaws.com`, which the bucket policy must allow, under `<prefix>/AWSLogs/<account>/BedrockModelInvocationLogs/<region>/YYYY/MM/DD/HH/` as gzipped JSON. Bodies follow the text, image, embedding and video delivery switches. Large bodies are not moved to `largeDataDeliveryS3Config`. |
| Bedrock API keys | ✅ | Long-term keys (`ABSK...`, from IAM `CreateServiceSpecificCredential` for `bedrock.amazonaws.com`) and short-term keys (`bedrock-api-key-...`, a presigned `CallWithBearerToken` URL) authenticate runtime and control plane calls as their IAM identity. The identity also needs `bedrock:CallWithBearerToken`, with `bedrock:BearerTokenType` as a condition key. Inactive or expired keys are refused. |

## Guardrails

| Feature | Status | Details |
| --- | :---: | --- |
| Guardrails and versions | ✅ | Create, update the draft, numbered versions, tags, resource policies. |
| Enforcement | 🟡 | `ApplyGuardrail`, `InvokeGuardrailChecks` (inline content filter, prompt attack and sensitive information checks with deterministic scores), `guardrailConfig` on Converse, guardrail headers on InvokeModel, and account-enforced guardrails. Deterministic detectors: denied topics (by name or example), content filter phrase lists, word lists and profanity, PII by pattern (email, phone, card numbers with Luhn, SSN, IP, AWS keys and more), custom regexes, and contextual grounding by word overlap. Names, addresses and other model-detected entities are not found. |
| Traces | ✅ | Input and output assessments in the Converse trace and `amazon-bedrock-trace`; `stopReason` `guardrail_intervened`. |

## Customization and jobs

| Feature | Status | Details |
| --- | :---: | --- |
| Model customization | 🟡 | Jobs check the base model supports the customization type and `iam:PassRole` (for `bedrock.amazonaws.com`), and Bedrock must be able to assume the role (`ValidationException` otherwise). As that role they read the training and validation JSONL from S3 and check each line's format for the model and customization type (`messages` for Claude and Nova, `prompt`/`completion` for others, `input` for continued pre-training). Missing or malformed data ends the job `Failed` with a `failureMessage` and no custom model; good data goes through validation and training (`statusDetails`), writes `training_artifacts/step_wise_training_metrics.csv` under `<output>/model-customization-job-<id>/`, reports `trainingMetrics` and produces an `Active` custom model. No real training happens; jobs take two seconds of emulated time. |
| Custom model import, copy and deployments | 🟡 | Import jobs check `iam:PassRole` and read the weights as the role: `config.json` with a supported `model_type`, tokenizer files and `.safetensors` weights, or the job fails. Imported models and on-demand deployments become invocable (answered as their architecture's family). |
| Evaluation and prompt optimization jobs | 🟡 | Evaluation jobs check `iam:PassRole`, read custom datasets (JSONL with a `prompt` per line, at most 1000) as the role, and write each model's records under `<output>/<job name>/<job id>/models/.../datasets/<name>/`; bad datasets fail the job with `failureMessages`. No model is scored. Prompt optimization: lifecycle, stop and batch delete. |
| Automated Reasoning | 🟡 | Policies, versions, build workflows, annotations, test cases and results; workflows complete on the clock and tests report their expected result. No reasoning happens. |
| Marketplace endpoints | 🟡 | Create, register and deregister. Registered endpoints can be invoked by their SageMaker ARN; they answer in the Llama or Mistral format when the model's identifier names one, and in OpenAI-style chat otherwise. No SageMaker endpoint is deployed. |

## Scripted answers

`POST /_aws/bedrock/responses` (unsigned) queues answers for the echo backend, used before any echo: a JSON object or array of `{"modelId"?, "text"?, "toolUse"?: {"name", "input"}, "stopReason"?, "error"?}`. An `error` fails that call with `ModelErrorException`. `GET` reports how many are queued; `DELETE` clears them.

## Model providers

Each provider has an API (`openai` for any OpenAI-compatible chat completions server, `anthropic`, `claude-code`, `codex`, or `echo`), a URL, an API key, the Bedrock model ids it answers (`models`, `*` wildcards; the most specific pattern wins, then the default provider), how those ids map to upstream model names (`model`, `modelMap`), request-body defaults (`params`, used when the Bedrock request does not set the field), extra `headers` and a `timeoutSeconds`. The built-in `echo` provider is the default.

`claude-code` and `codex` run the CLI installed where MWS runs (`command`, default `claude` / `codex`, plus extra `args`), once per request, in an empty scratch directory with the CLI's own tools off, using the CLI's existing login. The conversation goes in on stdin as a transcript; Bedrock tools become an instruction to answer with a `{"tool_use": {...}}` JSON object, which comes back as a real tool call. Claude Code gets the system prompt as `--system-prompt` and the Claude model a Bedrock `anthropic.*` id names, unless `model`/`modelMap` say otherwise; Codex uses its configured model unless one is set. Token counts are the CLI's own.

CLI providers also add their models to the catalog (`ListFoundationModels`, `GetFoundationModel`, the console's model catalog and playground) as `<provider>.<model>`: Claude Code's `opus`, `sonnet` and `haiku` (`claude-code.sonnet`), and the models `codex debug models` lists (`codex.gpt-5.5`). Invoking one goes to that provider with that model. The list refreshes at start-up, when providers change, and on `GET /_aws/bedrock/local`. A CLI that is not logged in fails with `ModelErrorException` naming the fix (`run \`claude login\` there`); `GET /_aws/bedrock/local` reports `loggedIn` from `claude auth status` / `codex login status`, and the console marks such providers.

MWS looks for the CLI on its `PATH`, then where the installers put it (`~/.claude/local`, `~/.local/bin`, Homebrew, `/usr/local/bin`, npm, bun, Volta and nvm directories), so it is found even when MWS was started from an IDE or a service manager. `command` may also be a path (`~/` works).

**MWS in a container.** The CLI and its login live on the host, so run the bridge there and point MWS at it:

```sh
mws bedrock-bridge                       # 127.0.0.1:4599; prints a token
mws bedrock-bridge --listen 0.0.0.0:4599 # Linux Docker: reachable from containers
```

Then give MWS `MWS_BEDROCK_CLI_BRIDGE=http://host.docker.internal:4599` and `MWS_BEDROCK_CLI_BRIDGE_TOKEN=<token>` (on Linux, add `--add-host host.docker.internal:host-gateway`), or set one provider's `url` and `apiKey` to the bridge's address and token. The bridge runs only Claude Code and Codex (`MWS_BEDROCK_BRIDGE_CLAUDE` / `MWS_BEDROCK_BRIDGE_CODEX` pick the executables, `MWS_BEDROCK_BRIDGE_TOKEN` fixes the token) and refuses requests without its token.

The console's Add provider sheet starts from presets (Claude Code, Codex, Ollama, LM Studio, vLLM, Anthropic, OpenAI, OpenRouter, Gemini, Mistral, Groq, DeepSeek, xAI, Fireworks, Cerebras, Perplexity) that fill in the API, URL, models and upstream model; local tools MWS found are marked.

Providers come from environment variables (see [configuration](../configuration.md#bedrock)) and from stored settings, which override them field by field and persist with MWS state (`MWS_DB`). The console edits them on Bedrock → Settings. The unsigned endpoint:

| Request | Effect |
| --- | --- |
| `GET /_aws/bedrock/providers` | `{"default", "providers": [...]}` with each provider's settings, `source` (`builtin`, `environment`, `stored`, `environment+stored`) and its API key redacted (`apiKey: "sk-…wxyz"`, `apiKeySet`). |
| `PUT /_aws/bedrock/providers/{name}` | Store settings for a provider (camelCase fields as above). An absent `apiKey` keeps the stored key; `""` removes it. |
| `DELETE /_aws/bedrock/providers/{name}` | Forget the stored settings; any environment settings apply again. |
| `PUT /_aws/bedrock/providers` | `{"default": "name"}` sets the default provider (`""` returns to the environment's); `{"providers": {...}}` stores several. |
| `GET /_aws/bedrock/providers/route?modelId=...` | Which provider answers a model, and the upstream model name it would use. |
| `GET /_aws/bedrock/local` | `{tools, container, bridge}`: which of `claude-code`, `codex`, `ollama`, `lmstudio` (`lms`) are installed (`{command, found, path}`, `via: "bridge"` when found on the bridge's host), whether MWS runs in a container, and the configured bridge (`{url, reachable}`). |

## Known gaps

Bidirectional streaming (Nova Sonic), real token counts, enforced model access (Anthropic's use case form, Marketplace subscriptions), Bedrock quota codes (MWS's own; the quota names follow AWS's), passing a real upstream Claude's reasoning signature through (MWS signs reasoning blocks itself), and model-based guardrail detection (guardrail scores come from phrase lists and patterns). Every model is offered in every Region. Invocation logs do not use large data delivery. A revoked API key fails with `UnrecognizedClientException`, not Bedrock's own API key message. The passthrough backends call the provider without streaming and do not use an HTTP proxy. The CLI providers answer text and tool calls only (images and documents are named, not passed), and need the CLI where MWS runs or a bridge on the host.

See also: [all services](README.md) · [authentication and authorization](../security.md).

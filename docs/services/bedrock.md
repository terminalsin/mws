# Amazon Bedrock

> Crates: [`mws-bedrock`](../../crates/services/mws-bedrock) (control plane) and [`mws-bedrock-runtime`](../../crates/services/mws-bedrock-runtime) · Tests: [`bedrock.rs`](../../tests/e2e-rust/tests/e2e/bedrock.rs), [`bedrock_runtime.rs`](../../tests/e2e-rust/tests/e2e/bedrock_runtime.rs)

All 108 control plane operations (`bedrock`) and 10 of the 11 runtime operations (`bedrock-runtime`) are generated from the AWS models (restJson1) and implemented. Both sign as `bedrock`; MWS routes by path. Long-running work (Provisioned Throughput, customization and import jobs, Automated Reasoning builds, asynchronous invocations) moves on the emulated clock.

Answers come from a pluggable backend. The default **echo** backend is deterministic: it replays queued scripted answers, calls a tool the request forces (or whose name the user mentions) with an input built from its JSON schema, summarizes tool results, and otherwise echoes the last user message, honouring `maxTokens` and stop sequences. `MWS_BEDROCK_BACKEND=openai` or `anthropic` passes requests to a real provider instead (see [configuration](../configuration.md#bedrock)).

✅ supported · 🟡 partial · ❌ not supported

## Models and inference profiles

| Feature | Status | Details |
| --- | :---: | --- |
| Foundation model catalog | ✅ | ~50 models (Claude, Nova, Titan, Llama, Mistral, Cohere, Jamba, DeepSeek, gpt-oss) with modalities, inference types, customizations and lifecycle; `ListFoundationModels` filters. Add models with `MWS_BEDROCK_MODELS`. |
| Model access | ✅ | Availability, agreement offers and agreements, the use case form, account data retention. |
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
| `Converse` and `ConverseStream` | ✅ | Text, images, documents, tools (`toolChoice` auto, any or a named tool), reasoning blocks, prompt variables, AWS's conversation validation, usage and latency. |
| `CountTokens` | 🟡 | Claude models; a count of a quarter of the characters, not the real tokenizer. |
| Authorization | ✅ | `bedrock:InvokeModel` (or `InvokeModelWithResponseStream`) on the profile or router and every model it can route to. |
| Asynchronous invocation | ✅ | `StartAsyncInvoke` writes its output (a placeholder MP4 for Nova Reel, JSON for other models) to S3 with the caller's own S3 permissions, idempotently by client token; `GetAsyncInvoke` and `ListAsyncInvokes` follow it to `Completed` or `Failed`. |
| Batch inference | ✅ | `CreateModelInvocationJob` checks `iam:PassRole`, then assumes the job role (its trust policy must allow `bedrock.amazonaws.com`) to read `.jsonl` records from S3 and write `<file>.out` and `manifest.json.out` under `<output>/<job id>/`. Failed records carry an error and make the job `PartiallyCompleted`; a role without S3 access fails the job. |
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
| Model customization | 🟡 | Jobs check the base model supports the customization type and produce an `Active` custom model; no training happens. |
| Custom model import, copy and deployments | 🟡 | Imported models and on-demand deployments become invocable (answered as their architecture's family). |
| Evaluation and prompt optimization jobs | 🟡 | Lifecycle, stop and batch delete; no evaluation runs. |
| Automated Reasoning | 🟡 | Policies, versions, build workflows, annotations, test cases and results; workflows complete on the clock and tests report their expected result. No reasoning happens. |
| Marketplace endpoints | 🟡 | Create, register and deregister. Registered endpoints can be invoked by their SageMaker ARN; they answer in the Llama or Mistral format when the model's identifier names one, and in OpenAI-style chat otherwise. No SageMaker endpoint is deployed. |

## Scripted answers

`POST /_aws/bedrock/responses` (unsigned) queues answers for the echo backend, used before any echo: a JSON object or array of `{"modelId"?, "text"?, "toolUse"?: {"name", "input"}, "stopReason"?, "error"?}`. An `error` fails that call with `ModelErrorException`. `GET` reports how many are queued; `DELETE` clears them.

## Known gaps

Bidirectional streaming (Nova Sonic), real token counts, and model-based guardrail detection (guardrail scores come from phrase lists and patterns). Every model is offered in every Region. Invocation logs do not use large data delivery. A revoked API key fails with `UnrecognizedClientException`, not Bedrock's own API key message. The passthrough backends call the provider without streaming and do not use an HTTP proxy.

See also: [all services](README.md) · [authentication and authorization](../security.md).

//! Amazon Bedrock runtime through the official Rust SDK: InvokeModel in
//! each provider's native format, Converse with tools, streaming,
//! guardrails, token counting, asynchronous invocation and batch jobs, all
//! answered by the deterministic echo backend.

use std::time::Duration;

use aws_sdk_bedrockruntime::primitives::Blob;
use aws_sdk_bedrockruntime::types::*;
use aws_sdk_bedrockruntime::Client;
use aws_smithy_types::Document;
use mws_e2e::Mws;
use serde_json::{json, Value};

use crate::bedrock::{advance, code, guardrail, message, ACCOUNT};

const HAIKU: &str = "anthropic.claude-3-haiku-20240307-v1:0";
const SONNET_45: &str = "anthropic.claude-sonnet-4-5-20250929-v1:0";
const NOVA_MICRO: &str = "amazon.nova-micro-v1:0";

fn user(text: &str) -> Message {
    Message::builder().role(ConversationRole::User).content(ContentBlock::Text(text.into())).build().unwrap()
}

fn doc(v: &Value) -> Document {
    match v {
        Value::Null => Document::Null,
        Value::Bool(b) => Document::Bool(*b),
        Value::Number(n) => match n.as_u64() {
            Some(u) => Document::Number(aws_smithy_types::Number::PosInt(u)),
            None => Document::Number(aws_smithy_types::Number::Float(n.as_f64().unwrap())),
        },
        Value::String(s) => Document::String(s.clone()),
        Value::Array(a) => Document::Array(a.iter().map(doc).collect()),
        Value::Object(o) => Document::Object(o.iter().map(|(k, v)| (k.clone(), doc(v))).collect()),
    }
}

async fn invoke(r: &Client, model: &str, body: Value) -> Value {
    let out = r
        .invoke_model()
        .model_id(model)
        .content_type("application/json")
        .body(Blob::new(body.to_string()))
        .send()
        .await
        .unwrap();
    assert_eq!(out.content_type(), "application/json");
    serde_json::from_slice(out.body().as_ref()).unwrap()
}

#[tokio::test]
async fn invoke_model_native_formats() {
    let mws = Mws::start().await;
    let r = Client::new(&mws.root_sdk_config().await);

    let claude = invoke(
        &r,
        HAIKU,
        json!({"anthropic_version": "bedrock-2023-05-31", "max_tokens": 100, "system": "Be brief.",
               "messages": [{"role": "user", "content": [{"type": "text", "text": "Hello, Claude"}]}]}),
    )
    .await;
    assert_eq!(claude["type"], "message");
    assert_eq!(claude["content"][0]["text"], "Hello, Claude");
    assert_eq!(claude["stop_reason"], "end_turn");
    assert!(claude["usage"]["input_tokens"].as_u64().unwrap() > 0);

    let nova = invoke(
        &r,
        NOVA_MICRO,
        json!({"messages": [{"role": "user", "content": [{"text": "Hi Nova"}]}], "inferenceConfig": {"maxTokens": 50}}),
    )
    .await;
    assert_eq!(nova["output"]["message"]["content"][0]["text"], "Hi Nova");
    assert_eq!(nova["stopReason"], "end_turn");

    let titan = invoke(&r, "amazon.titan-text-express-v1", json!({"inputText": "Say hi"})).await;
    assert_eq!(titan["results"][0]["outputText"], "Say hi");
    assert_eq!(titan["results"][0]["completionReason"], "FINISH");

    let llama = invoke(
        &r,
        "meta.llama3-70b-instruct-v1:0",
        json!({"prompt": "<|begin_of_text|><|start_header_id|>user<|end_header_id|>\n\nWhat is 2+2?<|eot_id|><|start_header_id|>assistant<|end_header_id|>", "max_gen_len": 64}),
    )
    .await;
    assert_eq!(llama["generation"], "What is 2+2?");

    // Token limits stop the answer.
    let short = invoke(
        &r,
        HAIKU,
        json!({"anthropic_version": "bedrock-2023-05-31", "max_tokens": 2,
               "messages": [{"role": "user", "content": "a long message that will be cut short"}]}),
    )
    .await;
    assert_eq!(short["stop_reason"], "max_tokens");
    assert_eq!(short["content"][0]["text"], "a long m");

    // Embeddings are deterministic and sized as asked.
    let e1 = invoke(&r, "amazon.titan-embed-text-v2:0", json!({"inputText": "hello world", "dimensions": 256})).await;
    let e2 = invoke(&r, "amazon.titan-embed-text-v2:0", json!({"inputText": "hello world", "dimensions": 256})).await;
    assert_eq!(e1["embedding"].as_array().unwrap().len(), 256);
    assert_eq!(e1["embedding"], e2["embedding"]);
    let cohere =
        invoke(&r, "cohere.embed-english-v3", json!({"texts": ["a", "b"], "input_type": "search_document"})).await;
    assert_eq!(cohere["embeddings"].as_array().unwrap().len(), 2);

    // Images are real PNGs.
    let img = invoke(
        &r,
        "amazon.nova-canvas-v1:0",
        json!({"taskType": "TEXT_IMAGE", "textToImageParams": {"text": "a red fox"},
               "imageGenerationConfig": {"numberOfImages": 2, "width": 64, "height": 64}}),
    )
    .await;
    let images = img["images"].as_array().unwrap();
    assert_eq!(images.len(), 2);
    use base64::Engine;
    let png = base64::engine::general_purpose::STANDARD.decode(images[0].as_str().unwrap()).unwrap();
    assert_eq!(&png[1..4], b"PNG");

    // Malformed bodies and unknown models fail as in AWS.
    let e = r.invoke_model().model_id(HAIKU).body(Blob::new(r#"{"messages": []}"#)).send().await.unwrap_err();
    let se = e.as_service_error().unwrap();
    assert_eq!(code(se), "ValidationException");
    assert!(message(se).starts_with("Malformed input request"), "{}", message(se));
    let e = r.invoke_model().model_id("acme.nope-v1").body(Blob::new("{}")).send().await.unwrap_err();
    assert_eq!(message(e.as_service_error().unwrap()), "The provided model identifier is invalid.");
    let e = r
        .invoke_model()
        .model_id(SONNET_45)
        .body(Blob::new(r#"{"anthropic_version": "bedrock-2023-05-31", "max_tokens": 10, "messages": []}"#))
        .send()
        .await
        .unwrap_err();
    assert!(message(e.as_service_error().unwrap()).contains("with on-demand throughput isn\u{2019}t supported"));

    // Through the cross-Region profile, the same model answers.
    let via_profile = invoke(
        &r,
        &format!("us.{SONNET_45}"),
        json!({"anthropic_version": "bedrock-2023-05-31", "max_tokens": 100,
               "messages": [{"role": "user", "content": "profile"}]}),
    )
    .await;
    assert_eq!(via_profile["content"][0]["text"], "profile");
    mws.stop().await;
}

#[tokio::test]
async fn invoke_model_streams() {
    let mws = Mws::start().await;
    let r = Client::new(&mws.root_sdk_config().await);
    let text = "streaming responses arrive in several small chunks of text";
    let mut out = r
        .invoke_model_with_response_stream()
        .model_id(HAIKU)
        .body(Blob::new(
            json!({"anthropic_version": "bedrock-2023-05-31", "max_tokens": 200,
                   "messages": [{"role": "user", "content": text}]})
            .to_string(),
        ))
        .send()
        .await
        .unwrap();
    let mut chunks = Vec::new();
    while let Some(event) = out.body.recv().await.unwrap() {
        if let ResponseStream::Chunk(part) = event {
            chunks.push(serde_json::from_slice::<Value>(part.bytes().unwrap().as_ref()).unwrap());
        }
    }
    assert_eq!(chunks[0]["type"], "message_start");
    let streamed: String = chunks
        .iter()
        .filter(|c| c["type"] == "content_block_delta")
        .map(|c| c["delta"]["text"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(streamed, text);
    let last = chunks.last().unwrap();
    assert_eq!(last["type"], "message_stop");
    assert!(last["amazon-bedrock-invocationMetrics"]["outputTokenCount"].as_u64().unwrap() > 0);

    let e = r
        .invoke_model_with_response_stream()
        .model_id("amazon.titan-embed-text-v2:0")
        .body(Blob::new(r#"{"inputText": "x"}"#))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "ValidationException");
    mws.stop().await;
}

#[tokio::test]
async fn converse_with_tools_and_scripted_answers() {
    let mws = Mws::start().await;
    let r = Client::new(&mws.root_sdk_config().await);

    let out = r
        .converse()
        .model_id(NOVA_MICRO)
        .system(SystemContentBlock::Text("You are terse.".into()))
        .messages(user("Hello there"))
        .inference_config(InferenceConfiguration::builder().max_tokens(100).temperature(0.2).build())
        .send()
        .await
        .unwrap();
    assert_eq!(out.stop_reason(), &StopReason::EndTurn);
    let ConverseOutput::Message(msg) = out.output().unwrap() else { panic!("no message") };
    assert_eq!(msg.role(), &ConversationRole::Assistant);
    assert_eq!(msg.content()[0].as_text().unwrap(), "Hello there");
    let usage = out.usage().unwrap();
    assert_eq!(usage.total_tokens(), usage.input_tokens() + usage.output_tokens());

    // Tools: the echo backend calls a tool the user names, with an input
    // that fits its schema; then it reports the tool's result.
    let schema = json!({"type": "object", "properties": {"city": {"type": "string"},
        "unit": {"type": "string", "enum": ["celsius", "fahrenheit"]}}, "required": ["city"]});
    let tools = ToolConfiguration::builder()
        .tools(Tool::ToolSpec(
            ToolSpecification::builder()
                .name("get_weather")
                .description("Current weather for a city")
                .input_schema(ToolInputSchema::Json(doc(&schema)))
                .build()
                .unwrap(),
        ))
        .build()
        .unwrap();
    let ask = user("Use get_weather for Paris");
    let out = r.converse().model_id(HAIKU).messages(ask.clone()).tool_config(tools.clone()).send().await.unwrap();
    assert_eq!(out.stop_reason(), &StopReason::ToolUse);
    let ConverseOutput::Message(call) = out.output().unwrap() else { panic!("no message") };
    let tool_use = call.content()[0].as_tool_use().unwrap();
    assert_eq!(tool_use.name(), "get_weather");
    let input = tool_use.input().as_object().unwrap();
    assert_eq!(input.get("unit"), Some(&Document::String("celsius".into())));
    let result = Message::builder()
        .role(ConversationRole::User)
        .content(ContentBlock::ToolResult(
            ToolResultBlock::builder()
                .tool_use_id(tool_use.tool_use_id())
                .content(ToolResultContentBlock::Text("18 degrees and sunny".into()))
                .build()
                .unwrap(),
        ))
        .build()
        .unwrap();
    let out = r
        .converse()
        .model_id(HAIKU)
        .messages(ask)
        .messages(call.clone())
        .messages(result)
        .tool_config(tools)
        .send()
        .await
        .unwrap();
    let ConverseOutput::Message(answer) = out.output().unwrap() else { panic!("no message") };
    assert_eq!(answer.content()[0].as_text().unwrap(), "18 degrees and sunny");

    // Scripted answers come first, then the echo resumes.
    let (status, _) = mws
        .control(
            "POST",
            "/_aws/bedrock/responses",
            Some(r#"[{"text": "scripted!"}, {"modelId": "amazon.nova-micro-v1:0", "error": "upstream exploded"}]"#),
        )
        .await;
    assert_eq!(status, 200);
    let out = r.converse().model_id(HAIKU).messages(user("anything")).send().await.unwrap();
    let ConverseOutput::Message(m) = out.output().unwrap() else { panic!("no message") };
    assert_eq!(m.content()[0].as_text().unwrap(), "scripted!");
    let e = r.converse().model_id(NOVA_MICRO).messages(user("anything")).send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "ModelErrorException");
    let (_, queued) = mws.control("GET", "/_aws/bedrock/responses", None).await;
    assert_eq!(queued["queued"], 0);

    // Validation as in AWS.
    let e = r
        .converse()
        .model_id(HAIKU)
        .messages(
            Message::builder()
                .role(ConversationRole::Assistant)
                .content(ContentBlock::Text("hi".into()))
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap_err();
    assert!(message(e.as_service_error().unwrap()).contains("must start with a user message"));
    let e = r.converse().model_id("amazon.titan-embed-text-v2:0").messages(user("x")).send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "ValidationException");
    mws.stop().await;
}

#[tokio::test]
async fn converse_streams() {
    let mws = Mws::start().await;
    let r = Client::new(&mws.root_sdk_config().await);
    let text = "a reply long enough to arrive as more than one delta";
    let mut out = r.converse_stream().model_id(HAIKU).messages(user(text)).send().await.unwrap();
    let (mut streamed, mut stop, mut usage) = (String::new(), None, None);
    let mut started = false;
    while let Some(event) = out.stream.recv().await.unwrap() {
        match event {
            ConverseStreamOutput::MessageStart(m) => {
                assert_eq!(m.role(), &ConversationRole::Assistant);
                started = true;
            }
            ConverseStreamOutput::ContentBlockDelta(d) => {
                if let Some(ContentBlockDelta::Text(t)) = d.delta() {
                    streamed.push_str(t);
                }
            }
            ConverseStreamOutput::MessageStop(s) => stop = Some(s.stop_reason().clone()),
            ConverseStreamOutput::Metadata(m) => usage = m.usage().cloned(),
            _ => {}
        }
    }
    assert!(started);
    assert_eq!(streamed, text);
    assert_eq!(stop, Some(StopReason::EndTurn));
    assert!(usage.unwrap().output_tokens() > 0);
    mws.stop().await;
}

#[tokio::test]
async fn guardrails_intervene() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let b = aws_sdk_bedrock::Client::new(&cfg);
    let r = Client::new(&cfg);
    let (id, _) = guardrail(&b, "chat-guard").await;

    let applied = r
        .apply_guardrail()
        .guardrail_identifier(&id)
        .guardrail_version("DRAFT")
        .source(GuardrailContentSource::Input)
        .content(GuardrailContentBlock::Text(
            GuardrailTextBlock::builder().text("Tell me about investments please").build().unwrap(),
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(applied.action(), &GuardrailAction::GuardrailIntervened);
    assert_eq!(applied.outputs()[0].text(), Some("Sorry, I can't help with that."));
    let topics = applied.assessments()[0].topic_policy().unwrap().topics();
    assert_eq!(topics[0].name(), "Investments");

    let masked = r
        .apply_guardrail()
        .guardrail_identifier(&id)
        .guardrail_version("DRAFT")
        .source(GuardrailContentSource::Output)
        .content(GuardrailContentBlock::Text(
            GuardrailTextBlock::builder().text("Write to jane@example.com").build().unwrap(),
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(masked.action(), &GuardrailAction::GuardrailIntervened);
    assert_eq!(masked.outputs()[0].text(), Some("Write to {EMAIL}"));
    let clean = r
        .apply_guardrail()
        .guardrail_identifier(&id)
        .guardrail_version("DRAFT")
        .source(GuardrailContentSource::Input)
        .content(GuardrailContentBlock::Text(GuardrailTextBlock::builder().text("Hello").build().unwrap()))
        .send()
        .await
        .unwrap();
    assert_eq!(clean.action(), &GuardrailAction::None);

    // Converse with a guardrail: blocked input never reaches the model.
    let g = GuardrailConfiguration::builder()
        .guardrail_identifier(&id)
        .guardrail_version("DRAFT")
        .trace(GuardrailTrace::Enabled)
        .build();
    let out = r
        .converse()
        .model_id(HAIKU)
        .messages(user("Which investments are best?"))
        .guardrail_config(g.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(out.stop_reason(), &StopReason::GuardrailIntervened);
    let ConverseOutput::Message(m) = out.output().unwrap() else { panic!("no message") };
    assert_eq!(m.content()[0].as_text().unwrap(), "Sorry, I can't help with that.");
    let trace = out.trace().unwrap().guardrail().unwrap();
    assert!(trace.input_assessment().unwrap().contains_key(&id));

    // Output masking: the echoed email is anonymized.
    let out =
        r.converse().model_id(HAIKU).messages(user("mail bob@example.com")).guardrail_config(g).send().await.unwrap();
    let ConverseOutput::Message(m) = out.output().unwrap() else { panic!("no message") };
    assert_eq!(m.content()[0].as_text().unwrap(), "mail {EMAIL}");

    // InvokeModel takes the guardrail in headers.
    let out = r
        .invoke_model()
        .model_id(HAIKU)
        .guardrail_identifier(&id)
        .guardrail_version("DRAFT")
        .body(Blob::new(
            json!({"anthropic_version": "bedrock-2023-05-31", "max_tokens": 50,
                   "messages": [{"role": "user", "content": "say frobnicate"}]})
            .to_string(),
        ))
        .send()
        .await
        .unwrap();
    let v: Value = serde_json::from_slice(out.body().as_ref()).unwrap();
    assert_eq!(v["amazon-bedrock-guardrailAction"], "INTERVENED");
    assert_eq!(v["content"][0]["text"], "Sorry, I can't help with that.");

    let e = r
        .apply_guardrail()
        .guardrail_identifier(&id)
        .guardrail_version("9")
        .source(GuardrailContentSource::Input)
        .content(GuardrailContentBlock::Text(GuardrailTextBlock::builder().text("x").build().unwrap()))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "ValidationException");
    mws.stop().await;
}

#[tokio::test]
async fn count_tokens_and_unsupported_operations() {
    let mws = Mws::start().await;
    let r = Client::new(&mws.root_sdk_config().await);
    let n = r
        .count_tokens()
        .model_id(HAIKU)
        .input(CountTokensInput::Converse(ConverseTokensRequest::builder().messages(user("12345678")).build()))
        .send()
        .await
        .unwrap();
    assert_eq!(n.input_tokens(), 2);
    let n = r
        .count_tokens()
        .model_id(HAIKU)
        .input(CountTokensInput::InvokeModel(
            InvokeModelTokensRequest::builder()
                .body(Blob::new(
                    json!({"anthropic_version": "bedrock-2023-05-31", "max_tokens": 10,
                           "messages": [{"role": "user", "content": "12345678"}]})
                    .to_string(),
                ))
                .build()
                .unwrap(),
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(n.input_tokens(), 2);
    let e = r
        .count_tokens()
        .model_id(NOVA_MICRO)
        .input(CountTokensInput::Converse(ConverseTokensRequest::builder().messages(user("x")).build()))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "ValidationException");

    // Bidirectional streaming (Nova Sonic) and guardrail checks are not
    // emulated; they fail cleanly.
    let stream = aws_sdk_bedrockruntime::primitives::event_stream::EventStreamSender::once(Ok(
        InvokeModelWithBidirectionalStreamInput::Chunk(
            BidirectionalInputPayloadPart::builder().bytes(Blob::new("{}")).build(),
        ),
    ));
    let e = r.invoke_model_with_bidirectional_stream().model_id("amazon.nova-sonic-v1:0").body(stream).send().await;
    assert!(e.is_err());
    let e = r.invoke_guardrail_checks().send().await;
    assert!(e.is_err());
    mws.stop().await;
}

#[tokio::test]
async fn async_invoke_and_batch_inference_write_to_s3() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let r = Client::new(&cfg);
    let b = aws_sdk_bedrock::Client::new(&cfg);
    let s3 = Mws::s3(&cfg);
    s3.create_bucket().bucket("bedrock-out").send().await.unwrap();

    let started = r
        .start_async_invoke()
        .model_id("amazon.nova-reel-v1:1")
        .model_input(doc(&json!({"taskType": "TEXT_VIDEO", "textToVideoParams": {"text": "waves at dusk"},
            "videoGenerationConfig": {"durationSeconds": 6, "fps": 24, "dimension": "1280x720"}})))
        .output_data_config(AsyncInvokeOutputDataConfig::S3OutputDataConfig(
            AsyncInvokeS3OutputDataConfig::builder().s3_uri("s3://bedrock-out/videos").build().unwrap(),
        ))
        .client_request_token("video-token-1")
        .send()
        .await
        .unwrap();
    let arn = started.invocation_arn().to_string();
    assert!(arn.starts_with(&format!("arn:aws:bedrock:us-east-1:{ACCOUNT}:async-invoke/")));
    let got = r.get_async_invoke().invocation_arn(&arn).send().await.unwrap();
    assert_eq!(got.status(), &AsyncInvokeStatus::InProgress);
    advance(&mws, 5).await;
    let got = r.get_async_invoke().invocation_arn(&arn).send().await.unwrap();
    assert_eq!(got.status(), &AsyncInvokeStatus::Completed);
    let AsyncInvokeOutputDataConfig::S3OutputDataConfig(out) = got.output_data_config().unwrap() else { panic!() };
    let key = format!("{}/output.mp4", out.s3_uri().trim_start_matches("s3://bedrock-out/"));
    let video = s3.get_object().bucket("bedrock-out").key(&key).send().await.unwrap();
    assert_eq!(video.content_type(), Some("video/mp4"));
    let list = r.list_async_invokes().status_equals(AsyncInvokeStatus::Completed).send().await.unwrap();
    assert_eq!(list.async_invoke_summaries().len(), 1);
    let again = r
        .start_async_invoke()
        .model_id("amazon.nova-reel-v1:1")
        .model_input(doc(&json!({"taskType": "TEXT_VIDEO", "textToVideoParams": {"text": "waves at dusk"}})))
        .output_data_config(AsyncInvokeOutputDataConfig::S3OutputDataConfig(
            AsyncInvokeS3OutputDataConfig::builder().s3_uri("s3://bedrock-out/videos").build().unwrap(),
        ))
        .client_request_token("video-token-1")
        .send()
        .await
        .unwrap();
    assert_eq!(again.invocation_arn(), arn);

    // Batch inference reads JSONL from S3 and writes the answers back.
    let records = [
        json!({"recordId": "r1", "modelInput": {"anthropic_version": "bedrock-2023-05-31", "max_tokens": 50,
               "messages": [{"role": "user", "content": "first"}]}}),
        json!({"recordId": "r2", "modelInput": {"anthropic_version": "bedrock-2023-05-31", "max_tokens": 50,
               "messages": [{"role": "user", "content": "second"}]}}),
        json!({"recordId": "r3", "modelInput": {"nonsense": true}}),
    ];
    let body = records.iter().map(|r| r.to_string()).collect::<Vec<_>>().join("\n");
    s3.put_object()
        .bucket("bedrock-out")
        .key("batch/in/records.jsonl")
        .body(body.into_bytes().into())
        .send()
        .await
        .unwrap();
    let job = b
        .create_model_invocation_job()
        .job_name("batch-1")
        .role_arn(format!("arn:aws:iam::{ACCOUNT}:role/batch"))
        .model_id(HAIKU)
        .input_data_config(aws_sdk_bedrock::types::ModelInvocationJobInputDataConfig::S3InputDataConfig(
            aws_sdk_bedrock::types::ModelInvocationJobS3InputDataConfig::builder()
                .s3_uri("s3://bedrock-out/batch/in/")
                .build()
                .unwrap(),
        ))
        .output_data_config(aws_sdk_bedrock::types::ModelInvocationJobOutputDataConfig::S3OutputDataConfig(
            aws_sdk_bedrock::types::ModelInvocationJobS3OutputDataConfig::builder()
                .s3_uri("s3://bedrock-out/batch/out/")
                .build()
                .unwrap(),
        ))
        .send()
        .await
        .unwrap();
    let mut status = None;
    for _ in 0..100 {
        let got = b.get_model_invocation_job().job_identifier(job.job_arn()).send().await.unwrap();
        status = got.status().cloned();
        if matches!(status, Some(aws_sdk_bedrock::types::ModelInvocationJobStatus::PartiallyCompleted)) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(status, Some(aws_sdk_bedrock::types::ModelInvocationJobStatus::PartiallyCompleted));
    let id = job.job_arn().rsplit('/').next().unwrap();
    let out =
        s3.get_object().bucket("bedrock-out").key(format!("batch/out/{id}/records.jsonl.out")).send().await.unwrap();
    let text = String::from_utf8(out.body.collect().await.unwrap().to_vec()).unwrap();
    let lines: Vec<Value> = text.lines().map(|l| serde_json::from_str(l).unwrap()).collect();
    assert_eq!(lines[0]["recordId"], "r1");
    assert_eq!(lines[0]["modelOutput"]["content"][0]["text"], "first");
    assert!(lines[2]["error"]["errorMessage"].as_str().unwrap().starts_with("Malformed input request"));
    let manifest =
        s3.get_object().bucket("bedrock-out").key(format!("batch/out/{id}/manifest.json.out")).send().await.unwrap();
    let manifest: Value = serde_json::from_slice(&manifest.body.collect().await.unwrap().to_vec()).unwrap();
    assert_eq!(manifest["successRecordCount"], 2);
    assert_eq!(manifest["errorRecordCount"], 1);
    let jobs = b.list_model_invocation_jobs().send().await.unwrap();
    assert_eq!(jobs.invocation_job_summaries().len(), 1);
    b.stop_model_invocation_job().job_identifier(job.job_arn()).send().await.unwrap_err();
    mws.stop().await;
}

#[tokio::test]
async fn invocation_needs_permission_on_profile_and_models() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let b = aws_sdk_bedrock::Client::new(&cfg);
    let app = b
        .create_inference_profile()
        .inference_profile_name("team-a")
        .model_source(aws_sdk_bedrock::types::InferenceProfileModelSource::CopyFrom(format!(
            "arn:aws:bedrock:us-east-1::foundation-model/{HAIKU}"
        )))
        .send()
        .await
        .unwrap();
    let profile = app.inference_profile_arn().to_string();

    // Allowed on the profile only: the model itself is denied.
    let only_profile = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"bedrock:InvokeModel","Resource":"{profile}"}}]}}"#
    );
    let (_, user_cfg) = mws_e2e::user_with_policy(&mws, "profile-only", Some(&only_profile)).await;
    let r = Client::new(&user_cfg);
    let e = r.converse().model_id(&profile).messages(user("hi")).send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "AccessDeniedException");

    let both = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"bedrock:InvokeModel","Resource":["{profile}","arn:aws:bedrock:*::foundation-model/*"]}}]}}"#
    );
    let (_, user_cfg) = mws_e2e::user_with_policy(&mws, "profile-and-model", Some(&both)).await;
    let r = Client::new(&user_cfg);
    let out = r.converse().model_id(&profile).messages(user("hi")).send().await.unwrap();
    let ConverseOutput::Message(m) = out.output().unwrap() else { panic!("no message") };
    assert_eq!(m.content()[0].as_text().unwrap(), "hi");
    // Streaming needs its own action.
    let e = r.converse_stream().model_id(&profile).messages(user("hi")).send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "AccessDeniedException");
    mws.stop().await;
}

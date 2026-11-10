//! Bedrock runtime checks through the official Rust SDK: IAM condition
//! keys on invocations (guardrails, inference profiles), per-model
//! capabilities and limits, tool result pairing, and model request fields
//! with Claude's extended thinking.

use aws_sdk_bedrockruntime::primitives::Blob;
use aws_sdk_bedrockruntime::types::*;
use aws_sdk_bedrockruntime::Client;
use mws_e2e::Mws;
use serde_json::json;

use crate::bedrock::{code, guardrail, message, ACCOUNT};
use crate::bedrock_runtime::{doc, user};

const HAIKU: &str = "anthropic.claude-3-haiku-20240307-v1:0";

fn err<E: aws_sdk_bedrockruntime::error::ProvideErrorMetadata>(e: &E) -> (String, String) {
    (code(e), message(e))
}

#[tokio::test]
async fn guardrail_and_profile_condition_keys() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let b = aws_sdk_bedrock::Client::new(&cfg);
    let (id, arn) = guardrail(&b, "required").await;
    let v = b.create_guardrail_version().guardrail_identifier(&id).send().await.unwrap();
    assert_eq!(v.version(), "1");
    let versioned = format!("{arn}:1");
    let with_guardrail = || GuardrailConfiguration::builder().guardrail_identifier(&id).guardrail_version("1").build();

    // Invocations are allowed only with the guardrail.
    let require = format!(
        r#"{{"Version":"2012-10-17","Statement":[
            {{"Effect":"Allow","Action":"bedrock:InvokeModel","Resource":"*",
              "Condition":{{"StringEquals":{{"bedrock:GuardrailIdentifier":"{versioned}"}}}}}},
            {{"Effect":"Allow","Action":"bedrock:ApplyGuardrail","Resource":"{arn}"}}]}}"#
    );
    let (_, user_cfg) = mws_e2e::user_with_policy(&mws, "needs-guardrail", Some(&require)).await;
    let r = Client::new(&user_cfg);
    let e = r.converse().model_id(HAIKU).messages(user("hi")).send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "AccessDeniedException");
    let out =
        r.converse().model_id(HAIKU).messages(user("hi")).guardrail_config(with_guardrail()).send().await.unwrap();
    assert_eq!(out.stop_reason(), &StopReason::EndTurn);
    // InvokeModel takes the guardrail in headers.
    let body = json!({"anthropic_version": "bedrock-2023-05-31", "max_tokens": 20,
                      "messages": [{"role": "user", "content": "hi"}]})
    .to_string();
    let e = r.invoke_model().model_id(HAIKU).body(Blob::new(body.clone())).send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "AccessDeniedException");
    r.invoke_model()
        .model_id(HAIKU)
        .body(Blob::new(body))
        .guardrail_identifier(&arn)
        .guardrail_version("1")
        .send()
        .await
        .unwrap();

    // Deny unless guarded: unguarded calls are denied, guarded ones pass.
    let deny = format!(
        r#"{{"Version":"2012-10-17","Statement":[
            {{"Effect":"Allow","Action":["bedrock:InvokeModel","bedrock:ApplyGuardrail"],"Resource":"*"}},
            {{"Effect":"Deny","Action":"bedrock:InvokeModel","Resource":"*",
              "Condition":{{"StringNotEquals":{{"bedrock:GuardrailIdentifier":"{versioned}"}}}}}}]}}"#
    );
    let (_, user_cfg) = mws_e2e::user_with_policy(&mws, "deny-unguarded", Some(&deny)).await;
    let r = Client::new(&user_cfg);
    let e = r.converse().model_id(HAIKU).messages(user("hi")).send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "AccessDeniedException");
    r.converse().model_id(HAIKU).messages(user("hi")).guardrail_config(with_guardrail()).send().await.unwrap();

    // Models may be invoked only through US inference profiles.
    let profiles = r#"{"Version":"2012-10-17","Statement":[
        {"Effect":"Allow","Action":"bedrock:InvokeModel","Resource":"arn:aws:bedrock:*:*:inference-profile/us.*"},
        {"Effect":"Allow","Action":"bedrock:InvokeModel","Resource":"arn:aws:bedrock:*::foundation-model/*",
         "Condition":{"StringLike":{"bedrock:InferenceProfileArn":"arn:aws:bedrock:*:*:inference-profile/us.*"}}}]}"#;
    let (_, user_cfg) = mws_e2e::user_with_policy(&mws, "profiles-only", Some(profiles)).await;
    let r = Client::new(&user_cfg);
    let e = r.converse().model_id(HAIKU).messages(user("hi")).send().await.unwrap_err();
    assert_eq!(code(e.as_service_error().unwrap()), "AccessDeniedException");
    let profile = format!("arn:aws:bedrock:us-east-1:{ACCOUNT}:inference-profile/us.{HAIKU}");
    r.converse().model_id(&profile).messages(user("hi")).send().await.unwrap();
    mws.stop().await;
}

fn weather_tools(choice: Option<ToolChoice>) -> ToolConfiguration {
    ToolConfiguration::builder()
        .tools(Tool::ToolSpec(
            ToolSpecification::builder()
                .name("get_weather")
                .input_schema(ToolInputSchema::Json(doc(&json!({"type": "object"}))))
                .build()
                .unwrap(),
        ))
        .set_tool_choice(choice)
        .build()
        .unwrap()
}

#[tokio::test]
async fn model_capabilities_and_limits() {
    let mws = Mws::start().await;
    let r = Client::new(&mws.root_sdk_config().await);
    let titan = "amazon.titan-text-express-v1";

    let e = r.converse().model_id(titan).messages(user("hi")).tool_config(weather_tools(None)).send().await;
    let e = e.unwrap_err();
    assert_eq!(
        err(e.as_service_error().unwrap()),
        ("ValidationException".into(), "This model doesn't support tool use.".into())
    );
    let e = r
        .converse()
        .model_id(titan)
        .system(SystemContentBlock::Text("Be brief.".into()))
        .messages(user("hi"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(message(e.as_service_error().unwrap()), "This model doesn't support system messages.");
    let any = ToolChoice::Any(AnyToolChoice::builder().build());
    let e = r
        .converse()
        .model_id("cohere.command-r-v1:0")
        .messages(user("hi"))
        .tool_config(weather_tools(Some(any)))
        .send()
        .await
        .unwrap_err();
    assert_eq!(
        message(e.as_service_error().unwrap()),
        "This model doesn't support the toolConfig.toolChoice.any field. Remove toolConfig.toolChoice.any and try again."
    );
    let image = Message::builder()
        .role(ConversationRole::User)
        .content(ContentBlock::Text("what is this?".into()))
        .content(ContentBlock::Image(
            ImageBlock::builder()
                .format(ImageFormat::Png)
                .source(ImageSource::Bytes(Blob::new(vec![0x89, b'P', b'N', b'G'])))
                .build()
                .unwrap(),
        ))
        .build()
        .unwrap();
    let e = r.converse().model_id("meta.llama3-8b-instruct-v1:0").messages(image.clone()).send().await.unwrap_err();
    assert_eq!(
        message(e.as_service_error().unwrap()),
        "This model doesn't support the image content block that you provided."
    );
    r.converse().model_id(HAIKU).messages(image).send().await.unwrap();

    // Output and context limits.
    let e = r
        .converse()
        .model_id(HAIKU)
        .messages(user("hi"))
        .inference_config(InferenceConfiguration::builder().max_tokens(5000).build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(
        message(e.as_service_error().unwrap()),
        "The maximum tokens you requested exceeds the model limit of 4096. Try again with a maximum tokens value that is lower than 4096."
    );
    let body = json!({"anthropic_version": "bedrock-2023-05-31", "max_tokens": 5000,
                      "messages": [{"role": "user", "content": "hi"}]});
    let e = r.invoke_model().model_id(HAIKU).body(Blob::new(body.to_string())).send().await.unwrap_err();
    assert_eq!(
        message(e.as_service_error().unwrap()),
        "max_tokens: 5000 > 4096, which is the maximum allowed number of output tokens for claude-3-haiku-20240307"
    );
    // Titan Text Lite has a 4,000-token context window.
    let long = "word ".repeat(4_000);
    let e = r.converse().model_id("amazon.titan-text-lite-v1").messages(user(&long)).send().await.unwrap_err();
    assert_eq!(
        err(e.as_service_error().unwrap()),
        ("ValidationException".into(), "Input is too long for requested model.".into())
    );
    mws.stop().await;
}

#[tokio::test]
async fn tool_results_answer_the_previous_turn() {
    let mws = Mws::start().await;
    let r = Client::new(&mws.root_sdk_config().await);
    let result = |id: &str| {
        Message::builder()
            .role(ConversationRole::User)
            .content(ContentBlock::ToolResult(
                ToolResultBlock::builder()
                    .tool_use_id(id)
                    .content(ToolResultContentBlock::Text("18 degrees".into()))
                    .build()
                    .unwrap(),
            ))
            .build()
            .unwrap()
    };
    let said =
        |content: ContentBlock| Message::builder().role(ConversationRole::Assistant).content(content).build().unwrap();
    let e = r
        .converse()
        .model_id(HAIKU)
        .messages(user("weather?"))
        .messages(said(ContentBlock::Text("Let me check.".into())))
        .messages(result("tooluse_1"))
        .tool_config(weather_tools(None))
        .send()
        .await
        .unwrap_err();
    assert_eq!(
        message(e.as_service_error().unwrap()),
        "The number of toolResult blocks at messages.2.content exceeds the number of toolUse blocks of previous turn."
    );
    let call = ContentBlock::ToolUse(
        ToolUseBlock::builder().tool_use_id("tooluse_1").name("get_weather").input(doc(&json!({}))).build().unwrap(),
    );
    let e = r
        .converse()
        .model_id(HAIKU)
        .messages(user("weather?"))
        .messages(said(call.clone()))
        .messages(result("tooluse_2"))
        .tool_config(weather_tools(None))
        .send()
        .await
        .unwrap_err();
    let m = message(e.as_service_error().unwrap());
    assert!(m.starts_with("messages.2.content.0: unexpected toolUseId found in toolResult blocks: tooluse_2."), "{m}");
    let out = r
        .converse()
        .model_id(HAIKU)
        .messages(user("weather?"))
        .messages(said(call))
        .messages(result("tooluse_1"))
        .tool_config(weather_tools(None))
        .send()
        .await
        .unwrap();
    let ConverseOutput::Message(m) = out.output().unwrap() else { panic!("no message") };
    assert_eq!(m.content()[0].as_text().unwrap(), "18 degrees");
    mws.stop().await;
}

#[tokio::test]
async fn model_request_fields_and_extended_thinking() {
    let mws = Mws::start().await;
    let r = Client::new(&mws.root_sdk_config().await);
    let sonnet = "us.anthropic.claude-sonnet-4-5-20250929-v1:0";
    let ask = |fields: serde_json::Value| {
        r.converse()
            .model_id(sonnet)
            .messages(user("Why is the sky blue?"))
            .inference_config(InferenceConfiguration::builder().max_tokens(4096).build())
            .additional_model_request_fields(doc(&fields))
            .send()
    };
    let out = ask(json!({"thinking": {"type": "enabled", "budget_tokens": 2048}, "top_k": 50})).await.unwrap();
    let ConverseOutput::Message(m) = out.output().unwrap() else { panic!("no message") };
    let ReasoningContentBlock::ReasoningText(t) = m.content()[0].as_reasoning_content().unwrap() else {
        panic!("no reasoning text")
    };
    assert!(t.text().contains("Why is the sky blue?"));
    let signature = t.signature().unwrap_or_default();
    assert!(signature.len() > 40, "{signature}");
    assert_eq!(m.content()[1].as_text().unwrap(), "Why is the sky blue?");

    // The reasoning block goes back with its signature in the next turn.
    let again = r
        .converse()
        .model_id(sonnet)
        .messages(user("Why is the sky blue?"))
        .messages(m.clone())
        .messages(user("And at sunset?"))
        .inference_config(InferenceConfiguration::builder().max_tokens(4096).build())
        .additional_model_request_fields(doc(&json!({"thinking": {"type": "enabled", "budget_tokens": 2048}})))
        .send()
        .await
        .unwrap();
    assert_eq!(again.stop_reason(), &StopReason::EndTurn);

    let e = ask(json!({"thinking": {"type": "enabled", "budget_tokens": 100}})).await.unwrap_err();
    assert_eq!(
        message(e.as_service_error().unwrap()),
        "thinking.enabled.budget_tokens: Input should be greater than or equal to 1024"
    );
    let e = ask(json!({"thinking": {"type": "enabled", "budget_tokens": 8000}})).await.unwrap_err();
    assert_eq!(message(e.as_service_error().unwrap()), "`max_tokens` must be greater than `thinking.budget_tokens`.");
    let e = ask(json!({"frobnicate": true})).await.unwrap_err();
    assert_eq!(
        err(e.as_service_error().unwrap()),
        (
            "ValidationException".into(),
            "Malformed input request: #: extraneous key [frobnicate] is not permitted, please reformat your input and try again."
                .into()
        )
    );

    // Native Claude bodies carry the signature too.
    let body = json!({"anthropic_version": "bedrock-2023-05-31", "max_tokens": 4096,
        "thinking": {"type": "enabled", "budget_tokens": 1024},
        "messages": [{"role": "user", "content": "think"}]});
    let out = r.invoke_model().model_id(sonnet).body(Blob::new(body.to_string())).send().await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(out.body().as_ref()).unwrap();
    assert_eq!(v["content"][0]["type"], "thinking");
    assert!(v["content"][0]["signature"].as_str().unwrap().len() > 40);
    mws.stop().await;
}

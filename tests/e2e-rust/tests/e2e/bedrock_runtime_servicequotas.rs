//! Bedrock on-demand throughput quotas through the official Rust SDK:
//! requests and tokens per minute per model, listed by Service Quotas,
//! enforced with `ThrottlingException`, and raised by increase requests.

use aws_sdk_bedrockruntime::config::retry::RetryConfig;
use aws_sdk_bedrockruntime::types::*;
use aws_sdk_bedrockruntime::Client;
use mws_e2e::Mws;

use crate::bedrock::{advance, code, message};
use crate::bedrock_runtime::user;

const SONNET_35: &str = "anthropic.claude-3-5-sonnet-20240620-v1:0";
const RPM: &str = "L-7F1F480A";

#[tokio::test]
async fn invocations_are_throttled_at_their_quotas() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let sq = aws_sdk_servicequotas::Client::new(&cfg);
    // No retries, so every throttled call shows.
    let r = Client::from_conf(
        aws_sdk_bedrockruntime::config::Builder::from(&cfg).retry_config(RetryConfig::disabled()).build(),
    );

    let quota = sq.get_service_quota().service_code("bedrock").quota_code(RPM).send().await.unwrap();
    let quota = quota.quota().unwrap();
    assert_eq!(quota.quota_name(), Some("On-demand InvokeModel requests per minute for Anthropic Claude 3.5 Sonnet"));
    assert_eq!(quota.value(), Some(50.0));
    let all = sq.list_service_quotas().service_code("bedrock").max_results(100).send().await.unwrap();
    assert!(all.quotas().iter().any(|q| q.quota_name() == Some("Minimum number of records per batch inference job")));

    for _ in 0..50 {
        r.converse().model_id(SONNET_35).messages(user("hi")).send().await.unwrap();
    }
    let e = r.converse().model_id(SONNET_35).messages(user("hi")).send().await.unwrap_err();
    assert_eq!(e.raw_response().unwrap().status().as_u16(), 429);
    let e = e.as_service_error().unwrap();
    assert_eq!(code(e), "ThrottlingException");
    assert_eq!(message(e), "Too many requests, please wait before trying again.");
    // Other models have quotas of their own.
    r.converse().model_id("anthropic.claude-3-haiku-20240307-v1:0").messages(user("hi")).send().await.unwrap();

    // A raised quota applies once approved.
    sq.request_service_quota_increase()
        .service_code("bedrock")
        .quota_code(RPM)
        .desired_value(100.0)
        .send()
        .await
        .unwrap();
    advance(&mws, 2).await;
    r.converse().model_id(SONNET_35).messages(user("hi")).send().await.unwrap();

    // Tokens per minute (400,000): two 180,000-token prompts fit, a third
    // does not until the window moves on.
    advance(&mws, 61).await;
    let big = "abcd".repeat(180_000);
    let ask = || {
        r.converse()
            .model_id(SONNET_35)
            .messages(user(&big))
            .inference_config(InferenceConfiguration::builder().max_tokens(10).build())
            .send()
    };
    ask().await.unwrap();
    ask().await.unwrap();
    let e = ask().await.unwrap_err();
    let e = e.as_service_error().unwrap();
    assert_eq!(code(e), "ThrottlingException");
    assert_eq!(message(e), "Too many tokens, please wait before trying again.");
    advance(&mws, 61).await;
    ask().await.unwrap();
    mws.stop().await;
}

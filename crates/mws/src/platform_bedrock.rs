//! Cross-service glue for Bedrock: on-demand token usage becomes Cost
//! Explorer charges.

use std::sync::Arc;

use mws_bedrock_runtime::{TokenUsage, TokenUsageSink};
use mws_ce::{CostExplorer, UsageCharge};

/// Bills each on-demand invocation's input and output tokens.
pub(crate) struct BedrockToCostExplorer(pub CostExplorer);

/// Public on-demand prices per 1,000 (input, output) tokens, by model id.
fn price_per_1k(model_id: &str) -> (f64, f64) {
    let m = model_id.to_ascii_lowercase();
    let table: &[(&str, (f64, f64))] = &[
        ("claude-opus-4", (0.015, 0.075)),
        ("claude-3-opus", (0.015, 0.075)),
        ("claude-sonnet-4", (0.003, 0.015)),
        ("claude-3-7-sonnet", (0.003, 0.015)),
        ("claude-3-5-sonnet", (0.003, 0.015)),
        ("claude-3-sonnet", (0.003, 0.015)),
        ("claude-3-5-haiku", (0.0008, 0.004)),
        ("claude-haiku-4", (0.001, 0.005)),
        ("claude-3-haiku", (0.00025, 0.00125)),
        ("nova-premier", (0.0025, 0.0125)),
        ("nova-pro", (0.0008, 0.0032)),
        ("nova-lite", (0.00006, 0.00024)),
        ("nova-micro", (0.000035, 0.00014)),
        ("titan-embed", (0.0001, 0.0)),
        ("titan-text", (0.0002, 0.0006)),
        ("llama3", (0.00072, 0.00072)),
        ("mistral-large", (0.004, 0.012)),
        ("mistral", (0.00015, 0.0002)),
        ("command", (0.0005, 0.0015)),
        ("cohere.embed", (0.0001, 0.0)),
    ];
    table.iter().find(|(k, _)| m.contains(k)).map(|(_, p)| *p).unwrap_or((0.001, 0.002))
}

/// The model part of a token usage type (the model id without its version).
fn model_label(model_id: &str) -> String {
    model_id.split(':').next().unwrap_or(model_id).to_string()
}

impl TokenUsageSink for BedrockToCostExplorer {
    fn record(&self, u: TokenUsage) {
        let (input_price, output_price) = price_per_1k(&u.model_id);
        let code = mws_ce::rates::region_code(&u.region);
        let label = model_label(&u.model_id);
        for (kind, tokens, price) in [("input", u.input_tokens, input_price), ("output", u.output_tokens, output_price)]
        {
            if tokens == 0 {
                continue;
            }
            self.0.record_usage(UsageCharge {
                account: u.account.clone(),
                region: u.region.clone(),
                at: u.at,
                service: "Amazon Bedrock".into(),
                usage_type: format!("{code}-{label}-{kind}-tokens"),
                operation: u.operation.clone(),
                resource_id: Some(u.resource_arn.clone()),
                unit: "Tokens".into(),
                quantity: tokens as f64,
                cost: tokens as f64 / 1000.0 * price,
                tags: Default::default(),
                dimensions: Default::default(),
            });
        }
    }
}

pub(crate) fn wire(runtime: &mws_bedrock_runtime::BedrockRuntime, ce: &CostExplorer) {
    runtime.set_usage_sink(Arc::new(BedrockToCostExplorer(ce.clone())));
}

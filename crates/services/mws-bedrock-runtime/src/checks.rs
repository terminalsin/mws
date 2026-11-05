//! `InvokeGuardrailChecks`: inline content filter, prompt attack and
//! sensitive information checks, scored by the guardrail engine's
//! deterministic detectors.

use mws_bedrock::guard;
use mws_core::{RequestContext, ServiceError};

use crate::generated::types;
use crate::{validation, BedrockRuntime};

impl BedrockRuntime {
    pub(crate) async fn invoke_guardrail_checks(
        &self,
        ctx: &RequestContext,
        input: types::InvokeGuardrailChecksRequest,
    ) -> Result<types::InvokeGuardrailChecksResponse, ServiceError> {
        ctx.authorize("bedrock:InvokeGuardrailChecks", "*", Default::default())?;
        let checks = &input.checks;
        if checks.content_filter.is_none() && checks.prompt_attack.is_none() && checks.sensitive_information.is_none() {
            return Err(validation("At least one check must be specified in checks."));
        }
        if input.messages.is_empty() {
            return Err(validation("At least one message must be provided."));
        }
        // (message index, content index, text)
        let texts: Vec<(usize, usize, &str)> = input
            .messages
            .iter()
            .enumerate()
            .flat_map(|(m, msg)| {
                msg.content.iter().enumerate().map(move |(c, block)| match block {
                    types::GuardrailChecksContentBlock::Text(t) => (m, c, t.as_str()),
                })
            })
            .collect();
        let chars: i64 = texts.iter().map(|(_, _, t)| t.chars().count() as i64).sum();
        let units = guard::text_units(chars) as i32;
        let score = |category: &str| texts.iter().map(|(_, _, t)| guard::severity(category, t)).fold(0.0, f64::max);

        let mut results = types::GuardrailChecksResults::default();
        let mut usage = types::GuardrailChecksUsageResults::default();
        if let Some(cf) = &checks.content_filter {
            results.content_filter = Some(types::GuardrailChecksContentFilterResult {
                results: cf
                    .categories
                    .iter()
                    .map(|c| types::GuardrailChecksContentFilterResultEntry {
                        category: c.category.clone(),
                        severity_score: score(&c.category),
                    })
                    .collect(),
            });
            usage.content_filter = Some(types::GuardrailChecksContentFilterUsage { text_units: units });
        }
        if let Some(pa) = &checks.prompt_attack {
            results.prompt_attack = Some(types::GuardrailChecksPromptAttackResult {
                results: pa
                    .categories
                    .iter()
                    .map(|c| types::GuardrailChecksPromptAttackResultEntry {
                        category: c.category.clone(),
                        severity_score: score(&c.category),
                    })
                    .collect(),
            });
            usage.prompt_attack = Some(types::GuardrailChecksPromptAttackUsage { text_units: units });
        }
        if let Some(si) = &checks.sensitive_information {
            let mut found = Vec::new();
            for (m, c, text) in &texts {
                for entity in &si.entities {
                    for (begin, end) in guard::pii_spans(&entity.r#type, text) {
                        found.push(types::GuardrailChecksSensitiveInformationResultEntry {
                            r#type: entity.r#type.clone(),
                            confidence_score: 0.99,
                            begin_offset: begin as i32,
                            end_offset: end as i32,
                            message_index: *m as i32,
                            content_index: *c as i32,
                        });
                    }
                }
            }
            found.sort_by_key(|e| (e.message_index, e.content_index, e.begin_offset));
            results.sensitive_information =
                Some(types::GuardrailChecksSensitiveInformationResult { results: found, truncated: Some(false) });
            usage.sensitive_information = Some(types::GuardrailChecksSensitiveInformationUsage { text_units: units });
        }
        Ok(types::InvokeGuardrailChecksResponse { results, usage })
    }
}

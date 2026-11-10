//! On-demand throughput quotas: requests and tokens per minute per model,
//! as Service Quotas applies them to the account, counted over a sliding
//! 60-second window on the emulated clock. Over either, the call fails
//! with `ThrottlingException` (429) as AWS's does.

use std::collections::{BTreeMap, VecDeque};

use chrono::{DateTime, Duration, Utc};
use mws_bedrock::{InvocationTarget, TargetKind};
use mws_core::{RequestContext, ServiceError};
use mws_servicequotas::catalog;

use crate::{generated, BedrockRuntime};

const SERVICE: &str = "bedrock";

/// The tokens one invocation used, for billing.
#[derive(Debug, Clone)]
pub struct TokenUsage {
    pub account: String,
    pub region: String,
    pub at: chrono::DateTime<chrono::Utc>,
    pub model_id: String,
    /// What the caller invoked (model, profile or router ARN).
    pub resource_arn: String,
    pub operation: String,
    pub input_tokens: u32,
    pub output_tokens: u32,
}

/// Receives the token usage of every on-demand invocation.
pub trait TokenUsageSink: Send + Sync {
    fn record(&self, usage: TokenUsage);
}

/// Requests and tokens counted against one model's quotas.
#[derive(Debug, Default)]
pub(crate) struct Windows {
    /// `account/region/rpm code` -> (when, counts as a request, tokens).
    entries: BTreeMap<String, VecDeque<(DateTime<Utc>, bool, u64)>>,
}

/// A request admitted against a quota pair; charge its output with
/// [`BedrockRuntime::charge`].
pub(crate) struct Admitted {
    key: String,
}

/// The `(requests, tokens)` quota codes for an invocation, if on-demand
/// quotas apply (not to Provisioned Throughput, custom deployments,
/// imported models or Marketplace endpoints).
fn quota_codes(target: &InvocationTarget) -> Option<(&'static str, &'static str)> {
    let cross = match target.kind {
        TargetKind::SystemProfile => true,
        // An application profile copied from a cross-Region profile routes
        // to more than one Region.
        TargetKind::ApplicationProfile => target.resources.len() > 2,
        TargetKind::FoundationModel | TargetKind::PromptRouter => false,
        _ => return None,
    };
    let m = target.model;
    let (named, other) = if cross {
        ("Cross-region model inference", "Cross-region model inference")
    } else {
        ("On-demand InvokeModel", "On-demand model inference")
    };
    let find = |prefix: &str, what: &str, model: &str| {
        let name = format!("{prefix} {what} per minute for {model}");
        catalog::quotas_of(SERVICE).find(|d| d.name == name).map(|d| d.code)
    };
    let model = format!("{} {}", m.provider_name, m.model_name);
    match (find(named, "requests", &model), find(named, "tokens", &model)) {
        (Some(r), Some(t)) => Some((r, t)),
        _ => Some((find(other, "requests", "other models")?, find(other, "tokens", "other models")?)),
    }
}

impl BedrockRuntime {
    /// Count a request of about `input_tokens` against the model's quotas,
    /// or throttle it.
    pub(crate) fn admit(
        &self,
        ctx: &RequestContext,
        target: &InvocationTarget,
        input_tokens: u32,
    ) -> Result<Option<Admitted>, ServiceError> {
        let Some((rpm_code, tpm_code)) = quota_codes(target) else { return Ok(None) };
        let (account, region, now) = (&ctx.caller.account_id, &ctx.region, ctx.received_at);
        // Read the applied values before taking our own lock.
        let rpm = self.inner.quotas.value(account, region, SERVICE, rpm_code, now);
        let tpm = self.inner.quotas.value(account, region, SERVICE, tpm_code, now);
        let key = format!("{account}/{region}/{rpm_code}");
        let mut windows = self.windows();
        let entries = windows.entries.entry(key.clone()).or_default();
        while entries.front().is_some_and(|(t, _, _)| *t <= now - Duration::seconds(60)) {
            entries.pop_front();
        }
        let requests = entries.iter().filter(|(_, r, _)| *r).count() as f64;
        let tokens: u64 = entries.iter().map(|(_, _, n)| n).sum();
        if requests + 1.0 > rpm {
            return Err(generated::errors::throttling("Too many requests, please wait before trying again."));
        }
        if (tokens + input_tokens as u64) as f64 > tpm {
            return Err(generated::errors::throttling("Too many tokens, please wait before trying again."));
        }
        entries.push_back((now, true, input_tokens as u64));
        Ok(Some(Admitted { key }))
    }

    /// Count the tokens a request produced (and any input beyond its
    /// estimate).
    pub(crate) fn charge(&self, ctx: &RequestContext, admitted: Option<Admitted>, tokens: u32) {
        let Some(a) = admitted else { return };
        if tokens == 0 {
            return;
        }
        self.windows().entries.entry(a.key).or_default().push_back((ctx.received_at, false, tokens as u64));
    }

    /// Report an on-demand invocation's tokens to the usage sink.
    pub(crate) fn bill(
        &self,
        ctx: &RequestContext,
        target: &InvocationTarget,
        operation: &str,
        input: u32,
        output: u32,
    ) {
        let Some(sink) = self.inner.usage.get() else { return };
        if input == 0 && output == 0 {
            return;
        }
        sink.record(TokenUsage {
            account: ctx.caller.account_id.clone(),
            region: ctx.region.clone(),
            at: ctx.received_at,
            model_id: target.model.model_id.to_string(),
            resource_arn: target.arn.clone(),
            operation: operation.to_string(),
            input_tokens: input,
            output_tokens: output,
        });
    }

    fn windows(&self) -> std::sync::MutexGuard<'_, Windows> {
        self.inner.windows.lock().expect("bedrock-runtime quota windows poisoned")
    }
}

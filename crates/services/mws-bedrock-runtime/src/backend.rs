//! What answers model requests.
//!
//! The default [`Echo`] backend is deterministic: it plays back queued
//! scripted responses first, otherwise it calls a tool when the request
//! asks for one (or names one), summarizes tool results, and echoes the
//! last user message. [`OpenAiCompatible`] and [`Anthropic`] pass requests
//! to a real provider (any OpenAI-compatible server such as OpenAI,
//! Ollama, vLLM or LM Studio; or the Anthropic Messages API).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::client as http;
use crate::prompt::{
    sample_input, tokens, truncate_tokens, Completion, OutPart, Part, Prompt, Role, StopReason, ToolChoice,
};

/// A model provider failure, reported as `ModelErrorException`.
#[derive(Debug, Clone)]
pub struct BackendError {
    pub status: u16,
    pub message: String,
}

#[async_trait::async_trait]
pub trait Backend: Send + Sync {
    async fn complete(&self, prompt: &Prompt) -> Result<Completion, BackendError>;
}

/// Which backend MWS uses (`MWS_BEDROCK_BACKEND`).
#[derive(Debug, Clone, Default)]
pub enum BackendConfig {
    #[default]
    Echo,
    OpenAi {
        url: String,
        api_key: Option<String>,
        model: Option<String>,
    },
    Anthropic {
        url: String,
        api_key: Option<String>,
        model: Option<String>,
    },
}

impl BackendConfig {
    /// Read `MWS_BEDROCK_BACKEND` (`echo`, `openai`, `anthropic`),
    /// `MWS_BEDROCK_BACKEND_URL`, `MWS_BEDROCK_BACKEND_API_KEY` and
    /// `MWS_BEDROCK_BACKEND_MODEL`.
    pub fn from_env() -> Self {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let api_key = var("MWS_BEDROCK_BACKEND_API_KEY");
        let model = var("MWS_BEDROCK_BACKEND_MODEL");
        match var("MWS_BEDROCK_BACKEND").as_deref().map(str::to_ascii_lowercase).as_deref() {
            Some("openai") => BackendConfig::OpenAi {
                url: var("MWS_BEDROCK_BACKEND_URL").unwrap_or_else(|| "https://api.openai.com/v1".into()),
                api_key: api_key.or_else(|| var("OPENAI_API_KEY")),
                model,
            },
            Some("anthropic") => BackendConfig::Anthropic {
                url: var("MWS_BEDROCK_BACKEND_URL").unwrap_or_else(|| "https://api.anthropic.com".into()),
                api_key: api_key.or_else(|| var("ANTHROPIC_API_KEY")),
                model,
            },
            Some("echo") | None => BackendConfig::Echo,
            Some(other) => {
                tracing::warn!("unknown MWS_BEDROCK_BACKEND {other:?}; using echo");
                BackendConfig::Echo
            }
        }
    }
}

/// A scripted response, queued through `POST /_aws/bedrock/responses`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Scripted {
    /// Only for this model id (any model when absent).
    #[serde(default)]
    pub model_id: Option<String>,
    #[serde(default)]
    pub text: Option<String>,
    #[serde(default)]
    pub tool_use: Option<ScriptedToolUse>,
    #[serde(default)]
    pub stop_reason: Option<String>,
    /// Fail the call with `ModelErrorException` and this message.
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScriptedToolUse {
    pub name: String,
    #[serde(default)]
    pub input: Value,
}

/// Queued scripted responses, shared by the echo backend and the
/// `/_aws/bedrock/responses` endpoint.
#[derive(Clone, Default)]
pub struct Script(Arc<Mutex<VecDeque<Scripted>>>);

impl Script {
    pub fn push(&self, s: Scripted) {
        self.0.lock().expect("script lock").push_back(s);
    }

    pub fn clear(&self) {
        self.0.lock().expect("script lock").clear();
    }

    pub fn len(&self) -> usize {
        self.0.lock().expect("script lock").len()
    }

    fn take(&self, model_id: &str) -> Option<Scripted> {
        let mut q = self.0.lock().expect("script lock");
        let i = q.iter().position(|s| s.model_id.as_deref().is_none_or(|m| m == model_id))?;
        q.remove(i)
    }
}

pub fn tool_use_id() -> String {
    format!("tooluse_{}", &uuid::Uuid::new_v4().simple().to_string()[..22])
}

/// The deterministic default backend.
pub struct Echo {
    pub script: Script,
}

#[async_trait::async_trait]
impl Backend for Echo {
    async fn complete(&self, prompt: &Prompt) -> Result<Completion, BackendError> {
        let input_tokens = prompt.input_tokens();
        if let Some(s) = self.script.take(&prompt.model_id) {
            if let Some(e) = s.error {
                return Err(BackendError { status: 500, message: e });
            }
            let mut parts = Vec::new();
            if let Some(t) = s.text.filter(|t| !t.is_empty()) {
                parts.push(OutPart::Text(t));
            }
            let mut stop = StopReason::EndTurn;
            if let Some(t) = s.tool_use {
                parts.push(OutPart::ToolUse { id: tool_use_id(), name: t.name, input: t.input });
                stop = StopReason::ToolUse;
            }
            stop = match s.stop_reason.as_deref() {
                Some("max_tokens") => StopReason::MaxTokens,
                Some("stop_sequence") => StopReason::StopSequence,
                Some("tool_use") => StopReason::ToolUse,
                Some("end_turn") => StopReason::EndTurn,
                _ => stop,
            };
            let output_tokens = parts.iter().map(out_tokens).sum::<u32>().max(1);
            return Ok(Completion { parts, stop_reason: stop, stop_sequence: None, input_tokens, output_tokens });
        }
        Ok(echo(prompt, input_tokens))
    }
}

fn out_tokens(p: &OutPart) -> u32 {
    match p {
        OutPart::Text(t) | OutPart::Reasoning(t) => tokens(t),
        OutPart::ToolUse { name, input, .. } => tokens(name) + tokens(&input.to_string()),
    }
}

fn echo(prompt: &Prompt, input_tokens: u32) -> Completion {
    let last = prompt.messages.last();
    // After tool results, say what the tools returned.
    let results: Vec<String> = last
        .filter(|m| m.role == Role::User)
        .into_iter()
        .flat_map(|m| &m.parts)
        .filter_map(|p| match p {
            Part::ToolResult { content, .. } => Some(content.join(" ")),
            _ => None,
        })
        .collect();
    let user_text = prompt.last_user_text();
    let tool = match &prompt.tool_choice {
        _ if prompt.tools.is_empty() || !results.is_empty() => None,
        ToolChoice::None => None,
        ToolChoice::Any => prompt.tools.first(),
        ToolChoice::Tool(name) => prompt.tools.iter().find(|t| &t.name == name),
        ToolChoice::Auto => {
            let lower = user_text.to_lowercase();
            prompt.tools.iter().find(|t| lower.contains(&t.name.to_lowercase()))
        }
    };
    if let Some(t) = tool {
        let parts = vec![OutPart::ToolUse { id: tool_use_id(), name: t.name.clone(), input: sample_input(&t.schema) }];
        let output_tokens = parts.iter().map(out_tokens).sum::<u32>().max(1);
        return Completion {
            parts,
            stop_reason: StopReason::ToolUse,
            stop_sequence: None,
            input_tokens,
            output_tokens,
        };
    }
    let mut text = if results.is_empty() { user_text } else { results.join("\n") };
    let mut stop = StopReason::EndTurn;
    let mut stop_sequence = None;
    if let Some((i, s)) =
        prompt.stop.iter().filter_map(|s| text.find(s.as_str()).map(|i| (i, s))).min_by_key(|(i, _)| *i)
    {
        text.truncate(i);
        stop = StopReason::StopSequence;
        stop_sequence = Some(s.clone());
    }
    if let Some(max) = prompt.max_tokens {
        if tokens(&text) > max {
            text = truncate_tokens(&text, max);
            stop = StopReason::MaxTokens;
        }
    }
    let output_tokens = tokens(&text).max(1);
    Completion { parts: vec![OutPart::Text(text)], stop_reason: stop, stop_sequence, input_tokens, output_tokens }
}

fn upstream_error(status: u16, body: &[u8]) -> BackendError {
    let text = String::from_utf8_lossy(body);
    let message = serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.pointer("/error/message").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_else(|| text.chars().take(500).collect());
    BackendError { status, message }
}

async fn post(url: &str, headers: Vec<(String, String)>, body: &Value) -> Result<Value, BackendError> {
    let mut headers = headers;
    headers.push(("Content-Type".into(), "application/json".into()));
    let res = http::send(http::Request {
        method: "POST",
        url,
        headers,
        body: Some(serde_json::to_vec(body).expect("JSON serializes")),
    })
    .await
    .map_err(|e| BackendError { status: 502, message: format!("The model provider could not be reached: {e}") })?;
    if !(200..300).contains(&res.status) {
        return Err(upstream_error(res.status, &res.body));
    }
    serde_json::from_slice(&res.body)
        .map_err(|e| BackendError { status: 502, message: format!("The model provider sent invalid JSON: {e}") })
}

/// Any server speaking the OpenAI Chat Completions API.
pub struct OpenAiCompatible {
    pub url: String,
    pub api_key: Option<String>,
    pub model: Option<String>,
}

#[async_trait::async_trait]
impl Backend for OpenAiCompatible {
    async fn complete(&self, prompt: &Prompt) -> Result<Completion, BackendError> {
        let mut messages: Vec<Value> = Vec::new();
        if !prompt.system.is_empty() {
            messages.push(json!({"role": "system", "content": prompt.system.join("\n")}));
        }
        for m in &prompt.messages {
            let mut text = Vec::new();
            let mut calls = Vec::new();
            for p in &m.parts {
                match p {
                    Part::Text(t) => text.push(t.clone()),
                    Part::ToolUse { id, name, input } => calls.push(json!({
                        "id": id, "type": "function",
                        "function": {"name": name, "arguments": input.to_string()},
                    })),
                    Part::ToolResult { id, content, .. } => {
                        messages.push(json!({"role": "tool", "tool_call_id": id, "content": content.join("\n")}))
                    }
                    _ => {}
                }
            }
            if !text.is_empty() || !calls.is_empty() {
                let mut msg = json!({"role": m.role.as_str(), "content": text.join("\n")});
                if !calls.is_empty() {
                    msg["tool_calls"] = json!(calls);
                }
                messages.push(msg);
            }
        }
        let mut body = json!({
            "model": self.model.clone().unwrap_or_else(|| prompt.model_id.clone()),
            "messages": messages,
        });
        if let Some(m) = prompt.max_tokens {
            body["max_tokens"] = json!(m);
        }
        if let Some(t) = prompt.temperature {
            body["temperature"] = json!(t);
        }
        if let Some(p) = prompt.top_p {
            body["top_p"] = json!(p);
        }
        if !prompt.stop.is_empty() {
            body["stop"] = json!(prompt.stop);
        }
        if !prompt.tools.is_empty() && prompt.tool_choice != ToolChoice::None {
            body["tools"] = json!(prompt
                .tools
                .iter()
                .map(|t| json!({"type": "function", "function": {
                    "name": t.name, "description": t.description.clone().unwrap_or_default(), "parameters": t.schema,
                }}))
                .collect::<Vec<_>>());
            body["tool_choice"] = match &prompt.tool_choice {
                ToolChoice::Any => json!("required"),
                ToolChoice::Tool(n) => json!({"type": "function", "function": {"name": n}}),
                _ => json!("auto"),
            };
        }
        let mut headers = Vec::new();
        if let Some(k) = &self.api_key {
            headers.push(("Authorization".into(), format!("Bearer {k}")));
        }
        let url = format!("{}/chat/completions", self.url.trim_end_matches('/'));
        let v = post(&url, headers, &body).await?;
        let choice = v.pointer("/choices/0").cloned().unwrap_or_default();
        let msg = choice.get("message").cloned().unwrap_or_default();
        let mut parts = Vec::new();
        if let Some(r) = msg.get("reasoning_content").and_then(Value::as_str).filter(|r| !r.is_empty()) {
            parts.push(OutPart::Reasoning(r.to_string()));
        }
        if let Some(t) = msg.get("content").and_then(Value::as_str).filter(|t| !t.is_empty()) {
            parts.push(OutPart::Text(t.to_string()));
        }
        for c in msg.get("tool_calls").and_then(Value::as_array).into_iter().flatten() {
            let args = c.pointer("/function/arguments").and_then(Value::as_str).unwrap_or("{}");
            parts.push(OutPart::ToolUse {
                id: c.get("id").and_then(Value::as_str).map(str::to_string).unwrap_or_else(tool_use_id),
                name: c.pointer("/function/name").and_then(Value::as_str).unwrap_or_default().to_string(),
                input: serde_json::from_str(args).unwrap_or(json!({})),
            });
        }
        let stop_reason = match choice.get("finish_reason").and_then(Value::as_str) {
            Some("length") => StopReason::MaxTokens,
            Some("tool_calls") => StopReason::ToolUse,
            Some("content_filter") => StopReason::ContentFiltered,
            _ if parts.iter().any(|p| matches!(p, OutPart::ToolUse { .. })) => StopReason::ToolUse,
            _ => StopReason::EndTurn,
        };
        let input_tokens = v
            .pointer("/usage/prompt_tokens")
            .and_then(Value::as_u64)
            .map(|n| n as u32)
            .unwrap_or_else(|| prompt.input_tokens());
        let output_tokens = v
            .pointer("/usage/completion_tokens")
            .and_then(Value::as_u64)
            .map(|n| n as u32)
            .unwrap_or_else(|| parts.iter().map(out_tokens).sum());
        Ok(Completion { parts, stop_reason, stop_sequence: None, input_tokens, output_tokens })
    }
}

/// The Anthropic Messages API.
pub struct Anthropic {
    pub url: String,
    pub api_key: Option<String>,
    pub model: Option<String>,
}

/// The Anthropic API name of a Bedrock model id:
/// `anthropic.claude-sonnet-4-5-20250929-v1:0` -> `claude-sonnet-4-5-20250929`.
pub fn anthropic_model_name(model_id: &str) -> String {
    let id = model_id.strip_prefix("anthropic.").unwrap_or(model_id);
    match id.rfind("-v") {
        Some(i) if id[i + 2..].starts_with(|c: char| c.is_ascii_digit()) => id[..i].to_string(),
        _ => id.to_string(),
    }
}

#[async_trait::async_trait]
impl Backend for Anthropic {
    async fn complete(&self, prompt: &Prompt) -> Result<Completion, BackendError> {
        let mut body = crate::native::anthropic_request(prompt);
        body["model"] = json!(self.model.clone().unwrap_or_else(|| anthropic_model_name(&prompt.model_id)));
        if let Some(o) = body.as_object_mut() {
            o.remove("anthropic_version");
        }
        let mut headers = vec![("anthropic-version".to_string(), "2023-06-01".to_string())];
        if let Some(k) = &self.api_key {
            headers.push(("x-api-key".into(), k.clone()));
        }
        let url = format!("{}/v1/messages", self.url.trim_end_matches('/'));
        let v = post(&url, headers, &body).await?;
        Ok(crate::native::anthropic_completion(&v, prompt))
    }
}

pub fn build(config: &BackendConfig, script: Script) -> Arc<dyn Backend> {
    match config.clone() {
        BackendConfig::Echo => Arc::new(Echo { script }),
        BackendConfig::OpenAi { url, api_key, model } => Arc::new(OpenAiCompatible { url, api_key, model }),
        BackendConfig::Anthropic { url, api_key, model } => Arc::new(Anthropic { url, api_key, model }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_bedrock_ids_to_anthropic_names() {
        assert_eq!(anthropic_model_name("anthropic.claude-sonnet-4-5-20250929-v1:0"), "claude-sonnet-4-5-20250929");
        assert_eq!(anthropic_model_name("anthropic.claude-3-haiku-20240307-v1:0"), "claude-3-haiku-20240307");
    }
}

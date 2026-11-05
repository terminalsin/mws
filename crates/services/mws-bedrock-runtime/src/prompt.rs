//! The provider-neutral form of a model request and response. `Converse`
//! and every `InvokeModel` body format translate to and from these, and
//! backends see only these.

use serde_json::{Map, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    User,
    Assistant,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::User => "user",
            Role::Assistant => "assistant",
        }
    }

    pub fn parse(s: &str) -> Role {
        if s.eq_ignore_ascii_case("assistant") || s.eq_ignore_ascii_case("chatbot") {
            Role::Assistant
        } else {
            Role::User
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Part {
    Text(String),
    /// An image (or document, video) the backend cannot see as text.
    Media {
        kind: String,
        format: String,
        bytes: Vec<u8>,
    },
    ToolUse {
        id: String,
        name: String,
        input: Value,
    },
    ToolResult {
        id: String,
        content: Vec<String>,
        error: bool,
    },
    Reasoning(String),
}

#[derive(Debug, Clone)]
pub struct Msg {
    pub role: Role,
    pub parts: Vec<Part>,
}

impl Msg {
    pub fn text(&self) -> String {
        self.parts
            .iter()
            .filter_map(|p| match p {
                Part::Text(t) => Some(t.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[derive(Debug, Clone)]
pub struct ToolDef {
    pub name: String,
    pub description: Option<String>,
    pub schema: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ToolChoice {
    #[default]
    Auto,
    Any,
    Tool(String),
    None,
}

/// A model request.
#[derive(Debug, Clone, Default)]
pub struct Prompt {
    /// The foundation model id (`anthropic.claude-...`).
    pub model_id: String,
    pub system: Vec<String>,
    pub messages: Vec<Msg>,
    pub tools: Vec<ToolDef>,
    pub tool_choice: ToolChoice,
    pub max_tokens: Option<u32>,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    pub stop: Vec<String>,
}

impl Prompt {
    /// The text of the last user turn.
    pub fn last_user_text(&self) -> String {
        self.messages.iter().rev().find(|m| m.role == Role::User).map(Msg::text).unwrap_or_default()
    }

    /// Every piece of text in the prompt, for guardrails and counting.
    pub fn texts(&self) -> Vec<String> {
        let mut v = self.system.clone();
        for m in &self.messages {
            for p in &m.parts {
                match p {
                    Part::Text(t) | Part::Reasoning(t) => v.push(t.clone()),
                    Part::ToolResult { content, .. } => v.extend(content.iter().cloned()),
                    Part::ToolUse { input, .. } => v.push(input.to_string()),
                    Part::Media { .. } => {}
                }
            }
        }
        v
    }

    pub fn input_tokens(&self) -> u32 {
        let mut n: u32 = self.texts().iter().map(|t| tokens(t)).sum();
        for t in &self.tools {
            n += tokens(&t.name) + tokens(t.description.as_deref().unwrap_or("")) + tokens(&t.schema.to_string());
        }
        for m in &self.messages {
            for p in &m.parts {
                if let Part::Media { bytes, .. } = p {
                    n += (bytes.len() as u32 / 750).max(85);
                }
            }
        }
        n.max(1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    EndTurn,
    ToolUse,
    MaxTokens,
    StopSequence,
    GuardrailIntervened,
    ContentFiltered,
}

impl StopReason {
    /// The `Converse` `stopReason`.
    pub fn converse(self) -> &'static str {
        match self {
            StopReason::EndTurn => "end_turn",
            StopReason::ToolUse => "tool_use",
            StopReason::MaxTokens => "max_tokens",
            StopReason::StopSequence => "stop_sequence",
            StopReason::GuardrailIntervened => "guardrail_intervened",
            StopReason::ContentFiltered => "content_filtered",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum OutPart {
    Text(String),
    ToolUse { id: String, name: String, input: Value },
    Reasoning(String),
}

/// A model response.
#[derive(Debug, Clone)]
pub struct Completion {
    pub parts: Vec<OutPart>,
    pub stop_reason: StopReason,
    pub stop_sequence: Option<String>,
    pub input_tokens: u32,
    pub output_tokens: u32,
}

impl Completion {
    pub fn text(&self) -> String {
        self.parts
            .iter()
            .filter_map(|p| match p {
                OutPart::Text(t) => Some(t.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("")
    }

    pub fn tool_uses(&self) -> impl Iterator<Item = (&str, &str, &Value)> {
        self.parts.iter().filter_map(|p| match p {
            OutPart::ToolUse { id, name, input } => Some((id.as_str(), name.as_str(), input)),
            _ => None,
        })
    }
}

/// MWS's token count: a quarter of the characters, rounded up, like the
/// usual rule of thumb (real tokenizers differ by model).
pub fn tokens(text: &str) -> u32 {
    let chars = text.chars().count() as u32;
    chars.div_ceil(4)
}

/// The first `n` tokens' worth of `text`.
pub fn truncate_tokens(text: &str, n: u32) -> String {
    text.chars().take((n as usize) * 4).collect()
}

/// A tool input that satisfies `schema`: every property gets its first
/// enum value, its default, or a placeholder of its type.
pub fn sample_input(schema: &Value) -> Value {
    if let Some(v) = schema.get("default") {
        return v.clone();
    }
    if let Some(v) = schema.get("enum").and_then(Value::as_array).and_then(|a| a.first()) {
        return v.clone();
    }
    if let Some(v) = schema.get("const") {
        return v.clone();
    }
    let ty = match schema.get("type") {
        Some(Value::String(t)) => t.clone(),
        Some(Value::Array(ts)) => {
            ts.iter().filter_map(Value::as_str).find(|t| *t != "null").unwrap_or("null").to_string()
        }
        _ if schema.get("properties").is_some() => "object".into(),
        _ => "string".into(),
    };
    match ty.as_str() {
        "object" => {
            let mut out = Map::new();
            for (k, v) in schema.get("properties").and_then(Value::as_object).into_iter().flatten() {
                out.insert(k.clone(), sample_input(v));
            }
            Value::Object(out)
        }
        "array" => match schema.get("items") {
            Some(items) if schema.get("minItems").and_then(Value::as_u64).unwrap_or(0) > 0 => {
                Value::Array(vec![sample_input(items)])
            }
            _ => Value::Array(Vec::new()),
        },
        "integer" => schema.get("minimum").cloned().unwrap_or(Value::from(0)),
        "number" => schema.get("minimum").cloned().unwrap_or(Value::from(0.0)),
        "boolean" => Value::Bool(false),
        "null" => Value::Null,
        _ => Value::String("example".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn samples_follow_the_schema() {
        let schema = json!({"type": "object", "properties": {
            "city": {"type": "string"},
            "unit": {"type": "string", "enum": ["celsius", "fahrenheit"]},
            "days": {"type": "integer", "minimum": 1},
        }});
        assert_eq!(sample_input(&schema), json!({"city": "example", "unit": "celsius", "days": 1}));
    }

    #[test]
    fn counts_tokens_by_characters() {
        assert_eq!(tokens(""), 0);
        assert_eq!(tokens("abcd"), 1);
        assert_eq!(tokens("abcde"), 2);
    }
}

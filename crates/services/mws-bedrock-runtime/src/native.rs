//! `InvokeModel` request and response bodies in each provider's native
//! format, and the chunks `InvokeModelWithResponseStream` sends.

use base64::Engine;
use mws_bedrock::catalog::Family;
use mws_core::ServiceError;
use serde_json::{json, Value};

use crate::prompt::{Completion, Msg, OutPart, Part, Prompt, Role, StopReason, ToolChoice, ToolDef};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// What a native request asks for.
pub enum Native {
    Chat(Prompt),
    Embed {
        texts: Vec<String>,
        images: usize,
        dimensions: usize,
        normalize: bool,
        cohere: bool,
        input_type: Option<String>,
    },
    Image {
        text: String,
        count: usize,
        width: u32,
        height: u32,
    },
    Rerank {
        query: String,
        documents: Vec<String>,
        top_n: Option<usize>,
    },
}

pub fn malformed(detail: impl std::fmt::Display) -> ServiceError {
    crate::validation(format!("Malformed input request: {detail}, please reformat your input and try again."))
}

fn required<'a>(v: &'a Value, key: &str) -> Result<&'a Value, ServiceError> {
    v.get(key).filter(|x| !x.is_null()).ok_or_else(|| malformed(format!("#: required key [{key}] not found")))
}

fn str_of<'a>(v: &'a Value, key: &str) -> Result<&'a str, ServiceError> {
    required(v, key)?.as_str().ok_or_else(|| malformed(format!("#/{key}: expected type: String")))
}

fn u32_of(v: &Value, key: &str) -> Option<u32> {
    v.get(key).and_then(Value::as_u64).map(|n| n as u32)
}

fn f64_of(v: &Value, key: &str) -> Option<f64> {
    v.get(key).and_then(Value::as_f64)
}

fn strings(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(str::to_string).collect(),
        _ => Vec::new(),
    }
}

/// Strip chat-template markers from a raw prompt (Llama, Mistral,
/// DeepSeek) and keep the last user turn.
fn last_turn(prompt: &str) -> String {
    let mut p = prompt.to_string();
    if let Some(i) = p.rfind("<|start_header_id|>user<|end_header_id|>") {
        p = p[i + "<|start_header_id|>user<|end_header_id|>".len()..].to_string();
    }
    if let Some(i) = p.rfind("[INST]") {
        p = p[i + 6..].to_string();
    }
    if let Some(i) = p.rfind("<｜User｜>") {
        p = p[i + "<｜User｜>".len()..].to_string();
    }
    for end in ["<|eot_id|>", "[/INST]", "<｜Assistant｜>", "<|start_header_id|>"] {
        if let Some(i) = p.find(end) {
            p.truncate(i);
        }
    }
    let p = p.replace("<|begin_of_text|>", "").replace("<s>", "").replace("</s>", "");
    p.trim().to_string()
}

fn raw_prompt(
    model_id: &str,
    text: String,
    max: Option<u32>,
    temperature: Option<f64>,
    top_p: Option<f64>,
    stop: Vec<String>,
) -> Prompt {
    Prompt {
        model_id: model_id.to_string(),
        messages: vec![Msg { role: Role::User, parts: vec![Part::Text(last_turn(&text))] }],
        max_tokens: max,
        temperature,
        top_p,
        stop,
        ..Default::default()
    }
}

/// OpenAI-style `messages` (Jamba, Pixtral, gpt-oss).
fn openai_messages(model_id: &str, v: &Value) -> Result<Prompt, ServiceError> {
    let msgs = required(v, "messages")?.as_array().ok_or_else(|| malformed("#/messages: expected type: JSONArray"))?;
    let mut p = Prompt { model_id: model_id.to_string(), ..Default::default() };
    for m in msgs {
        let role = m.get("role").and_then(Value::as_str).unwrap_or("user");
        let text = match m.get("content") {
            Some(Value::String(s)) => s.clone(),
            Some(Value::Array(a)) => {
                a.iter().filter_map(|c| c.get("text").and_then(Value::as_str)).collect::<Vec<_>>().join("\n")
            }
            _ => String::new(),
        };
        match role {
            "system" | "developer" => p.system.push(text),
            "tool" => p.messages.push(Msg {
                role: Role::User,
                parts: vec![Part::ToolResult {
                    id: m.get("tool_call_id").and_then(Value::as_str).unwrap_or_default().to_string(),
                    content: vec![text],
                    error: false,
                }],
            }),
            r => p.messages.push(Msg { role: Role::parse(r), parts: vec![Part::Text(text)] }),
        }
    }
    p.max_tokens = u32_of(v, "max_tokens").or_else(|| u32_of(v, "max_completion_tokens"));
    p.temperature = f64_of(v, "temperature");
    p.top_p = f64_of(v, "top_p");
    p.stop = strings(v.get("stop"));
    for t in v.get("tools").and_then(Value::as_array).into_iter().flatten() {
        let f = t.get("function").unwrap_or(t);
        p.tools.push(ToolDef {
            name: f.get("name").and_then(Value::as_str).unwrap_or_default().to_string(),
            description: f.get("description").and_then(Value::as_str).map(str::to_string),
            schema: f.get("parameters").cloned().unwrap_or(json!({"type": "object"})),
        });
    }
    p.tool_choice = match v.get("tool_choice") {
        Some(Value::String(s)) if s == "required" => ToolChoice::Any,
        Some(Value::String(s)) if s == "none" => ToolChoice::None,
        Some(Value::Object(o)) => o
            .get("function")
            .and_then(|f| f.get("name"))
            .and_then(Value::as_str)
            .map(|n| ToolChoice::Tool(n.to_string()))
            .unwrap_or_default(),
        _ => ToolChoice::Auto,
    };
    Ok(p)
}

fn anthropic_content(v: &Value) -> Vec<Part> {
    match v {
        Value::String(s) => vec![Part::Text(s.clone())],
        Value::Array(a) => a
            .iter()
            .filter_map(|c| match c.get("type").and_then(Value::as_str) {
                Some("text") => Some(Part::Text(c.get("text").and_then(Value::as_str).unwrap_or_default().to_string())),
                Some("image") | Some("document") => Some(Part::Media {
                    kind: c.get("type").and_then(Value::as_str).unwrap_or("image").to_string(),
                    format: c.pointer("/source/media_type").and_then(Value::as_str).unwrap_or_default().to_string(),
                    bytes: c
                        .pointer("/source/data")
                        .and_then(Value::as_str)
                        .and_then(|d| B64.decode(d).ok())
                        .unwrap_or_default(),
                }),
                Some("tool_use") => Some(Part::ToolUse {
                    id: c.get("id").and_then(Value::as_str).unwrap_or_default().to_string(),
                    name: c.get("name").and_then(Value::as_str).unwrap_or_default().to_string(),
                    input: c.get("input").cloned().unwrap_or(json!({})),
                }),
                Some("tool_result") => Some(Part::ToolResult {
                    id: c.get("tool_use_id").and_then(Value::as_str).unwrap_or_default().to_string(),
                    content: match c.get("content") {
                        Some(Value::String(s)) => vec![s.clone()],
                        Some(Value::Array(a)) => a
                            .iter()
                            .map(|x| {
                                x.get("text")
                                    .and_then(Value::as_str)
                                    .map(str::to_string)
                                    .unwrap_or_else(|| x.to_string())
                            })
                            .collect(),
                        _ => Vec::new(),
                    },
                    error: c.get("is_error").and_then(Value::as_bool).unwrap_or(false),
                }),
                Some("thinking") => {
                    Some(Part::Reasoning(c.get("thinking").and_then(Value::as_str).unwrap_or_default().to_string()))
                }
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn nova_content(v: &Value) -> Vec<Part> {
    v.as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| {
            if let Some(t) = c.get("text").and_then(Value::as_str) {
                return Some(Part::Text(t.to_string()));
            }
            for kind in ["image", "video", "document"] {
                if let Some(m) = c.get(kind) {
                    return Some(Part::Media {
                        kind: kind.into(),
                        format: m.get("format").and_then(Value::as_str).unwrap_or_default().to_string(),
                        bytes: m
                            .pointer("/source/bytes")
                            .and_then(Value::as_str)
                            .and_then(|d| B64.decode(d).ok())
                            .unwrap_or_default(),
                    });
                }
            }
            if let Some(t) = c.get("toolUse") {
                return Some(Part::ToolUse {
                    id: t.get("toolUseId").and_then(Value::as_str).unwrap_or_default().to_string(),
                    name: t.get("name").and_then(Value::as_str).unwrap_or_default().to_string(),
                    input: t.get("input").cloned().unwrap_or(json!({})),
                });
            }
            if let Some(t) = c.get("toolResult") {
                return Some(Part::ToolResult {
                    id: t.get("toolUseId").and_then(Value::as_str).unwrap_or_default().to_string(),
                    content: t
                        .get("content")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .map(|x| {
                            x.get("text")
                                .and_then(Value::as_str)
                                .map(str::to_string)
                                .unwrap_or_else(|| x.get("json").map(|j| j.to_string()).unwrap_or_default())
                        })
                        .collect(),
                    error: t.get("status").and_then(Value::as_str) == Some("error"),
                });
            }
            None
        })
        .collect()
}

pub fn parse(family: Family, model_id: &str, body: &[u8]) -> Result<Native, ServiceError> {
    let v: Value = serde_json::from_slice(body).map_err(|_| malformed("#: expected type: JSONObject"))?;
    if !v.is_object() {
        return Err(malformed("#: expected type: JSONObject"));
    }
    Ok(match family {
        Family::Anthropic => {
            str_of(&v, "anthropic_version")?;
            let max = required(&v, "max_tokens")?
                .as_u64()
                .ok_or_else(|| malformed("#/max_tokens: expected type: Integer"))?;
            let msgs = required(&v, "messages")?
                .as_array()
                .ok_or_else(|| malformed("#/messages: expected type: JSONArray"))?;
            let mut p = Prompt { model_id: model_id.to_string(), max_tokens: Some(max as u32), ..Default::default() };
            p.system = match v.get("system") {
                Some(Value::String(s)) => vec![s.clone()],
                Some(Value::Array(a)) => {
                    a.iter().filter_map(|b| b.get("text").and_then(Value::as_str)).map(str::to_string).collect()
                }
                _ => Vec::new(),
            };
            for m in msgs {
                let role = m
                    .get("role")
                    .and_then(Value::as_str)
                    .ok_or_else(|| malformed("#/messages: required key [role] not found"))?;
                p.messages.push(Msg {
                    role: Role::parse(role),
                    parts: anthropic_content(m.get("content").unwrap_or(&Value::Null)),
                });
            }
            p.temperature = f64_of(&v, "temperature");
            p.top_p = f64_of(&v, "top_p");
            p.stop = strings(v.get("stop_sequences"));
            for t in v.get("tools").and_then(Value::as_array).into_iter().flatten() {
                p.tools.push(ToolDef {
                    name: t.get("name").and_then(Value::as_str).unwrap_or_default().to_string(),
                    description: t.get("description").and_then(Value::as_str).map(str::to_string),
                    schema: t.get("input_schema").cloned().unwrap_or(json!({"type": "object"})),
                });
            }
            p.tool_choice = match v.pointer("/tool_choice/type").and_then(Value::as_str) {
                Some("any") => ToolChoice::Any,
                Some("none") => ToolChoice::None,
                Some("tool") => {
                    ToolChoice::Tool(v.pointer("/tool_choice/name").and_then(Value::as_str).unwrap_or_default().into())
                }
                _ => ToolChoice::Auto,
            };
            Native::Chat(p)
        }
        Family::Nova => {
            let msgs = required(&v, "messages")?
                .as_array()
                .ok_or_else(|| malformed("#/messages: expected type: JSONArray"))?;
            let mut p = Prompt { model_id: model_id.to_string(), ..Default::default() };
            p.system = v
                .get("system")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .map(str::to_string)
                .collect();
            for m in msgs {
                let role = m.get("role").and_then(Value::as_str).unwrap_or("user");
                p.messages.push(Msg {
                    role: Role::parse(role),
                    parts: nova_content(m.get("content").unwrap_or(&Value::Null)),
                });
            }
            let ic = v.get("inferenceConfig").cloned().unwrap_or_default();
            p.max_tokens = u32_of(&ic, "maxTokens").or_else(|| u32_of(&ic, "max_new_tokens"));
            p.temperature = f64_of(&ic, "temperature");
            p.top_p = f64_of(&ic, "topP").or_else(|| f64_of(&ic, "top_p"));
            p.stop = strings(ic.get("stopSequences"));
            for t in v.pointer("/toolConfig/tools").and_then(Value::as_array).into_iter().flatten() {
                let spec = t.get("toolSpec").unwrap_or(t);
                p.tools.push(ToolDef {
                    name: spec.get("name").and_then(Value::as_str).unwrap_or_default().to_string(),
                    description: spec.get("description").and_then(Value::as_str).map(str::to_string),
                    schema: spec.pointer("/inputSchema/json").cloned().unwrap_or(json!({"type": "object"})),
                });
            }
            p.tool_choice = match v.pointer("/toolConfig/toolChoice") {
                Some(c) if c.get("any").is_some() => ToolChoice::Any,
                Some(c) if c.get("tool").is_some() => {
                    ToolChoice::Tool(c.pointer("/tool/name").and_then(Value::as_str).unwrap_or_default().into())
                }
                _ => ToolChoice::Auto,
            };
            Native::Chat(p)
        }
        Family::TitanText => {
            let text = str_of(&v, "inputText")?.to_string();
            let c = v.get("textGenerationConfig").cloned().unwrap_or_default();
            Native::Chat(raw_prompt(
                model_id,
                text,
                u32_of(&c, "maxTokenCount"),
                f64_of(&c, "temperature"),
                f64_of(&c, "topP"),
                strings(c.get("stopSequences")),
            ))
        }
        Family::Llama => Native::Chat(raw_prompt(
            model_id,
            str_of(&v, "prompt")?.to_string(),
            u32_of(&v, "max_gen_len"),
            f64_of(&v, "temperature"),
            f64_of(&v, "top_p"),
            Vec::new(),
        )),
        Family::Mistral | Family::DeepSeek => {
            if v.get("messages").is_some() {
                Native::Chat(openai_messages(model_id, &v)?)
            } else {
                Native::Chat(raw_prompt(
                    model_id,
                    str_of(&v, "prompt")?.to_string(),
                    u32_of(&v, "max_tokens"),
                    f64_of(&v, "temperature"),
                    f64_of(&v, "top_p"),
                    strings(v.get("stop")),
                ))
            }
        }
        Family::MistralChat | Family::Jamba | Family::OpenAi => Native::Chat(openai_messages(model_id, &v)?),
        Family::CohereCommand => {
            let text = str_of(&v, "message")?.to_string();
            let mut p = Prompt { model_id: model_id.to_string(), ..Default::default() };
            if let Some(pre) = v.get("preamble").and_then(Value::as_str) {
                p.system.push(pre.to_string());
            }
            for h in v.get("chat_history").and_then(Value::as_array).into_iter().flatten() {
                p.messages.push(Msg {
                    role: Role::parse(h.get("role").and_then(Value::as_str).unwrap_or("USER")),
                    parts: vec![Part::Text(h.get("message").and_then(Value::as_str).unwrap_or_default().to_string())],
                });
            }
            p.messages.push(Msg { role: Role::User, parts: vec![Part::Text(text)] });
            p.max_tokens = u32_of(&v, "max_tokens");
            p.temperature = f64_of(&v, "temperature");
            p.top_p = f64_of(&v, "p");
            p.stop = strings(v.get("stop_sequences"));
            Native::Chat(p)
        }
        Family::TitanEmbed | Family::TitanEmbedImage => {
            let text = v.get("inputText").and_then(Value::as_str).map(str::to_string);
            let image = v.get("inputImage").and_then(Value::as_str).is_some();
            if text.is_none() && !image {
                return Err(malformed("#: required key [inputText] not found"));
            }
            let default = if model_id == "amazon.titan-embed-text-v1" { 1536 } else { 1024 };
            let dimensions = v
                .get("dimensions")
                .or_else(|| v.pointer("/embeddingConfig/outputEmbeddingLength"))
                .and_then(Value::as_u64)
                .map(|d| d as usize)
                .unwrap_or(default);
            let allowed: &[usize] = match model_id {
                "amazon.titan-embed-text-v1" => &[1536],
                "amazon.titan-embed-image-v1" => &[256, 384, 1024],
                _ => &[256, 512, 1024],
            };
            if !allowed.contains(&dimensions) {
                return Err(malformed(format!("#/dimensions: {dimensions} is not a valid enum value")));
            }
            Native::Embed {
                texts: text.into_iter().collect(),
                images: image as usize,
                dimensions,
                normalize: v.get("normalize").and_then(Value::as_bool).unwrap_or(true),
                cohere: false,
                input_type: None,
            }
        }
        Family::CohereEmbed => {
            let texts = strings(Some(required(&v, "texts")?));
            Native::Embed {
                texts,
                images: 0,
                dimensions: 1024,
                normalize: true,
                cohere: true,
                input_type: v.get("input_type").and_then(Value::as_str).map(str::to_string),
            }
        }
        Family::CohereRerank => Native::Rerank {
            query: str_of(&v, "query")?.to_string(),
            documents: required(&v, "documents")?
                .as_array()
                .into_iter()
                .flatten()
                .map(|d| d.as_str().map(str::to_string).unwrap_or_else(|| d.to_string()))
                .collect(),
            top_n: v.get("top_n").and_then(Value::as_u64).map(|n| n as usize),
        },
        Family::Image => {
            let text = v
                .pointer("/textToImageParams/text")
                .or_else(|| v.pointer("/text_prompts/0/text"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            let cfg = v.get("imageGenerationConfig").cloned().unwrap_or_default();
            Native::Image {
                text,
                count: cfg.get("numberOfImages").and_then(Value::as_u64).unwrap_or(1).clamp(1, 5) as usize,
                width: u32_of(&cfg, "width").unwrap_or(1024).clamp(1, 4096),
                height: u32_of(&cfg, "height").unwrap_or(1024).clamp(1, 4096),
            }
        }
        Family::Video => {
            return Err(crate::validation(format!(
                "The model {model_id} only supports asynchronous invocation. Use StartAsyncInvoke."
            )))
        }
    })
}

fn openai_finish(stop: StopReason) -> &'static str {
    match stop {
        StopReason::MaxTokens => "length",
        StopReason::ToolUse => "tool_calls",
        StopReason::ContentFiltered | StopReason::GuardrailIntervened => "content_filter",
        _ => "stop",
    }
}

fn anthropic_stop(stop: StopReason) -> &'static str {
    match stop {
        StopReason::MaxTokens => "max_tokens",
        StopReason::ToolUse => "tool_use",
        StopReason::StopSequence => "stop_sequence",
        _ => "end_turn",
    }
}

fn simple_stop(stop: StopReason) -> &'static str {
    if stop == StopReason::MaxTokens {
        "length"
    } else {
        "stop"
    }
}

pub fn message_id(prefix: &str) -> String {
    format!("{prefix}{}", &uuid::Uuid::new_v4().simple().to_string()[..24])
}

/// The Anthropic Messages request for a prompt (for the Anthropic
/// passthrough backend).
pub fn anthropic_request(p: &Prompt) -> Value {
    let messages: Vec<Value> = p
        .messages
        .iter()
        .map(|m| {
            let content: Vec<Value> = m
                .parts
                .iter()
                .filter_map(|part| match part {
                    Part::Text(t) => Some(json!({"type": "text", "text": t})),
                    Part::Media { kind, format, bytes } if kind == "image" => Some(json!({
                        "type": "image",
                        "source": {"type": "base64", "media_type": media_type(format), "data": B64.encode(bytes)},
                    })),
                    Part::ToolUse { id, name, input } => {
                        Some(json!({"type": "tool_use", "id": id, "name": name, "input": input}))
                    }
                    Part::ToolResult { id, content, error } => Some(json!({
                        "type": "tool_result", "tool_use_id": id, "is_error": error,
                        "content": content.iter().map(|c| json!({"type": "text", "text": c})).collect::<Vec<_>>(),
                    })),
                    _ => None,
                })
                .collect();
            json!({"role": m.role.as_str(), "content": content})
        })
        .collect();
    let mut body = json!({
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": p.max_tokens.unwrap_or(4096),
        "messages": messages,
    });
    if !p.system.is_empty() {
        body["system"] = json!(p.system.join("\n"));
    }
    if let Some(t) = p.temperature {
        body["temperature"] = json!(t);
    }
    if let Some(t) = p.top_p {
        body["top_p"] = json!(t);
    }
    if !p.stop.is_empty() {
        body["stop_sequences"] = json!(p.stop);
    }
    if !p.tools.is_empty() && p.tool_choice != ToolChoice::None {
        body["tools"] = json!(p
            .tools
            .iter()
            .map(|t| json!({"name": t.name, "description": t.description, "input_schema": t.schema}))
            .collect::<Vec<_>>());
        body["tool_choice"] = match &p.tool_choice {
            ToolChoice::Any => json!({"type": "any"}),
            ToolChoice::Tool(n) => json!({"type": "tool", "name": n}),
            _ => json!({"type": "auto"}),
        };
    }
    body
}

fn media_type(format: &str) -> String {
    if format.contains('/') {
        format.to_string()
    } else {
        format!("image/{}", if format == "jpg" { "jpeg" } else { format })
    }
}

/// A completion from an Anthropic Messages response.
pub fn anthropic_completion(v: &Value, p: &Prompt) -> Completion {
    let parts = v
        .get("content")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|c| match c.get("type").and_then(Value::as_str) {
            Some("text") => Some(OutPart::Text(c.get("text").and_then(Value::as_str).unwrap_or_default().to_string())),
            Some("thinking") => {
                Some(OutPart::Reasoning(c.get("thinking").and_then(Value::as_str).unwrap_or_default().to_string()))
            }
            Some("tool_use") => Some(OutPart::ToolUse {
                id: c.get("id").and_then(Value::as_str).unwrap_or_default().to_string(),
                name: c.get("name").and_then(Value::as_str).unwrap_or_default().to_string(),
                input: c.get("input").cloned().unwrap_or(json!({})),
            }),
            _ => None,
        })
        .collect();
    let stop_reason = match v.get("stop_reason").and_then(Value::as_str) {
        Some("max_tokens") => StopReason::MaxTokens,
        Some("tool_use") => StopReason::ToolUse,
        Some("stop_sequence") => StopReason::StopSequence,
        Some("refusal") => StopReason::ContentFiltered,
        _ => StopReason::EndTurn,
    };
    Completion {
        parts,
        stop_reason,
        stop_sequence: v.get("stop_sequence").and_then(Value::as_str).map(str::to_string),
        input_tokens: v
            .pointer("/usage/input_tokens")
            .and_then(Value::as_u64)
            .map(|n| n as u32)
            .unwrap_or_else(|| p.input_tokens()),
        output_tokens: v.pointer("/usage/output_tokens").and_then(Value::as_u64).unwrap_or(1) as u32,
    }
}

fn anthropic_api_name(model_id: &str) -> String {
    crate::backend::anthropic_model_name(model_id)
}

/// The native response body for a completion.
pub fn render(family: Family, model_id: &str, c: &Completion) -> Value {
    let text = c.text();
    let (i, o) = (c.input_tokens, c.output_tokens);
    match family {
        Family::Anthropic => {
            let content: Vec<Value> = c
                .parts
                .iter()
                .map(|p| match p {
                    OutPart::Text(t) => json!({"type": "text", "text": t}),
                    OutPart::Reasoning(t) => json!({"type": "thinking", "thinking": t, "signature": ""}),
                    OutPart::ToolUse { id, name, input } => {
                        json!({"type": "tool_use", "id": id, "name": name, "input": input})
                    }
                })
                .collect();
            json!({
                "id": message_id("msg_bdrk_"),
                "type": "message",
                "role": "assistant",
                "model": anthropic_api_name(model_id),
                "content": content,
                "stop_reason": anthropic_stop(c.stop_reason),
                "stop_sequence": c.stop_sequence,
                "usage": {"input_tokens": i, "output_tokens": o},
            })
        }
        Family::Nova => {
            let content: Vec<Value> = c
                .parts
                .iter()
                .map(|p| match p {
                    OutPart::Text(t) => json!({"text": t}),
                    OutPart::Reasoning(t) => json!({"reasoningContent": {"reasoningText": {"text": t}}}),
                    OutPart::ToolUse { id, name, input } => {
                        json!({"toolUse": {"toolUseId": id, "name": name, "input": input}})
                    }
                })
                .collect();
            json!({
                "output": {"message": {"role": "assistant", "content": content}},
                "stopReason": c.stop_reason.converse(),
                "usage": {"inputTokens": i, "outputTokens": o, "totalTokens": i + o,
                          "cacheReadInputTokenCount": 0, "cacheWriteInputTokenCount": 0},
            })
        }
        Family::TitanText => json!({
            "inputTextTokenCount": i,
            "results": [{"tokenCount": o, "outputText": text,
                         "completionReason": if c.stop_reason == StopReason::MaxTokens { "LENGTH" } else { "FINISH" }}],
        }),
        Family::Llama => json!({
            "generation": text, "prompt_token_count": i, "generation_token_count": o,
            "stop_reason": simple_stop(c.stop_reason),
        }),
        Family::Mistral => json!({"outputs": [{"text": text, "stop_reason": simple_stop(c.stop_reason)}]}),
        Family::DeepSeek => json!({"choices": [{"text": text, "stop_reason": simple_stop(c.stop_reason)}]}),
        Family::CohereCommand => json!({
            "response_id": uuid::Uuid::new_v4().to_string(),
            "text": text,
            "generation_id": uuid::Uuid::new_v4().to_string(),
            "chat_history": [],
            "finish_reason": if c.stop_reason == StopReason::MaxTokens { "MAX_TOKENS" } else { "COMPLETE" },
        }),
        _ => {
            let mut message = json!({"role": "assistant", "content": text});
            let calls: Vec<Value> = c
                .tool_uses()
                .map(|(id, name, input)| json!({"id": id, "type": "function", "function": {"name": name, "arguments": input.to_string()}}))
                .collect();
            if !calls.is_empty() {
                message["tool_calls"] = json!(calls);
            }
            if let Some(r) = c.parts.iter().find_map(|p| match p {
                OutPart::Reasoning(r) => Some(r.clone()),
                _ => None,
            }) {
                message["reasoning_content"] = json!(r);
            }
            json!({
                "id": message_id("chatcmpl-"),
                "object": "chat.completion",
                "created": chrono::Utc::now().timestamp(),
                "model": model_id,
                "choices": [{"index": 0, "message": message, "finish_reason": openai_finish(c.stop_reason)}],
                "usage": {"prompt_tokens": i, "completion_tokens": o, "total_tokens": i + o},
            })
        }
    }
}

/// Split text into the small deltas a streaming model sends.
pub fn deltas(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in text.chars() {
        cur.push(ch);
        if ch.is_whitespace() && cur.chars().count() >= 16 {
            out.push(std::mem::take(&mut cur));
        }
    }
    if !cur.is_empty() || out.is_empty() {
        out.push(cur);
    }
    out
}

/// The chunk payloads `InvokeModelWithResponseStream` sends for a
/// completion; the last one carries `amazon-bedrock-invocationMetrics`.
pub fn stream_chunks(family: Family, model_id: &str, c: &Completion, latency_ms: i64) -> Vec<Value> {
    let (i, o) = (c.input_tokens, c.output_tokens);
    let text = c.text();
    let mut chunks: Vec<Value> = Vec::new();
    match family {
        Family::Anthropic => {
            chunks.push(json!({"type": "message_start", "message": {
                "id": message_id("msg_bdrk_"), "type": "message", "role": "assistant",
                "model": anthropic_api_name(model_id), "content": [], "stop_reason": null,
                "stop_sequence": null, "usage": {"input_tokens": i, "output_tokens": 1},
            }}));
            for (index, p) in c.parts.iter().enumerate() {
                match p {
                    OutPart::Text(t) | OutPart::Reasoning(t) => {
                        let thinking = matches!(p, OutPart::Reasoning(_));
                        let block = if thinking {
                            json!({"type": "thinking", "thinking": ""})
                        } else {
                            json!({"type": "text", "text": ""})
                        };
                        chunks.push(json!({"type": "content_block_start", "index": index, "content_block": block}));
                        for d in deltas(t) {
                            let delta = if thinking {
                                json!({"type": "thinking_delta", "thinking": d})
                            } else {
                                json!({"type": "text_delta", "text": d})
                            };
                            chunks.push(json!({"type": "content_block_delta", "index": index, "delta": delta}));
                        }
                    }
                    OutPart::ToolUse { id, name, input } => {
                        chunks.push(json!({"type": "content_block_start", "index": index,
                            "content_block": {"type": "tool_use", "id": id, "name": name, "input": {}}}));
                        chunks.push(json!({"type": "content_block_delta", "index": index,
                            "delta": {"type": "input_json_delta", "partial_json": input.to_string()}}));
                    }
                }
                chunks.push(json!({"type": "content_block_stop", "index": index}));
            }
            chunks.push(json!({"type": "message_delta",
                "delta": {"stop_reason": anthropic_stop(c.stop_reason), "stop_sequence": c.stop_sequence},
                "usage": {"output_tokens": o}}));
            chunks.push(json!({"type": "message_stop"}));
        }
        Family::Nova => {
            chunks.push(json!({"messageStart": {"role": "assistant"}}));
            for (index, p) in c.parts.iter().enumerate() {
                match p {
                    OutPart::Text(t) => {
                        for d in deltas(t) {
                            chunks
                                .push(json!({"contentBlockDelta": {"delta": {"text": d}, "contentBlockIndex": index}}));
                        }
                    }
                    OutPart::Reasoning(t) => chunks.push(json!({"contentBlockDelta": {
                        "delta": {"reasoningContent": {"text": t}}, "contentBlockIndex": index}})),
                    OutPart::ToolUse { id, name, input } => {
                        chunks
                            .push(json!({"contentBlockStart": {"start": {"toolUse": {"toolUseId": id, "name": name}},
                            "contentBlockIndex": index}}));
                        chunks.push(json!({"contentBlockDelta": {"delta": {"toolUse": {"input": input.to_string()}},
                            "contentBlockIndex": index}}));
                    }
                }
                chunks.push(json!({"contentBlockStop": {"contentBlockIndex": index}}));
            }
            chunks.push(json!({"messageStop": {"stopReason": c.stop_reason.converse()}}));
            chunks.push(
                json!({"metadata": {"usage": {"inputTokens": i, "outputTokens": o}, "metrics": {}, "trace": {}}}),
            );
        }
        Family::TitanText => {
            let ds = deltas(&text);
            let n = ds.len();
            for (k, d) in ds.into_iter().enumerate() {
                let last = k + 1 == n;
                chunks.push(json!({
                    "outputText": d, "index": 0, "totalOutputTextTokenCount": if last { Some(o) } else { None },
                    "completionReason": if last { Some(if c.stop_reason == StopReason::MaxTokens { "LENGTH" } else { "FINISH" }) } else { None },
                    "inputTextTokenCount": if k == 0 { Some(i) } else { None },
                }));
            }
        }
        Family::Llama => {
            let ds = deltas(&text);
            let n = ds.len();
            for (k, d) in ds.into_iter().enumerate() {
                let last = k + 1 == n;
                chunks.push(json!({
                    "generation": d, "prompt_token_count": if k == 0 { Some(i) } else { None },
                    "generation_token_count": k + 1,
                    "stop_reason": if last { Some(simple_stop(c.stop_reason)) } else { None },
                }));
            }
        }
        Family::Mistral | Family::DeepSeek => {
            let ds = deltas(&text);
            let n = ds.len();
            let key = if family == Family::Mistral { "outputs" } else { "choices" };
            for (k, d) in ds.into_iter().enumerate() {
                let stop = (k + 1 == n).then(|| simple_stop(c.stop_reason));
                chunks.push(json!({ key: [{"text": d, "stop_reason": stop}] }));
            }
        }
        Family::CohereCommand => {
            chunks.push(json!({"is_finished": false, "event_type": "stream-start", "generation_id": uuid::Uuid::new_v4().to_string()}));
            for d in deltas(&text) {
                chunks.push(json!({"is_finished": false, "event_type": "text-generation", "text": d}));
            }
            let finish = if c.stop_reason == StopReason::MaxTokens { "MAX_TOKENS" } else { "COMPLETE" };
            chunks.push(json!({"is_finished": true, "event_type": "stream-end", "finish_reason": finish,
                "response": render(family, model_id, c)}));
        }
        _ => {
            let id = message_id("chatcmpl-");
            for d in deltas(&text) {
                chunks.push(json!({"id": id, "object": "chat.completion.chunk", "model": model_id,
                    "choices": [{"index": 0, "delta": {"role": "assistant", "content": d}, "finish_reason": null}]}));
            }
            chunks.push(json!({"id": id, "object": "chat.completion.chunk", "model": model_id,
                "choices": [{"index": 0, "delta": {}, "finish_reason": openai_finish(c.stop_reason)}],
                "usage": {"prompt_tokens": i, "completion_tokens": o, "total_tokens": i + o}}));
        }
    }
    if let Some(Value::Object(last)) = chunks.last_mut() {
        last.insert("amazon-bedrock-invocationMetrics".into(), invocation_metrics(i, o, latency_ms));
    }
    chunks
}

pub fn invocation_metrics(i: u32, o: u32, latency_ms: i64) -> Value {
    json!({"inputTokenCount": i, "outputTokenCount": o, "invocationLatency": latency_ms, "firstByteLatency": latency_ms})
}

/// A deterministic embedding: hashed character trigrams, so similar texts
/// get similar vectors.
pub fn embedding(text: &str, dims: usize, normalize: bool) -> Vec<f64> {
    use sha2::Digest;
    let mut v = vec![0f64; dims];
    let lower: Vec<char> = text.to_lowercase().chars().collect();
    let grams: Vec<String> = if lower.len() < 3 {
        vec![lower.iter().collect()]
    } else {
        lower.windows(3).map(|w| w.iter().collect()).collect()
    };
    for g in grams {
        let h = sha2::Sha256::digest(g.as_bytes());
        let idx = (u32::from_le_bytes([h[0], h[1], h[2], h[3]]) as usize) % dims;
        let sign = if h[4] & 1 == 0 { 1.0 } else { -1.0 };
        v[idx] += sign;
    }
    if normalize {
        let n = v.iter().map(|x| x * x).sum::<f64>().sqrt();
        if n > 0.0 {
            v.iter_mut().for_each(|x| *x /= n);
        }
    }
    v.iter_mut().for_each(|x| *x = (*x * 1e6).round() / 1e6);
    v
}

/// The response body for an embedding request.
pub fn render_embedding(
    model_id: &str,
    texts: &[String],
    images: usize,
    dims: usize,
    normalize: bool,
    cohere: bool,
    input_type: Option<&str>,
) -> Value {
    if cohere {
        let embeddings: Vec<Vec<f64>> = texts.iter().map(|t| embedding(t, dims, normalize)).collect();
        let _ = input_type;
        return json!({
            "embeddings": embeddings, "id": uuid::Uuid::new_v4().to_string(),
            "response_type": "embeddings_floats", "texts": texts,
        });
    }
    let text = texts.first().cloned().unwrap_or_default();
    let source = if images > 0 && text.is_empty() { "image".to_string() } else { text.clone() };
    let e = embedding(&source, dims, normalize);
    let mut out = json!({"embedding": e, "inputTextTokenCount": crate::prompt::tokens(&text)});
    if model_id == "amazon.titan-embed-text-v2:0" {
        out["embeddingsByType"] = json!({"float": e});
    }
    if model_id == "amazon.titan-embed-image-v1" {
        out["message"] = Value::Null;
    }
    out
}

/// Rerank by word overlap with the query.
pub fn render_rerank(query: &str, documents: &[String], top_n: Option<usize>) -> Value {
    let q: std::collections::BTreeSet<String> = query
        .to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_string)
        .collect();
    let mut scored: Vec<(usize, f64)> = documents
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let words: Vec<String> = d
                .to_lowercase()
                .split(|c: char| !c.is_alphanumeric())
                .filter(|w| !w.is_empty())
                .map(str::to_string)
                .collect();
            let hits = words.iter().filter(|w| q.contains(*w)).count() as f64;
            let score = if words.is_empty() || q.is_empty() {
                0.0
            } else {
                hits / (words.len() as f64).sqrt() / (q.len() as f64).sqrt()
            };
            (i, (score.min(1.0) * 1e6).round() / 1e6)
        })
        .collect();
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal).then(a.0.cmp(&b.0)));
    scored.truncate(top_n.unwrap_or(documents.len()));
    json!({
        "id": uuid::Uuid::new_v4().to_string(),
        "results": scored.into_iter().map(|(i, s)| json!({"index": i, "relevance_score": s})).collect::<Vec<_>>(),
    })
}

/// A solid-colour PNG, its colour derived from the prompt.
pub fn png(text: &str, width: u32, height: u32) -> Vec<u8> {
    use sha2::Digest;
    use std::io::Write;
    let h = sha2::Sha256::digest(text.as_bytes());
    let (r, g, b) = (h[0], h[1], h[2]);
    let mut raw = Vec::with_capacity(((width * 3 + 1) * height) as usize);
    for _ in 0..height {
        raw.push(0);
        for _ in 0..width {
            raw.extend_from_slice(&[r, g, b]);
        }
    }
    let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    z.write_all(&raw).expect("in-memory write");
    let idat = z.finish().expect("in-memory write");
    let mut out = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    let mut ihdr = Vec::new();
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.extend_from_slice(&[8, 2, 0, 0, 0]);
    for (kind, data) in [(b"IHDR", ihdr), (b"IDAT", idat), (b"IEND", Vec::new())] {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        let mut crc_input = kind.to_vec();
        crc_input.extend_from_slice(&data);
        out.extend_from_slice(kind);
        out.extend_from_slice(&data);
        out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
    }
    out
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

pub fn render_images(text: &str, count: usize, width: u32, height: u32) -> Value {
    let images: Vec<String> = (0..count).map(|k| B64.encode(png(&format!("{text}#{k}"), width, height))).collect();
    json!({"images": images, "error": null})
}

/// A placeholder MP4 (an `ftyp` box and an `mdat` box holding the prompt):
/// MWS does not render video.
pub fn mp4(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let ftyp: &[u8] = b"ftypisom\0\0\x02\0isomiso2mp41";
    out.extend_from_slice(&((ftyp.len() + 4) as u32).to_be_bytes());
    out.extend_from_slice(ftyp);
    out.extend_from_slice(&((text.len() + 8) as u32).to_be_bytes());
    out.extend_from_slice(b"mdat");
    out.extend_from_slice(text.as_bytes());
    out
}

/// Fields carried on the response object when a guardrail took part.
pub fn add_guardrail_fields(body: &mut Value, intervened: bool, trace: Option<Value>) {
    if let Some(o) = body.as_object_mut() {
        o.insert("amazon-bedrock-guardrailAction".into(), json!(if intervened { "INTERVENED" } else { "NONE" }));
        if let Some(t) = trace {
            o.insert("amazon-bedrock-trace".into(), json!({ "guardrail": t }));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_llama_templates() {
        let p = "<|begin_of_text|><|start_header_id|>user<|end_header_id|>\n\nHello there<|eot_id|><|start_header_id|>assistant<|end_header_id|>";
        assert_eq!(last_turn(p), "Hello there");
        assert_eq!(last_turn("<s>[INST] Hi [/INST]"), "Hi");
    }

    #[test]
    fn embeddings_are_deterministic_and_normalized() {
        let a = embedding("hello world", 256, true);
        assert_eq!(a, embedding("hello world", 256, true));
        let n: f64 = a.iter().map(|x| x * x).sum();
        assert!((n - 1.0).abs() < 1e-3);
    }

    #[test]
    fn pngs_have_a_signature() {
        assert_eq!(&png("x", 2, 2)[..4], &[0x89, b'P', b'N', b'G']);
    }
}

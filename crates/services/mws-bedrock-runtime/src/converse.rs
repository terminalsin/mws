//! `Converse` and `ConverseStream`: the provider-neutral request and
//! response shapes, translated to and from [`Prompt`] and [`Completion`].

use serde_json::{json, Value};

use crate::generated::types;
use crate::prompt::{
    reasoning_signature, Completion, Msg, OutPart, Part, Prompt, Role, StopReason, ToolChoice, ToolDef,
};
use mws_bedrock::catalog::ModelSpec;

/// The pieces of a `Converse` (or `CountTokens`) request.
pub struct ConverseInput<'a> {
    pub model_id: &'a str,
    pub messages: Option<&'a [types::Message]>,
    pub system: Option<&'a [types::SystemContentBlock]>,
    pub inference: Option<&'a types::InferenceConfiguration>,
    pub tools: Option<&'a types::ToolConfiguration>,
    pub prompt_variables: Option<&'a std::collections::BTreeMap<String, types::PromptVariableValues>>,
    /// `additionalModelRequestFields`, a JSON document.
    pub additional_fields: Option<&'a str>,
}

/// Content the request marked for guardrail evaluation (`guardContent`).
#[derive(Default)]
pub struct GuardContent {
    pub blocks: Vec<mws_bedrock::guard::Block>,
}

fn json_doc(s: &str) -> Value {
    serde_json::from_str(s).unwrap_or(Value::String(s.to_string()))
}

fn substitute(text: &str, vars: Option<&std::collections::BTreeMap<String, types::PromptVariableValues>>) -> String {
    let Some(vars) = vars else { return text.to_string() };
    let mut out = text.to_string();
    for (k, v) in vars {
        let types::PromptVariableValues::Text(t) = v;
        out = out.replace(&format!("{{{{{k}}}}}"), t);
    }
    out
}

fn guard_block(g: &types::GuardrailConverseContentBlock) -> Option<mws_bedrock::guard::Block> {
    match g {
        types::GuardrailConverseContentBlock::Text(t) => Some(mws_bedrock::guard::Block {
            text: t.text.clone(),
            qualifiers: t.qualifiers.clone().unwrap_or_else(|| vec!["guard_content".into()]),
        }),
        _ => None,
    }
}

fn tool_result_text(c: &types::ToolResultContentBlock) -> String {
    match c {
        types::ToolResultContentBlock::Json(j) => j.clone(),
        types::ToolResultContentBlock::Text(t) => t.clone(),
        types::ToolResultContentBlock::Image(_) => "[image]".into(),
        types::ToolResultContentBlock::Document(d) => format!("[document {}]", d.name),
        types::ToolResultContentBlock::Video(_) => "[video]".into(),
        types::ToolResultContentBlock::SearchResult(r) => {
            r.content.iter().map(|c| c.text.clone()).collect::<Vec<_>>().join("\n")
        }
    }
}

fn invalid(message: impl Into<String>) -> mws_core::ServiceError {
    crate::validation(message)
}

/// Reject what the model can't take: tools, forced tool choice, system
/// prompts, image or video content, and more output tokens than it makes.
pub fn check_capabilities(spec: &ModelSpec, input: &ConverseInput<'_>) -> Result<(), mws_core::ServiceError> {
    if let Some(tc) = input.tools {
        if !spec.tool_use {
            return Err(invalid("This model doesn't support tool use."));
        }
        let forced = match &tc.tool_choice {
            Some(types::ToolChoice::Any(_)) => Some("any"),
            Some(types::ToolChoice::Tool(_)) => Some("tool"),
            _ => None,
        };
        if let Some(f) = forced.filter(|_| !spec.tool_choice) {
            return Err(invalid(format!(
                "This model doesn't support the toolConfig.toolChoice.{f} field. Remove toolConfig.toolChoice.{f} and try again."
            )));
        }
    }
    let has_system =
        input.system.is_some_and(|s| s.iter().any(|b| !matches!(b, types::SystemContentBlock::CachePoint(_))));
    if has_system && !spec.system_prompt {
        return Err(invalid("This model doesn't support system messages."));
    }
    let takes = |m: &str| spec.input_modalities.iter().any(|x| x == m);
    for m in input.messages.unwrap_or_default() {
        for c in &m.content {
            let kind = match c {
                types::ContentBlock::Image(_) if !takes("IMAGE") => "image",
                types::ContentBlock::Video(_) if !takes("VIDEO") => "video",
                _ => continue,
            };
            return Err(invalid(format!("This model doesn't support the {kind} content block that you provided.")));
        }
    }
    if let Some(m) = input.inference.and_then(|ic| ic.max_tokens) {
        let max = spec.max_output_tokens;
        if max > 0 && m as i64 > max as i64 {
            return Err(invalid(format!(
                "The maximum tokens you requested exceeds the model limit of {max}. Try again with a maximum tokens value that is lower than {max}."
            )));
        }
    }
    Ok(())
}

/// The model-specific request fields each model family accepts through
/// `additionalModelRequestFields` (others pass through unchecked).
fn known_fields(spec: &ModelSpec) -> Option<&'static [&'static str]> {
    use mws_bedrock::catalog::Family;
    match spec.family {
        Family::Anthropic => {
            Some(&["top_k", "thinking", "anthropic_beta", "metadata", "context_management", "output_config"])
        }
        Family::Nova => Some(&["inferenceConfig", "reasoningConfig"]),
        _ => None,
    }
}

/// Checks on a built prompt: unknown model fields, the context window,
/// and the thinking budget.
pub fn check_limits(spec: &ModelSpec, p: &Prompt) -> Result<(), mws_core::ServiceError> {
    if let Some(known) = known_fields(spec) {
        if let Some(k) = p.extra.keys().find(|k| !known.contains(&k.as_str())) {
            return Err(crate::native::malformed(format!("#: extraneous key [{k}] is not permitted")));
        }
    }
    crate::native::check_limits(spec, p)
}

/// The prompt a `Converse` request describes, and its guard content.
pub fn prompt(input: ConverseInput<'_>) -> Result<(Prompt, GuardContent), mws_core::ServiceError> {
    let mut p = Prompt { model_id: input.model_id.to_string(), ..Default::default() };
    let mut guard = GuardContent::default();
    let vars = input.prompt_variables;
    for s in input.system.into_iter().flatten() {
        match s {
            types::SystemContentBlock::Text(t) => p.system.push(substitute(t, vars)),
            types::SystemContentBlock::GuardContent(g) => {
                if let Some(b) = guard_block(g) {
                    p.system.push(b.text.clone());
                    guard.blocks.push(b);
                }
            }
            types::SystemContentBlock::CachePoint(_) => {}
        }
    }
    match input.additional_fields.map(serde_json::from_str::<Value>) {
        None | Some(Ok(Value::Null)) => {}
        Some(Ok(Value::Object(m))) => p.extra = m,
        Some(_) => return Err(invalid("The additionalModelRequestFields field must be a JSON object.")),
    }
    let messages = input.messages.unwrap_or_default();
    if messages.is_empty() && vars.is_none() {
        return Err(invalid("The model returned the following errors: messages: at least one message is required"));
    }
    for (i, m) in messages.iter().enumerate() {
        let role = match m.role.as_str() {
            "user" => Role::User,
            "assistant" => Role::Assistant,
            other => return Err(invalid(format!("1 validation error detected: Value '{other}' at 'messages.{}.member.role' failed to satisfy constraint: Member must satisfy enum value set: [user, assistant]", i + 1))),
        };
        if i == 0 && role != Role::User {
            return Err(invalid("A conversation must start with a user message. Try again with a conversation that starts with a user message."));
        }
        if i > 0 && messages[i - 1].role == m.role {
            return Err(invalid("A conversation must alternate between user and assistant roles. Make sure the conversation alternates between user and assistant roles and try again."));
        }
        if m.content.is_empty() {
            return Err(invalid(format!("The content field in the Message object at messages.{i} is empty. Add a ContentBlock object to the content field and try again.")));
        }
        check_tool_results(messages, i)?;
        let mut parts = Vec::new();
        for c in &m.content {
            match c {
                types::ContentBlock::Text(t) => parts.push(Part::Text(substitute(t, vars))),
                types::ContentBlock::Image(img) => parts.push(Part::Media {
                    kind: "image".into(),
                    format: img.format.clone(),
                    bytes: match &img.source {
                        types::ImageSource::Bytes(b) => b.clone(),
                        _ => Vec::new(),
                    },
                }),
                types::ContentBlock::Document(d) => match &d.source {
                    types::DocumentSource::Text(t) => parts.push(Part::Text(t.clone())),
                    types::DocumentSource::Content(blocks) => {
                        for b in blocks {
                            let types::DocumentContentBlock::Text(t) = b;
                            parts.push(Part::Text(t.clone()));
                        }
                    }
                    types::DocumentSource::Bytes(b) if matches!(d.format.as_str(), "txt" | "md" | "csv" | "html") => {
                        parts.push(Part::Text(String::from_utf8_lossy(b).into_owned()))
                    }
                    types::DocumentSource::Bytes(b) => {
                        parts.push(Part::Media { kind: "document".into(), format: d.format.clone(), bytes: b.clone() })
                    }
                    types::DocumentSource::S3Location(_) => {
                        parts.push(Part::Media { kind: "document".into(), format: d.format.clone(), bytes: Vec::new() })
                    }
                },
                types::ContentBlock::Video(v) => parts.push(Part::Media {
                    kind: "video".into(),
                    format: v.format.clone(),
                    bytes: match &v.source {
                        types::VideoSource::Bytes(b) => b.clone(),
                        _ => Vec::new(),
                    },
                }),
                types::ContentBlock::Audio(a) => {
                    parts.push(Part::Media { kind: "audio".into(), format: a.format.clone(), bytes: Vec::new() })
                }
                types::ContentBlock::ToolUse(t) => parts.push(Part::ToolUse {
                    id: t.tool_use_id.clone(),
                    name: t.name.clone(),
                    input: json_doc(&t.input),
                }),
                types::ContentBlock::ToolResult(t) => parts.push(Part::ToolResult {
                    id: t.tool_use_id.clone(),
                    content: t.content.iter().map(tool_result_text).collect(),
                    error: t.status.as_deref() == Some("error"),
                }),
                types::ContentBlock::GuardContent(g) => {
                    if let Some(b) = guard_block(g) {
                        parts.push(Part::Text(b.text.clone()));
                        guard.blocks.push(b);
                    }
                }
                types::ContentBlock::ReasoningContent(types::ReasoningContentBlock::ReasoningText(r)) => {
                    parts.push(Part::Reasoning(r.text.clone()))
                }
                types::ContentBlock::SearchResult(r) => {
                    parts.extend(r.content.iter().map(|c| Part::Text(c.text.clone())))
                }
                _ => {}
            }
        }
        p.messages.push(Msg { role, parts });
    }
    if let Some(last) = p.messages.last() {
        if last.role != Role::User && !p.messages.is_empty() {
            // Prefill: Claude continues an assistant turn; others answer it.
        }
    }
    if let Some(ic) = input.inference {
        if let Some(m) = ic.max_tokens {
            if m < 1 {
                return Err(invalid(format!("1 validation error detected: Value '{m}' at 'inferenceConfig.maxTokens' failed to satisfy constraint: Member must have value greater than or equal to 1")));
            }
            p.max_tokens = Some(m as u32);
        }
        p.temperature = ic.temperature.map(f64::from);
        p.top_p = ic.top_p.map(f64::from);
        p.stop = ic.stop_sequences.clone().unwrap_or_default();
    }
    if let Some(tc) = input.tools {
        for t in &tc.tools {
            if let types::Tool::ToolSpec(spec) = t {
                let types::ToolInputSchema::Json(schema) = &spec.input_schema;
                p.tools.push(ToolDef {
                    name: spec.name.clone(),
                    description: spec.description.clone(),
                    schema: json_doc(schema),
                });
            }
        }
        p.tool_choice = match &tc.tool_choice {
            Some(types::ToolChoice::Any(_)) => ToolChoice::Any,
            Some(types::ToolChoice::Tool(t)) => {
                if !p.tools.iter().any(|d| d.name == t.name) {
                    return Err(invalid(format!(
                        "The tool {} named in toolChoice is not in toolConfig.tools. Add the tool or choose another and try again.",
                        t.name
                    )));
                }
                ToolChoice::Tool(t.name.clone())
            }
            _ => ToolChoice::Auto,
        };
    } else if messages.iter().any(|m| {
        m.content.iter().any(|c| matches!(c, types::ContentBlock::ToolUse(_) | types::ContentBlock::ToolResult(_)))
    }) {
        return Err(invalid("The toolConfig field must be defined when using toolUse and toolResult content blocks."));
    }
    Ok((p, guard))
}

/// The assistant message of a completion.
pub fn message(c: &Completion) -> types::Message {
    let content = c
        .parts
        .iter()
        .map(|p| match p {
            OutPart::Text(t) => types::ContentBlock::Text(t.clone()),
            OutPart::Reasoning(t) => {
                types::ContentBlock::ReasoningContent(types::ReasoningContentBlock::ReasoningText(
                    types::ReasoningTextBlock { text: t.clone(), signature: Some(reasoning_signature(t)) },
                ))
            }
            OutPart::ToolUse { id, name, input } => types::ContentBlock::ToolUse(types::ToolUseBlock {
                tool_use_id: id.clone(),
                name: name.clone(),
                input: input.to_string(),
                r#type: None,
            }),
        })
        .collect();
    types::Message { role: "assistant".into(), content }
}

pub fn usage(c: &Completion) -> types::TokenUsage {
    types::TokenUsage {
        input_tokens: c.input_tokens as i32,
        output_tokens: c.output_tokens as i32,
        total_tokens: (c.input_tokens + c.output_tokens) as i32,
        cache_read_input_tokens: None,
        cache_write_input_tokens: None,
        cache_details: None,
    }
}

/// The `ConverseStream` events for a completion.
pub fn stream(
    c: &Completion,
    latency_ms: i64,
    trace: Option<types::ConverseStreamTrace>,
    service_tier: Option<types::ServiceTier>,
) -> Vec<types::ConverseStreamOutput> {
    use types::ConverseStreamOutput as E;
    let mut out = vec![E::MessageStart(types::MessageStartEvent { role: "assistant".into() })];
    for (index, p) in c.parts.iter().enumerate() {
        let index = index as i32;
        match p {
            OutPart::Text(t) => {
                for d in crate::native::deltas(t) {
                    out.push(E::ContentBlockDelta(types::ContentBlockDeltaEvent {
                        delta: types::ContentBlockDelta::Text(d),
                        content_block_index: index,
                    }));
                }
            }
            OutPart::Reasoning(t) => {
                for d in crate::native::deltas(t) {
                    out.push(E::ContentBlockDelta(types::ContentBlockDeltaEvent {
                        delta: types::ContentBlockDelta::ReasoningContent(types::ReasoningContentBlockDelta::Text(d)),
                        content_block_index: index,
                    }));
                }
                out.push(E::ContentBlockDelta(types::ContentBlockDeltaEvent {
                    delta: types::ContentBlockDelta::ReasoningContent(types::ReasoningContentBlockDelta::Signature(
                        reasoning_signature(t),
                    )),
                    content_block_index: index,
                }));
            }
            OutPart::ToolUse { id, name, input } => {
                out.push(E::ContentBlockStart(types::ContentBlockStartEvent {
                    start: types::ContentBlockStart::ToolUse(types::ToolUseBlockStart {
                        tool_use_id: id.clone(),
                        name: name.clone(),
                        r#type: None,
                    }),
                    content_block_index: index,
                }));
                out.push(E::ContentBlockDelta(types::ContentBlockDeltaEvent {
                    delta: types::ContentBlockDelta::ToolUse(types::ToolUseBlockDelta { input: input.to_string() }),
                    content_block_index: index,
                }));
            }
        }
        out.push(E::ContentBlockStop(types::ContentBlockStopEvent { content_block_index: index }));
    }
    out.push(E::MessageStop(types::MessageStopEvent {
        stop_reason: c.stop_reason.converse().into(),
        additional_model_response_fields: None,
    }));
    out.push(E::Metadata(types::ConverseStreamMetadataEvent {
        usage: usage(c),
        metrics: types::ConverseStreamMetrics { latency_ms },
        trace,
        performance_config: None,
        service_tier,
    }));
    out
}

/// A completion that replaces the model's answer with a guardrail's
/// blocked message.
pub fn blocked(message: &str, input_tokens: u32) -> Completion {
    Completion {
        parts: vec![OutPart::Text(message.to_string())],
        stop_reason: StopReason::GuardrailIntervened,
        stop_sequence: None,
        input_tokens,
        output_tokens: 0,
    }
}

/// `additionalModelResponseFields` for the requested paths.
pub fn additional_fields(paths: Option<&[String]>, c: &Completion) -> Option<String> {
    let paths = paths?;
    let full = json!({"stop_sequence": c.stop_sequence, "stop_reason": c.stop_reason.converse()});
    let mut out = serde_json::Map::new();
    for p in paths {
        let key = p.trim_start_matches('/');
        if let Some(v) = full.pointer(&format!("/{key}")) {
            out.insert(key.to_string(), v.clone());
        }
    }
    Some(Value::Object(out).to_string())
}

/// `toolResult` blocks in message `i` must answer `toolUse` blocks of the
/// previous (assistant) turn, one each.
fn check_tool_results(messages: &[types::Message], i: usize) -> Result<(), mws_core::ServiceError> {
    let results: Vec<(usize, &str)> = messages[i]
        .content
        .iter()
        .enumerate()
        .filter_map(|(j, c)| match c {
            types::ContentBlock::ToolResult(t) => Some((j, t.tool_use_id.as_str())),
            _ => None,
        })
        .collect();
    if results.is_empty() {
        return Ok(());
    }
    let uses: Vec<&str> = match i.checked_sub(1) {
        Some(prev) => messages[prev]
            .content
            .iter()
            .filter_map(|c| match c {
                types::ContentBlock::ToolUse(t) => Some(t.tool_use_id.as_str()),
                _ => None,
            })
            .collect(),
        None => Vec::new(),
    };
    if results.len() > uses.len() {
        return Err(invalid(format!(
            "The number of toolResult blocks at messages.{i}.content exceeds the number of toolUse blocks of previous turn."
        )));
    }
    if let Some((j, id)) = results.iter().find(|(_, id)| !uses.contains(id)) {
        return Err(invalid(format!(
            "messages.{i}.content.{j}: unexpected toolUseId found in toolResult blocks: {id}. Each toolResult block must have a corresponding toolUse block in the previous turn."
        )));
    }
    Ok(())
}

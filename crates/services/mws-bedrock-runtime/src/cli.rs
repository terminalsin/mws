//! Local coding-agent CLIs as model providers: Claude Code (`claude -p`)
//! and Codex (`codex exec`). Each request runs the CLI once, in an empty
//! scratch directory with its own tools turned off, using whatever login
//! the CLI already has on this machine.
//!
//! The CLIs take one prompt and give one answer, so the conversation is
//! written out as a transcript. Bedrock tool definitions become an
//! instruction to answer with a JSON `tool_use` object, which is read back
//! as a real tool call.

use std::path::{Path, PathBuf};
use std::process::Stdio;

use serde_json::{json, Value};
use tokio::io::AsyncWriteExt;

use crate::backend::{tool_use_id, Backend, BackendError};
use crate::prompt::{tokens, Completion, OutPart, Part, Prompt, Role, StopReason, ToolChoice};
use crate::providers::{Kind, Resolved};

/// The executable a CLI provider runs when its `command` is not set.
pub fn default_command(kind: Kind) -> &'static str {
    match kind {
        Kind::Codex => "codex",
        _ => "claude",
    }
}

/// The full path of `command` (a bare name is looked up on `PATH`).
pub fn find(command: &str) -> Option<PathBuf> {
    let p = Path::new(command);
    if p.components().count() > 1 {
        return is_executable(p).then(|| p.to_path_buf());
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(command)).find(|c| is_executable(c))
}

fn is_executable(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        p.metadata().is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        p.is_file()
    }
}

/// The conversation as one prompt, plus the system prompt.
pub fn transcript(prompt: &Prompt) -> (String, String) {
    let mut system = prompt.system.join("\n\n");
    if !prompt.tools.is_empty() && prompt.tool_choice != ToolChoice::None {
        let tools: Vec<Value> = prompt
            .tools
            .iter()
            .map(|t| json!({"name": t.name, "description": t.description, "input_schema": t.schema}))
            .collect();
        let must = match &prompt.tool_choice {
            ToolChoice::Any => "You must call one of these tools.".to_string(),
            ToolChoice::Tool(n) => format!("You must call the tool {n:?}."),
            _ => "Call a tool only when it helps.".to_string(),
        };
        let tools = serde_json::to_string_pretty(&tools).expect("JSON serializes");
        let block = format!(
            "You can call these tools:\n{tools}\n\n{must} To call one, reply with only a JSON object \
             {{\"tool_use\": {{\"name\": \"<tool>\", \"input\": {{...}}}}}} and nothing else. \
             Tool results come back in the next user turn."
        );
        system = if system.is_empty() { block } else { format!("{system}\n\n{block}") };
    }
    let mut out = Vec::new();
    for m in &prompt.messages {
        let mut text = Vec::new();
        for p in &m.parts {
            match p {
                Part::Text(t) => text.push(t.clone()),
                Part::ToolUse { name, input, .. } => {
                    text.push(json!({"tool_use": {"name": name, "input": input}}).to_string())
                }
                Part::ToolResult { content, error, .. } => {
                    let label = if *error { "Tool error" } else { "Tool result" };
                    text.push(format!("[{label}]\n{}", content.join("\n")))
                }
                Part::Media { kind, format, .. } => text.push(format!("[{kind} ({format}) omitted]")),
                Part::Reasoning(_) => {}
            }
        }
        if !text.is_empty() {
            out.push((m.role, text.join("\n")));
        }
    }
    // A single user turn needs no transcript framing.
    let body = match out.as_slice() {
        [(Role::User, t)] => t.clone(),
        _ => {
            let turns: Vec<String> =
                out.iter().map(|(r, t)| format!("<{}>\n{t}\n</{}>", r.as_str(), r.as_str())).collect();
            format!(
                "{}\n\nReply as the assistant to the last user turn. Reply with the answer only.",
                turns.join("\n\n")
            )
        }
    };
    (system, body)
}

/// The answer text as Bedrock content: a tool call when the model answered
/// with a `tool_use` object naming one of the request's tools.
fn parts_of(prompt: &Prompt, text: String) -> (Vec<OutPart>, StopReason) {
    let trimmed = text.trim();
    let unfenced = trimmed
        .strip_prefix("```json")
        .or_else(|| trimmed.strip_prefix("```"))
        .and_then(|t| t.strip_suffix("```"))
        .map(str::trim)
        .unwrap_or(trimmed);
    if !prompt.tools.is_empty() {
        if let Ok(v) = serde_json::from_str::<Value>(unfenced) {
            let call = v.get("tool_use").unwrap_or(&v);
            if let Some(name) = call.get("name").and_then(Value::as_str) {
                if prompt.tools.iter().any(|t| t.name == name) {
                    let input = call.get("input").cloned().filter(Value::is_object).unwrap_or_else(|| json!({}));
                    let part = OutPart::ToolUse { id: tool_use_id(), name: name.to_string(), input };
                    return (vec![part], StopReason::ToolUse);
                }
            }
        }
    }
    let mut text = text;
    let mut stop = StopReason::EndTurn;
    if let Some(i) = prompt.stop.iter().filter_map(|s| text.find(s.as_str())).min() {
        text.truncate(i);
        stop = StopReason::StopSequence;
    }
    (vec![OutPart::Text(text)], stop)
}

/// A local coding-agent CLI.
pub struct Cli {
    pub provider: Resolved,
}

impl Cli {
    fn command(&self) -> String {
        self.provider.command.clone().unwrap_or_else(|| default_command(self.provider.kind).to_string())
    }

    fn args(&self, system: &str, model: Option<&str>, out_file: &Path) -> Vec<String> {
        let mut a: Vec<String> = Vec::new();
        match self.provider.kind {
            Kind::Codex => {
                a.extend(
                    [
                        "exec",
                        "--skip-git-repo-check",
                        "--ephemeral",
                        "--sandbox",
                        "read-only",
                        "--color",
                        "never",
                        "--json",
                    ]
                    .map(String::from),
                );
                a.push("-o".into());
                a.push(out_file.display().to_string());
                if let Some(m) = model {
                    a.extend(["-m".into(), m.to_string()]);
                }
            }
            _ => {
                a.extend(
                    [
                        "-p",
                        "--output-format",
                        "json",
                        "--no-session-persistence",
                        "--strict-mcp-config",
                        "--disable-slash-commands",
                        "--tools",
                        "",
                    ]
                    .map(String::from),
                );
                if !system.is_empty() {
                    a.extend(["--system-prompt".into(), system.to_string()]);
                }
                if let Some(m) = model {
                    a.extend(["--model".into(), m.to_string()]);
                }
            }
        }
        a.extend(self.provider.args.iter().cloned());
        if self.provider.kind == Kind::Codex {
            a.push("-".into());
        }
        a
    }
}

#[async_trait::async_trait]
impl Backend for Cli {
    async fn complete(&self, prompt: &Prompt) -> Result<Completion, BackendError> {
        let command = self.command();
        let label = match self.provider.kind {
            Kind::Codex => "Codex",
            _ => "Claude Code",
        };
        let Some(exe) = find(&command) else {
            return Err(BackendError {
                status: 502,
                message: format!("The {label} CLI ({command}) is not installed where MWS runs."),
            });
        };
        let (system, mut body) = transcript(prompt);
        if self.provider.kind == Kind::Codex && !system.is_empty() {
            body = format!("<instructions>\n{system}\n</instructions>\n\n{body}");
        }
        let model = self.provider.cli_model(&prompt.model_id);
        let dir = std::env::temp_dir().join(format!("mws-bedrock-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir)
            .map_err(|e| BackendError { status: 500, message: format!("Could not create a scratch directory: {e}") })?;
        let out_file = dir.join("answer.txt");
        let result = self.run(&exe, &dir, &self.args(&system, model.as_deref(), &out_file), &body, label).await;
        let answer = std::fs::read_to_string(&out_file).ok();
        let _ = std::fs::remove_dir_all(&dir);
        let stdout = result?;

        let (text, input_tokens, output_tokens) = match self.provider.kind {
            Kind::Codex => {
                let mut usage = (None, None);
                let mut last = None;
                for v in stdout.lines().filter_map(|l| serde_json::from_str::<Value>(l).ok()) {
                    if let Some(u) = v.get("usage") {
                        usage = (
                            u.get("input_tokens").and_then(Value::as_u64),
                            u.get("output_tokens").and_then(Value::as_u64),
                        );
                    }
                    if v.pointer("/item/type").and_then(Value::as_str) == Some("agent_message") {
                        last = v.pointer("/item/text").and_then(Value::as_str).map(str::to_string);
                    }
                    if v.get("type").and_then(Value::as_str).is_some_and(|t| t == "error" || t == "turn.failed") {
                        let msg = v
                            .pointer("/error/message")
                            .or_else(|| v.get("message"))
                            .and_then(Value::as_str)
                            .unwrap_or("Codex failed.");
                        return Err(BackendError { status: 502, message: msg.to_string() });
                    }
                }
                let text = answer.filter(|a| !a.trim().is_empty()).or(last).unwrap_or_default();
                (text, usage.0, usage.1)
            }
            _ => {
                let v: Value = serde_json::from_str(stdout.trim()).map_err(|e| BackendError {
                    status: 502,
                    message: format!(
                        "Claude Code sent unexpected output ({e}): {}",
                        stdout.chars().take(300).collect::<String>()
                    ),
                })?;
                let text = v.get("result").and_then(Value::as_str).unwrap_or_default().to_string();
                if v.get("is_error").and_then(Value::as_bool) == Some(true) {
                    let message = if text.is_empty() { "Claude Code failed.".to_string() } else { text };
                    return Err(BackendError { status: 502, message });
                }
                let u = v.get("usage");
                let input = u.map(|u| {
                    ["input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"]
                        .iter()
                        .filter_map(|k| u.get(*k).and_then(Value::as_u64))
                        .sum::<u64>()
                });
                (text, input, u.and_then(|u| u.get("output_tokens")).and_then(Value::as_u64))
            }
        };
        let (parts, stop_reason) = parts_of(prompt, text);
        let output_tokens = output_tokens.map(|n| n as u32).unwrap_or_else(|| {
            parts
                .iter()
                .map(|p| match p {
                    OutPart::Text(t) | OutPart::Reasoning(t) => tokens(t),
                    OutPart::ToolUse { input, .. } => tokens(&input.to_string()),
                })
                .sum::<u32>()
                .max(1)
        });
        Ok(Completion {
            parts,
            stop_reason,
            stop_sequence: None,
            input_tokens: input_tokens.map(|n| n as u32).unwrap_or_else(|| prompt.input_tokens()),
            output_tokens,
        })
    }
}

impl Cli {
    async fn run(
        &self,
        exe: &Path,
        dir: &Path,
        args: &[String],
        stdin: &str,
        label: &str,
    ) -> Result<String, BackendError> {
        let mut child = tokio::process::Command::new(exe)
            .args(args)
            .current_dir(dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| BackendError { status: 502, message: format!("Could not start {label}: {e}") })?;
        if let Some(mut input) = child.stdin.take() {
            let _ = input.write_all(stdin.as_bytes()).await;
        }
        let out = tokio::time::timeout(self.provider.timeout, child.wait_with_output())
            .await
            .map_err(|_| BackendError {
                status: 504,
                message: format!("{label} did not answer within {} seconds.", self.provider.timeout.as_secs()),
            })?
            .map_err(|e| BackendError { status: 502, message: format!("{label} failed: {e}") })?;
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        if !out.status.success() && self.provider.kind == Kind::Codex {
            let err = String::from_utf8_lossy(&out.stderr);
            let tail: String =
                err.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("").chars().take(500).collect();
            return Err(BackendError { status: 502, message: format!("{label} exited with {}: {tail}", out.status) });
        }
        if !out.status.success() && stdout.trim().is_empty() {
            let err = String::from_utf8_lossy(&out.stderr);
            return Err(BackendError {
                status: 502,
                message: format!(
                    "{label} exited with {}: {}",
                    out.status,
                    err.trim().chars().take(500).collect::<String>()
                ),
            });
        }
        Ok(stdout)
    }
}

/// Which local model tools this machine has: the CLIs on `PATH`.
pub fn detect() -> Value {
    let tools = [("claude-code", "claude"), ("codex", "codex"), ("ollama", "ollama"), ("lmstudio", "lms")];
    let mut out = serde_json::Map::new();
    for (name, command) in tools {
        let found = find(command);
        out.insert(
            name.to_string(),
            json!({ "command": command, "found": found.is_some(), "path": found.map(|p| p.display().to_string()) }),
        );
    }
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prompt::{Msg, ToolDef};

    fn prompt(messages: Vec<Msg>, tools: Vec<ToolDef>) -> Prompt {
        Prompt {
            model_id: "anthropic.claude-sonnet-4-5-20250929-v1:0".into(),
            system: vec!["Be brief.".into()],
            messages,
            tools,
            tool_choice: ToolChoice::Auto,
            max_tokens: None,
            temperature: None,
            top_p: None,
            stop: vec![],
        }
    }

    fn msg(role: Role, text: &str) -> Msg {
        Msg { role, parts: vec![Part::Text(text.into())] }
    }

    #[test]
    fn single_turn_is_the_prompt_itself() {
        let (system, body) = transcript(&prompt(vec![msg(Role::User, "hi")], vec![]));
        assert_eq!(system, "Be brief.");
        assert_eq!(body, "hi");
    }

    #[test]
    fn conversations_become_transcripts() {
        let p = prompt(vec![msg(Role::User, "a"), msg(Role::Assistant, "b"), msg(Role::User, "c")], vec![]);
        let (_, body) = transcript(&p);
        assert!(body.starts_with("<user>\na\n</user>\n\n<assistant>\nb\n</assistant>\n\n<user>\nc\n</user>"));
    }

    #[test]
    fn tool_calls_round_trip() {
        let tools = vec![ToolDef { name: "weather".into(), description: None, schema: json!({"type": "object"}) }];
        let p = prompt(vec![msg(Role::User, "weather?")], tools);
        let (system, _) = transcript(&p);
        assert!(system.contains("\"weather\""));
        let (parts, stop) = parts_of(
            &p,
            "```json\n{\"tool_use\": {\"name\": \"weather\", \"input\": {\"city\": \"Oslo\"}}}\n```".into(),
        );
        assert_eq!(stop, StopReason::ToolUse);
        assert!(
            matches!(&parts[0], OutPart::ToolUse { name, input, .. } if name == "weather" && input["city"] == "Oslo")
        );
        // An unknown tool name is just text.
        let (parts, stop) = parts_of(&p, "{\"tool_use\": {\"name\": \"other\"}}".into());
        assert_eq!(stop, StopReason::EndTurn);
        assert!(matches!(&parts[0], OutPart::Text(_)));
    }
}

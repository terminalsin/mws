//! Local coding-agent CLIs as model providers: Claude Code (`claude -p`)
//! and Codex (`codex exec`). Each request runs the CLI once, in an empty
//! scratch directory with its own tools turned off, using whatever login
//! the CLI already has on this machine.
//!
//! The CLIs take one prompt and give one answer, so the conversation is
//! written out as a transcript. Bedrock tool definitions become an
//! instruction to answer with a JSON `tool_use` object, which is read back
//! as a real tool call.
//!
//! When MWS runs in a container the CLI usually lives on the host, so a
//! provider can run it through a bridge instead: `mws bedrock-bridge` on
//! the host (see [`serve_bridge`]) runs the CLI with the host's login, and
//! the provider's `url` (or `MWS_BEDROCK_CLI_BRIDGE`) points at it.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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

/// The full path of `command`: a path as given (`~/` expanded), else a bare
/// name on `PATH`, else in the places the installers put these CLIs (MWS
/// started from an IDE or a service manager often has a shorter `PATH`).
pub fn find(command: &str) -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let expanded = match (command.strip_prefix("~/"), &home) {
        (Some(rest), Some(h)) => h.join(rest),
        _ => PathBuf::from(command),
    };
    if expanded.components().count() > 1 {
        return is_executable(&expanded).then_some(expanded);
    }
    let on_path = std::env::var_os("PATH")
        .into_iter()
        .flat_map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
        .map(|d| d.join(command));
    on_path.chain(install_dirs(home.as_deref()).into_iter().map(|d| d.join(command))).find(|c| is_executable(c))
}

/// Where the Claude Code, Codex, Ollama and LM Studio installers put their
/// executables.
fn install_dirs(home: Option<&Path>) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> =
        ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"].iter().map(PathBuf::from).collect();
    if let Some(h) = home {
        for d in [
            ".claude/local",
            ".local/bin",
            ".npm-global/bin",
            ".bun/bin",
            ".volta/bin",
            ".cargo/bin",
            ".lmstudio/bin",
            "bin",
        ] {
            dirs.push(h.join(d));
        }
        // nvm: every installed Node version, newest first.
        if let Ok(entries) = std::fs::read_dir(h.join(".nvm/versions/node")) {
            let mut versions: Vec<PathBuf> = entries.filter_map(|e| e.ok()).map(|e| e.path().join("bin")).collect();
            versions.sort();
            dirs.extend(versions.into_iter().rev());
        }
    }
    dirs
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
             {{\"tool_use\": {{\"name\": \"<tool>\", \"input\": {{...}}}}}} (one per call) and nothing else: \
             no tags, no prose. \
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
        let call = |v: &Value| -> Option<OutPart> {
            let call = v.get("tool_use").unwrap_or(v);
            let name = call.get("name").and_then(Value::as_str)?;
            prompt.tools.iter().any(|t| t.name == name).then(|| OutPart::ToolUse {
                id: tool_use_id(),
                name: name.to_string(),
                input: call.get("input").cloned().filter(Value::is_object).unwrap_or_else(|| json!({})),
            })
        };
        if let Some(part) = serde_json::from_str::<Value>(unfenced).ok().as_ref().and_then(call) {
            return (vec![part], StopReason::ToolUse);
        }
        // Models sometimes wrap the call (in tags, a list, a sentence):
        // every `{"tool_use": ...}` object anywhere in the answer counts.
        let mut calls = Vec::new();
        let mut from = 0;
        while let Some(at) = text[from..].find("\"tool_use\"").map(|i| i + from) {
            from = at + 1;
            let Some(open) = text[..at].rfind('{') else { continue };
            let mut stream = serde_json::Deserializer::from_str(&text[open..]).into_iter::<Value>();
            if let Some(Ok(v)) = stream.next() {
                if let Some(part) = call(&v) {
                    calls.push(part);
                    from = open + stream.byte_offset();
                }
            }
        }
        if !calls.is_empty() {
            return (calls, StopReason::ToolUse);
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

    fn args(&self, system: &str, model: Option<&str>) -> Vec<String> {
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
                a.push(OUT.into());
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
        let bridged = bridge_url(&self.provider).is_some();
        self.answer(prompt).await.map_err(|e| login_hint(e, self.provider.kind, bridged))
    }
}

/// A login failure, said as one: which CLI is not logged in, where, and the
/// command that fixes it.
fn login_hint(e: BackendError, kind: Kind, bridged: bool) -> BackendError {
    let m = e.message.to_ascii_lowercase();
    let auth = [
        "failed to authenticate",
        "oauth",
        "not logged in",
        "login",
        "invalid api key",
        "401",
        "unauthorized",
        "credit balance",
    ]
    .iter()
    .any(|k| m.contains(k));
    if !auth || m.contains("bridge token") {
        return e;
    }
    let (label, fix) = match kind {
        Kind::Codex => ("Codex", "codex login"),
        _ => ("Claude Code", "claude login"),
    };
    let place = if bridged { "on the bridge's host" } else { "where MWS runs" };
    BackendError {
        status: 401,
        message: format!("{label} is not logged in {place}: run `{fix}` there, then retry. ({})", e.message.trim()),
    }
}

impl Cli {
    async fn answer(&self, prompt: &Prompt) -> Result<Completion, BackendError> {
        let label = label(self.provider.kind);
        let (system, mut body) = transcript(prompt);
        if self.provider.kind == Kind::Codex && !system.is_empty() {
            body = format!("<instructions>\n{system}\n</instructions>\n\n{body}");
        }
        let model = self.provider.cli_model(&prompt.model_id);
        let run = Run {
            kind: self.provider.kind,
            args: self.args(&system, model.as_deref()),
            stdin: body,
            timeout_seconds: self.provider.timeout.as_secs(),
        };
        let out = match bridge_url(&self.provider) {
            Some(url) => run_on_bridge(&url, bridge_token(&self.provider).as_deref(), &run).await?,
            None => run_here(&self.command(), &run).await?,
        };
        let stdout = checked(&out, self.provider.kind, label)?;
        let answer = out.answer;

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

fn label(kind: Kind) -> &'static str {
    match kind {
        Kind::Codex => "Codex",
        _ => "Claude Code",
    }
}

/// Where a CLI provider's runs go instead of this machine: its `url`, else
/// `MWS_BEDROCK_CLI_BRIDGE`.
pub fn bridge_url(p: &Resolved) -> Option<String> {
    Some(p.url.clone())
        .filter(|u| !u.is_empty())
        .or_else(|| std::env::var("MWS_BEDROCK_CLI_BRIDGE").ok().filter(|u| !u.is_empty()))
}

/// The bridge's token: the provider's `apiKey`, else
/// `MWS_BEDROCK_CLI_BRIDGE_TOKEN`.
fn bridge_token(p: &Resolved) -> Option<String> {
    p.api_key.clone().or_else(|| std::env::var("MWS_BEDROCK_CLI_BRIDGE_TOKEN").ok().filter(|t| !t.is_empty()))
}

/// The placeholder for the answer file in a CLI's arguments; whoever runs
/// the CLI puts a file of its own there.
const OUT: &str = "{mws:answer-file}";

/// One CLI run, as MWS asks a bridge for it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Run {
    pub kind: Kind,
    pub args: Vec<String>,
    pub stdin: String,
    pub timeout_seconds: u64,
}

/// What a run produced.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RunOutput {
    pub success: bool,
    pub status: String,
    pub stdout: String,
    pub stderr: String,
    /// The answer file's contents, when the CLI wrote one.
    pub answer: Option<String>,
}

/// The CLI's stdout, or the failure it reported.
fn checked(out: &RunOutput, kind: Kind, label: &str) -> Result<String, BackendError> {
    let tail = |s: &str| {
        s.trim().lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("").chars().take(500).collect::<String>()
    };
    if !out.success && (kind == Kind::Codex || out.stdout.trim().is_empty()) {
        return Err(BackendError {
            status: 502,
            message: format!("{label} exited with {}: {}", out.status, tail(&out.stderr)),
        });
    }
    Ok(out.stdout.clone())
}

/// Run the CLI on this machine, in a scratch directory.
pub async fn run_here(command: &str, run: &Run) -> Result<RunOutput, BackendError> {
    let label = label(run.kind);
    let Some(exe) = find(command) else {
        let hint = if in_container() {
            " MWS runs in a container: run `mws bedrock-bridge` on the host and set the provider's URL (or MWS_BEDROCK_CLI_BRIDGE) to it."
        } else {
            ""
        };
        return Err(BackendError {
            status: 502,
            message: format!("The {label} CLI ({command}) is not installed where MWS runs.{hint}"),
        });
    };
    let dir = std::env::temp_dir().join(format!("mws-bedrock-{}", uuid::Uuid::new_v4().simple()));
    std::fs::create_dir_all(&dir)
        .map_err(|e| BackendError { status: 500, message: format!("Could not create a scratch directory: {e}") })?;
    let out_file = dir.join("answer.txt");
    let args: Vec<String> =
        run.args.iter().map(|a| if a == OUT { out_file.display().to_string() } else { a.clone() }).collect();
    let result = spawn(&exe, &dir, &args, &run.stdin, Duration::from_secs(run.timeout_seconds.max(1)), label).await;
    let answer = std::fs::read_to_string(&out_file).ok();
    let _ = std::fs::remove_dir_all(&dir);
    result.map(|o| RunOutput { answer, ..o })
}

async fn spawn(
    exe: &Path,
    dir: &Path,
    args: &[String],
    stdin: &str,
    timeout: Duration,
    label: &str,
) -> Result<RunOutput, BackendError> {
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
    let out = tokio::time::timeout(timeout, child.wait_with_output())
        .await
        .map_err(|_| BackendError {
            status: 504,
            message: format!("{label} did not answer within {} seconds.", timeout.as_secs()),
        })?
        .map_err(|e| BackendError { status: 502, message: format!("{label} failed: {e}") })?;
    Ok(RunOutput {
        success: out.status.success(),
        status: out.status.to_string(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        answer: None,
    })
}

/// Run the CLI through a bridge.
async fn run_on_bridge(url: &str, token: Option<&str>, run: &Run) -> Result<RunOutput, BackendError> {
    let label = label(run.kind);
    let mut headers = vec![("Content-Type".to_string(), "application/json".to_string())];
    if let Some(t) = token {
        headers.push(("Authorization".into(), format!("Bearer {t}")));
    }
    let endpoint = format!("{}/run", url.trim_end_matches('/'));
    let res = crate::client::send_with_timeout(
        crate::client::Request {
            method: "POST",
            url: &endpoint,
            headers,
            body: Some(serde_json::to_vec(run).expect("JSON serializes")),
        },
        Duration::from_secs(run.timeout_seconds + 10),
    )
    .await
    .map_err(|e| BackendError {
        status: 502,
        message: format!("The {label} bridge at {url} could not be reached: {e}"),
    })?;
    if res.status != 200 {
        let msg = serde_json::from_slice::<Value>(&res.body)
            .ok()
            .and_then(|v| v.get("message").and_then(Value::as_str).map(str::to_string))
            .unwrap_or_else(|| String::from_utf8_lossy(&res.body).chars().take(300).collect());
        return Err(BackendError {
            status: if res.status == 504 { 504 } else { 502 },
            message: format!("The {label} bridge: {msg}"),
        });
    }
    serde_json::from_slice(&res.body)
        .map_err(|e| BackendError { status: 502, message: format!("The {label} bridge sent invalid JSON: {e}") })
}

/// Whether MWS itself runs in a container.
pub fn in_container() -> bool {
    Path::new("/.dockerenv").exists() || Path::new("/run/.containerenv").exists()
}

/// Serve the bridge: `POST /run` runs Claude Code or Codex here (only those,
/// with this machine's login) for an MWS that cannot, `GET /health` says
/// which tools are installed. Every request needs `Authorization: Bearer
/// <token>`.
pub async fn serve_bridge(listener: tokio::net::TcpListener, token: String, commands: BridgeCommands) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else { continue };
        let token = token.clone();
        let commands = commands.clone();
        tokio::spawn(async move {
            let (status, body) = match read_request(&mut stream).await {
                Ok((method, path, auth, body)) => {
                    bridge_answer(&method, &path, auth.as_deref(), &body, &token, &commands).await
                }
                Err(e) => (400, json!({ "message": e })),
            };
            let body = body.to_string();
            let reason = match status {
                200 => "OK",
                401 => "Unauthorized",
                404 => "Not Found",
                504 => "Gateway Timeout",
                _ => "Bad Request",
            };
            let head = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(body.as_bytes()).await;
        });
    }
}

/// The executables a bridge runs.
#[derive(Debug, Clone)]
pub struct BridgeCommands {
    pub claude: String,
    pub codex: String,
}

impl Default for BridgeCommands {
    fn default() -> Self {
        BridgeCommands { claude: "claude".into(), codex: "codex".into() }
    }
}

async fn bridge_answer(
    method: &str,
    path: &str,
    auth: Option<&str>,
    body: &[u8],
    token: &str,
    commands: &BridgeCommands,
) -> (u16, Value) {
    let given = auth.and_then(|a| a.strip_prefix("Bearer ")).unwrap_or("");
    // Compare without an early exit, so timing says nothing about the token.
    let same =
        given.len() == token.len() && given.bytes().zip(token.bytes()).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0;
    if !same {
        return (401, json!({ "message": "Missing or wrong bridge token." }));
    }
    match (method, path) {
        ("GET", "/health") => (200, json!({ "tools": detect().await })),
        ("POST", "/run") => {
            let run: Run = match serde_json::from_slice(body) {
                Ok(r) => r,
                Err(e) => return (400, json!({ "message": format!("Invalid run: {e}") })),
            };
            if !run.kind.is_cli() {
                return (400, json!({ "message": "The bridge runs only Claude Code and Codex." }));
            }
            let command = match run.kind {
                Kind::Codex => &commands.codex,
                _ => &commands.claude,
            };
            match run_here(command, &run).await {
                Ok(out) => (200, serde_json::to_value(out).expect("JSON serializes")),
                Err(e) => (e.status, json!({ "message": e.message })),
            }
        }
        _ => (404, json!({ "message": "Use POST /run or GET /health." })),
    }
}

/// One HTTP/1.1 request: method, path, Authorization header, body.
async fn read_request(stream: &mut tokio::net::TcpStream) -> Result<(String, String, Option<String>, Vec<u8>), String> {
    const MAX: usize = 32 * 1024 * 1024;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_end = loop {
        let n = stream.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            return Err("connection closed".into());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        if buf.len() > 64 * 1024 {
            return Err("headers too large".into());
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let method = first.next().unwrap_or_default().to_string();
    let path = first.next().unwrap_or_default().split('?').next().unwrap_or_default().to_string();
    let mut length = 0usize;
    let mut auth = None;
    for l in lines {
        if let Some((k, v)) = l.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                length = v.trim().parse().map_err(|_| "bad Content-Length")?;
            } else if k.eq_ignore_ascii_case("authorization") {
                auth = Some(v.trim().to_string());
            }
        }
    }
    if length > MAX {
        return Err("body too large".into());
    }
    let mut body = buf[head_end + 4..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut chunk).await.map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(length);
    Ok((method, path, auth, body))
}

/// What `GET /_aws/bedrock/local` shows: the local tools here, whether MWS
/// runs in a container, and the bridge's tools when one is configured.
pub async fn describe_local() -> Value {
    let mut tools = detect().await;
    let bridge = std::env::var("MWS_BEDROCK_CLI_BRIDGE").ok().filter(|u| !u.is_empty());
    let mut bridge_info = Value::Null;
    if let Some(url) = &bridge {
        let mut headers = Vec::new();
        if let Ok(t) = std::env::var("MWS_BEDROCK_CLI_BRIDGE_TOKEN") {
            headers.push(("Authorization".to_string(), format!("Bearer {t}")));
        }
        let health = format!("{}/health", url.trim_end_matches('/'));
        let res = crate::client::send_with_timeout(
            crate::client::Request { method: "GET", url: &health, headers, body: None },
            Duration::from_secs(2),
        )
        .await;
        let remote = res.ok().filter(|r| r.status == 200).and_then(|r| serde_json::from_slice::<Value>(&r.body).ok());
        if let Some(remote_tools) = remote.as_ref().and_then(|v| v.get("tools")).and_then(Value::as_object) {
            for (name, t) in remote_tools {
                if t["found"] == true && tools[name]["found"] != true {
                    let mut t = t.clone();
                    t["via"] = json!("bridge");
                    tools[name] = t;
                }
            }
        }
        bridge_info = json!({ "url": url, "reachable": remote.is_some() });
    }
    json!({ "tools": tools, "container": in_container(), "bridge": bridge_info })
}

/// Which local model tools this machine has (on `PATH` or where their
/// installers put them), and whether the CLIs are logged in.
pub async fn detect() -> Value {
    let tools = [("claude-code", "claude"), ("codex", "codex"), ("ollama", "ollama"), ("lmstudio", "lms")];
    let mut out = serde_json::Map::new();
    for (name, command) in tools {
        let found = find(command);
        let logged_in = match (&found, name) {
            (Some(exe), "claude-code") => status_of(exe, &["auth", "status"]).await.map(|(_, o)| {
                serde_json::from_str::<Value>(o.trim()).ok().and_then(|v| v["loggedIn"].as_bool()).unwrap_or(false)
            }),
            (Some(exe), "codex") => status_of(exe, &["login", "status"]).await.map(|(ok, _)| ok),
            _ => None,
        };
        let mut t =
            json!({ "command": command, "found": found.is_some(), "path": found.map(|p| p.display().to_string()) });
        if let Some(l) = logged_in {
            t["loggedIn"] = json!(l);
        }
        out.insert(name.to_string(), t);
    }
    Value::Object(out)
}

/// Run a quick status command: whether it succeeded, and its stdout.
async fn status_of(exe: &Path, args: &[&str]) -> Option<(bool, String)> {
    let child = tokio::process::Command::new(exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .output();
    let out = tokio::time::timeout(Duration::from_secs(10), child).await.ok()?.ok()?;
    Some((out.status.success(), String::from_utf8_lossy(&out.stdout).into_owned()))
}

/// The models a CLI provider offers, as catalog entries `<provider>.<model>`:
/// Claude Code's model aliases, and the models `codex debug models` lists.
pub async fn discover_models(p: &Resolved) -> Vec<mws_bedrock::catalog::ModelSpec> {
    use mws_bedrock::catalog::{discovered_text_model, Family};
    let label = label(p.kind);
    let provider = if p.name == p.kind.as_str() { label.to_string() } else { format!("{label} ({})", p.name) };
    match p.kind {
        Kind::ClaudeCode => [("opus", "Claude Opus"), ("sonnet", "Claude Sonnet"), ("haiku", "Claude Haiku")]
            .iter()
            .map(|(alias, name)| {
                discovered_text_model(&format!("{}.{alias}", p.name), name, &provider, Family::Anthropic, 200_000)
            })
            .collect(),
        Kind::Codex => {
            let command = p.command.clone().unwrap_or_else(|| default_command(p.kind).to_string());
            let run = Run {
                kind: Kind::Codex,
                args: vec!["debug".into(), "models".into()],
                stdin: String::new(),
                timeout_seconds: 30,
            };
            let out = match bridge_url(p) {
                Some(url) => run_on_bridge(&url, bridge_token(p).as_deref(), &run).await,
                None => run_here(&command, &run).await,
            };
            let Ok(out) = out else { return Vec::new() };
            let Ok(v) = serde_json::from_str::<Value>(out.stdout.trim()) else { return Vec::new() };
            v["models"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|m| m["visibility"] == "list")
                .filter_map(|m| {
                    let slug = m["slug"].as_str()?;
                    let name = m["display_name"].as_str().unwrap_or(slug);
                    let window = m["context_window"].as_u64().unwrap_or(128_000) as u32;
                    Some(discovered_text_model(&format!("{}.{slug}", p.name), name, &provider, Family::OpenAi, window))
                })
                .collect()
        }
        _ => Vec::new(),
    }
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
            extra: Default::default(),
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
        // Wrapped calls still count.
        let (parts, stop) = parts_of(
            &p,
            "<function_calls>\n[{\"tool_use\": {\"name\": \"weather\", \"input\": {\"city\": \"Oslo\"}}}]\n</function_calls>\nChecking.".into(),
        );
        assert_eq!(stop, StopReason::ToolUse);
        assert_eq!(parts.len(), 1);
        // An unknown tool name is just text.
        let (parts, stop) = parts_of(&p, "{\"tool_use\": {\"name\": \"other\"}}".into());
        assert_eq!(stop, StopReason::EndTurn);
        assert!(matches!(&parts[0], OutPart::Text(_)));
    }
}

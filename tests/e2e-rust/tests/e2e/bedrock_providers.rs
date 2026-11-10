//! Bedrock model providers: settings from the environment, settings stored
//! through `/_aws/bedrock/providers` (kept in `MWS_DB` across restarts),
//! routing by model id, and what reaches the upstream server.

use std::collections::BTreeMap;

use aws_sdk_bedrockruntime::types::*;
use aws_sdk_bedrockruntime::Client;
use mws_e2e::Mws;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

const HAIKU: &str = "anthropic.claude-3-haiku-20240307-v1:0";
const LLAMA: &str = "meta.llama3-8b-instruct-v1:0";
const NOVA_MICRO: &str = "amazon.nova-micro-v1:0";

/// One request the fake provider received.
#[derive(Debug)]
struct Seen {
    path: String,
    headers: BTreeMap<String, String>,
    body: Value,
}

/// A fake model provider speaking both the OpenAI Chat Completions and the
/// Anthropic Messages API. Returns its base URL and the requests it sees.
async fn fake_provider() -> (String, mpsc::UnboundedReceiver<Seen>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else { return };
            let tx = tx.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let (head, body) = loop {
                    let n = sock.read(&mut chunk).await.unwrap();
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else { continue };
                    let head = String::from_utf8_lossy(&buf[..end]).to_string();
                    let len: usize = head
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap())
                        })
                        .unwrap_or(0);
                    while buf.len() < end + 4 + len {
                        let n = sock.read(&mut chunk).await.unwrap();
                        buf.extend_from_slice(&chunk[..n]);
                    }
                    break (head, buf[end + 4..end + 4 + len].to_vec());
                };
                let path = head.lines().next().unwrap().split(' ').nth(1).unwrap().to_string();
                let headers = head
                    .lines()
                    .skip(1)
                    .filter_map(|l| l.split_once(':'))
                    .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
                    .collect();
                let body: Value = serde_json::from_slice(&body).unwrap_or_default();
                let model = body["model"].as_str().unwrap_or_default().to_string();
                let reply = if path.ends_with("/v1/messages") {
                    json!({
                        "id": "msg_1", "type": "message", "role": "assistant", "model": model,
                        "content": [{"type": "text", "text": format!("anthropic says hi as {model}")}],
                        "stop_reason": "end_turn", "usage": {"input_tokens": 3, "output_tokens": 5},
                    })
                } else {
                    json!({
                        "id": "chatcmpl-1", "object": "chat.completion", "model": model,
                        "choices": [{"index": 0, "finish_reason": "stop",
                            "message": {"role": "assistant", "content": format!("openai says hi as {model}")}}],
                        "usage": {"prompt_tokens": 3, "completion_tokens": 5},
                    })
                }
                .to_string();
                let _ = tx.send(Seen { path, headers, body });
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                    reply.len()
                );
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (url, rx)
}

fn user(text: &str) -> Message {
    Message::builder().role(ConversationRole::User).content(ContentBlock::Text(text.into())).build().unwrap()
}

async fn say(r: &Client, model: &str, temperature: Option<f32>) -> String {
    let mut req = r.converse().model_id(model).messages(user("hello"));
    if let Some(t) = temperature {
        req = req.inference_config(InferenceConfiguration::builder().temperature(t).build());
    }
    let out = req.send().await.unwrap();
    let ConverseOutput::Message(m) = out.output().unwrap() else { panic!("no message") };
    m.content()[0].as_text().unwrap().to_string()
}

fn provider<'a>(list: &'a Value, name: &str) -> &'a Value {
    list["providers"].as_array().unwrap().iter().find(|p| p["name"] == name).unwrap_or_else(|| panic!("{name}: {list}"))
}

async fn route(mws: &Mws, model: &str) -> (String, String) {
    let (status, v) = mws.control("GET", &format!("/_aws/bedrock/providers/route?modelId={model}"), None).await;
    assert_eq!(status, 200, "{v}");
    (v["provider"].as_str().unwrap().into(), v["upstreamModel"].as_str().unwrap().into())
}

#[tokio::test]
async fn providers_come_from_env_and_stored_settings() {
    let (upstream, mut seen) = fake_provider().await;
    let dir = std::env::temp_dir().join(format!("mws-e2e-{}-bedrock-providers", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let env = [
        ("MWS_BEDROCK_PROVIDER_LOCAL_URL", format!("{upstream}/v1")),
        ("MWS_BEDROCK_PROVIDER_LOCAL_MODELS", "meta.*".into()),
        ("MWS_BEDROCK_PROVIDER_LOCAL_API_KEY", "sk-env-key-1234".into()),
        ("MWS_BEDROCK_PROVIDER_LOCAL_PARAMS", r#"{"temperature":0.3,"seed":7}"#.into()),
        ("MWS_BEDROCK_PROVIDER_LOCAL_MODEL_MAP", format!("{LLAMA}=llama3:8b")),
    ];
    let config = mws::Config {
        db: Some(dir.join("state.db")),
        bedrock_providers: mws::BedrockProviders::from_vars(env.iter().map(|(k, v)| (k.to_string(), v.clone()))),
        ..Default::default()
    };
    let mws = Mws::start_with(config.clone()).await;
    let r = Client::new(&mws.root_sdk_config().await);

    // The environment's provider, with its key redacted.
    let (status, list) = mws.control("GET", "/_aws/bedrock/providers", None).await;
    assert_eq!(status, 200);
    assert_eq!(list["default"], "echo");
    let local = provider(&list, "local");
    assert_eq!(local["source"], "environment");
    assert_eq!(local["kind"], "openai");
    assert_eq!(local["apiKey"], "sk-…1234");
    assert_eq!(local["apiKeySet"], true);
    assert!(!list.to_string().contains("sk-env-key-1234"));
    assert_eq!(provider(&list, "echo")["source"], "builtin");

    // Llama goes upstream with the mapped name, key and default params.
    assert_eq!(say(&r, LLAMA, None).await, "openai says hi as llama3:8b");
    let s = seen.recv().await.unwrap();
    assert_eq!(s.path, "/v1/chat/completions");
    assert_eq!(s.headers["authorization"], "Bearer sk-env-key-1234");
    assert_eq!(s.body["model"], "llama3:8b");
    assert_eq!(s.body["seed"], 7);
    assert_eq!(s.body["temperature"], 0.3);
    // A request's own inference parameters win over the defaults.
    say(&r, LLAMA, Some(0.9)).await;
    let s = seen.recv().await.unwrap();
    assert!((s.body["temperature"].as_f64().unwrap() - 0.9).abs() < 1e-6, "{}", s.body);
    // Other models stay on the echo.
    assert_eq!(say(&r, NOVA_MICRO, None).await, "hello");

    // Store an Anthropic provider for Claude models.
    let (status, stored) = mws
        .control(
            "PUT",
            "/_aws/bedrock/providers/claude",
            Some(
                &json!({
                    "kind": "anthropic", "url": upstream, "apiKey": "sk-ant-stored-5678",
                    "models": ["anthropic.*"], "headers": {"x-team": "ml"}, "params": {"top_k": 5},
                    "anthropicVersion": "2023-06-01",
                })
                .to_string(),
            ),
        )
        .await;
    assert_eq!(status, 200, "{stored}");
    assert_eq!(stored["source"], "stored");
    assert_eq!(stored["apiKey"], "sk-…5678");
    assert_eq!(say(&r, HAIKU, None).await, "anthropic says hi as claude-3-haiku-20240307");
    let s = seen.recv().await.unwrap();
    assert_eq!(s.path, "/v1/messages");
    assert_eq!(s.headers["x-api-key"], "sk-ant-stored-5678");
    assert_eq!(s.headers["x-team"], "ml");
    assert_eq!(s.headers["anthropic-version"], "2023-06-01");
    assert_eq!(s.body["top_k"], 5);

    // Stored settings override the environment's field by field.
    let (status, _) =
        mws.control("PUT", "/_aws/bedrock/providers/local", Some(&json!({"model": "llama3:70b"}).to_string())).await;
    assert_eq!(status, 200);
    assert_eq!(route(&mws, "meta.llama3-70b-instruct-v1:0").await, ("local".into(), "llama3:70b".into()));
    assert_eq!(route(&mws, LLAMA).await, ("local".into(), "llama3:8b".into()));
    let (_, list) = mws.control("GET", "/_aws/bedrock/providers", None).await;
    assert_eq!(provider(&list, "local")["source"], "environment+stored");
    assert_eq!(provider(&list, "local")["apiKeySet"], true);

    // A stored default catches every model no pattern claims.
    assert_eq!(route(&mws, NOVA_MICRO).await.0, "echo");
    let (status, _) = mws.control("PUT", "/_aws/bedrock/providers", Some(r#"{"default": "local"}"#)).await;
    assert_eq!(status, 200);
    assert_eq!(route(&mws, NOVA_MICRO).await, ("local".into(), "llama3:70b".into()));

    // Invalid settings are refused.
    let (status, e) = mws.control("PUT", "/_aws/bedrock/providers/bad", Some(r#"{"url": "ftp://nowhere"}"#)).await;
    assert_eq!(status, 400);
    assert!(e["message"].as_str().unwrap().contains("http://"), "{e}");
    let (status, _) = mws.control("PUT", "/_aws/bedrock/providers", Some(r#"{"default": "nope"}"#)).await;
    assert_eq!(status, 400);
    mws.stop().await;

    // Stored settings survive a restart.
    let mws = Mws::start_with(config).await;
    let r = Client::new(&mws.root_sdk_config().await);
    let (_, list) = mws.control("GET", "/_aws/bedrock/providers", None).await;
    assert_eq!(list["default"], "local");
    assert_eq!(provider(&list, "claude")["source"], "stored");
    assert_eq!(say(&r, HAIKU, None).await, "anthropic says hi as claude-3-haiku-20240307");
    assert_eq!(seen.recv().await.unwrap().headers["x-api-key"], "sk-ant-stored-5678");

    // Deleting stored settings falls back to the environment's.
    let (status, _) = mws.control("DELETE", "/_aws/bedrock/providers/claude", None).await;
    assert_eq!(status, 200);
    assert_eq!(route(&mws, HAIKU).await.0, "local");
    let (status, _) = mws.control("DELETE", "/_aws/bedrock/providers/claude", None).await;
    assert_eq!(status, 404);
    let (status, _) = mws.control("DELETE", "/_aws/bedrock/providers/local", None).await;
    assert_eq!(status, 200);
    let (_, list) = mws.control("GET", "/_aws/bedrock/providers", None).await;
    assert_eq!(list["default"], "echo");
    assert_eq!(provider(&list, "local")["source"], "environment");
    assert_eq!(route(&mws, LLAMA).await, ("local".into(), "llama3:8b".into()));
    mws.stop().await;
}

/// Write an executable script.
#[cfg(unix)]
fn script(path: &std::path::Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, format!("#!/bin/sh\n{body}")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// The local Claude Code and Codex CLIs as providers: MWS runs the CLI per
/// request, passes the conversation on stdin and reads the answer (and tool
/// calls) back. Fake CLIs record what they were given.
#[cfg(unix)]
#[tokio::test]
async fn local_cli_providers_answer_converse() {
    let dir = std::env::temp_dir().join(format!("mws-e2e-{}-bedrock-cli", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = dir.display();
    script(
        &dir.join("claude"),
        &format!(
            r#"printf '%s\n' "$@" > {d}/claude.args
cat > {d}/claude.stdin
if grep -q weather {d}/claude.stdin; then
  printf '%s' '{{"type":"result","is_error":false,"result":"{{\"tool_use\":{{\"name\":\"weather\",\"input\":{{\"city\":\"Oslo\"}}}}}}","usage":{{"input_tokens":11,"output_tokens":5}}}}'
else
  printf '%s' '{{"type":"result","is_error":false,"result":"hi from claude code","usage":{{"input_tokens":9,"cache_read_input_tokens":3,"output_tokens":4}}}}'
fi
"#
        ),
    );
    script(
        &dir.join("codex"),
        &format!(
            r#"printf '%s\n' "$@" > {d}/codex.args
cat > {d}/codex.stdin
while [ $# -gt 0 ]; do [ "$1" = "-o" ] && out="$2"; shift; done
printf 'hi from codex' > "$out"
echo '{{"type":"turn.completed","usage":{{"input_tokens":20,"output_tokens":3}}}}'
"#
        ),
    );

    let mws = Mws::start().await;
    let r = Client::new(&mws.root_sdk_config().await);
    let claude = json!({"kind": "claude-code", "command": dir.join("claude"), "models": ["anthropic.*"]});
    let (status, v) = mws.control("PUT", "/_aws/bedrock/providers/claude-code", Some(&claude.to_string())).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["kind"], "claude-code");
    assert_eq!(v["installed"], true);
    let codex = json!({"command": dir.join("codex"), "model": "gpt-5-codex", "models": ["openai.*"]});
    let (status, v) = mws.control("PUT", "/_aws/bedrock/providers/codex", Some(&codex.to_string())).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["kind"], "codex", "the kind follows from the name");

    // Claude Code: system prompt as a flag, Bedrock id -> Claude model name.
    let out = r
        .converse()
        .model_id(HAIKU)
        .system(SystemContentBlock::Text("Be brief.".into()))
        .messages(user("hello"))
        .send()
        .await
        .unwrap();
    let ConverseOutput::Message(m) = out.output().unwrap() else { panic!("no message") };
    assert_eq!(m.content()[0].as_text().unwrap(), "hi from claude code");
    assert_eq!(out.usage().unwrap().input_tokens(), 12);
    assert_eq!(out.usage().unwrap().output_tokens(), 4);
    let args = std::fs::read_to_string(dir.join("claude.args")).unwrap();
    let args: Vec<&str> = args.lines().collect();
    assert!(args.starts_with(&["-p", "--output-format", "json"]), "{args:?}");
    let at = |flag: &str| args[args.iter().position(|a| *a == flag).unwrap() + 1];
    assert_eq!(at("--system-prompt"), "Be brief.");
    assert_eq!(at("--model"), "claude-3-haiku-20240307");
    assert_eq!(std::fs::read_to_string(dir.join("claude.stdin")).unwrap(), "hello");

    // Tools: the CLI's JSON answer comes back as a real tool call.
    let schema = aws_smithy_types::Document::Object(
        [("type".to_string(), aws_smithy_types::Document::String("object".into()))].into_iter().collect(),
    );
    let tool = Tool::ToolSpec(
        ToolSpecification::builder().name("weather").input_schema(ToolInputSchema::Json(schema)).build().unwrap(),
    );
    let out = r
        .converse()
        .model_id(HAIKU)
        .messages(user("what's the weather in Oslo?"))
        .tool_config(ToolConfiguration::builder().tools(tool).build().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(out.stop_reason(), &StopReason::ToolUse);
    let ConverseOutput::Message(m) = out.output().unwrap() else { panic!("no message") };
    let call = m.content()[0].as_tool_use().unwrap();
    assert_eq!(call.name(), "weather");
    let system = std::fs::read_to_string(dir.join("claude.args")).unwrap();
    assert!(system.contains("You can call these tools"), "{system}");

    // Codex: the answer comes from its -o file, usage from its JSON events.
    let out = r.converse().model_id("openai.gpt-oss-20b-1:0").messages(user("hey")).send().await.unwrap();
    let ConverseOutput::Message(m) = out.output().unwrap() else { panic!("no message") };
    assert_eq!(m.content()[0].as_text().unwrap(), "hi from codex");
    assert_eq!(out.usage().unwrap().input_tokens(), 20);
    let args = std::fs::read_to_string(dir.join("codex.args")).unwrap();
    let args: Vec<&str> = args.lines().collect();
    assert_eq!(args[0], "exec");
    assert!(args.contains(&"--skip-git-repo-check") && args.contains(&"gpt-5-codex"), "{args:?}");
    assert_eq!(args.last(), Some(&"-"), "prompt on stdin");

    // A missing CLI is a model error, not a crash.
    let gone = json!({"kind": "codex", "command": dir.join("nope"), "models": ["mistral.*"]});
    mws.control("PUT", "/_aws/bedrock/providers/gone", Some(&gone.to_string())).await;
    let err = r.converse().model_id("mistral.mistral-large-2402-v1:0").messages(user("x")).send().await.unwrap_err();
    let err = err.into_service_error();
    assert!(err.is_model_error_exception(), "{err:?}");
    assert!(err.to_string().contains("not installed") || format!("{err:?}").contains("not installed"), "{err:?}");

    // What is installed where MWS runs.
    let (status, local) = mws.control("GET", "/_aws/bedrock/local", None).await;
    assert_eq!(status, 200);
    for k in ["claude-code", "codex", "ollama", "lmstudio"] {
        assert!(local["tools"][k]["found"].is_boolean(), "{local}");
    }
    assert!(local["container"].is_boolean(), "{local}");

    // Through a bridge (what an MWS in a container uses to reach the
    // host's CLI): the bridge runs its own command with its own login.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bridge = format!("http://{}", listener.local_addr().unwrap());
    let commands = mws::bedrock_cli::BridgeCommands {
        claude: dir.join("claude").display().to_string(),
        codex: dir.join("codex").display().to_string(),
    };
    tokio::spawn(mws::bedrock_cli::serve_bridge(listener, "bridge-secret".into(), commands));
    let via = json!({"kind": "claude-code", "url": bridge, "apiKey": "bridge-secret", "models": ["cohere.*"]});
    let (status, v) = mws.control("PUT", "/_aws/bedrock/providers/host-claude", Some(&via.to_string())).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["bridge"], bridge.as_str());
    let _ = std::fs::remove_file(dir.join("claude.stdin"));
    let out = r.converse().model_id("cohere.command-r-v1:0").messages(user("over the bridge")).send().await.unwrap();
    let ConverseOutput::Message(m) = out.output().unwrap() else { panic!("no message") };
    assert_eq!(m.content()[0].as_text().unwrap(), "hi from claude code");
    assert_eq!(std::fs::read_to_string(dir.join("claude.stdin")).unwrap(), "over the bridge");
    // A wrong token is refused.
    let bad = json!({"kind": "claude-code", "url": bridge, "apiKey": "nope", "models": ["cohere.*"]});
    mws.control("PUT", "/_aws/bedrock/providers/host-claude", Some(&bad.to_string())).await;
    let err = r.converse().model_id("cohere.command-r-v1:0").messages(user("x")).send().await.unwrap_err();
    assert!(format!("{:?}", err.into_service_error()).contains("bridge token"));
    mws.stop().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// CLI providers put their own models in the catalog (`<provider>.<model>`,
/// answered by that provider), and a CLI that is not logged in says so.
#[cfg(unix)]
#[tokio::test]
async fn cli_providers_list_their_models_and_report_logins() {
    let dir = std::env::temp_dir().join(format!("mws-e2e-{}-bedrock-cli-models", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = dir.display();
    script(
        &dir.join("claude"),
        &format!(
            r#"if [ "$1" = auth ]; then echo '{{"loggedIn": false}}'; exit 0; fi
printf '%s\n' "$@" > {d}/claude.args
cat > {d}/claude.stdin
if grep -q expired {d}/claude.stdin; then
  printf '%s' '{{"type":"result","is_error":true,"result":"Failed to authenticate: OAuth session expired and could not be refreshed"}}'
  exit 1
fi
printf '%s' '{{"type":"result","is_error":false,"result":"sonnet here","usage":{{"input_tokens":3,"output_tokens":2}}}}'
"#
        ),
    );
    script(
        &dir.join("codex"),
        r#"if [ "$1" = login ]; then echo 'Not logged in'; exit 1; fi
if [ "$1" = debug ]; then
  echo '{"models":[{"slug":"gpt-test","display_name":"GPT Test","visibility":"list","context_window":272000},{"slug":"hidden-one","display_name":"Hidden","visibility":"hide"}]}'
  exit 0
fi
exit 1
"#,
    );

    let mws = Mws::start().await;
    let r = Client::new(&mws.root_sdk_config().await);
    let b = aws_sdk_bedrock::Client::new(&mws.root_sdk_config().await);
    for (name, cmd) in [("claude-code", "claude"), ("codex", "codex")] {
        let body = json!({"command": dir.join(cmd)});
        let (status, v) = mws.control("PUT", &format!("/_aws/bedrock/providers/{name}"), Some(&body.to_string())).await;
        assert_eq!(status, 200, "{v}");
    }
    // Discovery runs in the background; the local-tools endpoint waits for it.
    mws.control("GET", "/_aws/bedrock/local", None).await;
    let list = b.list_foundation_models().send().await.unwrap();
    let ids: Vec<&str> = list.model_summaries().iter().map(|m| m.model_id()).collect();
    for id in ["claude-code.opus", "claude-code.sonnet", "claude-code.haiku", "codex.gpt-test"] {
        assert!(ids.contains(&id), "{id} missing from {ids:?}");
    }
    assert!(!ids.contains(&"codex.hidden-one"));
    let m = b.get_foundation_model().model_identifier("codex.gpt-test").send().await.unwrap();
    let details = m.model_details().unwrap();
    assert_eq!(details.model_name(), Some("GPT Test"));
    assert_eq!(details.provider_name(), Some("Codex"));

    // The listed model goes to its provider, under the CLI's own name.
    let out = r.converse().model_id("claude-code.sonnet").messages(user("hello")).send().await.unwrap();
    let ConverseOutput::Message(m) = out.output().unwrap() else { panic!("no message") };
    assert_eq!(m.content()[0].as_text().unwrap(), "sonnet here");
    let args = std::fs::read_to_string(dir.join("claude.args")).unwrap();
    let args: Vec<&str> = args.lines().collect();
    assert_eq!(args[args.iter().position(|a| *a == "--model").unwrap() + 1], "sonnet");

    // Not logged in: a ModelErrorException that names the fix.
    let err = r.converse().model_id("claude-code.sonnet").messages(user("expired")).send().await.unwrap_err();
    let err = err.into_service_error();
    assert!(err.is_model_error_exception(), "{err:?}");
    let msg = format!("{err:?}");
    assert!(msg.contains("not logged in") && msg.contains("claude login"), "{msg}");

    // Login state, as the console reads it.
    let (_, local) = mws.control("GET", "/_aws/bedrock/local", None).await;
    assert!(local["tools"]["claude-code"].get("loggedIn").is_some(), "{local}");

    // Removing the provider removes its models.
    mws.control("DELETE", "/_aws/bedrock/providers/codex", None).await;
    mws.control("GET", "/_aws/bedrock/local", None).await;
    let list = b.list_foundation_models().send().await.unwrap();
    assert!(!list.model_summaries().iter().any(|m| m.model_id() == "codex.gpt-test"));
    mws.stop().await;
    let _ = std::fs::remove_dir_all(&dir);
}

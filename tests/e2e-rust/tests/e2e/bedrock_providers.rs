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

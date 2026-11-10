//! Session Manager: `StartSession` hands out a stream URL on MWS's own
//! data channel listener, which speaks the Session Manager data channel
//! protocol (the one AWS's `session-manager-plugin` speaks to
//! `ssmmessages`) over WebSocket: the open-channel request with the
//! session token, agent messages with sequence numbers, digests and
//! acknowledgements, the session type handshake, shell or port data, and
//! `channel_closed`. Shells and interactive commands run in the node
//! (Docker-backed instances) and port sessions reach the node's ports,
//! through the [`ManagedNodes`](crate::ManagedNodes) the composition root
//! provides. Also just-in-time node access requests, connection status
//! and multicloud (Azure) connectors.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, Notify};

use crate::documents::{parse_content, pick_version};
use crate::generated::{errors, types};
use crate::names::{now, page};
use crate::Ssm;

/// What a session runs on its node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionKind {
    /// An interactive shell, or `command` under a terminal
    /// (`InteractiveCommands`).
    Shell { command: Option<String> },
    /// A TCP connection to `port` on the node, or on `host` as the node
    /// reaches it.
    Port { host: Option<String>, port: u16 },
}

/// The two ends of a session's byte stream on the node.
pub struct SessionIo {
    pub reader: Pin<Box<dyn AsyncRead + Send>>,
    pub writer: Pin<Box<dyn AsyncWrite + Send>>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionRecord {
    pub session: types::Session,
    pub token: String,
    /// `Standard_Stream`, `InteractiveCommands` or `Port`.
    pub session_type: String,
    pub properties: Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnectorRecord {
    pub connector: types::GetCloudConnectorResult,
    pub id: String,
    pub tags: BTreeMap<String, String>,
}

/// The data channel listener and the live channels.
#[derive(Default)]
pub(crate) struct SessionHub {
    addr: Mutex<Option<SocketAddr>>,
    terminate: Mutex<HashMap<String, Arc<Notify>>>,
}

const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

fn session_arn(ctx: &RequestContext, id: &str) -> String {
    format!("arn:{}:ssm:{}:{}:session/{id}", ctx.partition, ctx.region, ctx.caller.account_id)
}

fn instance_arn(ctx: &RequestContext, id: &str) -> String {
    format!("arn:{}:ec2:{}:{}:instance/{id}", ctx.partition, ctx.region, ctx.caller.account_id)
}

/// The name AWS starts session ids with: the user, the role session, or
/// `root`.
fn session_prefix(arn: &str) -> String {
    let last = arn.rsplit(['/', ':']).next().unwrap_or("session");
    let name = if arn.ends_with(":root") { "root" } else { last };
    let clean: String = name.chars().filter(|c| c.is_ascii_alphanumeric() || "-_.@".contains(*c)).take(64).collect();
    if clean.is_empty() {
        "session".into()
    } else {
        clean
    }
}

fn random_hex(n: usize) -> String {
    let mut s = String::new();
    while s.len() < n {
        s.push_str(&uuid::Uuid::new_v4().simple().to_string());
    }
    s.truncate(n);
    s
}

// ---- agent messages ----

pub(crate) const OUTPUT: u32 = 1;
const SIZE: u32 = 3;
const HANDSHAKE_REQUEST: u32 = 5;
const HANDSHAKE_RESPONSE: u32 = 6;
const HANDSHAKE_COMPLETE: u32 = 7;
const FLAG: u32 = 10;

/// One Session Manager agent message.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct AgentMessage {
    pub message_type: String,
    pub schema_version: u32,
    pub created: u64,
    pub sequence: i64,
    pub flags: u64,
    pub id: uuid::Uuid,
    pub payload_type: u32,
    pub payload: Vec<u8>,
}

const HEADER_LENGTH: u32 = 116;

impl AgentMessage {
    pub(crate) fn new(message_type: &str, sequence: i64, flags: u64, payload_type: u32, payload: Vec<u8>) -> Self {
        Self {
            message_type: message_type.into(),
            schema_version: 1,
            created: Utc::now().timestamp_millis() as u64,
            sequence,
            flags,
            id: uuid::Uuid::new_v4(),
            payload_type,
            payload,
        }
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(120 + self.payload.len());
        b.extend_from_slice(&HEADER_LENGTH.to_be_bytes());
        let mut t = self.message_type.as_bytes().to_vec();
        t.resize(32, b' ');
        b.extend_from_slice(&t[..32]);
        b.extend_from_slice(&self.schema_version.to_be_bytes());
        b.extend_from_slice(&self.created.to_be_bytes());
        b.extend_from_slice(&self.sequence.to_be_bytes());
        b.extend_from_slice(&self.flags.to_be_bytes());
        // The least significant half of the UUID comes first.
        let id = self.id.as_bytes();
        b.extend_from_slice(&id[8..16]);
        b.extend_from_slice(&id[0..8]);
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &self.payload);
        b.extend_from_slice(digest.as_ref());
        b.extend_from_slice(&self.payload_type.to_be_bytes());
        b.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        b.extend_from_slice(&self.payload);
        b
    }

    pub(crate) fn decode(b: &[u8]) -> Option<Self> {
        let u32_at = |o: usize| Some(u32::from_be_bytes(b.get(o..o + 4)?.try_into().ok()?));
        let u64_at = |o: usize| Some(u64::from_be_bytes(b.get(o..o + 8)?.try_into().ok()?));
        let header = u32_at(0)? as usize;
        let message_type = String::from_utf8_lossy(b.get(4..36)?).trim_end_matches([' ', '\0']).to_string();
        let mut id = [0u8; 16];
        id[8..16].copy_from_slice(b.get(64..72)?);
        id[0..8].copy_from_slice(b.get(72..80)?);
        let payload_type = u32_at(112)?;
        let len = u32_at(header)? as usize;
        let payload = b.get(header + 4..header + 4 + len)?.to_vec();
        Some(Self {
            message_type,
            schema_version: u32_at(36)?,
            created: u64_at(40)?,
            sequence: u64_at(48)? as i64,
            flags: u64_at(56)?,
            id: uuid::Uuid::from_bytes(id),
            payload_type,
            payload,
        })
    }
}

// ---- WebSocket framing ----

/// Read one WebSocket message (joining fragments); its opcode and data.
async fn read_ws<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<(u8, Vec<u8>)> {
    let mut data = Vec::new();
    let mut opcode = 0u8;
    loop {
        let mut h = [0u8; 2];
        r.read_exact(&mut h).await?;
        let fin = h[0] & 0x80 != 0;
        let op = h[0] & 0x0f;
        let masked = h[1] & 0x80 != 0;
        let mut len = u64::from(h[1] & 0x7f);
        if len == 126 {
            let mut x = [0u8; 2];
            r.read_exact(&mut x).await?;
            len = u64::from(u16::from_be_bytes(x));
        } else if len == 127 {
            let mut x = [0u8; 8];
            r.read_exact(&mut x).await?;
            len = u64::from_be_bytes(x);
        }
        if len > 64 * 1024 * 1024 {
            return Err(std::io::Error::other("frame too large"));
        }
        let mut mask = [0u8; 4];
        if masked {
            r.read_exact(&mut mask).await?;
        }
        let mut payload = vec![0u8; len as usize];
        r.read_exact(&mut payload).await?;
        if masked {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }
        if op >= 8 {
            // Control frames may arrive between fragments.
            return Ok((op, payload));
        }
        if op != 0 {
            opcode = op;
        }
        data.extend_from_slice(&payload);
        if fin {
            return Ok((opcode, data));
        }
    }
}

/// One unmasked WebSocket frame, as a server sends it.
pub(crate) fn ws_frame(opcode: u8, data: &[u8]) -> Vec<u8> {
    let mut f = vec![0x80 | opcode];
    match data.len() {
        n if n < 126 => f.push(n as u8),
        n if n <= u16::MAX as usize => {
            f.push(126);
            f.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            f.push(127);
            f.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    f.extend_from_slice(data);
    f
}

fn ws_accept(key: &str) -> String {
    let d =
        aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, format!("{key}{WS_GUID}").as_bytes());
    base64::engine::general_purpose::STANDARD.encode(d.as_ref())
}

/// What the writer task sends.
enum Out {
    /// `output_stream_data`, numbered by the writer.
    Stream(u32, Vec<u8>),
    Ack(Value),
    Closed(String),
    Close,
}

impl Ssm {
    fn find_session(&self, id: &str) -> Option<(String, String, SessionRecord)> {
        let st = self.lock();
        st.regions.iter().find_map(|(key, r)| {
            let rec = r.sessions.get(id)?;
            let (account, region) = key.split_once('/')?;
            Some((account.to_string(), region.to_string(), rec.clone()))
        })
    }

    fn update_session(&self, account: &str, region: &str, id: &str, f: impl FnOnce(&mut SessionRecord)) {
        let mut st = self.lock();
        if let Some(r) = st.region(account, region).sessions.get_mut(id) {
            f(r);
        }
    }

    /// The data channel listener's address, started on first use.
    async fn session_listener(&self, ctx: &RequestContext) -> Result<SocketAddr, ServiceError> {
        if let Some(a) = *self.sessions.addr.lock().expect("session hub lock") {
            return Ok(a);
        }
        let bind = std::env::var("MWS_SSM_SESSION_LISTEN").ok().unwrap_or_else(|| {
            let host = ctx
                .endpoint
                .as_deref()
                .and_then(|e| e.split("://").nth(1))
                .and_then(|h| h.rsplit_once(':').map(|(h, _)| h.to_string()))
                .unwrap_or_else(|| "127.0.0.1".into());
            let host = if host == "localhost" { "127.0.0.1".to_string() } else { host };
            format!("{host}:0")
        });
        let listener = tokio::net::TcpListener::bind(&bind)
            .await
            .map_err(|e| errors::internal_server_error(format!("Session Manager could not listen on {bind}: {e}")))?;
        let addr = listener.local_addr().map_err(|e| errors::internal_server_error(e.to_string()))?;
        let mut slot = self.sessions.addr.lock().expect("session hub lock");
        if let Some(a) = *slot {
            return Ok(a);
        }
        *slot = Some(addr);
        drop(slot);
        let ssm = self.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { continue };
                let ssm = ssm.clone();
                tokio::spawn(async move {
                    let _ = ssm.serve_data_channel(stream).await;
                });
            }
        });
        Ok(addr)
    }

    fn stream_url(&self, ctx: &RequestContext, addr: SocketAddr, id: &str) -> String {
        let host = if addr.ip().is_unspecified() {
            ctx.endpoint
                .as_deref()
                .and_then(|e| e.split("://").nth(1))
                .and_then(|h| h.rsplit_once(':').map(|(h, _)| h.to_string()))
                .unwrap_or_else(|| "127.0.0.1".into())
        } else {
            addr.ip().to_string()
        };
        format!(
            "ws://{host}:{}/v1/data-channel/{id}?role=publish_subscribe&cell-number={}",
            addr.port(),
            base64::engine::general_purpose::STANDARD.encode(format!("mws-{}", ctx.region))
        )
    }

    pub(crate) async fn start_session(
        &self,
        ctx: &RequestContext,
        input: types::StartSessionRequest,
    ) -> Result<types::StartSessionResponse, ServiceError> {
        let document = input.document_name.clone().unwrap_or_else(|| "SSM-SessionManagerRunShell".into());
        let found = self.find_document(ctx, &document);
        let doc_arn = match &found {
            Some(f) if f.doc.amazon() => crate::documents::arn(&ctx.partition, &ctx.region, "", &f.doc.name),
            Some(f) => crate::documents::arn(&ctx.partition, &ctx.region, &f.owner_account, &f.doc.name),
            None => crate::documents::arn(&ctx.partition, &ctx.region, &ctx.caller.account_id, &document),
        };
        ctx.authorize("ssm:StartSession", &instance_arn(ctx, &input.target), ConditionContext::new())?;
        ctx.authorize("ssm:StartSession", &doc_arn, ConditionContext::new())?;
        let found = found.ok_or_else(|| crate::documents::not_found(&document))?;
        if found.doc.document_type != "Session" {
            return Err(errors::invalid_document(format!(
                "Document type {} is not supported. Only documents of type Session can be used.",
                found.doc.document_type
            )));
        }
        let version = pick_version(&found.doc, None, None)?;
        let content = parse_content(&version.content, &version.format)?;
        let node = self
            .nodes_of(&ctx.caller.account_id, &ctx.region)
            .into_iter()
            .find(|n| n.instance_id == input.target && n.ping_status == "Online");
        if node.is_none() {
            return Err(errors::target_not_connected(format!("{} is not connected.", input.target)));
        }
        let session_type = content.get("sessionType").and_then(Value::as_str).unwrap_or("Standard_Stream").to_string();
        let given = input.parameters.clone().unwrap_or_default();
        let declared = content.get("parameters").and_then(Value::as_object).cloned().unwrap_or_default();
        if let Some(k) = given.keys().find(|k| !declared.contains_key(*k)) {
            return Err(errors::invalid_parameters(format!("Parameter {k} is not defined in the document.")));
        }
        let mut vars: BTreeMap<String, Value> = BTreeMap::new();
        for (name, spec) in &declared {
            let value = given.get(name).and_then(|v| v.first().cloned()).or_else(|| {
                spec.get("default").map(|d| match d {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
            });
            let Some(value) = value else {
                return Err(errors::invalid_parameters(format!("Parameter {name} is required.")));
            };
            if let Some(p) = spec.get("allowedPattern").and_then(Value::as_str) {
                if regex::Regex::new(p).is_ok_and(|re| !re.is_match(&value)) {
                    return Err(errors::invalid_parameters(format!(
                        "Parameter {name} value {value} does not match {p}."
                    )));
                }
            }
            vars.insert(name.clone(), Value::String(value));
        }
        let properties = crate::engine::substitute(&content.get("properties").cloned().unwrap_or(json!({})), &vars);
        let addr = self.session_listener(ctx).await?;
        let id = format!("{}-{}", session_prefix(&ctx.caller.arn), random_hex(17));
        let token = base64::engine::general_purpose::STANDARD.encode(format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        ));
        let record = SessionRecord {
            session: types::Session {
                session_id: Some(id.clone()),
                target: Some(input.target.clone()),
                status: Some("Connecting".into()),
                start_date: Some(now(ctx)),
                document_name: Some(found.doc.name.clone()),
                owner: Some(ctx.caller.arn.clone()),
                reason: input.reason.clone(),
                details: Some(String::new()),
                output_url: Some(types::SessionManagerOutputUrl {
                    s3_output_url: Some(String::new()),
                    cloud_watch_output_url: Some(String::new()),
                }),
                access_type: Some("Standard".into()),
                ..Default::default()
            },
            token: token.clone(),
            session_type,
            properties,
        };
        self.lock().region(&ctx.caller.account_id, &ctx.region).sessions.insert(id.clone(), record);
        Ok(types::StartSessionResponse {
            session_id: Some(id.clone()),
            token_value: Some(token),
            stream_url: Some(self.stream_url(ctx, addr, &id)),
        })
    }

    pub(crate) async fn resume_session(
        &self,
        ctx: &RequestContext,
        input: types::ResumeSessionRequest,
    ) -> Result<types::ResumeSessionResponse, ServiceError> {
        ctx.authorize("ssm:ResumeSession", &session_arn(ctx, &input.session_id), ConditionContext::new())?;
        let rec = self
            .lock()
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .and_then(|r| r.sessions.get(&input.session_id))
            .cloned()
            .ok_or_else(|| errors::does_not_exist(format!("Session {} does not exist.", input.session_id)))?;
        if matches!(rec.session.status.as_deref(), Some("Terminated" | "Failed")) {
            return Err(errors::does_not_exist(format!("Session {} is terminated.", input.session_id)));
        }
        let addr = self.session_listener(ctx).await?;
        let token = base64::engine::general_purpose::STANDARD.encode(format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        ));
        let t = token.clone();
        self.update_session(&ctx.caller.account_id, &ctx.region, &input.session_id, |r| r.token = t);
        Ok(types::ResumeSessionResponse {
            session_id: Some(input.session_id.clone()),
            token_value: Some(token),
            stream_url: Some(self.stream_url(ctx, addr, &input.session_id)),
        })
    }

    pub(crate) fn terminate_session(
        &self,
        ctx: &RequestContext,
        input: types::TerminateSessionRequest,
    ) -> Result<types::TerminateSessionResponse, ServiceError> {
        ctx.authorize("ssm:TerminateSession", &session_arn(ctx, &input.session_id), ConditionContext::new())?;
        let at = now(ctx);
        let exists = self
            .lock()
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .is_some_and(|r| r.sessions.contains_key(&input.session_id));
        if exists {
            self.update_session(&ctx.caller.account_id, &ctx.region, &input.session_id, |r| {
                if !matches!(r.session.status.as_deref(), Some("Terminated" | "Failed")) {
                    r.session.status = Some("Terminated".into());
                    r.session.end_date = Some(at);
                }
            });
            if let Some(n) = self.sessions.terminate.lock().expect("session hub lock").get(&input.session_id) {
                n.notify_one();
            }
        }
        Ok(types::TerminateSessionResponse { session_id: Some(input.session_id) })
    }

    pub(crate) fn describe_sessions(
        &self,
        ctx: &RequestContext,
        input: types::DescribeSessionsRequest,
    ) -> Result<types::DescribeSessionsResponse, ServiceError> {
        ctx.authorize("ssm:DescribeSessions", "*", ConditionContext::new())?;
        let filters = input.filters.unwrap_or_default();
        let time = |v: &str| {
            DateTime::parse_from_rfc3339(v)
                .map(|t| t.with_timezone(&Utc))
                .map_err(|_| errors::invalid_filter_value(format!("{v} is not a valid date (yyyy-MM-ddTHH:mm:ssZ).")))
        };
        for f in &filters {
            const KEYS: &[&str] =
                &["InvokedAfter", "InvokedBefore", "Target", "Owner", "Status", "SessionId", "AccessType"];
            if !KEYS.contains(&f.key.as_str()) {
                return Err(errors::invalid_filter_key(format!("The filter key {} isn't valid.", f.key)));
            }
            if f.key.starts_with("Invoked") {
                time(&f.value)?;
            }
        }
        let active = input.state == "Active";
        let mut list: Vec<types::Session> = {
            let st = self.lock();
            st.region_ref(&ctx.caller.account_id, &ctx.region)
                .map(|r| r.sessions.values().map(|s| s.session.clone()).collect())
                .unwrap_or_default()
        };
        list.retain(|s| {
            let terminal = matches!(s.status.as_deref(), Some("Terminated" | "Failed"));
            terminal != active
                && filters.iter().all(|f| match f.key.as_str() {
                    "InvokedAfter" => time(&f.value).ok().zip(s.start_date).is_some_and(|(t, d)| d >= t),
                    "InvokedBefore" => time(&f.value).ok().zip(s.start_date).is_some_and(|(t, d)| d <= t),
                    "Target" => s.target.as_deref() == Some(f.value.as_str()),
                    "Owner" => s.owner.as_deref() == Some(f.value.as_str()),
                    "Status" => s.status.as_deref() == Some(f.value.as_str()),
                    "SessionId" => s.session_id.as_deref() == Some(f.value.as_str()),
                    "AccessType" => s.access_type.as_deref() == Some(f.value.as_str()),
                    _ => false,
                })
        });
        list.sort_by_key(|s| std::cmp::Reverse(s.start_date));
        let limit = input.max_results.unwrap_or(20).clamp(1, 200) as usize;
        let (items, next) = page(list, input.next_token.as_deref(), limit)?;
        Ok(types::DescribeSessionsResponse { sessions: Some(items), next_token: next })
    }

    pub(crate) fn get_connection_status(
        &self,
        ctx: &RequestContext,
        input: types::GetConnectionStatusRequest,
    ) -> Result<types::GetConnectionStatusResponse, ServiceError> {
        ctx.authorize("ssm:GetConnectionStatus", &instance_arn(ctx, &input.target), ConditionContext::new())?;
        let online = self
            .nodes_of(&ctx.caller.account_id, &ctx.region)
            .iter()
            .any(|n| n.instance_id == input.target && n.ping_status == "Online");
        Ok(types::GetConnectionStatusResponse {
            target: Some(input.target),
            status: Some(if online { "connected" } else { "notconnected" }.into()),
        })
    }

    /// Serve one data channel connection: the WebSocket upgrade, then the
    /// session.
    async fn serve_data_channel(&self, mut stream: tokio::net::TcpStream) -> std::io::Result<()> {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if head.len() > 16 * 1024 {
                return Ok(());
            }
            stream.read_exact(&mut byte).await?;
            head.push(byte[0]);
        }
        let head = String::from_utf8_lossy(&head).to_string();
        let mut lines = head.lines();
        let request = lines.next().unwrap_or_default();
        let path = request.split_whitespace().nth(1).unwrap_or_default();
        let id = path.split('?').next().unwrap_or_default().strip_prefix("/v1/data-channel/").unwrap_or_default();
        let key = lines
            .filter_map(|l| l.split_once(':'))
            .find(|(k, _)| k.trim().eq_ignore_ascii_case("sec-websocket-key"))
            .map(|(_, v)| v.trim().to_string());
        let (Some(key), Some((account, region, _))) = (key, self.find_session(id)) else {
            stream.write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await?;
            return Ok(());
        };
        let reply = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            ws_accept(&key)
        );
        stream.write_all(reply.as_bytes()).await?;
        let id = id.to_string();
        let (mut rd, wr) = stream.into_split();
        // The open-channel request carries the session token.
        let (op, data) = read_ws(&mut rd).await?;
        let open: Value = if op == 1 { serde_json::from_slice(&data).unwrap_or_default() } else { Value::Null };
        let Some((_, _, rec)) = self.find_session(&id) else { return Ok(()) };
        let (tx, rx) = mpsc::unbounded_channel::<Out>();
        let writer = tokio::spawn(write_loop(wr, rx, id.clone()));
        if open.get("TokenValue").and_then(Value::as_str) != Some(rec.token.as_str())
            || matches!(rec.session.status.as_deref(), Some("Terminated" | "Failed"))
        {
            let _ = tx.send(Out::Closed("The session token is not valid.".into()));
            let _ = tx.send(Out::Close);
            let _ = writer.await;
            return Ok(());
        }
        self.update_session(&account, &region, &id, |r| r.session.status = Some("Connected".into()));
        let terminate = Arc::new(Notify::new());
        self.sessions.terminate.lock().expect("session hub lock").insert(id.clone(), terminate.clone());
        let result = self.run_channel(&account, &region, &rec, &mut rd, &tx, &terminate).await;
        self.sessions.terminate.lock().expect("session hub lock").remove(&id);
        let message = match &result {
            Ok(m) => m.clone(),
            Err(e) => format!("The session ended: {e}"),
        };
        let _ = tx.send(Out::Closed(message));
        let _ = tx.send(Out::Close);
        let _ = writer.await;
        let at = self.clock_now();
        self.update_session(&account, &region, &id, |r| {
            if !matches!(r.session.status.as_deref(), Some("Terminated" | "Failed")) {
                r.session.status = Some("Terminated".into());
                r.session.end_date = Some(at);
            }
        });
        Ok(())
    }

    /// The session itself; the message `channel_closed` carries.
    async fn run_channel<R: AsyncRead + Unpin>(
        &self,
        account: &str,
        region: &str,
        rec: &SessionRecord,
        rd: &mut R,
        tx: &mpsc::UnboundedSender<Out>,
        terminate: &Notify,
    ) -> Result<String, String> {
        let kind = match rec.session_type.as_str() {
            "Port" => {
                let port = rec
                    .properties
                    .get("portNumber")
                    .and_then(|p| p.as_str().map(str::to_string).or_else(|| p.as_u64().map(|n| n.to_string())))
                    .and_then(|p| p.parse().ok())
                    .unwrap_or(80);
                let host =
                    rec.properties.get("host").and_then(Value::as_str).filter(|h| !h.is_empty()).map(str::to_string);
                SessionKind::Port { host, port }
            }
            "InteractiveCommands" => SessionKind::Shell {
                command: rec
                    .properties
                    .get("linux")
                    .and_then(|l| l.get("commands"))
                    .and_then(Value::as_str)
                    .map(str::to_string),
            },
            _ => SessionKind::Shell { command: None },
        };
        let (agent_version, action_type, properties) = match &kind {
            // Agents before 3.0.196 forward one connection at a time
            // (no multiplexing), which is what MWS does.
            SessionKind::Port { .. } => ("3.0.0.0", "Port", rec.properties.clone()),
            SessionKind::Shell { .. } => (
                "3.3.40.0",
                rec.session_type.as_str(),
                json!({"linux": {"commands": rec.properties.get("linux").and_then(|l| l.get("commands")).cloned().unwrap_or(json!("")), "runAsElevated": false}}),
            ),
        };
        let handshake = json!({
            "AgentVersion": agent_version,
            "RequestedClientActions": [{
                "ActionType": "SessionType",
                "ActionParameters": { "SessionType": action_type, "Properties": properties },
            }],
        });
        let _ = tx.send(Out::Stream(HANDSHAKE_REQUEST, handshake.to_string().into_bytes()));
        let started = std::time::Instant::now();
        let mut expected: i64 = 0;
        let mut pending: BTreeMap<i64, AgentMessage> = BTreeMap::new();
        let mut io_writer: Option<Pin<Box<dyn AsyncWrite + Send>>> = None;
        let mut reader_task: Option<tokio::task::JoinHandle<()>> = None;
        let (eof_tx, mut eof_rx) = mpsc::unbounded_channel::<()>();
        let open = |me: &Ssm| {
            let nodes = me.managed();
            let target = rec.session.target.clone().unwrap_or_default();
            let kind = kind.clone();
            let (account, region) = (account.to_string(), region.to_string());
            async move {
                match nodes {
                    Some(n) => n.open_session(&account, &region, &target, &kind).await,
                    None => Ok(None),
                }
            }
        };
        loop {
            tokio::select! {
                msg = read_ws(rd) => {
                    let (op, data) = msg.map_err(|e| e.to_string())?;
                    match op {
                        8 => return Ok(String::new()),
                        2 => {}
                        _ => continue,
                    }
                    let Some(m) = AgentMessage::decode(&data) else { continue };
                    match m.message_type.as_str() {
                        "input_stream_data" => {
                            let _ = tx.send(Out::Ack(json!({
                                "AcknowledgedMessageType": m.message_type,
                                "AcknowledgedMessageId": m.id.to_string(),
                                "AcknowledgedMessageSequenceNumber": m.sequence,
                                "IsSequentialMessage": true,
                            })));
                            if m.sequence < expected {
                                continue;
                            }
                            pending.insert(m.sequence, m);
                            while let Some(m) = pending.remove(&expected) {
                                expected += 1;
                                match m.payload_type {
                                    HANDSHAKE_RESPONSE => {
                                        let done = json!({
                                            "HandshakeTimeToComplete": started.elapsed().as_nanos() as u64,
                                            "CustomerMessage": "",
                                        });
                                        let _ = tx.send(Out::Stream(HANDSHAKE_COMPLETE, done.to_string().into_bytes()));
                                        if matches!(kind, SessionKind::Shell { .. }) {
                                            match open(self).await {
                                                Ok(Some(io)) => {
                                                    io_writer = Some(io.writer);
                                                    reader_task = Some(pump(io.reader, tx.clone(), eof_tx.clone()));
                                                }
                                                Ok(None) => {
                                                    let _ = tx.send(Out::Stream(OUTPUT, b"\r\nThis instance has no machine to connect to: MWS runs EC2 with the metadata-only backend (set MWS_EC2_BACKEND=docker).\r\n".to_vec()));
                                                    return Ok(String::new());
                                                }
                                                Err(e) => return Err(e),
                                            }
                                        }
                                    }
                                    OUTPUT => {
                                        if io_writer.is_none() && matches!(kind, SessionKind::Port { .. }) {
                                            match open(self).await {
                                                Ok(Some(io)) => {
                                                    io_writer = Some(io.writer);
                                                    reader_task = Some(pump(io.reader, tx.clone(), eof_tx.clone()));
                                                }
                                                Ok(None) => return Err("The node has no ports to connect to.".into()),
                                                Err(e) => return Err(e),
                                            }
                                        }
                                        if let Some(w) = io_writer.as_mut() {
                                            if w.write_all(&m.payload).await.is_err() || w.flush().await.is_err() {
                                                io_writer = None;
                                            }
                                        }
                                    }
                                    FLAG => {
                                        let flag = m.payload.get(..4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
                                        match flag {
                                            // DisconnectToPort: the local client went away.
                                            Some(1) => {
                                                io_writer = None;
                                                if let Some(t) = reader_task.take() {
                                                    t.abort();
                                                }
                                            }
                                            // TerminateSession.
                                            Some(2) => return Ok(String::new()),
                                            _ => {}
                                        }
                                    }
                                    SIZE => {}
                                    _ => {}
                                }
                            }
                        }
                        "acknowledge" | "start_publication" | "pause_publication" => {}
                        "channel_closed" => return Ok(String::new()),
                        _ => {}
                    }
                }
                _ = eof_rx.recv() => {
                    if matches!(kind, SessionKind::Port { .. }) {
                        // The node closed the connection; the next data
                        // opens another.
                        io_writer = None;
                        reader_task = None;
                        continue;
                    }
                    return Ok(String::new());
                }
                _ = terminate.notified() => return Ok(String::new()),
            }
        }
    }

    pub(crate) fn start_access_request(
        &self,
        ctx: &RequestContext,
        input: types::StartAccessRequestRequest,
    ) -> Result<types::StartAccessRequestResponse, ServiceError> {
        let target = input
            .targets
            .iter()
            .find(|t| t.key.as_deref() == Some("InstanceIds"))
            .and_then(|t| t.values.clone())
            .unwrap_or_default();
        if input.targets.len() != 1 || target.len() != 1 {
            return Err(errors::validation("Access requests name exactly one node, as Key=InstanceIds."));
        }
        let node = target[0].clone();
        ctx.authorize("ssm:StartAccessRequest", &instance_arn(ctx, &node), ConditionContext::new())?;
        let tags: BTreeMap<String, String> =
            input.tags.iter().flatten().map(|t| (t.key.clone(), t.value.clone())).collect();
        let at = now(ctx);
        let data = BTreeMap::from([(
            "/aws/accessrequest".to_string(),
            types::OpsItemDataValue {
                value: Some(
                    json!({ "requesterArn": ctx.caller.arn, "requesterId": ctx.caller.user_id, "targetResourceId": node, "reason": input.reason })
                        .to_string(),
                ),
                r#type: Some("SearchableString".into()),
            },
        )]);
        let item = types::OpsItem {
            created_by: Some(ctx.caller.arn.clone()),
            ops_item_type: Some("/aws/accessrequest".into()),
            created_time: Some(at),
            description: Some(input.reason.clone()),
            last_modified_by: Some(ctx.caller.arn.clone()),
            last_modified_time: Some(at),
            status: Some("Pending".into()),
            title: Some(format!("Access request for {node}")),
            source: Some("SSM".into()),
            operational_data: Some(data),
            ..Default::default()
        };
        let (id, _) = self.insert_ops_item(&ctx.partition, &ctx.caller.account_id, &ctx.region, item, tags)?;
        Ok(types::StartAccessRequestResponse { access_request_id: Some(id) })
    }

    pub(crate) async fn get_access_token(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessTokenRequest,
    ) -> Result<types::GetAccessTokenResponse, ServiceError> {
        let arn = format!(
            "arn:{}:ssm:{}:{}:opsitem/{}",
            ctx.partition, ctx.region, ctx.caller.account_id, input.access_request_id
        );
        ctx.authorize("ssm:GetAccessToken", &arn, ConditionContext::new())?;
        let item = self
            .lock()
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .and_then(|r| r.ops.items.get(&input.access_request_id))
            .map(|r| r.item.clone())
            .filter(|i| i.ops_item_type.as_deref() == Some("/aws/accessrequest"))
            .ok_or_else(|| {
                errors::resource_not_found(format!("Access request {} not found.", input.access_request_id))
            })?;
        if item.created_by.as_deref() != Some(ctx.caller.arn.as_str()) {
            return Err(errors::access_denied("Only the requester can get the access token of an access request."));
        }
        let status = item.status.clone().unwrap_or_else(|| "Pending".into());
        let status = match status.as_str() {
            "Approved" | "Rejected" | "Revoked" | "Pending" => status,
            "Open" | "InProgress" | "PendingApproval" => "Pending".into(),
            _ => "Expired".into(),
        };
        if status != "Approved" {
            return Ok(types::GetAccessTokenResponse { credentials: None, access_request_status: Some(status) });
        }
        let runtime = self.runtime().ok_or_else(|| errors::internal_server_error("Credentials are not available."))?;
        let out = runtime
            .call(ctx, "sts", "GetSessionToken", json!({ "DurationSeconds": 3600 }))
            .await
            .map_err(|e| errors::access_denied(format!("Credentials could not be issued: {}", e.message)))?;
        let c = &out["Credentials"];
        let expiration = c["Expiration"]
            .as_str()
            .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
            .map(|t| t.with_timezone(&Utc))
            .or_else(|| c["Expiration"].as_f64().and_then(|s| DateTime::from_timestamp(s as i64, 0)))
            .unwrap_or_else(|| now(ctx) + chrono::Duration::hours(1));
        Ok(types::GetAccessTokenResponse {
            credentials: Some(types::Credentials {
                access_key_id: c["AccessKeyId"].as_str().unwrap_or_default().into(),
                secret_access_key: c["SecretAccessKey"].as_str().unwrap_or_default().into(),
                session_token: c["SessionToken"].as_str().unwrap_or_default().into(),
                expiration_time: expiration,
            }),
            access_request_status: Some(status),
        })
    }

    fn connector_by_id(&self, ctx: &RequestContext, action: &str, id: &str) -> Result<ConnectorRecord, ServiceError> {
        let arn = format!("arn:{}:ssm:{}:{}:cloud-connector/{id}", ctx.partition, ctx.region, ctx.caller.account_id);
        ctx.authorize(&format!("ssm:{action}"), &arn, ConditionContext::new())?;
        self.lock()
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .and_then(|r| r.connectors.get(id))
            .cloned()
            .ok_or_else(|| errors::resource_not_found(format!("Cloud connector {id} not found.")))
    }

    pub(crate) fn create_cloud_connector(
        &self,
        ctx: &RequestContext,
        input: types::CreateCloudConnectorRequest,
    ) -> Result<types::CreateCloudConnectorResult, ServiceError> {
        let id = uuid::Uuid::new_v4().to_string();
        let arn = format!("arn:{}:ssm:{}:{}:cloud-connector/{id}", ctx.partition, ctx.region, ctx.caller.account_id);
        let tags: BTreeMap<String, String> =
            input.tags.iter().flatten().map(|t| (t.key.clone(), t.value.clone())).collect();
        ctx.authorize("ssm:CreateCloudConnector", &arn, crate::names::request_tag_conditions(tags.iter()))?;
        if !input.role_arn.starts_with("arn:") || !input.role_arn.contains(":role/") {
            return Err(errors::validation(format!("RoleArn {} is not an IAM role ARN.", input.role_arn)));
        }
        let at = now(ctx);
        let record = ConnectorRecord {
            id: id.clone(),
            tags,
            connector: types::GetCloudConnectorResult {
                cloud_connector_arn: Some(arn),
                display_name: Some(input.display_name),
                description: input.description,
                role_arn: Some(input.role_arn),
                configuration: Some(input.configuration),
                config_connector_arn: Some(input.config_connector_arn),
                created_at: Some(at),
                updated_at: Some(at),
            },
        };
        self.lock().region(&ctx.caller.account_id, &ctx.region).connectors.insert(id.clone(), record);
        Ok(types::CreateCloudConnectorResult { cloud_connector_id: Some(id) })
    }

    pub(crate) fn get_cloud_connector(
        &self,
        ctx: &RequestContext,
        input: types::GetCloudConnectorRequest,
    ) -> Result<types::GetCloudConnectorResult, ServiceError> {
        Ok(self.connector_by_id(ctx, "GetCloudConnector", &input.cloud_connector_id)?.connector)
    }

    pub(crate) fn update_cloud_connector(
        &self,
        ctx: &RequestContext,
        input: types::UpdateCloudConnectorRequest,
    ) -> Result<types::UpdateCloudConnectorResult, ServiceError> {
        self.connector_by_id(ctx, "UpdateCloudConnector", &input.cloud_connector_id)?;
        let at = now(ctx);
        let mut st = self.lock();
        if let Some(r) = st.region(&ctx.caller.account_id, &ctx.region).connectors.get_mut(&input.cloud_connector_id) {
            if let Some(n) = input.display_name {
                r.connector.display_name = Some(n);
            }
            if let Some(d) = input.description {
                r.connector.description = Some(d);
            }
            if let Some(c) = input.configuration {
                r.connector.configuration = Some(c);
            }
            r.connector.updated_at = Some(at);
        }
        Ok(types::UpdateCloudConnectorResult::default())
    }

    pub(crate) fn delete_cloud_connector(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCloudConnectorRequest,
    ) -> Result<types::DeleteCloudConnectorResult, ServiceError> {
        self.connector_by_id(ctx, "DeleteCloudConnector", &input.cloud_connector_id)?;
        self.lock().region(&ctx.caller.account_id, &ctx.region).connectors.remove(&input.cloud_connector_id);
        Ok(types::DeleteCloudConnectorResult::default())
    }

    pub(crate) fn list_cloud_connectors(
        &self,
        ctx: &RequestContext,
        input: types::ListCloudConnectorsRequest,
    ) -> Result<types::ListCloudConnectorsResult, ServiceError> {
        ctx.authorize("ssm:ListCloudConnectors", "*", ConditionContext::new())?;
        let mut list: Vec<ConnectorRecord> = {
            let st = self.lock();
            st.region_ref(&ctx.caller.account_id, &ctx.region)
                .map(|r| r.connectors.values().cloned().collect())
                .unwrap_or_default()
        };
        for f in input.filters.iter().flatten() {
            let values = f.filter_values.clone().unwrap_or_default();
            list.retain(|c| {
                let Some(types::CloudConnectorConfiguration::AzureConfiguration(a)) = &c.connector.configuration else {
                    return false;
                };
                match f.filter_key.as_deref() {
                    Some("TenantId") => values.contains(&a.tenant_id),
                    Some("SubscriptionId") => {
                        let subs = serde_json::to_value(&a.targets).unwrap_or_default().to_string();
                        values.iter().any(|v| subs.contains(v.as_str()))
                    }
                    _ => true,
                }
            });
        }
        let summaries: Vec<types::CloudConnectorSummary> = list
            .into_iter()
            .map(|c| types::CloudConnectorSummary {
                cloud_connector_id: Some(c.id),
                display_name: c.connector.display_name,
                description: c.connector.description,
                role_arn: c.connector.role_arn,
                created_at: c.connector.created_at,
                updated_at: c.connector.updated_at,
            })
            .collect();
        let limit = input.max_results.unwrap_or(50).clamp(1, 100) as usize;
        let (items, next) = page(summaries, input.next_token.as_deref(), limit)?;
        Ok(types::ListCloudConnectorsResult { cloud_connectors: Some(items), next_token: next })
    }

    pub(crate) fn validate_cloud_connector(
        &self,
        ctx: &RequestContext,
        input: types::ValidateCloudConnectorRequest,
    ) -> Result<types::ValidateCloudConnectorResult, ServiceError> {
        let rec = self.connector_by_id(ctx, "ValidateCloudConnector", &input.cloud_connector_id)?;
        let role = rec.connector.role_arn.clone().unwrap_or_default();
        let tenant = match &rec.connector.configuration {
            Some(types::CloudConnectorConfiguration::AzureConfiguration(a)) => a.tenant_id.clone(),
            None => String::new(),
        };
        let mut findings = Vec::new();
        let arn = rec.connector.cloud_connector_arn.clone().unwrap_or_default();
        let assumed = match self.runtime() {
            Some(r) => r.assume_role(ctx, &role, &arn).is_ok(),
            None => false,
        };
        let scope = Some(types::ValidationFindingScope { r#type: Some("azure:tenant".into()), id: Some(tenant) });
        if assumed {
            findings.push(types::ValidationFinding {
                r#type: Some("ERROR".into()),
                code: Some("ProviderCredentialCreationFailed".into()),
                message: Some(
                    "Systems Manager assumed the role, but MWS does not contact Microsoft Entra ID for Azure credentials."
                        .into(),
                ),
                provider_message: Some(String::new()),
                scope,
            });
        } else {
            findings.push(types::ValidationFinding {
                r#type: Some("ERROR".into()),
                code: Some("AwsRoleAssumptionFailed".into()),
                message: Some(format!("Systems Manager could not assume the role {role}.")),
                provider_message: Some(String::new()),
                scope,
            });
        }
        let limit = input.max_results.unwrap_or(50).clamp(1, 100) as usize;
        let (items, next) = page(findings, input.next_token.as_deref(), limit)?;
        Ok(types::ValidateCloudConnectorResult { validation_findings: Some(items), next_token: next })
    }
}

/// Copy the node's output into `output_stream_data` messages.
fn pump(
    mut reader: Pin<Box<dyn AsyncRead + Send>>,
    tx: mpsc::UnboundedSender<Out>,
    eof: mpsc::UnboundedSender<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => {
                    let _ = eof.send(());
                    return;
                }
                Ok(n) => {
                    if tx.send(Out::Stream(OUTPUT, buf[..n].to_vec())).is_err() {
                        return;
                    }
                }
            }
        }
    })
}

/// Write outgoing messages, numbering the stream data.
async fn write_loop(mut wr: tokio::net::tcp::OwnedWriteHalf, mut rx: mpsc::UnboundedReceiver<Out>, session: String) {
    let mut seq: i64 = 0;
    while let Some(out) = rx.recv().await {
        let frame = match out {
            Out::Stream(payload_type, payload) => {
                let m =
                    AgentMessage::new("output_stream_data", seq, if seq == 0 { 1 } else { 0 }, payload_type, payload);
                seq += 1;
                ws_frame(2, &m.encode())
            }
            Out::Ack(v) => ws_frame(2, &AgentMessage::new("acknowledge", 0, 3, 0, v.to_string().into_bytes()).encode()),
            Out::Closed(output) => {
                let id = uuid::Uuid::new_v4();
                let body = json!({
                    "MessageId": id.to_string(),
                    "CreatedDate": Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                    "DestinationId": session,
                    "SessionId": session,
                    "MessageType": "channel_closed",
                    "SchemaVersion": 1,
                    "Output": output,
                });
                ws_frame(2, &AgentMessage::new("channel_closed", seq, 0, 0, body.to_string().into_bytes()).encode())
            }
            Out::Close => {
                let _ = wr.write_all(&ws_frame(8, &1000u16.to_be_bytes())).await;
                let _ = wr.shutdown().await;
                return;
            }
        };
        if wr.write_all(&frame).await.is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_messages_round_trip() {
        let m = AgentMessage::new("input_stream_data", 7, 0, OUTPUT, b"ls\n".to_vec());
        let b = m.encode();
        assert_eq!(&b[4..21], b"input_stream_data");
        assert_eq!(b[21], b' ');
        assert_eq!(b.len(), 120 + 3);
        assert_eq!(AgentMessage::decode(&b), Some(m));
    }

    #[test]
    fn websocket_accept_key() {
        // RFC 6455's example.
        assert_eq!(ws_accept("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
        assert_eq!(session_prefix("arn:aws:iam::123456789012:user/alice"), "alice");
        assert_eq!(session_prefix("arn:aws:iam::123456789012:root"), "root");
        assert_eq!(session_prefix("arn:aws:sts::123456789012:assumed-role/Admin/bob"), "bob");
    }
}

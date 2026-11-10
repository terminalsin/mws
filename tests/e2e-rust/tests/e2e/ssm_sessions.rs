//! Session Manager, just-in-time node access and multicloud connectors
//! through the official Rust SDK. The data channel is driven with an
//! independent WebSocket client speaking the Session Manager agent
//! message protocol, as `session-manager-plugin` does.

use std::time::Duration;

use aws_sdk_ec2::types::{Filter, IamInstanceProfileSpecification, InstanceStateName};
use aws_sdk_ssm::error::ProvideErrorMetadata;
use aws_sdk_ssm::types::{
    AzureConfiguration, CloudConnectorConfiguration, OpsItemStatus, SessionFilter, SessionFilterKey, SessionState,
    SessionStatus, Target,
};
use aws_sdk_ssm::Client;
use base64::Engine as _;
use mws_e2e::Mws;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn code<E: ProvideErrorMetadata>(e: E) -> String {
    e.code().unwrap_or_default().to_string()
}

async fn profile(mws: &Mws, name: &str) {
    let iam = aws_sdk_iam::Client::new(&mws.root_sdk_config().await);
    let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    iam.create_role().role_name(name).assume_role_policy_document(trust).send().await.unwrap();
    iam.create_instance_profile().instance_profile_name(name).send().await.unwrap();
    iam.add_role_to_instance_profile().instance_profile_name(name).role_name(name).send().await.unwrap();
}

async fn launch(ec2: &aws_sdk_ec2::Client, pattern: &str, profile: Option<&str>) -> String {
    let images = ec2
        .describe_images()
        .owners("amazon")
        .filters(Filter::builder().name("name").values(pattern).build())
        .send()
        .await
        .unwrap();
    let image = images.images()[0].image_id().unwrap().to_string();
    let mut run = ec2.run_instances().image_id(image).min_count(1).max_count(1);
    if let Some(p) = profile {
        run = run.iam_instance_profile(IamInstanceProfileSpecification::builder().name(p).build());
    }
    let id = run.send().await.unwrap().instances()[0].instance_id().unwrap().to_string();
    for _ in 0..240 {
        let d = ec2.describe_instances().instance_ids(&id).send().await.unwrap();
        if d.reservations()[0].instances()[0].state().and_then(|s| s.name()) == Some(&InstanceStateName::Running) {
            return id;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("instance {id} never ran");
}

// ---- a minimal data channel client ----

#[derive(Debug, Clone)]
struct Message {
    message_type: String,
    sequence: i64,
    id: [u8; 16],
    payload_type: u32,
    payload: Vec<u8>,
}

fn encode(message_type: &str, sequence: i64, flags: u64, payload_type: u32, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&116u32.to_be_bytes());
    let mut t = message_type.as_bytes().to_vec();
    t.resize(32, b' ');
    b.extend_from_slice(&t);
    b.extend_from_slice(&1u32.to_be_bytes());
    b.extend_from_slice(&(chrono::Utc::now().timestamp_millis() as u64).to_be_bytes());
    b.extend_from_slice(&sequence.to_be_bytes());
    b.extend_from_slice(&flags.to_be_bytes());
    let id: [u8; 16] = rand_id();
    b.extend_from_slice(&id);
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, payload);
    b.extend_from_slice(digest.as_ref());
    b.extend_from_slice(&payload_type.to_be_bytes());
    b.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    b.extend_from_slice(payload);
    b
}

fn rand_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    aws_lc_rs::rand::fill(&mut id).unwrap();
    id
}

fn decode(b: &[u8]) -> Message {
    let u32_at = |o: usize| u32::from_be_bytes(b[o..o + 4].try_into().unwrap());
    let header = u32_at(0) as usize;
    assert_eq!(header, 116);
    let len = u32_at(header) as usize;
    let payload = b[header + 4..header + 4 + len].to_vec();
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &payload);
    assert_eq!(&b[80..112], digest.as_ref(), "payload digest");
    Message {
        message_type: String::from_utf8_lossy(&b[4..36]).trim_end().to_string(),
        sequence: i64::from_be_bytes(b[48..56].try_into().unwrap()),
        id: b[64..80].try_into().unwrap(),
        payload_type: u32_at(112),
        payload,
    }
}

/// The message id as the agent formats it (the halves swapped).
fn message_id(id: &[u8; 16]) -> String {
    let mut u = [0u8; 16];
    u[0..8].copy_from_slice(&id[8..16]);
    u[8..16].copy_from_slice(&id[0..8]);
    let h = hex::encode(u);
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

struct Channel {
    stream: TcpStream,
    sequence: i64,
}

impl Channel {
    async fn open(url: &str, token: &str) -> Channel {
        let rest = url.strip_prefix("ws://").expect("ws:// stream URL");
        let (authority, path) = rest.split_once('/').unwrap();
        let mut stream = TcpStream::connect(authority).await.unwrap();
        let key = base64::engine::general_purpose::STANDARD.encode(rand_id());
        let req = format!(
            "GET /{path} HTTP/1.1\r\nHost: {authority}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            head.push(stream.read_u8().await.unwrap());
        }
        let head = String::from_utf8(head).unwrap();
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
        let mut sha = sha1::Sha1::default();
        sha1::Digest::update(&mut sha, format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes());
        let accept = base64::engine::general_purpose::STANDARD.encode(sha1::Digest::finalize(sha));
        assert!(head.to_ascii_lowercase().contains(&format!("sec-websocket-accept: {}", accept.to_ascii_lowercase())));
        let mut c = Channel { stream, sequence: 0 };
        let open = json!({
            "MessageSchemaVersion": "1.0",
            "RequestId": "11111111-2222-3333-4444-555555555555",
            "TokenValue": token,
            "ClientId": "e2e-client",
            "ClientVersion": "1.2.694.0",
        });
        c.send_frame(1, open.to_string().as_bytes()).await;
        c
    }

    async fn send_frame(&mut self, opcode: u8, data: &[u8]) {
        let mut f = vec![0x80 | opcode];
        match data.len() {
            n if n < 126 => f.push(0x80 | n as u8),
            n if n <= u16::MAX as usize => {
                f.push(0x80 | 126);
                f.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                f.push(0x80 | 127);
                f.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        let mask: [u8; 4] = rand_id()[..4].try_into().unwrap();
        f.extend_from_slice(&mask);
        f.extend(data.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        // The server may already have closed (after channel_closed).
        let _ = self.stream.write_all(&f).await;
    }

    /// The next binary message, or `None` once the server closes.
    async fn next(&mut self) -> Option<Message> {
        loop {
            let mut h = [0u8; 2];
            if self.stream.read_exact(&mut h).await.is_err() {
                return None;
            }
            assert_eq!(h[1] & 0x80, 0, "server frames are not masked");
            let mut len = u64::from(h[1] & 0x7f);
            if len == 126 {
                len = u64::from(self.stream.read_u16().await.unwrap());
            } else if len == 127 {
                len = self.stream.read_u64().await.unwrap();
            }
            let mut data = vec![0u8; len as usize];
            self.stream.read_exact(&mut data).await.unwrap();
            match h[0] & 0x0f {
                8 => return None,
                2 => return Some(decode(&data)),
                _ => continue,
            }
        }
    }

    /// The next message that is not an acknowledgement, acknowledging it.
    async fn next_data(&mut self) -> Option<Message> {
        loop {
            let m = tokio::time::timeout(Duration::from_secs(30), self.next()).await.expect("timed out")?;
            if m.message_type == "acknowledge" {
                continue;
            }
            if m.message_type == "output_stream_data" {
                let ack = json!({
                    "AcknowledgedMessageType": "output_stream_data",
                    "AcknowledgedMessageId": message_id(&m.id),
                    "AcknowledgedMessageSequenceNumber": m.sequence,
                    "IsSequentialMessage": true,
                });
                let b = encode("acknowledge", 0, 3, 0, ack.to_string().as_bytes());
                self.send_frame(2, &b).await;
            }
            return Some(m);
        }
    }

    async fn input(&mut self, payload_type: u32, payload: &[u8]) {
        let b = encode("input_stream_data", self.sequence, 0, payload_type, payload);
        self.sequence += 1;
        self.send_frame(2, &b).await;
    }

    /// Answer the agent's handshake request; the session type it asked for.
    async fn handshake(&mut self) -> Value {
        let req = self.next_data().await.expect("handshake request");
        assert_eq!(req.message_type, "output_stream_data");
        assert_eq!(req.sequence, 0);
        assert_eq!(req.payload_type, 5, "HandshakeRequest");
        let req: Value = serde_json::from_slice(&req.payload).unwrap();
        let action = req["RequestedClientActions"][0].clone();
        assert_eq!(action["ActionType"], "SessionType");
        let response = json!({
            "ClientVersion": "1.2.694.0",
            "ProcessedClientActions": [{"ActionType": "SessionType", "ActionStatus": 1}],
            "Errors": [],
        });
        self.input(6, response.to_string().as_bytes()).await;
        let done = self.next_data().await.expect("handshake complete");
        assert_eq!(done.payload_type, 7, "HandshakeComplete");
        action["ActionParameters"].clone()
    }

    /// Output until `channel_closed`: the text and the closing message.
    async fn drain(&mut self) -> (String, Value) {
        let mut text = String::new();
        while let Some(m) = self.next_data().await {
            match m.message_type.as_str() {
                "output_stream_data" => text.push_str(&String::from_utf8_lossy(&m.payload)),
                "channel_closed" => return (text, serde_json::from_slice(&m.payload).unwrap()),
                _ => {}
            }
        }
        panic!("the channel ended without channel_closed: {text}");
    }
}

async fn session_status(ssm: &Client, id: &str) -> Option<SessionStatus> {
    for state in [SessionState::Active, SessionState::History] {
        let out = ssm
            .describe_sessions()
            .state(state)
            .filters(SessionFilter::builder().key(SessionFilterKey::SessionId).value(id).build().unwrap())
            .send()
            .await
            .unwrap();
        if let Some(s) = out.sessions().first() {
            return s.status().cloned();
        }
    }
    None
}

async fn wait_status(ssm: &Client, id: &str, want: SessionStatus) {
    for _ in 0..100 {
        if session_status(ssm, id).await == Some(want.clone()) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("session {id} never got {want:?}: {:?}", session_status(ssm, id).await);
}

#[tokio::test]
async fn sessions_speak_the_data_channel_protocol() {
    let mws =
        Mws::start_with(mws::Config { ec2_backend: mws_ec2::BackendChoice::Metadata, ..Default::default() }).await;
    let cfg = mws.root_sdk_config().await;
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let ssm = Client::new(&cfg);
    profile(&mws, "managed").await;
    let node = launch(&ec2, "al2023-ami-*", Some("managed")).await;
    let unmanaged = launch(&ec2, "al2023-ami-*", None).await;

    let s = ssm.get_connection_status().target(&node).send().await.unwrap();
    assert_eq!(s.status().map(|s| s.as_str()), Some("connected"));
    let s = ssm.get_connection_status().target(&unmanaged).send().await.unwrap();
    assert_eq!(s.status().map(|s| s.as_str()), Some("notconnected"));
    let e = ssm.start_session().target(&unmanaged).send().await.unwrap_err();
    let e = e.into_service_error();
    assert_eq!(e.code(), Some("TargetNotConnected"));
    assert_eq!(e.message(), Some(format!("{unmanaged} is not connected.").as_str()));
    let e = ssm.start_session().target(&node).document_name("AWS-RunShellScript").send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "InvalidDocument");

    // A shell: the handshake, then (with no machine behind the node) a
    // notice and channel_closed.
    let started = ssm.start_session().target(&node).reason("e2e").send().await.unwrap();
    let id = started.session_id().unwrap().to_string();
    assert!(id.starts_with("root-"), "{id}");
    let url = started.stream_url().unwrap();
    assert!(url.contains(&format!("/v1/data-channel/{id}?role=publish_subscribe")), "{url}");
    assert_eq!(session_status(&ssm, &id).await, Some(SessionStatus::Connecting));
    let mut channel = Channel::open(url, started.token_value().unwrap()).await;
    let params = channel.handshake().await;
    assert_eq!(params["SessionType"], "Standard_Stream");
    let (text, closed) = channel.drain().await;
    assert!(text.contains("metadata-only backend"), "{text}");
    assert_eq!(closed["MessageType"], "channel_closed");
    assert_eq!(closed["SessionId"], id.as_str());
    wait_status(&ssm, &id, SessionStatus::Terminated).await;
    let history = ssm.describe_sessions().state(SessionState::History).send().await.unwrap();
    let s = history.sessions().iter().find(|s| s.session_id() == Some(id.as_str())).unwrap();
    assert_eq!(s.target(), Some(node.as_str()));
    assert_eq!(s.document_name(), Some("SSM-SessionManagerRunShell"));
    assert_eq!(s.reason(), Some("e2e"));
    assert!(s.end_date().is_some());
    assert!(s.owner().unwrap().ends_with(":root"));

    // A wrong token closes the channel without a handshake.
    let started = ssm.start_session().target(&node).send().await.unwrap();
    let mut channel = Channel::open(started.stream_url().unwrap(), "not-the-token").await;
    let m = channel.next_data().await.unwrap();
    assert_eq!(m.message_type, "channel_closed");

    // Resuming hands out a fresh token; terminating ends the session.
    let id = started.session_id().unwrap().to_string();
    let resumed = ssm.resume_session().session_id(&id).send().await.unwrap();
    assert_ne!(resumed.token_value(), started.token_value());
    let active = ssm.describe_sessions().state(SessionState::Active).send().await.unwrap();
    assert!(active.sessions().iter().any(|s| s.session_id() == Some(id.as_str())));
    ssm.terminate_session().session_id(&id).send().await.unwrap();
    assert_eq!(session_status(&ssm, &id).await, Some(SessionStatus::Terminated));
    let e = ssm.resume_session().session_id(&id).send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "DoesNotExistException");

    // Port forwarding: the handshake names the port.
    let started = ssm
        .start_session()
        .target(&node)
        .document_name("AWS-StartPortForwardingSession")
        .parameters("portNumber", vec!["8080".into()])
        .send()
        .await
        .unwrap();
    let mut channel = Channel::open(started.stream_url().unwrap(), started.token_value().unwrap()).await;
    let params = channel.handshake().await;
    assert_eq!(params["SessionType"], "Port");
    assert_eq!(params["Properties"]["portNumber"], "8080");
    channel.input(1, b"GET / HTTP/1.0\r\n\r\n").await;
    let (_, closed) = channel.drain().await;
    assert!(closed["Output"].as_str().unwrap().contains("no ports"), "{closed}");
    let e = ssm
        .start_session()
        .target(&node)
        .document_name("AWS-StartPortForwardingSession")
        .parameters("portNumber", vec!["99999".into()])
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(e.into_service_error()), "InvalidParameters");

    let filtered = ssm
        .describe_sessions()
        .state(SessionState::History)
        .filters(SessionFilter::builder().key(SessionFilterKey::TargetId).value(&node).build().unwrap())
        .send()
        .await
        .unwrap();
    assert!(filtered.sessions().len() >= 3);
}

#[tokio::test]
async fn access_requests_and_cloud_connectors() {
    let mws =
        Mws::start_with(mws::Config { ec2_backend: mws_ec2::BackendChoice::Metadata, ..Default::default() }).await;
    let cfg = mws.root_sdk_config().await;
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let ssm = Client::new(&cfg);
    profile(&mws, "managed").await;
    let node = launch(&ec2, "al2023-ami-*", Some("managed")).await;

    let started = ssm
        .start_access_request()
        .reason("debug the outage")
        .targets(Target::builder().key("InstanceIds").values(&node).build())
        .send()
        .await
        .unwrap();
    let request = started.access_request_id().unwrap().to_string();
    let token = ssm.get_access_token().access_request_id(&request).send().await.unwrap();
    assert_eq!(token.access_request_status().map(|s| s.as_str()), Some("Pending"));
    assert!(token.credentials().is_none());
    let item = ssm.get_ops_item().ops_item_id(&request).send().await.unwrap();
    let item = item.ops_item().unwrap();
    assert_eq!(item.ops_item_type(), Some("/aws/accessrequest"));
    assert_eq!(item.description(), Some("debug the outage"));

    ssm.update_ops_item().ops_item_id(&request).status(OpsItemStatus::Approved).send().await.unwrap();
    let token = ssm.get_access_token().access_request_id(&request).send().await.unwrap();
    assert_eq!(token.access_request_status().map(|s| s.as_str()), Some("Approved"));
    let c = token.credentials().unwrap();
    let creds = mws.sdk_config(c.access_key_id(), c.secret_access_key(), Some(c.session_token())).await;
    let me = aws_sdk_sts::Client::new(&creds).get_caller_identity().send().await.unwrap();
    assert_eq!(me.account(), Some("123456789012"));
    let e = ssm.get_access_token().access_request_id("oi-000000000000").send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "ResourceNotFoundException");

    // Multicloud connectors: stored, listed, validated (the role cannot
    // be assumed, so validation says so).
    let azure = AzureConfiguration::builder()
        .tenant_id("11111111-2222-3333-4444-555555555555")
        .application_id("66666666-7777-8888-9999-000000000000")
        .build()
        .unwrap();
    let created = ssm
        .create_cloud_connector()
        .display_name("azure-prod")
        .role_arn("arn:aws:iam::123456789012:role/NoSuchRole")
        .config_connector_arn("arn:aws:config:us-east-1:123456789012:connector/cc-1")
        .configuration(CloudConnectorConfiguration::AzureConfiguration(azure))
        .send()
        .await;
    let created = match created {
        Ok(c) => c,
        Err(e) => panic!("{:?}", e.into_service_error()),
    };
    let id = created.cloud_connector_id().unwrap().to_string();
    let got = ssm.get_cloud_connector().cloud_connector_id(&id).send().await.unwrap();
    assert_eq!(got.display_name(), Some("azure-prod"));
    ssm.update_cloud_connector().cloud_connector_id(&id).display_name("azure-main").send().await.unwrap();
    let list = ssm.list_cloud_connectors().send().await.unwrap();
    assert_eq!(list.cloud_connectors().len(), 1);
    assert_eq!(list.cloud_connectors()[0].display_name(), Some("azure-main"));
    let v = ssm.validate_cloud_connector().cloud_connector_id(&id).send().await.unwrap();
    assert_eq!(v.validation_findings()[0].code().map(|c| c.as_str()), Some("AwsRoleAssumptionFailed"));
    ssm.delete_cloud_connector().cloud_connector_id(&id).send().await.unwrap();
    let e = ssm.get_cloud_connector().cloud_connector_id(&id).send().await.unwrap_err();
    assert_eq!(code(e.into_service_error()), "ResourceNotFoundException");
}

#[tokio::test]
async fn shell_sessions_run_in_docker_instances() {
    let docker = std::process::Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .is_ok_and(|o| o.status.success());
    if !docker {
        eprintln!("skipping: no Docker daemon");
        return;
    }
    let mws =
        Mws::start_on_all_interfaces(mws::Config { ec2_backend: mws_ec2::BackendChoice::Docker, ..Default::default() })
            .await;
    let cfg = mws.root_sdk_config().await;
    let ec2 = aws_sdk_ec2::Client::new(&cfg);
    let ssm = Client::new(&cfg);
    profile(&mws, "managed").await;
    let node = launch(&ec2, "mws-alpine-*", Some("managed")).await;

    let started = ssm.start_session().target(&node).send().await.unwrap();
    let mut channel = Channel::open(started.stream_url().unwrap(), started.token_value().unwrap()).await;
    channel.handshake().await;
    channel.input(1, b"echo session-$((6*7)); id -un; exit\n").await;
    let (text, _) = channel.drain().await;
    assert!(text.contains("session-42"), "{text}");
    assert!(text.contains("ssm-user"), "{text}");
    wait_status(&ssm, started.session_id().unwrap(), SessionStatus::Terminated).await;

    // Interactive commands run under a terminal and end the session.
    let doc = r#"{"schemaVersion":"1.0","description":"uname","sessionType":"InteractiveCommands","properties":{"linux":{"commands":"uname -s","runAsElevated":false}}}"#;
    ssm.create_document()
        .name("Uname")
        .document_type(aws_sdk_ssm::types::DocumentType::Session)
        .content(doc)
        .send()
        .await
        .unwrap();
    let started = ssm.start_session().target(&node).document_name("Uname").send().await.unwrap();
    let mut channel = Channel::open(started.stream_url().unwrap(), started.token_value().unwrap()).await;
    let params = channel.handshake().await;
    assert_eq!(params["SessionType"], "InteractiveCommands");
    let (text, _) = channel.drain().await;
    assert!(text.contains("Linux"), "{text}");
}

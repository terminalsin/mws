//! KMS external key stores against an independent XKS proxy: a TLS
//! server speaking the XKS Proxy API v1 that checks each request's SigV4
//! signature (computed with `aws-sigv4`), holds its own AES-256 key and
//! records what KMS asked.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use aws_sdk_kms::error::ProvideErrorMetadata;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{
    ConnectionErrorCodeType, ConnectionStateType, CustomKeyStoreType, OriginType, XksProxyAuthenticationCredentialType,
    XksProxyConnectivityType,
};
use aws_sdk_kms::Client;
use base64::Engine as _;
use mws_e2e::Mws;
use serde_json::{json, Value};

const HOST: &str = "xks.mws.test";
const ACCESS_KEY: &str = "XKSACCESSKEY2EXAMPLE";
const SECRET: &str = "c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3JldA==";
const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

struct Proxy {
    port: u16,
    ca_pem: String,
    requests: Arc<Mutex<Vec<(String, Value)>>>,
    key_disabled: Arc<AtomicBool>,
}

fn code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

/// The SigV4 signature `aws-sigv4` computes for the request.
fn expected_signature(path: &str, headers: &[(String, String)], body: &[u8]) -> Option<String> {
    use aws_sigv4::http_request::{sign, SignableBody, SignableRequest, SigningSettings};
    use aws_sigv4::sign::v4;
    let header = |n: &str| headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(n)).map(|(_, v)| v.clone());
    let amz_date = header("x-amz-date")?;
    let time = chrono::NaiveDateTime::parse_from_str(&amz_date, "%Y%m%dT%H%M%SZ").ok()?.and_utc();
    let identity = aws_credential_types::Credentials::new(ACCESS_KEY, SECRET, None, None, "test").into();
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region("us-east-1")
        .name("kms-xks-proxy")
        .time(SystemTime::from(time))
        .settings(SigningSettings::default())
        .build()
        .ok()?
        .into();
    let signed_names = ["content-type", "host", "x-amz-content-sha256", "x-amz-date"];
    let signed: Vec<(String, String)> =
        signed_names.iter().filter_map(|n| header(n).map(|v| (n.to_string(), v))).collect();
    let url = format!("https://{HOST}{path}");
    let request = SignableRequest::new(
        "POST",
        &url,
        signed.iter().map(|(k, v)| (k.as_str(), v.as_str())),
        SignableBody::Bytes(body),
    )
    .ok()?;
    let (instructions, _) = sign(request, &params).ok()?.into_parts();
    let auth = instructions.headers().find(|(k, _)| k.eq_ignore_ascii_case("authorization"))?.1.to_string();
    Some(auth.rsplit("Signature=").next()?.to_string())
}

fn respond(status: u16, body: Value) -> Vec<u8> {
    let body = body.to_string();
    format!("HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len())
        .into_bytes()
}

fn handle(
    key: &LessSafeKey,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
    requests: &Mutex<Vec<(String, Value)>>,
    disabled: &AtomicBool,
) -> Vec<u8> {
    let auth = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("authorization")).map(|(_, v)| v.as_str());
    let given = auth.and_then(|a| a.rsplit("Signature=").next());
    if auth
        .is_none_or(|a| !a.contains(&format!("Credential={ACCESS_KEY}/")) || !a.contains("/kms-xks-proxy/aws4_request"))
        || given != expected_signature(path, headers, body).as_deref()
    {
        return respond(401, json!({"errorName": "AuthenticationFailedException", "errorMessage": "bad signature"}));
    }
    let req: Value = serde_json::from_slice(body).unwrap_or_default();
    requests.lock().unwrap().push((path.to_string(), req.clone()));
    let rest = path.strip_prefix("/kms/xks/v1").unwrap_or_default();
    if rest == "/health" {
        return respond(
            200,
            json!({"xksProxyFipsCompliant": false, "xksProxyVersion": "1.0.0", "ekmVendor": "e2e",
                   "ekmFleetDetails": [{"id": "hsm-1", "model": "soft", "healthStatus": "ACTIVE"}]}),
        );
    }
    let parts: Vec<&str> = rest.trim_start_matches('/').split('/').collect();
    let ["keys", id, op] = parts[..] else {
        return respond(404, json!({"errorName": "UnsupportedOperationException", "errorMessage": path}));
    };
    let usage = match id {
        "good" => json!(["ENCRYPT", "DECRYPT"]),
        "sign-only" => json!(["SIGN", "VERIFY"]),
        _ => return respond(404, json!({"errorName": "KeyNotFoundException", "errorMessage": id})),
    };
    if op != "metadata" && disabled.load(Ordering::SeqCst) {
        return respond(400, json!({"errorName": "InvalidStateException", "errorMessage": "the key is disabled"}));
    }
    let field = |k: &str| B64.decode(req[k].as_str().unwrap_or_default()).unwrap_or_default();
    match op {
        "metadata" => respond(200, json!({"keySpec": "AES_256", "keyUsage": usage, "keyStatus": "ENABLED"})),
        "encrypt" => {
            let mut iv = [0u8; 12];
            aws_lc_rs::rand::fill(&mut iv).unwrap();
            let mut data = field("plaintext");
            let aad = field("additionalAuthenticatedData");
            let tag = key
                .seal_in_place_separate_tag(Nonce::assume_unique_for_key(iv), Aad::from(aad.as_slice()), &mut data)
                .unwrap();
            respond(
                200,
                json!({"ciphertext": B64.encode(&data), "initializationVector": B64.encode(iv),
                       "authenticationTag": B64.encode(tag.as_ref())}),
            )
        }
        "decrypt" => {
            let iv: [u8; 12] = field("initializationVector").try_into().unwrap_or([0; 12]);
            let mut data = [field("ciphertext"), field("authenticationTag")].concat();
            let aad = field("additionalAuthenticatedData");
            match key.open_in_place(Nonce::assume_unique_for_key(iv), Aad::from(aad.as_slice()), &mut data) {
                Ok(plain) => respond(200, json!({"plaintext": B64.encode(&*plain)})),
                Err(_) => respond(400, json!({"errorName": "InvalidCiphertextException", "errorMessage": "no"})),
            }
        }
        _ => respond(404, json!({"errorName": "UnsupportedOperationException", "errorMessage": op})),
    }
}

fn start_proxy() -> Proxy {
    let cert_key = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec![HOST.to_string()]).unwrap();
    let cert = params.self_signed(&cert_key).unwrap();
    let ca_pem = cert.pem();
    let config = Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                rustls_pki_types::PrivateKeyDer::Pkcs8(cert_key.serialize_der().into()),
            )
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let requests = Arc::new(Mutex::new(Vec::new()));
    let key_disabled = Arc::new(AtomicBool::new(false));
    let (reqs, disabled) = (requests.clone(), key_disabled.clone());
    std::thread::spawn(move || {
        let mut secret = [0u8; 32];
        aws_lc_rs::rand::fill(&mut secret).unwrap();
        let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &secret).unwrap());
        for stream in listener.incoming() {
            let Ok(tcp) = stream else { continue };
            let _ = tcp.set_read_timeout(Some(Duration::from_secs(5)));
            let conn = rustls::ServerConnection::new(config.clone()).unwrap();
            let mut tls = rustls::StreamOwned::new(conn, tcp);
            let mut raw = Vec::new();
            let mut buf = [0u8; 8192];
            let (head_end, length) = loop {
                match tls.read(&mut buf) {
                    Ok(0) | Err(_) => break (None, 0),
                    Ok(n) => raw.extend_from_slice(&buf[..n]),
                }
                if let Some(i) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&raw[..i]).to_string();
                    let len = head
                        .lines()
                        .find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case("content-length")))
                        .and_then(|(_, v)| v.trim().parse().ok())
                        .unwrap_or(0);
                    if raw.len() >= i + 4 + len {
                        break (Some(i), len);
                    }
                }
            };
            let Some(i) = head_end else { continue };
            let head = String::from_utf8_lossy(&raw[..i]).to_string();
            let mut lines = head.lines();
            let path = lines.next().unwrap_or_default().split_whitespace().nth(1).unwrap_or_default().to_string();
            let headers: Vec<(String, String)> = lines
                .filter_map(|l| l.split_once(':'))
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                .collect();
            let body = raw[i + 4..i + 4 + length].to_vec();
            let out = handle(&key, &path, &headers, &body, &reqs, &disabled);
            let _ = tls.write_all(&out);
            let _ = tls.flush();
            tls.conn.send_close_notify();
            let _ = tls.flush();
        }
    });
    Proxy { port, ca_pem, requests, key_disabled }
}

async fn wait_connection(c: &Client, id: &str) -> (ConnectionStateType, Option<ConnectionErrorCodeType>) {
    for _ in 0..100 {
        let d = c.describe_custom_key_stores().custom_key_store_id(id).send().await.unwrap();
        let s = &d.custom_key_stores()[0];
        if s.connection_state() != Some(&ConnectionStateType::Connecting) {
            return (s.connection_state().unwrap().clone(), s.connection_error_code().cloned());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the store never stopped connecting");
}

#[tokio::test]
async fn external_key_stores_double_encrypt_through_the_proxy() {
    let proxy = start_proxy();
    let config = mws::Config {
        kms_xks: mws_kms::XksTransport {
            connect_to: [(HOST.to_string(), format!("127.0.0.1:{}", proxy.port))].into(),
            ca_pem: Some(proxy.ca_pem.clone()),
        },
        ..Default::default()
    };
    let mws = Mws::start_with(config).await;
    let c = Client::new(&mws.root_sdk_config().await);

    // A wrong secret: the proxy rejects the signature.
    let wrong = XksProxyAuthenticationCredentialType::builder()
        .access_key_id(ACCESS_KEY)
        .raw_secret_access_key("d3Jvbmctd3Jvbmctd3Jvbmctd3Jvbmctd3Jvbmctd3Jvbmc=")
        .build()
        .unwrap();
    let store = c
        .create_custom_key_store()
        .custom_key_store_name("xks")
        .custom_key_store_type(CustomKeyStoreType::ExternalKeyStore)
        .xks_proxy_uri_endpoint(format!("https://{HOST}"))
        .xks_proxy_uri_path("/kms/xks/v1")
        .xks_proxy_connectivity(XksProxyConnectivityType::PublicEndpoint)
        .xks_proxy_authentication_credential(wrong)
        .send()
        .await
        .unwrap();
    let store = store.custom_key_store_id().unwrap().to_string();
    c.connect_custom_key_store().custom_key_store_id(&store).send().await.unwrap();
    let (state, error) = wait_connection(&c, &store).await;
    assert_eq!(state, ConnectionStateType::Failed);
    assert_eq!(error, Some(ConnectionErrorCodeType::InvalidCredentials));

    c.disconnect_custom_key_store().custom_key_store_id(&store).send().await.unwrap();
    let right = XksProxyAuthenticationCredentialType::builder()
        .access_key_id(ACCESS_KEY)
        .raw_secret_access_key(SECRET)
        .build()
        .unwrap();
    c.update_custom_key_store()
        .custom_key_store_id(&store)
        .xks_proxy_authentication_credential(right)
        .send()
        .await
        .unwrap();
    c.connect_custom_key_store().custom_key_store_id(&store).send().await.unwrap();
    assert_eq!(wait_connection(&c, &store).await, (ConnectionStateType::Connected, None));

    let create = |xks: &'static str| {
        c.create_key().origin(OriginType::ExternalKeyStore).custom_key_store_id(&store).xks_key_id(xks).send()
    };
    assert_eq!(code(&create("missing").await.unwrap_err()), "XksKeyNotFoundException");
    assert_eq!(code(&create("sign-only").await.unwrap_err()), "XksKeyInvalidConfigurationException");
    let key = create("good").await.unwrap();
    let md = key.key_metadata().unwrap();
    assert_eq!(md.origin(), Some(&OriginType::ExternalKeyStore));
    assert_eq!(md.xks_key_configuration().and_then(|x| x.id()), Some("good"));
    let key_arn = md.arn().unwrap().to_string();
    assert_eq!(code(&create("good").await.unwrap_err()), "XksKeyAlreadyInUseException");

    // Double encryption: the proxy takes part in every encrypt and decrypt.
    let before = proxy.requests.lock().unwrap().len();
    let out = c
        .encrypt()
        .key_id(&key_arn)
        .plaintext(Blob::new("top secret"))
        .encryption_context("app", "e2e")
        .send()
        .await
        .unwrap();
    let blob = out.ciphertext_blob().unwrap().clone();
    let plain = c.decrypt().ciphertext_blob(blob.clone()).encryption_context("app", "e2e").send().await.unwrap();
    assert_eq!(plain.plaintext().unwrap().as_ref(), b"top secret");
    assert_eq!(plain.key_id(), Some(key_arn.as_str()));
    let e = c.decrypt().ciphertext_blob(blob.clone()).send().await.unwrap_err();
    assert_eq!(code(&e), "InvalidCiphertextException");
    {
        let seen = proxy.requests.lock().unwrap();
        let ops: Vec<(&str, &str)> = seen[before..]
            .iter()
            .map(|(p, r)| (p.rsplit('/').next().unwrap(), r["requestMetadata"]["kmsOperation"].as_str().unwrap()))
            .collect();
        assert_eq!(&ops[..2], &[("encrypt", "Encrypt"), ("decrypt", "Decrypt")]);
        let md = &seen[before].1["requestMetadata"];
        assert_eq!(md["kmsKeyArn"], key_arn.as_str());
        assert!(md["awsPrincipalArn"].as_str().unwrap().ends_with(":root"));
    }

    let dk = c.generate_data_key().key_id(&key_arn).number_of_bytes(32).send().await.unwrap();
    let again = c.decrypt().ciphertext_blob(dk.ciphertext_blob().unwrap().clone()).send().await.unwrap();
    assert_eq!(again.plaintext(), dk.plaintext());

    // The external key is unusable: KMS can't decrypt.
    proxy.key_disabled.store(true, Ordering::SeqCst);
    let e = c.decrypt().ciphertext_blob(blob.clone()).encryption_context("app", "e2e").send().await.unwrap_err();
    assert_eq!(code(&e), "KMSInvalidStateException");
    proxy.key_disabled.store(false, Ordering::SeqCst);

    // A disconnected store makes its keys unusable.
    c.disconnect_custom_key_store().custom_key_store_id(&store).send().await.unwrap();
    let e = c.encrypt().key_id(&key_arn).plaintext(Blob::new("x")).send().await.unwrap_err();
    assert_eq!(code(&e), "KMSInvalidStateException");
}

#[tokio::test]
async fn key_policies_name_existing_principals_and_services_use_grants() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let c = Client::new(&cfg);
    let iam = aws_sdk_iam::Client::new(&cfg);
    iam.create_user().user_name("alice").send().await.unwrap();
    let policy = |principal: &str| {
        format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::123456789012:root"}},"Action":"kms:*","Resource":"*"}},{{"Effect":"Allow","Principal":{{"AWS":["{principal}"]}},"Action":"kms:Decrypt","Resource":"*"}}]}}"#
        )
    };
    let e = c.create_key().policy(policy("arn:aws:iam::123456789012:user/nobody")).send().await.unwrap_err();
    let e = e.into_service_error();
    assert_eq!(e.code(), Some("MalformedPolicyDocumentException"));
    assert_eq!(e.message(), Some("Policy contains a statement with one or more invalid principals."));
    let key = c.create_key().policy(policy("arn:aws:iam::123456789012:user/alice")).send().await.unwrap();
    let id = key.key_metadata().unwrap().key_id().to_string();
    let e =
        c.put_key_policy().key_id(&id).policy(policy("arn:aws:iam::123456789012:role/ghost")).send().await.unwrap_err();
    assert_eq!(code(&e), "MalformedPolicyDocumentException");

    // ListAliases shows the predefined AWS managed aliases, keyless
    // until a service uses them.
    let aliases = c.list_aliases().limit(100).send().await.unwrap();
    let ebs = aliases.aliases().iter().find(|a| a.alias_name() == Some("alias/aws/ebs")).unwrap();
    assert!(ebs.target_key_id().is_none());
    assert!(ebs.alias_arn().unwrap().ends_with(":alias/aws/ebs"));

    // A service principal the key policy doesn't name may still use the
    // key through a grant to it (CloudWatch Logs encrypting a log group).
    let logs = aws_sdk_cloudwatchlogs::Client::new(&cfg);
    let key = c.create_key().send().await.unwrap();
    let key_arn = key.key_metadata().unwrap().arn().unwrap().to_string();
    let e = logs.create_log_group().log_group_name("granted").kms_key_id(&key_arn).send().await.unwrap_err();
    assert!(e.into_service_error().meta().code().is_some());
    c.create_grant()
        .key_id(&key_arn)
        .grantee_service_principal("logs.us-east-1.amazonaws.com")
        .operations(aws_sdk_kms::types::GrantOperation::Encrypt)
        .operations(aws_sdk_kms::types::GrantOperation::Decrypt)
        .operations(aws_sdk_kms::types::GrantOperation::GenerateDataKey)
        .send()
        .await
        .unwrap();
    logs.create_log_group().log_group_name("granted").kms_key_id(&key_arn).send().await.unwrap();
}

//! Amazon Data Firehose through the official Rust SDK: delivery streams
//! really deliver, to S3 (as the delivery role), HTTP endpoints, through
//! Lambda processors, and from Kinesis data streams.

use std::io::Read;
use std::time::Duration;

use aws_sdk_firehose::error::ProvideErrorMetadata;
use aws_sdk_firehose::primitives::Blob;
use aws_sdk_firehose::types::{
    BufferingHints, CompressionFormat, ContentEncoding, DeliveryStreamEncryptionConfigurationInput,
    DeliveryStreamEncryptionStatus, DeliveryStreamStatus, DeliveryStreamType, DynamicPartitioningConfiguration,
    ExtendedS3DestinationConfiguration, ExtendedS3DestinationUpdate, HttpEndpointBufferingHints,
    HttpEndpointConfiguration, HttpEndpointDestinationConfiguration, HttpEndpointRequestConfiguration,
    HttpEndpointS3BackupMode, KeyType, KinesisStreamSourceConfiguration, ProcessingConfiguration, Processor,
    ProcessorParameter, ProcessorParameterName, ProcessorType, Record, S3DestinationConfiguration, Tag,
};
use aws_sdk_firehose::Client;
use mws_e2e::Mws;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ACCOUNT: &str = "123456789012";

const TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"firehose.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

fn code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

fn stream_arn(name: &str) -> String {
    format!("arn:aws:firehose:us-east-1:{ACCOUNT}:deliverystream/{name}")
}

/// A delivery role allowed `actions`, and a bucket to deliver to.
async fn role_and_bucket(mws: &Mws, role: &str, bucket: &str, actions: &str) -> String {
    let cfg = mws.root_sdk_config().await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let created = iam.create_role().role_name(role).assume_role_policy_document(TRUST).send().await.unwrap();
    let policy =
        format!(r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":{actions},"Resource":"*"}}]}}"#);
    iam.put_role_policy().role_name(role).policy_name("delivery").policy_document(policy).send().await.unwrap();
    Mws::s3(&cfg).create_bucket().bucket(bucket).send().await.unwrap();
    created.role().unwrap().arn().to_string()
}

async fn wait_status(f: &Client, name: &str, status: DeliveryStreamStatus) {
    for _ in 0..100 {
        let d = f.describe_delivery_stream().delivery_stream_name(name).send().await.unwrap();
        if d.delivery_stream_description().unwrap().delivery_stream_status() == &status {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("delivery stream {name} never became {status:?}");
}

fn hints() -> BufferingHints {
    BufferingHints::builder().interval_in_seconds(0).size_in_mbs(1).build()
}

fn s3_config(role: &str, bucket: &str) -> ExtendedS3DestinationConfiguration {
    ExtendedS3DestinationConfiguration::builder()
        .role_arn(role)
        .bucket_arn(format!("arn:aws:s3:::{bucket}"))
        .buffering_hints(hints())
        .build()
        .unwrap()
}

/// Wait until the bucket holds `n` objects under `prefix`; returns their
/// keys and contents.
async fn objects(mws: &Mws, f: &Client, bucket: &str, prefix: &str, n: usize) -> Vec<(String, Vec<u8>)> {
    let s3 = Mws::s3(&mws.root_sdk_config().await);
    for _ in 0..100 {
        // Any Firehose request carries the emulated clock to deliveries.
        let _ = f.list_delivery_streams().send().await;
        let listed = s3.list_objects_v2().bucket(bucket).prefix(prefix).send().await.unwrap();
        if listed.contents().len() >= n {
            let mut out = Vec::new();
            for o in listed.contents() {
                let key = o.key().unwrap().to_string();
                let body = s3.get_object().bucket(bucket).key(&key).send().await.unwrap();
                out.push((key, body.body.collect().await.unwrap().into_bytes().to_vec()));
            }
            return out;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{bucket}/{prefix} never got {n} objects");
}

fn gunzip(data: &[u8]) -> String {
    let mut out = String::new();
    flate2::read::GzDecoder::new(data).read_to_string(&mut out).unwrap();
    out
}

#[tokio::test]
async fn control_plane() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let f = Client::new(&cfg);
    let role = role_and_bucket(&mws, "delivery", "landing", r#"["s3:*","kms:*"]"#).await;

    let created = f
        .create_delivery_stream()
        .delivery_stream_name("events")
        .delivery_stream_type(DeliveryStreamType::DirectPut)
        .extended_s3_destination_configuration(s3_config(&role, "landing"))
        .tags(Tag::builder().key("team").value("data").build().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(created.delivery_stream_arn(), Some(stream_arn("events").as_str()));
    let dup = f
        .create_delivery_stream()
        .delivery_stream_name("events")
        .extended_s3_destination_configuration(s3_config(&role, "landing"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&dup.into_service_error()), "ResourceInUseException");
    // Records can only go in once the stream is ACTIVE.
    let early = f
        .put_record()
        .delivery_stream_name("events")
        .record(Record::builder().data(Blob::new("x")).build().unwrap())
        .send()
        .await;
    assert_eq!(code(&early.unwrap_err().into_service_error()), "ResourceNotFoundException");
    wait_status(&f, "events", DeliveryStreamStatus::Active).await;

    let d = f.describe_delivery_stream().delivery_stream_name("events").send().await.unwrap();
    let desc = d.delivery_stream_description().unwrap();
    assert_eq!(desc.delivery_stream_type(), &DeliveryStreamType::DirectPut);
    assert_eq!(desc.version_id(), "1");
    assert_eq!(desc.destinations().len(), 1);
    let dest = &desc.destinations()[0];
    assert_eq!(dest.destination_id(), "destinationId-000000000001");
    let s3 = dest.extended_s3_destination_description().unwrap();
    assert_eq!(s3.bucket_arn(), "arn:aws:s3:::landing");
    assert_eq!(s3.compression_format(), &CompressionFormat::Uncompressed);
    assert_eq!(s3.buffering_hints().unwrap().interval_in_seconds(), Some(0));
    assert_eq!(
        desc.delivery_stream_encryption_configuration().unwrap().status(),
        Some(&DeliveryStreamEncryptionStatus::Disabled)
    );

    let missing = f.describe_delivery_stream().delivery_stream_name("nope").send().await.unwrap_err();
    let missing = missing.into_service_error();
    assert_eq!(code(&missing), "ResourceNotFoundException");
    assert_eq!(missing.message(), Some(format!("Firehose nope under account {ACCOUNT} not found.").as_str()));

    let listed = f.list_delivery_streams().send().await.unwrap();
    assert_eq!(listed.delivery_stream_names(), ["events"]);
    assert!(!listed.has_more_delivery_streams());
    let typed = f.list_delivery_streams().delivery_stream_type(DeliveryStreamType::KinesisStreamAsSource).send().await;
    assert!(typed.unwrap().delivery_stream_names().is_empty());

    // Tags.
    f.tag_delivery_stream()
        .delivery_stream_name("events")
        .tags(Tag::builder().key("env").value("test").build().unwrap())
        .send()
        .await
        .unwrap();
    let tags = f.list_tags_for_delivery_stream().delivery_stream_name("events").send().await.unwrap();
    let keys: Vec<_> = tags.tags().iter().map(|t| t.key()).collect();
    assert_eq!(keys, ["env", "team"]);
    f.untag_delivery_stream().delivery_stream_name("events").tag_keys("env").send().await.unwrap();
    let tags = f.list_tags_for_delivery_stream().delivery_stream_name("events").limit(1).send().await.unwrap();
    assert_eq!(tags.tags().len(), 1);
    assert!(!tags.has_more_tags());

    // Server-side encryption with an AWS owned key.
    f.start_delivery_stream_encryption()
        .delivery_stream_name("events")
        .delivery_stream_encryption_configuration_input(
            DeliveryStreamEncryptionConfigurationInput::builder().key_type(KeyType::AwsOwnedCmk).build().unwrap(),
        )
        .send()
        .await
        .unwrap();
    for _ in 0..50 {
        let d = f.describe_delivery_stream().delivery_stream_name("events").send().await.unwrap();
        let e = d.delivery_stream_description().unwrap().delivery_stream_encryption_configuration().unwrap().clone();
        if e.status() == Some(&DeliveryStreamEncryptionStatus::Enabled) {
            assert_eq!(e.key_type(), Some(&KeyType::AwsOwnedCmk));
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let put = f
        .put_record()
        .delivery_stream_name("events")
        .record(Record::builder().data(Blob::new("x")).build().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(put.encrypted(), Some(true));
    assert!(!put.record_id().is_empty());
    f.stop_delivery_stream_encryption().delivery_stream_name("events").send().await.unwrap();

    // UpdateDestination needs the current version id.
    let stale = f
        .update_destination()
        .delivery_stream_name("events")
        .current_delivery_stream_version_id("7")
        .destination_id("destinationId-000000000001")
        .extended_s3_destination_update(ExtendedS3DestinationUpdate::builder().prefix("p/").build())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&stale.into_service_error()), "ConcurrentModificationException");
    f.update_destination()
        .delivery_stream_name("events")
        .current_delivery_stream_version_id("1")
        .destination_id("destinationId-000000000001")
        .extended_s3_destination_update(
            ExtendedS3DestinationUpdate::builder().prefix("p/").compression_format(CompressionFormat::Gzip).build(),
        )
        .send()
        .await
        .unwrap();
    let d = f.describe_delivery_stream().delivery_stream_name("events").send().await.unwrap();
    let desc = d.delivery_stream_description().unwrap();
    assert_eq!(desc.version_id(), "2");
    let s3 = desc.destinations()[0].extended_s3_destination_description().unwrap();
    assert_eq!(s3.prefix(), Some("p/"));
    assert_eq!(s3.compression_format(), &CompressionFormat::Gzip);
    assert_eq!(s3.bucket_arn(), "arn:aws:s3:::landing");

    // IAM applies: a user without firehose permissions is denied.
    let (_, user) = mws_e2e::user_with_policy(&mws, "nobody", None).await;
    let denied = Client::new(&user).describe_delivery_stream().delivery_stream_name("events").send().await;
    assert_eq!(code(&denied.unwrap_err().into_service_error()), "AccessDeniedException");

    f.delete_delivery_stream().delivery_stream_name("events").send().await.unwrap();
    for _ in 0..50 {
        if f.list_delivery_streams().send().await.unwrap().delivery_stream_names().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(f.list_delivery_streams().send().await.unwrap().delivery_stream_names().is_empty());
}

#[tokio::test]
async fn delivers_to_s3_with_partitioning() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let f = Client::new(&cfg);
    let role = role_and_bucket(&mws, "delivery", "landing", r#"["s3:PutObject"]"#).await;

    // GZIP-compressed objects under the default YYYY/MM/DD/HH/ prefix.
    let config = ExtendedS3DestinationConfiguration::builder()
        .role_arn(&role)
        .bucket_arn("arn:aws:s3:::landing")
        .prefix("plain/")
        .compression_format(CompressionFormat::Gzip)
        .buffering_hints(hints())
        .build()
        .unwrap();
    f.create_delivery_stream()
        .delivery_stream_name("plain")
        .extended_s3_destination_configuration(config)
        .send()
        .await
        .unwrap();
    wait_status(&f, "plain", DeliveryStreamStatus::Active).await;
    f.put_record()
        .delivery_stream_name("plain")
        .record(Record::builder().data(Blob::new("one\n")).build().unwrap())
        .send()
        .await
        .unwrap();
    let batch = f
        .put_record_batch()
        .delivery_stream_name("plain")
        .records(Record::builder().data(Blob::new("two\n")).build().unwrap())
        .records(Record::builder().data(Blob::new("three\n")).build().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(batch.failed_put_count(), 0);
    assert_eq!(batch.request_responses().len(), 2);
    let got = objects(&mws, &f, "landing", "plain/", 1).await;
    let (key, body) = &got[0];
    let hour = chrono::Utc::now().format("%Y/%m/%d/").to_string();
    assert!(key.starts_with(&format!("plain/{hour}")), "{key}");
    assert!(key.contains("/plain-1-") && key.ends_with(".gz"), "{key}");
    assert_eq!(gunzip(body), "one\ntwo\nthree\n");

    // Dynamic partitioning by a JQ query, with a newline delimiter added.
    let partitioned = ExtendedS3DestinationConfiguration::builder()
        .role_arn(&role)
        .bucket_arn("arn:aws:s3:::landing")
        .prefix("customer=!{partitionKeyFromQuery:customer}/")
        .error_output_prefix("errors/!{firehose:error-output-type}/")
        .buffering_hints(BufferingHints::builder().interval_in_seconds(0).size_in_mbs(64).build())
        .dynamic_partitioning_configuration(DynamicPartitioningConfiguration::builder().enabled(true).build())
        .processing_configuration(
            ProcessingConfiguration::builder()
                .enabled(true)
                .processors(
                    Processor::builder()
                        .r#type(ProcessorType::MetadataExtraction)
                        .parameters(
                            ProcessorParameter::builder()
                                .parameter_name(ProcessorParameterName::MetadataExtractionQuery)
                                .parameter_value("{customer: .customer}")
                                .build()
                                .unwrap(),
                        )
                        .parameters(
                            ProcessorParameter::builder()
                                .parameter_name(ProcessorParameterName::JsonParsingEngine)
                                .parameter_value("JQ-1.6")
                                .build()
                                .unwrap(),
                        )
                        .build()
                        .unwrap(),
                )
                .processors(Processor::builder().r#type(ProcessorType::AppendDelimiterToRecord).build().unwrap())
                .build(),
        )
        .build()
        .unwrap();
    f.create_delivery_stream()
        .delivery_stream_name("dynamic")
        .extended_s3_destination_configuration(partitioned)
        .send()
        .await
        .unwrap();
    wait_status(&f, "dynamic", DeliveryStreamStatus::Active).await;
    let mut b = f.put_record_batch().delivery_stream_name("dynamic");
    for doc in [r#"{"customer":"a","n":1}"#, r#"{"customer":"b","n":2}"#, r#"{"customer":"a","n":3}"#, "not json"] {
        b = b.records(Record::builder().data(Blob::new(doc)).build().unwrap());
    }
    b.send().await.unwrap();
    let a = objects(&mws, &f, "landing", "customer=a/", 1).await;
    assert_eq!(String::from_utf8_lossy(&a[0].1), "{\"customer\":\"a\",\"n\":1}\n{\"customer\":\"a\",\"n\":3}\n");
    let b = objects(&mws, &f, "landing", "customer=b/", 1).await;
    assert_eq!(String::from_utf8_lossy(&b[0].1), "{\"customer\":\"b\",\"n\":2}\n");
    // The record without the key goes to the error output.
    let errors = objects(&mws, &f, "landing", "errors/", 1).await;
    assert!(errors[0].0.starts_with("errors/partitioning-failed/"), "{}", errors[0].0);
    let line: serde_json::Value = serde_json::from_slice(errors[0].1.split(|b| *b == b'\n').next().unwrap()).unwrap();
    assert_eq!(line["rawData"], base64_encode(b"not json"));
    assert!(line["errorCode"].as_str().unwrap().starts_with("DynamicPartitioning."), "{line}");
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

#[tokio::test]
async fn delivery_role_without_access_writes_nothing() {
    let mws = Mws::start().await;
    let f = Client::new(&mws.root_sdk_config().await);
    // The role may not write to the bucket: records stay buffered.
    let role = role_and_bucket(&mws, "readonly", "landing", r#"["s3:GetObject"]"#).await;
    f.create_delivery_stream()
        .delivery_stream_name("blocked")
        .extended_s3_destination_configuration(s3_config(&role, "landing"))
        .send()
        .await
        .unwrap();
    wait_status(&f, "blocked", DeliveryStreamStatus::Active).await;
    f.put_record()
        .delivery_stream_name("blocked")
        .record(Record::builder().data(Blob::new("x")).build().unwrap())
        .send()
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(2500)).await;
    let s3 = Mws::s3(&mws.root_sdk_config().await);
    let listed = s3.list_objects_v2().bucket("landing").send().await.unwrap();
    assert!(listed.contents().is_empty());
}

/// An HTTPS listener with a self-signed `localhost` certificate that MWS
/// trusts (through `SSL_CERT_FILE`): Firehose only delivers over HTTPS.
async fn https_listener() -> (tokio::net::TcpListener, tokio_rustls::TlsAcceptor) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let dir = std::env::temp_dir().join(format!("mws-firehose-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let pem = dir.join("ca.pem");
    std::fs::write(&pem, cert.cert.pem()).unwrap();
    std::env::set_var("SSL_CERT_FILE", &pem);
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls_pki_types::CertificateDer::from(cert.cert.der().to_vec())],
            rustls_pki_types::PrivateKeyDer::Pkcs8(cert.key_pair.serialize_der().into()),
        )
        .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    (listener, tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(tls)))
}

/// Accept one HTTPS request; answer 200 and hand back (head, body).
async fn one_request(listener: tokio::net::TcpListener, acceptor: tokio_rustls::TlsAcceptor) -> (String, Vec<u8>) {
    let (tcp, _) = listener.accept().await.unwrap();
    let mut sock = acceptor.accept(tcp).await.unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = sock.read(&mut chunk).await.unwrap();
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_string();
            let len: usize = head
                .lines()
                .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap()))
                .unwrap_or(0);
            while buf.len() < end + 4 + len {
                let n = sock.read(&mut chunk).await.unwrap();
                buf.extend_from_slice(&chunk[..n]);
            }
            let body = buf[end + 4..end + 4 + len].to_vec();
            let reply = r#"{"requestId":"x","timestamp":1}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
                reply.len()
            );
            sock.write_all(response.as_bytes()).await.unwrap();
            let _ = sock.shutdown().await;
            return (head, body);
        }
    }
}

#[tokio::test]
async fn delivers_to_http_endpoints() {
    let mws = Mws::start().await;
    let f = Client::new(&mws.root_sdk_config().await);
    let role = role_and_bucket(&mws, "delivery", "backup", r#"["s3:PutObject"]"#).await;
    let (listener, acceptor) = https_listener().await;
    let url = format!("https://localhost:{}/ingest", listener.local_addr().unwrap().port());
    let server = tokio::spawn(one_request(listener, acceptor));

    let config = HttpEndpointDestinationConfiguration::builder()
        .endpoint_configuration(
            HttpEndpointConfiguration::builder().url(&url).name("sink").access_key("secret-key").build().unwrap(),
        )
        .buffering_hints(HttpEndpointBufferingHints::builder().interval_in_seconds(0).size_in_mbs(1).build())
        .request_configuration(
            HttpEndpointRequestConfiguration::builder()
                .content_encoding(ContentEncoding::None)
                .common_attributes(
                    aws_sdk_firehose::types::HttpEndpointCommonAttribute::builder()
                        .attribute_name("env")
                        .attribute_value("test")
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .role_arn(&role)
        .s3_backup_mode(HttpEndpointS3BackupMode::FailedDataOnly)
        .s3_configuration(
            S3DestinationConfiguration::builder().role_arn(&role).bucket_arn("arn:aws:s3:::backup").build().unwrap(),
        )
        .build();
    f.create_delivery_stream()
        .delivery_stream_name("http")
        .http_endpoint_destination_configuration(config)
        .send()
        .await
        .unwrap();
    wait_status(&f, "http", DeliveryStreamStatus::Active).await;
    let d = f.describe_delivery_stream().delivery_stream_name("http").send().await.unwrap();
    let h = d.delivery_stream_description().unwrap().destinations()[0]
        .http_endpoint_destination_description()
        .unwrap()
        .clone();
    // The access key is never described.
    assert_eq!(h.endpoint_configuration().unwrap().url(), Some(url.as_str()));
    assert_eq!(h.endpoint_configuration().unwrap().name(), Some("sink"));

    f.put_record_batch()
        .delivery_stream_name("http")
        .records(Record::builder().data(Blob::new("hello")).build().unwrap())
        .records(Record::builder().data(Blob::new("world")).build().unwrap())
        .send()
        .await
        .unwrap();
    let (head, body) = loop {
        let _ = f.list_delivery_streams().send().await;
        if server.is_finished() {
            break server.await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let lower = head.to_ascii_lowercase();
    assert!(lower.starts_with("post /ingest http/1.1"), "{head}");
    assert!(lower.contains("x-amz-firehose-access-key: secret-key"), "{head}");
    assert!(lower.contains("x-amz-firehose-protocol-version: 1.0"), "{head}");
    assert!(lower.contains("x-amz-firehose-common-attributes: {\"commonattributes\":{\"env\":\"test\"}}"), "{head}");
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        body["records"],
        serde_json::json!([{"data": base64_encode(b"hello")}, {"data": base64_encode(b"world")}])
    );
    assert!(body["requestId"].is_string());
}

const TRANSFORM: &str = r#"
import base64, json

def handler(event, context):
    out = []
    for r in event["records"]:
        text = base64.b64decode(r["data"]).decode()
        if text == "drop":
            out.append({"recordId": r["recordId"], "result": "Dropped", "data": r["data"]})
        elif text == "bad":
            out.append({"recordId": r["recordId"], "result": "ProcessingFailed", "data": r["data"]})
        else:
            data = base64.b64encode((text.upper() + "\n").encode()).decode()
            out.append({"recordId": r["recordId"], "result": "Ok", "data": data})
    return {"records": out}
"#;

#[tokio::test]
async fn lambda_processors_transform_records() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let f = Client::new(&cfg);
    let role = role_and_bucket(&mws, "delivery", "landing", r#"["s3:PutObject","lambda:InvokeFunction"]"#).await;
    let iam = aws_sdk_iam::Client::new(&cfg);
    let lambda_trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
    let fn_role = iam.create_role().role_name("fn").assume_role_policy_document(lambda_trust).send().await.unwrap();
    let lambda = aws_sdk_lambda::Client::new(&cfg);
    let function = lambda
        .create_function()
        .function_name("transform")
        .runtime(aws_sdk_lambda::types::Runtime::Python312)
        .role(fn_role.role().unwrap().arn())
        .handler("app.handler")
        .code(
            aws_sdk_lambda::types::FunctionCode::builder()
                .zip_file(aws_sdk_lambda::primitives::Blob::new(zip(&[("app.py", TRANSFORM)])))
                .build(),
        )
        .send()
        .await
        .unwrap();
    let config = ExtendedS3DestinationConfiguration::builder()
        .role_arn(&role)
        .bucket_arn("arn:aws:s3:::landing")
        .prefix("out/")
        .buffering_hints(hints())
        .processing_configuration(
            ProcessingConfiguration::builder()
                .enabled(true)
                .processors(
                    Processor::builder()
                        .r#type(ProcessorType::Lambda)
                        .parameters(
                            ProcessorParameter::builder()
                                .parameter_name(ProcessorParameterName::LambdaArn)
                                .parameter_value(function.function_arn().unwrap())
                                .build()
                                .unwrap(),
                        )
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .build()
        .unwrap();
    f.create_delivery_stream()
        .delivery_stream_name("t")
        .extended_s3_destination_configuration(config)
        .send()
        .await
        .unwrap();
    wait_status(&f, "t", DeliveryStreamStatus::Active).await;
    let mut b = f.put_record_batch().delivery_stream_name("t");
    for doc in ["hello", "drop", "bad", "world"] {
        b = b.records(Record::builder().data(Blob::new(doc)).build().unwrap());
    }
    b.send().await.unwrap();
    let out = objects(&mws, &f, "landing", "out/", 1).await;
    assert_eq!(String::from_utf8_lossy(&out[0].1), "HELLO\nWORLD\n");
    let failed = objects(&mws, &f, "landing", "processing-failed/", 1).await;
    let line: serde_json::Value = serde_json::from_slice(failed[0].1.split(|b| *b == b'\n').next().unwrap()).unwrap();
    assert_eq!(line["rawData"], base64_encode(b"bad"));
    assert_eq!(line["errorCode"], "Lambda.ProcessingFailedStatus");
    assert_eq!(line["lambdaArn"], function.function_arn().unwrap());
}

fn zip(files: &[(&str, &str)]) -> Vec<u8> {
    use std::io::Write;
    let mut buf = std::io::Cursor::new(Vec::new());
    {
        let mut z = zip::ZipWriter::new(&mut buf);
        for (name, body) in files {
            z.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
            z.write_all(body.as_bytes()).unwrap();
        }
        z.finish().unwrap();
    }
    buf.into_inner()
}

#[tokio::test]
async fn reads_kinesis_streams() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let f = Client::new(&cfg);
    let k = aws_sdk_kinesis::Client::new(&cfg);
    let role = role_and_bucket(&mws, "delivery", "landing", r#"["s3:PutObject","kinesis:*"]"#).await;
    k.create_stream().stream_name("clicks").shard_count(2).send().await.unwrap();
    for _ in 0..50 {
        let s = k.describe_stream_summary().stream_name("clicks").send().await.unwrap();
        if s.stream_description_summary().unwrap().stream_status() == &aws_sdk_kinesis::types::StreamStatus::Active {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let kinesis_arn = format!("arn:aws:kinesis:us-east-1:{ACCOUNT}:stream/clicks");

    // A role that cannot read the stream is refused at creation.
    let blocked = role_and_bucket(&mws, "no-kinesis", "other", r#"["s3:PutObject"]"#).await;
    let refused = f
        .create_delivery_stream()
        .delivery_stream_name("refused")
        .delivery_stream_type(DeliveryStreamType::KinesisStreamAsSource)
        .kinesis_stream_source_configuration(
            KinesisStreamSourceConfiguration::builder()
                .kinesis_stream_arn(&kinesis_arn)
                .role_arn(&blocked)
                .build()
                .unwrap(),
        )
        .extended_s3_destination_configuration(s3_config(&blocked, "other"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&refused.into_service_error()), "InvalidArgumentException");

    f.create_delivery_stream()
        .delivery_stream_name("from-kinesis")
        .delivery_stream_type(DeliveryStreamType::KinesisStreamAsSource)
        .kinesis_stream_source_configuration(
            KinesisStreamSourceConfiguration::builder()
                .kinesis_stream_arn(&kinesis_arn)
                .role_arn(&role)
                .build()
                .unwrap(),
        )
        .extended_s3_destination_configuration(s3_config(&role, "landing"))
        .send()
        .await
        .unwrap();
    wait_status(&f, "from-kinesis", DeliveryStreamStatus::Active).await;
    let d = f.describe_delivery_stream().delivery_stream_name("from-kinesis").send().await.unwrap();
    let source =
        d.delivery_stream_description().unwrap().source().unwrap().kinesis_stream_source_description().unwrap().clone();
    assert_eq!(source.kinesis_stream_arn(), Some(kinesis_arn.as_str()));
    // Direct puts are refused for a Kinesis-sourced stream.
    let direct = f
        .put_record()
        .delivery_stream_name("from-kinesis")
        .record(Record::builder().data(Blob::new("x")).build().unwrap())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&direct.into_service_error()), "InvalidArgumentException");

    for (key, data) in [("a", "1\n"), ("b", "2\n"), ("c", "3\n")] {
        k.put_record()
            .stream_name("clicks")
            .partition_key(key)
            .data(aws_sdk_kinesis::primitives::Blob::new(data))
            .send()
            .await
            .unwrap();
    }
    let got = objects(&mws, &f, "landing", "", 1).await;
    let mut lines: Vec<String> = got
        .iter()
        .flat_map(|(_, b)| String::from_utf8_lossy(b).lines().map(str::to_string).collect::<Vec<_>>())
        .collect();
    lines.sort();
    assert_eq!(lines, ["1", "2", "3"]);
}

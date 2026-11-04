//! What Firehose reports, through the official Rust SDKs: delivery errors
//! in CloudWatch Logs, `AWS/Firehose` metrics, record format conversion
//! (which needs a Glue table MWS cannot have), and HTTP endpoints that
//! answer badly or take their key from Secrets Manager.

use std::time::Duration;

use aws_sdk_firehose::primitives::Blob;
use aws_sdk_firehose::types::{
    BufferingHints, CloudWatchLoggingOptions, DataFormatConversionConfiguration, DeliveryStreamStatus, Deserializer,
    DynamicPartitioningConfiguration, ExtendedS3DestinationConfiguration, HttpEndpointBufferingHints,
    HttpEndpointConfiguration, HttpEndpointDestinationConfiguration, HttpEndpointRetryOptions,
    InputFormatConfiguration, OpenXJsonSerDe, OutputFormatConfiguration, ParquetSerDe, Record,
    S3DestinationConfiguration, SchemaConfiguration, SecretsManagerConfiguration, Serializer,
};
use aws_sdk_firehose::Client;
use mws_e2e::Mws;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::firehose::{code, https_listener, objects, role_and_bucket, wait_status};

fn hints() -> BufferingHints {
    BufferingHints::builder().interval_in_seconds(0).size_in_mbs(1).build()
}

async fn put(f: &Client, stream: &str, data: &str) {
    f.put_record()
        .delivery_stream_name(stream)
        .record(Record::builder().data(Blob::new(data)).build().unwrap())
        .send()
        .await
        .unwrap();
}

/// Wait for a log event in `group`/`stream`; returns the messages.
async fn log_messages(mws: &Mws, f: &Client, group: &str, stream: &str) -> Vec<serde_json::Value> {
    let logs = aws_sdk_cloudwatchlogs::Client::new(&mws.root_sdk_config().await);
    for _ in 0..100 {
        let _ = f.list_delivery_streams().send().await;
        let out = logs.get_log_events().log_group_name(group).log_stream_name(stream).send().await.unwrap();
        if !out.events().is_empty() {
            return out.events().iter().map(|e| serde_json::from_str(e.message().unwrap()).unwrap()).collect();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("no Firehose error was logged to {group}/{stream}");
}

#[tokio::test]
async fn logs_delivery_errors_and_publishes_metrics() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let f = Client::new(&cfg);
    let role = role_and_bucket(&mws, "delivery", "landing", r#"["s3:PutObject","logs:PutLogEvents"]"#).await;
    let logs = aws_sdk_cloudwatchlogs::Client::new(&cfg);
    logs.create_log_group().log_group_name("/aws/kinesisfirehose/broken").send().await.unwrap();
    logs.create_log_stream()
        .log_group_name("/aws/kinesisfirehose/broken")
        .log_stream_name("DestinationDelivery")
        .send()
        .await
        .unwrap();

    // Deliveries to a bucket that does not exist fail, and say why in the
    // log stream.
    let broken = ExtendedS3DestinationConfiguration::builder()
        .role_arn(&role)
        .bucket_arn("arn:aws:s3:::no-such-bucket")
        .buffering_hints(hints())
        .cloud_watch_logging_options(
            CloudWatchLoggingOptions::builder()
                .enabled(true)
                .log_group_name("/aws/kinesisfirehose/broken")
                .log_stream_name("DestinationDelivery")
                .build(),
        )
        .build()
        .unwrap();
    f.create_delivery_stream()
        .delivery_stream_name("broken")
        .extended_s3_destination_configuration(broken)
        .send()
        .await
        .unwrap();
    wait_status(&f, "broken", DeliveryStreamStatus::Active).await;
    put(&f, "broken", "lost").await;
    let messages = log_messages(&mws, &f, "/aws/kinesisfirehose/broken", "DestinationDelivery").await;
    let m = &messages[0];
    assert_eq!(m["errorCode"], "S3.NoSuchBucket", "{m}");
    assert_eq!(m["destination"], "arn:aws:s3:::no-such-bucket", "{m}");
    assert_eq!(m["deliveryStreamARN"], crate::firehose::stream_arn("broken"), "{m}");
    assert_eq!(m["deliveryStreamVersionId"], 1, "{m}");

    // A working stream publishes incoming and delivery metrics.
    let ok = ExtendedS3DestinationConfiguration::builder()
        .role_arn(&role)
        .bucket_arn("arn:aws:s3:::landing")
        .buffering_hints(hints())
        .build()
        .unwrap();
    f.create_delivery_stream()
        .delivery_stream_name("ok")
        .extended_s3_destination_configuration(ok)
        .send()
        .await
        .unwrap();
    wait_status(&f, "ok", DeliveryStreamStatus::Active).await;
    put(&f, "ok", "hello").await;
    objects(&mws, &f, "landing", "", 1).await;
    let cw = aws_sdk_cloudwatch::Client::new(&cfg);
    let mut names = Vec::new();
    for _ in 0..50 {
        let listed = cw
            .list_metrics()
            .namespace("AWS/Firehose")
            .dimensions(
                aws_sdk_cloudwatch::types::DimensionFilter::builder().name("DeliveryStreamName").value("ok").build(),
            )
            .send()
            .await
            .unwrap();
        names = listed.metrics().iter().filter_map(|m| m.metric_name().map(str::to_string)).collect();
        if names.iter().any(|n| n == "DeliveryToS3.Success") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    for want in
        ["IncomingRecords", "IncomingBytes", "PutRecord.Requests", "DeliveryToS3.Records", "DeliveryToS3.Success"]
    {
        assert!(names.iter().any(|n| n == want), "{want} missing from {names:?}");
    }
    let now = aws_sdk_cloudwatch::primitives::DateTime::from_secs(chrono::Utc::now().timestamp());
    let stats = cw
        .get_metric_statistics()
        .namespace("AWS/Firehose")
        .metric_name("IncomingBytes")
        .dimensions(aws_sdk_cloudwatch::types::Dimension::builder().name("DeliveryStreamName").value("ok").build())
        .start_time(aws_sdk_cloudwatch::primitives::DateTime::from_secs(now.secs() - 600))
        .end_time(aws_sdk_cloudwatch::primitives::DateTime::from_secs(now.secs() + 600))
        .period(3600)
        .statistics(aws_sdk_cloudwatch::types::Statistic::Sum)
        .send()
        .await
        .unwrap();
    assert_eq!(stats.datapoints()[0].sum(), Some(5.0));
}

fn conversion() -> DataFormatConversionConfiguration {
    DataFormatConversionConfiguration::builder()
        .enabled(true)
        .schema_configuration(
            SchemaConfiguration::builder()
                .role_arn("arn:aws:iam::123456789012:role/delivery")
                .database_name("analytics")
                .table_name("events")
                .region("us-east-1")
                .build(),
        )
        .input_format_configuration(
            InputFormatConfiguration::builder()
                .deserializer(Deserializer::builder().open_x_json_ser_de(OpenXJsonSerDe::builder().build()).build())
                .build(),
        )
        .output_format_configuration(
            OutputFormatConfiguration::builder()
                .serializer(Serializer::builder().parquet_ser_de(ParquetSerDe::builder().build()).build())
                .build(),
        )
        .build()
}

#[tokio::test]
async fn format_conversion_and_partitioning_buffer_defaults() {
    let mws = Mws::start().await;
    let f = Client::new(&mws.root_sdk_config().await);
    let role = role_and_bucket(&mws, "delivery", "lake", r#"["s3:PutObject"]"#).await;
    let base = || {
        ExtendedS3DestinationConfiguration::builder()
            .role_arn(&role)
            .bucket_arn("arn:aws:s3:::lake")
            .prefix("data/")
            .error_output_prefix("errors/!{firehose:error-output-type}/")
    };

    // Conversion needs at least 64 MiB buffers, and does its own
    // compression.
    let small = base().data_format_conversion_configuration(conversion()).buffering_hints(hints()).build().unwrap();
    let e = f
        .create_delivery_stream()
        .delivery_stream_name("small")
        .extended_s3_destination_configuration(small)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e), "InvalidArgumentException");
    let gzip = base()
        .data_format_conversion_configuration(conversion())
        .compression_format(aws_sdk_firehose::types::CompressionFormat::Gzip)
        .buffering_hints(BufferingHints::builder().size_in_mbs(64).build())
        .build()
        .unwrap();
    let e = f
        .create_delivery_stream()
        .delivery_stream_name("gzip")
        .extended_s3_destination_configuration(gzip)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e), "InvalidArgumentException");

    // Without buffering hints, conversion and dynamic partitioning buffer
    // 128 MiB.
    let dynamic = base()
        .prefix("c=!{partitionKeyFromLambda:c}/")
        .dynamic_partitioning_configuration(DynamicPartitioningConfiguration::builder().enabled(true).build())
        .build()
        .unwrap();
    f.create_delivery_stream()
        .delivery_stream_name("dynamic")
        .extended_s3_destination_configuration(dynamic)
        .send()
        .await
        .unwrap();
    let converted = base().data_format_conversion_configuration(conversion()).build().unwrap();
    f.create_delivery_stream()
        .delivery_stream_name("converted")
        .extended_s3_destination_configuration(converted)
        .send()
        .await
        .unwrap();
    for name in ["dynamic", "converted"] {
        let d = f.describe_delivery_stream().delivery_stream_name(name).send().await.unwrap();
        let s3 = d.delivery_stream_description().unwrap().destinations()[0]
            .extended_s3_destination_description()
            .unwrap()
            .clone();
        assert_eq!(s3.buffering_hints().unwrap().size_in_mbs(), Some(128), "{name}");
    }

    // There is no Glue table to convert with: records go to the
    // format-conversion-failed error output.
    let quick = base()
        .data_format_conversion_configuration(conversion())
        .buffering_hints(BufferingHints::builder().interval_in_seconds(0).size_in_mbs(64).build())
        .build()
        .unwrap();
    f.create_delivery_stream()
        .delivery_stream_name("quick")
        .extended_s3_destination_configuration(quick)
        .send()
        .await
        .unwrap();
    wait_status(&f, "quick", DeliveryStreamStatus::Active).await;
    put(&f, "quick", r#"{"a":1}"#).await;
    let got = objects(&mws, &f, "lake", "errors/format-conversion-failed/", 1).await;
    let line: serde_json::Value = serde_json::from_slice(got[0].1.split(|b| *b == b'\n').next().unwrap()).unwrap();
    assert_eq!(line["errorCode"], "DataFormatConversion.EntityNotFound", "{line}");
    let s3 = Mws::s3(&mws.root_sdk_config().await);
    let data = s3.list_objects_v2().bucket("lake").prefix("data/").send().await.unwrap();
    assert!(data.contents().is_empty());
}

/// Answer one HTTPS request with 200 and `body(request_id)`; hand back the
/// request head.
async fn answer(
    listener: &tokio::net::TcpListener,
    acceptor: &tokio_rustls::TlsAcceptor,
    body: impl Fn(&str) -> String,
) -> String {
    let (tcp, _) = listener.accept().await.unwrap();
    let mut sock = acceptor.accept(tcp).await.unwrap();
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let (head, end, len) = loop {
        let n = sock.read(&mut chunk).await.unwrap();
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_string();
            let len: usize = head
                .lines()
                .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse().unwrap()))
                .unwrap_or(0);
            break (head, end, len);
        }
    };
    while buf.len() < end + 4 + len {
        let n = sock.read(&mut chunk).await.unwrap();
        buf.extend_from_slice(&chunk[..n]);
    }
    let id = head
        .lines()
        .find_map(|l| l.to_ascii_lowercase().strip_prefix("x-amz-firehose-request-id:").map(|v| v.trim().to_string()))
        .unwrap_or_default();
    let reply = body(&id);
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{reply}",
        reply.len()
    );
    sock.write_all(response.as_bytes()).await.unwrap();
    let _ = sock.shutdown().await;
    head
}

#[tokio::test]
async fn http_endpoints_check_responses_and_read_keys_from_secrets_manager() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let f = Client::new(&cfg);
    let role = role_and_bucket(
        &mws,
        "delivery",
        "backup",
        r#"["s3:PutObject","secretsmanager:GetSecretValue","kms:Decrypt"]"#,
    )
    .await;
    let secret = aws_sdk_secretsmanager::Client::new(&cfg)
        .create_secret()
        .name("endpoint-key")
        .secret_string(r#"{"api_key":"from-secrets-manager"}"#)
        .send()
        .await
        .unwrap();
    let (listener, acceptor) = https_listener().await;
    let url = format!("https://localhost:{}/ingest", listener.local_addr().unwrap().port());
    let server = tokio::spawn(async move {
        // The first answer does not echo the request id; the second does.
        let first = answer(&listener, &acceptor, |_| r#"{"requestId":"wrong","timestamp":1}"#.to_string()).await;
        let second = answer(&listener, &acceptor, |id| format!(r#"{{"requestId":"{id}","timestamp":1}}"#)).await;
        (first, second)
    });

    let config = HttpEndpointDestinationConfiguration::builder()
        .endpoint_configuration(HttpEndpointConfiguration::builder().url(&url).build().unwrap())
        .secrets_manager_configuration(
            SecretsManagerConfiguration::builder().enabled(true).secret_arn(secret.arn().unwrap()).build().unwrap(),
        )
        .buffering_hints(HttpEndpointBufferingHints::builder().interval_in_seconds(0).size_in_mbs(1).build())
        .retry_options(HttpEndpointRetryOptions::builder().duration_in_seconds(0).build())
        .role_arn(&role)
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

    // An answer that does not echo the request id is a failure: with no
    // retries, the record goes to the S3 backup.
    put(&f, "http", "first").await;
    let got = objects(&mws, &f, "backup", "http-endpoint-failed/", 1).await;
    let line: serde_json::Value = serde_json::from_slice(got[0].1.split(|b| *b == b'\n').next().unwrap()).unwrap();
    assert_eq!(line["errorCode"], "HttpEndpoint.InvalidResponseFromDestination", "{line}");

    put(&f, "http", "second").await;
    let (first, _second) = loop {
        let _ = f.list_delivery_streams().send().await;
        if server.is_finished() {
            break server.await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let lower = first.to_ascii_lowercase();
    assert!(lower.contains("x-amz-firehose-access-key: from-secrets-manager"), "{first}");
    assert!(
        lower.contains(
            &format!("x-amz-firehose-source-arn: {}", crate::firehose::stream_arn("http")).to_ascii_lowercase()
        ),
        "{first}"
    );
    // The second delivery succeeded: nothing more in the backup.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let s3 = Mws::s3(&cfg);
    let listed = s3.list_objects_v2().bucket("backup").prefix("http-endpoint-failed/").send().await.unwrap();
    assert_eq!(listed.contents().len(), 1);
}

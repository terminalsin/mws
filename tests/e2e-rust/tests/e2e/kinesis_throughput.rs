//! Kinesis per-shard throughput limits through the official Rust SDK:
//! writes above 1 MiB/s per shard throttle (`PutRecord` fails, `PutRecords`
//! fails per record), more than five `GetRecords` calls a second on a shard
//! throttle, and the `Write/ReadProvisionedThroughputExceeded` metrics
//! count them.

use std::time::Duration;

use aws_sdk_cloudwatch::types::{Dimension, Statistic};
use aws_sdk_kinesis::error::ProvideErrorMetadata;
use aws_sdk_kinesis::primitives::Blob;
use aws_sdk_kinesis::types::{PutRecordsRequestEntry, ShardIteratorType, StreamStatus};
use aws_sdk_kinesis::Client;
use mws_e2e::Mws;

/// A client that surfaces throttling instead of retrying it (the SDK's
/// standard retry mode retries `ProvisionedThroughputExceededException`).
fn no_retries(config: &aws_config::SdkConfig) -> Client {
    Client::from_conf(
        aws_sdk_kinesis::config::Builder::from(config)
            .retry_config(aws_sdk_kinesis::config::retry::RetryConfig::disabled())
            .build(),
    )
}

async fn provisioned(k: &Client, name: &str, shards: i32) {
    k.create_stream().stream_name(name).shard_count(shards).send().await.unwrap();
    for _ in 0..100 {
        let s = k.describe_stream_summary().stream_name(name).send().await.unwrap();
        if s.stream_description_summary().unwrap().stream_status() == &StreamStatus::Active {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("stream {name} never became ACTIVE");
}

/// The `Sum` of a stream metric over the last ten minutes.
async fn sum(cw: &aws_sdk_cloudwatch::Client, metric: &str, stream: &str) -> f64 {
    let now = std::time::SystemTime::now();
    let stats = cw
        .get_metric_statistics()
        .namespace("AWS/Kinesis")
        .metric_name(metric)
        .dimensions(Dimension::builder().name("StreamName").value(stream).build())
        .start_time((now - Duration::from_secs(600)).into())
        .end_time((now + Duration::from_secs(120)).into())
        .period(60)
        .statistics(Statistic::Sum)
        .send()
        .await
        .unwrap();
    stats.datapoints().iter().filter_map(|p| p.sum()).sum()
}

const RATE_EXCEEDED: &str = "Rate exceeded for shard shardId-000000000000 in stream hot under account 123456789012.";

#[tokio::test]
async fn writes_above_a_mebibyte_per_second_throttle_per_shard() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let k = no_retries(&config);
    let cw = aws_sdk_cloudwatch::Client::new(&config);
    provisioned(&k, "hot", 2).await;
    // Twenty 100 KiB records on one partition key: about 2 MiB on one
    // shard, twice what it takes in a second.
    // ("hotkey" hashes into the first shard's half of the key space.)
    let data = vec![b'x'; 100 * 1024];
    let mut batch = k.put_records().stream_name("hot");
    for _ in 0..20 {
        batch = batch.records(
            PutRecordsRequestEntry::builder().partition_key("hotkey").data(Blob::new(data.clone())).build().unwrap(),
        );
    }
    let out = batch.send().await.unwrap();
    let failed: Vec<_> = out.records().iter().filter(|r| r.error_code().is_some()).collect();
    assert_eq!(out.failed_record_count(), Some(failed.len() as i32));
    assert!((9..=11).contains(&failed.len()), "{} records throttled", failed.len());
    for r in &failed {
        assert_eq!(r.error_code(), Some("ProvisionedThroughputExceededException"));
        assert_eq!(r.error_message(), Some(RATE_EXCEEDED));
        assert!(r.sequence_number().is_none() && r.shard_id().is_none());
    }
    // Successful records keep their order: the throttled ones are the
    // last of the batch.
    assert!(out.records()[..9].iter().all(|r| r.sequence_number().is_some()));

    // PutRecord on the throttled shard fails as a whole.
    let half = vec![b'y'; 512 * 1024];
    let e = k
        .put_record()
        .stream_name("hot")
        .partition_key("hotkey")
        .data(Blob::new(half.clone()))
        .send()
        .await
        .unwrap_err();
    assert_eq!(e.code(), Some("ProvisionedThroughputExceededException"));
    assert_eq!(e.message(), Some(RATE_EXCEEDED));
    // The other shard still has its own capacity.
    let other = k
        .put_record()
        .stream_name("hot")
        .partition_key("cold")
        .explicit_hash_key("340282366920938463463374607431768211455")
        .data(Blob::new(half.clone()))
        .send()
        .await
        .unwrap();
    assert_eq!(other.shard_id(), "shardId-000000000001");
    // A second later the shard accepts writes again: retrying works.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    k.put_record().stream_name("hot").partition_key("hotkey").data(Blob::new(half)).send().await.unwrap();

    let throttled = failed.len() as f64 + 1.0;
    assert_eq!(sum(&cw, "WriteProvisionedThroughputExceeded", "hot").await, throttled);
    assert_eq!(sum(&cw, "PutRecords.ThrottledRecords", "hot").await, failed.len() as f64);
    assert_eq!(sum(&cw, "PutRecords.SuccessfulRecords", "hot").await, 20.0 - failed.len() as f64);
    assert_eq!(sum(&cw, "IncomingRecords", "hot").await, 20.0 - failed.len() as f64 + 2.0);
    mws.stop().await;
}

#[tokio::test]
async fn more_than_a_thousand_records_per_second_throttle() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let k = no_retries(&config);
    provisioned(&k, "hot", 1).await;
    let mut failed = 0;
    for _ in 0..3 {
        let mut batch = k.put_records().stream_name("hot");
        for i in 0..500 {
            batch = batch.records(
                PutRecordsRequestEntry::builder().partition_key(format!("k{i}")).data(Blob::new("r")).build().unwrap(),
            );
        }
        failed += batch.send().await.unwrap().failed_record_count().unwrap_or_default();
    }
    // 1,500 records in well under a second: about 500 throttled (the
    // bucket refills while the requests run).
    assert!((300..=500).contains(&failed), "{failed} records throttled");
    mws.stop().await;
}

#[tokio::test]
async fn more_than_five_get_records_per_second_throttle() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let k = no_retries(&config);
    let cw = aws_sdk_cloudwatch::Client::new(&config);
    provisioned(&k, "hot", 1).await;
    k.put_record().stream_name("hot").partition_key("a").data(Blob::new("one")).send().await.unwrap();
    let it = k
        .get_shard_iterator()
        .stream_name("hot")
        .shard_id("shardId-000000000000")
        .shard_iterator_type(ShardIteratorType::TrimHorizon)
        .send()
        .await
        .unwrap();
    let mut iterator = it.shard_iterator().unwrap().to_string();
    let mut throttled = None;
    for i in 0..8 {
        match k.get_records().shard_iterator(&iterator).send().await {
            Ok(out) => iterator = out.next_shard_iterator().unwrap().to_string(),
            Err(e) => {
                throttled = Some((i, e.into_service_error()));
                break;
            }
        }
    }
    let (calls, e) = throttled.expect("GetRecords was never throttled");
    assert!(calls >= 5, "five calls succeed in a second, got {calls}");
    assert!(e.is_provisioned_throughput_exceeded_exception(), "{e:?}");
    assert_eq!(e.message(), Some(RATE_EXCEEDED));
    // The iterator is still good: a consumer that backs off carries on.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    k.get_records().shard_iterator(&iterator).send().await.unwrap();
    assert_eq!(sum(&cw, "ReadProvisionedThroughputExceeded", "hot").await, 1.0);
    mws.stop().await;
}

//! Kinesis behaviours found in the parity audit: CloudWatch metrics,
//! `SubscribeToShard` takeover, account-level IAM resources, `ListShards`
//! trim-horizon filters and the per-day limits on capacity changes.

use std::time::Duration;

use aws_sdk_cloudwatch::types::{Dimension, Statistic};
use aws_sdk_kinesis::error::ProvideErrorMetadata;
use aws_sdk_kinesis::primitives::Blob;
use aws_sdk_kinesis::types::{
    ConsumerStatus, MetricsName, ScalingType, ShardFilter, ShardFilterType, ShardIteratorType, StartingPosition,
    StreamMode, StreamModeDetails, StreamStatus, SubscribeToShardEventStream,
};
use aws_sdk_kinesis::Client;
use mws_e2e::{user_with_policy, Mws};

const ACCOUNT: &str = "123456789012";

fn code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

fn arn(name: &str) -> String {
    format!("arn:aws:kinesis:us-east-1:{ACCOUNT}:stream/{name}")
}

async fn wait_active(k: &Client, name: &str) {
    for _ in 0..100 {
        let s = k.describe_stream_summary().stream_name(name).send().await.unwrap();
        if s.stream_description_summary().unwrap().stream_status() == &StreamStatus::Active {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("stream {name} never became ACTIVE");
}

async fn provisioned(k: &Client, name: &str, shards: i32) {
    k.create_stream().stream_name(name).shard_count(shards).send().await.unwrap();
    wait_active(k, name).await;
}

fn dim(name: &str, value: &str) -> Dimension {
    Dimension::builder().name(name).value(value).build()
}

/// The `Sum` of a metric over the last ten minutes.
async fn sum(cw: &aws_sdk_cloudwatch::Client, metric: &str, dims: Vec<Dimension>) -> f64 {
    let now = std::time::SystemTime::now();
    let stats = cw
        .get_metric_statistics()
        .namespace("AWS/Kinesis")
        .metric_name(metric)
        .set_dimensions(Some(dims))
        .start_time((now - Duration::from_secs(600)).into())
        .end_time((now + Duration::from_secs(120)).into())
        .period(60)
        .statistics(Statistic::Sum)
        .send()
        .await
        .unwrap();
    stats.datapoints().iter().filter_map(|p| p.sum()).sum()
}

#[tokio::test]
async fn reads_and_writes_publish_cloudwatch_metrics() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let k = Client::new(&config);
    let cw = aws_sdk_cloudwatch::Client::new(&config);
    provisioned(&k, "metered", 1).await;
    k.enable_enhanced_monitoring()
        .stream_name("metered")
        .shard_level_metrics(MetricsName::IncomingRecords)
        .shard_level_metrics(MetricsName::OutgoingBytes)
        .send()
        .await
        .unwrap();

    k.put_record().stream_name("metered").partition_key("a").data(Blob::new("hello")).send().await.unwrap();
    let mut batch = k.put_records().stream_name("metered");
    for data in ["b1", "b2"] {
        batch = batch.records(
            aws_sdk_kinesis::types::PutRecordsRequestEntry::builder()
                .partition_key("p")
                .data(Blob::new(data))
                .build()
                .unwrap(),
        );
    }
    batch.send().await.unwrap();
    let it = k
        .get_shard_iterator()
        .stream_name("metered")
        .shard_id("shardId-000000000000")
        .shard_iterator_type(ShardIteratorType::TrimHorizon)
        .send()
        .await
        .unwrap();
    let got = k.get_records().shard_iterator(it.shard_iterator().unwrap()).send().await.unwrap();
    assert_eq!(got.records().len(), 3);

    let stream = || vec![dim("StreamName", "metered")];
    let shard = || vec![dim("StreamName", "metered"), dim("ShardId", "shardId-000000000000")];
    assert_eq!(sum(&cw, "IncomingRecords", stream()).await, 3.0);
    assert_eq!(sum(&cw, "IncomingBytes", stream()).await, 9.0);
    assert_eq!(sum(&cw, "PutRecord.Success", stream()).await, 1.0);
    assert_eq!(sum(&cw, "PutRecords.TotalRecords", stream()).await, 2.0);
    assert_eq!(sum(&cw, "PutRecords.FailedRecords", stream()).await, 0.0);
    assert_eq!(sum(&cw, "GetRecords.Records", stream()).await, 3.0);
    assert_eq!(sum(&cw, "GetRecords.Bytes", stream()).await, 9.0);
    // Shard-level metrics only for what enhanced monitoring enabled.
    assert_eq!(sum(&cw, "IncomingRecords", shard()).await, 3.0);
    assert_eq!(sum(&cw, "OutgoingBytes", shard()).await, 9.0);
    let listed = cw.list_metrics().namespace("AWS/Kinesis").metric_name("IncomingBytes").send().await.unwrap();
    let shard_dims = listed.metrics().iter().filter(|m| m.dimensions().iter().any(|d| d.name() == Some("ShardId")));
    assert_eq!(shard_dims.count(), 0, "IncomingBytes was not enabled per shard");
    mws.stop().await;
}

#[tokio::test]
async fn subscriptions_are_taken_over_after_five_seconds() {
    let mws = Mws::start().await;
    let k = Client::new(&mws.root_sdk_config().await);
    provisioned(&k, "fanout", 1).await;
    let c = k.register_stream_consumer().stream_arn(arn("fanout")).consumer_name("app").send().await.unwrap();
    let consumer_arn = c.consumer().unwrap().consumer_arn().to_string();
    for _ in 0..50 {
        let d = k.describe_stream_consumer().consumer_arn(&consumer_arn).send().await.unwrap();
        if d.consumer_description().unwrap().consumer_status() == &ConsumerStatus::Active {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let subscribe = || {
        k.subscribe_to_shard()
            .consumer_arn(&consumer_arn)
            .shard_id("shardId-000000000000")
            .starting_position(StartingPosition::builder().r#type(ShardIteratorType::Latest).build().unwrap())
            .send()
    };
    let mut first = subscribe().await.unwrap();
    // A second subscription within five seconds is refused...
    let early = subscribe().await.unwrap_err();
    assert_eq!(code(&early.into_service_error()), "ResourceInUseException");
    // ...after five seconds it takes over, and the first one ends.
    tokio::time::sleep(Duration::from_millis(5200)).await;
    let mut second = subscribe().await.unwrap();
    let ended = loop {
        match tokio::time::timeout(Duration::from_secs(10), first.event_stream.recv()).await.expect("an event") {
            Ok(Some(SubscribeToShardEventStream::SubscribeToShardEvent(_))) => continue,
            Ok(other) => panic!("expected the takeover error, got {other:?}"),
            Err(e) => break e,
        }
    };
    // Event stream errors arrive as modeled variants (the SDK sets no code).
    let ended = ended.into_service_error();
    assert!(ended.is_resource_in_use_exception(), "{ended:?}");

    // Deregistering the consumer ends its subscription.
    k.deregister_stream_consumer().consumer_arn(&consumer_arn).send().await.unwrap();
    let gone = loop {
        match tokio::time::timeout(Duration::from_secs(10), second.event_stream.recv()).await.expect("an event") {
            Ok(Some(SubscribeToShardEventStream::SubscribeToShardEvent(_))) => continue,
            Ok(other) => panic!("expected the consumer to be gone, got {other:?}"),
            Err(e) => break e,
        }
    };
    let gone = gone.into_service_error();
    assert!(gone.is_resource_not_found_exception(), "{gone:?}");
    mws.stop().await;
}

#[tokio::test]
async fn account_actions_authorize_on_star() {
    let mws = Mws::start().await;
    // A statement scoped to stream ARNs does not grant actions that name no
    // resource; one on "*" does.
    let scoped = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["kinesis:ListStreams","kinesis:DescribeLimits"],"Resource":"arn:aws:kinesis:*:*:stream/*"}]}"#;
    let (_, scoped_cfg) = user_with_policy(&mws, "scoped", Some(scoped)).await;
    let scoped = Client::new(&scoped_cfg);
    let e = scoped.list_streams().send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "AccessDeniedException");
    let e = scoped.describe_limits().send().await.unwrap_err();
    assert_eq!(code(&e.into_service_error()), "AccessDeniedException");
    let star = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["kinesis:ListStreams","kinesis:DescribeLimits","kinesis:DescribeAccountSettings"],"Resource":"*"}]}"#;
    let (_, star_cfg) = user_with_policy(&mws, "star", Some(star)).await;
    let star = Client::new(&star_cfg);
    star.list_streams().send().await.unwrap();
    star.describe_limits().send().await.unwrap();
    star.describe_account_settings().send().await.unwrap();
    mws.stop().await;
}

#[tokio::test]
async fn trim_horizon_filters_and_daily_limits() {
    let mws = Mws::start().await;
    let k = Client::new(&mws.root_sdk_config().await);

    // AT_TRIM_HORIZON lists the shards open at the trim horizon (the
    // parent), FROM_TRIM_HORIZON every shard, AT_LATEST the open ones.
    provisioned(&k, "split", 1).await;
    k.split_shard()
        .stream_name("split")
        .shard_to_split("shardId-000000000000")
        .new_starting_hash_key("170141183460469231731687303715884105728")
        .send()
        .await
        .unwrap();
    wait_active(&k, "split").await;
    let ids = |f: ShardFilterType| {
        let k = k.clone();
        async move {
            let out = k
                .list_shards()
                .stream_name("split")
                .shard_filter(ShardFilter::builder().r#type(f).build().unwrap())
                .send()
                .await
                .unwrap();
            out.shards().iter().map(|s| s.shard_id().to_string()).collect::<Vec<_>>()
        }
    };
    assert_eq!(ids(ShardFilterType::AtTrimHorizon).await, ["shardId-000000000000"]);
    assert_eq!(ids(ShardFilterType::FromTrimHorizon).await.len(), 3);
    assert_eq!(ids(ShardFilterType::AtLatest).await, ["shardId-000000000001", "shardId-000000000002"]);

    // The capacity mode can change twice per 24 hours.
    let mode = |m: StreamMode| StreamModeDetails::builder().stream_mode(m).build().unwrap();
    k.create_stream().stream_name("modes").stream_mode_details(mode(StreamMode::OnDemand)).send().await.unwrap();
    wait_active(&k, "modes").await;
    for m in [StreamMode::Provisioned, StreamMode::OnDemand] {
        k.update_stream_mode().stream_arn(arn("modes")).stream_mode_details(mode(m)).send().await.unwrap();
        wait_active(&k, "modes").await;
    }
    let third = k
        .update_stream_mode()
        .stream_arn(arn("modes"))
        .stream_mode_details(mode(StreamMode::Provisioned))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&third.into_service_error()), "LimitExceededException");

    // UpdateShardCount works ten times per rolling 24 hours.
    provisioned(&k, "scaled", 1).await;
    for i in 0..10 {
        let target = if i % 2 == 0 { 2 } else { 1 };
        k.update_shard_count()
            .stream_name("scaled")
            .target_shard_count(target)
            .scaling_type(ScalingType::UniformScaling)
            .send()
            .await
            .unwrap();
        wait_active(&k, "scaled").await;
    }
    let eleventh = k
        .update_shard_count()
        .stream_name("scaled")
        .target_shard_count(2)
        .scaling_type(ScalingType::UniformScaling)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&eleventh.into_service_error()), "LimitExceededException");
    mws.stop().await;
}

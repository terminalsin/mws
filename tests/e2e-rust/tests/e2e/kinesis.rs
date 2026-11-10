//! Amazon Kinesis Data Streams through the official Rust SDK.

use std::time::Duration;

use aws_sdk_kinesis::error::ProvideErrorMetadata;
use aws_sdk_kinesis::primitives::Blob;
use aws_sdk_kinesis::types::{
    ChannelStreamConfiguration, ConsumerStatus, EncryptionType, MetricsName, MinimumThroughputBillingCommitmentInput,
    MinimumThroughputBillingCommitmentInputStatus, PutRecordsRequestEntry, RecordConfiguration, RecordFormatType,
    S3DestinationConfiguration, S3StorageConfiguration, ScalingType, ShardFilter, ShardFilterType, ShardIteratorType,
    StartingPosition, StreamMode, StreamModeDetails, StreamStatus, SubscribeToShardEventStream,
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

pub(crate) async fn wait_active(k: &Client, name: &str) {
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

#[tokio::test]
async fn streams_records_and_iterators() {
    let mws = Mws::start().await;
    let k = Client::new(&mws.root_sdk_config().await);

    // A new stream is CREATING, then ACTIVE; puts before then fail.
    k.create_stream().stream_name("orders").shard_count(2).send().await.unwrap();
    let early = k.put_record().stream_name("orders").partition_key("a").data(Blob::new("x")).send().await;
    assert_eq!(code(&early.unwrap_err().into_service_error()), "ResourceNotFoundException");
    wait_active(&k, "orders").await;
    let dup = k.create_stream().stream_name("orders").shard_count(1).send().await.unwrap_err();
    assert_eq!(code(&dup.into_service_error()), "ResourceInUseException");

    let d = k.describe_stream().stream_name("orders").send().await.unwrap();
    let desc = d.stream_description().unwrap();
    assert_eq!(desc.stream_arn(), arn("orders"));
    assert_eq!(desc.shards().len(), 2);
    assert_eq!(desc.shards()[0].hash_key_range().unwrap().ending_hash_key(), "170141183460469231731687303715884105727");
    assert_eq!(desc.retention_period_hours(), 24);
    assert_eq!(desc.stream_mode_details().unwrap().stream_mode(), &StreamMode::Provisioned);

    // md5("a") starts with 0x0c, the lower half; md5("c") with 0x4a, too;
    // an explicit hash key picks the upper shard.
    let p1 = k.put_record().stream_name("orders").partition_key("a").data(Blob::new("one")).send().await.unwrap();
    assert_eq!(p1.shard_id(), "shardId-000000000000");
    assert_eq!(p1.sequence_number().len(), 56);
    assert_eq!(p1.encryption_type(), Some(&EncryptionType::None));
    let p2 = k
        .put_record()
        .stream_arn(arn("orders"))
        .partition_key("a")
        .explicit_hash_key("340282366920938463463374607431768211455")
        .data(Blob::new("two"))
        .send()
        .await
        .unwrap();
    assert_eq!(p2.shard_id(), "shardId-000000000001");
    let batch = k
        .put_records()
        .stream_name("orders")
        .records(PutRecordsRequestEntry::builder().partition_key("a").data(Blob::new("three")).build().unwrap())
        .records(PutRecordsRequestEntry::builder().partition_key("a").data(Blob::new("four")).build().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(batch.failed_record_count(), Some(0));
    assert_eq!(batch.records().len(), 2);
    assert!(batch.records()[0].sequence_number().unwrap() > p1.sequence_number());

    // TRIM_HORIZON reads everything in order; AFTER_SEQUENCE_NUMBER skips.
    let it = k
        .get_shard_iterator()
        .stream_name("orders")
        .shard_id("shardId-000000000000")
        .shard_iterator_type(ShardIteratorType::TrimHorizon)
        .send()
        .await
        .unwrap();
    let got = k.get_records().shard_iterator(it.shard_iterator().unwrap()).send().await.unwrap();
    let data: Vec<String> =
        got.records().iter().map(|r| String::from_utf8(r.data().as_ref().to_vec()).unwrap()).collect();
    assert_eq!(data, ["one", "three", "four"]);
    assert_eq!(got.records()[0].partition_key(), Some("a"));
    assert_eq!(got.millis_behind_latest(), Some(0));
    let next = got.next_shard_iterator().unwrap().to_string();
    let empty = k.get_records().shard_iterator(&next).send().await.unwrap();
    assert!(empty.records().is_empty());
    let after = k
        .get_shard_iterator()
        .stream_name("orders")
        .shard_id("shardId-000000000000")
        .shard_iterator_type(ShardIteratorType::AfterSequenceNumber)
        .starting_sequence_number(p1.sequence_number())
        .send()
        .await
        .unwrap();
    let rest = k.get_records().shard_iterator(after.shard_iterator().unwrap()).limit(1).send().await.unwrap();
    assert_eq!(rest.records()[0].data().as_ref(), b"three");
    assert!(rest.millis_behind_latest().unwrap() >= 0);
    let wrong = k
        .get_shard_iterator()
        .stream_name("orders")
        .shard_id("shardId-000000000001")
        .shard_iterator_type(ShardIteratorType::AtSequenceNumber)
        .starting_sequence_number(p1.sequence_number())
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&wrong.into_service_error()), "InvalidArgumentException");
    let bad = k.get_records().shard_iterator("not-an-iterator").send().await.unwrap_err();
    assert_eq!(code(&bad.into_service_error()), "InvalidArgumentException");
    let missing = k
        .get_shard_iterator()
        .stream_name("orders")
        .shard_id("shardId-000000000009")
        .shard_iterator_type(ShardIteratorType::Latest)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&missing.into_service_error()), "ResourceNotFoundException");

    // Iterators expire after five minutes on the emulated clock.
    let (status, _) = mws.control("POST", "/_mws/clock", Some(r#"{"advanceSeconds":301}"#)).await;
    assert_eq!(status, 200);
    let expired = k.get_records().shard_iterator(&next).send().await.unwrap_err();
    assert_eq!(code(&expired.into_service_error()), "ExpiredIteratorException");

    // DryRun answers with DryRunOperationException when the call would work.
    let dry = k.put_record().stream_name("orders").partition_key("a").data(Blob::new("x")).dry_run(true).send().await;
    assert_eq!(code(&dry.unwrap_err().into_service_error()), "DryRunOperationException");

    // Listing.
    provisioned(&k, "audit", 1).await;
    let list = k.list_streams().limit(1).send().await.unwrap();
    assert_eq!(list.stream_names(), ["audit"]);
    assert!(list.has_more_streams());
    let page2 = k.list_streams().next_token(list.next_token().unwrap()).send().await.unwrap();
    assert_eq!(page2.stream_names(), ["orders"]);
    assert_eq!(page2.stream_summaries()[0].stream_arn(), arn("orders"));
    let shards = k.list_shards().stream_name("orders").max_results(1).send().await.unwrap();
    assert_eq!(shards.shards().len(), 1);
    let more = k.list_shards().next_token(shards.next_token().unwrap()).send().await.unwrap();
    assert_eq!(more.shards()[0].shard_id(), "shardId-000000000001");
    let both = k.list_shards().stream_name("orders").next_token(shards.next_token().unwrap()).send().await;
    assert_eq!(code(&both.unwrap_err().into_service_error()), "InvalidArgumentException");
    let summary = k.describe_stream_summary().stream_arn(arn("orders")).send().await.unwrap();
    let summary = summary.stream_description_summary().unwrap();
    assert_eq!(summary.open_shard_count(), 2);
    assert!(summary.stream_id().is_some());
    assert_eq!(summary.max_record_size_in_kib(), Some(1024));

    let limits = k.describe_limits().send().await.unwrap();
    assert_eq!(limits.shard_limit(), 500);
    assert_eq!(limits.open_shard_count(), 3);
    assert_eq!(limits.on_demand_stream_count_limit(), 50);

    // Retention.
    k.increase_stream_retention_period().stream_name("orders").retention_period_hours(48).send().await.unwrap();
    let shorter = k.increase_stream_retention_period().stream_name("orders").retention_period_hours(36).send().await;
    assert_eq!(code(&shorter.unwrap_err().into_service_error()), "InvalidArgumentException");
    k.decrease_stream_retention_period().stream_name("orders").retention_period_hours(24).send().await.unwrap();
    let too_short = k.decrease_stream_retention_period().stream_name("orders").retention_period_hours(1).send().await;
    assert_eq!(code(&too_short.unwrap_err().into_service_error()), "InvalidArgumentException");

    // Enhanced monitoring.
    let on = k
        .enable_enhanced_monitoring()
        .stream_name("orders")
        .shard_level_metrics(MetricsName::IncomingBytes)
        .send()
        .await
        .unwrap();
    assert!(on.current_shard_level_metrics().is_empty());
    assert_eq!(on.desired_shard_level_metrics(), [MetricsName::IncomingBytes]);
    let off = k
        .disable_enhanced_monitoring()
        .stream_name("orders")
        .shard_level_metrics(MetricsName::All)
        .send()
        .await
        .unwrap();
    assert!(off.desired_shard_level_metrics().is_empty());

    // Deleting: the stream goes DELETING, then away.
    k.delete_stream().stream_name("audit").send().await.unwrap();
    for _ in 0..50 {
        match k.describe_stream_summary().stream_name("audit").send().await {
            Ok(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            Err(e) => {
                assert_eq!(code(&e.into_service_error()), "ResourceNotFoundException");
                break;
            }
        }
    }
    mws.stop().await;
}

#[tokio::test]
async fn resharding_reports_child_shards() {
    let mws = Mws::start().await;
    let k = Client::new(&mws.root_sdk_config().await);
    provisioned(&k, "r", 1).await;
    k.put_record().stream_name("r").partition_key("a").data(Blob::new("before")).send().await.unwrap();

    k.split_shard()
        .stream_name("r")
        .shard_to_split("shardId-000000000000")
        .new_starting_hash_key("170141183460469231731687303715884105728")
        .send()
        .await
        .unwrap();
    wait_active(&k, "r").await;
    let shards = k.list_shards().stream_name("r").send().await.unwrap();
    let ids: Vec<&str> = shards.shards().iter().map(|s| s.shard_id()).collect();
    assert_eq!(ids, ["shardId-000000000000", "shardId-000000000001", "shardId-000000000002"]);
    assert!(shards.shards()[0].sequence_number_range().unwrap().ending_sequence_number().is_some());
    assert_eq!(shards.shards()[1].parent_shard_id(), Some("shardId-000000000000"));
    let open = k
        .list_shards()
        .stream_name("r")
        .shard_filter(ShardFilter::builder().r#type(ShardFilterType::AtLatest).build().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(open.shards().len(), 2);

    // Reading the closed parent ends with its children.
    let it = k
        .get_shard_iterator()
        .stream_name("r")
        .shard_id("shardId-000000000000")
        .shard_iterator_type(ShardIteratorType::TrimHorizon)
        .send()
        .await
        .unwrap();
    let got = k.get_records().shard_iterator(it.shard_iterator().unwrap()).send().await.unwrap();
    assert_eq!(got.records().len(), 1);
    assert!(got.next_shard_iterator().is_none());
    let children: Vec<&str> = got.child_shards().iter().map(|c| c.shard_id()).collect();
    assert_eq!(children, ["shardId-000000000001", "shardId-000000000002"]);

    let again = k
        .split_shard()
        .stream_name("r")
        .shard_to_split("shardId-000000000000")
        .new_starting_hash_key("5")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&again.into_service_error()), "ResourceInUseException");

    k.merge_shards()
        .stream_name("r")
        .shard_to_merge("shardId-000000000001")
        .adjacent_shard_to_merge("shardId-000000000002")
        .send()
        .await
        .unwrap();
    wait_active(&k, "r").await;
    let merged = k.describe_stream().stream_name("r").send().await.unwrap();
    let last = merged.stream_description().unwrap().shards().last().unwrap().clone();
    assert_eq!(last.shard_id(), "shardId-000000000003");
    assert_eq!(last.adjacent_parent_shard_id(), Some("shardId-000000000002"));

    let scaled = k
        .update_shard_count()
        .stream_name("r")
        .target_shard_count(2)
        .scaling_type(ScalingType::UniformScaling)
        .send()
        .await
        .unwrap();
    assert_eq!(scaled.current_shard_count(), Some(1));
    assert_eq!(scaled.target_shard_count(), Some(2));
    wait_active(&k, "r").await;
    let too_many = k
        .update_shard_count()
        .stream_name("r")
        .target_shard_count(10)
        .scaling_type(ScalingType::UniformScaling)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&too_many.into_service_error()), "LimitExceededException");

    // Capacity modes.
    k.update_stream_mode()
        .stream_arn(arn("r"))
        .stream_mode_details(StreamModeDetails::builder().stream_mode(StreamMode::OnDemand).build().unwrap())
        .send()
        .await
        .unwrap();
    wait_active(&k, "r").await;
    k.update_stream_warm_throughput().stream_arn(arn("r")).warm_throughput_mibps(10).send().await.unwrap();
    wait_active(&k, "r").await;
    k.update_stream_record_distribution_strategy()
        .stream_arn(arn("r"))
        .record_distribution_strategy(aws_sdk_kinesis::types::RecordDistributionStrategy::Auto)
        .send()
        .await
        .unwrap();
    // AUTO ignores partition keys, so none is needed.
    k.put_record().stream_name("r").data(Blob::new("auto")).send().await.unwrap();
    k.update_max_record_size().stream_arn(arn("r")).max_record_size_in_kib(2048).send().await.unwrap();
    wait_active(&k, "r").await;
    let s = k.describe_stream_summary().stream_name("r").send().await.unwrap();
    let s = s.stream_description_summary().unwrap();
    assert_eq!(s.stream_mode_details().unwrap().stream_mode(), &StreamMode::OnDemand);
    assert_eq!(s.warm_throughput().unwrap().target_mibps(), Some(10));
    assert_eq!(s.max_record_size_in_kib(), Some(2048));
    mws.stop().await;
}

#[tokio::test]
async fn consumers_subscribe_tags_and_policies() {
    let mws = Mws::start().await;
    let k = Client::new(&mws.root_sdk_config().await);
    provisioned(&k, "fan", 1).await;

    let c = k.register_stream_consumer().stream_arn(arn("fan")).consumer_name("app").send().await.unwrap();
    let consumer_arn = c.consumer().unwrap().consumer_arn().to_string();
    assert!(consumer_arn.starts_with(&format!("{}/consumer/app:", arn("fan"))));
    for _ in 0..50 {
        let d = k.describe_stream_consumer().consumer_arn(&consumer_arn).send().await.unwrap();
        if d.consumer_description().unwrap().consumer_status() == &ConsumerStatus::Active {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let by_name = k.describe_stream_consumer().stream_arn(arn("fan")).consumer_name("app").send().await.unwrap();
    assert_eq!(by_name.consumer_description().unwrap().stream_arn(), arn("fan"));
    let list = k.list_stream_consumers().stream_arn(arn("fan")).send().await.unwrap();
    assert_eq!(list.consumers().len(), 1);

    k.put_record().stream_name("fan").partition_key("k").data(Blob::new("first")).send().await.unwrap();
    let mut sub = k
        .subscribe_to_shard()
        .consumer_arn(&consumer_arn)
        .shard_id("shardId-000000000000")
        .starting_position(StartingPosition::builder().r#type(ShardIteratorType::TrimHorizon).build().unwrap())
        .send()
        .await
        .unwrap();
    let mut seen = Vec::new();
    let pusher = {
        let k = k.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(300)).await;
            k.put_record().stream_name("fan").partition_key("k").data(Blob::new("second")).send().await.unwrap();
        })
    };
    while seen.len() < 2 {
        let event = tokio::time::timeout(Duration::from_secs(10), sub.event_stream.recv())
            .await
            .expect("an event within 10 s")
            .unwrap()
            .expect("the stream stays open");
        if let SubscribeToShardEventStream::SubscribeToShardEvent(e) = event {
            for r in e.records() {
                seen.push(String::from_utf8(r.data().as_ref().to_vec()).unwrap());
            }
        }
    }
    pusher.await.unwrap();
    assert_eq!(seen, ["first", "second"]);

    // Tags on streams (both APIs) and consumers.
    k.add_tags_to_stream().stream_name("fan").tags("team", "data").send().await.unwrap();
    k.tag_resource().resource_arn(arn("fan")).tags("env", "test").send().await.unwrap();
    let tags = k.list_tags_for_stream().stream_name("fan").send().await.unwrap();
    let keys: Vec<&str> = tags.tags().iter().map(|t| t.key()).collect();
    assert_eq!(keys, ["env", "team"]);
    k.remove_tags_from_stream().stream_name("fan").tag_keys("team").send().await.unwrap();
    k.untag_resource().resource_arn(arn("fan")).tag_keys("env").send().await.unwrap();
    k.tag_resource().resource_arn(&consumer_arn).tags("c", "1").send().await.unwrap();
    let ct = k.list_tags_for_resource().resource_arn(&consumer_arn).send().await.unwrap();
    assert_eq!(ct.tags()[0].key(), "c");
    assert!(k.list_tags_for_resource().resource_arn(arn("fan")).send().await.unwrap().tags().is_empty());

    // A resource policy lets another principal read the stream.
    let (_, reader_cfg) = user_with_policy(&mws, "reader", None).await;
    let reader = Client::new(&reader_cfg);
    let denied = reader.describe_stream_summary().stream_arn(arn("fan")).send().await.unwrap_err();
    assert_eq!(code(&denied.into_service_error()), "AccessDeniedException");
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{ACCOUNT}:user/reader"}},"Action":"kinesis:DescribeStreamSummary","Resource":"{}"}}]}}"#,
        arn("fan")
    );
    k.put_resource_policy().resource_arn(arn("fan")).policy(&policy).send().await.unwrap();
    let got = k.get_resource_policy().resource_arn(arn("fan")).send().await.unwrap();
    assert_eq!(got.policy(), policy);
    reader.describe_stream_summary().stream_arn(arn("fan")).send().await.unwrap();
    k.delete_resource_policy().resource_arn(arn("fan")).send().await.unwrap();
    assert_eq!(k.get_resource_policy().resource_arn(arn("fan")).send().await.unwrap().policy(), "{}");

    // A stream with consumers needs EnforceConsumerDeletion.
    let blocked = k.delete_stream().stream_name("fan").send().await.unwrap_err();
    assert_eq!(code(&blocked.into_service_error()), "ResourceInUseException");
    k.deregister_stream_consumer().consumer_arn(&consumer_arn).send().await.unwrap();
    k.delete_stream().stream_name("fan").enforce_consumer_deletion(true).send().await.unwrap();
    mws.stop().await;
}

#[tokio::test]
async fn encryption_channels_and_account_settings() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let k = Client::new(&cfg);
    let kms = aws_sdk_kms::Client::new(&cfg);
    provisioned(&k, "secret", 1).await;

    let missing = k
        .start_stream_encryption()
        .stream_name("secret")
        .encryption_type(EncryptionType::Kms)
        .key_id(format!("arn:aws:kms:us-east-1:{ACCOUNT}:key/00000000-0000-0000-0000-000000000000"))
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&missing.into_service_error()), "KMSNotFoundException");
    let key = kms.create_key().send().await.unwrap().key_metadata().unwrap().arn().unwrap().to_string();
    k.start_stream_encryption()
        .stream_name("secret")
        .encryption_type(EncryptionType::Kms)
        .key_id(&key)
        .send()
        .await
        .unwrap();
    wait_active(&k, "secret").await;
    let put = k.put_record().stream_name("secret").partition_key("p").data(Blob::new("s")).send().await.unwrap();
    assert_eq!(put.encryption_type(), Some(&EncryptionType::Kms));
    let summary = k.describe_stream_summary().stream_name("secret").send().await.unwrap();
    assert_eq!(summary.stream_description_summary().unwrap().key_id(), Some(key.as_str()));

    // A reader without kms:Decrypt cannot read the records.
    let (_, reader_cfg) = user_with_policy(
        &mws,
        "nokms",
        Some(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"kinesis:*","Resource":"*"}]}"#),
    )
    .await;
    let reader = Client::new(&reader_cfg);
    let it = reader
        .get_shard_iterator()
        .stream_name("secret")
        .shard_id("shardId-000000000000")
        .shard_iterator_type(ShardIteratorType::TrimHorizon)
        .send()
        .await
        .unwrap();
    let denied = reader.get_records().shard_iterator(it.shard_iterator().unwrap()).send().await.unwrap_err();
    assert_eq!(code(&denied.into_service_error()), "KMSAccessDeniedException");
    let ok = k.get_records().shard_iterator(it.shard_iterator().unwrap()).send().await.unwrap();
    assert_eq!(ok.records()[0].encryption_type(), Some(&EncryptionType::Kms));

    k.stop_stream_encryption()
        .stream_name("secret")
        .encryption_type(EncryptionType::Kms)
        .key_id(&key)
        .send()
        .await
        .unwrap();
    wait_active(&k, "secret").await;

    // Channels.
    let channel = k
        .create_channel()
        .channel_name("to-s3")
        .service_execution_role_arn(format!("arn:aws:iam::{ACCOUNT}:role/channel"))
        .stream_configuration_list(
            ChannelStreamConfiguration::builder()
                .stream_arn(arn("secret"))
                .record_configuration(
                    RecordConfiguration::builder().record_format_type(RecordFormatType::Json).build().unwrap(),
                )
                .build()
                .unwrap(),
        )
        .s3_destination_configuration(
            S3DestinationConfiguration::builder()
                .storage_configuration(
                    S3StorageConfiguration::builder()
                        .bucket_arn("arn:aws:s3:::channel-bucket")
                        .expected_bucket_owner(ACCOUNT)
                        .compression_type(aws_sdk_kinesis::types::S3CompressionType::Gzip)
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    let channel_arn = channel.channel_description().unwrap().channel_arn().to_string();
    assert_eq!(channel_arn, format!("arn:aws:kinesis:us-east-1:{ACCOUNT}:channel/to-s3"));
    tokio::time::sleep(Duration::from_millis(700)).await;
    let d = k.describe_channel().channel_arn(&channel_arn).send().await.unwrap();
    assert_eq!(d.channel_description().unwrap().channel_status().as_str(), "ACTIVE");
    let listed = k.list_channels().send().await.unwrap();
    assert_eq!(listed.channel_summaries().len(), 1);
    let updated = k
        .update_channel()
        .channel_arn(&channel_arn)
        .s3_destination_configuration(
            aws_sdk_kinesis::types::S3DestinationUpdateInput::builder().data_freshness_in_seconds(60).build().unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        updated.channel_description().unwrap().s3_destination_configuration().unwrap().data_freshness_in_seconds(),
        60
    );
    let blocked = k.delete_stream().stream_name("secret").send().await.unwrap_err();
    assert_eq!(code(&blocked.into_service_error()), "ResourceInUseException");
    k.delete_channel().channel_arn(&channel_arn).send().await.unwrap();

    // Account settings.
    let before = k.describe_account_settings().send().await.unwrap();
    assert_eq!(before.minimum_throughput_billing_commitment().unwrap().status().as_str(), "DISABLED");
    let on = k
        .update_account_settings()
        .minimum_throughput_billing_commitment(
            MinimumThroughputBillingCommitmentInput::builder()
                .status(MinimumThroughputBillingCommitmentInputStatus::Enabled)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let c = on.minimum_throughput_billing_commitment().unwrap();
    assert_eq!(c.status().as_str(), "ENABLED");
    assert!(c.earliest_allowed_end_at().is_some());
    mws.stop().await;
}

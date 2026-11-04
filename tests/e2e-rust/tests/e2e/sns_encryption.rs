//! SNS server-side encryption through the official Rust SDK: publishing to
//! a topic with `KmsMasterKeyId` needs `kms:GenerateDataKey*` and
//! `kms:Decrypt` on its key (SNS's `KMS*` errors otherwise), the AWS
//! managed key `alias/aws/sns` works through SNS for the whole account, and
//! AWS services publishing for a bucket need the key policy to allow them.

use std::time::Duration;

use aws_sdk_sns::error::ProvideErrorMetadata;
use aws_sdk_sns::Client;
use mws_e2e::{user_with_policy, Mws};
use serde_json::json;

fn code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

#[tokio::test]
async fn publishers_need_the_topic_key() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let sns = Client::new(&cfg);
    let kms = aws_sdk_kms::Client::new(&cfg);
    let key = kms.create_key().send().await.unwrap().key_metadata().unwrap().key_id().to_string();
    let topic = sns
        .create_topic()
        .name("secure")
        .attributes("KmsMasterKeyId", &key)
        .send()
        .await
        .unwrap()
        .topic_arn()
        .unwrap()
        .to_string();
    let attrs = sns.get_topic_attributes().topic_arn(&topic).send().await.unwrap();
    assert_eq!(attrs.attributes().unwrap()["KmsMasterKeyId"], key);
    sns.publish().topic_arn(&topic).message("from root").send().await.unwrap();

    // SNS permission alone is not enough.
    let publish_only = json!({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "sns:Publish", "Resource": "*"}
    ]});
    let (_, user_cfg) = user_with_policy(&mws, "publisher", Some(&publish_only.to_string())).await;
    let user_sns = Client::new(&user_cfg);
    let e = user_sns.publish().topic_arn(&topic).message("denied").send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "KMSAccessDenied");
    let e = user_sns
        .publish_batch()
        .topic_arn(&topic)
        .publish_batch_request_entries(
            aws_sdk_sns::types::PublishBatchRequestEntry::builder().id("1").message("m").build().unwrap(),
        )
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert_eq!(code(&e), "KMSAccessDenied");

    let iam = aws_sdk_iam::Client::new(&cfg);
    let with_key = json!({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": "sns:Publish", "Resource": "*"},
        {"Effect": "Allow", "Action": ["kms:GenerateDataKey*", "kms:Decrypt"], "Resource": "*"}
    ]});
    iam.put_user_policy()
        .user_name("publisher")
        .policy_name("inline")
        .policy_document(with_key.to_string())
        .send()
        .await
        .unwrap();
    user_sns.publish().topic_arn(&topic).message("allowed").send().await.unwrap();

    // A disabled key stops publishing.
    kms.disable_key().key_id(&key).send().await.unwrap();
    let e = sns.publish().topic_arn(&topic).message("x").send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "KMSDisabled");

    // The AWS managed key lets every principal in the account publish
    // through SNS, without IAM permissions for the key.
    let managed = sns
        .create_topic()
        .name("managed")
        .attributes("KmsMasterKeyId", "alias/aws/sns")
        .send()
        .await
        .unwrap()
        .topic_arn()
        .unwrap()
        .to_string();
    let (_, other_cfg) = user_with_policy(&mws, "other", Some(&publish_only.to_string())).await;
    Client::new(&other_cfg).publish().topic_arn(&managed).message("managed").send().await.unwrap();
    let aliases = kms.list_aliases().send().await.unwrap();
    assert!(aliases.aliases().iter().any(|a| a.alias_name() == Some("alias/aws/sns")));

    // A missing key.
    sns.set_topic_attributes()
        .topic_arn(&managed)
        .attribute_name("KmsMasterKeyId")
        .attribute_value("alias/nope")
        .send()
        .await
        .unwrap();
    let e = sns.publish().topic_arn(&managed).message("x").send().await.unwrap_err().into_service_error();
    assert_eq!(code(&e), "KMSNotFound");
    mws.stop().await;
}

#[tokio::test]
async fn s3_events_reach_encrypted_topics_only_when_the_key_policy_allows_s3() {
    use aws_sdk_s3::types::{Event, NotificationConfiguration, TopicConfiguration};
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let sns = Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let kms = aws_sdk_kms::Client::new(&cfg);
    let s3 = Mws::s3(&cfg);

    let root_only = json!({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "kms:*", "Resource": "*"}
    ]});
    let key_arn = kms
        .create_key()
        .policy(root_only.to_string())
        .send()
        .await
        .unwrap()
        .key_metadata()
        .unwrap()
        .arn()
        .unwrap()
        .to_string();
    let topic = sns
        .create_topic()
        .name("uploads")
        .attributes("KmsMasterKeyId", &key_arn)
        .send()
        .await
        .unwrap()
        .topic_arn()
        .unwrap()
        .to_string();
    let topic_policy = json!({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"}, "Action": "SNS:Publish", "Resource": topic,
        "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}}
    }]});
    sns.set_topic_attributes()
        .topic_arn(&topic)
        .attribute_name("Policy")
        .attribute_value(topic_policy.to_string())
        .send()
        .await
        .unwrap();

    let url = sqs.create_queue().queue_name("events").send().await.unwrap().queue_url().unwrap().to_string();
    let queue_arn = "arn:aws:sqs:us-east-1:123456789012:events";
    let queue_policy = json!({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sqs:SendMessage", "Resource": queue_arn
    }]});
    sqs.set_queue_attributes()
        .queue_url(&url)
        .attributes(aws_sdk_sqs::types::QueueAttributeName::Policy, queue_policy.to_string())
        .send()
        .await
        .unwrap();
    sns.subscribe()
        .topic_arn(&topic)
        .protocol("sqs")
        .endpoint(queue_arn)
        .attributes("RawMessageDelivery", "true")
        .send()
        .await
        .unwrap();

    s3.create_bucket().bucket("uploads").send().await.unwrap();
    s3.put_bucket_notification_configuration()
        .bucket("uploads")
        .notification_configuration(
            NotificationConfiguration::builder()
                .topic_configurations(
                    TopicConfiguration::builder().topic_arn(&topic).events(Event::S3ObjectCreated).build().unwrap(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    let drain = || async {
        let mut bodies = Vec::new();
        loop {
            let got = sqs.receive_message().queue_url(&url).max_number_of_messages(10).send().await.unwrap();
            if got.messages().is_empty() {
                return bodies;
            }
            for m in got.messages() {
                bodies.push(m.body().unwrap().to_string());
                sqs.delete_message().queue_url(&url).receipt_handle(m.receipt_handle().unwrap()).send().await.unwrap();
            }
        }
    };

    // The key policy does not let S3 use the key: the event is lost.
    s3.put_object().bucket("uploads").key("first").body(b"1".to_vec().into()).send().await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(drain().await.iter().all(|b| !b.contains("ObjectCreated")));

    let with_s3 = json!({"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "kms:*", "Resource": "*"},
        {"Effect": "Allow", "Principal": {"Service": "s3.amazonaws.com"},
         "Action": ["kms:GenerateDataKey*", "kms:Decrypt"], "Resource": "*"}
    ]});
    kms.put_key_policy().key_id(&key_arn).policy(with_s3.to_string()).send().await.unwrap();
    s3.put_object().bucket("uploads").key("second").body(b"2".to_vec().into()).send().await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let bodies = drain().await;
    assert!(bodies.iter().any(|b| b.contains("ObjectCreated") && b.contains("second")), "{bodies:#?}");
    mws.stop().await;
}

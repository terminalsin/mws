//! Amazon SQS through the official Rust SDK.

use std::time::{Duration, Instant};

use aws_sdk_sqs::error::ProvideErrorMetadata;
use aws_sdk_sqs::primitives::Blob;
use aws_sdk_sqs::types::{
    ChangeMessageVisibilityBatchRequestEntry, DeleteMessageBatchRequestEntry, MessageAttributeValue,
    MessageSystemAttributeName, MessageSystemAttributeNameForSends, MessageSystemAttributeValue, QueueAttributeName,
    SendMessageBatchRequestEntry,
};
use aws_sdk_sqs::Client;
use mws_e2e::{user_with_policy, Mws};

const ACCOUNT: &str = "123456789012";

async fn client(mws: &Mws) -> Client {
    Client::new(&mws.root_sdk_config().await)
}

fn code<E: ProvideErrorMetadata>(e: &E) -> String {
    e.code().unwrap_or_default().to_string()
}

async fn create(sqs: &Client, name: &str, attrs: &[(QueueAttributeName, &str)]) -> String {
    let mut req = sqs.create_queue().queue_name(name);
    for (k, v) in attrs {
        req = req.attributes(k.clone(), *v);
    }
    req.send().await.unwrap().queue_url().unwrap().to_string()
}

async fn attr(sqs: &Client, url: &str, name: QueueAttributeName) -> Option<String> {
    let out = sqs.get_queue_attributes().queue_url(url).attribute_names(name.clone()).send().await.unwrap();
    out.attributes().and_then(|a| a.get(&name)).cloned()
}

async fn advance_seconds(mws: &Mws, seconds: i64) {
    let body = format!(r#"{{"advanceSeconds":{seconds}}}"#);
    let (status, _) = mws.control("POST", "/_mws/clock", Some(&body)).await;
    assert_eq!(status, 200);
}

#[tokio::test]
async fn queue_lifecycle_attributes_and_tags() {
    let mws = Mws::start().await;
    let sqs = client(&mws).await;
    let url = sqs
        .create_queue()
        .queue_name("orders")
        .attributes(QueueAttributeName::VisibilityTimeout, "45")
        .tags("team", "web")
        .send()
        .await
        .unwrap()
        .queue_url()
        .unwrap()
        .to_string();
    assert_eq!(url, format!("{}/{ACCOUNT}/orders", mws.endpoint));
    // Same attributes: the existing queue. Different ones: an error.
    let again = sqs
        .create_queue()
        .queue_name("orders")
        .attributes(QueueAttributeName::VisibilityTimeout, "45")
        .send()
        .await
        .unwrap();
    assert_eq!(again.queue_url(), Some(url.as_str()));
    let clash = sqs
        .create_queue()
        .queue_name("orders")
        .attributes(QueueAttributeName::VisibilityTimeout, "60")
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert!(clash.is_queue_name_exists());
    assert_eq!(code(&clash), "QueueAlreadyExists");

    let bad = sqs.create_queue().queue_name("bad name").send().await.unwrap_err();
    assert_eq!(code(&bad), "InvalidParameterValue");
    let fifo_name = sqs.create_queue().queue_name("plain.fifo").send().await.unwrap_err();
    assert_eq!(code(&fifo_name), "InvalidParameterValue");
    let range = sqs
        .create_queue()
        .queue_name("x")
        .attributes(QueueAttributeName::DelaySeconds, "901")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&range), "InvalidAttributeValue");
    assert_eq!(range.message(), Some("Invalid value for the parameter DelaySeconds."));
    let fifo_only = sqs
        .create_queue()
        .queue_name("x")
        .attributes(QueueAttributeName::ContentBasedDeduplication, "true")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&fifo_only), "InvalidAttributeName");

    let got = sqs.get_queue_url().queue_name("orders").send().await.unwrap();
    assert_eq!(got.queue_url(), Some(url.as_str()));
    let missing = sqs.get_queue_url().queue_name("nope").send().await.unwrap_err().into_service_error();
    assert!(missing.is_queue_does_not_exist());
    assert_eq!(code(&missing), "AWS.SimpleQueueService.NonExistentQueue");
    assert_eq!(missing.message(), Some("The specified queue does not exist."));

    let all = sqs.get_queue_attributes().queue_url(&url).attribute_names(QueueAttributeName::All).send().await.unwrap();
    let all = all.attributes().unwrap();
    assert_eq!(all[&QueueAttributeName::VisibilityTimeout], "45");
    assert_eq!(all[&QueueAttributeName::DelaySeconds], "0");
    assert_eq!(all[&QueueAttributeName::MaximumMessageSize], "1048576");
    assert_eq!(all[&QueueAttributeName::MessageRetentionPeriod], "345600");
    assert_eq!(all[&QueueAttributeName::SqsManagedSseEnabled], "true");
    assert_eq!(all[&QueueAttributeName::QueueArn], format!("arn:aws:sqs:us-east-1:{ACCOUNT}:orders"));
    assert_eq!(all[&QueueAttributeName::ApproximateNumberOfMessages], "0");
    assert!(!all.contains_key(&QueueAttributeName::FifoQueue));
    assert!(!all.contains_key(&QueueAttributeName::Policy));

    sqs.set_queue_attributes()
        .queue_url(&url)
        .attributes(QueueAttributeName::ReceiveMessageWaitTimeSeconds, "5")
        .send()
        .await
        .unwrap();
    assert_eq!(attr(&sqs, &url, QueueAttributeName::ReceiveMessageWaitTimeSeconds).await.as_deref(), Some("5"));
    let read_only = sqs
        .set_queue_attributes()
        .queue_url(&url)
        .attributes(QueueAttributeName::QueueArn, "x")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&read_only), "InvalidAttributeName");

    sqs.tag_queue().queue_url(&url).tags("env", "prod").send().await.unwrap();
    sqs.untag_queue().queue_url(&url).tag_keys("team").send().await.unwrap();
    let tags = sqs.list_queue_tags().queue_url(&url).send().await.unwrap();
    let tags = tags.tags().unwrap();
    assert_eq!(tags.len(), 1);
    assert_eq!(tags["env"], "prod");

    create(&sqs, "orders-dlq", &[]).await;
    create(&sqs, "payments", &[]).await;
    let listed = sqs.list_queues().queue_name_prefix("orders").send().await.unwrap();
    assert_eq!(listed.queue_urls().len(), 2);
    let page = sqs.list_queues().max_results(2).send().await.unwrap();
    assert_eq!(page.queue_urls().len(), 2);
    let rest = sqs.list_queues().max_results(2).next_token(page.next_token().unwrap()).send().await.unwrap();
    assert_eq!(rest.queue_urls(), [format!("{}/{ACCOUNT}/payments", mws.endpoint)]);
    assert!(rest.next_token().is_none());

    sqs.delete_queue().queue_url(&url).send().await.unwrap();
    let gone = sqs.get_queue_attributes().queue_url(&url).send().await.unwrap_err().into_service_error();
    assert!(gone.is_queue_does_not_exist());
    let recently = sqs.create_queue().queue_name("orders").send().await.unwrap_err().into_service_error();
    assert!(recently.is_queue_deleted_recently());
    assert_eq!(code(&recently), "AWS.SimpleQueueService.QueueDeletedRecently");
    advance_seconds(&mws, 61).await;
    create(&sqs, "orders", &[]).await;
    let bad_url = sqs.purge_queue().queue_url("http://localhost/orders").send().await.unwrap_err();
    assert_eq!(code(&bad_url), "InvalidAddress");
}

#[tokio::test]
async fn send_receive_change_visibility_and_delete() {
    let mws = Mws::start().await;
    let sqs = client(&mws).await;
    let url = create(&sqs, "work", &[]).await;
    let sent = sqs
        .send_message()
        .queue_url(&url)
        .message_body("hello")
        .message_attributes(
            "kind",
            MessageAttributeValue::builder().data_type("String").string_value("greeting").build().unwrap(),
        )
        .message_attributes(
            "blob",
            MessageAttributeValue::builder().data_type("Binary").binary_value(Blob::new(b"\x00\x01")).build().unwrap(),
        )
        .message_attributes(
            "n.count",
            MessageAttributeValue::builder().data_type("Number.int").string_value("3").build().unwrap(),
        )
        .message_system_attributes(
            MessageSystemAttributeNameForSends::AwsTraceHeader,
            MessageSystemAttributeValue::builder()
                .data_type("String")
                .string_value("Root=1-5759e988-bd862e3fe1be46a994272793")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(sent.md5_of_message_body(), Some("5d41402abc4b2a76b9719d911017c592"));
    assert!(sent.md5_of_message_attributes().is_some());
    assert!(sent.md5_of_message_system_attributes().is_some());
    assert!(sent.sequence_number().is_none());
    let id = sent.message_id().unwrap().to_string();

    let got = sqs
        .receive_message()
        .queue_url(&url)
        .message_system_attribute_names(MessageSystemAttributeName::All)
        .message_attribute_names("All")
        .visibility_timeout(30)
        .send()
        .await
        .unwrap();
    let m = &got.messages()[0];
    assert_eq!(m.message_id(), Some(id.as_str()));
    assert_eq!(m.body(), Some("hello"));
    assert_eq!(m.md5_of_body(), Some("5d41402abc4b2a76b9719d911017c592"));
    assert_eq!(m.md5_of_message_attributes(), sent.md5_of_message_attributes());
    let attrs = m.attributes().unwrap();
    assert_eq!(attrs[&MessageSystemAttributeName::ApproximateReceiveCount], "1");
    assert_eq!(attrs[&MessageSystemAttributeName::AwsTraceHeader], "Root=1-5759e988-bd862e3fe1be46a994272793");
    assert!(attrs.contains_key(&MessageSystemAttributeName::SentTimestamp));
    assert!(attrs.contains_key(&MessageSystemAttributeName::SenderId));
    let user = m.message_attributes().unwrap();
    assert_eq!(user["blob"].binary_value().map(|b| b.as_ref().to_vec()), Some(vec![0, 1]));
    assert_eq!(user["n.count"].string_value(), Some("3"));
    let handle = m.receipt_handle().unwrap().to_string();

    // A prefix filter returns only matching attributes, with their digest.
    sqs.change_message_visibility().queue_url(&url).receipt_handle(&handle).visibility_timeout(0).send().await.unwrap();
    let again = sqs.receive_message().queue_url(&url).message_attribute_names("n.*").send().await.unwrap();
    let m2 = &again.messages()[0];
    assert_eq!(m2.message_attributes().unwrap().len(), 1);
    assert_ne!(m2.md5_of_message_attributes(), sent.md5_of_message_attributes());
    assert_ne!(m2.receipt_handle(), Some(handle.as_str()));
    // In flight now: nothing to receive, one not visible.
    assert!(sqs.receive_message().queue_url(&url).send().await.unwrap().messages().is_empty());
    assert_eq!(attr(&sqs, &url, QueueAttributeName::ApproximateNumberOfMessagesNotVisible).await.as_deref(), Some("1"));

    // The old handle no longer acts on the message.
    let stale = sqs
        .change_message_visibility()
        .queue_url(&url)
        .receipt_handle(&handle)
        .visibility_timeout(10)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&stale), "InvalidParameterValue");
    assert_eq!(
        stale.message(),
        Some(
            format!("Value {handle} for parameter ReceiptHandle is invalid. Reason: The receipt handle has expired.")
                .as_str()
        )
    );
    let too_long = sqs
        .change_message_visibility()
        .queue_url(&url)
        .receipt_handle(m2.receipt_handle().unwrap())
        .visibility_timeout(43_201)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&too_long), "InvalidParameterValue");
    let invalid =
        sqs.delete_message().queue_url(&url).receipt_handle("garbage").send().await.unwrap_err().into_service_error();
    assert!(invalid.is_receipt_handle_is_invalid());
    sqs.delete_message().queue_url(&url).receipt_handle(m2.receipt_handle().unwrap()).send().await.unwrap();
    assert_eq!(attr(&sqs, &url, QueueAttributeName::ApproximateNumberOfMessagesNotVisible).await.as_deref(), Some("0"));

    let empty = sqs.send_message().queue_url(&url).message_body("").send().await.unwrap_err();
    assert_eq!(code(&empty), "MissingParameter");
    let control =
        sqs.send_message().queue_url(&url).message_body("bad\u{1}char").send().await.unwrap_err().into_service_error();
    assert!(control.is_invalid_message_contents());
    let too_many = sqs.receive_message().queue_url(&url).max_number_of_messages(11).send().await.unwrap_err();
    assert_eq!(code(&too_many), "InvalidParameterValue");
    assert_eq!(
        too_many.message(),
        Some("Value 11 for parameter MaxNumberOfMessages is invalid. Reason: Must be between 1 and 10, if provided.")
    );
    let bad_attr = sqs
        .send_message()
        .queue_url(&url)
        .message_body("x")
        .message_attributes(
            "n",
            MessageAttributeValue::builder().data_type("Number").string_value("abc").build().unwrap(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&bad_attr), "InvalidParameterValue");
    let small = create(&sqs, "small", &[(QueueAttributeName::MaximumMessageSize, "1024")]).await;
    let big = sqs.send_message().queue_url(&small).message_body("x".repeat(1025)).send().await.unwrap_err();
    assert_eq!(code(&big), "InvalidParameterValue");
}

#[tokio::test]
async fn batches() {
    let mws = Mws::start().await;
    let sqs = client(&mws).await;
    let url = create(&sqs, "batch", &[]).await;
    let entry =
        |id: &str, body: &str| SendMessageBatchRequestEntry::builder().id(id).message_body(body).build().unwrap();
    let out = sqs
        .send_message_batch()
        .queue_url(&url)
        .entries(entry("a", "one"))
        .entries(entry("b", "two"))
        .entries(
            SendMessageBatchRequestEntry::builder().id("c").message_body("three").delay_seconds(901).build().unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(out.successful().len(), 2);
    assert_eq!(out.failed().len(), 1);
    assert_eq!(out.failed()[0].id(), "c");
    assert_eq!(out.failed()[0].code(), "InvalidParameterValue");
    assert!(out.failed()[0].sender_fault());

    let dup = sqs
        .send_message_batch()
        .queue_url(&url)
        .entries(entry("a", "1"))
        .entries(entry("a", "2"))
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert!(dup.is_batch_entry_ids_not_distinct());
    let mut eleven = sqs.send_message_batch().queue_url(&url);
    for i in 0..11 {
        eleven = eleven.entries(entry(&format!("e{i}"), "x"));
    }
    let many = eleven.send().await.unwrap_err().into_service_error();
    assert!(many.is_too_many_entries_in_batch_request());
    let bad_id = sqs
        .send_message_batch()
        .queue_url(&url)
        .entries(entry("no spaces", "x"))
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert!(bad_id.is_invalid_batch_entry_id());
    let empty = sqs
        .delete_message_batch()
        .queue_url(&url)
        .set_entries(Some(vec![]))
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert!(empty.is_empty_batch_request());
    let huge = sqs
        .send_message_batch()
        .queue_url(&url)
        .entries(entry("a", &"x".repeat(600_000)))
        .entries(entry("b", &"y".repeat(600_000)))
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert!(huge.is_batch_request_too_long());

    let got = sqs.receive_message().queue_url(&url).max_number_of_messages(10).send().await.unwrap();
    assert_eq!(got.messages().len(), 2);
    let handles: Vec<String> = got.messages().iter().map(|m| m.receipt_handle().unwrap().to_string()).collect();
    let changed = sqs
        .change_message_visibility_batch()
        .queue_url(&url)
        .entries(
            ChangeMessageVisibilityBatchRequestEntry::builder()
                .id("x")
                .receipt_handle(&handles[0])
                .visibility_timeout(0)
                .build()
                .unwrap(),
        )
        .entries(
            ChangeMessageVisibilityBatchRequestEntry::builder()
                .id("y")
                .receipt_handle("nope")
                .visibility_timeout(0)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(changed.successful()[0].id(), "x");
    assert_eq!(changed.failed()[0].code(), "ReceiptHandleIsInvalid");
    let deleted = sqs
        .delete_message_batch()
        .queue_url(&url)
        .entries(DeleteMessageBatchRequestEntry::builder().id("1").receipt_handle(&handles[0]).build().unwrap())
        .entries(DeleteMessageBatchRequestEntry::builder().id("2").receipt_handle(&handles[1]).build().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.successful().len(), 2);
    assert_eq!(attr(&sqs, &url, QueueAttributeName::ApproximateNumberOfMessages).await.as_deref(), Some("0"));
}

#[tokio::test]
async fn delays_long_polling_retention_and_purge() {
    let mws = Mws::start().await;
    let sqs = client(&mws).await;
    let url = create(&sqs, "poll", &[]).await;
    sqs.send_message().queue_url(&url).message_body("later").delay_seconds(1).send().await.unwrap();
    assert_eq!(attr(&sqs, &url, QueueAttributeName::ApproximateNumberOfMessagesDelayed).await.as_deref(), Some("1"));
    assert!(sqs.receive_message().queue_url(&url).send().await.unwrap().messages().is_empty());
    // A long poll waits out the delay.
    let started = Instant::now();
    let got = sqs.receive_message().queue_url(&url).wait_time_seconds(5).send().await.unwrap();
    assert_eq!(got.messages()[0].body(), Some("later"));
    assert!(started.elapsed() < Duration::from_secs(4));
    sqs.delete_message()
        .queue_url(&url)
        .receipt_handle(got.messages()[0].receipt_handle().unwrap())
        .send()
        .await
        .unwrap();

    // ... and wakes up when a message arrives.
    let poller = {
        let sqs = sqs.clone();
        let url = url.clone();
        tokio::spawn(async move { sqs.receive_message().queue_url(&url).wait_time_seconds(10).send().await.unwrap() })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    let started = Instant::now();
    sqs.send_message().queue_url(&url).message_body("ping").send().await.unwrap();
    let got = poller.await.unwrap();
    assert_eq!(got.messages()[0].body(), Some("ping"));
    assert!(started.elapsed() < Duration::from_secs(2));
    // An empty long poll returns after the wait.
    let started = Instant::now();
    let none = sqs.receive_message().queue_url(&url).wait_time_seconds(1).send().await.unwrap();
    assert!(none.messages().is_empty());
    assert!(started.elapsed() >= Duration::from_millis(900));

    // Messages expire after the retention period.
    sqs.set_queue_attributes()
        .queue_url(&url)
        .attributes(QueueAttributeName::MessageRetentionPeriod, "60")
        .send()
        .await
        .unwrap();
    sqs.send_message().queue_url(&url).message_body("old").send().await.unwrap();
    advance_seconds(&mws, 61).await;
    assert_eq!(attr(&sqs, &url, QueueAttributeName::ApproximateNumberOfMessages).await.as_deref(), Some("0"));

    sqs.send_message().queue_url(&url).message_body("a").send().await.unwrap();
    sqs.purge_queue().queue_url(&url).send().await.unwrap();
    assert_eq!(attr(&sqs, &url, QueueAttributeName::ApproximateNumberOfMessages).await.as_deref(), Some("0"));
    let busy = sqs.purge_queue().queue_url(&url).send().await.unwrap_err().into_service_error();
    assert!(busy.is_purge_queue_in_progress());
    assert_eq!(code(&busy), "AWS.SimpleQueueService.PurgeQueueInProgress");
}

#[tokio::test]
async fn fifo_queues() {
    let mws = Mws::start().await;
    let sqs = client(&mws).await;
    let url = create(&sqs, "jobs.fifo", &[(QueueAttributeName::FifoQueue, "true")]).await;
    let all = sqs.get_queue_attributes().queue_url(&url).attribute_names(QueueAttributeName::All).send().await.unwrap();
    let all = all.attributes().unwrap();
    assert_eq!(all[&QueueAttributeName::FifoQueue], "true");
    assert_eq!(all[&QueueAttributeName::ContentBasedDeduplication], "false");
    assert_eq!(all[&QueueAttributeName::DeduplicationScope], "queue");
    assert_eq!(all[&QueueAttributeName::FifoThroughputLimit], "perQueue");

    let no_group =
        sqs.send_message().queue_url(&url).message_body("x").message_deduplication_id("d").send().await.unwrap_err();
    assert_eq!(code(&no_group), "MissingParameter");
    let no_dedup = sqs.send_message().queue_url(&url).message_body("x").message_group_id("g").send().await.unwrap_err();
    assert_eq!(code(&no_dedup), "InvalidParameterValue");
    let delay = sqs
        .send_message()
        .queue_url(&url)
        .message_body("x")
        .message_group_id("g")
        .message_deduplication_id("d")
        .delay_seconds(5)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&delay), "InvalidParameterValue");

    let send = |body: &'static str, group: &'static str, dedup: &'static str| {
        let sqs = sqs.clone();
        let url = url.clone();
        async move {
            sqs.send_message()
                .queue_url(&url)
                .message_body(body)
                .message_group_id(group)
                .message_deduplication_id(dedup)
                .send()
                .await
                .unwrap()
        }
    };
    let first = send("g1-1", "g1", "a").await;
    let dup = send("g1-1 again", "g1", "a").await;
    assert_eq!(dup.message_id(), first.message_id());
    assert_eq!(dup.sequence_number(), first.sequence_number());
    let second = send("g1-2", "g1", "b").await;
    send("g2-1", "g2", "c").await;
    let s1: u128 = first.sequence_number().unwrap().parse().unwrap();
    let s2: u128 = second.sequence_number().unwrap().parse().unwrap();
    assert!(s2 > s1);
    assert_eq!(first.sequence_number().unwrap().len(), 20);

    let one = sqs
        .receive_message()
        .queue_url(&url)
        .receive_request_attempt_id("attempt-1")
        .message_system_attribute_names(MessageSystemAttributeName::All)
        .send()
        .await
        .unwrap();
    let m = &one.messages()[0];
    assert_eq!(m.body(), Some("g1-1"));
    let a = m.attributes().unwrap();
    assert_eq!(a[&MessageSystemAttributeName::MessageGroupId], "g1");
    assert_eq!(a[&MessageSystemAttributeName::MessageDeduplicationId], "a");
    assert_eq!(a[&MessageSystemAttributeName::SequenceNumber], first.sequence_number().unwrap());
    // A retry with the same attempt id gets the same message and handle.
    let retry = sqs.receive_message().queue_url(&url).receive_request_attempt_id("attempt-1").send().await.unwrap();
    assert_eq!(retry.messages()[0].receipt_handle(), m.receipt_handle());
    // g1 has a message in flight, so only g2 is available.
    let rest = sqs.receive_message().queue_url(&url).max_number_of_messages(10).send().await.unwrap();
    let bodies: Vec<_> = rest.messages().iter().filter_map(|m| m.body()).collect();
    assert_eq!(bodies, ["g2-1"]);
    sqs.delete_message().queue_url(&url).receipt_handle(m.receipt_handle().unwrap()).send().await.unwrap();
    let next = sqs.receive_message().queue_url(&url).send().await.unwrap();
    assert_eq!(next.messages()[0].body(), Some("g1-2"));

    // Content-based deduplication hashes the body.
    let cbd = create(
        &sqs,
        "cbd.fifo",
        &[(QueueAttributeName::FifoQueue, "true"), (QueueAttributeName::ContentBasedDeduplication, "true")],
    )
    .await;
    let a = sqs.send_message().queue_url(&cbd).message_body("same").message_group_id("g").send().await.unwrap();
    let b = sqs.send_message().queue_url(&cbd).message_body("same").message_group_id("g").send().await.unwrap();
    assert_eq!(a.message_id(), b.message_id());
    assert_eq!(attr(&sqs, &cbd, QueueAttributeName::ApproximateNumberOfMessages).await.as_deref(), Some("1"));
}

#[tokio::test]
async fn dead_letter_queues_and_message_move_tasks() {
    let mws = Mws::start().await;
    let sqs = client(&mws).await;
    let dlq = create(&sqs, "dlq", &[]).await;
    let dlq_arn = format!("arn:aws:sqs:us-east-1:{ACCOUNT}:dlq");
    let policy = format!(r#"{{"deadLetterTargetArn":"{dlq_arn}","maxReceiveCount":"1"}}"#);
    let src = create(&sqs, "src", &[(QueueAttributeName::RedrivePolicy, &policy)]).await;
    let src_arn = format!("arn:aws:sqs:us-east-1:{ACCOUNT}:src");
    let stored = attr(&sqs, &src, QueueAttributeName::RedrivePolicy).await.unwrap();
    assert_eq!(stored, format!(r#"{{"deadLetterTargetArn":"{dlq_arn}","maxReceiveCount":1}}"#));
    let missing_target = sqs
        .create_queue()
        .queue_name("other")
        .attributes(
            QueueAttributeName::RedrivePolicy,
            format!(r#"{{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:{ACCOUNT}:nope","maxReceiveCount":1}}"#),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&missing_target), "InvalidParameterValue");
    let sources = sqs.list_dead_letter_source_queues().queue_url(&dlq).send().await.unwrap();
    assert_eq!(sources.queue_urls(), std::slice::from_ref(&src));

    sqs.send_message().queue_url(&src).message_body("poison").send().await.unwrap();
    let first = sqs.receive_message().queue_url(&src).visibility_timeout(0).send().await.unwrap();
    assert_eq!(first.messages().len(), 1);
    // Received maxReceiveCount times: the next receive moves it.
    assert!(sqs.receive_message().queue_url(&src).send().await.unwrap().messages().is_empty());
    let dead = sqs
        .receive_message()
        .queue_url(&dlq)
        .message_system_attribute_names(MessageSystemAttributeName::DeadLetterQueueSourceArn)
        .visibility_timeout(0)
        .send()
        .await
        .unwrap();
    let m = &dead.messages()[0];
    assert_eq!(m.body(), Some("poison"));
    assert_eq!(m.message_id(), first.messages()[0].message_id());
    assert_eq!(m.attributes().unwrap()[&MessageSystemAttributeName::DeadLetterQueueSourceArn], src_arn);

    // Redrive back to the source queue.
    let not_dlq = sqs.start_message_move_task().source_arn(&src_arn).send().await.unwrap_err().into_service_error();
    assert!(not_dlq.is_unsupported_operation());
    let started = sqs.start_message_move_task().source_arn(&dlq_arn).send().await.unwrap();
    assert!(started.task_handle().is_some());
    let tasks = sqs.list_message_move_tasks().source_arn(&dlq_arn).send().await.unwrap();
    let t = &tasks.results()[0];
    assert_eq!(t.status(), Some("COMPLETED"));
    assert_eq!(t.approximate_number_of_messages_moved(), 1);
    assert_eq!(t.approximate_number_of_messages_to_move(), Some(1));
    let back = sqs.receive_message().queue_url(&src).send().await.unwrap();
    assert_eq!(back.messages()[0].body(), Some("poison"));
    let done = sqs
        .cancel_message_move_task()
        .task_handle(started.task_handle().unwrap())
        .send()
        .await
        .unwrap_err()
        .into_service_error();
    assert!(done.is_unsupported_operation());

    // A rate-limited task runs over time and can be cancelled.
    let custom = create(&sqs, "custom", &[]).await;
    for i in 0..5 {
        sqs.send_message().queue_url(&dlq).message_body(format!("m{i}")).send().await.unwrap();
    }
    let slow = sqs
        .start_message_move_task()
        .source_arn(&dlq_arn)
        .destination_arn(format!("arn:aws:sqs:us-east-1:{ACCOUNT}:custom"))
        .max_number_of_messages_per_second(1)
        .send()
        .await
        .unwrap();
    let twice = sqs.start_message_move_task().source_arn(&dlq_arn).send().await.unwrap_err().into_service_error();
    assert!(twice.is_unsupported_operation());
    let running = sqs.list_message_move_tasks().source_arn(&dlq_arn).max_results(10).send().await.unwrap();
    assert_eq!(running.results().len(), 2);
    assert_eq!(running.results()[0].status(), Some("RUNNING"));
    assert_eq!(running.results()[0].approximate_number_of_messages_to_move(), Some(5));
    let cancelled = sqs.cancel_message_move_task().task_handle(slow.task_handle().unwrap()).send().await.unwrap();
    assert!(cancelled.approximate_number_of_messages_moved() < 5);
    let listed = sqs.list_message_move_tasks().source_arn(&dlq_arn).send().await.unwrap();
    assert_eq!(listed.results()[0].status(), Some("CANCELLED"));
    let unknown = sqs.cancel_message_move_task().task_handle("bm9wZQ==").send().await.unwrap_err().into_service_error();
    assert!(unknown.is_resource_not_found_exception());
    let _ = custom;
}

#[tokio::test]
async fn iam_queue_policies_and_permissions() {
    let mws = Mws::start().await;
    let sqs = client(&mws).await;
    let url = create(&sqs, "shared", &[]).await;
    let arn = format!("arn:aws:sqs:us-east-1:{ACCOUNT}:shared");
    let (_, cfg) = user_with_policy(&mws, "bob", None).await;
    let bob = Client::new(&cfg);
    let denied = bob.send_message().queue_url(&url).message_body("x").send().await.unwrap_err();
    assert_eq!(code(&denied), "AccessDenied");
    assert!(denied.message().unwrap().contains("is not authorized to perform: sqs:SendMessage"));

    // The queue policy can grant on its own.
    let policy = format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Principal":{{"AWS":"arn:aws:iam::{ACCOUNT}:user/bob"}},"Action":"sqs:SendMessage","Resource":"{arn}"}}]}}"#
    );
    sqs.set_queue_attributes().queue_url(&url).attributes(QueueAttributeName::Policy, &policy).send().await.unwrap();
    bob.send_message().queue_url(&url).message_body("x").send().await.unwrap();
    assert_eq!(code(&bob.receive_message().queue_url(&url).send().await.unwrap_err()), "AccessDenied");
    let bad_policy = sqs
        .set_queue_attributes()
        .queue_url(&url)
        .attributes(QueueAttributeName::Policy, "{")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&bad_policy), "InvalidAttributeValue");

    // AddPermission / RemovePermission edit the policy by label.
    sqs.add_permission()
        .queue_url(&url)
        .label("partners")
        .aws_account_ids("111122223333")
        .actions("ReceiveMessage")
        .actions("DeleteMessage")
        .send()
        .await
        .unwrap();
    let doc: serde_json::Value =
        serde_json::from_str(&attr(&sqs, &url, QueueAttributeName::Policy).await.unwrap()).unwrap();
    let st = doc["Statement"].as_array().unwrap();
    assert_eq!(st.len(), 2);
    assert_eq!(st[1]["Sid"], "partners");
    assert_eq!(st[1]["Principal"]["AWS"], "arn:aws:iam::111122223333:root");
    assert_eq!(st[1]["Action"], serde_json::json!(["SQS:ReceiveMessage", "SQS:DeleteMessage"]));
    let dup = sqs
        .add_permission()
        .queue_url(&url)
        .label("partners")
        .aws_account_ids("111122223333")
        .actions("SendMessage")
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&dup), "InvalidParameterValue");
    sqs.remove_permission().queue_url(&url).label("partners").send().await.unwrap();
    let missing = sqs.remove_permission().queue_url(&url).label("partners").send().await.unwrap_err();
    assert_eq!(code(&missing), "InvalidParameterValue");

    // ABAC on queue tags.
    let tagged = sqs.create_queue().queue_name("web-jobs").tags("team", "web").send().await.unwrap();
    let tagged = tagged.queue_url().unwrap();
    let other = create(&sqs, "ops-jobs", &[]).await;
    let (_, cfg) = user_with_policy(
        &mws,
        "carol",
        Some(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"*","Condition":{"StringEquals":{"aws:ResourceTag/team":"web"}}}]}"#),
    )
    .await;
    let carol = Client::new(&cfg);
    carol.send_message().queue_url(tagged).message_body("ok").send().await.unwrap();
    assert_eq!(
        code(&carol.send_message().queue_url(&other).message_body("no").send().await.unwrap_err()),
        "AccessDenied"
    );
    // Creating with tags needs sqs:TagQueue too, checked against the request tags.
    let (_, cfg) = user_with_policy(
        &mws,
        "dave",
        Some(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:CreateQueue","Resource":"*"}]}"#),
    )
    .await;
    let dave = Client::new(&cfg);
    dave.create_queue().queue_name("dave-plain").send().await.unwrap();
    let tag_denied = dave.create_queue().queue_name("dave-tagged").tags("a", "b").send().await.unwrap_err();
    assert_eq!(code(&tag_denied), "AccessDenied");
}

#[tokio::test]
async fn sse_kms_queues() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let sqs = Client::new(&cfg);
    let kms = aws_sdk_kms::Client::new(&cfg);
    let key = kms.create_key().send().await.unwrap().key_metadata().unwrap().key_id().to_string();
    let url = create(&sqs, "secure", &[(QueueAttributeName::KmsMasterKeyId, &key)]).await;
    let all = sqs.get_queue_attributes().queue_url(&url).attribute_names(QueueAttributeName::All).send().await.unwrap();
    let all = all.attributes().unwrap();
    assert_eq!(all[&QueueAttributeName::KmsMasterKeyId], key);
    assert_eq!(all[&QueueAttributeName::KmsDataKeyReusePeriodSeconds], "300");
    assert_eq!(all[&QueueAttributeName::SqsManagedSseEnabled], "false");
    sqs.send_message().queue_url(&url).message_body("secret").send().await.unwrap();
    let got = sqs.receive_message().queue_url(&url).send().await.unwrap();
    assert_eq!(got.messages()[0].body(), Some("secret"));

    // Senders need kms:GenerateDataKey on the key, receivers kms:Decrypt.
    let (_, cfg) = user_with_policy(
        &mws,
        "eve",
        Some(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"*"}]}"#),
    )
    .await;
    let eve = Client::new(&cfg);
    let denied = eve.send_message().queue_url(&url).message_body("x").send().await.unwrap_err().into_service_error();
    assert!(denied.is_kms_access_denied());
    assert_eq!(code(&denied), "KMS.AccessDeniedException");
    let received = eve.receive_message().queue_url(&url).visibility_timeout(0).send().await;
    assert!(received.unwrap().messages().is_empty()); // still in flight from root's receive

    kms.disable_key().key_id(&key).send().await.unwrap();
    let disabled = create(&sqs, "secure2", &[(QueueAttributeName::KmsMasterKeyId, &key)]).await;
    let err = sqs.send_message().queue_url(&disabled).message_body("x").send().await.unwrap_err().into_service_error();
    assert!(err.is_kms_disabled());
    assert_eq!(code(&err), "KMS.DisabledException");

    // The AWS managed key works for the account's own principals.
    let managed = create(&sqs, "managed", &[(QueueAttributeName::KmsMasterKeyId, "alias/aws/sqs")]).await;
    sqs.send_message().queue_url(&managed).message_body("m").send().await.unwrap();
    assert_eq!(sqs.receive_message().queue_url(&managed).send().await.unwrap().messages().len(), 1);
}

#[tokio::test]
async fn state_survives_export_and_import() {
    let mws = Mws::start().await;
    let sqs = client(&mws).await;
    let url = create(&sqs, "persist", &[]).await;
    sqs.send_message().queue_url(&url).message_body("kept").send().await.unwrap();
    let (status, snapshot) = mws.control("GET", "/_mws/state", None).await;
    assert_eq!(status, 200);
    let (status, _) = mws.control("POST", "/_mws/reset?to=empty", None).await;
    assert_eq!(status, 200);
    assert!(sqs.get_queue_url().queue_name("persist").send().await.is_err());
    let (status, _) = mws.control("PUT", "/_mws/state", Some(&snapshot.to_string())).await;
    assert_eq!(status, 200);
    let got = sqs.receive_message().queue_url(&url).send().await.unwrap();
    assert_eq!(got.messages()[0].body(), Some("kept"));
}

#[tokio::test]
async fn receipt_handle_errors() {
    let mws = Mws::start().await;
    let sqs = client(&mws).await;
    let fifo = create(
        &sqs,
        "handles.fifo",
        &[(QueueAttributeName::FifoQueue, "true"), (QueueAttributeName::ContentBasedDeduplication, "true")],
    )
    .await;
    let other = create(&sqs, "handles-other", &[]).await;
    sqs.send_message().queue_url(&fifo).message_body("a").message_group_id("g").send().await.unwrap();
    let got = sqs.receive_message().queue_url(&fifo).visibility_timeout(0).send().await.unwrap();
    let handle = got.messages()[0].receipt_handle().unwrap().to_string();
    let expired =
        format!("Value {handle} for parameter ReceiptHandle is invalid. Reason: The receipt handle has expired.");

    // A FIFO handle stops working when the visibility timeout ends.
    let e = sqs.delete_message().queue_url(&fifo).receipt_handle(&handle).send().await.unwrap_err();
    assert_eq!(code(&e), "InvalidParameterValue");
    assert_eq!(e.message(), Some(expired.as_str()));
    let e = sqs
        .change_message_visibility()
        .queue_url(&fifo)
        .receipt_handle(&handle)
        .visibility_timeout(5)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e), "InvalidParameterValue");
    assert_eq!(e.message(), Some(expired.as_str()));
    // Batch entries carry ReceiptHandleIsInvalid with the bare reason.
    let batch = sqs
        .delete_message_batch()
        .queue_url(&fifo)
        .entries(DeleteMessageBatchRequestEntry::builder().id("a").receipt_handle(&handle).build().unwrap())
        .send()
        .await
        .unwrap();
    let failed = &batch.failed()[0];
    assert_eq!(failed.code(), "ReceiptHandleIsInvalid");
    assert_eq!(failed.message(), Some("The receipt handle has expired."));
    assert!(failed.sender_fault());

    // A handle of another queue.
    let e = sqs.delete_message().queue_url(&other).receipt_handle(&handle).send().await.unwrap_err();
    assert!(e.as_service_error().is_some_and(|e| e.is_receipt_handle_is_invalid()));
    assert_eq!(e.message(), Some(format!("The receipt handle \"{handle}\" is not valid for this queue.").as_str()));

    // A deleted message.
    let again = sqs.receive_message().queue_url(&fifo).send().await.unwrap();
    let current = again.messages()[0].receipt_handle().unwrap().to_string();
    sqs.delete_message().queue_url(&fifo).receipt_handle(&current).send().await.unwrap();
    let e = sqs
        .change_message_visibility()
        .queue_url(&fifo)
        .receipt_handle(&current)
        .visibility_timeout(5)
        .send()
        .await
        .unwrap_err();
    assert_eq!(code(&e), "InvalidParameterValue");
    assert!(e
        .message()
        .unwrap()
        .ends_with("Reason: Message does not exist or is not available for visibility timeout change."));
}

#[tokio::test]
async fn fifo_dead_letter_queues_restart_retention() {
    let mws = Mws::start().await;
    let sqs = client(&mws).await;
    let fifo = [(QueueAttributeName::FifoQueue, "true"), (QueueAttributeName::ContentBasedDeduplication, "true")];
    let retention = (QueueAttributeName::MessageRetentionPeriod, "600");
    let dlq = create(&sqs, "ret-dlq.fifo", &[fifo[0].clone(), fifo[1].clone(), retention.clone()]).await;
    let sdlq = create(&sqs, "ret-dlq", std::slice::from_ref(&retention)).await;
    let redrive = |target: &str| {
        format!(r#"{{"deadLetterTargetArn":"arn:aws:sqs:us-east-1:{ACCOUNT}:{target}","maxReceiveCount":1}}"#)
    };
    let src = create(
        &sqs,
        "ret-src.fifo",
        &[fifo[0].clone(), fifo[1].clone(), (QueueAttributeName::RedrivePolicy, &redrive("ret-dlq.fifo"))],
    )
    .await;
    let ssrc = create(&sqs, "ret-src", &[(QueueAttributeName::RedrivePolicy, &redrive("ret-dlq"))]).await;
    sqs.send_message().queue_url(&src).message_body("poison").message_group_id("g").send().await.unwrap();
    sqs.send_message().queue_url(&ssrc).message_body("poison").send().await.unwrap();
    // Eight minutes later, both are received once and then moved.
    advance_seconds(&mws, 480).await;
    for url in [&src, &ssrc] {
        assert_eq!(
            sqs.receive_message().queue_url(url).visibility_timeout(0).send().await.unwrap().messages().len(),
            1
        );
        assert!(sqs.receive_message().queue_url(url).send().await.unwrap().messages().is_empty());
    }
    assert_eq!(attr(&sqs, &dlq, QueueAttributeName::ApproximateNumberOfMessages).await.as_deref(), Some("1"));
    assert_eq!(attr(&sqs, &sdlq, QueueAttributeName::ApproximateNumberOfMessages).await.as_deref(), Some("1"));
    // Past 600 s from the send: the standard DLQ counts from the original
    // send and drops it; the FIFO one restarted the clock at the move.
    advance_seconds(&mws, 180).await;
    assert_eq!(attr(&sqs, &sdlq, QueueAttributeName::ApproximateNumberOfMessages).await.as_deref(), Some("0"));
    assert_eq!(attr(&sqs, &dlq, QueueAttributeName::ApproximateNumberOfMessages).await.as_deref(), Some("1"));
    advance_seconds(&mws, 480).await;
    assert_eq!(attr(&sqs, &dlq, QueueAttributeName::ApproximateNumberOfMessages).await.as_deref(), Some("0"));
}

#[tokio::test]
async fn queue_metrics_reach_cloudwatch() {
    use aws_sdk_cloudwatch::types::{Dimension, Statistic};
    let mws = Mws::start().await;
    let sqs = client(&mws).await;
    let cw = aws_sdk_cloudwatch::Client::new(&mws.root_sdk_config().await);
    let url = create(&sqs, "metered", &[]).await;
    for _ in 0..3 {
        sqs.send_message().queue_url(&url).message_body("0123456789").send().await.unwrap();
    }
    let got = sqs.receive_message().queue_url(&url).send().await.unwrap();
    sqs.delete_message()
        .queue_url(&url)
        .receipt_handle(got.messages()[0].receipt_handle().unwrap())
        .send()
        .await
        .unwrap();
    let rest = sqs.receive_message().queue_url(&url).max_number_of_messages(10).visibility_timeout(90).send().await;
    assert_eq!(rest.unwrap().messages().len(), 2);
    sqs.receive_message().queue_url(&url).send().await.unwrap();
    // Close the minute on the emulated clock; SQS learns it from a request.
    advance_seconds(&mws, 180).await;
    sqs.list_queues().send().await.unwrap();

    let now = aws_sdk_cloudwatch::primitives::DateTime::from_secs(emulated_now(&mws).await);
    let start = aws_sdk_cloudwatch::primitives::DateTime::from_secs(now.secs() - 600);
    let stat = |name: &'static str, s: Statistic| {
        let cw = cw.clone();
        async move {
            let out = cw
                .get_metric_statistics()
                .namespace("AWS/SQS")
                .metric_name(name)
                .dimensions(Dimension::builder().name("QueueName").value("metered").build())
                .start_time(start)
                .end_time(now)
                .period(600)
                .statistics(s.clone())
                .send()
                .await
                .unwrap();
            let d = &out.datapoints()[0];
            match s {
                Statistic::Sum => d.sum().unwrap(),
                Statistic::Maximum => d.maximum().unwrap(),
                _ => d.average().unwrap(),
            }
        }
    };
    assert_eq!(stat("NumberOfMessagesSent", Statistic::Sum).await, 3.0);
    assert_eq!(stat("NumberOfMessagesReceived", Statistic::Sum).await, 3.0);
    assert_eq!(stat("NumberOfMessagesDeleted", Statistic::Sum).await, 1.0);
    assert_eq!(stat("NumberOfEmptyReceives", Statistic::Sum).await, 1.0);
    assert_eq!(stat("SentMessageSize", Statistic::Average).await, 10.0);
    // Two messages left: in flight in the first minute, visible again later.
    assert_eq!(stat("ApproximateNumberOfMessagesVisible", Statistic::Maximum).await, 2.0);
    assert_eq!(stat("ApproximateNumberOfMessagesNotVisible", Statistic::Maximum).await, 2.0);
    assert!(stat("ApproximateAgeOfOldestMessage", Statistic::Maximum).await >= 60.0);
}

/// The emulated clock, in epoch seconds.
async fn emulated_now(mws: &Mws) -> i64 {
    let (status, doc) = mws.control("GET", "/_mws/clock", None).await;
    assert_eq!(status, 200);
    let wall = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    wall + doc["offsetSeconds"].as_i64().unwrap() + 5
}

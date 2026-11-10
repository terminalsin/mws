//! SNS delivers after `Publish` returns, through the official Rust SDK:
//! consumers long-poll for what a topic fans out, and a FIFO topic's
//! messages still reach a FIFO queue in order, per message group.

use aws_sdk_sns::Client;
use aws_sdk_sqs::types::{MessageSystemAttributeName, QueueAttributeName};
use mws_e2e::Mws;

const ACCOUNT: &str = "123456789012";

/// A queue SNS may send to; returns its URL and ARN.
async fn queue(sqs: &aws_sdk_sqs::Client, name: &str) -> (String, String) {
    let mut req = sqs.create_queue().queue_name(name);
    if name.ends_with(".fifo") {
        req = req.attributes(QueueAttributeName::FifoQueue, "true");
    }
    let url = req.send().await.unwrap().queue_url.unwrap();
    let arn = format!("arn:aws:sqs:us-east-1:{ACCOUNT}:{name}");
    let policy = serde_json::json!({"Version":"2012-10-17","Statement":[{
        "Effect":"Allow","Principal":{"Service":"sns.amazonaws.com"},
        "Action":"sqs:SendMessage","Resource":arn}]});
    sqs.set_queue_attributes()
        .queue_url(&url)
        .attributes(QueueAttributeName::Policy, policy.to_string())
        .send()
        .await
        .unwrap();
    (url, arn)
}

/// Long-polls until `n` messages have arrived (or the wait runs out),
/// deleting them; returns (body, group id) in arrival order.
async fn collect(sqs: &aws_sdk_sqs::Client, url: &str, n: usize) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    for _ in 0..20 {
        if out.len() >= n {
            break;
        }
        let got = sqs
            .receive_message()
            .queue_url(url)
            .max_number_of_messages(10)
            .message_system_attribute_names(MessageSystemAttributeName::MessageGroupId)
            .wait_time_seconds(1)
            .send()
            .await
            .unwrap();
        for m in got.messages() {
            let group = m.attributes().and_then(|a| a.get(&MessageSystemAttributeName::MessageGroupId)).cloned();
            out.push((m.body().unwrap().to_string(), group));
            sqs.delete_message().queue_url(url).receipt_handle(m.receipt_handle().unwrap()).send().await.unwrap();
        }
    }
    out
}

#[tokio::test]
async fn publish_fans_out_after_it_returns_and_consumers_long_poll() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let sns = Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let topic = sns.create_topic().name("fanout").send().await.unwrap().topic_arn.unwrap();
    let mut urls = Vec::new();
    for name in ["a", "b", "c"] {
        let (url, arn) = queue(&sqs, name).await;
        sns.subscribe()
            .topic_arn(&topic)
            .protocol("sqs")
            .endpoint(arn)
            .attributes("RawMessageDelivery", "true")
            .send()
            .await
            .unwrap();
        urls.push(url);
    }
    for n in 0..5 {
        sns.publish().topic_arn(&topic).message(format!("m{n}")).send().await.unwrap();
    }
    for url in &urls {
        let mut got: Vec<String> = collect(&sqs, url, 5).await.into_iter().map(|(b, _)| b).collect();
        got.sort();
        assert_eq!(got, ["m0", "m1", "m2", "m3", "m4"]);
    }

    // A subscription made after the publish does not get the message.
    let (late_url, late_arn) = queue(&sqs, "late").await;
    sns.publish().topic_arn(&topic).message("before").send().await.unwrap();
    sns.subscribe()
        .topic_arn(&topic)
        .protocol("sqs")
        .endpoint(late_arn)
        .attributes("RawMessageDelivery", "true")
        .send()
        .await
        .unwrap();
    sns.publish().topic_arn(&topic).message("after").send().await.unwrap();
    let got: Vec<String> = collect(&sqs, &late_url, 1).await.into_iter().map(|(b, _)| b).collect();
    assert_eq!(got, ["after"]);
    mws.stop().await;
}

#[tokio::test]
async fn fifo_topics_keep_each_group_in_order_through_asynchronous_delivery() {
    let mws = Mws::start().await;
    let cfg = mws.root_sdk_config().await;
    let sns = Client::new(&cfg);
    let sqs = aws_sdk_sqs::Client::new(&cfg);
    let topic = sns
        .create_topic()
        .name("orders.fifo")
        .attributes("FifoTopic", "true")
        .attributes("ContentBasedDeduplication", "true")
        .send()
        .await
        .unwrap()
        .topic_arn
        .unwrap();
    let (url, arn) = queue(&sqs, "orders.fifo").await;
    sqs.set_queue_attributes()
        .queue_url(&url)
        .attributes(QueueAttributeName::ContentBasedDeduplication, "true")
        .send()
        .await
        .unwrap();
    sns.subscribe()
        .topic_arn(&topic)
        .protocol("sqs")
        .endpoint(arn)
        .attributes("RawMessageDelivery", "true")
        .send()
        .await
        .unwrap();
    for n in 0..20 {
        let group = if n % 2 == 0 { "even" } else { "odd" };
        sns.publish().topic_arn(&topic).message(format!("{n}")).message_group_id(group).send().await.unwrap();
    }
    let got = collect(&sqs, &url, 20).await;
    assert_eq!(got.len(), 20, "{got:?}");
    for group in ["even", "odd"] {
        let order: Vec<u32> =
            got.iter().filter(|(_, g)| g.as_deref() == Some(group)).map(|(b, _)| b.parse().unwrap()).collect();
        let mut sorted = order.clone();
        sorted.sort();
        assert_eq!(order, sorted, "group {group} out of order");
        assert_eq!(order.len(), 10);
    }
    mws.stop().await;
}

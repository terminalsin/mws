//! How `ReceiveMessage` reads a standard queue, through the official Rust
//! SDK: a short poll samples a subset of SQS's servers, so it can return
//! fewer messages than are visible, and order is best effort. A long poll
//! asks every server. FIFO queues keep strict order.

use aws_sdk_sqs::types::QueueAttributeName;
use aws_sdk_sqs::Client;
use mws_e2e::Mws;

async fn queue(sqs: &Client, name: &str, attrs: &[(QueueAttributeName, &str)]) -> String {
    let mut req = sqs.create_queue().queue_name(name);
    for (k, v) in attrs {
        req = req.attributes(k.clone(), *v);
    }
    let url = req.send().await.unwrap().queue_url.unwrap();
    for n in 0..10 {
        let mut send = sqs.send_message().queue_url(&url).message_body(n.to_string());
        if name.ends_with(".fifo") {
            send = send.message_group_id("g");
        }
        send.send().await.unwrap();
    }
    url
}

/// The bodies one receive returns; `VisibilityTimeout` 0 leaves them visible.
async fn bodies(sqs: &Client, url: &str, wait: Option<i32>) -> Vec<String> {
    let out = sqs
        .receive_message()
        .queue_url(url)
        .max_number_of_messages(10)
        .visibility_timeout(0)
        .set_wait_time_seconds(wait)
        .send()
        .await
        .unwrap();
    out.messages().iter().map(|m| m.body().unwrap().to_string()).collect()
}

fn sent() -> Vec<String> {
    (0..10).map(|n| n.to_string()).collect()
}

#[tokio::test]
async fn short_polls_sample_standard_queues_and_long_polls_see_everything() {
    let mws = Mws::start().await;
    let sqs = Client::new(&mws.root_sdk_config().await);
    let url = queue(&sqs, "sampled", &[]).await;

    let mut partial = false;
    let mut reordered = false;
    for _ in 0..30 {
        let got = bodies(&sqs, &url, None).await;
        // MWS's simplification: a short poll returns at least one visible message.
        assert!(!got.is_empty());
        partial |= got.len() < 10;
        let mut sorted = got.clone();
        sorted.sort_by_key(|b| b.parse::<u32>().unwrap());
        reordered |= sorted != got;
    }
    assert!(partial, "a short poll never sampled a subset of the servers");
    assert!(reordered, "a standard queue never reordered messages");

    // A long poll asks every server: all ten (in best-effort order).
    for _ in 0..5 {
        let mut got = bodies(&sqs, &url, Some(1)).await;
        assert_eq!(got.len(), 10);
        got.sort_by_key(|b| b.parse::<u32>().unwrap());
        assert_eq!(got, sent());
    }

    // So does a receive on a queue whose default wait makes it a long poll.
    let waiting = queue(&sqs, "waiting", &[(QueueAttributeName::ReceiveMessageWaitTimeSeconds, "1")]).await;
    assert_eq!(bodies(&sqs, &waiting, None).await.len(), 10);
    // ... unless the request asks for a short poll.
    let mut partial = false;
    for _ in 0..30 {
        let got = bodies(&sqs, &waiting, Some(0)).await;
        assert!(!got.is_empty());
        partial |= got.len() < 10;
    }
    assert!(partial);
    mws.stop().await;
}

#[tokio::test]
async fn fifo_queues_return_every_visible_message_in_order() {
    let mws = Mws::start().await;
    let sqs = Client::new(&mws.root_sdk_config().await);
    let url = queue(
        &sqs,
        "ordered.fifo",
        &[(QueueAttributeName::FifoQueue, "true"), (QueueAttributeName::ContentBasedDeduplication, "true")],
    )
    .await;
    for _ in 0..10 {
        assert_eq!(bodies(&sqs, &url, None).await, sent());
    }
    mws.stop().await;
}

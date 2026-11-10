//! SQS resource types.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::{boolean, changed, document, gone_ok, list, req, s, text, Created, Cx, HResult, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::SQS::Queue", Arc::new(Queue));
    m.insert("AWS::SQS::QueuePolicy", Arc::new(QueuePolicy));
    m.insert("AWS::SQS::QueueInlinePolicy", Arc::new(QueueInlinePolicy));
}

/// Queue attributes the resource sets, with the value AWS reverts to
/// when a property is removed.
const ATTRIBUTES: &[(&str, &str)] = &[
    ("DelaySeconds", "0"),
    ("MaximumMessageSize", "262144"),
    ("MessageRetentionPeriod", "345600"),
    ("ReceiveMessageWaitTimeSeconds", "0"),
    ("VisibilityTimeout", "30"),
    ("RedrivePolicy", ""),
    ("RedriveAllowPolicy", ""),
    ("KmsMasterKeyId", ""),
    ("KmsDataKeyReusePeriodSeconds", "300"),
    ("SqsManagedSseEnabled", "true"),
    ("ContentBasedDeduplication", "false"),
    ("DeduplicationScope", "queue"),
    ("FifoThroughputLimit", "perQueue"),
];

fn attribute(props: &Props, k: &str) -> Option<String> {
    match k {
        "RedrivePolicy" | "RedriveAllowPolicy" => document(props, k),
        _ => s(props, k),
    }
}

async fn queue_arn(cx: &Cx<'_>, url: &str) -> HResult<String> {
    let out = cx.call("sqs", "GetQueueAttributes", json!({"QueueUrl": url, "AttributeNames": ["QueueArn"]})).await?;
    Ok(text(&out["Attributes"]["QueueArn"]))
}

struct Queue;

#[async_trait::async_trait]
impl Provider for Queue {
    fn name_property(&self) -> Option<&'static str> {
        Some("QueueName")
    }

    fn create_only(&self) -> &'static [&'static str] {
        &["QueueName", "FifoQueue"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn", "QueueName", "QueueUrl"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let fifo = boolean(props, "FifoQueue") == Some(true);
        let name = s(props, "QueueName").unwrap_or_else(|| {
            if fifo {
                format!("{}.fifo", cx.physical_name(75))
            } else {
                cx.physical_name(80)
            }
        });
        let mut attrs = Map::new();
        if fifo {
            attrs.insert("FifoQueue".into(), json!("true"));
        }
        for (k, _) in ATTRIBUTES {
            if let Some(v) = attribute(props, k) {
                attrs.insert((*k).into(), json!(v));
            }
        }
        let mut input = json!({"QueueName": name, "Attributes": attrs});
        let tags = cx.tag_map(props);
        if !tags.is_empty() {
            input["tags"] = Value::Object(tags);
        }
        let out = cx.call("sqs", "CreateQueue", input).await?;
        let url = text(&out["QueueUrl"]);
        let arn = queue_arn(cx, &url).await?;
        Ok(Created::new(&url).attr("Arn", arn).attr("QueueUrl", url.clone()).attr("QueueName", name))
    }

    async fn update(&self, cx: &Cx<'_>, url: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let mut set = Map::new();
        for (k, default) in ATTRIBUTES {
            if changed(old, new, k) {
                set.insert((*k).into(), json!(attribute(new, k).unwrap_or_else(|| default.to_string())));
            }
        }
        if !set.is_empty() {
            cx.call("sqs", "SetQueueAttributes", json!({"QueueUrl": url, "Attributes": set})).await?;
        }
        if changed(old, new, "Tags") {
            let new_tags = cx.tag_map(new);
            let removed: Vec<String> = cx.tag_map(old).keys().filter(|k| !new_tags.contains_key(*k)).cloned().collect();
            if !removed.is_empty() {
                cx.call("sqs", "UntagQueue", json!({"QueueUrl": url, "TagKeys": removed})).await?;
            }
            if !new_tags.is_empty() {
                cx.call("sqs", "TagQueue", json!({"QueueUrl": url, "Tags": new_tags})).await?;
            }
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, url: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("sqs", "DeleteQueue", json!({"QueueUrl": url})).await)
    }

    async fn read(&self, cx: &Cx<'_>, url: &str, props: &Props) -> Option<HResult<Props>> {
        Some(
            async {
                let out =
                    cx.call("sqs", "GetQueueAttributes", json!({"QueueUrl": url, "AttributeNames": ["All"]})).await?;
                let a = &out["Attributes"];
                let mut p = Props::new();
                for k in props.keys() {
                    match k.as_str() {
                        "QueueName" => {
                            p.insert(k.clone(), json!(url.rsplit('/').next().unwrap_or_default()));
                        }
                        "RedrivePolicy" | "RedriveAllowPolicy" => {
                            if let Some(v) = a[k.as_str()].as_str() {
                                p.insert(k.clone(), serde_json::from_str(v).unwrap_or(json!(v)));
                            }
                        }
                        other => {
                            if let Some(v) = a.get(other) {
                                let original = &props[other];
                                p.insert(
                                    k.clone(),
                                    match original {
                                        Value::Number(_) => v
                                            .as_str()
                                            .and_then(|s| s.parse::<i64>().ok())
                                            .map(Value::from)
                                            .unwrap_or(v.clone()),
                                        Value::Bool(_) => json!(v.as_str() == Some("true")),
                                        _ => v.clone(),
                                    },
                                );
                            }
                        }
                    }
                }
                Ok(p)
            }
            .await,
        )
    }
}

struct QueuePolicy;

#[async_trait::async_trait]
impl Provider for QueuePolicy {
    fn required(&self) -> &'static [&'static str] {
        &["Queues", "PolicyDocument"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Id"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let policy = document(props, "PolicyDocument").unwrap_or_default();
        for q in list(props, "Queues") {
            cx.call("sqs", "SetQueueAttributes", json!({"QueueUrl": q, "Attributes": {"Policy": policy}})).await?;
        }
        let id = cx.physical_name(128);
        Ok(Created::new(&id).attr("Id", id.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, _id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let n = list(new, "Queues");
        for q in list(old, "Queues").iter().filter(|q| !n.contains(q)) {
            gone_ok(cx.call("sqs", "SetQueueAttributes", json!({"QueueUrl": q, "Attributes": {"Policy": ""}})).await)?;
        }
        self.create(cx, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, _id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        for q in list(props, "Queues") {
            gone_ok(cx.call("sqs", "SetQueueAttributes", json!({"QueueUrl": q, "Attributes": {"Policy": ""}})).await)?;
        }
        Ok(())
    }
}

struct QueueInlinePolicy;

#[async_trait::async_trait]
impl Provider for QueueInlinePolicy {
    fn create_only(&self) -> &'static [&'static str] {
        &["Queue"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["Queue", "PolicyDocument"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let q = req(props, "Queue")?;
        cx.call(
            "sqs",
            "SetQueueAttributes",
            json!({"QueueUrl": q, "Attributes": {"Policy": document(props, "PolicyDocument").unwrap_or_default()}}),
        )
        .await?;
        Ok(Created::new(q))
    }

    async fn update(&self, cx: &Cx<'_>, _id: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        self.create(cx, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, q: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("sqs", "SetQueueAttributes", json!({"QueueUrl": q, "Attributes": {"Policy": ""}})).await)
    }
}

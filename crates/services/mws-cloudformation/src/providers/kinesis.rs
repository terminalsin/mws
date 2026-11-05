//! Kinesis Data Streams and Firehose resource types.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::{changed, copy, gone_ok, int, s, text, Created, Cx, HResult, HandlerError, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::Kinesis::Stream", Arc::new(Stream));
    m.insert("AWS::KinesisFirehose::DeliveryStream", Arc::new(DeliveryStream));
}

async fn wait_stream(cx: &Cx<'_>, name: &str) -> HResult<Value> {
    for _ in 0..600 {
        let out = cx.call("kinesis", "DescribeStreamSummary", json!({"StreamName": name})).await?;
        let d = out["StreamDescriptionSummary"].clone();
        if d["StreamStatus"] == json!("ACTIVE") {
            return Ok(d);
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Err(HandlerError::handler("NotStabilized", format!("Stream {name} did not become ACTIVE")))
}

struct Stream;

#[async_trait::async_trait]
impl Provider for Stream {
    fn create_only(&self) -> &'static [&'static str] {
        &["Name"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "Name").unwrap_or_else(|| cx.physical_name(128));
        let mode = props.get("StreamModeDetails").and_then(|m| m.get("StreamMode")).map(text);
        let mut input = json!({"StreamName": name});
        if mode.as_deref() == Some("ON_DEMAND") {
            input["StreamModeDetails"] = json!({"StreamMode": "ON_DEMAND"});
        } else {
            input["ShardCount"] = json!(int(props, "ShardCount").unwrap_or(1));
        }
        let tags = cx.tag_map(props);
        if !tags.is_empty() {
            input["Tags"] = Value::Object(tags);
        }
        cx.call("kinesis", "CreateStream", input).await?;
        let d = wait_stream(cx, &name).await?;
        if let Some(h) = int(props, "RetentionPeriodHours").filter(|h| *h != 24) {
            cx.call("kinesis", "IncreaseStreamRetentionPeriod", json!({"StreamName": name, "RetentionPeriodHours": h})).await?;
            wait_stream(cx, &name).await?;
        }
        if let Some(e) = props.get("StreamEncryption") {
            cx.call(
                "kinesis",
                "StartStreamEncryption",
                json!({"StreamName": name, "EncryptionType": e.get("EncryptionType").map(text).unwrap_or_else(|| "KMS".into()), "KeyId": e.get("KeyId").map(text).unwrap_or_default()}),
            )
            .await?;
            wait_stream(cx, &name).await?;
        }
        Ok(Created::new(&name).attr("Arn", d["StreamARN"].clone()))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "ShardCount") {
            if let Some(n) = int(new, "ShardCount") {
                cx.call("kinesis", "UpdateShardCount", json!({"StreamName": name, "TargetShardCount": n, "ScalingType": "UNIFORM_SCALING"})).await?;
                wait_stream(cx, name).await?;
            }
        }
        if changed(old, new, "RetentionPeriodHours") {
            let (o, n) = (int(old, "RetentionPeriodHours").unwrap_or(24), int(new, "RetentionPeriodHours").unwrap_or(24));
            let op = if n > o { "IncreaseStreamRetentionPeriod" } else { "DecreaseStreamRetentionPeriod" };
            cx.call("kinesis", op, json!({"StreamName": name, "RetentionPeriodHours": n})).await?;
            wait_stream(cx, name).await?;
        }
        if changed(old, new, "StreamEncryption") {
            match new.get("StreamEncryption") {
                Some(e) => cx
                    .call(
                        "kinesis",
                        "StartStreamEncryption",
                        json!({"StreamName": name, "EncryptionType": "KMS", "KeyId": e.get("KeyId").map(text).unwrap_or_default()}),
                    )
                    .await?,
                None => {
                    let e = old.get("StreamEncryption").cloned().unwrap_or_default();
                    cx.call(
                        "kinesis",
                        "StopStreamEncryption",
                        json!({"StreamName": name, "EncryptionType": "KMS", "KeyId": e.get("KeyId").map(text).unwrap_or_default()}),
                    )
                    .await?
                }
            };
            wait_stream(cx, name).await?;
        }
        if changed(old, new, "Tags") {
            let new_tags = cx.tag_map(new);
            let removed: Vec<String> = cx.tag_map(old).keys().filter(|k| !new_tags.contains_key(*k)).cloned().collect();
            if !removed.is_empty() {
                cx.call("kinesis", "RemoveTagsFromStream", json!({"StreamName": name, "TagKeys": removed})).await?;
            }
            if !new_tags.is_empty() {
                cx.call("kinesis", "AddTagsToStream", json!({"StreamName": name, "Tags": new_tags})).await?;
            }
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("kinesis", "DeleteStream", json!({"StreamName": name, "EnforceConsumerDeletion": true})).await)
    }

    async fn read(&self, cx: &Cx<'_>, name: &str, props: &Props) -> Option<HResult<Props>> {
        Some(
            async {
                let out = cx.call("kinesis", "DescribeStreamSummary", json!({"StreamName": name})).await?;
                let d = &out["StreamDescriptionSummary"];
                let mut p = Props::new();
                if props.contains_key("ShardCount") {
                    p.insert("ShardCount".into(), d["OpenShardCount"].clone());
                }
                if props.contains_key("RetentionPeriodHours") {
                    p.insert("RetentionPeriodHours".into(), d["RetentionPeriodHours"].clone());
                }
                if props.contains_key("Name") {
                    p.insert("Name".into(), json!(name));
                }
                Ok(p)
            }
            .await,
        )
    }
}

struct DeliveryStream;

#[async_trait::async_trait]
impl Provider for DeliveryStream {
    fn updatable(&self) -> bool {
        false
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "DeliveryStreamName").unwrap_or_else(|| cx.physical_name(64));
        let mut input = Map::new();
        input.insert("DeliveryStreamName".into(), json!(name));
        copy(
            props,
            &mut input,
            &[
                "DeliveryStreamType",
                "DirectPutSourceConfiguration",
                "KinesisStreamSourceConfiguration",
                "DeliveryStreamEncryptionConfigurationInput",
                "S3DestinationConfiguration",
                "ExtendedS3DestinationConfiguration",
                "HttpEndpointDestinationConfiguration",
                "MSKSourceConfiguration",
            ],
        );
        let tags = cx.tags(props);
        if !tags.is_empty() {
            input.insert("Tags".into(), json!(tags));
        }
        let out = cx.call("firehose", "CreateDeliveryStream", Value::Object(input)).await?;
        for _ in 0..600 {
            let d = cx.call("firehose", "DescribeDeliveryStream", json!({"DeliveryStreamName": name})).await?;
            match d["DeliveryStreamDescription"]["DeliveryStreamStatus"].as_str() {
                Some("ACTIVE") => break,
                Some("CREATING_FAILED") => {
                    return Err(HandlerError::handler("NotStabilized", format!("Delivery stream {name} failed to create")))
                }
                _ => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
            }
        }
        Ok(Created::new(&name).attr("Arn", out["DeliveryStreamARN"].clone()))
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("firehose", "DeleteDeliveryStream", json!({"DeliveryStreamName": name})).await)
    }
}

//! SNS resource types.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::{changed, document, gone_ok, list, req, s, text, Created, Cx, HResult, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::SNS::Topic", Arc::new(Topic));
    m.insert("AWS::SNS::Subscription", Arc::new(Subscription));
    m.insert("AWS::SNS::TopicPolicy", Arc::new(TopicPolicy));
    m.insert("AWS::SNS::TopicInlinePolicy", Arc::new(TopicInlinePolicy));
}

const TOPIC_ATTRIBUTES: &[&str] = &[
    "DisplayName",
    "KmsMasterKeyId",
    "SignatureVersion",
    "TracingConfig",
    "ContentBasedDeduplication",
    "ArchivePolicy",
    "DeliveryPolicy",
    "FifoThroughputScope",
];

fn attr_value(props: &Props, k: &str) -> Option<String> {
    match k {
        "ArchivePolicy" | "DeliveryPolicy" | "FilterPolicy" | "RedrivePolicy" | "ReplayPolicy" => document(props, k),
        _ => s(props, k),
    }
}

struct Topic;

#[async_trait::async_trait]
impl Provider for Topic {
    fn create_only(&self) -> &'static [&'static str] {
        &["TopicName", "FifoTopic"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["TopicArn", "TopicName"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let fifo = super::boolean(props, "FifoTopic") == Some(true);
        let name = s(props, "TopicName").unwrap_or_else(|| {
            if fifo {
                format!("{}.fifo", cx.physical_name(251))
            } else {
                cx.physical_name(256)
            }
        });
        let mut attrs = Map::new();
        if fifo {
            attrs.insert("FifoTopic".into(), json!("true"));
        }
        for k in TOPIC_ATTRIBUTES {
            if let Some(v) = attr_value(props, k) {
                attrs.insert((*k).into(), json!(v));
            }
        }
        let mut input = json!({"Name": name, "Attributes": attrs});
        let tags = cx.tags(props);
        if !tags.is_empty() {
            input["Tags"] = json!(tags);
        }
        let out = cx.call("sns", "CreateTopic", input).await?;
        let arn = text(&out["TopicArn"]);
        if let Some(Value::Array(subs)) = props.get("Subscription") {
            for sub in subs {
                cx.call(
                    "sns",
                    "Subscribe",
                    json!({"TopicArn": arn, "Protocol": sub.get("Protocol").map(text).unwrap_or_default(), "Endpoint": sub.get("Endpoint").map(text).unwrap_or_default()}),
                )
                .await?;
            }
        }
        Ok(Created::new(&arn).attr("TopicArn", arn.clone()).attr("TopicName", name))
    }

    async fn update(&self, cx: &Cx<'_>, arn: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        for k in TOPIC_ATTRIBUTES {
            if changed(old, new, k) {
                cx.call(
                    "sns",
                    "SetTopicAttributes",
                    json!({"TopicArn": arn, "AttributeName": k, "AttributeValue": attr_value(new, k).unwrap_or_default()}),
                )
                .await?;
            }
        }
        if changed(old, new, "Subscription") {
            let subs = |p: &Props| -> Vec<(String, String)> {
                p.get("Subscription")
                    .and_then(Value::as_array)
                    .map(|a| {
                        a.iter()
                            .map(|x| (x.get("Protocol").map(text).unwrap_or_default(), x.get("Endpoint").map(text).unwrap_or_default()))
                            .collect()
                    })
                    .unwrap_or_default()
            };
            let (o, n) = (subs(old), subs(new));
            for (p, e) in n.iter().filter(|x| !o.contains(x)) {
                cx.call("sns", "Subscribe", json!({"TopicArn": arn, "Protocol": p, "Endpoint": e})).await?;
            }
            let removed: Vec<&(String, String)> = o.iter().filter(|x| !n.contains(x)).collect();
            if !removed.is_empty() {
                let out = cx.call("sns", "ListSubscriptionsByTopic", json!({"TopicArn": arn})).await?;
                for sub in out["Subscriptions"].as_array().cloned().unwrap_or_default() {
                    let key = (text(&sub["Protocol"]), text(&sub["Endpoint"]));
                    if removed.contains(&&key) {
                        gone_ok(cx.call("sns", "Unsubscribe", json!({"SubscriptionArn": sub["SubscriptionArn"]})).await)?;
                    }
                }
            }
        }
        if changed(old, new, "Tags") {
            let new_tags = cx.tags(new);
            let keys: Vec<String> = new_tags.iter().map(|t| text(&t["Key"])).collect();
            let removed: Vec<String> = cx.tags(old).iter().map(|t| text(&t["Key"])).filter(|k| !keys.contains(k)).collect();
            if !removed.is_empty() {
                cx.call("sns", "UntagResource", json!({"ResourceArn": arn, "TagKeys": removed})).await?;
            }
            if !new_tags.is_empty() {
                cx.call("sns", "TagResource", json!({"ResourceArn": arn, "Tags": new_tags})).await?;
            }
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, arn: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("sns", "DeleteTopic", json!({"TopicArn": arn})).await)
    }

    async fn read(&self, cx: &Cx<'_>, arn: &str, props: &Props) -> Option<HResult<Props>> {
        Some(
            async {
                let out = cx.call("sns", "GetTopicAttributes", json!({"TopicArn": arn})).await?;
                let a = &out["Attributes"];
                let mut p = Props::new();
                for k in props.keys() {
                    match k.as_str() {
                        "TopicName" => {
                            p.insert(k.clone(), json!(arn.rsplit(':').next().unwrap_or_default()));
                        }
                        other if TOPIC_ATTRIBUTES.contains(&other) => {
                            p.insert(k.clone(), a.get(other).cloned().unwrap_or(json!("")));
                        }
                        _ => {}
                    }
                }
                Ok(p)
            }
            .await,
        )
    }
}

const SUBSCRIPTION_ATTRIBUTES: &[&str] =
    &["FilterPolicy", "FilterPolicyScope", "RawMessageDelivery", "RedrivePolicy", "DeliveryPolicy", "SubscriptionRoleArn", "ReplayPolicy"];

struct Subscription;

#[async_trait::async_trait]
impl Provider for Subscription {
    fn create_only(&self) -> &'static [&'static str] {
        &["TopicArn", "Protocol", "Endpoint", "Region"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["TopicArn", "Protocol"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut attrs = Map::new();
        for k in SUBSCRIPTION_ATTRIBUTES {
            if let Some(v) = attr_value(props, k) {
                attrs.insert((*k).into(), json!(v));
            }
        }
        let mut input = json!({"TopicArn": req(props, "TopicArn")?, "Protocol": req(props, "Protocol")?, "ReturnSubscriptionArn": true});
        if let Some(e) = s(props, "Endpoint") {
            input["Endpoint"] = json!(e);
        }
        if !attrs.is_empty() {
            input["Attributes"] = Value::Object(attrs);
        }
        let out = cx.call("sns", "Subscribe", input).await?;
        Ok(Created::new(text(&out["SubscriptionArn"])))
    }

    async fn update(&self, cx: &Cx<'_>, arn: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        for k in SUBSCRIPTION_ATTRIBUTES {
            if changed(old, new, k) {
                cx.call(
                    "sns",
                    "SetSubscriptionAttributes",
                    json!({"SubscriptionArn": arn, "AttributeName": k, "AttributeValue": attr_value(new, k).unwrap_or_default()}),
                )
                .await?;
            }
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, arn: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        if arn.ends_with("pending confirmation") || !arn.starts_with("arn:") {
            return Ok(());
        }
        gone_ok(cx.call("sns", "Unsubscribe", json!({"SubscriptionArn": arn})).await)
    }
}

fn default_topic_policy(cx: &Cx<'_>, arn: &str) -> String {
    json!({
        "Version": "2008-10-17",
        "Id": "__default_policy_ID",
        "Statement": [{
            "Sid": "__default_statement_ID",
            "Effect": "Allow",
            "Principal": {"AWS": "*"},
            "Action": ["SNS:GetTopicAttributes", "SNS:SetTopicAttributes", "SNS:AddPermission", "SNS:RemovePermission", "SNS:DeleteTopic", "SNS:Subscribe", "SNS:ListSubscriptionsByTopic", "SNS:Publish"],
            "Resource": arn,
            "Condition": {"StringEquals": {"AWS:SourceOwner": cx.account()}}
        }]
    })
    .to_string()
}

struct TopicPolicy;

#[async_trait::async_trait]
impl Provider for TopicPolicy {
    fn required(&self) -> &'static [&'static str] {
        &["Topics", "PolicyDocument"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Id"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let policy = document(props, "PolicyDocument").unwrap_or_default();
        for t in list(props, "Topics") {
            cx.call("sns", "SetTopicAttributes", json!({"TopicArn": t, "AttributeName": "Policy", "AttributeValue": policy})).await?;
        }
        let id = cx.physical_name(128);
        Ok(Created::new(&id).attr("Id", id.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, _id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let n = list(new, "Topics");
        for t in list(old, "Topics").iter().filter(|t| !n.contains(t)) {
            let p = default_topic_policy(cx, t);
            gone_ok(cx.call("sns", "SetTopicAttributes", json!({"TopicArn": t, "AttributeName": "Policy", "AttributeValue": p})).await)?;
        }
        self.create(cx, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, _id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        for t in list(props, "Topics") {
            let p = default_topic_policy(cx, &t);
            gone_ok(cx.call("sns", "SetTopicAttributes", json!({"TopicArn": t, "AttributeName": "Policy", "AttributeValue": p})).await)?;
        }
        Ok(())
    }
}

struct TopicInlinePolicy;

#[async_trait::async_trait]
impl Provider for TopicInlinePolicy {
    fn create_only(&self) -> &'static [&'static str] {
        &["TopicArn"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["TopicArn", "PolicyDocument"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let t = req(props, "TopicArn")?;
        cx.call(
            "sns",
            "SetTopicAttributes",
            json!({"TopicArn": t, "AttributeName": "Policy", "AttributeValue": document(props, "PolicyDocument").unwrap_or_default()}),
        )
        .await?;
        Ok(Created::new(t))
    }

    async fn update(&self, cx: &Cx<'_>, _id: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        self.create(cx, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, t: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        let p = default_topic_policy(cx, t);
        gone_ok(cx.call("sns", "SetTopicAttributes", json!({"TopicArn": t, "AttributeName": "Policy", "AttributeValue": p})).await)
    }
}

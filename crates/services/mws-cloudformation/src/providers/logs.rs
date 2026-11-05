//! CloudWatch Logs resource types.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::{changed, gone_ok, int, req, s, text, Created, Cx, HResult, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::Logs::LogGroup", Arc::new(LogGroup));
    m.insert("AWS::Logs::LogStream", Arc::new(LogStream));
    m.insert("AWS::Logs::MetricFilter", Arc::new(MetricFilter));
    m.insert("AWS::Logs::SubscriptionFilter", Arc::new(SubscriptionFilter));
}

struct LogGroup;

fn group_arn(cx: &Cx<'_>, name: &str) -> String {
    cx.arn("logs", &format!("log-group:{name}"))
}

#[async_trait::async_trait]
impl Provider for LogGroup {
    fn create_only(&self) -> &'static [&'static str] {
        &["LogGroupName", "LogGroupClass"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "LogGroupName").unwrap_or_else(|| cx.physical_name(512));
        let mut input = json!({"logGroupName": name});
        if let Some(k) = s(props, "KmsKeyId") {
            input["kmsKeyId"] = json!(k);
        }
        if let Some(c) = s(props, "LogGroupClass") {
            input["logGroupClass"] = json!(c);
        }
        let tags = cx.tag_map(props);
        if !tags.is_empty() {
            input["tags"] = Value::Object(tags);
        }
        cx.call("logs", "CreateLogGroup", input).await?;
        if let Some(days) = int(props, "RetentionInDays") {
            cx.call("logs", "PutRetentionPolicy", json!({"logGroupName": name, "retentionInDays": days})).await?;
        }
        Ok(Created::new(&name).attr("Arn", format!("{}:*", group_arn(cx, &name))))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "RetentionInDays") {
            match int(new, "RetentionInDays") {
                Some(d) => {
                    cx.call("logs", "PutRetentionPolicy", json!({"logGroupName": name, "retentionInDays": d})).await?
                }
                None => cx.call("logs", "DeleteRetentionPolicy", json!({"logGroupName": name})).await?,
            };
        }
        if changed(old, new, "KmsKeyId") {
            match s(new, "KmsKeyId") {
                Some(k) => cx.call("logs", "AssociateKmsKey", json!({"logGroupName": name, "kmsKeyId": k})).await?,
                None => cx.call("logs", "DisassociateKmsKey", json!({"logGroupName": name})).await?,
            };
        }
        if changed(old, new, "Tags") {
            let arn = group_arn(cx, name);
            let new_tags = cx.tag_map(new);
            let removed: Vec<String> = cx.tag_map(old).keys().filter(|k| !new_tags.contains_key(*k)).cloned().collect();
            if !removed.is_empty() {
                cx.call("logs", "UntagResource", json!({"resourceArn": arn, "tagKeys": removed})).await?;
            }
            if !new_tags.is_empty() {
                cx.call("logs", "TagResource", json!({"resourceArn": arn, "tags": new_tags})).await?;
            }
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("logs", "DeleteLogGroup", json!({"logGroupName": name})).await)
    }

    async fn read(&self, cx: &Cx<'_>, name: &str, props: &Props) -> Option<HResult<Props>> {
        Some(
            async {
                let out = cx.call("logs", "DescribeLogGroups", json!({"logGroupNamePrefix": name})).await?;
                let g = out["logGroups"]
                    .as_array()
                    .and_then(|a| a.iter().find(|g| g["logGroupName"] == json!(name)).cloned())
                    .ok_or_else(|| {
                        super::HandlerError::handler("NotFound", format!("Log group {name} does not exist"))
                    })?;
                let mut p = Props::new();
                if props.contains_key("LogGroupName") {
                    p.insert("LogGroupName".into(), json!(name));
                }
                if props.contains_key("RetentionInDays") {
                    p.insert("RetentionInDays".into(), g.get("retentionInDays").cloned().unwrap_or(Value::Null));
                }
                Ok(p)
            }
            .await,
        )
    }
}

struct LogStream;

#[async_trait::async_trait]
impl Provider for LogStream {
    fn create_only(&self) -> &'static [&'static str] {
        &["LogGroupName", "LogStreamName"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["LogGroupName"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "LogStreamName").unwrap_or_else(|| cx.physical_name(512));
        cx.call("logs", "CreateLogStream", json!({"logGroupName": req(props, "LogGroupName")?, "logStreamName": name}))
            .await?;
        Ok(Created::new(name))
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(
            cx.call(
                "logs",
                "DeleteLogStream",
                json!({"logGroupName": req(props, "LogGroupName")?, "logStreamName": name}),
            )
            .await,
        )
    }
}

fn lower_first(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_lowercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

fn transformations(props: &Props) -> Vec<Value> {
    props
        .get("MetricTransformations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|t| {
            let mut m = Map::new();
            for (k, v) in t.as_object().cloned().unwrap_or_default() {
                let v = match k.as_str() {
                    "DefaultValue" => match &v {
                        Value::String(s) => s.parse::<f64>().map(|f| json!(f)).unwrap_or(v.clone()),
                        _ => v.clone(),
                    },
                    "Dimensions" => {
                        let mut d = Map::new();
                        for x in v.as_array().cloned().unwrap_or_default() {
                            d.insert(
                                x.get("Key").map(text).unwrap_or_default(),
                                json!(x.get("Value").map(text).unwrap_or_default()),
                            );
                        }
                        Value::Object(d)
                    }
                    _ => v.clone(),
                };
                m.insert(lower_first(&k), v);
            }
            Value::Object(m)
        })
        .collect()
}

struct MetricFilter;

#[async_trait::async_trait]
impl Provider for MetricFilter {
    fn create_only(&self) -> &'static [&'static str] {
        &["FilterName", "LogGroupName"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["FilterPattern", "LogGroupName", "MetricTransformations"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "FilterName").unwrap_or_else(|| cx.physical_name(512));
        let mut input = json!({
            "logGroupName": req(props, "LogGroupName")?,
            "filterName": name,
            "filterPattern": s(props, "FilterPattern").unwrap_or_default(),
            "metricTransformations": transformations(props),
        });
        if let Some(b) = super::boolean(props, "ApplyOnTransformedLogs") {
            input["applyOnTransformedLogs"] = json!(b);
        }
        cx.call("logs", "PutMetricFilter", input).await?;
        Ok(Created::new(name))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let mut p = new.clone();
        p.insert("FilterName".into(), json!(name));
        self.create(cx, &p).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(
            cx.call(
                "logs",
                "DeleteMetricFilter",
                json!({"logGroupName": req(props, "LogGroupName")?, "filterName": name}),
            )
            .await,
        )
    }
}

struct SubscriptionFilter;

#[async_trait::async_trait]
impl Provider for SubscriptionFilter {
    fn create_only(&self) -> &'static [&'static str] {
        &["FilterName", "LogGroupName"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["DestinationArn", "FilterPattern", "LogGroupName"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "FilterName").unwrap_or_else(|| cx.physical_name(512));
        let mut input = json!({
            "logGroupName": req(props, "LogGroupName")?,
            "filterName": name,
            "filterPattern": s(props, "FilterPattern").unwrap_or_default(),
            "destinationArn": req(props, "DestinationArn")?,
        });
        if let Some(r) = s(props, "RoleArn") {
            input["roleArn"] = json!(r);
        }
        if let Some(d) = s(props, "Distribution") {
            input["distribution"] = json!(d);
        }
        cx.call("logs", "PutSubscriptionFilter", input).await?;
        Ok(Created::new(name))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let mut p = new.clone();
        p.insert("FilterName".into(), json!(name));
        self.create(cx, &p).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(
            cx.call(
                "logs",
                "DeleteSubscriptionFilter",
                json!({"logGroupName": req(props, "LogGroupName")?, "filterName": name}),
            )
            .await,
        )
    }
}

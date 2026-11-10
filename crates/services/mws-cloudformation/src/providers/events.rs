//! EventBridge resource types.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::{changed, document, gone_ok, s, text, Created, Cx, HResult, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::Events::Rule", Arc::new(Rule));
    m.insert("AWS::Events::EventBus", Arc::new(EventBus));
}

struct Rule;

/// `(bus, rule)` of a rule's physical id: `rule` or `bus|rule`.
fn split(id: &str) -> (Option<&str>, &str) {
    match id.split_once('|') {
        Some((b, r)) => (Some(b), r),
        None => (None, id),
    }
}

fn targets(props: &Props) -> Vec<Value> {
    props.get("Targets").and_then(Value::as_array).cloned().unwrap_or_default()
}

impl Rule {
    async fn put(&self, cx: &Cx<'_>, name: &str, props: &Props) -> HResult<Value> {
        let mut input = Map::new();
        input.insert("Name".into(), json!(name));
        if let Some(b) = s(props, "EventBusName") {
            input.insert("EventBusName".into(), json!(b));
        }
        if let Some(p) = document(props, "EventPattern") {
            input.insert("EventPattern".into(), json!(p));
        }
        for k in ["ScheduleExpression", "State", "Description", "RoleArn"] {
            if let Some(v) = s(props, k) {
                input.insert(k.into(), json!(v));
            }
        }
        cx.call("events", "PutRule", Value::Object(input)).await
    }

    async fn put_targets(&self, cx: &Cx<'_>, name: &str, props: &Props) -> HResult<()> {
        let t = targets(props);
        if t.is_empty() {
            return Ok(());
        }
        let mut input = json!({"Rule": name, "Targets": t});
        if let Some(b) = s(props, "EventBusName") {
            input["EventBusName"] = json!(b);
        }
        let out = cx.call("events", "PutTargets", input).await?;
        if let Some(f) = out["FailedEntries"].as_array().and_then(|a| a.first()) {
            return Err(super::HandlerError::invalid(format!(
                "Target {} failed: {}",
                text(&f["TargetId"]),
                text(&f["ErrorMessage"])
            )));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl Provider for Rule {
    fn name_property(&self) -> Option<&'static str> {
        Some("Name")
    }

    fn create_only(&self) -> &'static [&'static str] {
        &["Name", "EventBusName"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "Name").unwrap_or_else(|| cx.physical_name(64));
        let out = self.put(cx, &name, props).await?;
        self.put_targets(cx, &name, props).await?;
        let bus = s(props, "EventBusName").filter(|b| b != "default");
        let id = match &bus {
            Some(b) => format!("{}|{name}", b.rsplit('/').next().unwrap_or(b)),
            None => name.clone(),
        };
        Ok(Created::new(id).attr("Arn", out["RuleArn"].clone()))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let (_, name) = split(id);
        self.put(cx, name, new).await?;
        if changed(old, new, "Targets") {
            let keep: Vec<String> = targets(new).iter().map(|t| t.get("Id").map(text).unwrap_or_default()).collect();
            let removed: Vec<String> = targets(old)
                .iter()
                .map(|t| t.get("Id").map(text).unwrap_or_default())
                .filter(|i| !keep.contains(i))
                .collect();
            if !removed.is_empty() {
                let mut input = json!({"Rule": name, "Ids": removed});
                if let Some(b) = s(new, "EventBusName") {
                    input["EventBusName"] = json!(b);
                }
                cx.call("events", "RemoveTargets", input).await?;
            }
            self.put_targets(cx, name, new).await?;
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let (bus, name) = split(id);
        let bus = bus.map(str::to_string).or_else(|| s(props, "EventBusName"));
        let ids: Vec<String> = targets(props).iter().map(|t| t.get("Id").map(text).unwrap_or_default()).collect();
        if !ids.is_empty() {
            let mut input = json!({"Rule": name, "Ids": ids});
            if let Some(b) = &bus {
                input["EventBusName"] = json!(b);
            }
            gone_ok(cx.call("events", "RemoveTargets", input).await)?;
        }
        let mut input = json!({"Name": name});
        if let Some(b) = &bus {
            input["EventBusName"] = json!(b);
        }
        gone_ok(cx.call("events", "DeleteRule", input).await)
    }
}

struct EventBus;

#[async_trait::async_trait]
impl Provider for EventBus {
    fn name_property(&self) -> Option<&'static str> {
        Some("Name")
    }

    fn create_only(&self) -> &'static [&'static str] {
        &["Name", "EventSourceName"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["Name"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn", "Name", "Policy"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "Name").unwrap_or_default();
        let mut input = Map::new();
        input.insert("Name".into(), json!(name));
        super::copy(
            props,
            &mut input,
            &["EventSourceName", "Description", "KmsKeyIdentifier", "DeadLetterConfig", "LogConfig"],
        );
        let tags = cx.tags(props);
        if !tags.is_empty() {
            input.insert("Tags".into(), json!(tags));
        }
        let out = cx.call("events", "CreateEventBus", Value::Object(input)).await?;
        if let Some(p) = document(props, "Policy") {
            cx.call("events", "PutPermission", json!({"EventBusName": name, "Policy": p})).await?;
        }
        Ok(Created::new(&name)
            .attr("Arn", out["EventBusArn"].clone())
            .attr("Name", name.clone())
            .attr("Policy", document(props, "Policy").unwrap_or_default()))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let mut attrs = attrs.clone();
        if changed(old, new, "Policy") {
            if let Some(p) = document(new, "Policy") {
                cx.call("events", "PutPermission", json!({"EventBusName": name, "Policy": p})).await?;
                attrs.insert("Policy".into(), json!(p));
            }
        }
        if changed(old, new, "Description")
            || changed(old, new, "KmsKeyIdentifier")
            || changed(old, new, "DeadLetterConfig")
        {
            let mut input = Map::new();
            input.insert("Name".into(), json!(name));
            super::copy(new, &mut input, &["Description", "KmsKeyIdentifier", "DeadLetterConfig", "LogConfig"]);
            cx.call("events", "UpdateEventBus", Value::Object(input)).await?;
        }
        Ok(attrs)
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("events", "DeleteEventBus", json!({"Name": name})).await)
    }
}

//! Route 53 resource types.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::{changed, gone_ok, s, text, Created, Cx, HResult, HandlerError, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::Route53::HostedZone", Arc::new(HostedZone));
    m.insert("AWS::Route53::RecordSet", Arc::new(RecordSet));
    m.insert("AWS::Route53::RecordSetGroup", Arc::new(RecordSetGroup));
    m.insert("AWS::Route53::HealthCheck", Arc::new(HealthCheck));
}

fn zone_id(id: &str) -> String {
    id.trim_start_matches("/hostedzone/").to_string()
}

fn absolute(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    }
}

struct HostedZone;

#[async_trait::async_trait]
impl Provider for HostedZone {
    fn create_only(&self) -> &'static [&'static str] {
        &["Name"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["Name"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Id", "NameServers"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "Name").unwrap_or_default();
        let vpcs = props.get("VPCs").and_then(Value::as_array).cloned().unwrap_or_default();
        let mut input = json!({"Name": name, "CallerReference": uuid::Uuid::new_v4().to_string()});
        let comment = props.get("HostedZoneConfig").and_then(|c| c.get("Comment")).map(text);
        let mut config = Map::new();
        if let Some(c) = &comment {
            config.insert("Comment".into(), json!(c));
        }
        if let Some(v) = vpcs.first() {
            input["VPC"] = json!({"VPCId": v.get("VPCId").map(text), "VPCRegion": v.get("VPCRegion").map(text)});
            config.insert("PrivateZone".into(), json!(true));
        }
        if !config.is_empty() {
            input["HostedZoneConfig"] = Value::Object(config);
        }
        let out = cx.call("route53", "CreateHostedZone", input).await?;
        let id = zone_id(&text(&out["HostedZone"]["Id"]));
        for v in vpcs.iter().skip(1) {
            cx.call(
                "route53",
                "AssociateVPCWithHostedZone",
                json!({"HostedZoneId": id, "VPC": {"VPCId": v.get("VPCId").map(text), "VPCRegion": v.get("VPCRegion").map(text)}}),
            )
            .await?;
        }
        let tags: Vec<Value> = props.get("HostedZoneTags").and_then(Value::as_array).cloned().unwrap_or_default();
        if !tags.is_empty() {
            cx.call(
                "route53",
                "ChangeTagsForResource",
                json!({"ResourceType": "hostedzone", "ResourceId": id, "AddTags": tags}),
            )
            .await?;
        }
        if let Some(arn) = props.get("QueryLoggingConfig").and_then(|q| q.get("CloudWatchLogsLogGroupArn")).map(text) {
            cx.call(
                "route53",
                "CreateQueryLoggingConfig",
                json!({"HostedZoneId": id, "CloudWatchLogsLogGroupArn": arn}),
            )
            .await?;
        }
        let ns: Vec<Value> = out["DelegationSet"]["NameServers"].as_array().cloned().unwrap_or_default();
        Ok(Created::new(&id).attr("Id", id.clone()).attr("NameServers", Value::Array(ns)))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "HostedZoneConfig") {
            let comment = new.get("HostedZoneConfig").and_then(|c| c.get("Comment")).map(text).unwrap_or_default();
            cx.call("route53", "UpdateHostedZoneComment", json!({"Id": id, "Comment": comment})).await?;
        }
        if changed(old, new, "HostedZoneTags") {
            let new_tags: Vec<Value> = new.get("HostedZoneTags").and_then(Value::as_array).cloned().unwrap_or_default();
            let keys: Vec<String> = new_tags.iter().map(|t| t.get("Key").map(text).unwrap_or_default()).collect();
            let removed: Vec<String> = old
                .get("HostedZoneTags")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(|t| t.get("Key").map(text).unwrap_or_default())
                .filter(|k| !keys.contains(k))
                .collect();
            let mut input = json!({"ResourceType": "hostedzone", "ResourceId": id});
            if !new_tags.is_empty() {
                input["AddTags"] = json!(new_tags);
            }
            if !removed.is_empty() {
                input["RemoveTagKeys"] = json!(removed);
            }
            cx.call("route53", "ChangeTagsForResource", input).await?;
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        if let Ok(out) = cx.call("route53", "ListQueryLoggingConfigs", json!({"HostedZoneId": id})).await {
            for c in out["QueryLoggingConfigs"].as_array().cloned().unwrap_or_default() {
                gone_ok(cx.call("route53", "DeleteQueryLoggingConfig", json!({"Id": text(&c["Id"])})).await)?;
            }
        }
        gone_ok(cx.call("route53", "DeleteHostedZone", json!({"Id": id})).await)
    }
}

/// The zone a record set belongs to, from `HostedZoneId` or
/// `HostedZoneName`.
async fn resolve_zone(cx: &Cx<'_>, props: &Props) -> HResult<String> {
    if let Some(id) = s(props, "HostedZoneId") {
        return Ok(zone_id(&id));
    }
    let Some(name) = s(props, "HostedZoneName") else {
        return Err(HandlerError::invalid("Exactly one of [HostedZoneId, HostedZoneName] must be specified"));
    };
    let name = absolute(&name);
    let out = cx.call("route53", "ListHostedZonesByName", json!({"DNSName": name})).await?;
    let zones: Vec<Value> = out["HostedZones"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|z| text(&z["Name"]).eq_ignore_ascii_case(&name))
        .collect();
    match zones.as_slice() {
        [z] => Ok(zone_id(&text(&z["Id"]))),
        [] => Err(HandlerError::invalid(format!("No hosted zone found with name {name}"))),
        _ => Err(HandlerError::invalid(format!("Found more than one hosted zone with name {name}"))),
    }
}

/// A record set's API shape from template properties.
fn record_set(p: &Value) -> Value {
    let mut r = Map::new();
    r.insert("Name".into(), json!(absolute(&p.get("Name").map(text).unwrap_or_default())));
    r.insert("Type".into(), json!(p.get("Type").map(text).unwrap_or_default()));
    if let Some(t) = p.get("TTL") {
        r.insert("TTL".into(), json!(text(t).parse::<i64>().unwrap_or(300)));
    }
    if let Some(Value::Array(rr)) = p.get("ResourceRecords") {
        r.insert("ResourceRecords".into(), Value::Array(rr.iter().map(|v| json!({"Value": text(v)})).collect()));
    }
    for k in ["SetIdentifier", "Failover", "HealthCheckId", "Region", "MultiValueAnswer"] {
        if let Some(v) = p.get(k) {
            r.insert(k.into(), if k == "MultiValueAnswer" { json!(text(v) == "true") } else { json!(text(v)) });
        }
    }
    if let Some(w) = p.get("Weight") {
        r.insert("Weight".into(), json!(text(w).parse::<i64>().unwrap_or(0)));
    }
    if let Some(g) = p.get("GeoLocation") {
        r.insert("GeoLocation".into(), g.clone());
    }
    if let Some(a) = p.get("AliasTarget") {
        r.insert(
            "AliasTarget".into(),
            json!({
                "HostedZoneId": a.get("HostedZoneId").map(text).unwrap_or_default(),
                "DNSName": a.get("DNSName").map(text).unwrap_or_default(),
                "EvaluateTargetHealth": a.get("EvaluateTargetHealth").map(|v| text(v) == "true").unwrap_or(false),
            }),
        );
    }
    Value::Object(r)
}

async fn change(cx: &Cx<'_>, zone: &str, changes: Vec<Value>) -> HResult<()> {
    if changes.is_empty() {
        return Ok(());
    }
    cx.call("route53", "ChangeResourceRecordSets", json!({"HostedZoneId": zone, "ChangeBatch": {"Changes": changes}}))
        .await?;
    Ok(())
}

struct RecordSet;

#[async_trait::async_trait]
impl Provider for RecordSet {
    fn create_only(&self) -> &'static [&'static str] {
        &["HostedZoneId", "HostedZoneName", "Name", "SetIdentifier"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["Name", "Type"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let zone = resolve_zone(cx, props).await?;
        let rs = record_set(&Value::Object(props.clone()));
        change(cx, &zone, vec![json!({"Action": "CREATE", "ResourceRecordSet": rs})]).await?;
        Ok(Created::new(absolute(&s(props, "Name").unwrap_or_default()).trim_end_matches('.')))
    }

    async fn update(&self, cx: &Cx<'_>, _id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let zone = resolve_zone(cx, new).await?;
        let mut changes = Vec::new();
        if old.get("Type") != new.get("Type") {
            changes.push(json!({"Action": "DELETE", "ResourceRecordSet": record_set(&Value::Object(old.clone()))}));
        }
        changes.push(json!({"Action": "UPSERT", "ResourceRecordSet": record_set(&Value::Object(new.clone()))}));
        change(cx, &zone, changes).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, _id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let zone = match resolve_zone(cx, props).await {
            Ok(z) => z,
            Err(_) => return Ok(()),
        };
        let rs = record_set(&Value::Object(props.clone()));
        match change(cx, &zone, vec![json!({"Action": "DELETE", "ResourceRecordSet": rs})]).await {
            Err(e) if e.not_found || e.code == "InvalidChangeBatch" => Ok(()),
            r => r,
        }
    }
}

struct RecordSetGroup;

fn group_sets(props: &Props) -> Vec<Value> {
    props.get("RecordSets").and_then(Value::as_array).cloned().unwrap_or_default()
}

fn set_key(v: &Value) -> (String, String, String) {
    (
        absolute(&v.get("Name").map(text).unwrap_or_default()).to_lowercase(),
        v.get("Type").map(text).unwrap_or_default(),
        v.get("SetIdentifier").map(text).unwrap_or_default(),
    )
}

#[async_trait::async_trait]
impl Provider for RecordSetGroup {
    fn create_only(&self) -> &'static [&'static str] {
        &["HostedZoneId", "HostedZoneName"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let zone = resolve_zone(cx, props).await?;
        let changes =
            group_sets(props).iter().map(|r| json!({"Action": "CREATE", "ResourceRecordSet": record_set(r)})).collect();
        change(cx, &zone, changes).await?;
        Ok(Created::new(cx.physical_name(128)))
    }

    async fn update(&self, cx: &Cx<'_>, _id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let zone = resolve_zone(cx, new).await?;
        let new_sets = group_sets(new);
        let keys: Vec<_> = new_sets.iter().map(set_key).collect();
        let mut changes: Vec<Value> = group_sets(old)
            .iter()
            .filter(|r| !keys.contains(&set_key(r)))
            .map(|r| json!({"Action": "DELETE", "ResourceRecordSet": record_set(r)}))
            .collect();
        changes.extend(new_sets.iter().map(|r| json!({"Action": "UPSERT", "ResourceRecordSet": record_set(r)})));
        change(cx, &zone, changes).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, _id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let Ok(zone) = resolve_zone(cx, props).await else {
            return Ok(());
        };
        for r in group_sets(props) {
            let _ = change(cx, &zone, vec![json!({"Action": "DELETE", "ResourceRecordSet": record_set(&r)})]).await;
        }
        Ok(())
    }
}

struct HealthCheck;

fn health_check_config(props: &Props) -> Value {
    let mut c = props.get("HealthCheckConfig").and_then(Value::as_object).cloned().unwrap_or_default();
    super::numbers(&mut c, &["Port", "RequestInterval", "FailureThreshold", "HealthThreshold"]);
    super::bools(&mut c, &["MeasureLatency", "Inverted", "Disabled", "EnableSNI"]);
    Value::Object(c)
}

#[async_trait::async_trait]
impl Provider for HealthCheck {
    fn required(&self) -> &'static [&'static str] {
        &["HealthCheckConfig"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["HealthCheckId"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let out = cx
            .call("route53", "CreateHealthCheck", json!({"CallerReference": uuid::Uuid::new_v4().to_string(), "HealthCheckConfig": health_check_config(props)}))
            .await?;
        let id = text(&out["HealthCheck"]["Id"]);
        let tags: Vec<Value> = props.get("HealthCheckTags").and_then(Value::as_array).cloned().unwrap_or_default();
        if !tags.is_empty() {
            cx.call(
                "route53",
                "ChangeTagsForResource",
                json!({"ResourceType": "healthcheck", "ResourceId": id, "AddTags": tags}),
            )
            .await?;
        }
        Ok(Created::new(&id).attr("HealthCheckId", id.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "HealthCheckConfig") {
            let mut input = health_check_config(new).as_object().cloned().unwrap_or_default();
            for k in ["Type", "RequestInterval", "MeasureLatency"] {
                input.remove(k);
            }
            input.insert("HealthCheckId".into(), json!(id));
            cx.call("route53", "UpdateHealthCheck", Value::Object(input)).await?;
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("route53", "DeleteHealthCheck", json!({"HealthCheckId": id})).await)
    }
}

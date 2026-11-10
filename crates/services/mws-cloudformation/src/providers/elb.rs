//! Elastic Load Balancing resource types: Application, Network and Gateway
//! Load Balancers (`AWS::ElasticLoadBalancingV2::*`) and Classic Load
//! Balancers (`AWS::ElasticLoadBalancing::LoadBalancer`).

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::ecs::{coerce, stabilize, tag_changes};
use super::{changed, copy, gone_ok, list, req, s, text, Created, Cx, HResult, HandlerError, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::ElasticLoadBalancingV2::LoadBalancer", Arc::new(LoadBalancer));
    m.insert("AWS::ElasticLoadBalancingV2::TargetGroup", Arc::new(TargetGroup));
    m.insert("AWS::ElasticLoadBalancingV2::Listener", Arc::new(Listener));
    m.insert("AWS::ElasticLoadBalancingV2::ListenerRule", Arc::new(ListenerRule));
    m.insert("AWS::ElasticLoadBalancingV2::ListenerCertificate", Arc::new(ListenerCertificate));
    m.insert("AWS::ElasticLoadBalancing::LoadBalancer", Arc::new(ClassicLoadBalancer));
}

const V2: &str = "elbv2";
const CLASSIC: &str = "elb";

/// `{Key, Value}` attribute lists take string values.
fn attributes(props: &Props, key: &str) -> Vec<Value> {
    props
        .get(key)
        .and_then(Value::as_array)
        .map(|a| a.iter().map(|x| json!({"Key": text(&x["Key"]), "Value": text(&x["Value"])})).collect())
        .unwrap_or_default()
}

/// Actions (listener default actions and rule actions) with CloudFormation's
/// scalars converted to the API's types.
fn actions(v: Option<&Value>) -> Value {
    let mut v = v.cloned().unwrap_or(json!([]));
    coerce(
        &mut v,
        &["Order", "Weight", "DurationSeconds", "SessionTimeout"],
        &["Enabled", "UseExistingClientSecret"],
        &["Port", "StatusCode"],
    );
    v
}

fn conditions(v: Option<&Value>) -> Value {
    let mut v = v.cloned().unwrap_or(json!([]));
    coerce(&mut v, &[], &[], &["Values", "Key", "Value", "HttpHeaderName"]);
    v
}

async fn retag(cx: &Cx<'_>, arn: &str, old: &Props, new: &Props) -> HResult<()> {
    if let Some((set, removed)) = tag_changes(cx, old, new, "Tags") {
        if !removed.is_empty() {
            cx.call(V2, "RemoveTags", json!({"ResourceArns": [arn], "TagKeys": removed})).await?;
        }
        if !set.is_empty() {
            cx.call(V2, "AddTags", json!({"ResourceArns": [arn], "Tags": set})).await?;
        }
    }
    Ok(())
}

/// The part of an ARN after `loadbalancer/` or `:` (`app/name/id`,
/// `targetgroup/name/id`).
fn full_name(arn: &str, marker: &str) -> String {
    arn.split_once(marker).map(|(_, r)| r.to_string()).unwrap_or_default()
}

// ---- LoadBalancer ------------------------------------------------------

struct LoadBalancer;

async fn describe_lb(cx: &Cx<'_>, arn: &str) -> HResult<Value> {
    let out = cx.call(V2, "DescribeLoadBalancers", json!({"LoadBalancerArns": [arn]})).await?;
    Ok(out["LoadBalancers"][0].clone())
}

fn lb_attrs(lb: &Value) -> Props {
    let arn = text(&lb["LoadBalancerArn"]);
    let mut a = Props::new();
    a.insert("LoadBalancerArn".into(), json!(arn));
    a.insert("LoadBalancerName".into(), lb["LoadBalancerName"].clone());
    a.insert("LoadBalancerFullName".into(), json!(full_name(&arn, ":loadbalancer/")));
    a.insert("DNSName".into(), json!(text(&lb["DNSName"])));
    a.insert("CanonicalHostedZoneID".into(), json!(text(&lb["CanonicalHostedZoneId"])));
    a.insert("SecurityGroups".into(), lb.get("SecurityGroups").cloned().unwrap_or(json!([])));
    a
}

async fn set_security_groups(cx: &Cx<'_>, arn: &str, props: &Props) -> HResult<()> {
    let mut input = json!({"LoadBalancerArn": arn, "SecurityGroups": list(props, "SecurityGroups")});
    if let Some(e) = s(props, "EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic") {
        input["EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic"] = json!(e);
    }
    cx.call(V2, "SetSecurityGroups", input).await?;
    Ok(())
}

async fn set_capacity(cx: &Cx<'_>, arn: &str, props: &Props) -> HResult<()> {
    let mut input = json!({"LoadBalancerArn": arn});
    match props.get("MinimumLoadBalancerCapacity").and_then(|m| m.get("CapacityUnits")) {
        Some(u) => {
            let mut v = json!({"CapacityUnits": u});
            coerce(&mut v, &["CapacityUnits"], &[], &[]);
            input["MinimumLoadBalancerCapacity"] = v;
        }
        None => input["ResetCapacityReservation"] = json!(true),
    }
    cx.call(V2, "ModifyCapacityReservation", input).await?;
    Ok(())
}

#[async_trait::async_trait]
impl Provider for LoadBalancer {
    fn create_only(&self) -> &'static [&'static str] {
        &["Name", "Scheme", "Type"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &[
            "CanonicalHostedZoneID",
            "DNSName",
            "LoadBalancerArn",
            "LoadBalancerFullName",
            "LoadBalancerName",
            "SecurityGroups",
        ]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("Name")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "Name").unwrap_or_else(|| cx.physical_name(32));
        let mut input = Map::new();
        input.insert("Name".into(), json!(name));
        copy(
            props,
            &mut input,
            &["Type", "Scheme", "IpAddressType", "SubnetMappings", "SecurityGroups", "EnablePrefixForIpv6SourceNat"],
        );
        if props.contains_key("Subnets") {
            input.insert("Subnets".into(), json!(list(props, "Subnets")));
        }
        if let Some(pool) = s(props, "Ipv4IpamPoolId") {
            input.insert("IpamPools".into(), json!({"Ipv4IpamPoolId": pool}));
        }
        let tags = cx.tags(props);
        if !tags.is_empty() {
            input.insert("Tags".into(), Value::Array(tags));
        }
        let out = cx.call(V2, "CreateLoadBalancer", Value::Object(input)).await?;
        let arn = text(&out["LoadBalancers"][0]["LoadBalancerArn"]);
        // The handler waits for the load balancer to become active.
        let lb = stabilize(&format!("Load balancer {arn}"), || async {
            let lb = describe_lb(cx, &arn).await?;
            match lb["State"]["Code"].as_str() {
                Some("active") | Some("active_impaired") => Ok(Some(lb)),
                Some("failed") => Err(HandlerError::handler(
                    "NotStabilized",
                    format!("Load balancer {arn} failed: {}", text(&lb["State"]["Reason"])),
                )),
                _ => Ok(None),
            }
        })
        .await?;
        let attrs = attributes(props, "LoadBalancerAttributes");
        if !attrs.is_empty() {
            cx.call(V2, "ModifyLoadBalancerAttributes", json!({"LoadBalancerArn": arn, "Attributes": attrs})).await?;
        }
        if props.contains_key("EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic") {
            set_security_groups(cx, &arn, props).await?;
        }
        if props.contains_key("MinimumLoadBalancerCapacity") {
            set_capacity(cx, &arn, props).await?;
        }
        let lb = if props.contains_key("EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic") {
            describe_lb(cx, &arn).await?
        } else {
            lb
        };
        Ok(Created { physical_id: arn, attributes: lb_attrs(&lb) })
    }

    async fn update(&self, cx: &Cx<'_>, arn: &str, old: &Props, new: &Props, _attrs: &Props) -> HResult<Props> {
        if changed(old, new, "Subnets") || changed(old, new, "SubnetMappings") {
            let mut input = Map::new();
            input.insert("LoadBalancerArn".into(), json!(arn));
            if new.contains_key("SubnetMappings") {
                copy(new, &mut input, &["SubnetMappings"]);
            } else {
                input.insert("Subnets".into(), json!(list(new, "Subnets")));
            }
            cx.call(V2, "SetSubnets", Value::Object(input)).await?;
        }
        if changed(old, new, "SecurityGroups")
            || changed(old, new, "EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic")
        {
            set_security_groups(cx, arn, new).await?;
        }
        if changed(old, new, "IpAddressType") {
            let t = s(new, "IpAddressType").unwrap_or_else(|| "ipv4".into());
            cx.call(V2, "SetIpAddressType", json!({"LoadBalancerArn": arn, "IpAddressType": t})).await?;
        }
        if changed(old, new, "LoadBalancerAttributes") {
            let attrs = attributes(new, "LoadBalancerAttributes");
            if !attrs.is_empty() {
                cx.call(V2, "ModifyLoadBalancerAttributes", json!({"LoadBalancerArn": arn, "Attributes": attrs}))
                    .await?;
            }
        }
        if changed(old, new, "MinimumLoadBalancerCapacity") {
            set_capacity(cx, arn, new).await?;
        }
        retag(cx, arn, old, new).await?;
        Ok(lb_attrs(&describe_lb(cx, arn).await?))
    }

    async fn delete(&self, cx: &Cx<'_>, arn: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call(V2, "DeleteLoadBalancer", json!({"LoadBalancerArn": arn})).await)?;
        stabilize(&format!("Load balancer {arn}"), || async {
            match describe_lb(cx, arn).await {
                Err(e) if e.not_found => Ok(Some(Value::Null)),
                Err(e) => Err(e),
                Ok(lb) => Ok(lb.is_null().then_some(Value::Null)),
            }
        })
        .await
        .map(|_| ())
    }

    async fn read(&self, cx: &Cx<'_>, arn: &str, props: &Props) -> Option<HResult<Props>> {
        Some(
            async {
                let lb = describe_lb(cx, arn).await?;
                let mut p = Props::new();
                for k in ["Scheme", "Type", "IpAddressType"] {
                    if props.contains_key(k) {
                        p.insert(k.into(), lb[k].clone());
                    }
                }
                if props.contains_key("Name") {
                    p.insert("Name".into(), lb["LoadBalancerName"].clone());
                }
                Ok(p)
            }
            .await,
        )
    }
}

// ---- TargetGroup -------------------------------------------------------

struct TargetGroup;

const HEALTH: &[&str] = &[
    "HealthCheckProtocol",
    "HealthCheckPort",
    "HealthCheckEnabled",
    "HealthCheckPath",
    "HealthCheckIntervalSeconds",
    "HealthCheckTimeoutSeconds",
    "HealthyThresholdCount",
    "UnhealthyThresholdCount",
    "Matcher",
];

fn tg_coerce(v: &mut Value) {
    coerce(
        v,
        &[
            "Port",
            "HealthCheckIntervalSeconds",
            "HealthCheckTimeoutSeconds",
            "HealthyThresholdCount",
            "UnhealthyThresholdCount",
            "TargetControlPort",
        ],
        &["HealthCheckEnabled"],
        &["HealthCheckPort", "HttpCode", "GrpcCode"],
    );
}

fn targets(props: &Props) -> Vec<Value> {
    let mut v = props.get("Targets").cloned().unwrap_or(json!([]));
    coerce(&mut v, &["Port"], &[], &["Id"]);
    v.as_array().cloned().unwrap_or_default()
}

async fn describe_tg(cx: &Cx<'_>, arn: &str) -> HResult<Value> {
    let out = cx.call(V2, "DescribeTargetGroups", json!({"TargetGroupArns": [arn]})).await?;
    Ok(out["TargetGroups"][0].clone())
}

fn tg_attrs(tg: &Value) -> Props {
    let arn = text(&tg["TargetGroupArn"]);
    let mut a = Props::new();
    a.insert("TargetGroupArn".into(), json!(arn));
    a.insert("TargetGroupName".into(), tg["TargetGroupName"].clone());
    a.insert("TargetGroupFullName".into(), json!(arn.rsplit(':').next().unwrap_or_default()));
    a.insert("LoadBalancerArns".into(), tg.get("LoadBalancerArns").cloned().unwrap_or(json!([])));
    a
}

#[async_trait::async_trait]
impl Provider for TargetGroup {
    fn create_only(&self) -> &'static [&'static str] {
        &["Name", "Port", "Protocol", "ProtocolVersion", "TargetType", "VpcId", "IpAddressType", "TargetControlPort"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["LoadBalancerArns", "TargetGroupArn", "TargetGroupFullName", "TargetGroupName"]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("Name")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "Name").unwrap_or_else(|| cx.physical_name(32));
        let mut input = Map::new();
        input.insert("Name".into(), json!(name));
        copy(
            props,
            &mut input,
            &["Protocol", "ProtocolVersion", "Port", "VpcId", "TargetType", "IpAddressType", "TargetControlPort"],
        );
        copy(props, &mut input, HEALTH);
        let tags = cx.tags(props);
        if !tags.is_empty() {
            input.insert("Tags".into(), Value::Array(tags));
        }
        let mut v = Value::Object(input);
        tg_coerce(&mut v);
        let out = cx.call(V2, "CreateTargetGroup", v).await?;
        let tg = out["TargetGroups"][0].clone();
        let arn = text(&tg["TargetGroupArn"]);
        let attrs = attributes(props, "TargetGroupAttributes");
        if !attrs.is_empty() {
            cx.call(V2, "ModifyTargetGroupAttributes", json!({"TargetGroupArn": arn, "Attributes": attrs})).await?;
        }
        let t = targets(props);
        if !t.is_empty() {
            cx.call(V2, "RegisterTargets", json!({"TargetGroupArn": arn, "Targets": t})).await?;
        }
        Ok(Created { physical_id: arn, attributes: tg_attrs(&tg) })
    }

    async fn update(&self, cx: &Cx<'_>, arn: &str, old: &Props, new: &Props, _attrs: &Props) -> HResult<Props> {
        if HEALTH.iter().any(|k| changed(old, new, k)) {
            let mut input = Map::new();
            input.insert("TargetGroupArn".into(), json!(arn));
            copy(new, &mut input, HEALTH);
            let mut v = Value::Object(input);
            tg_coerce(&mut v);
            cx.call(V2, "ModifyTargetGroup", v).await?;
        }
        if changed(old, new, "TargetGroupAttributes") {
            let attrs = attributes(new, "TargetGroupAttributes");
            if !attrs.is_empty() {
                cx.call(V2, "ModifyTargetGroupAttributes", json!({"TargetGroupArn": arn, "Attributes": attrs})).await?;
            }
        }
        if changed(old, new, "Targets") {
            let (was, now) = (targets(old), targets(new));
            let gone: Vec<Value> = was.iter().filter(|t| !now.contains(t)).cloned().collect();
            let added: Vec<Value> = now.iter().filter(|t| !was.contains(t)).cloned().collect();
            if !gone.is_empty() {
                cx.call(V2, "DeregisterTargets", json!({"TargetGroupArn": arn, "Targets": gone})).await?;
            }
            if !added.is_empty() {
                cx.call(V2, "RegisterTargets", json!({"TargetGroupArn": arn, "Targets": added})).await?;
            }
        }
        retag(cx, arn, old, new).await?;
        Ok(tg_attrs(&describe_tg(cx, arn).await?))
    }

    async fn delete(&self, cx: &Cx<'_>, arn: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call(V2, "DeleteTargetGroup", json!({"TargetGroupArn": arn})).await)
    }

    async fn read(&self, cx: &Cx<'_>, arn: &str, props: &Props) -> Option<HResult<Props>> {
        Some(
            async {
                let tg = describe_tg(cx, arn).await?;
                let mut p = Props::new();
                for k in ["Port", "Protocol", "VpcId", "TargetType", "HealthCheckPath", "HealthCheckEnabled"] {
                    if props.contains_key(k) {
                        p.insert(k.into(), tg[k].clone());
                    }
                }
                Ok(p)
            }
            .await,
        )
    }
}

// ---- Listener ----------------------------------------------------------

struct Listener;

fn listener_input(props: &Props) -> Map<String, Value> {
    let mut input = Map::new();
    copy(props, &mut input, &["Protocol", "Port", "SslPolicy", "Certificates", "AlpnPolicy", "MutualAuthentication"]);
    input.insert("DefaultActions".into(), actions(props.get("DefaultActions")));
    let mut v = Value::Object(input);
    coerce(&mut v, &["Port"], &["IgnoreClientCertificateExpiry"], &[]);
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

async fn listener_attributes(cx: &Cx<'_>, arn: &str, props: &Props) -> HResult<()> {
    let attrs = attributes(props, "ListenerAttributes");
    if !attrs.is_empty() {
        cx.call(V2, "ModifyListenerAttributes", json!({"ListenerArn": arn, "Attributes": attrs})).await?;
    }
    Ok(())
}

#[async_trait::async_trait]
impl Provider for Listener {
    fn create_only(&self) -> &'static [&'static str] {
        &["LoadBalancerArn"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["LoadBalancerArn", "DefaultActions"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["ListenerArn"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = listener_input(props);
        input.insert("LoadBalancerArn".into(), json!(req(props, "LoadBalancerArn")?));
        let out = cx.call(V2, "CreateListener", Value::Object(input)).await?;
        let arn = text(&out["Listeners"][0]["ListenerArn"]);
        listener_attributes(cx, &arn, props).await?;
        Ok(Created::new(&arn).attr("ListenerArn", arn.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, arn: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let keys =
            ["Protocol", "Port", "SslPolicy", "Certificates", "AlpnPolicy", "MutualAuthentication", "DefaultActions"];
        if keys.iter().any(|k| changed(old, new, k)) {
            let mut input = listener_input(new);
            input.insert("ListenerArn".into(), json!(arn));
            cx.call(V2, "ModifyListener", Value::Object(input)).await?;
        }
        if changed(old, new, "ListenerAttributes") {
            listener_attributes(cx, arn, new).await?;
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, arn: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call(V2, "DeleteListener", json!({"ListenerArn": arn})).await)
    }
}

// ---- ListenerRule ------------------------------------------------------

struct ListenerRule;

#[async_trait::async_trait]
impl Provider for ListenerRule {
    fn create_only(&self) -> &'static [&'static str] {
        &["ListenerArn"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["Actions", "Conditions", "Priority"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["IsDefault", "RuleArn"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = json!({
            "ListenerArn": req(props, "ListenerArn")?,
            "Priority": props.get("Priority").cloned().unwrap_or(Value::Null),
            "Conditions": conditions(props.get("Conditions")),
            "Actions": actions(props.get("Actions")),
        });
        coerce(&mut input, &["Priority"], &[], &[]);
        if let Some(t) = props.get("Transforms") {
            input["Transforms"] = t.clone();
        }
        let out = cx.call(V2, "CreateRule", input).await?;
        let rule = &out["Rules"][0];
        let arn = text(&rule["RuleArn"]);
        Ok(Created::new(&arn).attr("RuleArn", arn.clone()).attr("IsDefault", rule["IsDefault"].clone()))
    }

    async fn update(&self, cx: &Cx<'_>, arn: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if ["Conditions", "Actions", "Transforms"].iter().any(|k| changed(old, new, k)) {
            let mut input = json!({
                "RuleArn": arn,
                "Conditions": conditions(new.get("Conditions")),
                "Actions": actions(new.get("Actions")),
            });
            match new.get("Transforms") {
                Some(t) => input["Transforms"] = t.clone(),
                None if old.contains_key("Transforms") => input["ResetTransforms"] = json!(true),
                None => {}
            }
            cx.call(V2, "ModifyRule", input).await?;
        }
        if changed(old, new, "Priority") {
            let mut input = json!({"RulePriorities": [{"RuleArn": arn, "Priority": new.get("Priority")}]});
            coerce(&mut input, &["Priority"], &[], &[]);
            cx.call(V2, "SetRulePriorities", input).await?;
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, arn: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call(V2, "DeleteRule", json!({"RuleArn": arn})).await)
    }
}

// ---- ListenerCertificate -----------------------------------------------

struct ListenerCertificate;

fn certificates(props: &Props) -> Vec<Value> {
    props
        .get("Certificates")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(|c| json!({"CertificateArn": text(&c["CertificateArn"])})).collect())
        .unwrap_or_default()
}

#[async_trait::async_trait]
impl Provider for ListenerCertificate {
    fn create_only(&self) -> &'static [&'static str] {
        &["ListenerArn"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["Certificates", "ListenerArn"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let listener = req(props, "ListenerArn")?;
        cx.call(V2, "AddListenerCertificates", json!({"ListenerArn": listener, "Certificates": certificates(props)}))
            .await?;
        Ok(Created::new(cx.physical_name(128)))
    }

    async fn update(&self, cx: &Cx<'_>, _id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let listener = req(new, "ListenerArn")?;
        let (was, now) = (certificates(old), certificates(new));
        let gone: Vec<Value> = was.iter().filter(|c| !now.contains(c)).cloned().collect();
        let added: Vec<Value> = now.iter().filter(|c| !was.contains(c)).cloned().collect();
        if !added.is_empty() {
            cx.call(V2, "AddListenerCertificates", json!({"ListenerArn": listener, "Certificates": added})).await?;
        }
        if !gone.is_empty() {
            cx.call(V2, "RemoveListenerCertificates", json!({"ListenerArn": listener, "Certificates": gone})).await?;
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, _id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let listener = req(props, "ListenerArn")?;
        gone_ok(
            cx.call(
                V2,
                "RemoveListenerCertificates",
                json!({"ListenerArn": listener, "Certificates": certificates(props)}),
            )
            .await,
        )
    }
}

// ---- Classic LoadBalancer ----------------------------------------------

struct ClassicLoadBalancer;

/// CloudFormation listeners as the API's (`PolicyNames` is applied
/// separately).
fn classic_listeners(props: &Props) -> Vec<Value> {
    props
        .get("Listeners")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|l| {
                    let mut out = Map::new();
                    if let Value::Object(m) = l {
                        copy(
                            m,
                            &mut out,
                            &["Protocol", "LoadBalancerPort", "InstanceProtocol", "InstancePort", "SSLCertificateId"],
                        );
                    }
                    let mut v = Value::Object(out);
                    coerce(&mut v, &["LoadBalancerPort", "InstancePort"], &[], &[]);
                    v
                })
                .collect()
        })
        .unwrap_or_default()
}

fn classic_attributes(props: &Props) -> Option<Value> {
    let mut a = Map::new();
    if let Some(c) = super::boolean(props, "CrossZone") {
        a.insert("CrossZoneLoadBalancing".into(), json!({"Enabled": c}));
    }
    if let Some(d) = props.get("ConnectionDrainingPolicy") {
        a.insert("ConnectionDraining".into(), d.clone());
    }
    if let Some(c) = props.get("ConnectionSettings") {
        a.insert("ConnectionSettings".into(), c.clone());
    }
    if let Some(l) = props.get("AccessLoggingPolicy") {
        a.insert("AccessLog".into(), l.clone());
    }
    if a.is_empty() {
        return None;
    }
    let mut v = Value::Object(a);
    coerce(&mut v, &["Timeout", "IdleTimeout", "EmitInterval"], &["Enabled"], &[]);
    Some(v)
}

async fn classic_health_check(cx: &Cx<'_>, name: &str, props: &Props) -> HResult<()> {
    if let Some(h) = props.get("HealthCheck") {
        let mut h = h.clone();
        coerce(&mut h, &["Interval", "Timeout", "UnhealthyThreshold", "HealthyThreshold"], &[], &[]);
        cx.call(CLASSIC, "ConfigureHealthCheck", json!({"LoadBalancerName": name, "HealthCheck": h})).await?;
    }
    Ok(())
}

/// Create the template's policies and attach them (and listeners'
/// `PolicyNames`) to their ports.
async fn classic_policies(cx: &Cx<'_>, name: &str, props: &Props, existing: &[String]) -> HResult<()> {
    let arr = |k: &str| props.get(k).and_then(Value::as_array).cloned().unwrap_or_default();
    for p in arr("AppCookieStickinessPolicy") {
        let pn = text(&p["PolicyName"]);
        if !existing.contains(&pn) {
            cx.call(
                CLASSIC,
                "CreateAppCookieStickinessPolicy",
                json!({"LoadBalancerName": name, "PolicyName": pn, "CookieName": text(&p["CookieName"])}),
            )
            .await?;
        }
    }
    for p in arr("LBCookieStickinessPolicy") {
        let pn = text(&p["PolicyName"]);
        if !existing.contains(&pn) {
            let mut input = json!({"LoadBalancerName": name, "PolicyName": pn});
            if let Some(e) = p.get("CookieExpirationPeriod") {
                input["CookieExpirationPeriod"] = e.clone();
                coerce(&mut input, &["CookieExpirationPeriod"], &[], &[]);
            }
            cx.call(CLASSIC, "CreateLBCookieStickinessPolicy", input).await?;
        }
    }
    let mut listener_policies: BTreeMap<i64, Vec<String>> = BTreeMap::new();
    let mut backend_policies: BTreeMap<i64, Vec<String>> = BTreeMap::new();
    let port = |v: &Value| match v {
        Value::Number(n) => n.as_i64(),
        other => text(other).parse().ok(),
    };
    for p in arr("Policies") {
        let pn = text(&p["PolicyName"]);
        if !existing.contains(&pn) {
            let attrs: Vec<Value> = p["Attributes"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .iter()
                .map(|a| json!({"AttributeName": text(&a["Name"]), "AttributeValue": text(&a["Value"])}))
                .collect();
            cx.call(
                CLASSIC,
                "CreateLoadBalancerPolicy",
                json!({"LoadBalancerName": name, "PolicyName": pn, "PolicyTypeName": text(&p["PolicyType"]), "PolicyAttributes": attrs}),
            )
            .await?;
        }
        for lp in p["LoadBalancerPorts"].as_array().cloned().unwrap_or_default() {
            if let Some(n) = port(&lp) {
                listener_policies.entry(n).or_default().push(pn.clone());
            }
        }
        for ip in p["InstancePorts"].as_array().cloned().unwrap_or_default() {
            if let Some(n) = port(&ip) {
                backend_policies.entry(n).or_default().push(pn.clone());
            }
        }
    }
    for l in arr("Listeners") {
        let names: Vec<String> = l["PolicyNames"].as_array().map(|a| a.iter().map(text).collect()).unwrap_or_default();
        if let Some(n) = port(&l["LoadBalancerPort"]) {
            let e = listener_policies.entry(n).or_default();
            for pn in names {
                if !e.contains(&pn) {
                    e.push(pn);
                }
            }
        }
    }
    for (p, names) in listener_policies {
        cx.call(
            CLASSIC,
            "SetLoadBalancerPoliciesOfListener",
            json!({"LoadBalancerName": name, "LoadBalancerPort": p, "PolicyNames": names}),
        )
        .await?;
    }
    for (p, names) in backend_policies {
        cx.call(
            CLASSIC,
            "SetLoadBalancerPoliciesForBackendServer",
            json!({"LoadBalancerName": name, "InstancePort": p, "PolicyNames": names}),
        )
        .await?;
    }
    Ok(())
}

fn instances(props: &Props) -> Vec<String> {
    list(props, "Instances")
}

async fn describe_classic(cx: &Cx<'_>, name: &str) -> HResult<Value> {
    let out = cx.call(CLASSIC, "DescribeLoadBalancers", json!({"LoadBalancerNames": [name]})).await?;
    Ok(out["LoadBalancerDescriptions"][0].clone())
}

fn classic_attrs(d: &Value) -> Props {
    let mut a = Props::new();
    a.insert("DNSName".into(), json!(text(&d["DNSName"])));
    a.insert("CanonicalHostedZoneName".into(), json!(text(&d["CanonicalHostedZoneName"])));
    a.insert("CanonicalHostedZoneNameID".into(), json!(text(&d["CanonicalHostedZoneNameID"])));
    a.insert("SourceSecurityGroup.GroupName".into(), json!(text(&d["SourceSecurityGroup"]["GroupName"])));
    a.insert("SourceSecurityGroup.OwnerAlias".into(), json!(text(&d["SourceSecurityGroup"]["OwnerAlias"])));
    a
}

#[async_trait::async_trait]
impl Provider for ClassicLoadBalancer {
    fn create_only(&self) -> &'static [&'static str] {
        &["LoadBalancerName", "Scheme"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["Listeners"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &[
            "CanonicalHostedZoneName",
            "CanonicalHostedZoneNameID",
            "DNSName",
            "SourceSecurityGroup.GroupName",
            "SourceSecurityGroup.OwnerAlias",
        ]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("LoadBalancerName")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "LoadBalancerName").unwrap_or_else(|| cx.physical_name(32));
        let mut input = Map::new();
        input.insert("LoadBalancerName".into(), json!(name));
        input.insert("Listeners".into(), Value::Array(classic_listeners(props)));
        for k in ["AvailabilityZones", "Subnets", "SecurityGroups"] {
            if props.contains_key(k) {
                input.insert(k.into(), json!(list(props, k)));
            }
        }
        copy(props, &mut input, &["Scheme"]);
        let tags = cx.tags(props);
        if !tags.is_empty() {
            input.insert("Tags".into(), Value::Array(tags));
        }
        cx.call(CLASSIC, "CreateLoadBalancer", Value::Object(input)).await?;
        classic_health_check(cx, &name, props).await?;
        let inst = instances(props);
        if !inst.is_empty() {
            let ids: Vec<Value> = inst.iter().map(|i| json!({"InstanceId": i})).collect();
            cx.call(CLASSIC, "RegisterInstancesWithLoadBalancer", json!({"LoadBalancerName": name, "Instances": ids}))
                .await?;
        }
        if let Some(a) = classic_attributes(props) {
            cx.call(
                CLASSIC,
                "ModifyLoadBalancerAttributes",
                json!({"LoadBalancerName": name, "LoadBalancerAttributes": a}),
            )
            .await?;
        }
        classic_policies(cx, &name, props, &[]).await?;
        let d = describe_classic(cx, &name).await?;
        Ok(Created { physical_id: name, attributes: classic_attrs(&d) })
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, _attrs: &Props) -> HResult<Props> {
        if changed(old, new, "Listeners") {
            let (was, now) = (classic_listeners(old), classic_listeners(new));
            let gone: Vec<Value> =
                was.iter().filter(|l| !now.contains(l)).map(|l| l["LoadBalancerPort"].clone()).collect();
            let added: Vec<Value> = now.iter().filter(|l| !was.contains(l)).cloned().collect();
            if !gone.is_empty() {
                cx.call(
                    CLASSIC,
                    "DeleteLoadBalancerListeners",
                    json!({"LoadBalancerName": name, "LoadBalancerPorts": gone}),
                )
                .await?;
            }
            if !added.is_empty() {
                cx.call(CLASSIC, "CreateLoadBalancerListeners", json!({"LoadBalancerName": name, "Listeners": added}))
                    .await?;
            }
        }
        if changed(old, new, "HealthCheck") {
            classic_health_check(cx, name, new).await?;
        }
        if changed(old, new, "Instances") {
            let (was, now) = (instances(old), instances(new));
            let gone: Vec<Value> = was.iter().filter(|i| !now.contains(i)).map(|i| json!({"InstanceId": i})).collect();
            let added: Vec<Value> = now.iter().filter(|i| !was.contains(i)).map(|i| json!({"InstanceId": i})).collect();
            if !gone.is_empty() {
                cx.call(
                    CLASSIC,
                    "DeregisterInstancesFromLoadBalancer",
                    json!({"LoadBalancerName": name, "Instances": gone}),
                )
                .await?;
            }
            if !added.is_empty() {
                cx.call(
                    CLASSIC,
                    "RegisterInstancesWithLoadBalancer",
                    json!({"LoadBalancerName": name, "Instances": added}),
                )
                .await?;
            }
        }
        if ["CrossZone", "ConnectionDrainingPolicy", "ConnectionSettings", "AccessLoggingPolicy"]
            .iter()
            .any(|k| changed(old, new, k))
        {
            if let Some(a) = classic_attributes(new) {
                cx.call(
                    CLASSIC,
                    "ModifyLoadBalancerAttributes",
                    json!({"LoadBalancerName": name, "LoadBalancerAttributes": a}),
                )
                .await?;
            }
        }
        if changed(old, new, "SecurityGroups") {
            cx.call(
                CLASSIC,
                "ApplySecurityGroupsToLoadBalancer",
                json!({"LoadBalancerName": name, "SecurityGroups": list(new, "SecurityGroups")}),
            )
            .await?;
        }
        for (k, attach, detach, member) in [
            ("Subnets", "AttachLoadBalancerToSubnets", "DetachLoadBalancerFromSubnets", "Subnets"),
            (
                "AvailabilityZones",
                "EnableAvailabilityZonesForLoadBalancer",
                "DisableAvailabilityZonesForLoadBalancer",
                "AvailabilityZones",
            ),
        ] {
            if changed(old, new, k) {
                let (was, now) = (list(old, k), list(new, k));
                let added: Vec<&String> = now.iter().filter(|x| !was.contains(x)).collect();
                let gone: Vec<&String> = was.iter().filter(|x| !now.contains(x)).collect();
                if !added.is_empty() {
                    cx.call(CLASSIC, attach, json!({"LoadBalancerName": name, member: added})).await?;
                }
                if !gone.is_empty() {
                    cx.call(CLASSIC, detach, json!({"LoadBalancerName": name, member: gone})).await?;
                }
            }
        }
        if ["Policies", "AppCookieStickinessPolicy", "LBCookieStickinessPolicy", "Listeners"]
            .iter()
            .any(|k| changed(old, new, k))
        {
            let out = cx.call(CLASSIC, "DescribeLoadBalancerPolicies", json!({"LoadBalancerName": name})).await?;
            let existing: Vec<String> = out["PolicyDescriptions"]
                .as_array()
                .map(|a| a.iter().map(|p| text(&p["PolicyName"])).collect())
                .unwrap_or_default();
            classic_policies(cx, name, new, &existing).await?;
        }
        if let Some((set, removed)) = tag_changes(cx, old, new, "Tags") {
            if !removed.is_empty() {
                let keys: Vec<Value> = removed.iter().map(|k| json!({"Key": k})).collect();
                cx.call(CLASSIC, "RemoveTags", json!({"LoadBalancerNames": [name], "Tags": keys})).await?;
            }
            if !set.is_empty() {
                cx.call(CLASSIC, "AddTags", json!({"LoadBalancerNames": [name], "Tags": set})).await?;
            }
        }
        Ok(classic_attrs(&describe_classic(cx, name).await?))
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call(CLASSIC, "DeleteLoadBalancer", json!({"LoadBalancerName": name})).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actions_take_api_types() {
        let a = actions(Some(&json!([
            {"Type": "redirect", "RedirectConfig": {"Port": 443, "StatusCode": "HTTP_301"}},
            {"Type": "forward", "ForwardConfig": {"TargetGroups": [{"TargetGroupArn": "x", "Weight": "5"}]}}
        ])));
        assert_eq!(a[0]["RedirectConfig"]["Port"], json!("443"));
        assert_eq!(a[1]["ForwardConfig"]["TargetGroups"][0]["Weight"], json!(5));
        assert_eq!(full_name("arn:aws:elasticloadbalancing:r:1:loadbalancer/app/n/id", ":loadbalancer/"), "app/n/id");
    }
}

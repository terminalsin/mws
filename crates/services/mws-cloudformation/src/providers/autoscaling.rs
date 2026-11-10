//! EC2 Auto Scaling resource types: groups (waiting for their desired
//! capacity to be in service, as CloudFormation does), launch
//! configurations, scaling policies, lifecycle hooks, scheduled actions and
//! warm pools.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::rds::{coerce, pick, settle, stabilize};
use super::{changed, list, req, s, text, Created, Cx, HResult, HandlerError, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::AutoScaling::AutoScalingGroup", Arc::new(Group));
    m.insert("AWS::AutoScaling::LaunchConfiguration", Arc::new(LaunchConfiguration));
    m.insert("AWS::AutoScaling::ScalingPolicy", Arc::new(ScalingPolicy));
    m.insert("AWS::AutoScaling::LifecycleHook", Arc::new(LifecycleHook));
    m.insert("AWS::AutoScaling::ScheduledAction", Arc::new(ScheduledAction));
    m.insert("AWS::AutoScaling::WarmPool", Arc::new(WarmPool));
}

const NUMS: &[&str] = &[
    "Cooldown",
    "DefaultCooldown",
    "DefaultInstanceWarmup",
    "DesiredCapacity",
    "EstimatedInstanceWarmup",
    "HealthCheckGracePeriod",
    "HeartbeatTimeout",
    "HttpPutResponseHopLimit",
    "Iops",
    "MaxCapacityBuffer",
    "MaxGroupPreparedCapacity",
    "MaxHealthyPercentage",
    "MaxInstanceLifetime",
    "MaxSize",
    "MaxSpotPriceAsPercentageOfOptimalOnDemandPrice",
    "MinAdjustmentMagnitude",
    "MinAdjustmentStep",
    "MinHealthyPercentage",
    "MinSize",
    "OnDemandBaseCapacity",
    "OnDemandMaxPricePercentageOverLowestPrice",
    "OnDemandPercentageAboveBaseCapacity",
    "Period",
    "ScalingAdjustment",
    "SchedulingBufferTime",
    "SpotInstancePools",
    "SpotMaxPricePercentageOverLowestPrice",
    "Throughput",
    "VolumeSize",
    "MetricIntervalLowerBound",
    "MetricIntervalUpperBound",
    "TargetValue",
    "Max",
    "Min",
];
const BOOLS: &[&str] = &[
    "AssociatePublicIpAddress",
    "CapacityRebalance",
    "DeleteOnTermination",
    "DisableScaleIn",
    "EbsOptimized",
    "Enabled",
    "Encrypted",
    "NewInstancesProtectedFromScaleIn",
    "NoDevice",
    "PropagateAtLaunch",
    "ReturnData",
    "ReuseOnScaleIn",
    "SkipZonalShiftValidation",
];
const STRS: &[&str] = &[
    "AdjustmentType",
    "DeviceName",
    "ImageId",
    "InstanceType",
    "KeyName",
    "LaunchTemplateId",
    "LaunchTemplateName",
    "MetricAggregationType",
    "NotificationMetadata",
    "PolicyType",
    "Recurrence",
    "SnapshotId",
    "SpotMaxPrice",
    "SpotPrice",
    "TimeZone",
    "UserData",
    "Value",
    "Version",
    "VolumeType",
    "WeightedCapacity",
];

const CREATE_GROUP: &[&str] = &[
    "LaunchConfigurationName",
    "LaunchTemplate",
    "MixedInstancesPolicy",
    "InstanceId",
    "MinSize",
    "MaxSize",
    "DesiredCapacity",
    "DefaultCooldown",
    "AvailabilityZones",
    "AvailabilityZoneIds",
    "LoadBalancerNames",
    "TargetGroupARNs",
    "HealthCheckType",
    "HealthCheckGracePeriod",
    "PlacementGroup",
    "VPCZoneIdentifier",
    "TerminationPolicies",
    "NewInstancesProtectedFromScaleIn",
    "CapacityRebalance",
    "LifecycleHookSpecificationList",
    "DeletionProtection",
    "ServiceLinkedRoleARN",
    "MaxInstanceLifetime",
    "Context",
    "DesiredCapacityType",
    "DefaultInstanceWarmup",
    "TrafficSources",
    "InstanceMaintenancePolicy",
    "AvailabilityZoneDistribution",
    "AvailabilityZoneImpairmentPolicy",
    "SkipZonalShiftValidation",
    "CapacityReservationSpecification",
    "InstanceLifecyclePolicy",
];
const UPDATE_GROUP: &[&str] = &[
    "LaunchConfigurationName",
    "LaunchTemplate",
    "MixedInstancesPolicy",
    "MinSize",
    "MaxSize",
    "DesiredCapacity",
    "DefaultCooldown",
    "AvailabilityZones",
    "AvailabilityZoneIds",
    "HealthCheckType",
    "HealthCheckGracePeriod",
    "PlacementGroup",
    "VPCZoneIdentifier",
    "TerminationPolicies",
    "NewInstancesProtectedFromScaleIn",
    "ServiceLinkedRoleARN",
    "MaxInstanceLifetime",
    "CapacityRebalance",
    "Context",
    "DesiredCapacityType",
    "DefaultInstanceWarmup",
    "InstanceMaintenancePolicy",
    "AvailabilityZoneDistribution",
    "AvailabilityZoneImpairmentPolicy",
    "SkipZonalShiftValidation",
    "CapacityReservationSpecification",
    "InstanceLifecyclePolicy",
    "DeletionProtection",
];
const CREATE_LAUNCH_CONFIGURATION: &[&str] = &[
    "ImageId",
    "KeyName",
    "SecurityGroups",
    "ClassicLinkVPCId",
    "ClassicLinkVPCSecurityGroups",
    "UserData",
    "InstanceId",
    "InstanceType",
    "KernelId",
    "RamdiskId",
    "BlockDeviceMappings",
    "InstanceMonitoring",
    "SpotPrice",
    "IamInstanceProfile",
    "EbsOptimized",
    "AssociatePublicIpAddress",
    "PlacementTenancy",
    "MetadataOptions",
];
const PUT_SCALING_POLICY: &[&str] = &[
    "PolicyType",
    "AdjustmentType",
    "MinAdjustmentMagnitude",
    "ScalingAdjustment",
    "Cooldown",
    "MetricAggregationType",
    "StepAdjustments",
    "EstimatedInstanceWarmup",
    "TargetTrackingConfiguration",
    "PredictiveScalingConfiguration",
];

fn coerced(mut m: Map<String, Value>) -> Map<String, Value> {
    let mut v = Value::Object(std::mem::take(&mut m));
    coerce(&mut v, NUMS, BOOLS, STRS);
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

/// Whether an Auto Scaling error says the thing is gone (Auto Scaling
/// answers `ValidationError` for missing resources).
fn missing(e: &HandlerError) -> bool {
    e.not_found
        || e.code == "ValidationError" && {
            let m = e.message.to_ascii_lowercase();
            m.contains("not found") || m.contains("no lifecycle hook found") || m.contains("no warm pool found")
        }
}

fn gone(r: HResult<Value>) -> HResult<()> {
    match r {
        Ok(_) => Ok(()),
        Err(e) if missing(&e) => Ok(()),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------
// Groups.

fn group_props(props: &Props) -> Map<String, Value> {
    let mut out = props.clone();
    if let Some(v) = out.remove("Cooldown") {
        out.insert("DefaultCooldown".into(), v);
    }
    if props.contains_key("VPCZoneIdentifier") {
        out.insert("VPCZoneIdentifier".into(), json!(list(props, "VPCZoneIdentifier").join(",")));
    }
    for k in ["AvailabilityZones", "LoadBalancerNames", "TargetGroupARNs", "TerminationPolicies"] {
        if props.contains_key(k) {
            out.insert(k.into(), json!(list(props, k)));
        }
    }
    coerced(out)
}

/// The group's tags, with `PropagateAtLaunch`; stack tags propagate.
fn group_tags(cx: &Cx<'_>, name: &str, props: &Props) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    let tag = |k: &str, v: &str, p: bool| json!({"ResourceId": name, "ResourceType": "auto-scaling-group", "Key": k, "Value": v, "PropagateAtLaunch": p});
    for (k, v) in cx.stack_tags {
        out.push(tag(k, v, true));
    }
    if let Some(Value::Array(tags)) = props.get("Tags") {
        for t in tags {
            let k = t.get("Key").map(text).unwrap_or_default();
            let p = match t.get("PropagateAtLaunch") {
                Some(Value::Bool(b)) => *b,
                Some(v) => text(v).eq_ignore_ascii_case("true"),
                None => false,
            };
            out.retain(|x| x["Key"] != json!(k));
            out.push(tag(&k, &t.get("Value").map(text).unwrap_or_default(), p));
        }
    }
    out
}

fn notifications(props: &Props) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    let mut add = |n: &Value| {
        if let Some(topic) = n.get("TopicARN").map(text) {
            let types = match n.get("NotificationTypes") {
                Some(Value::Array(a)) => a.iter().map(text).collect(),
                _ => Vec::new(),
            };
            out.push((topic, types));
        }
    };
    if let Some(Value::Array(a)) = props.get("NotificationConfigurations") {
        a.iter().for_each(&mut add);
    }
    if let Some(n) = props.get("NotificationConfiguration").filter(|v| v.is_object()) {
        add(n);
    }
    out
}

fn metrics(props: &Props) -> Vec<(String, Vec<String>)> {
    match props.get("MetricsCollection") {
        Some(Value::Array(a)) => a
            .iter()
            .map(|m| {
                let metrics = match m.get("Metrics") {
                    Some(Value::Array(x)) => x.iter().map(text).collect(),
                    _ => Vec::new(),
                };
                (m.get("Granularity").map(text).unwrap_or_else(|| "1Minute".into()), metrics)
            })
            .collect(),
        _ => Vec::new(),
    }
}

async fn describe_group(cx: &Cx<'_>, name: &str) -> HResult<Option<Value>> {
    let out = cx.call("autoscaling", "DescribeAutoScalingGroups", json!({"AutoScalingGroupNames": [name]})).await?;
    Ok(out["AutoScalingGroups"].as_array().and_then(|a| a.first()).cloned())
}

/// Wait until the group's desired capacity is in service; CloudFormation
/// reports a group that does not get there as not stabilized.
async fn wait_capacity(cx: &Cx<'_>, name: &str) -> HResult<Value> {
    settle(&format!("Auto Scaling group {name} to reach its desired capacity"), || async move {
        let Some(g) = describe_group(cx, name).await? else {
            return Err(HandlerError::handler("NotFound", format!("Auto Scaling group {name} not found")));
        };
        let desired = g["DesiredCapacity"].as_i64().unwrap_or(0);
        let in_service = g["Instances"]
            .as_array()
            .map(|a| a.iter().filter(|i| i["LifecycleState"] == json!("InService")).count())
            .unwrap_or(0) as i64;
        Ok((in_service >= desired).then_some(g))
    })
    .await
}

struct Group;

#[async_trait::async_trait]
impl Provider for Group {
    fn create_only(&self) -> &'static [&'static str] {
        &["AutoScalingGroupName", "InstanceId", "LoadBalancerNames", "LifecycleHookSpecificationList"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["MinSize", "MaxSize"]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("AutoScalingGroupName")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "AutoScalingGroupName").unwrap_or_else(|| cx.physical_name(255));
        let mut input = pick(&group_props(props), CREATE_GROUP);
        input.insert("AutoScalingGroupName".into(), json!(name));
        let tags = group_tags(cx, &name, props);
        if !tags.is_empty() {
            input.insert("Tags".into(), json!(tags));
        }
        cx.call("autoscaling", "CreateAutoScalingGroup", Value::Object(input)).await?;
        async {
            for (topic, types) in notifications(props) {
                cx.call(
                    "autoscaling",
                    "PutNotificationConfiguration",
                    json!({"AutoScalingGroupName": name, "TopicARN": topic, "NotificationTypes": types}),
                )
                .await?;
            }
            for (granularity, m) in metrics(props) {
                let mut input = json!({"AutoScalingGroupName": name, "Granularity": granularity});
                if !m.is_empty() {
                    input["Metrics"] = json!(m);
                }
                cx.call("autoscaling", "EnableMetricsCollection", input).await?;
            }
            wait_capacity(cx, &name).await
        }
        .await
        .map_err(|e: HandlerError| e.created(&name))?;
        Ok(Created::new(name))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let (o, n) = (group_props(old), group_props(new));
        let mut m: Map<String, Value> = UPDATE_GROUP
            .iter()
            .filter(|k| o.get(**k) != n.get(**k))
            .filter_map(|k| n.get(*k).map(|v| ((*k).to_string(), v.clone())))
            .collect();
        // Switching between a launch configuration and a launch template
        // names the new one; the old one is dropped by the service.
        if !m.is_empty() {
            m.insert("AutoScalingGroupName".into(), json!(name));
            cx.call("autoscaling", "UpdateAutoScalingGroup", Value::Object(m)).await?;
        }
        for (key, attach, detach, member) in [
            ("TargetGroupARNs", "AttachLoadBalancerTargetGroups", "DetachLoadBalancerTargetGroups", "TargetGroupARNs"),
            ("LoadBalancerNames", "AttachLoadBalancers", "DetachLoadBalancers", "LoadBalancerNames"),
        ] {
            if changed(old, new, key) {
                let (ol, nl) = (list(old, key), list(new, key));
                let add: Vec<&String> = nl.iter().filter(|x| !ol.contains(x)).collect();
                let remove: Vec<&String> = ol.iter().filter(|x| !nl.contains(x)).collect();
                if !remove.is_empty() {
                    cx.call("autoscaling", detach, json!({"AutoScalingGroupName": name, member: remove})).await?;
                }
                if !add.is_empty() {
                    cx.call("autoscaling", attach, json!({"AutoScalingGroupName": name, member: add})).await?;
                }
            }
        }
        if changed(old, new, "NotificationConfigurations") || changed(old, new, "NotificationConfiguration") {
            let now = notifications(new);
            for (topic, _) in notifications(old) {
                if !now.iter().any(|(t, _)| *t == topic) {
                    gone(
                        cx.call(
                            "autoscaling",
                            "DeleteNotificationConfiguration",
                            json!({"AutoScalingGroupName": name, "TopicARN": topic}),
                        )
                        .await,
                    )?;
                }
            }
            for (topic, types) in now {
                cx.call(
                    "autoscaling",
                    "PutNotificationConfiguration",
                    json!({"AutoScalingGroupName": name, "TopicARN": topic, "NotificationTypes": types}),
                )
                .await?;
            }
        }
        if changed(old, new, "MetricsCollection") {
            cx.call("autoscaling", "DisableMetricsCollection", json!({"AutoScalingGroupName": name})).await?;
            for (granularity, m) in metrics(new) {
                let mut input = json!({"AutoScalingGroupName": name, "Granularity": granularity});
                if !m.is_empty() {
                    input["Metrics"] = json!(m);
                }
                cx.call("autoscaling", "EnableMetricsCollection", input).await?;
            }
        }
        if changed(old, new, "Tags") {
            let (ot, nt) = (group_tags(cx, name, old), group_tags(cx, name, new));
            let removed: Vec<Value> = ot.iter().filter(|t| !nt.iter().any(|n| n["Key"] == t["Key"])).cloned().collect();
            let set: Vec<Value> = nt.iter().filter(|t| !ot.contains(t)).cloned().collect();
            if !removed.is_empty() {
                cx.call("autoscaling", "DeleteTags", json!({"Tags": removed})).await?;
            }
            if !set.is_empty() {
                cx.call("autoscaling", "CreateOrUpdateTags", json!({"Tags": set})).await?;
            }
        }
        wait_capacity(cx, name).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        // CloudFormation scales the group in to zero (running termination
        // lifecycle hooks), then deletes it.
        if gone(
            cx.call(
                "autoscaling",
                "UpdateAutoScalingGroup",
                json!({"AutoScalingGroupName": name, "MinSize": 0, "MaxSize": 0, "DesiredCapacity": 0}),
            )
            .await,
        )
        .is_ok()
        {
            stabilize(&format!("Auto Scaling group {name} to terminate its instances"), || async move {
                Ok(match describe_group(cx, name).await? {
                    None => true,
                    Some(g) => g["Instances"].as_array().is_none_or(|a| a.is_empty()),
                })
            })
            .await?;
        }
        stabilize(&format!("Auto Scaling group {name} to be deleted"), || async move {
            match cx.call("autoscaling", "DeleteAutoScalingGroup", json!({"AutoScalingGroupName": name})).await {
                Ok(_) => Ok(true),
                Err(e) if missing(&e) => Ok(true),
                // Scaling activities still finishing.
                Err(e) if e.code == "ScalingActivityInProgress" || e.code == "ResourceInUse" => Ok(false),
                Err(e) => Err(e),
            }
        })
        .await
    }
}

// ---------------------------------------------------------------------
// Launch configurations.

struct LaunchConfiguration;

#[async_trait::async_trait]
impl Provider for LaunchConfiguration {
    fn required(&self) -> &'static [&'static str] {
        &["ImageId", "InstanceType"]
    }
    fn updatable(&self) -> bool {
        false
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("LaunchConfigurationName")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "LaunchConfigurationName").unwrap_or_else(|| cx.physical_name(255));
        let mut p = props.clone();
        if let Some(m) = p.get("InstanceMonitoring").cloned() {
            if !m.is_object() {
                p.insert("InstanceMonitoring".into(), json!({"Enabled": m}));
            }
        }
        for k in ["SecurityGroups", "ClassicLinkVPCSecurityGroups"] {
            if props.contains_key(k) {
                p.insert(k.into(), json!(list(props, k)));
            }
        }
        let mut input = coerced(pick(&p, CREATE_LAUNCH_CONFIGURATION));
        input.insert("LaunchConfigurationName".into(), json!(name));
        cx.call("autoscaling", "CreateLaunchConfiguration", Value::Object(input)).await?;
        Ok(Created::new(name))
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone(cx.call("autoscaling", "DeleteLaunchConfiguration", json!({"LaunchConfigurationName": name})).await)
    }
}

// ---------------------------------------------------------------------
// Scaling policies.

struct ScalingPolicy;

impl ScalingPolicy {
    async fn put(&self, cx: &Cx<'_>, group: &str, name: &str, props: &Props) -> HResult<String> {
        let mut input = coerced(pick(props, PUT_SCALING_POLICY));
        input.insert("AutoScalingGroupName".into(), json!(group));
        input.insert("PolicyName".into(), json!(name));
        let out = cx.call("autoscaling", "PutScalingPolicy", Value::Object(input)).await?;
        Ok(text(&out["PolicyARN"]))
    }
}

#[async_trait::async_trait]
impl Provider for ScalingPolicy {
    fn create_only(&self) -> &'static [&'static str] {
        &["AutoScalingGroupName"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["AutoScalingGroupName"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn", "PolicyName"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let group = req(props, "AutoScalingGroupName")?;
        let name = cx.physical_name(255);
        let arn = self.put(cx, &group, &name, props).await?;
        Ok(Created::new(&arn).attr("Arn", arn.clone()).attr("PolicyName", name))
    }

    async fn update(&self, cx: &Cx<'_>, _arn: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let group = req(new, "AutoScalingGroupName")?;
        let name = attrs.get("PolicyName").map(text).unwrap_or_default();
        self.put(cx, &group, &name, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, arn: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let mut input = json!({"PolicyName": arn});
        if let Some(g) = s(props, "AutoScalingGroupName") {
            input["AutoScalingGroupName"] = json!(g);
        }
        gone(cx.call("autoscaling", "DeletePolicy", input).await)
    }
}

// ---------------------------------------------------------------------
// Lifecycle hooks.

struct LifecycleHook;

impl LifecycleHook {
    async fn put(&self, cx: &Cx<'_>, name: &str, props: &Props) -> HResult<()> {
        let mut input = coerced(pick(
            props,
            &[
                "AutoScalingGroupName",
                "LifecycleTransition",
                "RoleARN",
                "NotificationTargetARN",
                "NotificationMetadata",
                "HeartbeatTimeout",
                "DefaultResult",
            ],
        ));
        input.insert("LifecycleHookName".into(), json!(name));
        cx.call("autoscaling", "PutLifecycleHook", Value::Object(input)).await.map(|_| ())
    }
}

#[async_trait::async_trait]
impl Provider for LifecycleHook {
    fn create_only(&self) -> &'static [&'static str] {
        &["AutoScalingGroupName", "LifecycleHookName"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["AutoScalingGroupName", "LifecycleTransition"]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("LifecycleHookName")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "LifecycleHookName").unwrap_or_else(|| cx.physical_name(255));
        self.put(cx, &name, props).await?;
        Ok(Created::new(name))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        self.put(cx, name, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        gone(
            cx.call(
                "autoscaling",
                "DeleteLifecycleHook",
                json!({"AutoScalingGroupName": req(props, "AutoScalingGroupName")?, "LifecycleHookName": name}),
            )
            .await,
        )
    }
}

// ---------------------------------------------------------------------
// Scheduled actions.

struct ScheduledAction;

impl ScheduledAction {
    async fn put(&self, cx: &Cx<'_>, name: &str, props: &Props) -> HResult<()> {
        let mut input = coerced(pick(
            props,
            &[
                "AutoScalingGroupName",
                "StartTime",
                "EndTime",
                "Recurrence",
                "MinSize",
                "MaxSize",
                "DesiredCapacity",
                "TimeZone",
            ],
        ));
        input.insert("ScheduledActionName".into(), json!(name));
        cx.call("autoscaling", "PutScheduledUpdateGroupAction", Value::Object(input)).await.map(|_| ())
    }
}

#[async_trait::async_trait]
impl Provider for ScheduledAction {
    fn create_only(&self) -> &'static [&'static str] {
        &["AutoScalingGroupName"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["AutoScalingGroupName"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["ScheduledActionName"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = cx.physical_name(255);
        self.put(cx, &name, props).await?;
        Ok(Created::new(&name).attr("ScheduledActionName", name.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        self.put(cx, name, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        gone(
            cx.call(
                "autoscaling",
                "DeleteScheduledAction",
                json!({"AutoScalingGroupName": req(props, "AutoScalingGroupName")?, "ScheduledActionName": name}),
            )
            .await,
        )
    }
}

// ---------------------------------------------------------------------
// Warm pools.

struct WarmPool;

impl WarmPool {
    async fn put(&self, cx: &Cx<'_>, props: &Props) -> HResult<String> {
        let group = req(props, "AutoScalingGroupName")?;
        let mut input =
            coerced(pick(props, &["MaxGroupPreparedCapacity", "MinSize", "PoolState", "InstanceReusePolicy"]));
        input.insert("AutoScalingGroupName".into(), json!(group));
        cx.call("autoscaling", "PutWarmPool", Value::Object(input)).await?;
        Ok(group)
    }
}

#[async_trait::async_trait]
impl Provider for WarmPool {
    fn create_only(&self) -> &'static [&'static str] {
        &["AutoScalingGroupName"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["AutoScalingGroupName"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        Ok(Created::new(self.put(cx, props).await?))
    }

    async fn update(&self, cx: &Cx<'_>, _group: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        self.put(cx, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, group: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone(
            cx.call("autoscaling", "DeleteWarmPool", json!({"AutoScalingGroupName": group, "ForceDelete": true})).await,
        )?;
        stabilize(&format!("warm pool of {group} to be deleted"), || async move {
            match cx.call("autoscaling", "DescribeWarmPool", json!({"AutoScalingGroupName": group})).await {
                Ok(out) => Ok(out["WarmPoolConfiguration"].is_null()),
                Err(e) if missing(&e) => Ok(true),
                Err(e) => Err(e),
            }
        })
        .await
    }
}

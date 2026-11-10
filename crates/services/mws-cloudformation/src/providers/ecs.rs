//! Amazon ECS resource types, plus the property-shape helpers the other
//! container-platform providers (ECR, EFS, ELB, SES) share.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Map, Value};

use super::{changed, gone_ok, s, text, Created, Cx, HResult, HandlerError, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::ECS::Cluster", Arc::new(Cluster));
    m.insert("AWS::ECS::TaskDefinition", Arc::new(TaskDefinition));
    m.insert("AWS::ECS::Service", Arc::new(Service));
    m.insert("AWS::ECS::CapacityProvider", Arc::new(CapacityProvider));
    m.insert("AWS::ECS::ClusterCapacityProviderAssociations", Arc::new(ClusterCapacityProviderAssociations));
    m.insert("AWS::ECS::TaskSet", Arc::new(TaskSet));
}

// ---- shared helpers ----------------------------------------------------

/// A CloudFormation (PascalCase) property name as the lowerCamelCase API
/// member: a leading acronym is lowercased whole (`EFSVolumeConfiguration`
/// becomes `efsVolumeConfiguration`, `IAM` becomes `iam`).
pub(super) fn camel_key(k: &str) -> String {
    match k {
        "FSxWindowsFileServerVolumeConfiguration" => return "fsxWindowsFileServerVolumeConfiguration".into(),
        "PlacementStrategies" => return "placementStrategy".into(),
        "ProxyConfigurationProperties" => return "properties".into(),
        "ClusterSettings" => return "settings".into(),
        // EFSVolumeConfiguration spells it this way in CloudFormation.
        "FilesystemId" => return "fileSystemId".into(),
        _ => {}
    }
    let chars: Vec<char> = k.chars().collect();
    let run = chars.iter().take_while(|c| c.is_ascii_uppercase()).count();
    let lower = if run > 1 && chars.get(run).is_some_and(|c| c.is_ascii_lowercase()) { run - 1 } else { run.max(1) };
    chars.iter().enumerate().map(|(i, c)| if i < lower { c.to_ascii_lowercase() } else { *c }).collect()
}

/// `v` with every object key converted by [`camel_key`]. The values of
/// keys in `keep` are user-defined maps (Docker labels, log driver
/// options), whose keys stay as written.
pub(super) fn camel(v: &Value, keep: &[&str]) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .filter(|(_, v)| !v.is_null())
                .map(|(k, v)| (camel_key(k), if keep.contains(&k.as_str()) { v.clone() } else { camel(v, keep) }))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(|x| camel(x, keep)).collect()),
        other => other.clone(),
    }
}

/// Coerce scalars the way CloudFormation does from the type schema: the
/// members named in `ints` become numbers, `bools` booleans and `strings`
/// strings, wherever they appear in `v` (lists are converted element-wise).
pub(super) fn coerce(v: &mut Value, ints: &[&str], bools: &[&str], strings: &[&str]) {
    fn scalar(v: &mut Value, f: &dyn Fn(&Value) -> Option<Value>) {
        match v {
            Value::Array(a) => a.iter_mut().for_each(|x| scalar(x, f)),
            other => {
                if let Some(n) = f(other) {
                    *other = n;
                }
            }
        }
    }
    let to_int = |x: &Value| match x {
        Value::String(s) => s.parse::<i64>().ok().map(Value::from).or_else(|| s.parse::<f64>().ok().map(|f| json!(f))),
        _ => None,
    };
    let to_bool = |x: &Value| match x {
        Value::String(s) => Some(Value::Bool(s.eq_ignore_ascii_case("true"))),
        _ => None,
    };
    let to_str = |x: &Value| match x {
        Value::Number(_) | Value::Bool(_) => Some(Value::String(text(x))),
        _ => None,
    };
    match v {
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                if ints.contains(&k.as_str()) {
                    scalar(x, &to_int);
                } else if bools.contains(&k.as_str()) {
                    scalar(x, &to_bool);
                } else if strings.contains(&k.as_str()) {
                    scalar(x, &to_str);
                } else {
                    coerce(x, ints, bools, strings);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| coerce(x, ints, bools, strings)),
        _ => {}
    }
}

/// The resource's tags under `key` (`Tags`, `FileSystemTags`, ...) plus the
/// stack's, as `[{Key, Value}]`.
pub(super) fn tags_at(cx: &Cx<'_>, props: &Props, key: &str) -> Vec<Value> {
    let mut p = Props::new();
    if let Some(t) = props.get(key) {
        p.insert("Tags".into(), t.clone());
    }
    cx.tags(&p)
}

/// Tags to set and keys to remove when the `key` tags change.
pub(super) fn tag_changes(cx: &Cx<'_>, old: &Props, new: &Props, key: &str) -> Option<(Vec<Value>, Vec<String>)> {
    if !changed(old, new, key) {
        return None;
    }
    let set = tags_at(cx, new, key);
    let keys: Vec<String> = set.iter().map(|t| text(&t["Key"])).collect();
    let removed =
        tags_at(cx, old, key).iter().map(|t| text(&t["Key"])).filter(|k| !keys.contains(k)).collect::<Vec<_>>();
    Some((set, removed))
}

/// `[{Key, Value}]` tags as ECS's `[{key, value}]`.
fn lower_tags(tags: &[Value]) -> Vec<Value> {
    tags.iter().map(|t| json!({"key": t["Key"], "value": t["Value"]})).collect()
}

/// Poll `check` until it returns `Some`, the way resource handlers
/// stabilize.
pub(super) async fn stabilize<F, Fut>(what: &str, mut check: F) -> HResult<Value>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = HResult<Option<Value>>>,
{
    for _ in 0..3000 {
        if let Some(v) = check().await? {
            return Ok(v);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(HandlerError::handler("NotStabilized", format!("{what} did not stabilize")))
}

/// Ignore a failure whose service error code is one of `codes` (services
/// whose "not found" codes don't say NotFound), or NotFound itself.
pub(super) fn gone_codes(r: HResult<Value>, codes: &[&str]) -> HResult<()> {
    match r {
        Err(e) if codes.contains(&e.code.as_str()) => Ok(()),
        other => gone_ok(other),
    }
}

/// Whether a failed call means the resource is gone.
pub(super) fn is_gone(e: &HandlerError, codes: &[&str]) -> bool {
    e.not_found || codes.contains(&e.code.as_str())
}

/// `props` without `skip`, as an API input converted by [`camel`].
fn input_from(props: &Props, skip: &[&str], keep: &[&str]) -> Map<String, Value> {
    let mut p = props.clone();
    for k in skip {
        p.remove(*k);
    }
    match camel(&Value::Object(p), keep) {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

/// User-defined map members in ECS shapes.
const KEEP: &[&str] = &["DockerLabels", "Options", "DriverOpts", "Labels"];

const INTS: &[&str] = &[
    "desiredCount",
    "healthCheckGracePeriodSeconds",
    "maximumPercent",
    "minimumHealthyPercent",
    "bakeTimeInMinutes",
    "weight",
    "base",
    "containerPort",
    "hostPort",
    "cpu",
    "memory",
    "memoryReservation",
    "startTimeout",
    "stopTimeout",
    "softLimit",
    "hardLimit",
    "interval",
    "timeout",
    "retries",
    "startPeriod",
    "sizeInGiB",
    "transitEncryptionPort",
    "sharedMemorySize",
    "maxSwap",
    "swappiness",
    "size",
    "restartAttemptPeriod",
    "ignoredExitCodes",
    "iops",
    "throughput",
    "volumeInitializationRate",
    "targetCapacity",
    "minimumScalingStepSize",
    "maximumScalingStepSize",
    "instanceWarmupPeriod",
    "idleTimeoutSeconds",
    "perRequestTimeoutSeconds",
];

const BOOLS: &[&str] = &[
    "essential",
    "privileged",
    "readonlyRootFilesystem",
    "disableNetworking",
    "interactive",
    "pseudoTerminal",
    "initProcessEnabled",
    "enable",
    "rollback",
    "autoprovision",
    "configuredAtLaunch",
    "enableECSManagedTags",
    "enableExecuteCommand",
    "enableFaultInjection",
    "enabled",
    "encrypted",
    "cloudWatchEncryptionEnabled",
    "s3EncryptionEnabled",
];

fn ecs_input(props: &Props, skip: &[&str]) -> Map<String, Value> {
    let mut v = Value::Object(input_from(props, skip, KEEP));
    coerce(&mut v, INTS, BOOLS, &["value", "name", "key"]);
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

async fn ecs_retag(cx: &Cx<'_>, arn: &str, old: &Props, new: &Props) -> HResult<()> {
    if let Some((set, removed)) = tag_changes(cx, old, new, "Tags") {
        if !removed.is_empty() {
            cx.call("ecs", "UntagResource", json!({"resourceArn": arn, "tagKeys": removed})).await?;
        }
        if !set.is_empty() {
            cx.call("ecs", "TagResource", json!({"resourceArn": arn, "tags": lower_tags(&set)})).await?;
        }
    }
    Ok(())
}

fn with_tags(cx: &Cx<'_>, props: &Props, input: &mut Map<String, Value>) {
    let tags = cx.tags(props);
    if !tags.is_empty() {
        input.insert("tags".into(), Value::Array(lower_tags(&tags)));
    }
}

// ---- Cluster -----------------------------------------------------------

struct Cluster;

#[async_trait::async_trait]
impl Provider for Cluster {
    fn create_only(&self) -> &'static [&'static str] {
        &["ClusterName"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn"]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("ClusterName")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "ClusterName").unwrap_or_else(|| cx.physical_name(255));
        let mut input = ecs_input(props, &["Tags", "ClusterName"]);
        input.insert("clusterName".into(), json!(name));
        with_tags(cx, props, &mut input);
        let out = cx.call("ecs", "CreateCluster", Value::Object(input)).await?;
        let arn = text(&out["cluster"]["clusterArn"]);
        Ok(Created::new(&name).attr("Arn", arn))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if ["ClusterSettings", "Configuration", "ServiceConnectDefaults"].iter().any(|k| changed(old, new, k)) {
            let mut input =
                ecs_input(new, &["Tags", "ClusterName", "CapacityProviders", "DefaultCapacityProviderStrategy"]);
            input.insert("cluster".into(), json!(name));
            if !input.contains_key("settings") && changed(old, new, "ClusterSettings") {
                input.insert("settings".into(), json!([{"name": "containerInsights", "value": "disabled"}]));
            }
            if !input.contains_key("serviceConnectDefaults") && changed(old, new, "ServiceConnectDefaults") {
                input.insert("serviceConnectDefaults".into(), json!({"namespace": ""}));
            }
            cx.call("ecs", "UpdateCluster", Value::Object(input)).await?;
        }
        if changed(old, new, "CapacityProviders") || changed(old, new, "DefaultCapacityProviderStrategy") {
            let p = ecs_input(new, &[]);
            cx.call(
                "ecs",
                "PutClusterCapacityProviders",
                json!({
                    "cluster": name,
                    "capacityProviders": p.get("capacityProviders").cloned().unwrap_or(json!([])),
                    "defaultCapacityProviderStrategy": p.get("defaultCapacityProviderStrategy").cloned().unwrap_or(json!([])),
                }),
            )
            .await?;
        }
        ecs_retag(cx, &text(&attrs["Arn"]), old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("ecs", "DeleteCluster", json!({"cluster": name})).await)
    }

    async fn read(&self, cx: &Cx<'_>, name: &str, _props: &Props) -> Option<HResult<Props>> {
        Some(
            async {
                let out = cx.call("ecs", "DescribeClusters", json!({"clusters": [name]})).await?;
                let c = &out["clusters"][0];
                if c.is_null() || c["status"] == "INACTIVE" {
                    return Err(HandlerError::handler("NotFound", format!("Cluster {name} not found")));
                }
                let mut p = Props::new();
                p.insert("ClusterName".into(), c["clusterName"].clone());
                Ok(p)
            }
            .await,
        )
    }
}

// ---- TaskDefinition ----------------------------------------------------

struct TaskDefinition;

const TASK_DEFINITION_PROPS: &[&str] = &[
    "Family",
    "ContainerDefinitions",
    "Cpu",
    "Memory",
    "ExecutionRoleArn",
    "TaskRoleArn",
    "NetworkMode",
    "RequiresCompatibilities",
    "Volumes",
    "PlacementConstraints",
    "ProxyConfiguration",
    "InferenceAccelerators",
    "IpcMode",
    "PidMode",
    "RuntimePlatform",
    "EphemeralStorage",
    "EnableFaultInjection",
];

#[async_trait::async_trait]
impl Provider for TaskDefinition {
    // A task definition revision is immutable: every change but tags
    // registers a new revision.
    fn create_only(&self) -> &'static [&'static str] {
        TASK_DEFINITION_PROPS
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["TaskDefinitionArn"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let family = s(props, "Family").unwrap_or_else(|| cx.physical_name(255));
        let mut input = ecs_input(props, &["Tags", "Family"]);
        input.insert("family".into(), json!(family));
        // Task-level CPU and memory are strings ("256", "1 vCPU").
        for k in ["cpu", "memory"] {
            if let Some(v) = input.get(k).cloned() {
                input.insert(k.into(), json!(text(&v)));
            }
        }
        with_tags(cx, props, &mut input);
        let out = cx.call("ecs", "RegisterTaskDefinition", Value::Object(input)).await?;
        let arn = text(&out["taskDefinition"]["taskDefinitionArn"]);
        Ok(Created::new(&arn).attr("TaskDefinitionArn", arn.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, arn: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        ecs_retag(cx, arn, old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, arn: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_codes(cx.call("ecs", "DeregisterTaskDefinition", json!({"taskDefinition": arn})).await, &[])
    }
}

// ---- Service -----------------------------------------------------------

struct Service;

/// Properties `UpdateService` applies.
const SERVICE_UPDATABLE: &[&str] = &[
    "TaskDefinition",
    "DesiredCount",
    "CapacityProviderStrategy",
    "DeploymentConfiguration",
    "NetworkConfiguration",
    "PlacementConstraints",
    "PlacementStrategies",
    "PlatformVersion",
    "HealthCheckGracePeriodSeconds",
    "EnableExecuteCommand",
    "EnableECSManagedTags",
    "PropagateTags",
    "LoadBalancers",
    "ServiceRegistries",
    "ServiceConnectConfiguration",
    "VolumeConfigurations",
    "VpcLatticeConfigurations",
    "AvailabilityZoneRebalancing",
    "ForceNewDeployment",
];

fn cluster_of(props: &Props) -> String {
    s(props, "Cluster").unwrap_or_else(|| "default".into())
}

fn external(props: &Props) -> bool {
    props.get("DeploymentController").and_then(|d| d.get("Type")).map(text).is_some_and(|t| t != "ECS")
}

/// Wait for the service to reach a steady state, as the CloudFormation
/// handler does: one deployment, completed, with the desired count running.
async fn wait_steady(cx: &Cx<'_>, cluster: &str, arn: &str) -> HResult<()> {
    stabilize(&format!("ECS service {arn}"), || async {
        let out = cx.call("ecs", "DescribeServices", json!({"cluster": cluster, "services": [arn]})).await?;
        let svc = &out["services"][0];
        if svc.is_null() {
            return Err(HandlerError::handler("NotFound", format!("Service {arn} not found")));
        }
        let deployments = svc["deployments"].as_array().cloned().unwrap_or_default();
        if let Some(primary) = deployments.iter().find(|d| d["status"] == "PRIMARY") {
            if primary["rolloutState"] == "FAILED" {
                return Err(HandlerError::handler(
                    "GeneralServiceException",
                    format!(
                        "Error occurred during operation 'ECS Deployment Circuit Breaker was triggered'. {}",
                        text(&primary["rolloutStateReason"])
                    ),
                ));
            }
            let done = primary["rolloutState"].is_null() || primary["rolloutState"] == "COMPLETED";
            let steady = deployments.len() == 1 && svc["runningCount"] == svc["desiredCount"];
            return Ok((done && steady).then(|| svc.clone()));
        }
        Ok(Some(svc.clone()))
    })
    .await
    .map(|_| ())
}

#[async_trait::async_trait]
impl Provider for Service {
    fn create_only(&self) -> &'static [&'static str] {
        &["Cluster", "DeploymentController", "LaunchType", "Role", "SchedulingStrategy", "ServiceName"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Name", "ServiceArn"]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("ServiceName")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let cluster = cluster_of(props);
        let name = s(props, "ServiceName").unwrap_or_else(|| cx.physical_name(255));
        let mut input = ecs_input(props, &["Tags", "ServiceName", "ForceNewDeployment"]);
        input.insert("serviceName".into(), json!(name));
        input.insert("cluster".into(), json!(cluster));
        with_tags(cx, props, &mut input);
        let out = cx.call("ecs", "CreateService", Value::Object(input)).await?;
        let arn = text(&out["service"]["serviceArn"]);
        if !external(props) {
            wait_steady(cx, &cluster, &arn).await.map_err(|e| e.created(&arn))?;
        }
        Ok(Created::new(&arn).attr("ServiceArn", arn.clone()).attr("Name", name))
    }

    async fn update(&self, cx: &Cx<'_>, arn: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let cluster = cluster_of(new);
        let keys: Vec<&str> = SERVICE_UPDATABLE.iter().copied().filter(|k| changed(old, new, k)).collect();
        if !keys.is_empty() {
            let mut p = Props::new();
            for k in &keys {
                if let Some(v) = new.get(*k) {
                    p.insert((*k).to_string(), v.clone());
                }
            }
            let mut input = ecs_input(&p, &["ForceNewDeployment"]);
            // Removed list properties are cleared.
            for (k, member) in [
                ("LoadBalancers", "loadBalancers"),
                ("ServiceRegistries", "serviceRegistries"),
                ("PlacementConstraints", "placementConstraints"),
                ("PlacementStrategies", "placementStrategy"),
                ("CapacityProviderStrategy", "capacityProviderStrategy"),
                ("VolumeConfigurations", "volumeConfigurations"),
                ("VpcLatticeConfigurations", "vpcLatticeConfigurations"),
            ] {
                if keys.contains(&k) && !new.contains_key(k) {
                    input.insert(member.into(), json!([]));
                }
            }
            if keys.contains(&"DesiredCount") && !new.contains_key("DesiredCount") {
                input.insert("desiredCount".into(), json!(1));
            }
            let force = new
                .get("ForceNewDeployment")
                .and_then(|f| f.get("EnableForceNewDeployment"))
                .is_some_and(|b| b == &json!(true) || b == "true");
            if force {
                input.insert("forceNewDeployment".into(), json!(true));
            }
            input.insert("cluster".into(), json!(cluster));
            input.insert("service".into(), json!(arn));
            cx.call("ecs", "UpdateService", Value::Object(input)).await?;
            if !external(new) {
                wait_steady(cx, &cluster, arn).await?;
            }
        }
        ecs_retag(cx, arn, old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, arn: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let cluster = cluster_of(props);
        let r = cx.call("ecs", "DeleteService", json!({"cluster": cluster, "service": arn, "force": true})).await;
        match r {
            Err(e) if e.not_found || e.code == "ClusterNotFoundException" => return Ok(()),
            Err(e) => return Err(e),
            Ok(_) => {}
        }
        // The handler waits until the service is INACTIVE (its tasks have
        // stopped), so that the cluster can be deleted after it.
        stabilize(&format!("ECS service {arn}"), || async {
            let out = cx.call("ecs", "DescribeServices", json!({"cluster": cluster, "services": [arn]})).await;
            let out = match out {
                Err(e) if e.not_found => return Ok(Some(Value::Null)),
                other => other?,
            };
            let svc = &out["services"][0];
            Ok((svc.is_null() || svc["status"] == "INACTIVE").then_some(Value::Null))
        })
        .await
        .map(|_| ())
    }

    async fn read(&self, cx: &Cx<'_>, arn: &str, props: &Props) -> Option<HResult<Props>> {
        Some(
            async {
                let cluster = cluster_of(props);
                let out = cx.call("ecs", "DescribeServices", json!({"cluster": cluster, "services": [arn]})).await?;
                let svc = &out["services"][0];
                if svc.is_null() || svc["status"] == "INACTIVE" {
                    return Err(HandlerError::handler("NotFound", format!("Service {arn} not found")));
                }
                let mut p = Props::new();
                for (k, member) in [("DesiredCount", "desiredCount"), ("ServiceName", "serviceName")] {
                    if props.contains_key(k) {
                        p.insert(k.into(), svc[member].clone());
                    }
                }
                Ok(p)
            }
            .await,
        )
    }
}

// ---- CapacityProvider --------------------------------------------------

struct CapacityProvider;

#[async_trait::async_trait]
impl Provider for CapacityProvider {
    fn create_only(&self) -> &'static [&'static str] {
        &["Name", "ClusterName"]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("Name")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "Name").unwrap_or_else(|| cx.physical_name(255));
        let mut input = ecs_input(props, &["Tags", "Name", "ClusterName"]);
        input.insert("name".into(), json!(name));
        if let Some(c) = s(props, "ClusterName") {
            input.insert("cluster".into(), json!(c));
        }
        with_tags(cx, props, &mut input);
        cx.call("ecs", "CreateCapacityProvider", Value::Object(input)).await?;
        Ok(Created::new(&name))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "AutoScalingGroupProvider") || changed(old, new, "ManagedInstancesProvider") {
            let mut input = ecs_input(new, &["Tags", "Name", "ClusterName"]);
            if let Some(Value::Object(asg)) = input.get_mut("autoScalingGroupProvider") {
                asg.remove("autoScalingGroupArn");
            }
            input.insert("name".into(), json!(name));
            if let Some(c) = s(new, "ClusterName") {
                input.insert("cluster".into(), json!(c));
            }
            cx.call("ecs", "UpdateCapacityProvider", Value::Object(input)).await?;
        }
        if changed(old, new, "Tags") {
            let out = cx.call("ecs", "DescribeCapacityProviders", json!({"capacityProviders": [name]})).await?;
            let arn = text(&out["capacityProviders"][0]["capacityProviderArn"]);
            ecs_retag(cx, &arn, old, new).await?;
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let mut input = json!({"capacityProvider": name});
        if let Some(c) = s(props, "ClusterName") {
            input["cluster"] = json!(c);
        }
        gone_codes(cx.call("ecs", "DeleteCapacityProvider", input).await, &[])
    }
}

// ---- ClusterCapacityProviderAssociations -------------------------------

struct ClusterCapacityProviderAssociations;

async fn put_providers(cx: &Cx<'_>, props: &Props, clear: bool) -> HResult<Value> {
    let p = ecs_input(props, &[]);
    let (providers, strategy) = if clear {
        (json!([]), json!([]))
    } else {
        (
            p.get("capacityProviders").cloned().unwrap_or(json!([])),
            p.get("defaultCapacityProviderStrategy").cloned().unwrap_or(json!([])),
        )
    };
    cx.call(
        "ecs",
        "PutClusterCapacityProviders",
        json!({"cluster": cluster_of(props), "capacityProviders": providers, "defaultCapacityProviderStrategy": strategy}),
    )
    .await
}

#[async_trait::async_trait]
impl Provider for ClusterCapacityProviderAssociations {
    fn create_only(&self) -> &'static [&'static str] {
        &["Cluster"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["Cluster", "DefaultCapacityProviderStrategy"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        put_providers(cx, props, false).await?;
        Ok(Created::new(cluster_of(props)))
    }

    async fn update(&self, cx: &Cx<'_>, _id: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        put_providers(cx, new, false).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, _id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(put_providers(cx, props, true).await)
    }
}

// ---- TaskSet -----------------------------------------------------------

struct TaskSet;

fn scale(props: &Props) -> Option<Value> {
    let sc = props.get("Scale")?;
    let value = match sc.get("Value") {
        Some(Value::String(s)) => s.parse::<f64>().ok().map(|f| json!(f)),
        Some(v) => Some(v.clone()),
        None => None,
    };
    let mut out = json!({"unit": sc.get("Unit").map(text).unwrap_or_else(|| "PERCENT".into())});
    if let Some(v) = value {
        out["value"] = v;
    }
    Some(out)
}

#[async_trait::async_trait]
impl Provider for TaskSet {
    fn create_only(&self) -> &'static [&'static str] {
        &[
            "Cluster",
            "ExternalId",
            "LaunchType",
            "LoadBalancers",
            "NetworkConfiguration",
            "PlatformVersion",
            "Service",
            "ServiceRegistries",
            "TaskDefinition",
            "CapacityProviderStrategy",
        ]
    }
    fn required(&self) -> &'static [&'static str] {
        &["Cluster", "Service", "TaskDefinition"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Id"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = ecs_input(props, &["Tags", "Scale"]);
        if let Some(sc) = scale(props) {
            input.insert("scale".into(), sc);
        }
        with_tags(cx, props, &mut input);
        let out = cx.call("ecs", "CreateTaskSet", Value::Object(input)).await?;
        let id = text(&out["taskSet"]["id"]);
        Ok(Created::new(&id).attr("Id", id.clone()).attr("TaskSetArn", text(&out["taskSet"]["taskSetArn"])))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "Scale") {
            let sc = scale(new).unwrap_or(json!({"unit": "PERCENT", "value": 100.0}));
            cx.call(
                "ecs",
                "UpdateTaskSet",
                json!({"cluster": cluster_of(new), "service": text(&new["Service"]), "taskSet": id, "scale": sc}),
            )
            .await?;
        }
        if let Some(arn) = attrs.get("TaskSetArn").map(text) {
            ecs_retag(cx, &arn, old, new).await?;
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let r = cx
            .call(
                "ecs",
                "DeleteTaskSet",
                json!({"cluster": cluster_of(props), "service": text(&props["Service"]), "taskSet": id, "force": true}),
            )
            .await;
        gone_codes(r, &["ServiceNotActiveException"])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn camel_keys_follow_the_api_members() {
        assert_eq!(camel_key("TaskRoleArn"), "taskRoleArn");
        assert_eq!(camel_key("EFSVolumeConfiguration"), "efsVolumeConfiguration");
        assert_eq!(camel_key("IAM"), "iam");
        assert_eq!(camel_key("EnableECSManagedTags"), "enableECSManagedTags");
        assert_eq!(camel_key("S3BucketName"), "s3BucketName");
        assert_eq!(camel_key("SizeInGiB"), "sizeInGiB");
        assert_eq!(camel_key("PlacementStrategies"), "placementStrategy");
        let v = camel(&json!({"DockerLabels": {"Foo": "x"}, "PortMappings": [{"ContainerPort": "80"}]}), KEEP);
        assert_eq!(v, json!({"dockerLabels": {"Foo": "x"}, "portMappings": [{"containerPort": "80"}]}));
        let mut v = v;
        coerce(&mut v, INTS, BOOLS, &[]);
        assert_eq!(v["portMappings"][0]["containerPort"], json!(80));
    }
}

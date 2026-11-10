//! EKS resource types: clusters, managed node groups, add-ons and Fargate
//! profiles (waiting for them to become `ACTIVE`, as CloudFormation's
//! handlers do), access entries and pod identity associations.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::rds::{coerce, failed, settle, wait_gone};
use super::{boolean, changed, gone_ok, list, req, s, text, Created, Cx, HResult, HandlerError, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::EKS::Cluster", Arc::new(Cluster));
    m.insert("AWS::EKS::Nodegroup", Arc::new(Nodegroup));
    m.insert("AWS::EKS::Addon", Arc::new(Addon));
    m.insert("AWS::EKS::FargateProfile", Arc::new(FargateProfile));
    m.insert("AWS::EKS::AccessEntry", Arc::new(AccessEntry));
    m.insert("AWS::EKS::PodIdentityAssociation", Arc::new(PodIdentityAssociation));
}

/// A CloudFormation structure (PascalCase) under the camelCase member
/// names of the REST JSON APIs (EKS, GuardDuty). Keys of the objects named
/// in `opaque` (maps such as labels) are kept as written.
pub(super) fn camel(v: &Value, opaque: &[&str]) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| {
                    let key = lower_first(k);
                    let x = if opaque.contains(&k.as_str()) { x.clone() } else { camel(x, opaque) };
                    (key, x)
                })
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(|x| camel(x, opaque)).collect()),
        other => other.clone(),
    }
}

fn lower_first(k: &str) -> String {
    let mut c = k.chars();
    match c.next() {
        Some(f) => f.to_lowercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

const NUMS: &[&str] = &["minSize", "maxSize", "desiredSize", "diskSize", "maxUnavailable", "maxUnavailablePercentage"];
const BOOLS: &[&str] = &[
    "endpointPublicAccess",
    "endpointPrivateAccess",
    "enabled",
    "bootstrapClusterCreatorAdminPermissions",
    "bootstrapSelfManagedAddons",
    "deletionProtection",
    "disableSessionTags",
];
const STRS: &[&str] = &["version", "releaseVersion", "value", "key"];

fn api(v: &Value) -> Value {
    let mut v = camel(v, &["Labels", "Tags"]);
    coerce(&mut v, NUMS, BOOLS, STRS);
    v
}

/// Copy the CloudFormation properties `keys` into `out` under their
/// camelCase API names.
fn put(out: &mut Map<String, Value>, props: &Props, keys: &[&str]) {
    for k in keys {
        if let Some(v) = props.get(*k).filter(|v| !v.is_null()) {
            let mut one = Map::new();
            one.insert((*k).to_string(), v.clone());
            if let Value::Object(m) = api(&Value::Object(one)) {
                out.extend(m);
            }
        }
    }
}

async fn retag(cx: &Cx<'_>, arn: &str, old: &Props, new: &Props) -> HResult<()> {
    if !changed(old, new, "Tags") {
        return Ok(());
    }
    let (o, n) = (cx.tag_map(old), cx.tag_map(new));
    let removed: Vec<&String> = o.keys().filter(|k| !n.contains_key(*k)).collect();
    if !removed.is_empty() {
        cx.call("eks", "UntagResource", json!({"resourceArn": arn, "tagKeys": removed})).await?;
    }
    let set: Map<String, Value> = n.into_iter().filter(|(k, v)| o.get(k) != Some(v)).collect();
    if !set.is_empty() {
        cx.call("eks", "TagResource", json!({"resourceArn": arn, "tags": set})).await?;
    }
    Ok(())
}

/// Wait for an EKS object to become `ACTIVE`.
async fn wait_active<F, Fut>(what: &str, describe: F) -> HResult<Value>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = HResult<Value>>,
{
    settle(&format!("{what} to become ACTIVE"), || {
        let f = describe();
        async move {
            let v = f.await?;
            match text(&v["status"]).as_str() {
                "ACTIVE" => Ok(Some(v)),
                s @ ("FAILED" | "CREATE_FAILED" | "DEGRADED" | "DELETE_FAILED") => Err(failed(what, s)),
                _ => Ok(None),
            }
        }
    })
    .await
}

// ---------------------------------------------------------------------
// Clusters.

const LOG_TYPES: &[&str] = &["api", "audit", "authenticator", "controllerManager", "scheduler"];

/// `Logging.ClusterLogging.EnabledTypes` as the API's `logging`.
fn logging(props: &Props) -> Option<Value> {
    let l = props.get("Logging")?;
    let enabled: Vec<String> = l["ClusterLogging"]["EnabledTypes"]
        .as_array()
        .map(|a| a.iter().map(|t| text(&t["Type"])).collect())
        .unwrap_or_default();
    let disabled: Vec<&str> = LOG_TYPES.iter().copied().filter(|t| !enabled.iter().any(|e| e == t)).collect();
    let mut setups = Vec::new();
    if !enabled.is_empty() {
        setups.push(json!({"types": enabled, "enabled": true}));
    }
    if !disabled.is_empty() {
        setups.push(json!({"types": disabled, "enabled": false}));
    }
    Some(json!({"clusterLogging": setups}))
}

async fn describe_cluster(cx: &Cx<'_>, name: &str) -> HResult<Value> {
    Ok(cx.call("eks", "DescribeCluster", json!({"name": name})).await?["cluster"].clone())
}

async fn wait_cluster(cx: &Cx<'_>, name: &str) -> HResult<Value> {
    wait_active(&format!("Cluster {name}"), || describe_cluster(cx, name)).await
}

fn cluster_attributes(c: &Value) -> Props {
    let mut a = Props::new();
    a.insert("Arn".into(), json!(text(&c["arn"])));
    a.insert("Endpoint".into(), json!(text(&c["endpoint"])));
    a.insert("CertificateAuthorityData".into(), json!(text(&c["certificateAuthority"]["data"])));
    a.insert("ClusterSecurityGroupId".into(), json!(text(&c["resourcesVpcConfig"]["clusterSecurityGroupId"])));
    a.insert("EncryptionConfigKeyArn".into(), json!(text(&c["encryptionConfig"][0]["provider"]["keyArn"])));
    a.insert("Id".into(), json!(text(&c["id"])));
    a.insert("OpenIdConnectIssuerUrl".into(), json!(text(&c["identity"]["oidc"]["issuer"])));
    a.insert(
        "KubernetesNetworkConfig.ServiceIpv6Cidr".into(),
        json!(text(&c["kubernetesNetworkConfig"]["serviceIpv6Cidr"])),
    );
    a
}

struct Cluster;

#[async_trait::async_trait]
impl Provider for Cluster {
    fn create_only(&self) -> &'static [&'static str] {
        &["Name", "RoleArn", "EncryptionConfig", "OutpostConfig", "BootstrapSelfManagedAddons"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["RoleArn", "ResourcesVpcConfig"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &[
            "Arn",
            "Endpoint",
            "CertificateAuthorityData",
            "ClusterSecurityGroupId",
            "EncryptionConfigKeyArn",
            "Id",
            "OpenIdConnectIssuerUrl",
            "KubernetesNetworkConfig.ServiceIpv6Cidr",
        ]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("Name")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "Name").unwrap_or_else(|| cx.physical_name(100));
        let mut input = Map::new();
        input.insert("name".into(), json!(name));
        put(
            &mut input,
            props,
            &[
                "Version",
                "RoleArn",
                "ResourcesVpcConfig",
                "KubernetesNetworkConfig",
                "EncryptionConfig",
                "OutpostConfig",
                "AccessConfig",
                "BootstrapSelfManagedAddons",
                "UpgradePolicy",
                "ZonalShiftConfig",
                "RemoteNetworkConfig",
                "ComputeConfig",
                "StorageConfig",
                "DeletionProtection",
                "ControlPlaneScalingConfig",
            ],
        );
        if let Some(l) = logging(props) {
            input.insert("logging".into(), l);
        }
        let tags = cx.tag_map(props);
        if !tags.is_empty() {
            input.insert("tags".into(), Value::Object(tags));
        }
        cx.call("eks", "CreateCluster", Value::Object(input)).await?;
        let c = wait_cluster(cx, &name).await?;
        Ok(Created { physical_id: name, attributes: cluster_attributes(&c) })
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, _attrs: &Props) -> HResult<Props> {
        // EKS runs one update at a time: wait between them.
        if changed(old, new, "Version") {
            let version = req(new, "Version")?;
            cx.call("eks", "UpdateClusterVersion", json!({"name": name, "version": version})).await?;
            wait_cluster(cx, name).await?;
        }
        let config_keys = [
            "ResourcesVpcConfig",
            "AccessConfig",
            "UpgradePolicy",
            "ZonalShiftConfig",
            "ComputeConfig",
            "KubernetesNetworkConfig",
            "StorageConfig",
            "RemoteNetworkConfig",
            "DeletionProtection",
            "ControlPlaneScalingConfig",
        ];
        for k in config_keys {
            if changed(old, new, k) {
                let mut input = Map::new();
                input.insert("name".into(), json!(name));
                if k == "ResourcesVpcConfig" {
                    // Only the endpoint settings and the network change in
                    // place.
                    let mut vpc = Map::new();
                    put(
                        &mut vpc,
                        new.get(k).and_then(Value::as_object).unwrap_or(&Map::new()),
                        &[
                            "SubnetIds",
                            "SecurityGroupIds",
                            "EndpointPublicAccess",
                            "EndpointPrivateAccess",
                            "PublicAccessCidrs",
                        ],
                    );
                    input.insert("resourcesVpcConfig".into(), Value::Object(vpc));
                } else if k == "AccessConfig" {
                    let mut access = Map::new();
                    put(
                        &mut access,
                        new.get(k).and_then(Value::as_object).unwrap_or(&Map::new()),
                        &["AuthenticationMode"],
                    );
                    input.insert("accessConfig".into(), Value::Object(access));
                } else if k == "DeletionProtection" {
                    input.insert("deletionProtection".into(), json!(boolean(new, k).unwrap_or(false)));
                } else {
                    put(&mut input, new, &[k]);
                }
                cx.call("eks", "UpdateClusterConfig", Value::Object(input)).await?;
                wait_cluster(cx, name).await?;
            }
        }
        if changed(old, new, "Logging") {
            let l = logging(new).unwrap_or_else(|| json!({"clusterLogging": [{"types": LOG_TYPES, "enabled": false}]}));
            cx.call("eks", "UpdateClusterConfig", json!({"name": name, "logging": l})).await?;
            wait_cluster(cx, name).await?;
        }
        let c = wait_cluster(cx, name).await?;
        retag(cx, &text(&c["arn"]), old, new).await?;
        Ok(cluster_attributes(&c))
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        match cx.call("eks", "DeleteCluster", json!({"name": name})).await {
            Err(e) if e.not_found => return Ok(()),
            r => {
                r?;
            }
        }
        wait_gone(&format!("Cluster {name} to be deleted"), || describe_cluster(cx, name)).await
    }
}

// ---------------------------------------------------------------------
// Node groups.

fn split2(id: &str, sep: char) -> HResult<(&str, &str)> {
    id.split_once(sep).ok_or_else(|| HandlerError::handler("NotFound", format!("Malformed identifier {id}")))
}

async fn describe_nodegroup(cx: &Cx<'_>, cluster: &str, name: &str) -> HResult<Value> {
    Ok(cx.call("eks", "DescribeNodegroup", json!({"clusterName": cluster, "nodegroupName": name})).await?["nodegroup"]
        .clone())
}

async fn wait_nodegroup(cx: &Cx<'_>, cluster: &str, name: &str) -> HResult<Value> {
    wait_active(&format!("Nodegroup {name}"), || describe_nodegroup(cx, cluster, name)).await
}

fn nodegroup_attributes(n: &Value) -> Props {
    let mut a = Props::new();
    a.insert("Arn".into(), json!(text(&n["nodegroupArn"])));
    a.insert("ClusterName".into(), json!(text(&n["clusterName"])));
    a.insert("NodegroupName".into(), json!(text(&n["nodegroupName"])));
    a.insert("Id".into(), json!(format!("{}/{}", text(&n["clusterName"]), text(&n["nodegroupName"]))));
    a
}

fn label_map(props: &Props) -> Map<String, Value> {
    match props.get("Labels") {
        Some(Value::Object(m)) => m.iter().map(|(k, v)| (k.clone(), json!(text(v)))).collect(),
        _ => Map::new(),
    }
}

fn taints(props: &Props) -> Vec<Value> {
    props.get("Taints").map(api).and_then(|v| v.as_array().cloned()).unwrap_or_default()
}

struct Nodegroup;

#[async_trait::async_trait]
impl Provider for Nodegroup {
    fn create_only(&self) -> &'static [&'static str] {
        &[
            "ClusterName",
            "NodegroupName",
            "Subnets",
            "NodeRole",
            "AmiType",
            "CapacityType",
            "DiskSize",
            "InstanceTypes",
            "RemoteAccess",
        ]
    }
    fn required(&self) -> &'static [&'static str] {
        &["ClusterName", "NodeRole", "Subnets"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn", "ClusterName", "NodegroupName", "Id"]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("NodegroupName")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let cluster = req(props, "ClusterName")?;
        let name = s(props, "NodegroupName").unwrap_or_else(|| format!("{}-{}", cx.logical_id, random(12)));
        let mut input = Map::new();
        input.insert("clusterName".into(), json!(cluster));
        input.insert("nodegroupName".into(), json!(name));
        put(
            &mut input,
            props,
            &[
                "ScalingConfig",
                "DiskSize",
                "Subnets",
                "InstanceTypes",
                "AmiType",
                "RemoteAccess",
                "NodeRole",
                "Taints",
                "LaunchTemplate",
                "UpdateConfig",
                "NodeRepairConfig",
                "CapacityType",
                "Version",
                "ReleaseVersion",
            ],
        );
        let labels = label_map(props);
        if !labels.is_empty() {
            input.insert("labels".into(), Value::Object(labels));
        }
        let tags = cx.tag_map(props);
        if !tags.is_empty() {
            input.insert("tags".into(), Value::Object(tags));
        }
        cx.call("eks", "CreateNodegroup", Value::Object(input)).await?;
        let n = wait_nodegroup(cx, &cluster, &name).await?;
        Ok(Created { physical_id: format!("{cluster}/{name}"), attributes: nodegroup_attributes(&n) })
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, _attrs: &Props) -> HResult<Props> {
        let (cluster, name) = split2(id, '/')?;
        let wait = || wait_nodegroup(cx, cluster, name);
        if ["Version", "ReleaseVersion", "LaunchTemplate"].iter().any(|k| changed(old, new, k)) {
            let mut input = Map::new();
            input.insert("clusterName".into(), json!(cluster));
            input.insert("nodegroupName".into(), json!(name));
            put(&mut input, new, &["Version", "ReleaseVersion", "LaunchTemplate"]);
            if boolean(new, "ForceUpdateEnabled") == Some(true) {
                input.insert("force".into(), json!(true));
            }
            cx.call("eks", "UpdateNodegroupVersion", Value::Object(input)).await?;
            wait().await?;
        }
        let mut input = Map::new();
        if changed(old, new, "Labels") {
            let (o, n) = (label_map(old), label_map(new));
            let remove: Vec<&String> = o.keys().filter(|k| !n.contains_key(*k)).collect();
            let add: Map<String, Value> =
                n.iter().filter(|(k, v)| o.get(*k) != Some(v)).map(|(k, v)| (k.clone(), v.clone())).collect();
            input.insert("labels".into(), json!({"addOrUpdateLabels": add, "removeLabels": remove}));
        }
        if changed(old, new, "Taints") {
            let (o, n) = (taints(old), taints(new));
            let remove: Vec<&Value> = o.iter().filter(|t| !n.iter().any(|x| x["key"] == t["key"])).collect();
            let add: Vec<&Value> = n.iter().filter(|t| !o.contains(t)).collect();
            input.insert("taints".into(), json!({"addOrUpdateTaints": add, "removeTaints": remove}));
        }
        for k in ["ScalingConfig", "UpdateConfig", "NodeRepairConfig"] {
            if changed(old, new, k) {
                put(&mut input, new, &[k]);
            }
        }
        if !input.is_empty() {
            input.insert("clusterName".into(), json!(cluster));
            input.insert("nodegroupName".into(), json!(name));
            cx.call("eks", "UpdateNodegroupConfig", Value::Object(input)).await?;
            wait().await?;
        }
        let n = wait().await?;
        retag(cx, &text(&n["nodegroupArn"]), old, new).await?;
        Ok(nodegroup_attributes(&n))
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        let (cluster, name) = split2(id, '/')?;
        match cx.call("eks", "DeleteNodegroup", json!({"clusterName": cluster, "nodegroupName": name})).await {
            Err(e) if e.not_found => return Ok(()),
            r => {
                r?;
            }
        }
        wait_gone(&format!("Nodegroup {name} to be deleted"), || describe_nodegroup(cx, cluster, name)).await
    }
}

fn random(n: usize) -> String {
    use rand::Rng;
    const A: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..n).map(|_| A[rng.gen_range(0..A.len())] as char).collect()
}

// ---------------------------------------------------------------------
// Add-ons.

async fn describe_addon(cx: &Cx<'_>, cluster: &str, name: &str) -> HResult<Value> {
    Ok(cx.call("eks", "DescribeAddon", json!({"clusterName": cluster, "addonName": name})).await?["addon"].clone())
}

struct Addon;

#[async_trait::async_trait]
impl Provider for Addon {
    fn create_only(&self) -> &'static [&'static str] {
        &["ClusterName", "AddonName", "NamespaceConfig"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["ClusterName", "AddonName"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let cluster = req(props, "ClusterName")?;
        let name = req(props, "AddonName")?;
        let mut input = Map::new();
        input.insert("clusterName".into(), json!(cluster));
        input.insert("addonName".into(), json!(name));
        put(
            &mut input,
            props,
            &[
                "AddonVersion",
                "ServiceAccountRoleArn",
                "ResolveConflicts",
                "ConfigurationValues",
                "PodIdentityAssociations",
                "NamespaceConfig",
            ],
        );
        let tags = cx.tag_map(props);
        if !tags.is_empty() {
            input.insert("tags".into(), Value::Object(tags));
        }
        cx.call("eks", "CreateAddon", Value::Object(input)).await?;
        let a = wait_active(&format!("Addon {name}"), || describe_addon(cx, &cluster, &name)).await?;
        Ok(Created::new(format!("{cluster}|{name}")).attr("Arn", text(&a["addonArn"])))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let (cluster, name) = split2(id, '|')?;
        let keys = ["AddonVersion", "ServiceAccountRoleArn", "ConfigurationValues", "PodIdentityAssociations"];
        if keys.iter().any(|k| changed(old, new, k)) {
            let mut input = Map::new();
            input.insert("clusterName".into(), json!(cluster));
            input.insert("addonName".into(), json!(name));
            put(&mut input, new, &keys);
            put(&mut input, new, &["ResolveConflicts"]);
            if changed(old, new, "PodIdentityAssociations") && !new.contains_key("PodIdentityAssociations") {
                input.insert("podIdentityAssociations".into(), json!([]));
            }
            cx.call("eks", "UpdateAddon", Value::Object(input)).await?;
        }
        let a = wait_active(&format!("Addon {name}"), || describe_addon(cx, cluster, name)).await?;
        retag(cx, &text(&a["addonArn"]), old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let (cluster, name) = split2(id, '|')?;
        let preserve = boolean(props, "PreserveOnDelete").unwrap_or(false);
        match cx
            .call("eks", "DeleteAddon", json!({"clusterName": cluster, "addonName": name, "preserve": preserve}))
            .await
        {
            Err(e) if e.not_found => return Ok(()),
            r => {
                r?;
            }
        }
        wait_gone(&format!("Addon {name} to be deleted"), || describe_addon(cx, cluster, name)).await
    }
}

// ---------------------------------------------------------------------
// Fargate profiles.

async fn describe_profile(cx: &Cx<'_>, cluster: &str, name: &str) -> HResult<Value> {
    Ok(cx.call("eks", "DescribeFargateProfile", json!({"clusterName": cluster, "fargateProfileName": name})).await?
        ["fargateProfile"]
        .clone())
}

struct FargateProfile;

#[async_trait::async_trait]
impl Provider for FargateProfile {
    fn create_only(&self) -> &'static [&'static str] {
        &["ClusterName", "FargateProfileName", "PodExecutionRoleArn", "Subnets", "Selectors"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["ClusterName", "PodExecutionRoleArn", "Selectors"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn"]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("FargateProfileName")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let cluster = req(props, "ClusterName")?;
        let name = s(props, "FargateProfileName").unwrap_or_else(|| format!("{}-{}", cx.logical_id, random(12)));
        let mut input = Map::new();
        input.insert("clusterName".into(), json!(cluster));
        input.insert("fargateProfileName".into(), json!(name));
        put(&mut input, props, &["PodExecutionRoleArn", "Subnets"]);
        if let Some(sel) = props.get("Selectors") {
            input.insert("selectors".into(), camel(sel, &["Labels"]));
            // Labels are a `[{Key, Value}]` list in the template and a map
            // in the API.
            if let Some(a) = input["selectors"].as_array_mut() {
                for s in a {
                    if let Some(Value::Array(labels)) = s.get("labels").cloned() {
                        let m: Map<String, Value> =
                            labels.iter().map(|l| (text(&l["Key"]), json!(text(&l["Value"])))).collect();
                        s["labels"] = Value::Object(m);
                    }
                }
            }
        }
        let tags = cx.tag_map(props);
        if !tags.is_empty() {
            input.insert("tags".into(), Value::Object(tags));
        }
        cx.call("eks", "CreateFargateProfile", Value::Object(input)).await?;
        let p = wait_active(&format!("Fargate profile {name}"), || describe_profile(cx, &cluster, &name)).await?;
        Ok(Created::new(format!("{cluster}|{name}")).attr("Arn", text(&p["fargateProfileArn"])))
    }

    async fn update(&self, cx: &Cx<'_>, _id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        retag(cx, &text(&attrs["Arn"]), old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        let (cluster, name) = split2(id, '|')?;
        match cx.call("eks", "DeleteFargateProfile", json!({"clusterName": cluster, "fargateProfileName": name})).await
        {
            Err(e) if e.not_found => return Ok(()),
            r => {
                r?;
            }
        }
        wait_gone(&format!("Fargate profile {name} to be deleted"), || describe_profile(cx, cluster, name)).await
    }
}

// ---------------------------------------------------------------------
// Access entries.

fn policies(props: &Props) -> BTreeMap<String, Value> {
    props
        .get("AccessPolicies")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(|p| (text(&p["PolicyArn"]), camel(&p["AccessScope"], &[]))).collect())
        .unwrap_or_default()
}

struct AccessEntry;

#[async_trait::async_trait]
impl Provider for AccessEntry {
    fn create_only(&self) -> &'static [&'static str] {
        &["ClusterName", "PrincipalArn", "Type"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["ClusterName", "PrincipalArn"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["AccessEntryArn"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let cluster = req(props, "ClusterName")?;
        let principal = req(props, "PrincipalArn")?;
        let mut input = Map::new();
        input.insert("clusterName".into(), json!(cluster));
        input.insert("principalArn".into(), json!(principal));
        put(&mut input, props, &["KubernetesGroups", "Username", "Type"]);
        let tags = cx.tag_map(props);
        if !tags.is_empty() {
            input.insert("tags".into(), Value::Object(tags));
        }
        let out = cx.call("eks", "CreateAccessEntry", Value::Object(input)).await?;
        let arn = text(&out["accessEntry"]["accessEntryArn"]);
        for (policy, scope) in policies(props) {
            cx.call(
                "eks",
                "AssociateAccessPolicy",
                json!({"clusterName": cluster, "principalArn": principal, "policyArn": policy, "accessScope": scope}),
            )
            .await?;
        }
        Ok(Created::new(format!("{cluster}|{principal}")).attr("AccessEntryArn", arn))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let (cluster, principal) = split2(id, '|')?;
        if changed(old, new, "KubernetesGroups") || changed(old, new, "Username") {
            let mut input = Map::new();
            input.insert("clusterName".into(), json!(cluster));
            input.insert("principalArn".into(), json!(principal));
            input.insert("kubernetesGroups".into(), json!(list(new, "KubernetesGroups")));
            put(&mut input, new, &["Username"]);
            cx.call("eks", "UpdateAccessEntry", Value::Object(input)).await?;
        }
        if changed(old, new, "AccessPolicies") {
            let (o, n) = (policies(old), policies(new));
            for p in o.keys().filter(|k| !n.contains_key(*k)) {
                gone_ok(
                    cx.call(
                        "eks",
                        "DisassociateAccessPolicy",
                        json!({"clusterName": cluster, "principalArn": principal, "policyArn": p}),
                    )
                    .await,
                )?;
            }
            for (p, scope) in n.iter().filter(|(k, v)| o.get(*k) != Some(v)) {
                cx.call(
                    "eks",
                    "AssociateAccessPolicy",
                    json!({"clusterName": cluster, "principalArn": principal, "policyArn": p, "accessScope": scope}),
                )
                .await?;
            }
        }
        retag(cx, &text(&attrs["AccessEntryArn"]), old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        let (cluster, principal) = split2(id, '|')?;
        gone_ok(cx.call("eks", "DeleteAccessEntry", json!({"clusterName": cluster, "principalArn": principal})).await)
    }
}

// ---------------------------------------------------------------------
// Pod identity associations.

struct PodIdentityAssociation;

#[async_trait::async_trait]
impl Provider for PodIdentityAssociation {
    fn create_only(&self) -> &'static [&'static str] {
        &["ClusterName", "Namespace", "ServiceAccount"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["ClusterName", "Namespace", "ServiceAccount", "RoleArn"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["AssociationArn", "AssociationId", "ExternalId"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = Map::new();
        put(
            &mut input,
            props,
            &["ClusterName", "Namespace", "ServiceAccount", "RoleArn", "DisableSessionTags", "TargetRoleArn", "Policy"],
        );
        let tags = cx.tag_map(props);
        if !tags.is_empty() {
            input.insert("tags".into(), Value::Object(tags));
        }
        let out = cx.call("eks", "CreatePodIdentityAssociation", Value::Object(input)).await?;
        let a = &out["association"];
        let arn = text(&a["associationArn"]);
        Ok(Created::new(&arn)
            .attr("AssociationArn", arn.clone())
            .attr("AssociationId", text(&a["associationId"]))
            .attr("ExternalId", text(&a["externalId"])))
    }

    async fn update(&self, cx: &Cx<'_>, _arn: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let cluster = req(new, "ClusterName")?;
        let id = text(&attrs["AssociationId"]);
        let keys = ["RoleArn", "DisableSessionTags", "TargetRoleArn", "Policy"];
        if keys.iter().any(|k| changed(old, new, k)) {
            let mut input = Map::new();
            input.insert("clusterName".into(), json!(cluster));
            input.insert("associationId".into(), json!(id));
            put(&mut input, new, &keys);
            if old.contains_key("TargetRoleArn") && !new.contains_key("TargetRoleArn") {
                input.insert("targetRoleArn".into(), json!(""));
            }
            cx.call("eks", "UpdatePodIdentityAssociation", Value::Object(input)).await?;
        }
        retag(cx, &text(&attrs["AssociationArn"]), old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, _arn: &str, props: &Props, attrs: &Props) -> HResult<()> {
        let cluster = req(props, "ClusterName")?;
        gone_ok(
            cx.call(
                "eks",
                "DeletePodIdentityAssociation",
                json!({"clusterName": cluster, "associationId": text(&attrs["AssociationId"])}),
            )
            .await,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn camel_case_keeps_opaque_maps() {
        let v = json!({"ScalingConfig": {"MinSize": "1"}, "Labels": {"Team": "a"}});
        let mut out = camel(&v, &["Labels"]);
        coerce(&mut out, NUMS, BOOLS, STRS);
        assert_eq!(out, json!({"scalingConfig": {"minSize": 1}, "labels": {"Team": "a"}}));
    }
}

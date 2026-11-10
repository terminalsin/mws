//! ElastiCache resource types: cache clusters, replication groups and
//! serverless caches (waiting for them to become `available`), subnet and
//! parameter groups, users and user groups.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::rds::{coerce, failed, identifier, pick, retag, settle, snapshot_name, stabilize, wait_gone};
use super::{boolean, changed, gone_ok, int, list, req, s, text, Created, Cx, HResult, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::ElastiCache::CacheCluster", Arc::new(CacheCluster));
    m.insert("AWS::ElastiCache::ReplicationGroup", Arc::new(ReplicationGroup));
    m.insert("AWS::ElastiCache::SubnetGroup", Arc::new(SubnetGroup));
    m.insert("AWS::ElastiCache::ParameterGroup", Arc::new(ParameterGroup));
    m.insert("AWS::ElastiCache::ServerlessCache", Arc::new(ServerlessCache));
    m.insert("AWS::ElastiCache::User", Arc::new(User));
    m.insert("AWS::ElastiCache::UserGroup", Arc::new(UserGroup));
}

const NUMS: &[&str] = &[
    "Maximum",
    "Minimum",
    "NumCacheClusters",
    "NumCacheNodes",
    "NumNodeGroups",
    "Port",
    "ReplicaCount",
    "ReplicasPerNodeGroup",
    "SnapshotRetentionLimit",
];
const BOOLS: &[&str] = &[
    "AtRestEncryptionEnabled",
    "AutoMinorVersionUpgrade",
    "AutomaticFailoverEnabled",
    "DataTieringEnabled",
    "MultiAZEnabled",
    "TransitEncryptionEnabled",
    "NoPasswordRequired",
];
const STRS: &[&str] = &[
    "AZMode",
    "AuthToken",
    "CacheClusterId",
    "CacheNodeType",
    "CacheParameterGroupName",
    "CacheSubnetGroupName",
    "ClusterMode",
    "DailySnapshotTime",
    "Description",
    "Engine",
    "EngineVersion",
    "KmsKeyId",
    "MajorEngineVersion",
    "NodeGroupId",
    "PreferredAvailabilityZone",
    "PreferredMaintenanceWindow",
    "PrimaryAvailabilityZone",
    "PrimaryClusterId",
    "ReplicationGroupDescription",
    "ReplicationGroupId",
    "Slots",
    "SnapshotName",
    "SnapshotWindow",
    "Unit",
    "UserGroupId",
    "Value",
];

const CREATE_CACHE_CLUSTER: &[&str] = &[
    "CacheClusterId",
    "AZMode",
    "PreferredAvailabilityZone",
    "PreferredAvailabilityZones",
    "NumCacheNodes",
    "CacheNodeType",
    "Engine",
    "EngineVersion",
    "CacheParameterGroupName",
    "CacheSubnetGroupName",
    "CacheSecurityGroupNames",
    "SecurityGroupIds",
    "Tags",
    "SnapshotArns",
    "SnapshotName",
    "PreferredMaintenanceWindow",
    "Port",
    "NotificationTopicArn",
    "AutoMinorVersionUpgrade",
    "SnapshotRetentionLimit",
    "SnapshotWindow",
    "LogDeliveryConfigurations",
    "TransitEncryptionEnabled",
    "NetworkType",
    "IpDiscovery",
];
const MODIFY_CACHE_CLUSTER: &[&str] = &[
    "NumCacheNodes",
    "AZMode",
    "CacheSecurityGroupNames",
    "SecurityGroupIds",
    "PreferredMaintenanceWindow",
    "NotificationTopicArn",
    "CacheParameterGroupName",
    "EngineVersion",
    "AutoMinorVersionUpgrade",
    "SnapshotRetentionLimit",
    "SnapshotWindow",
    "CacheNodeType",
    "LogDeliveryConfigurations",
    "IpDiscovery",
];
const CREATE_REPLICATION_GROUP: &[&str] = &[
    "ReplicationGroupId",
    "ReplicationGroupDescription",
    "GlobalReplicationGroupId",
    "PrimaryClusterId",
    "AutomaticFailoverEnabled",
    "MultiAZEnabled",
    "NumCacheClusters",
    "PreferredCacheClusterAZs",
    "NumNodeGroups",
    "ReplicasPerNodeGroup",
    "NodeGroupConfiguration",
    "CacheNodeType",
    "Engine",
    "EngineVersion",
    "CacheParameterGroupName",
    "CacheSubnetGroupName",
    "CacheSecurityGroupNames",
    "SecurityGroupIds",
    "Tags",
    "SnapshotArns",
    "SnapshotName",
    "PreferredMaintenanceWindow",
    "Port",
    "NotificationTopicArn",
    "AutoMinorVersionUpgrade",
    "SnapshotRetentionLimit",
    "SnapshotWindow",
    "AuthToken",
    "TransitEncryptionEnabled",
    "AtRestEncryptionEnabled",
    "KmsKeyId",
    "UserGroupIds",
    "LogDeliveryConfigurations",
    "DataTieringEnabled",
    "NetworkType",
    "IpDiscovery",
    "TransitEncryptionMode",
    "ClusterMode",
];
const MODIFY_REPLICATION_GROUP: &[&str] = &[
    "ReplicationGroupDescription",
    "PrimaryClusterId",
    "SnapshottingClusterId",
    "AutomaticFailoverEnabled",
    "MultiAZEnabled",
    "CacheSecurityGroupNames",
    "SecurityGroupIds",
    "PreferredMaintenanceWindow",
    "NotificationTopicArn",
    "CacheParameterGroupName",
    "EngineVersion",
    "AutoMinorVersionUpgrade",
    "SnapshotRetentionLimit",
    "SnapshotWindow",
    "CacheNodeType",
    "LogDeliveryConfigurations",
    "IpDiscovery",
    "TransitEncryptionEnabled",
    "TransitEncryptionMode",
    "ClusterMode",
];
const CREATE_SERVERLESS_CACHE: &[&str] = &[
    "ServerlessCacheName",
    "Description",
    "Engine",
    "MajorEngineVersion",
    "CacheUsageLimits",
    "KmsKeyId",
    "SecurityGroupIds",
    "SnapshotArnsToRestore",
    "Tags",
    "UserGroupId",
    "SubnetIds",
    "SnapshotRetentionLimit",
    "DailySnapshotTime",
];
const MODIFY_SERVERLESS_CACHE: &[&str] = &[
    "Description",
    "CacheUsageLimits",
    "UserGroupId",
    "SecurityGroupIds",
    "SnapshotRetentionLimit",
    "DailySnapshotTime",
    "MajorEngineVersion",
];

/// The template's properties under the API's member names.
fn api_props(cx: &Cx<'_>, props: &Props) -> Map<String, Value> {
    let mut out = props.clone();
    if let Some(v) = out.remove("ClusterName") {
        out.insert("CacheClusterId".into(), v);
    }
    if let Some(v) = out.remove("VpcSecurityGroupIds") {
        out.insert("SecurityGroupIds".into(), v);
    }
    out.remove("Tags");
    let tags = cx.tags(props);
    if !tags.is_empty() {
        out.insert("Tags".into(), Value::Array(tags));
    }
    let mut v = Value::Object(out);
    coerce(&mut v, NUMS, BOOLS, STRS);
    match v {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

fn changes(old: &Map<String, Value>, new: &Map<String, Value>, members: &[&str]) -> Map<String, Value> {
    members
        .iter()
        .filter(|k| old.get(**k) != new.get(**k))
        .filter_map(|k| new.get(*k).filter(|v| !v.is_null()).map(|v| ((*k).to_string(), v.clone())))
        .collect()
}

fn unstable(status: &str) -> bool {
    matches!(status, "create-failed" | "incompatible-network" | "restore-failed" | "incompatible-parameters")
}

/// Take a snapshot and wait for it to become available.
async fn take_snapshot(cx: &Cx<'_>, source: (&str, &str)) -> HResult<()> {
    let name = snapshot_name(cx, 255);
    match cx.call("elasticache", "CreateSnapshot", json!({source.0: source.1, "SnapshotName": name})).await {
        Err(e) if e.not_found => return Ok(()),
        r => r?,
    };
    let name = &name;
    stabilize(&format!("snapshot {name} to become available"), || async move {
        let out = cx.call("elasticache", "DescribeSnapshots", json!({"SnapshotName": name})).await?;
        let status = text(&out["Snapshots"][0]["SnapshotStatus"]);
        if status == "failed" {
            return Err(failed(&format!("Snapshot {name}"), &status));
        }
        Ok(status == "available")
    })
    .await
}

// ---------------------------------------------------------------------
// Cache clusters.

async fn describe_cluster(cx: &Cx<'_>, id: &str) -> HResult<Value> {
    let out = cx
        .call("elasticache", "DescribeCacheClusters", json!({"CacheClusterId": id, "ShowCacheNodeInfo": true}))
        .await?;
    Ok(out["CacheClusters"][0].clone())
}

async fn wait_cluster(cx: &Cx<'_>, id: &str) -> HResult<Value> {
    settle(&format!("cache cluster {id} to become available"), || async move {
        let c = describe_cluster(cx, id).await?;
        let status = text(&c["CacheClusterStatus"]);
        if unstable(&status) {
            return Err(failed(&format!("Cache cluster {id}"), &status));
        }
        Ok((status == "available").then_some(c))
    })
    .await
}

fn cluster_attributes(c: &Value) -> Props {
    let mut a = Props::new();
    let conf = &c["ConfigurationEndpoint"];
    if conf.is_object() {
        a.insert("ConfigurationEndpoint.Address".into(), json!(text(&conf["Address"])));
        a.insert("ConfigurationEndpoint.Port".into(), json!(text(&conf["Port"])));
    }
    let node = &c["CacheNodes"][0]["Endpoint"];
    if text(&c["Engine"]) != "memcached" && node.is_object() {
        a.insert("RedisEndpoint.Address".into(), json!(text(&node["Address"])));
        a.insert("RedisEndpoint.Port".into(), json!(text(&node["Port"])));
    }
    a
}

struct CacheCluster;

#[async_trait::async_trait]
impl Provider for CacheCluster {
    fn create_only(&self) -> &'static [&'static str] {
        &[
            "ClusterName",
            "Engine",
            "CacheSubnetGroupName",
            "NetworkType",
            "Port",
            "PreferredAvailabilityZone",
            "SnapshotArns",
            "SnapshotName",
            "TransitEncryptionEnabled",
        ]
    }
    fn required(&self) -> &'static [&'static str] {
        &["CacheNodeType", "Engine", "NumCacheNodes"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["ConfigurationEndpoint.Address", "ConfigurationEndpoint.Port", "RedisEndpoint.Address", "RedisEndpoint.Port"]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("ClusterName")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut p = api_props(cx, props);
        let id = s(props, "ClusterName").unwrap_or_else(|| identifier(cx, 40));
        p.insert("CacheClusterId".into(), json!(id));
        let out = cx.call("elasticache", "CreateCacheCluster", Value::Object(pick(&p, CREATE_CACHE_CLUSTER))).await?;
        let id = text(&out["CacheCluster"]["CacheClusterId"]);
        let c = wait_cluster(cx, &id).await.map_err(|e| e.created(&id))?;
        Ok(Created { physical_id: id, attributes: cluster_attributes(&c) })
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, _attrs: &Props) -> HResult<Props> {
        let (o, n) = (api_props(cx, old), api_props(cx, new));
        let mut m = changes(&o, &n, MODIFY_CACHE_CLUSTER);
        if changed(old, new, "PreferredAvailabilityZones") {
            let have = list(old, "PreferredAvailabilityZones").len();
            let zones: Vec<String> = list(new, "PreferredAvailabilityZones").into_iter().skip(have).collect();
            if !zones.is_empty() {
                m.insert("NewAvailabilityZones".into(), json!(zones));
            }
        }
        if !m.is_empty() {
            m.insert("CacheClusterId".into(), json!(id));
            m.insert("ApplyImmediately".into(), json!(true));
            cx.call("elasticache", "ModifyCacheCluster", Value::Object(m)).await?;
        }
        let c = wait_cluster(cx, id).await?;
        retag(cx, "elasticache", &text(&c["ARN"]), old, new).await?;
        Ok(cluster_attributes(&c))
    }

    async fn snapshot(&self, cx: &Cx<'_>, id: &str, props: &Props, _attrs: &Props) -> Option<HResult<()>> {
        // Memcached keeps no data to snapshot.
        if s(props, "Engine").as_deref() == Some("memcached") {
            return None;
        }
        Some(take_snapshot(cx, ("CacheClusterId", id)).await)
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        match cx.call("elasticache", "DeleteCacheCluster", json!({"CacheClusterId": id})).await {
            Err(e) if e.not_found => return Ok(()),
            r => {
                r?;
            }
        }
        wait_gone(&format!("cache cluster {id} to be deleted"), || describe_cluster(cx, id)).await
    }
}

// ---------------------------------------------------------------------
// Replication groups.

async fn describe_group(cx: &Cx<'_>, id: &str) -> HResult<Value> {
    let out = cx.call("elasticache", "DescribeReplicationGroups", json!({"ReplicationGroupId": id})).await?;
    Ok(out["ReplicationGroups"][0].clone())
}

async fn wait_group(cx: &Cx<'_>, id: &str) -> HResult<Value> {
    settle(&format!("replication group {id} to become available"), || async move {
        let g = describe_group(cx, id).await?;
        let status = text(&g["Status"]);
        if unstable(&status) {
            return Err(failed(&format!("Replication group {id}"), &status));
        }
        Ok((status == "available").then_some(g))
    })
    .await
}

fn group_attributes(g: &Value) -> Props {
    let mut a = Props::new();
    let conf = &g["ConfigurationEndpoint"];
    if conf.is_object() {
        a.insert("ConfigurationEndPoint.Address".into(), json!(text(&conf["Address"])));
        a.insert("ConfigurationEndPoint.Port".into(), json!(text(&conf["Port"])));
    }
    let ng = &g["NodeGroups"][0];
    for (attr, member) in [("PrimaryEndPoint", "PrimaryEndpoint"), ("ReaderEndPoint", "ReaderEndpoint")] {
        let e = &ng[member];
        if e.is_object() {
            a.insert(format!("{attr}.Address"), json!(text(&e["Address"])));
            a.insert(format!("{attr}.Port"), json!(text(&e["Port"])));
        }
    }
    let reads: Vec<(String, String)> = ng["NodeGroupMembers"]
        .as_array()
        .map(|m| {
            m.iter()
                .filter(|x| x["ReadEndpoint"].is_object())
                .map(|x| (text(&x["ReadEndpoint"]["Address"]), text(&x["ReadEndpoint"]["Port"])))
                .collect()
        })
        .unwrap_or_default();
    if !reads.is_empty() {
        let addrs: Vec<String> = reads.iter().map(|r| r.0.clone()).collect();
        let ports: Vec<String> = reads.iter().map(|r| r.1.clone()).collect();
        a.insert("ReadEndPoint.Addresses".into(), json!(addrs.join(",")));
        a.insert("ReadEndPoint.Ports".into(), json!(ports.join(",")));
        a.insert("ReadEndPoint.Addresses.List".into(), json!(addrs));
        a.insert("ReadEndPoint.Ports.List".into(), json!(ports));
    }
    a
}

struct ReplicationGroup;

#[async_trait::async_trait]
impl Provider for ReplicationGroup {
    fn create_only(&self) -> &'static [&'static str] {
        &[
            "ReplicationGroupId",
            "AtRestEncryptionEnabled",
            "CacheSubnetGroupName",
            "DataTieringEnabled",
            "Engine",
            "GlobalReplicationGroupId",
            "KmsKeyId",
            "NetworkType",
            "NodeGroupConfiguration",
            "Port",
            "PreferredCacheClusterAZs",
            "SnapshotArns",
            "SnapshotName",
        ]
    }
    fn required(&self) -> &'static [&'static str] {
        &["ReplicationGroupDescription"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &[
            "ConfigurationEndPoint.Address",
            "ConfigurationEndPoint.Port",
            "PrimaryEndPoint.Address",
            "PrimaryEndPoint.Port",
            "ReaderEndPoint.Address",
            "ReaderEndPoint.Port",
            "ReadEndPoint.Addresses",
            "ReadEndPoint.Ports",
            "ReadEndPoint.Addresses.List",
            "ReadEndPoint.Ports.List",
        ]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("ReplicationGroupId")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut p = api_props(cx, props);
        let id = s(props, "ReplicationGroupId").unwrap_or_else(|| identifier(cx, 40));
        p.insert("ReplicationGroupId".into(), json!(id));
        let out =
            cx.call("elasticache", "CreateReplicationGroup", Value::Object(pick(&p, CREATE_REPLICATION_GROUP))).await?;
        let id = text(&out["ReplicationGroup"]["ReplicationGroupId"]);
        let g = async {
            wait_group(cx, &id).await?;
            // The snapshotting cluster can only be named once the group's
            // clusters exist.
            if let Some(c) = s(props, "SnapshottingClusterId") {
                cx.call(
                    "elasticache",
                    "ModifyReplicationGroup",
                    json!({"ReplicationGroupId": id, "SnapshottingClusterId": c, "ApplyImmediately": true}),
                )
                .await?;
            }
            wait_group(cx, &id).await
        }
        .await
        .map_err(|e| e.created(&id))?;
        Ok(Created { physical_id: id, attributes: group_attributes(&g) })
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, _attrs: &Props) -> HResult<Props> {
        let (o, n) = (api_props(cx, old), api_props(cx, new));
        let mut m = changes(&o, &n, MODIFY_REPLICATION_GROUP);
        if changed(old, new, "UserGroupIds") {
            let (ou, nu) = (list(old, "UserGroupIds"), list(new, "UserGroupIds"));
            let add: Vec<&String> = nu.iter().filter(|u| !ou.contains(u)).collect();
            let remove: Vec<&String> = ou.iter().filter(|u| !nu.contains(u)).collect();
            if !add.is_empty() {
                m.insert("UserGroupIdsToAdd".into(), json!(add));
            }
            if !remove.is_empty() {
                m.insert("UserGroupIdsToRemove".into(), json!(remove));
            }
        }
        if changed(old, new, "AuthToken") {
            if let Some(t) = s(new, "AuthToken") {
                m.insert("AuthToken".into(), json!(t));
                m.insert("AuthTokenUpdateStrategy".into(), json!("ROTATE"));
            }
        }
        if !m.is_empty() {
            m.insert("ReplicationGroupId".into(), json!(id));
            m.insert("ApplyImmediately".into(), json!(true));
            cx.call("elasticache", "ModifyReplicationGroup", Value::Object(m)).await?;
            wait_group(cx, id).await?;
        }
        // Replica counts.
        let replicas = |p: &Props| int(p, "NumCacheClusters").map(|n| n - 1).or_else(|| int(p, "ReplicasPerNodeGroup"));
        if let (Some(was), Some(now)) = (replicas(old), replicas(new)) {
            if was != now {
                let op = if now > was { "IncreaseReplicaCount" } else { "DecreaseReplicaCount" };
                cx.call(
                    "elasticache",
                    op,
                    json!({"ReplicationGroupId": id, "NewReplicaCount": now, "ApplyImmediately": true}),
                )
                .await?;
                wait_group(cx, id).await?;
            }
        }
        // Shard count.
        if let (Some(was), Some(now)) = (int(old, "NumNodeGroups"), int(new, "NumNodeGroups")) {
            if was != now {
                let mut input = json!({"ReplicationGroupId": id, "NodeGroupCount": now, "ApplyImmediately": true});
                if now < was {
                    let g = describe_group(cx, id).await?;
                    let keep: Vec<String> = g["NodeGroups"]
                        .as_array()
                        .map(|a| a.iter().map(|n| text(&n["NodeGroupId"])).take(now as usize).collect())
                        .unwrap_or_default();
                    input["NodeGroupsToRetain"] = json!(keep);
                }
                cx.call("elasticache", "ModifyReplicationGroupShardConfiguration", input).await?;
                wait_group(cx, id).await?;
            }
        }
        let g = wait_group(cx, id).await?;
        retag(cx, "elasticache", &text(&g["ARN"]), old, new).await?;
        Ok(group_attributes(&g))
    }

    async fn snapshot(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> Option<HResult<()>> {
        Some(take_snapshot(cx, ("ReplicationGroupId", id)).await)
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        match cx
            .call(
                "elasticache",
                "DeleteReplicationGroup",
                json!({"ReplicationGroupId": id, "RetainPrimaryCluster": false}),
            )
            .await
        {
            Err(e) if e.not_found => return Ok(()),
            r => {
                r?;
            }
        }
        wait_gone(&format!("replication group {id} to be deleted"), || describe_group(cx, id)).await
    }
}

// ---------------------------------------------------------------------
// Subnet groups.

struct SubnetGroup;

#[async_trait::async_trait]
impl Provider for SubnetGroup {
    fn create_only(&self) -> &'static [&'static str] {
        &["CacheSubnetGroupName"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["Description", "SubnetIds"]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("CacheSubnetGroupName")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "CacheSubnetGroupName").unwrap_or_else(|| identifier(cx, 255));
        let mut input = json!({
            "CacheSubnetGroupName": name,
            "CacheSubnetGroupDescription": req(props, "Description")?,
            "SubnetIds": list(props, "SubnetIds"),
        });
        let tags = cx.tags(props);
        if !tags.is_empty() {
            input["Tags"] = json!(tags);
        }
        let out = cx.call("elasticache", "CreateCacheSubnetGroup", input).await?;
        Ok(Created::new(text(&out["CacheSubnetGroup"]["CacheSubnetGroupName"])))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "Description") || changed(old, new, "SubnetIds") {
            cx.call(
                "elasticache",
                "ModifyCacheSubnetGroup",
                json!({
                    "CacheSubnetGroupName": name,
                    "CacheSubnetGroupDescription": req(new, "Description")?,
                    "SubnetIds": list(new, "SubnetIds"),
                }),
            )
            .await?;
        }
        retag(cx, "elasticache", &cx.arn("elasticache", &format!("subnetgroup:{name}")), old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("elasticache", "DeleteCacheSubnetGroup", json!({"CacheSubnetGroupName": name})).await)
    }
}

// ---------------------------------------------------------------------
// Parameter groups.

fn properties(props: &Props) -> BTreeMap<String, String> {
    match props.get("Properties") {
        Some(Value::Object(m)) => m.iter().map(|(k, v)| (k.clone(), text(v))).collect(),
        _ => BTreeMap::new(),
    }
}

async fn set_parameters(cx: &Cx<'_>, name: &str, values: &BTreeMap<String, String>) -> HResult<()> {
    let all: Vec<Value> = values.iter().map(|(k, v)| json!({"ParameterName": k, "ParameterValue": v})).collect();
    for chunk in all.chunks(20) {
        cx.call(
            "elasticache",
            "ModifyCacheParameterGroup",
            json!({"CacheParameterGroupName": name, "ParameterNameValues": chunk}),
        )
        .await?;
    }
    Ok(())
}

struct ParameterGroup;

#[async_trait::async_trait]
impl Provider for ParameterGroup {
    fn create_only(&self) -> &'static [&'static str] {
        &["CacheParameterGroupFamily", "Description"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["CacheParameterGroupFamily", "Description"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = identifier(cx, 255);
        let mut input = json!({
            "CacheParameterGroupName": name,
            "CacheParameterGroupFamily": req(props, "CacheParameterGroupFamily")?,
            "Description": req(props, "Description")?,
        });
        let tags = cx.tags(props);
        if !tags.is_empty() {
            input["Tags"] = json!(tags);
        }
        let out = cx.call("elasticache", "CreateCacheParameterGroup", input).await?;
        let name = text(&out["CacheParameterGroup"]["CacheParameterGroupName"]);
        if let Err(e) = set_parameters(cx, &name, &properties(props)).await {
            let _ = cx.call("elasticache", "DeleteCacheParameterGroup", json!({"CacheParameterGroupName": name})).await;
            return Err(e);
        }
        Ok(Created::new(name))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "Properties") {
            let (o, n) = (properties(old), properties(new));
            let removed: Vec<Value> =
                o.keys().filter(|k| !n.contains_key(*k)).map(|k| json!({"ParameterName": k})).collect();
            if !removed.is_empty() {
                cx.call(
                    "elasticache",
                    "ResetCacheParameterGroup",
                    json!({"CacheParameterGroupName": name, "ParameterNameValues": removed}),
                )
                .await?;
            }
            let set: BTreeMap<String, String> = n.into_iter().filter(|(k, v)| o.get(k) != Some(v)).collect();
            set_parameters(cx, name, &set).await?;
        }
        retag(cx, "elasticache", &cx.arn("elasticache", &format!("parametergroup:{name}")), old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("elasticache", "DeleteCacheParameterGroup", json!({"CacheParameterGroupName": name})).await)
    }
}

// ---------------------------------------------------------------------
// Serverless caches.

async fn describe_serverless(cx: &Cx<'_>, name: &str) -> HResult<Value> {
    let out = cx.call("elasticache", "DescribeServerlessCaches", json!({"ServerlessCacheName": name})).await?;
    Ok(out["ServerlessCaches"][0].clone())
}

async fn wait_serverless(cx: &Cx<'_>, name: &str) -> HResult<Value> {
    settle(&format!("serverless cache {name} to become available"), || async move {
        let c = describe_serverless(cx, name).await?;
        let status = text(&c["Status"]);
        if status == "create-failed" {
            return Err(failed(&format!("Serverless cache {name}"), &status));
        }
        Ok((status == "available").then_some(c))
    })
    .await
}

fn serverless_attributes(c: &Value) -> Props {
    let mut a = Props::new();
    a.insert("ARN".into(), json!(text(&c["ARN"])));
    a.insert("CreateTime".into(), json!(text(&c["CreateTime"])));
    a.insert("Status".into(), json!(text(&c["Status"])));
    a.insert("FullEngineVersion".into(), json!(text(&c["FullEngineVersion"])));
    for k in ["Endpoint", "ReaderEndpoint"] {
        a.insert(format!("{k}.Address"), json!(text(&c[k]["Address"])));
        a.insert(format!("{k}.Port"), json!(text(&c[k]["Port"])));
    }
    a
}

struct ServerlessCache;

#[async_trait::async_trait]
impl Provider for ServerlessCache {
    fn create_only(&self) -> &'static [&'static str] {
        &["ServerlessCacheName", "Engine", "KmsKeyId", "SnapshotArnsToRestore", "SubnetIds"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["ServerlessCacheName", "Engine"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &[
            "ARN",
            "CreateTime",
            "Status",
            "FullEngineVersion",
            "Endpoint.Address",
            "Endpoint.Port",
            "ReaderEndpoint.Address",
            "ReaderEndpoint.Port",
        ]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("ServerlessCacheName")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let p = api_props(cx, props);
        let out =
            cx.call("elasticache", "CreateServerlessCache", Value::Object(pick(&p, CREATE_SERVERLESS_CACHE))).await?;
        let name = text(&out["ServerlessCache"]["ServerlessCacheName"]);
        let c = wait_serverless(cx, &name).await.map_err(|e| e.created(&name))?;
        Ok(Created { physical_id: name, attributes: serverless_attributes(&c) })
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, _attrs: &Props) -> HResult<Props> {
        let (o, n) = (api_props(cx, old), api_props(cx, new));
        let mut m = changes(&o, &n, MODIFY_SERVERLESS_CACHE);
        if o.contains_key("UserGroupId") && !n.contains_key("UserGroupId") {
            m.insert("RemoveUserGroup".into(), json!(true));
        }
        if m.contains_key("MajorEngineVersion") {
            if let Some(e) = n.get("Engine") {
                m.insert("Engine".into(), e.clone());
            }
        }
        if !m.is_empty() {
            m.insert("ServerlessCacheName".into(), json!(name));
            cx.call("elasticache", "ModifyServerlessCache", Value::Object(m)).await?;
        }
        let c = wait_serverless(cx, name).await?;
        retag(cx, "elasticache", &text(&c["ARN"]), old, new).await?;
        Ok(serverless_attributes(&c))
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let mut input = json!({"ServerlessCacheName": name});
        if let Some(f) = s(props, "FinalSnapshotName") {
            input["FinalSnapshotName"] = json!(f);
        }
        match cx.call("elasticache", "DeleteServerlessCache", input).await {
            Err(e) if e.not_found => return Ok(()),
            r => {
                r?;
            }
        }
        wait_gone(&format!("serverless cache {name} to be deleted"), || describe_serverless(cx, name)).await
    }
}

// ---------------------------------------------------------------------
// Users and user groups.

async fn describe_user(cx: &Cx<'_>, id: &str) -> HResult<Value> {
    let out = cx.call("elasticache", "DescribeUsers", json!({"UserId": id})).await?;
    Ok(out["Users"][0].clone())
}

async fn wait_user(cx: &Cx<'_>, id: &str) -> HResult<Value> {
    settle(&format!("user {id} to become active"), || async move {
        let u = describe_user(cx, id).await?;
        Ok((text(&u["Status"]) == "active").then_some(u))
    })
    .await
}

fn user_input(props: &Props) -> Map<String, Value> {
    let mut m = Map::new();
    if let Some(a) = s(props, "AccessString") {
        m.insert("AccessString".into(), json!(a));
    }
    let passwords = list(props, "Passwords");
    if !passwords.is_empty() {
        m.insert("Passwords".into(), json!(passwords));
    }
    if let Some(b) = boolean(props, "NoPasswordRequired") {
        m.insert("NoPasswordRequired".into(), json!(b));
    }
    if let Some(a) = props.get("AuthenticationMode").filter(|v| v.is_object()) {
        m.insert("AuthenticationMode".into(), a.clone());
    }
    m
}

struct User;

#[async_trait::async_trait]
impl Provider for User {
    fn create_only(&self) -> &'static [&'static str] {
        &["UserId", "UserName", "Engine"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["UserId", "UserName", "Engine"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn", "Status"]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("UserId")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = user_input(props);
        input.insert("UserId".into(), json!(req(props, "UserId")?));
        input.insert("UserName".into(), json!(req(props, "UserName")?));
        input.insert("Engine".into(), json!(req(props, "Engine")?));
        input.entry("AccessString").or_insert(json!(""));
        let tags = cx.tags(props);
        if !tags.is_empty() {
            input.insert("Tags".into(), json!(tags));
        }
        let out = cx.call("elasticache", "CreateUser", Value::Object(input)).await?;
        let id = text(&out["UserId"]);
        let u = wait_user(cx, &id).await.map_err(|e| e.created(&id))?;
        Ok(Created::new(&id).attr("Arn", text(&u["ARN"])).attr("Status", text(&u["Status"])))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, _attrs: &Props) -> HResult<Props> {
        let (o, n) = (user_input(old), user_input(new));
        let m: Map<String, Value> = n.into_iter().filter(|(k, v)| o.get(k) != Some(v)).collect();
        if !m.is_empty() {
            let mut m = m;
            m.insert("UserId".into(), json!(id));
            cx.call("elasticache", "ModifyUser", Value::Object(m)).await?;
        }
        let u = wait_user(cx, id).await?;
        retag(cx, "elasticache", &text(&u["ARN"]), old, new).await?;
        let mut a = Props::new();
        a.insert("Arn".into(), json!(text(&u["ARN"])));
        a.insert("Status".into(), json!(text(&u["Status"])));
        Ok(a)
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        match cx.call("elasticache", "DeleteUser", json!({"UserId": id})).await {
            Err(e) if e.not_found => return Ok(()),
            r => {
                r?;
            }
        }
        wait_gone(&format!("user {id} to be deleted"), || describe_user(cx, id)).await
    }
}

async fn describe_user_group(cx: &Cx<'_>, id: &str) -> HResult<Value> {
    let out = cx.call("elasticache", "DescribeUserGroups", json!({"UserGroupId": id})).await?;
    Ok(out["UserGroups"][0].clone())
}

async fn wait_user_group(cx: &Cx<'_>, id: &str) -> HResult<Value> {
    settle(&format!("user group {id} to become active"), || async move {
        let g = describe_user_group(cx, id).await?;
        Ok((text(&g["Status"]) == "active").then_some(g))
    })
    .await
}

struct UserGroup;

#[async_trait::async_trait]
impl Provider for UserGroup {
    fn create_only(&self) -> &'static [&'static str] {
        &["UserGroupId"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["UserGroupId", "Engine"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn", "Status"]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("UserGroupId")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = json!({
            "UserGroupId": req(props, "UserGroupId")?,
            "Engine": req(props, "Engine")?,
            "UserIds": list(props, "UserIds"),
        });
        let tags = cx.tags(props);
        if !tags.is_empty() {
            input["Tags"] = json!(tags);
        }
        let out = cx.call("elasticache", "CreateUserGroup", input).await?;
        let id = text(&out["UserGroupId"]);
        let g = wait_user_group(cx, &id).await.map_err(|e| e.created(&id))?;
        Ok(Created::new(&id).attr("Arn", text(&g["ARN"])).attr("Status", text(&g["Status"])))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, _attrs: &Props) -> HResult<Props> {
        if changed(old, new, "UserIds") || changed(old, new, "Engine") {
            let o: BTreeSet<String> = list(old, "UserIds").into_iter().collect();
            let n: BTreeSet<String> = list(new, "UserIds").into_iter().collect();
            let mut input = json!({"UserGroupId": id});
            let add: Vec<&String> = n.difference(&o).collect();
            let remove: Vec<&String> = o.difference(&n).collect();
            if !add.is_empty() {
                input["UserIdsToAdd"] = json!(add);
            }
            if !remove.is_empty() {
                input["UserIdsToRemove"] = json!(remove);
            }
            if changed(old, new, "Engine") {
                input["Engine"] = json!(req(new, "Engine")?);
            }
            cx.call("elasticache", "ModifyUserGroup", input).await?;
        }
        let g = wait_user_group(cx, id).await?;
        retag(cx, "elasticache", &text(&g["ARN"]), old, new).await?;
        let mut a = Props::new();
        a.insert("Arn".into(), json!(text(&g["ARN"])));
        a.insert("Status".into(), json!(text(&g["Status"])));
        Ok(a)
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        match cx.call("elasticache", "DeleteUserGroup", json!({"UserGroupId": id})).await {
            Err(e) if e.not_found => return Ok(()),
            r => {
                r?;
            }
        }
        wait_gone(&format!("user group {id} to be deleted"), || describe_user_group(cx, id)).await
    }
}

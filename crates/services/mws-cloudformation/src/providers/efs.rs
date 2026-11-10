//! Amazon EFS resource types.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::ecs::{coerce, is_gone, stabilize, tag_changes, tags_at};
use super::{boolean, changed, copy, document, gone_ok, list, req, s, text, Created, Cx, HResult, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::EFS::FileSystem", Arc::new(FileSystem));
    m.insert("AWS::EFS::MountTarget", Arc::new(MountTarget));
    m.insert("AWS::EFS::AccessPoint", Arc::new(AccessPoint));
}

const SVC: &str = "elasticfilesystem";

async fn retag(cx: &Cx<'_>, id: &str, old: &Props, new: &Props, key: &str) -> HResult<()> {
    if let Some((set, removed)) = tag_changes(cx, old, new, key) {
        if !removed.is_empty() {
            cx.call(SVC, "UntagResource", json!({"ResourceId": id, "TagKeys": removed})).await?;
        }
        if !set.is_empty() {
            cx.call(SVC, "TagResource", json!({"ResourceId": id, "Tags": set})).await?;
        }
    }
    Ok(())
}

// ---- FileSystem --------------------------------------------------------

struct FileSystem;

async fn describe_fs(cx: &Cx<'_>, id: &str) -> HResult<Value> {
    let out = cx.call(SVC, "DescribeFileSystems", json!({"FileSystemId": id})).await?;
    Ok(out["FileSystems"][0].clone())
}

async fn put_lifecycle(cx: &Cx<'_>, id: &str, props: &Props) -> HResult<()> {
    let policies = props.get("LifecyclePolicies").cloned().unwrap_or(json!([]));
    cx.call(SVC, "PutLifecycleConfiguration", json!({"FileSystemId": id, "LifecyclePolicies": policies})).await?;
    Ok(())
}

async fn put_backup(cx: &Cx<'_>, id: &str, props: &Props) -> HResult<()> {
    let status = props.get("BackupPolicy").and_then(|b| b.get("Status")).map(text).unwrap_or_else(|| "DISABLED".into());
    cx.call(SVC, "PutBackupPolicy", json!({"FileSystemId": id, "BackupPolicy": {"Status": status}})).await?;
    Ok(())
}

async fn put_policy(cx: &Cx<'_>, id: &str, props: &Props, removing: bool) -> HResult<()> {
    match document(props, "FileSystemPolicy") {
        Some(p) => {
            let mut input = json!({"FileSystemId": id, "Policy": p});
            if let Some(b) = boolean(props, "BypassPolicyLockoutSafetyCheck") {
                input["BypassPolicyLockoutSafetyCheck"] = json!(b);
            }
            cx.call(SVC, "PutFileSystemPolicy", input).await?;
        }
        None if removing => {
            gone_ok(cx.call(SVC, "DeleteFileSystemPolicy", json!({"FileSystemId": id})).await)?;
        }
        None => {}
    }
    Ok(())
}

async fn put_protection(cx: &Cx<'_>, id: &str, props: &Props) -> HResult<()> {
    let v = props
        .get("FileSystemProtection")
        .and_then(|p| p.get("ReplicationOverwriteProtection"))
        .map(text)
        .unwrap_or_else(|| "ENABLED".into());
    cx.call(SVC, "UpdateFileSystemProtection", json!({"FileSystemId": id, "ReplicationOverwriteProtection": v}))
        .await?;
    Ok(())
}

async fn create_replication(cx: &Cx<'_>, id: &str, props: &Props) -> HResult<()> {
    let Some(dests) =
        props.get("ReplicationConfiguration").and_then(|r| r.get("Destinations")).and_then(Value::as_array)
    else {
        return Ok(());
    };
    let dests: Vec<Value> = dests
        .iter()
        .map(|d| {
            let mut out = Map::new();
            if let Value::Object(m) = d {
                copy(m, &mut out, &["Region", "AvailabilityZoneName", "KmsKeyId", "FileSystemId", "RoleArn"]);
            }
            Value::Object(out)
        })
        .collect();
    cx.call(SVC, "CreateReplicationConfiguration", json!({"SourceFileSystemId": id, "Destinations": dests})).await?;
    Ok(())
}

#[async_trait::async_trait]
impl Provider for FileSystem {
    fn create_only(&self) -> &'static [&'static str] {
        &["AvailabilityZoneName", "Encrypted", "KmsKeyId", "PerformanceMode"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn", "FileSystemId"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = Map::new();
        input.insert("CreationToken".into(), json!(cx.physical_name(64)));
        copy(
            props,
            &mut input,
            &[
                "PerformanceMode",
                "Encrypted",
                "KmsKeyId",
                "ThroughputMode",
                "ProvisionedThroughputInMibps",
                "AvailabilityZoneName",
            ],
        );
        let mut v = Value::Object(input);
        coerce(&mut v, &["ProvisionedThroughputInMibps"], &["Encrypted"], &[]);
        let tags = tags_at(cx, props, "FileSystemTags");
        if !tags.is_empty() {
            v["Tags"] = Value::Array(tags);
        }
        let out = cx.call(SVC, "CreateFileSystem", v).await?;
        let id = text(&out["FileSystemId"]);
        let arn = text(&out["FileSystemArn"]);
        stabilize(&format!("File system {id}"), || async {
            let fs = describe_fs(cx, &id).await?;
            Ok((fs["LifeCycleState"] == "available").then_some(fs))
        })
        .await?;
        if props.contains_key("LifecyclePolicies") {
            put_lifecycle(cx, &id, props).await?;
        }
        if props.contains_key("BackupPolicy") {
            put_backup(cx, &id, props).await?;
        }
        put_policy(cx, &id, props, false).await?;
        if props.contains_key("FileSystemProtection") {
            put_protection(cx, &id, props).await?;
        }
        create_replication(cx, &id, props).await?;
        Ok(Created::new(&id).attr("Arn", arn).attr("FileSystemId", id.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "ThroughputMode") || changed(old, new, "ProvisionedThroughputInMibps") {
            let mut input = Map::new();
            input.insert("FileSystemId".into(), json!(id));
            input.insert("ThroughputMode".into(), json!(s(new, "ThroughputMode").unwrap_or_else(|| "bursting".into())));
            copy(new, &mut input, &["ProvisionedThroughputInMibps"]);
            let mut v = Value::Object(input);
            coerce(&mut v, &["ProvisionedThroughputInMibps"], &[], &[]);
            cx.call(SVC, "UpdateFileSystem", v).await?;
        }
        if changed(old, new, "LifecyclePolicies") {
            put_lifecycle(cx, id, new).await?;
        }
        if changed(old, new, "BackupPolicy") {
            put_backup(cx, id, new).await?;
        }
        if changed(old, new, "FileSystemPolicy") || changed(old, new, "BypassPolicyLockoutSafetyCheck") {
            put_policy(cx, id, new, true).await?;
        }
        if changed(old, new, "FileSystemProtection") {
            put_protection(cx, id, new).await?;
        }
        if changed(old, new, "ReplicationConfiguration") {
            if old.contains_key("ReplicationConfiguration") {
                gone_ok(cx.call(SVC, "DeleteReplicationConfiguration", json!({"SourceFileSystemId": id})).await)?;
            }
            create_replication(cx, id, new).await?;
        }
        retag(cx, id, old, new, "FileSystemTags").await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        if props.contains_key("ReplicationConfiguration") {
            gone_ok(cx.call(SVC, "DeleteReplicationConfiguration", json!({"SourceFileSystemId": id})).await)?;
        }
        if let Err(e) = cx.call(SVC, "DeleteFileSystem", json!({"FileSystemId": id})).await {
            return if e.not_found { Ok(()) } else { Err(e) };
        }
        stabilize(&format!("File system {id}"), || async {
            match describe_fs(cx, id).await {
                Err(e) if is_gone(&e, &[]) => Ok(Some(Value::Null)),
                Err(e) => Err(e),
                Ok(fs) => Ok((fs.is_null() || fs["LifeCycleState"] == "deleted").then_some(Value::Null)),
            }
        })
        .await
        .map(|_| ())
    }

    async fn read(&self, cx: &Cx<'_>, id: &str, props: &Props) -> Option<HResult<Props>> {
        Some(
            async {
                let fs = describe_fs(cx, id).await?;
                let mut p = Props::new();
                for k in ["PerformanceMode", "Encrypted", "ThroughputMode", "KmsKeyId"] {
                    if props.contains_key(k) {
                        p.insert(k.into(), fs[k].clone());
                    }
                }
                Ok(p)
            }
            .await,
        )
    }
}

// ---- MountTarget -------------------------------------------------------

struct MountTarget;

async fn describe_mt(cx: &Cx<'_>, id: &str) -> HResult<Value> {
    let out = cx.call(SVC, "DescribeMountTargets", json!({"MountTargetId": id})).await?;
    Ok(out["MountTargets"][0].clone())
}

#[async_trait::async_trait]
impl Provider for MountTarget {
    fn create_only(&self) -> &'static [&'static str] {
        &["FileSystemId", "SubnetId", "IpAddress", "Ipv6Address", "IpAddressType"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["FileSystemId", "SubnetId", "SecurityGroups"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Id", "IpAddress"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = Map::new();
        copy(props, &mut input, &["FileSystemId", "SubnetId", "IpAddress", "Ipv6Address", "IpAddressType"]);
        input.insert("SecurityGroups".into(), json!(list(props, "SecurityGroups")));
        let out = cx.call(SVC, "CreateMountTarget", Value::Object(input)).await?;
        let id = text(&out["MountTargetId"]);
        let mt = stabilize(&format!("Mount target {id}"), || async {
            let mt = describe_mt(cx, &id).await?;
            Ok((mt["LifeCycleState"] == "available").then_some(mt))
        })
        .await?;
        Ok(Created::new(&id).attr("Id", id.clone()).attr("IpAddress", text(&mt["IpAddress"])))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "SecurityGroups") {
            cx.call(
                SVC,
                "ModifyMountTargetSecurityGroups",
                json!({"MountTargetId": id, "SecurityGroups": list(new, "SecurityGroups")}),
            )
            .await?;
        }
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        if let Err(e) = cx.call(SVC, "DeleteMountTarget", json!({"MountTargetId": id})).await {
            return if e.not_found { Ok(()) } else { Err(e) };
        }
        stabilize(&format!("Mount target {id}"), || async {
            match describe_mt(cx, id).await {
                Err(e) if e.not_found => Ok(Some(Value::Null)),
                Err(e) => Err(e),
                Ok(mt) => Ok((mt.is_null() || mt["LifeCycleState"] == "deleted").then_some(Value::Null)),
            }
        })
        .await
        .map(|_| ())
    }
}

// ---- AccessPoint -------------------------------------------------------

struct AccessPoint;

#[async_trait::async_trait]
impl Provider for AccessPoint {
    fn create_only(&self) -> &'static [&'static str] {
        &["FileSystemId", "PosixUser", "RootDirectory", "ClientToken"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["FileSystemId"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["AccessPointId", "Arn"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let fs = req(props, "FileSystemId")?;
        let mut input = Map::new();
        input.insert("FileSystemId".into(), json!(fs));
        input.insert("ClientToken".into(), json!(s(props, "ClientToken").unwrap_or_else(|| cx.physical_name(64))));
        copy(props, &mut input, &["PosixUser", "RootDirectory"]);
        let mut v = Value::Object(input);
        // CloudFormation takes the IDs as strings; the API as numbers.
        coerce(&mut v, &["Uid", "Gid", "SecondaryGids", "OwnerUid", "OwnerGid"], &[], &["Permissions"]);
        let tags = tags_at(cx, props, "AccessPointTags");
        if !tags.is_empty() {
            v["Tags"] = Value::Array(tags);
        }
        let out = cx.call(SVC, "CreateAccessPoint", v).await?;
        let id = text(&out["AccessPointId"]);
        let arn = text(&out["AccessPointArn"]);
        stabilize(&format!("Access point {id}"), || async {
            let out = cx.call(SVC, "DescribeAccessPoints", json!({"AccessPointId": id})).await?;
            let ap = out["AccessPoints"][0].clone();
            Ok((ap["LifeCycleState"] == "available").then_some(ap))
        })
        .await?;
        Ok(Created::new(&id).attr("AccessPointId", id.clone()).attr("Arn", arn))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        retag(cx, id, old, new, "AccessPointTags").await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call(SVC, "DeleteAccessPoint", json!({"AccessPointId": id})).await)
    }
}

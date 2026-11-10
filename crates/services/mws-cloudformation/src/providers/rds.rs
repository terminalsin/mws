//! RDS resource types: DB instances and clusters (waiting for them to
//! become `available`, as CloudFormation's handlers do), subnet, parameter
//! and option groups, and event subscriptions.
//!
//! Also the small helpers the other database and compute providers share:
//! type coercion of CloudFormation's scalars, stabilization polling,
//! tag diffs and generated snapshot names.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Map, Value};

use super::{boolean, changed, gone_ok, list, req, s, text, Created, Cx, HResult, HandlerError, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::RDS::DBInstance", Arc::new(DbInstance));
    m.insert("AWS::RDS::DBCluster", Arc::new(DbCluster));
    m.insert("AWS::RDS::DBSubnetGroup", Arc::new(DbSubnetGroup));
    m.insert("AWS::RDS::DBParameterGroup", Arc::new(ParameterGroup(&INSTANCE_PARAMS)));
    m.insert("AWS::RDS::DBClusterParameterGroup", Arc::new(ParameterGroup(&CLUSTER_PARAMS)));
    m.insert("AWS::RDS::OptionGroup", Arc::new(OptionGroup));
    m.insert("AWS::RDS::EventSubscription", Arc::new(EventSubscription));
}

// ---------------------------------------------------------------------
// Shared helpers.

/// How long a handler waits for a resource to stabilize before it reports
/// `NotStabilized`.
const STABILIZE: Duration = Duration::from_secs(30 * 60);

/// Convert CloudFormation's scalars to the types the API members take:
/// strings to numbers for `nums`, to booleans for `bools`, and numbers or
/// booleans to strings for `strs`, at any depth.
pub(super) fn coerce(v: &mut Value, nums: &[&str], bools: &[&str], strs: &[&str]) {
    match v {
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                let k = k.as_str();
                match x {
                    Value::String(s) if nums.contains(&k) => {
                        if let Ok(n) = s.trim().parse::<i64>() {
                            *x = Value::from(n);
                        } else if let Ok(f) = s.trim().parse::<f64>() {
                            *x = json!(f);
                        }
                    }
                    Value::String(s) if bools.contains(&k) => {
                        if s.eq_ignore_ascii_case("true") || s.eq_ignore_ascii_case("false") {
                            *x = Value::Bool(s.eq_ignore_ascii_case("true"));
                        }
                    }
                    Value::Number(_) | Value::Bool(_) if strs.contains(&k) => *x = Value::String(text(x)),
                    Value::Array(a) if strs.contains(&k) => {
                        for e in a.iter_mut() {
                            if matches!(e, Value::Number(_) | Value::Bool(_)) {
                                *e = Value::String(text(e));
                            } else {
                                coerce(e, nums, bools, strs);
                            }
                        }
                    }
                    _ => coerce(x, nums, bools, strs),
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|e| coerce(e, nums, bools, strs)),
        _ => {}
    }
}

/// Poll until `poll` says the resource is stable (`Ok(Some(_))`); an
/// error ends the wait.
pub(super) async fn settle<T, F, Fut>(what: &str, mut poll: F) -> HResult<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = HResult<Option<T>>>,
{
    let start = tokio::time::Instant::now();
    loop {
        if let Some(v) = poll().await? {
            return Ok(v);
        }
        if start.elapsed() > STABILIZE {
            return Err(HandlerError::handler("NotStabilized", format!("Exceeded attempts to wait for {what}")));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// [`settle`] for a poll that only says whether the resource is stable.
pub(super) async fn stabilize<F, Fut>(what: &str, mut poll: F) -> HResult<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = HResult<bool>>,
{
    settle(what, || {
        let f = poll();
        async move { Ok(f.await?.then_some(())) }
    })
    .await
}

/// Poll a describe call until it answers NotFound.
pub(super) async fn wait_gone<F, Fut>(what: &str, mut describe: F) -> HResult<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = HResult<Value>>,
{
    stabilize(what, || {
        let f = describe();
        async move {
            match f.await {
                Ok(_) => Ok(false),
                Err(e) if e.not_found => Ok(true),
                Err(e) => Err(e),
            }
        }
    })
    .await
}

/// A failed resource state, worded as the handlers report it.
pub(super) fn failed(what: &str, status: &str) -> HandlerError {
    HandlerError::handler("NotStabilized", format!("{what} is in state {status}, which is not a stable state"))
}

/// A name for a snapshot CloudFormation takes on deletion:
/// `<stack>-<logical id>-<random>`, lower case, with only letters, digits
/// and single hyphens, starting with a letter.
pub(super) fn snapshot_name(cx: &Cx<'_>, max: usize) -> String {
    let raw = cx.physical_name(max).to_lowercase();
    let mut out = String::new();
    for c in raw.chars() {
        let c = if c.is_ascii_alphanumeric() { c } else { '-' };
        if c == '-' && (out.is_empty() || out.ends_with('-')) {
            continue;
        }
        out.push(c);
    }
    while out.ends_with('-') {
        out.pop();
    }
    if !out.starts_with(|c: char| c.is_ascii_alphabetic()) {
        out.insert_str(0, "s-");
    }
    out.chars().take(max).collect::<String>().trim_end_matches('-').to_string()
}

/// A generated lower-case identifier (`<stack>-<logical id>-<random>`)
/// that RDS and ElastiCache accept.
pub(super) fn identifier(cx: &Cx<'_>, max: usize) -> String {
    snapshot_name(cx, max)
}

/// The tags to set and the keys to remove when `old` becomes `new` (both
/// `[{Key, Value}]` lists).
pub(super) fn tag_diff(old: &[Value], new: &[Value]) -> (Vec<Value>, Vec<String>) {
    let key = |t: &Value| t.get("Key").map(text).unwrap_or_default();
    let new_keys: BTreeSet<String> = new.iter().map(key).collect();
    let removed = old.iter().map(key).filter(|k| !new_keys.contains(k)).collect();
    let set = new.iter().filter(|t| !old.contains(t)).cloned().collect();
    (set, removed)
}

/// Members of `props` (already renamed to API names) that `members`
/// lists.
pub(super) fn pick(props: &Map<String, Value>, members: &[&str]) -> Map<String, Value> {
    props
        .iter()
        .filter(|(k, v)| members.contains(&k.as_str()) && !v.is_null())
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Tags on an RDS (or ElastiCache) resource: add the new, remove the
/// dropped.
pub(super) async fn retag(cx: &Cx<'_>, service: &str, arn: &str, old: &Props, new: &Props) -> HResult<()> {
    if !changed(old, new, "Tags") {
        return Ok(());
    }
    let (set, removed) = tag_diff(&cx.tags(old), &cx.tags(new));
    if !removed.is_empty() {
        cx.call(service, "RemoveTagsFromResource", json!({"ResourceName": arn, "TagKeys": removed})).await?;
    }
    if !set.is_empty() {
        cx.call(service, "AddTagsToResource", json!({"ResourceName": arn, "Tags": set})).await?;
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Member types, from the RDS model.

const NUMS: &[&str] = &[
    "AllocatedStorage",
    "BacktrackWindow",
    "BackupRetentionPeriod",
    "DBPortNumber",
    "IOPS",
    "Iops",
    "MaxAllocatedStorage",
    "MonitoringInterval",
    "PerformanceInsightsRetentionPeriod",
    "Port",
    "PromotionTier",
    "ResumeFullAutomationModeMinutes",
    "SecondsBeforeTimeout",
    "SecondsUntilAutoPause",
    "StorageThroughput",
    "MaxCapacity",
    "MinCapacity",
];
const BOOLS: &[&str] = &[
    "AllowEngineModeChange",
    "AllowMajorVersionUpgrade",
    "ApplyImmediately",
    "AutoMinorVersionUpgrade",
    "AutoPause",
    "CertificateRotationRestart",
    "CopyTagsToSnapshot",
    "DedicatedLogVolume",
    "DeletionProtection",
    "DisableDomain",
    "EnableCustomerOwnedIp",
    "EnableGlobalWriteForwarding",
    "EnableHttpEndpoint",
    "EnableIAMDatabaseAuthentication",
    "EnableLimitlessDatabase",
    "EnableLocalWriteForwarding",
    "EnablePerformanceInsights",
    "Enabled",
    "ManageMasterUserPassword",
    "MultiAZ",
    "MultiTenant",
    "PubliclyAccessible",
    "RotateMasterUserPassword",
    "StorageEncrypted",
    "UseDefaultProcessorFeatures",
    "UseLatestRestorableTime",
];
const STRS: &[&str] = &[
    "AvailabilityZone",
    "AvailabilityZones",
    "CACertificateIdentifier",
    "CharacterSetName",
    "DBClusterIdentifier",
    "DBClusterInstanceClass",
    "DBClusterParameterGroupName",
    "DBInstanceClass",
    "DBInstanceIdentifier",
    "DBName",
    "DBParameterGroupFamily",
    "DBParameterGroupName",
    "DBSubnetGroupName",
    "DatabaseName",
    "Description",
    "Engine",
    "EngineVersion",
    "KmsKeyId",
    "MajorEngineVersion",
    "MasterUserPassword",
    "MasterUsername",
    "OptionGroupName",
    "OptionVersion",
    "ParameterValue",
    "PreferredBackupWindow",
    "PreferredMaintenanceWindow",
    "StorageType",
    "SubnetIds",
    "Value",
    "VpcSecurityGroupIds",
];

const CREATE_DB_INSTANCE: &[&str] = &[
    "DBName",
    "DBInstanceIdentifier",
    "AllocatedStorage",
    "DBInstanceClass",
    "Engine",
    "MasterUsername",
    "MasterUserPassword",
    "DBSecurityGroups",
    "VpcSecurityGroupIds",
    "AvailabilityZone",
    "DBSubnetGroupName",
    "PreferredMaintenanceWindow",
    "DBParameterGroupName",
    "BackupRetentionPeriod",
    "PreferredBackupWindow",
    "Port",
    "MultiAZ",
    "EngineVersion",
    "AutoMinorVersionUpgrade",
    "LicenseModel",
    "Iops",
    "StorageThroughput",
    "OptionGroupName",
    "CharacterSetName",
    "NcharCharacterSetName",
    "PubliclyAccessible",
    "Tags",
    "DBClusterIdentifier",
    "StorageType",
    "TdeCredentialArn",
    "TdeCredentialPassword",
    "StorageEncrypted",
    "KmsKeyId",
    "Domain",
    "DomainFqdn",
    "DomainOu",
    "DomainAuthSecretArn",
    "DomainDnsIps",
    "CopyTagsToSnapshot",
    "MonitoringInterval",
    "MonitoringRoleArn",
    "DomainIAMRoleName",
    "PromotionTier",
    "Timezone",
    "EnableIAMDatabaseAuthentication",
    "DatabaseInsightsMode",
    "EnablePerformanceInsights",
    "PerformanceInsightsKMSKeyId",
    "PerformanceInsightsRetentionPeriod",
    "EnableCloudwatchLogsExports",
    "ProcessorFeatures",
    "DeletionProtection",
    "MaxAllocatedStorage",
    "NetworkType",
    "CustomIamInstanceProfile",
    "DBSystemId",
    "CACertificateIdentifier",
    "ManageMasterUserPassword",
    "MasterUserSecretKmsKeyId",
    "DedicatedLogVolume",
    "EngineLifecycleSupport",
];
const MODIFY_DB_INSTANCE: &[&str] = &[
    "AllocatedStorage",
    "DBInstanceClass",
    "DBSubnetGroupName",
    "DBSecurityGroups",
    "VpcSecurityGroupIds",
    "MasterUserPassword",
    "DBParameterGroupName",
    "BackupRetentionPeriod",
    "PreferredBackupWindow",
    "PreferredMaintenanceWindow",
    "MultiAZ",
    "EngineVersion",
    "AllowMajorVersionUpgrade",
    "AutoMinorVersionUpgrade",
    "LicenseModel",
    "Iops",
    "StorageThroughput",
    "OptionGroupName",
    "StorageType",
    "TdeCredentialArn",
    "TdeCredentialPassword",
    "CACertificateIdentifier",
    "Domain",
    "DomainFqdn",
    "DomainOu",
    "DomainAuthSecretArn",
    "DomainDnsIps",
    "CopyTagsToSnapshot",
    "MonitoringInterval",
    "PubliclyAccessible",
    "MonitoringRoleArn",
    "DomainIAMRoleName",
    "PromotionTier",
    "EnableIAMDatabaseAuthentication",
    "DatabaseInsightsMode",
    "EnablePerformanceInsights",
    "PerformanceInsightsKMSKeyId",
    "PerformanceInsightsRetentionPeriod",
    "ProcessorFeatures",
    "UseDefaultProcessorFeatures",
    "DeletionProtection",
    "MaxAllocatedStorage",
    "CertificateRotationRestart",
    "ReplicaMode",
    "NetworkType",
    "ManageMasterUserPassword",
    "MasterUserSecretKmsKeyId",
    "DedicatedLogVolume",
    "EngineLifecycleSupport",
];
const RESTORE_DB_INSTANCE_FROM_SNAPSHOT: &[&str] = &[
    "DBInstanceIdentifier",
    "DBSnapshotIdentifier",
    "DBInstanceClass",
    "Port",
    "AvailabilityZone",
    "DBSubnetGroupName",
    "MultiAZ",
    "PubliclyAccessible",
    "AutoMinorVersionUpgrade",
    "LicenseModel",
    "DBName",
    "Engine",
    "Iops",
    "StorageThroughput",
    "OptionGroupName",
    "Tags",
    "StorageType",
    "TdeCredentialArn",
    "TdeCredentialPassword",
    "VpcSecurityGroupIds",
    "Domain",
    "DomainFqdn",
    "DomainOu",
    "DomainAuthSecretArn",
    "DomainDnsIps",
    "CopyTagsToSnapshot",
    "DomainIAMRoleName",
    "EnableIAMDatabaseAuthentication",
    "EnableCloudwatchLogsExports",
    "ProcessorFeatures",
    "UseDefaultProcessorFeatures",
    "DBParameterGroupName",
    "DeletionProtection",
    "NetworkType",
    "CustomIamInstanceProfile",
    "AllocatedStorage",
    "DBClusterSnapshotIdentifier",
    "BackupRetentionPeriod",
    "PreferredBackupWindow",
    "DedicatedLogVolume",
    "CACertificateIdentifier",
    "EngineLifecycleSupport",
    "ManageMasterUserPassword",
    "MasterUserSecretKmsKeyId",
];
const CREATE_READ_REPLICA: &[&str] = &[
    "DBInstanceIdentifier",
    "SourceDBInstanceIdentifier",
    "DBInstanceClass",
    "AvailabilityZone",
    "Port",
    "MultiAZ",
    "AutoMinorVersionUpgrade",
    "Iops",
    "StorageThroughput",
    "OptionGroupName",
    "DBParameterGroupName",
    "PubliclyAccessible",
    "Tags",
    "DBSubnetGroupName",
    "VpcSecurityGroupIds",
    "StorageType",
    "CopyTagsToSnapshot",
    "MonitoringInterval",
    "MonitoringRoleArn",
    "KmsKeyId",
    "EnableIAMDatabaseAuthentication",
    "DatabaseInsightsMode",
    "EnablePerformanceInsights",
    "PerformanceInsightsKMSKeyId",
    "PerformanceInsightsRetentionPeriod",
    "EnableCloudwatchLogsExports",
    "ProcessorFeatures",
    "UseDefaultProcessorFeatures",
    "DeletionProtection",
    "Domain",
    "DomainIAMRoleName",
    "DomainFqdn",
    "DomainOu",
    "DomainAuthSecretArn",
    "DomainDnsIps",
    "ReplicaMode",
    "NetworkType",
    "MaxAllocatedStorage",
    "CustomIamInstanceProfile",
    "AllocatedStorage",
    "SourceDBClusterIdentifier",
    "DedicatedLogVolume",
    "CACertificateIdentifier",
];
const CREATE_DB_CLUSTER: &[&str] = &[
    "AvailabilityZones",
    "BackupRetentionPeriod",
    "CharacterSetName",
    "DatabaseName",
    "DBClusterIdentifier",
    "DBClusterParameterGroupName",
    "VpcSecurityGroupIds",
    "DBSubnetGroupName",
    "Engine",
    "EngineVersion",
    "Port",
    "MasterUsername",
    "MasterUserPassword",
    "OptionGroupName",
    "PreferredBackupWindow",
    "PreferredMaintenanceWindow",
    "ReplicationSourceIdentifier",
    "Tags",
    "StorageEncrypted",
    "KmsKeyId",
    "EnableIAMDatabaseAuthentication",
    "BacktrackWindow",
    "EnableCloudwatchLogsExports",
    "EngineMode",
    "ScalingConfiguration",
    "DBClusterInstanceClass",
    "AllocatedStorage",
    "StorageType",
    "Iops",
    "PubliclyAccessible",
    "AutoMinorVersionUpgrade",
    "DeletionProtection",
    "GlobalClusterIdentifier",
    "EnableHttpEndpoint",
    "CopyTagsToSnapshot",
    "Domain",
    "DomainIAMRoleName",
    "EnableGlobalWriteForwarding",
    "NetworkType",
    "ServerlessV2ScalingConfiguration",
    "MonitoringInterval",
    "MonitoringRoleArn",
    "DatabaseInsightsMode",
    "EnablePerformanceInsights",
    "PerformanceInsightsKMSKeyId",
    "PerformanceInsightsRetentionPeriod",
    "EnableLimitlessDatabase",
    "ClusterScalabilityType",
    "DBSystemId",
    "ManageMasterUserPassword",
    "EnableLocalWriteForwarding",
    "MasterUserSecretKmsKeyId",
    "CACertificateIdentifier",
    "EngineLifecycleSupport",
];
const MODIFY_DB_CLUSTER: &[&str] = &[
    "BackupRetentionPeriod",
    "DBClusterParameterGroupName",
    "VpcSecurityGroupIds",
    "Port",
    "MasterUserPassword",
    "OptionGroupName",
    "PreferredBackupWindow",
    "PreferredMaintenanceWindow",
    "EnableIAMDatabaseAuthentication",
    "BacktrackWindow",
    "EngineVersion",
    "AllowMajorVersionUpgrade",
    "DBInstanceParameterGroupName",
    "Domain",
    "DomainIAMRoleName",
    "ScalingConfiguration",
    "DeletionProtection",
    "EnableHttpEndpoint",
    "CopyTagsToSnapshot",
    "EnableGlobalWriteForwarding",
    "DBClusterInstanceClass",
    "AllocatedStorage",
    "StorageType",
    "Iops",
    "AutoMinorVersionUpgrade",
    "NetworkType",
    "ServerlessV2ScalingConfiguration",
    "MonitoringInterval",
    "MonitoringRoleArn",
    "DatabaseInsightsMode",
    "EnablePerformanceInsights",
    "PerformanceInsightsKMSKeyId",
    "PerformanceInsightsRetentionPeriod",
    "ManageMasterUserPassword",
    "EnableLocalWriteForwarding",
    "MasterUserSecretKmsKeyId",
    "EngineMode",
    "EnableLimitlessDatabase",
    "CACertificateIdentifier",
    "EngineLifecycleSupport",
];
const RESTORE_DB_CLUSTER_FROM_SNAPSHOT: &[&str] = &[
    "AvailabilityZones",
    "DBClusterIdentifier",
    "SnapshotIdentifier",
    "Engine",
    "EngineVersion",
    "Port",
    "DBSubnetGroupName",
    "DatabaseName",
    "OptionGroupName",
    "VpcSecurityGroupIds",
    "Tags",
    "KmsKeyId",
    "EnableIAMDatabaseAuthentication",
    "BacktrackWindow",
    "EnableCloudwatchLogsExports",
    "EngineMode",
    "ScalingConfiguration",
    "DBClusterParameterGroupName",
    "DeletionProtection",
    "CopyTagsToSnapshot",
    "Domain",
    "DomainIAMRoleName",
    "DBClusterInstanceClass",
    "StorageType",
    "Iops",
    "PubliclyAccessible",
    "NetworkType",
    "ServerlessV2ScalingConfiguration",
    "MonitoringInterval",
    "MonitoringRoleArn",
    "EnablePerformanceInsights",
    "PerformanceInsightsKMSKeyId",
    "PerformanceInsightsRetentionPeriod",
    "BackupRetentionPeriod",
    "PreferredBackupWindow",
    "EngineLifecycleSupport",
];
const RESTORE_DB_CLUSTER_TO_POINT_IN_TIME: &[&str] = &[
    "DBClusterIdentifier",
    "RestoreType",
    "SourceDBClusterIdentifier",
    "RestoreToTime",
    "UseLatestRestorableTime",
    "Port",
    "DBSubnetGroupName",
    "OptionGroupName",
    "VpcSecurityGroupIds",
    "Tags",
    "KmsKeyId",
    "EnableIAMDatabaseAuthentication",
    "BacktrackWindow",
    "EnableCloudwatchLogsExports",
    "DBClusterParameterGroupName",
    "DeletionProtection",
    "CopyTagsToSnapshot",
    "Domain",
    "DomainIAMRoleName",
    "DBClusterInstanceClass",
    "StorageType",
    "PubliclyAccessible",
    "Iops",
    "NetworkType",
    "ServerlessV2ScalingConfiguration",
    "ScalingConfiguration",
    "EngineMode",
    "MonitoringInterval",
    "MonitoringRoleArn",
    "EnablePerformanceInsights",
    "PerformanceInsightsKMSKeyId",
    "PerformanceInsightsRetentionPeriod",
    "BackupRetentionPeriod",
    "PreferredBackupWindow",
    "EngineLifecycleSupport",
];

/// The template's properties under the API's member names.
fn api_props(cx: &Cx<'_>, props: &Props) -> Map<String, Value> {
    let mut out = props.clone();
    if let Some(v) = out.remove("VPCSecurityGroups") {
        out.insert("VpcSecurityGroupIds".into(), v);
    }
    if let Some(v) = out.remove("CustomIAMInstanceProfile") {
        out.insert("CustomIamInstanceProfile".into(), v);
    }
    if let Some(k) = props.get("MasterUserSecret").and_then(|m| m.get("KmsKeyId")).filter(|v| !v.is_null()) {
        out.insert("MasterUserSecretKmsKeyId".into(), k.clone());
    }
    out.remove("MasterUserSecret");
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

/// `CloudwatchLogsExportConfiguration` for a change of
/// `EnableCloudwatchLogsExports`.
fn log_exports(old: &Props, new: &Props) -> Value {
    let o: BTreeSet<String> = list(old, "EnableCloudwatchLogsExports").into_iter().collect();
    let n: BTreeSet<String> = list(new, "EnableCloudwatchLogsExports").into_iter().collect();
    json!({
        "EnableLogTypes": n.difference(&o).collect::<Vec<_>>(),
        "DisableLogTypes": o.difference(&n).collect::<Vec<_>>(),
    })
}

/// The members of `members` whose value changed between `old` and `new`
/// (both under API names), with their new values.
fn changes(old: &Map<String, Value>, new: &Map<String, Value>, members: &[&str]) -> Map<String, Value> {
    members
        .iter()
        .filter(|k| old.get(**k) != new.get(**k))
        .filter_map(|k| new.get(*k).filter(|v| !v.is_null()).map(|v| ((*k).to_string(), v.clone())))
        .collect()
}

/// Associated IAM roles (`[{RoleArn, FeatureName}]`) to add and remove.
fn role_diff(old: &Props, new: &Props) -> (Vec<Value>, Vec<Value>) {
    let roles = |p: &Props| p.get("AssociatedRoles").and_then(Value::as_array).cloned().unwrap_or_default();
    let (o, n) = (roles(old), roles(new));
    (n.iter().filter(|r| !o.contains(r)).cloned().collect(), o.iter().filter(|r| !n.contains(r)).cloned().collect())
}

// ---------------------------------------------------------------------
// DB instances.

async fn describe_instance(cx: &Cx<'_>, id: &str) -> HResult<Value> {
    let out = cx.call("rds", "DescribeDBInstances", json!({"DBInstanceIdentifier": id})).await?;
    Ok(out["DBInstances"][0].clone())
}

async fn wait_instance(cx: &Cx<'_>, id: &str) -> HResult<Value> {
    settle(&format!("DB instance {id} to become available"), || async move {
        let db = describe_instance(cx, id).await?;
        let status = text(&db["DBInstanceStatus"]);
        let done = match status.as_str() {
            "available" | "storage-optimization" => db["PendingModifiedValues"]
                .as_object()
                .is_none_or(|p| p.iter().all(|(k, v)| v.is_null() || k == "PendingCloudwatchLogsExports")),
            "failed" | "incompatible-parameters" | "incompatible-restore" | "incompatible-network" | "storage-full" => {
                return Err(failed(&format!("DB instance {id}"), &status))
            }
            _ => false,
        };
        Ok(done.then_some(db))
    })
    .await
}

fn instance_attributes(db: &Value) -> Props {
    let mut a = Props::new();
    let ep = &db["Endpoint"];
    a.insert("Endpoint.Address".into(), json!(text(&ep["Address"])));
    a.insert("Endpoint.Port".into(), json!(text(&ep["Port"])));
    a.insert("Endpoint.HostedZoneId".into(), json!(text(&ep["HostedZoneId"])));
    a.insert("DBInstanceArn".into(), json!(text(&db["DBInstanceArn"])));
    a.insert("DbiResourceId".into(), json!(text(&db["DbiResourceId"])));
    a.insert("DBSystemId".into(), json!(text(&db["DBSystemId"])));
    a.insert("MasterUserSecret.SecretArn".into(), json!(text(&db["MasterUserSecret"]["SecretArn"])));
    a.insert("CertificateDetails.CAIdentifier".into(), json!(text(&db["CertificateDetails"]["CAIdentifier"])));
    a.insert("CertificateDetails.ValidTill".into(), json!(text(&db["CertificateDetails"]["ValidTill"])));
    a
}

struct DbInstance;

#[async_trait::async_trait]
impl Provider for DbInstance {
    fn create_only(&self) -> &'static [&'static str] {
        &[
            "DBInstanceIdentifier",
            "AvailabilityZone",
            "CharacterSetName",
            "DBClusterIdentifier",
            "DBName",
            "Engine",
            "KmsKeyId",
            "MasterUsername",
            "NcharCharacterSetName",
            "SourceDBInstanceIdentifier",
            "SourceRegion",
            "StorageEncrypted",
            "Timezone",
            "DBSnapshotIdentifier",
            "DBClusterSnapshotIdentifier",
        ]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &[
            "Endpoint.Address",
            "Endpoint.Port",
            "Endpoint.HostedZoneId",
            "DBInstanceArn",
            "DbiResourceId",
            "DBSystemId",
            "MasterUserSecret.SecretArn",
            "CertificateDetails.CAIdentifier",
            "CertificateDetails.ValidTill",
        ]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("DBInstanceIdentifier")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut p = api_props(cx, props);
        let id = s(props, "DBInstanceIdentifier").unwrap_or_else(|| identifier(cx, 63));
        p.insert("DBInstanceIdentifier".into(), json!(id));
        let (op, members) = if props.contains_key("DBSnapshotIdentifier")
            || props.contains_key("DBClusterSnapshotIdentifier") && !props.contains_key("DBClusterIdentifier")
        {
            ("RestoreDBInstanceFromDBSnapshot", RESTORE_DB_INSTANCE_FROM_SNAPSHOT)
        } else if props.contains_key("SourceDBInstanceIdentifier") {
            ("CreateDBInstanceReadReplica", CREATE_READ_REPLICA)
        } else {
            ("CreateDBInstance", CREATE_DB_INSTANCE)
        };
        let out = cx.call("rds", op, Value::Object(pick(&p, members))).await?;
        let id = text(&out["DBInstance"]["DBInstanceIdentifier"]);
        let attributes = async {
            wait_instance(cx, &id).await?;
            // What a restore or replica could not set is applied afterwards,
            // as CloudFormation does.
            if op != "CreateDBInstance" {
                let mut rest: Map<String, Value> =
                    pick(&p, MODIFY_DB_INSTANCE).into_iter().filter(|(k, _)| !members.contains(&k.as_str())).collect();
                if !rest.is_empty() {
                    rest.insert("DBInstanceIdentifier".into(), json!(id));
                    rest.insert("ApplyImmediately".into(), json!(true));
                    cx.call("rds", "ModifyDBInstance", Value::Object(rest)).await?;
                    wait_instance(cx, &id).await?;
                }
            }
            for r in role_diff(&Props::new(), props).0 {
                cx.call(
                    "rds",
                    "AddRoleToDBInstance",
                    json!({"DBInstanceIdentifier": id, "RoleArn": text(&r["RoleArn"]), "FeatureName": text(&r["FeatureName"])}),
                )
                .await?;
            }
            Ok::<_, HandlerError>(instance_attributes(&wait_instance(cx, &id).await?))
        }
        .await
        .map_err(|e| e.created(&id))?;
        Ok(Created { physical_id: id, attributes })
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, _attrs: &Props) -> HResult<Props> {
        let (o, n) = (api_props(cx, old), api_props(cx, new));
        let mut m = changes(&o, &n, MODIFY_DB_INSTANCE);
        if o.get("Port") != n.get("Port") {
            if let Some(port) = n.get("Port") {
                m.insert("DBPortNumber".into(), port.clone());
            }
        }
        if changed(old, new, "EnableCloudwatchLogsExports") {
            m.insert("CloudwatchLogsExportConfiguration".into(), log_exports(old, new));
        }
        if m.contains_key("EngineVersion") {
            if let Some(v) = n.get("AllowMajorVersionUpgrade") {
                m.insert("AllowMajorVersionUpgrade".into(), v.clone());
            }
        }
        if !m.is_empty() {
            m.insert("DBInstanceIdentifier".into(), json!(id));
            m.insert("ApplyImmediately".into(), json!(boolean(new, "ApplyImmediately").unwrap_or(true)));
            cx.call("rds", "ModifyDBInstance", Value::Object(m)).await?;
            wait_instance(cx, id).await?;
        }
        let (add, remove) = role_diff(old, new);
        for r in remove {
            gone_ok(
                cx.call(
                    "rds",
                    "RemoveRoleFromDBInstance",
                    json!({"DBInstanceIdentifier": id, "RoleArn": text(&r["RoleArn"]), "FeatureName": text(&r["FeatureName"])}),
                )
                .await,
            )?;
        }
        for r in add {
            cx.call(
                "rds",
                "AddRoleToDBInstance",
                json!({"DBInstanceIdentifier": id, "RoleArn": text(&r["RoleArn"]), "FeatureName": text(&r["FeatureName"])}),
            )
            .await?;
        }
        let db = wait_instance(cx, id).await?;
        retag(cx, "rds", &text(&db["DBInstanceArn"]), old, new).await?;
        Ok(instance_attributes(&db))
    }

    async fn snapshot(&self, cx: &Cx<'_>, id: &str, props: &Props, _attrs: &Props) -> Option<HResult<()>> {
        // Instances of a cluster have no snapshots of their own: the
        // cluster's snapshot covers them.
        if props.contains_key("DBClusterIdentifier") {
            return Some(Ok(()));
        }
        Some(
            async {
                let name = snapshot_name(cx, 255);
                match cx
                    .call("rds", "CreateDBSnapshot", json!({"DBSnapshotIdentifier": name, "DBInstanceIdentifier": id}))
                    .await
                {
                    Err(e) if e.not_found => return Ok(()),
                    r => r?,
                };
                let name = &name;
                stabilize(&format!("DB snapshot {name} to become available"), || async move {
                    let out = cx.call("rds", "DescribeDBSnapshots", json!({"DBSnapshotIdentifier": name})).await?;
                    let status = text(&out["DBSnapshots"][0]["Status"]);
                    if status == "failed" {
                        return Err(failed(&format!("DB snapshot {name}"), &status));
                    }
                    Ok(status == "available")
                })
                .await
            }
            .await,
        )
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let mut input = json!({"DBInstanceIdentifier": id, "SkipFinalSnapshot": true});
        if let Some(b) = boolean(props, "DeleteAutomatedBackups") {
            input["DeleteAutomatedBackups"] = json!(b);
        }
        match cx.call("rds", "DeleteDBInstance", input).await {
            Err(e) if e.not_found => return Ok(()),
            // Already being deleted.
            Err(e) if e.code == "InvalidDBInstanceState" && e.message.contains("already being deleted") => {}
            r => {
                r?;
            }
        }
        wait_gone(&format!("DB instance {id} to be deleted"), || describe_instance(cx, id)).await
    }
}

// ---------------------------------------------------------------------
// DB clusters.

async fn describe_cluster(cx: &Cx<'_>, id: &str) -> HResult<Value> {
    let out = cx.call("rds", "DescribeDBClusters", json!({"DBClusterIdentifier": id})).await?;
    Ok(out["DBClusters"][0].clone())
}

async fn wait_cluster(cx: &Cx<'_>, id: &str) -> HResult<Value> {
    settle(&format!("DB cluster {id} to become available"), || async move {
        let c = describe_cluster(cx, id).await?;
        let status = text(&c["Status"]);
        let done = match status.as_str() {
            "available" => true,
            "failed" | "inaccessible-encryption-credentials" | "incompatible-parameters" | "incompatible-restore" => {
                return Err(failed(&format!("DB cluster {id}"), &status))
            }
            _ => false,
        };
        Ok(done.then_some(c))
    })
    .await
}

fn cluster_attributes(c: &Value) -> Props {
    let mut a = Props::new();
    a.insert("DBClusterArn".into(), json!(text(&c["DBClusterArn"])));
    a.insert("DBClusterResourceId".into(), json!(text(&c["DbClusterResourceId"])));
    a.insert("Endpoint.Address".into(), json!(text(&c["Endpoint"])));
    a.insert("Endpoint.Port".into(), json!(text(&c["Port"])));
    a.insert("ReadEndpoint.Address".into(), json!(text(&c["ReaderEndpoint"])));
    a.insert("MasterUserSecret.SecretArn".into(), json!(text(&c["MasterUserSecret"]["SecretArn"])));
    a.insert("StorageThroughput".into(), json!(text(&c["StorageThroughput"])));
    a
}

struct DbCluster;

#[async_trait::async_trait]
impl Provider for DbCluster {
    fn create_only(&self) -> &'static [&'static str] {
        &[
            "DBClusterIdentifier",
            "AvailabilityZones",
            "DatabaseName",
            "DBSubnetGroupName",
            "DBSystemId",
            "Engine",
            "KmsKeyId",
            "MasterUsername",
            "RestoreToTime",
            "RestoreType",
            "SnapshotIdentifier",
            "SourceDBClusterIdentifier",
            "SourceRegion",
            "StorageEncrypted",
            "UseLatestRestorableTime",
            "ClusterScalabilityType",
        ]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &[
            "DBClusterArn",
            "DBClusterResourceId",
            "Endpoint.Address",
            "Endpoint.Port",
            "ReadEndpoint.Address",
            "MasterUserSecret.SecretArn",
            "StorageThroughput",
        ]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("DBClusterIdentifier")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut p = api_props(cx, props);
        let id = s(props, "DBClusterIdentifier").unwrap_or_else(|| identifier(cx, 63));
        p.insert("DBClusterIdentifier".into(), json!(id));
        let (op, members) = if props.contains_key("SnapshotIdentifier") {
            ("RestoreDBClusterFromSnapshot", RESTORE_DB_CLUSTER_FROM_SNAPSHOT)
        } else if props.contains_key("SourceDBClusterIdentifier") {
            ("RestoreDBClusterToPointInTime", RESTORE_DB_CLUSTER_TO_POINT_IN_TIME)
        } else {
            ("CreateDBCluster", CREATE_DB_CLUSTER)
        };
        let out = cx.call("rds", op, Value::Object(pick(&p, members))).await?;
        let id = text(&out["DBCluster"]["DBClusterIdentifier"]);
        let attributes = async {
            wait_cluster(cx, &id).await?;
            if op != "CreateDBCluster" {
                let mut rest: Map<String, Value> =
                    pick(&p, MODIFY_DB_CLUSTER).into_iter().filter(|(k, _)| !members.contains(&k.as_str())).collect();
                if !rest.is_empty() {
                    rest.insert("DBClusterIdentifier".into(), json!(id));
                    rest.insert("ApplyImmediately".into(), json!(true));
                    cx.call("rds", "ModifyDBCluster", Value::Object(rest)).await?;
                    wait_cluster(cx, &id).await?;
                }
            }
            for r in role_diff(&Props::new(), props).0 {
                let mut input = json!({"DBClusterIdentifier": id, "RoleArn": text(&r["RoleArn"])});
                if let Some(f) = r.get("FeatureName") {
                    input["FeatureName"] = json!(text(f));
                }
                cx.call("rds", "AddRoleToDBCluster", input).await?;
            }
            Ok::<_, HandlerError>(cluster_attributes(&wait_cluster(cx, &id).await?))
        }
        .await
        .map_err(|e| e.created(&id))?;
        Ok(Created { physical_id: id, attributes })
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, _attrs: &Props) -> HResult<Props> {
        let (o, n) = (api_props(cx, old), api_props(cx, new));
        let mut m = changes(&o, &n, MODIFY_DB_CLUSTER);
        if changed(old, new, "EnableCloudwatchLogsExports") {
            m.insert("CloudwatchLogsExportConfiguration".into(), log_exports(old, new));
        }
        if m.contains_key("EngineVersion") {
            if let Some(v) = n.get("AllowMajorVersionUpgrade") {
                m.insert("AllowMajorVersionUpgrade".into(), v.clone());
            }
            if let Some(v) = n.get("DBInstanceParameterGroupName") {
                m.insert("DBInstanceParameterGroupName".into(), v.clone());
            }
        }
        if !m.is_empty() {
            m.insert("DBClusterIdentifier".into(), json!(id));
            m.insert("ApplyImmediately".into(), json!(true));
            cx.call("rds", "ModifyDBCluster", Value::Object(m)).await?;
            wait_cluster(cx, id).await?;
        }
        let (add, remove) = role_diff(old, new);
        for r in remove {
            let mut input = json!({"DBClusterIdentifier": id, "RoleArn": text(&r["RoleArn"])});
            if let Some(f) = r.get("FeatureName") {
                input["FeatureName"] = json!(text(f));
            }
            gone_ok(cx.call("rds", "RemoveRoleFromDBCluster", input).await)?;
        }
        for r in add {
            let mut input = json!({"DBClusterIdentifier": id, "RoleArn": text(&r["RoleArn"])});
            if let Some(f) = r.get("FeatureName") {
                input["FeatureName"] = json!(text(f));
            }
            cx.call("rds", "AddRoleToDBCluster", input).await?;
        }
        let c = wait_cluster(cx, id).await?;
        retag(cx, "rds", &text(&c["DBClusterArn"]), old, new).await?;
        Ok(cluster_attributes(&c))
    }

    async fn snapshot(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> Option<HResult<()>> {
        Some(
            async {
                let name = snapshot_name(cx, 255);
                match cx
                    .call(
                        "rds",
                        "CreateDBClusterSnapshot",
                        json!({"DBClusterSnapshotIdentifier": name, "DBClusterIdentifier": id}),
                    )
                    .await
                {
                    Err(e) if e.not_found => return Ok(()),
                    r => r?,
                };
                let name = &name;
                stabilize(&format!("DB cluster snapshot {name} to become available"), || async move {
                    let out = cx
                        .call("rds", "DescribeDBClusterSnapshots", json!({"DBClusterSnapshotIdentifier": name}))
                        .await?;
                    let status = text(&out["DBClusterSnapshots"][0]["Status"]);
                    if status == "failed" {
                        return Err(failed(&format!("DB cluster snapshot {name}"), &status));
                    }
                    Ok(status == "available")
                })
                .await
            }
            .await,
        )
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        match cx.call("rds", "DeleteDBCluster", json!({"DBClusterIdentifier": id, "SkipFinalSnapshot": true})).await {
            Err(e) if e.not_found => return Ok(()),
            r => {
                r?;
            }
        }
        wait_gone(&format!("DB cluster {id} to be deleted"), || describe_cluster(cx, id)).await
    }
}

// ---------------------------------------------------------------------
// Subnet groups.

struct DbSubnetGroup;

#[async_trait::async_trait]
impl Provider for DbSubnetGroup {
    fn create_only(&self) -> &'static [&'static str] {
        &["DBSubnetGroupName"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["DBSubnetGroupDescription", "SubnetIds"]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("DBSubnetGroupName")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "DBSubnetGroupName").unwrap_or_else(|| identifier(cx, 255));
        let mut input = json!({
            "DBSubnetGroupName": name,
            "DBSubnetGroupDescription": req(props, "DBSubnetGroupDescription")?,
            "SubnetIds": list(props, "SubnetIds"),
        });
        let tags = cx.tags(props);
        if !tags.is_empty() {
            input["Tags"] = json!(tags);
        }
        let out = cx.call("rds", "CreateDBSubnetGroup", input).await?;
        Ok(Created::new(text(&out["DBSubnetGroup"]["DBSubnetGroupName"])))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "DBSubnetGroupDescription") || changed(old, new, "SubnetIds") {
            cx.call(
                "rds",
                "ModifyDBSubnetGroup",
                json!({
                    "DBSubnetGroupName": name,
                    "DBSubnetGroupDescription": req(new, "DBSubnetGroupDescription")?,
                    "SubnetIds": list(new, "SubnetIds"),
                }),
            )
            .await?;
        }
        retag(cx, "rds", &cx.arn("rds", &format!("subgrp:{name}")), old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("rds", "DeleteDBSubnetGroup", json!({"DBSubnetGroupName": name})).await)
    }
}

// ---------------------------------------------------------------------
// Parameter groups (instance and cluster).

struct ParamKind {
    name: &'static str,
    create: &'static str,
    modify: &'static str,
    reset: &'static str,
    describe: &'static str,
    delete: &'static str,
    arn_kind: &'static str,
}

const INSTANCE_PARAMS: ParamKind = ParamKind {
    name: "DBParameterGroupName",
    create: "CreateDBParameterGroup",
    modify: "ModifyDBParameterGroup",
    reset: "ResetDBParameterGroup",
    describe: "DescribeDBParameters",
    delete: "DeleteDBParameterGroup",
    arn_kind: "pg",
};

const CLUSTER_PARAMS: ParamKind = ParamKind {
    name: "DBClusterParameterGroupName",
    create: "CreateDBClusterParameterGroup",
    modify: "ModifyDBClusterParameterGroup",
    reset: "ResetDBClusterParameterGroup",
    describe: "DescribeDBClusterParameters",
    delete: "DeleteDBClusterParameterGroup",
    arn_kind: "cluster-pg",
};

fn parameters(props: &Props) -> BTreeMap<String, String> {
    match props.get("Parameters") {
        Some(Value::Object(m)) => m.iter().map(|(k, v)| (k.clone(), text(v))).collect(),
        _ => BTreeMap::new(),
    }
}

struct ParameterGroup(&'static ParamKind);

impl ParameterGroup {
    /// Each parameter's apply type (`static` or `dynamic`).
    async fn apply_types(&self, cx: &Cx<'_>, name: &str) -> HResult<BTreeMap<String, String>> {
        let mut out = BTreeMap::new();
        let mut marker: Option<String> = None;
        loop {
            let mut input = json!({self.0.name: name, "MaxRecords": 100});
            if let Some(m) = &marker {
                input["Marker"] = json!(m);
            }
            let page = cx.call("rds", self.0.describe, input).await?;
            for p in page["Parameters"].as_array().cloned().unwrap_or_default() {
                out.insert(text(&p["ParameterName"]), text(&p["ApplyType"]));
            }
            match page["Marker"].as_str().filter(|m| !m.is_empty()) {
                Some(m) => marker = Some(m.to_string()),
                None => return Ok(out),
            }
        }
    }

    async fn set(&self, cx: &Cx<'_>, name: &str, values: &BTreeMap<String, String>) -> HResult<()> {
        if values.is_empty() {
            return Ok(());
        }
        let types = self.apply_types(cx, name).await?;
        let all: Vec<Value> = values
            .iter()
            .map(|(k, v)| {
                let method =
                    if types.get(k).map(String::as_str) == Some("dynamic") { "immediate" } else { "pending-reboot" };
                json!({"ParameterName": k, "ParameterValue": v, "ApplyMethod": method})
            })
            .collect();
        for chunk in all.chunks(20) {
            cx.call("rds", self.0.modify, json!({self.0.name: name, "Parameters": chunk})).await?;
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl Provider for ParameterGroup {
    fn create_only(&self) -> &'static [&'static str] {
        if self.0.name == "DBParameterGroupName" {
            &["DBParameterGroupName", "Family", "Description"]
        } else {
            &["DBClusterParameterGroupName", "Family", "Description"]
        }
    }
    fn required(&self) -> &'static [&'static str] {
        if self.0.name == "DBParameterGroupName" {
            &["Family", "Description"]
        } else {
            &["Family", "Description", "Parameters"]
        }
    }
    fn attributes(&self) -> &'static [&'static str] {
        if self.0.name == "DBParameterGroupName" {
            &["DBParameterGroupName"]
        } else {
            &[]
        }
    }
    fn name_property(&self) -> Option<&'static str> {
        Some(self.0.name)
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, self.0.name).unwrap_or_else(|| identifier(cx, 255));
        let mut input = json!({
            self.0.name: name,
            "DBParameterGroupFamily": req(props, "Family")?,
            "Description": req(props, "Description")?,
        });
        let tags = cx.tags(props);
        if !tags.is_empty() {
            input["Tags"] = json!(tags);
        }
        let out = cx.call("rds", self.0.create, input).await?;
        let group = if self.0.name == "DBParameterGroupName" { "DBParameterGroup" } else { "DBClusterParameterGroup" };
        let name = text(&out[group][self.0.name]);
        if let Err(e) = self.set(cx, &name, &parameters(props)).await {
            let _ = cx.call("rds", self.0.delete, json!({self.0.name: name})).await;
            return Err(e);
        }
        let mut c = Created::new(&name);
        if self.0.name == "DBParameterGroupName" {
            c = c.attr("DBParameterGroupName", name.clone());
        }
        Ok(c)
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "Parameters") {
            let (o, n) = (parameters(old), parameters(new));
            let removed: Vec<Value> = o
                .keys()
                .filter(|k| !n.contains_key(*k))
                .map(|k| json!({"ParameterName": k, "ApplyMethod": "pending-reboot"}))
                .collect();
            for chunk in removed.chunks(20) {
                cx.call("rds", self.0.reset, json!({self.0.name: name, "Parameters": chunk})).await?;
            }
            let set: BTreeMap<String, String> = n.into_iter().filter(|(k, v)| o.get(k) != Some(v)).collect();
            self.set(cx, name, &set).await?;
        }
        retag(cx, "rds", &cx.arn("rds", &format!("{}:{name}", self.0.arn_kind)), old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("rds", self.0.delete, json!({self.0.name: name})).await)
    }
}

// ---------------------------------------------------------------------
// Option groups.

fn options(props: &Props) -> Vec<Value> {
    let mut v = props.get("OptionConfigurations").cloned().unwrap_or(json!([]));
    coerce(&mut v, &["Port"], &[], &["Value", "OptionVersion"]);
    v.as_array().cloned().unwrap_or_default()
}

struct OptionGroup;

#[async_trait::async_trait]
impl Provider for OptionGroup {
    fn create_only(&self) -> &'static [&'static str] {
        &["EngineName", "MajorEngineVersion", "OptionGroupDescription", "OptionGroupName"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["EngineName", "MajorEngineVersion", "OptionGroupDescription"]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("OptionGroupName")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "OptionGroupName").unwrap_or_else(|| identifier(cx, 255));
        let mut input = json!({
            "OptionGroupName": name,
            "EngineName": req(props, "EngineName")?,
            "MajorEngineVersion": req(props, "MajorEngineVersion")?,
            "OptionGroupDescription": req(props, "OptionGroupDescription")?,
        });
        let tags = cx.tags(props);
        if !tags.is_empty() {
            input["Tags"] = json!(tags);
        }
        let out = cx.call("rds", "CreateOptionGroup", input).await?;
        let name = text(&out["OptionGroup"]["OptionGroupName"]);
        let opts = options(props);
        if !opts.is_empty() {
            if let Err(e) = cx
                .call(
                    "rds",
                    "ModifyOptionGroup",
                    json!({"OptionGroupName": name, "OptionsToInclude": opts, "ApplyImmediately": true}),
                )
                .await
            {
                let _ = cx.call("rds", "DeleteOptionGroup", json!({"OptionGroupName": name})).await;
                return Err(e);
            }
        }
        Ok(Created::new(name))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if changed(old, new, "OptionConfigurations") {
            let (o, n) = (options(old), options(new));
            let new_names: BTreeSet<String> = n.iter().map(|x| text(&x["OptionName"])).collect();
            let include: Vec<Value> = n.iter().filter(|x| !o.contains(x)).cloned().collect();
            let remove: Vec<String> =
                o.iter().map(|x| text(&x["OptionName"])).filter(|k| !new_names.contains(k)).collect();
            let mut input = json!({"OptionGroupName": name, "ApplyImmediately": true});
            if !include.is_empty() {
                input["OptionsToInclude"] = json!(include);
            }
            if !remove.is_empty() {
                input["OptionsToRemove"] = json!(remove);
            }
            if !include.is_empty() || !remove.is_empty() {
                cx.call("rds", "ModifyOptionGroup", input).await?;
            }
        }
        retag(cx, "rds", &cx.arn("rds", &format!("og:{name}")), old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("rds", "DeleteOptionGroup", json!({"OptionGroupName": name})).await)
    }
}

// ---------------------------------------------------------------------
// Event subscriptions.

struct EventSubscription;

async fn describe_subscription(cx: &Cx<'_>, name: &str) -> HResult<Value> {
    let out = cx.call("rds", "DescribeEventSubscriptions", json!({"SubscriptionName": name})).await?;
    Ok(out["EventSubscriptionsList"][0].clone())
}

async fn wait_subscription(cx: &Cx<'_>, name: &str) -> HResult<()> {
    stabilize(&format!("event subscription {name} to become active"), || async move {
        let s = describe_subscription(cx, name).await?;
        Ok(matches!(text(&s["Status"]).as_str(), "active" | "no-permission" | "topic-not-exist" | ""))
    })
    .await
}

#[async_trait::async_trait]
impl Provider for EventSubscription {
    fn create_only(&self) -> &'static [&'static str] {
        &["SubscriptionName"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["SnsTopicArn"]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("SubscriptionName")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "SubscriptionName").unwrap_or_else(|| identifier(cx, 255));
        let mut input = json!({
            "SubscriptionName": name,
            "SnsTopicArn": req(props, "SnsTopicArn")?,
            "Enabled": boolean(props, "Enabled").unwrap_or(true),
        });
        if let Some(t) = s(props, "SourceType") {
            input["SourceType"] = json!(t);
        }
        for k in ["EventCategories", "SourceIds"] {
            let v = list(props, k);
            if !v.is_empty() {
                input[k] = json!(v);
            }
        }
        let tags = cx.tags(props);
        if !tags.is_empty() {
            input["Tags"] = json!(tags);
        }
        let out = cx.call("rds", "CreateEventSubscription", input).await?;
        let name = text(&out["EventSubscription"]["CustSubscriptionId"]);
        wait_subscription(cx, &name).await.map_err(|e| e.created(&name))?;
        Ok(Created::new(name))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if ["SnsTopicArn", "SourceType", "EventCategories", "Enabled"].iter().any(|k| changed(old, new, k)) {
            let mut input = json!({
                "SubscriptionName": name,
                "SnsTopicArn": req(new, "SnsTopicArn")?,
                "Enabled": boolean(new, "Enabled").unwrap_or(true),
                "EventCategories": list(new, "EventCategories"),
            });
            if let Some(t) = s(new, "SourceType") {
                input["SourceType"] = json!(t);
            }
            cx.call("rds", "ModifyEventSubscription", input).await?;
        }
        if changed(old, new, "SourceIds") {
            let (o, n) = (list(old, "SourceIds"), list(new, "SourceIds"));
            for id in o.iter().filter(|i| !n.contains(i)) {
                gone_ok(
                    cx.call(
                        "rds",
                        "RemoveSourceIdentifierFromSubscription",
                        json!({"SubscriptionName": name, "SourceIdentifier": id}),
                    )
                    .await,
                )?;
            }
            for id in n.iter().filter(|i| !o.contains(i)) {
                cx.call(
                    "rds",
                    "AddSourceIdentifierToSubscription",
                    json!({"SubscriptionName": name, "SourceIdentifier": id}),
                )
                .await?;
            }
        }
        wait_subscription(cx, name).await?;
        retag(cx, "rds", &cx.arn("rds", &format!("es:{name}")), old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        match cx.call("rds", "DeleteEventSubscription", json!({"SubscriptionName": name})).await {
            Err(e) if e.not_found => return Ok(()),
            r => {
                r?;
            }
        }
        wait_gone(&format!("event subscription {name} to be deleted"), || describe_subscription(cx, name)).await
    }
}

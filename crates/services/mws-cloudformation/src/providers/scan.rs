//! Listing existing resources of a type (resource scans, the IaC
//! generator and IMPORT change sets), through the owning services' APIs.

use serde_json::{json, Map, Value};

use super::{text, Cx, HResult, Props};

/// One existing resource, as a scan finds it.
#[derive(Debug, Clone, Default)]
pub struct Scanned {
    /// The resource's primary identifier, e.g. `{"BucketName": "x"}`.
    pub identifier: Props,
    /// The physical id CloudFormation tracks it by.
    pub physical_id: String,
    /// Template properties that recreate it.
    pub properties: Props,
    /// `Fn::GetAtt` values.
    pub attributes: Props,
    pub tags: Vec<(String, String)>,
    /// Write-only properties filled with a placeholder.
    pub write_only: Vec<String>,
}

fn one(key: &str, v: impl Into<Value>) -> Props {
    let mut m = Map::new();
    m.insert(key.into(), v.into());
    m
}

fn obj(v: Value) -> Props {
    match v {
        Value::Object(m) => m.into_iter().filter(|(_, v)| !v.is_null()).collect(),
        _ => Map::new(),
    }
}

fn arr(v: &Value) -> Vec<Value> {
    v.as_array().cloned().unwrap_or_default()
}

fn ec2_tags(v: &Value) -> Vec<(String, String)> {
    arr(&v["Tags"]).iter().map(|t| (text(&t["Key"]), text(&t["Value"]))).collect()
}

fn tag_list(tags: &[(String, String)]) -> Value {
    Value::Array(
        tags.iter().filter(|(k, _)| !k.starts_with("aws:")).map(|(k, v)| json!({"Key": k, "Value": v})).collect(),
    )
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(n) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(n);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_default()
}

fn policy_doc(v: &Value) -> Value {
    let t = text(v);
    let t = if t.starts_with('%') || t.contains("%22") { percent_decode(&t) } else { t };
    serde_json::from_str(&t).unwrap_or(Value::String(t))
}

/// The resource types scans support.
pub const SCANNABLE: &[&str] = &[
    "AWS::CloudWatch::Alarm",
    "AWS::EC2::SecurityGroup",
    "AWS::EC2::Subnet",
    "AWS::EC2::VPC",
    "AWS::Events::Rule",
    "AWS::IAM::Role",
    "AWS::IAM::User",
    "AWS::KMS::Key",
    "AWS::Kinesis::Stream",
    "AWS::Lambda::Function",
    "AWS::Logs::LogGroup",
    "AWS::Route53::HostedZone",
    "AWS::S3::Bucket",
    "AWS::SNS::Topic",
    "AWS::SQS::Queue",
    "AWS::SSM::Parameter",
    "AWS::SecretsManager::Secret",
];

/// Every existing resource of `ty` in the context's account and Region,
/// or `None` when the type cannot be listed.
pub async fn list(cx: &Cx<'_>, ty: &str) -> Option<HResult<Vec<Scanned>>> {
    Some(match ty {
        "AWS::S3::Bucket" => buckets(cx).await,
        "AWS::SQS::Queue" => queues(cx).await,
        "AWS::SNS::Topic" => topics(cx).await,
        "AWS::Lambda::Function" => functions(cx).await,
        "AWS::IAM::Role" => roles(cx).await,
        "AWS::IAM::User" => users(cx).await,
        "AWS::KMS::Key" => keys(cx).await,
        "AWS::SSM::Parameter" => parameters(cx).await,
        "AWS::SecretsManager::Secret" => secrets(cx).await,
        "AWS::Logs::LogGroup" => log_groups(cx).await,
        "AWS::Kinesis::Stream" => streams(cx).await,
        "AWS::Route53::HostedZone" => zones(cx).await,
        "AWS::EC2::VPC" => vpcs(cx).await,
        "AWS::EC2::Subnet" => subnets(cx).await,
        "AWS::EC2::SecurityGroup" => security_groups(cx).await,
        "AWS::CloudWatch::Alarm" => alarms(cx).await,
        "AWS::Events::Rule" => rules(cx).await,
        _ => return None,
    })
}

async fn buckets(cx: &Cx<'_>) -> HResult<Vec<Scanned>> {
    let out = cx.call("s3", "ListBuckets", json!({})).await?;
    let mut v = Vec::new();
    for b in arr(&out["Buckets"]) {
        let name = text(&b["Name"]);
        let loc = cx.call("s3", "GetBucketLocation", json!({"Bucket": name})).await;
        let region = loc
            .ok()
            .and_then(|l| l["LocationConstraint"].as_str().map(str::to_string))
            .filter(|r| !r.is_empty())
            .unwrap_or_else(|| "us-east-1".into());
        if region != cx.region() {
            continue;
        }
        let tags: Vec<(String, String)> = cx
            .call("s3", "GetBucketTagging", json!({"Bucket": name}))
            .await
            .map(|t| arr(&t["TagSet"]).iter().map(|t| (text(&t["Key"]), text(&t["Value"]))).collect())
            .unwrap_or_default();
        let mut props = one("BucketName", name.clone());
        if !tags.is_empty() {
            props.insert("Tags".into(), tag_list(&tags));
        }
        let partition = cx.partition().to_string();
        v.push(Scanned {
            identifier: one("BucketName", name.clone()),
            physical_id: name.clone(),
            properties: props,
            attributes: obj(json!({
                "Arn": format!("arn:{partition}:s3:::{name}"),
                "DomainName": format!("{name}.s3.amazonaws.com"),
                "RegionalDomainName": format!("{name}.s3.{region}.amazonaws.com"),
            })),
            tags,
            ..Default::default()
        });
    }
    Ok(v)
}

async fn queues(cx: &Cx<'_>) -> HResult<Vec<Scanned>> {
    let out = cx.call("sqs", "ListQueues", json!({})).await?;
    let mut v = Vec::new();
    for url in arr(&out["QueueUrls"]).iter().map(text) {
        let a = cx.call("sqs", "GetQueueAttributes", json!({"QueueUrl": url, "AttributeNames": ["All"]})).await?;
        let a = &a["Attributes"];
        let name = url.rsplit('/').next().unwrap_or_default().to_string();
        let mut props = one("QueueName", name.clone());
        for (k, default) in [
            ("DelaySeconds", "0"),
            ("MaximumMessageSize", "262144"),
            ("MessageRetentionPeriod", "345600"),
            ("ReceiveMessageWaitTimeSeconds", "0"),
            ("VisibilityTimeout", "30"),
        ] {
            if let Some(x) = a[k].as_str().filter(|x| *x != default) {
                props.insert(k.into(), json!(x.parse::<i64>().map(Value::from).unwrap_or(json!(x))));
            }
        }
        if a["FifoQueue"].as_str() == Some("true") {
            props.insert("FifoQueue".into(), json!(true));
        }
        if let Some(r) = a["RedrivePolicy"].as_str() {
            props.insert("RedrivePolicy".into(), serde_json::from_str(r).unwrap_or(json!(r)));
        }
        let tags: Vec<(String, String)> = cx
            .call("sqs", "ListQueueTags", json!({"QueueUrl": url}))
            .await
            .ok()
            .and_then(|t| t["Tags"].as_object().cloned())
            .map(|m| m.into_iter().map(|(k, v)| (k, text(&v))).collect())
            .unwrap_or_default();
        if !tags.is_empty() {
            props.insert("Tags".into(), tag_list(&tags));
        }
        v.push(Scanned {
            identifier: one("QueueUrl", url.clone()),
            physical_id: url.clone(),
            properties: props,
            attributes: obj(json!({"Arn": a["QueueArn"], "QueueUrl": url, "QueueName": name})),
            tags,
            ..Default::default()
        });
    }
    Ok(v)
}

async fn topics(cx: &Cx<'_>) -> HResult<Vec<Scanned>> {
    let out = cx.call("sns", "ListTopics", json!({})).await?;
    let mut v = Vec::new();
    for t in arr(&out["Topics"]) {
        let arn = text(&t["TopicArn"]);
        let name = arn.rsplit(':').next().unwrap_or_default().to_string();
        let attrs = cx.call("sns", "GetTopicAttributes", json!({"TopicArn": arn})).await.unwrap_or_default();
        let mut props = one("TopicName", name.clone());
        if let Some(d) = attrs["Attributes"]["DisplayName"].as_str().filter(|d| !d.is_empty()) {
            props.insert("DisplayName".into(), json!(d));
        }
        if name.ends_with(".fifo") {
            props.insert("FifoTopic".into(), json!(true));
        }
        v.push(Scanned {
            identifier: one("TopicArn", arn.clone()),
            physical_id: arn.clone(),
            properties: props,
            attributes: obj(json!({"TopicArn": arn, "TopicName": name})),
            ..Default::default()
        });
    }
    Ok(v)
}

async fn functions(cx: &Cx<'_>) -> HResult<Vec<Scanned>> {
    let out = cx.call("lambda", "ListFunctions", json!({})).await?;
    let mut v = Vec::new();
    for f in arr(&out["Functions"]) {
        let name = text(&f["FunctionName"]);
        // The registry's own handler functions are not the account's.
        if name.starts_with("CloudFormation-resource-") || name.starts_with("CloudFormation-hook-") {
            continue;
        }
        let mut props = obj(json!({
            "FunctionName": name,
            "Role": f["Role"],
            "Runtime": f["Runtime"],
            "Handler": f["Handler"],
            "Timeout": f["Timeout"],
            "MemorySize": f["MemorySize"],
            "Description": f["Description"].as_str().filter(|d| !d.is_empty()),
        }));
        if let Some(env) = f["Environment"]["Variables"].as_object().filter(|e| !e.is_empty()) {
            props.insert("Environment".into(), json!({"Variables": env}));
        }
        // The code cannot be read back; AWS's generator leaves a
        // placeholder too.
        props.insert("Code".into(), json!({"S3Bucket": "REPLACEME", "S3Key": "REPLACEME"}));
        v.push(Scanned {
            identifier: one("FunctionName", name.clone()),
            physical_id: name.clone(),
            properties: props,
            attributes: obj(json!({"Arn": f["FunctionArn"]})),
            write_only: vec!["/properties/Code".into()],
            ..Default::default()
        });
    }
    Ok(v)
}

async fn roles(cx: &Cx<'_>) -> HResult<Vec<Scanned>> {
    let out = cx.call("iam", "ListRoles", json!({})).await?;
    let mut v = Vec::new();
    for r in arr(&out["Roles"]) {
        let path = text(&r["Path"]);
        if path.starts_with("/aws-service-role/") || path.starts_with("/aws-reserved/") {
            continue;
        }
        let name = text(&r["RoleName"]);
        let mut props = obj(json!({
            "RoleName": name,
            "Path": path,
            "AssumeRolePolicyDocument": policy_doc(&r["AssumeRolePolicyDocument"]),
            "Description": r["Description"].as_str().filter(|d| !d.is_empty()),
            "MaxSessionDuration": r["MaxSessionDuration"],
        }));
        let attached = cx.call("iam", "ListAttachedRolePolicies", json!({"RoleName": name})).await.unwrap_or_default();
        let arns: Vec<Value> = arr(&attached["AttachedPolicies"]).iter().map(|p| p["PolicyArn"].clone()).collect();
        if !arns.is_empty() {
            props.insert("ManagedPolicyArns".into(), Value::Array(arns));
        }
        let inline = cx.call("iam", "ListRolePolicies", json!({"RoleName": name})).await.unwrap_or_default();
        let mut policies = Vec::new();
        for p in arr(&inline["PolicyNames"]).iter().map(text) {
            if let Ok(doc) = cx.call("iam", "GetRolePolicy", json!({"RoleName": name, "PolicyName": p})).await {
                policies.push(json!({"PolicyName": p, "PolicyDocument": policy_doc(&doc["PolicyDocument"])}));
            }
        }
        if !policies.is_empty() {
            props.insert("Policies".into(), Value::Array(policies));
        }
        v.push(Scanned {
            identifier: one("RoleName", name.clone()),
            physical_id: name.clone(),
            properties: props,
            attributes: obj(json!({"Arn": r["Arn"], "RoleId": r["RoleId"]})),
            ..Default::default()
        });
    }
    Ok(v)
}

async fn users(cx: &Cx<'_>) -> HResult<Vec<Scanned>> {
    let out = cx.call("iam", "ListUsers", json!({})).await?;
    Ok(arr(&out["Users"])
        .iter()
        .map(|u| {
            let name = text(&u["UserName"]);
            Scanned {
                identifier: one("UserName", name.clone()),
                physical_id: name.clone(),
                properties: obj(json!({"UserName": name, "Path": u["Path"]})),
                attributes: obj(json!({"Arn": u["Arn"]})),
                ..Default::default()
            }
        })
        .collect())
}

async fn keys(cx: &Cx<'_>) -> HResult<Vec<Scanned>> {
    let out = cx.call("kms", "ListKeys", json!({})).await?;
    let mut v = Vec::new();
    for k in arr(&out["Keys"]) {
        let id = text(&k["KeyId"]);
        let d = cx.call("kms", "DescribeKey", json!({"KeyId": id})).await?;
        let m = &d["KeyMetadata"];
        if m["KeyManager"].as_str() == Some("AWS") || m["KeyState"].as_str() == Some("PendingDeletion") {
            continue;
        }
        let policy = cx
            .call("kms", "GetKeyPolicy", json!({"KeyId": id, "PolicyName": "default"}))
            .await
            .map(|p| policy_doc(&p["Policy"]))
            .unwrap_or(Value::Null);
        v.push(Scanned {
            identifier: one("KeyId", id.clone()),
            physical_id: id.clone(),
            properties: obj(json!({
                "Description": m["Description"].as_str().filter(|d| !d.is_empty()),
                "KeyUsage": m["KeyUsage"],
                "KeySpec": m["KeySpec"],
                "Enabled": m["Enabled"],
                "KeyPolicy": policy,
            })),
            attributes: obj(json!({"KeyId": id, "Arn": m["Arn"]})),
            ..Default::default()
        });
    }
    Ok(v)
}

async fn parameters(cx: &Cx<'_>) -> HResult<Vec<Scanned>> {
    let out = cx.call("ssm", "DescribeParameters", json!({})).await?;
    let mut v = Vec::new();
    for p in arr(&out["Parameters"]) {
        let ty = text(&p["Type"]);
        // CloudFormation cannot manage SecureString parameters.
        if ty == "SecureString" {
            continue;
        }
        let name = text(&p["Name"]);
        let value = cx.call("ssm", "GetParameter", json!({"Name": name})).await?;
        let value = text(&value["Parameter"]["Value"]);
        v.push(Scanned {
            identifier: one("Name", name.clone()),
            physical_id: name.clone(),
            properties: obj(json!({
                "Name": name,
                "Type": ty,
                "Value": value,
                "Description": p["Description"].as_str().filter(|d| !d.is_empty()),
                "Tier": p["Tier"],
            })),
            attributes: obj(json!({"Type": ty, "Value": value})),
            ..Default::default()
        });
    }
    Ok(v)
}

async fn secrets(cx: &Cx<'_>) -> HResult<Vec<Scanned>> {
    let out = cx.call("secretsmanager", "ListSecrets", json!({})).await?;
    Ok(arr(&out["SecretList"])
        .iter()
        .map(|s| {
            let arn = text(&s["ARN"]);
            let tags: Vec<(String, String)> =
                arr(&s["Tags"]).iter().map(|t| (text(&t["Key"]), text(&t["Value"]))).collect();
            let mut props = obj(json!({
                "Name": s["Name"],
                "Description": s["Description"].as_str().filter(|d| !d.is_empty()),
                "KmsKeyId": s["KmsKeyId"],
            }));
            if !tags.is_empty() {
                props.insert("Tags".into(), tag_list(&tags));
            }
            Scanned {
                identifier: one("Id", arn.clone()),
                physical_id: arn.clone(),
                properties: props,
                attributes: obj(json!({"Id": arn})),
                tags,
                write_only: vec!["/properties/SecretString".into()],
            }
        })
        .collect())
}

async fn log_groups(cx: &Cx<'_>) -> HResult<Vec<Scanned>> {
    let out = cx.call("logs", "DescribeLogGroups", json!({})).await?;
    Ok(arr(&out["logGroups"])
        .iter()
        .map(|g| {
            let name = text(&g["logGroupName"]);
            Scanned {
                identifier: one("LogGroupName", name.clone()),
                physical_id: name.clone(),
                properties: obj(json!({
                    "LogGroupName": name,
                    "RetentionInDays": g["retentionInDays"],
                    "KmsKeyId": g["kmsKeyId"],
                })),
                attributes: obj(json!({"Arn": g["arn"]})),
                ..Default::default()
            }
        })
        .collect())
}

async fn streams(cx: &Cx<'_>) -> HResult<Vec<Scanned>> {
    let out = cx.call("kinesis", "ListStreams", json!({})).await?;
    let mut v = Vec::new();
    for name in arr(&out["StreamNames"]).iter().map(text) {
        let d = cx.call("kinesis", "DescribeStreamSummary", json!({"StreamName": name})).await?;
        let d = &d["StreamDescriptionSummary"];
        let mode = d["StreamModeDetails"]["StreamMode"].as_str().unwrap_or("PROVISIONED");
        let mut props = obj(json!({
            "Name": name,
            "RetentionPeriodHours": d["RetentionPeriodHours"],
            "StreamModeDetails": {"StreamMode": mode},
        }));
        if mode == "PROVISIONED" {
            props.insert("ShardCount".into(), d["OpenShardCount"].clone());
        }
        v.push(Scanned {
            identifier: one("Name", name.clone()),
            physical_id: name.clone(),
            properties: props,
            attributes: obj(json!({"Arn": d["StreamARN"]})),
            ..Default::default()
        });
    }
    Ok(v)
}

async fn zones(cx: &Cx<'_>) -> HResult<Vec<Scanned>> {
    let out = cx.call("route53", "ListHostedZones", json!({})).await?;
    Ok(arr(&out["HostedZones"])
        .iter()
        .map(|z| {
            let id = text(&z["Id"]).trim_start_matches("/hostedzone/").to_string();
            let mut props = one("Name", z["Name"].clone());
            if let Some(c) = z["Config"]["Comment"].as_str().filter(|c| !c.is_empty()) {
                props.insert("HostedZoneConfig".into(), json!({"Comment": c}));
            }
            Scanned {
                identifier: one("Id", id.clone()),
                physical_id: id.clone(),
                properties: props,
                attributes: obj(json!({"Id": id})),
                ..Default::default()
            }
        })
        .collect())
}

async fn vpcs(cx: &Cx<'_>) -> HResult<Vec<Scanned>> {
    let out = cx.call("ec2", "DescribeVpcs", json!({})).await?;
    Ok(arr(&out["Vpcs"])
        .iter()
        .map(|x| {
            let id = text(&x["VpcId"]);
            let tags = ec2_tags(x);
            let mut props = obj(json!({"CidrBlock": x["CidrBlock"], "InstanceTenancy": x["InstanceTenancy"]}));
            if !tags.is_empty() {
                props.insert("Tags".into(), tag_list(&tags));
            }
            Scanned {
                identifier: one("VpcId", id.clone()),
                physical_id: id.clone(),
                properties: props,
                attributes: obj(json!({"VpcId": id, "CidrBlock": x["CidrBlock"]})),
                tags,
                ..Default::default()
            }
        })
        .collect())
}

async fn subnets(cx: &Cx<'_>) -> HResult<Vec<Scanned>> {
    let out = cx.call("ec2", "DescribeSubnets", json!({})).await?;
    Ok(arr(&out["Subnets"])
        .iter()
        .map(|x| {
            let id = text(&x["SubnetId"]);
            let tags = ec2_tags(x);
            let mut props = obj(json!({
                "VpcId": x["VpcId"],
                "CidrBlock": x["CidrBlock"],
                "AvailabilityZone": x["AvailabilityZone"],
                "MapPublicIpOnLaunch": x["MapPublicIpOnLaunch"],
            }));
            if !tags.is_empty() {
                props.insert("Tags".into(), tag_list(&tags));
            }
            Scanned {
                identifier: one("SubnetId", id.clone()),
                physical_id: id.clone(),
                properties: props,
                attributes: obj(
                    json!({"SubnetId": id, "VpcId": x["VpcId"], "AvailabilityZone": x["AvailabilityZone"]}),
                ),
                tags,
                ..Default::default()
            }
        })
        .collect())
}

async fn security_groups(cx: &Cx<'_>) -> HResult<Vec<Scanned>> {
    let out = cx.call("ec2", "DescribeSecurityGroups", json!({})).await?;
    Ok(arr(&out["SecurityGroups"])
        .iter()
        .filter(|g| g["GroupName"].as_str() != Some("default"))
        .map(|g| {
            let id = text(&g["GroupId"]);
            let tags = ec2_tags(g);
            let ingress: Vec<Value> = arr(&g["IpPermissions"])
                .iter()
                .flat_map(|p| {
                    arr(&p["IpRanges"])
                        .into_iter()
                        .map(|r| {
                            obj(json!({
                                "IpProtocol": p["IpProtocol"],
                                "FromPort": p["FromPort"],
                                "ToPort": p["ToPort"],
                                "CidrIp": r["CidrIp"],
                            }))
                        })
                        .map(Value::Object)
                        .collect::<Vec<_>>()
                })
                .collect();
            let mut props = obj(json!({
                "GroupName": g["GroupName"],
                "GroupDescription": g["Description"],
                "VpcId": g["VpcId"],
            }));
            if !ingress.is_empty() {
                props.insert("SecurityGroupIngress".into(), Value::Array(ingress));
            }
            if !tags.is_empty() {
                props.insert("Tags".into(), tag_list(&tags));
            }
            Scanned {
                identifier: one("Id", id.clone()),
                physical_id: id.clone(),
                properties: props,
                attributes: obj(json!({"GroupId": id, "VpcId": g["VpcId"]})),
                tags,
                ..Default::default()
            }
        })
        .collect())
}

async fn alarms(cx: &Cx<'_>) -> HResult<Vec<Scanned>> {
    let out = cx.call("monitoring", "DescribeAlarms", json!({})).await?;
    Ok(arr(&out["MetricAlarms"])
        .iter()
        .map(|a| {
            let name = text(&a["AlarmName"]);
            Scanned {
                identifier: one("AlarmName", name.clone()),
                physical_id: name.clone(),
                properties: obj(json!({
                    "AlarmName": name,
                    "AlarmDescription": a["AlarmDescription"],
                    "MetricName": a["MetricName"],
                    "Namespace": a["Namespace"],
                    "Statistic": a["Statistic"],
                    "Period": a["Period"],
                    "EvaluationPeriods": a["EvaluationPeriods"],
                    "Threshold": a["Threshold"],
                    "ComparisonOperator": a["ComparisonOperator"],
                    "Dimensions": a["Dimensions"].as_array().filter(|d| !d.is_empty()).map(|d| Value::Array(d.clone())),
                    "AlarmActions": a["AlarmActions"].as_array().filter(|d| !d.is_empty()).map(|d| Value::Array(d.clone())),
                })),
                attributes: obj(json!({"Arn": a["AlarmArn"]})),
                ..Default::default()
            }
        })
        .collect())
}

async fn rules(cx: &Cx<'_>) -> HResult<Vec<Scanned>> {
    let out = cx.call("events", "ListRules", json!({})).await?;
    Ok(arr(&out["Rules"])
        .iter()
        .filter(|r| r["ManagedBy"].is_null())
        .map(|r| {
            let name = text(&r["Name"]);
            let arn = text(&r["Arn"]);
            Scanned {
                identifier: one("Arn", arn.clone()),
                physical_id: name.clone(),
                properties: obj(json!({
                    "Name": name,
                    "Description": r["Description"],
                    "EventPattern": r["EventPattern"].as_str().and_then(|p| serde_json::from_str::<Value>(p).ok()),
                    "ScheduleExpression": r["ScheduleExpression"],
                    "State": r["State"],
                })),
                attributes: obj(json!({"Arn": arn})),
                ..Default::default()
            }
        })
        .collect())
}

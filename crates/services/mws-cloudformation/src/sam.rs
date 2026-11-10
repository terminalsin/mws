//! The `AWS::Serverless-2016-10-31` transform for the SAM resource types
//! whose output MWS can deploy: functions (with SQS, Kinesis, SNS, S3,
//! Schedule and EventBridge events), layers and nested applications.
//! Logical ids follow SAM's (`<Function>Role`, `<Function><Event>`,
//! `<Function><Event>Permission`), so templates that refer to generated
//! resources keep working.

use serde_json::{json, Map, Value};

const PREFIX: &str = "Transform AWS::Serverless-2016-10-31 failed with: Invalid Serverless Application Specification document. Number of errors found: 1.";

fn invalid(id: &str, why: impl std::fmt::Display) -> String {
    format!("{PREFIX} Resource with id [{id}] is invalid. {why}")
}

fn sub(s: &str) -> Value {
    json!({"Fn::Sub": s})
}

/// An S3 location (`s3://bucket/key` or `{Bucket, Key, Version}`) as
/// Lambda's `S3Bucket`/`S3Key`/`S3ObjectVersion`.
fn s3_location(id: &str, v: &Value, bucket: &str, key: &str, version: &str) -> Result<Value, String> {
    match v {
        Value::String(s) => {
            let rest = s
                .strip_prefix("s3://")
                .ok_or_else(|| invalid(id, format!("'{s}' is not a valid S3 Uri of the form 's3://bucket/key'.")))?;
            let (b, k) = rest
                .split_once('/')
                .ok_or_else(|| invalid(id, format!("'{s}' is not a valid S3 Uri of the form 's3://bucket/key'.")))?;
            Ok(json!({bucket: b, key: k}))
        }
        Value::Object(o) => {
            let mut out = Map::new();
            out.insert(bucket.into(), o.get("Bucket").cloned().unwrap_or_default());
            out.insert(key.into(), o.get("Key").cloned().unwrap_or_default());
            if let Some(ver) = o.get("Version") {
                out.insert(version.into(), ver.clone());
            }
            Ok(Value::Object(out))
        }
        _ => Err(invalid(id, "CodeUri must be an S3 Uri or an object.")),
    }
}

/// SAM tags (a map) as a CloudFormation tag list, with SAM's own tag.
fn tag_list(tags: Option<&Value>) -> Value {
    let mut out = vec![json!({"Key": "lambda:createdBy", "Value": "SAM"})];
    if let Some(Value::Object(m)) = tags {
        for (k, v) in m {
            out.push(json!({"Key": k, "Value": v}));
        }
    }
    Value::Array(out)
}

/// A SAM policy template's statements.
fn policy_template(id: &str, name: &str, args: &Value) -> Result<Value, String> {
    let arg = |k: &str| args.get(k).cloned().unwrap_or_default();
    let bucket_arns = |b: Value| {
        json!([
            {"Fn::Sub": ["arn:${AWS::Partition}:s3:::${bucketName}", {"bucketName": b.clone()}]},
            {"Fn::Sub": ["arn:${AWS::Partition}:s3:::${bucketName}/*", {"bucketName": b}]}
        ])
    };
    let queue_arn = |q: Value| json!({"Fn::Sub": ["arn:${AWS::Partition}:sqs:${AWS::Region}:${AWS::AccountId}:${queueName}", {"queueName": q}]});
    Ok(match name {
        "S3ReadPolicy" => {
            json!([{"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation",
            "s3:GetObjectVersion", "s3:GetLifecycleConfiguration"], "Resource": bucket_arns(arg("BucketName"))}])
        }
        "S3WritePolicy" => json!([{"Effect": "Allow", "Action": ["s3:PutObject", "s3:PutObjectAcl",
            "s3:PutLifecycleConfiguration"], "Resource": bucket_arns(arg("BucketName"))}]),
        "S3CrudPolicy" => {
            json!([{"Effect": "Allow", "Action": ["s3:GetObject", "s3:ListBucket", "s3:GetBucketLocation",
            "s3:GetObjectVersion", "s3:PutObject", "s3:PutObjectAcl", "s3:GetLifecycleConfiguration",
            "s3:PutLifecycleConfiguration", "s3:DeleteObject"], "Resource": bucket_arns(arg("BucketName"))}])
        }
        "SQSPollerPolicy" => json!([{"Effect": "Allow", "Action": ["sqs:ChangeMessageVisibility",
            "sqs:ChangeMessageVisibilityBatch", "sqs:DeleteMessage", "sqs:DeleteMessageBatch",
            "sqs:GetQueueAttributes", "sqs:ReceiveMessage"], "Resource": queue_arn(arg("QueueName"))}]),
        "SQSSendMessagePolicy" => json!([{"Effect": "Allow", "Action": ["sqs:SendMessage*"],
            "Resource": queue_arn(arg("QueueName"))}]),
        "SNSPublishMessagePolicy" => json!([{"Effect": "Allow", "Action": ["sns:Publish"],
            "Resource": {"Fn::Sub": ["arn:${AWS::Partition}:sns:${AWS::Region}:${AWS::AccountId}:${topicName}",
                {"topicName": arg("TopicName")}]}}]),
        "LambdaInvokePolicy" => json!([{"Effect": "Allow", "Action": ["lambda:InvokeFunction"],
            "Resource": {"Fn::Sub": ["arn:${AWS::Partition}:lambda:${AWS::Region}:${AWS::AccountId}:function:${functionName}*",
                {"functionName": arg("FunctionName")}]}}]),
        "SSMParameterReadPolicy" => {
            json!([{"Effect": "Allow", "Action": ["ssm:DescribeParameters", "ssm:GetParameters",
            "ssm:GetParameter", "ssm:GetParametersByPath"],
            "Resource": {"Fn::Sub": ["arn:${AWS::Partition}:ssm:${AWS::Region}:${AWS::AccountId}:parameter/${parameterName}",
                {"parameterName": arg("ParameterName")}]}}])
        }
        "AWSSecretsManagerGetSecretValuePolicy" => json!([{"Effect": "Allow",
            "Action": ["secretsmanager:GetSecretValue"], "Resource": arg("SecretArn")}]),
        "KMSDecryptPolicy" => json!([{"Effect": "Allow", "Action": "kms:Decrypt",
            "Resource": {"Fn::Sub": ["arn:${AWS::Partition}:kms:${AWS::Region}:${AWS::AccountId}:key/${keyId}",
                {"keyId": arg("KeyId")}]}}]),
        other => return Err(invalid(id, format!("Policy template '{other}' is not supported by MWS."))),
    })
}

/// Shallow-merge `Globals.Function` under a function's properties (maps
/// such as `Environment.Variables` and `Tags` merge one level down, as
/// SAM does).
fn with_globals(props: &mut Map<String, Value>, globals: Option<&Map<String, Value>>) {
    let Some(g) = globals else { return };
    for (k, v) in g {
        match (props.get_mut(k), v) {
            (None, _) => {
                props.insert(k.clone(), v.clone());
            }
            (Some(Value::Object(mine)), Value::Object(theirs)) => {
                for (gk, gv) in theirs {
                    match (mine.get_mut(gk), gv) {
                        (None, _) => {
                            mine.insert(gk.clone(), gv.clone());
                        }
                        (Some(Value::Object(m2)), Value::Object(t2)) => {
                            for (k3, v3) in t2 {
                                m2.entry(k3.clone()).or_insert_with(|| v3.clone());
                            }
                        }
                        _ => {}
                    }
                }
            }
            (Some(Value::Array(mine)), Value::Array(theirs)) if k == "Layers" || k == "Policies" => {
                let mut all = theirs.clone();
                all.append(mine);
                *mine = all;
            }
            _ => {}
        }
    }
}

const FUNCTION_KEYS: &[&str] = &[
    "Architectures",
    "DeadLetterConfig",
    "Description",
    "Environment",
    "EphemeralStorage",
    "FileSystemConfigs",
    "FunctionName",
    "Handler",
    "ImageConfig",
    "KmsKeyArn",
    "Layers",
    "LoggingConfig",
    "MemorySize",
    "PackageType",
    "ReservedConcurrentExecutions",
    "Runtime",
    "SnapStart",
    "Timeout",
    "TracingConfig",
    "VpcConfig",
];

struct Out {
    resources: Map<String, Value>,
}

impl Out {
    fn add(&mut self, id: String, ty: &str, props: Value, extra: Option<(&str, Value)>) {
        let mut r = json!({"Type": ty, "Properties": props});
        if let Some((k, v)) = extra {
            r[k] = v;
        }
        self.resources.insert(id, r);
    }
}

fn function(
    id: &str,
    def: &Map<String, Value>,
    globals: Option<&Map<String, Value>>,
    out: &mut Out,
    buckets: &mut Vec<(String, Value)>,
) -> Result<(), String> {
    let mut props = def.get("Properties").and_then(Value::as_object).cloned().unwrap_or_default();
    with_globals(&mut props, globals);
    let mut f = Map::new();
    for k in FUNCTION_KEYS {
        if let Some(v) = props.get(*k) {
            f.insert((*k).to_string(), v.clone());
        }
    }
    if let Some(t) = props.get("Tracing") {
        f.insert("TracingConfig".into(), json!({"Mode": t}));
    }
    if let Some(dlq) = props.get("DeadLetterQueue") {
        f.insert("DeadLetterConfig".into(), json!({"TargetArn": dlq.get("TargetArn").cloned().unwrap_or_default()}));
    }
    match (props.get("InlineCode"), props.get("CodeUri"), props.get("ImageUri")) {
        (Some(code), _, _) => {
            f.insert("Code".into(), json!({"ZipFile": code}));
        }
        (None, Some(uri), _) => {
            f.insert("Code".into(), s3_location(id, uri, "S3Bucket", "S3Key", "S3ObjectVersion")?);
        }
        (None, None, Some(image)) => {
            f.insert("Code".into(), json!({"ImageUri": image}));
            f.insert("PackageType".into(), json!("Image"));
        }
        _ => return Err(invalid(id, "Either 'InlineCode' or 'CodeUri' must be set.")),
    }
    f.insert("Tags".into(), tag_list(props.get("Tags")));
    let events = props.get("Events").and_then(Value::as_object).cloned().unwrap_or_default();
    let role_id = format!("{id}Role");
    let own_role = props.get("Role").is_none();
    let mut managed = vec![sub("arn:${AWS::Partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")];
    let mut inline: Vec<Value> = Vec::new();
    match props.get("Role") {
        Some(r) => {
            f.insert("Role".into(), r.clone());
        }
        None => {
            f.insert("Role".into(), json!({"Fn::GetAtt": [role_id, "Arn"]}));
        }
    }
    let policies = match props.get("Policies") {
        None => Vec::new(),
        Some(Value::Array(a)) => a.clone(),
        Some(other) => vec![other.clone()],
    };
    for (i, p) in policies.iter().enumerate() {
        match p {
            Value::String(s) if s.starts_with("arn:") => managed.push(p.clone()),
            Value::String(s) => managed.push(sub(&format!("arn:${{AWS::Partition}}:iam::aws:policy/{s}"))),
            Value::Object(o) if o.contains_key("Statement") => inline.push(json!({
                "PolicyName": format!("{role_id}Policy{i}"),
                "PolicyDocument": p,
            })),
            Value::Object(o) if o.len() == 1 => {
                let (name, args) = o.iter().next().expect("one entry");
                inline.push(json!({
                    "PolicyName": format!("{role_id}Policy{i}"),
                    "PolicyDocument": {"Version": "2012-10-17", "Statement": policy_template(id, name, args)?},
                }));
            }
            Value::Object(_) => managed.push(p.clone()),
            _ => return Err(invalid(id, "Policies must be a policy name, ARN, document or policy template.")),
        }
    }
    let fn_arn = json!({"Fn::GetAtt": [id, "Arn"]});
    for (event_id, e) in &events {
        let ty = e.get("Type").and_then(Value::as_str).unwrap_or_default();
        let ep = e.get("Properties").and_then(Value::as_object).cloned().unwrap_or_default();
        let logical = format!("{id}{event_id}");
        let permission = |principal: &str, source: Option<Value>, account: bool| {
            let mut p = json!({"Action": "lambda:InvokeFunction", "FunctionName": {"Ref": id}, "Principal": principal});
            if let Some(s) = source {
                p["SourceArn"] = s;
            }
            if account {
                p["SourceAccount"] = json!({"Ref": "AWS::AccountId"});
            }
            p
        };
        match ty {
            "SQS" | "Kinesis" | "DynamoDB" => {
                let source = match ty {
                    "SQS" => ep.get("Queue"),
                    _ => ep.get("Stream"),
                }
                .cloned()
                .ok_or_else(|| invalid(&logical, format!("Event of type {ty} requires its source.")))?;
                let mut m = json!({"FunctionName": {"Ref": id}, "EventSourceArn": source});
                for k in [
                    "BatchSize",
                    "Enabled",
                    "StartingPosition",
                    "MaximumBatchingWindowInSeconds",
                    "FilterCriteria",
                    "FunctionResponseTypes",
                    "ScalingConfig",
                    "BisectBatchOnFunctionError",
                    "MaximumRetryAttempts",
                    "ParallelizationFactor",
                ] {
                    if let Some(v) = ep.get(k) {
                        m[k] = v.clone();
                    }
                }
                managed.push(sub(match ty {
                    "SQS" => "arn:${AWS::Partition}:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole",
                    "Kinesis" => "arn:${AWS::Partition}:iam::aws:policy/service-role/AWSLambdaKinesisExecutionRole",
                    _ => "arn:${AWS::Partition}:iam::aws:policy/service-role/AWSLambdaDynamoDBExecutionRole",
                }));
                out.add(logical, "AWS::Lambda::EventSourceMapping", m, None);
            }
            "SNS" => {
                let topic =
                    ep.get("Topic").cloned().ok_or_else(|| invalid(&logical, "Event of type SNS requires Topic."))?;
                let mut s = json!({"Protocol": "lambda", "Endpoint": fn_arn.clone(), "TopicArn": topic.clone()});
                if let Some(fp) = ep.get("FilterPolicy") {
                    s["FilterPolicy"] = fp.clone();
                }
                out.add(logical.clone(), "AWS::SNS::Subscription", s, None);
                out.add(
                    format!("{logical}Permission"),
                    "AWS::Lambda::Permission",
                    permission("sns.amazonaws.com", Some(topic), false),
                    None,
                );
            }
            "Schedule" | "EventBridgeRule" | "CloudWatchEvent" | "ScheduleV1" => {
                let mut rule = Map::new();
                if ty == "Schedule" || ty == "ScheduleV1" {
                    let expr = ep
                        .get("Schedule")
                        .cloned()
                        .ok_or_else(|| invalid(&logical, "Event of type Schedule requires Schedule."))?;
                    rule.insert("ScheduleExpression".into(), expr);
                } else {
                    let pattern = ep
                        .get("Pattern")
                        .cloned()
                        .ok_or_else(|| invalid(&logical, format!("Event of type {ty} requires Pattern.")))?;
                    rule.insert("EventPattern".into(), pattern);
                    if let Some(b) = ep.get("EventBusName") {
                        rule.insert("EventBusName".into(), b.clone());
                    }
                }
                let enabled = match (ep.get("Enabled"), ep.get("State")) {
                    (_, Some(s)) => s.clone(),
                    (Some(Value::Bool(false)), None) => json!("DISABLED"),
                    _ => json!("ENABLED"),
                };
                rule.insert("State".into(), enabled);
                for k in ["Name", "Description"] {
                    if let Some(v) = ep.get(k) {
                        rule.insert(k.into(), v.clone());
                    }
                }
                let mut target = json!({"Arn": fn_arn.clone(), "Id": format!("{logical}LambdaTarget")});
                for k in ["Input", "InputPath"] {
                    if let Some(v) = ep.get(k) {
                        target[k] = v.clone();
                    }
                }
                rule.insert("Targets".into(), json!([target]));
                out.add(logical.clone(), "AWS::Events::Rule", Value::Object(rule), None);
                out.add(
                    format!("{logical}Permission"),
                    "AWS::Lambda::Permission",
                    permission("events.amazonaws.com", Some(json!({"Fn::GetAtt": [logical, "Arn"]})), false),
                    None,
                );
            }
            "S3" => {
                let bucket = ep.get("Bucket").and_then(|b| b.get("Ref")).and_then(Value::as_str).ok_or_else(|| {
                    invalid(
                        &logical,
                        "Event with id [S3] is invalid. S3 events must reference an S3 bucket in the same template.",
                    )
                })?;
                let events = match ep.get("Events") {
                    Some(Value::Array(a)) => a.clone(),
                    Some(v) => vec![v.clone()],
                    None => return Err(invalid(&logical, "Event of type S3 requires Events.")),
                };
                let perm = format!("{logical}Permission");
                out.add(perm.clone(), "AWS::Lambda::Permission", permission("s3.amazonaws.com", None, true), None);
                for ev in events {
                    let mut c = json!({"Event": ev, "Function": fn_arn.clone()});
                    if let Some(filter) = ep.get("Filter") {
                        c["Filter"] = filter.clone();
                    }
                    buckets.push((bucket.to_string(), json!({"config": c, "depends": perm})));
                }
            }
            other => {
                return Err(invalid(
                    &logical,
                    format!("Event type {other} is not supported by MWS (it needs a service MWS does not deploy)."),
                ))
            }
        }
    }
    if own_role {
        let mut role = json!({
            "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{"Effect": "Allow",
                "Principal": {"Service": ["lambda.amazonaws.com"]}, "Action": ["sts:AssumeRole"]}]},
            "ManagedPolicyArns": managed,
            "Tags": tag_list(props.get("Tags")),
        });
        if !inline.is_empty() {
            role["Policies"] = Value::Array(inline);
        }
        if let Some(b) = props.get("PermissionsBoundary") {
            role["PermissionsBoundary"] = b.clone();
        }
        out.add(role_id, "AWS::IAM::Role", role, None);
    }
    let mut extra = None;
    if let Some(d) = def.get("DependsOn") {
        extra = Some(("DependsOn", d.clone()));
    }
    out.add(id.to_string(), "AWS::Lambda::Function", Value::Object(f), extra);
    let mut copied = Map::new();
    for k in ["Condition", "DeletionPolicy", "UpdateReplacePolicy", "Metadata"] {
        if let Some(v) = def.get(k) {
            copied.insert(k.into(), v.clone());
        }
    }
    if let Some(Value::Object(r)) = out.resources.get_mut(id) {
        r.extend(copied);
    }
    Ok(())
}

/// Expand the SAM resource types in `root`.
pub(crate) fn expand(root: &mut Value) -> Result<(), String> {
    let Value::Object(top) = root else { return Ok(()) };
    let globals = top.remove("Globals");
    let function_globals = globals.as_ref().and_then(|g| g.get("Function")).and_then(Value::as_object).cloned();
    let resources = top.get("Resources").and_then(Value::as_object).cloned().unwrap_or_default();
    let mut out = Out { resources: Map::new() };
    let mut buckets: Vec<(String, Value)> = Vec::new();
    for (id, r) in &resources {
        let Some(def) = r.as_object() else {
            out.resources.insert(id.clone(), r.clone());
            continue;
        };
        let ty = def.get("Type").and_then(Value::as_str).unwrap_or_default();
        let props = def.get("Properties").and_then(Value::as_object).cloned().unwrap_or_default();
        match ty {
            "AWS::Serverless::Function" => function(id, def, function_globals.as_ref(), &mut out, &mut buckets)?,
            "AWS::Serverless::LayerVersion" => {
                let mut l = Map::new();
                for (from, to) in [
                    ("LayerName", "LayerName"),
                    ("Description", "Description"),
                    ("CompatibleRuntimes", "CompatibleRuntimes"),
                    ("CompatibleArchitectures", "CompatibleArchitectures"),
                    ("LicenseInfo", "LicenseInfo"),
                ] {
                    if let Some(v) = props.get(from) {
                        l.insert(to.into(), v.clone());
                    }
                }
                let uri =
                    props.get("ContentUri").ok_or_else(|| invalid(id, "Missing required property 'ContentUri'."))?;
                l.insert("Content".into(), s3_location(id, uri, "S3Bucket", "S3Key", "S3ObjectVersion")?);
                let mut r = json!({"Type": "AWS::Lambda::LayerVersion", "Properties": l,
                    "DeletionPolicy": props.get("RetentionPolicy").and_then(Value::as_str).unwrap_or("Retain")});
                if let Some(c) = def.get("Condition") {
                    r["Condition"] = c.clone();
                }
                out.resources.insert(id.clone(), r);
            }
            "AWS::Serverless::Application" => {
                let location = match props.get("Location") {
                    Some(Value::String(s)) => json!(s),
                    _ => {
                        return Err(invalid(
                            id,
                            "MWS deploys applications from a template URL only, not from the Serverless Application Repository.",
                        ))
                    }
                };
                let mut s = json!({"TemplateURL": location});
                for k in ["Parameters", "NotificationARNs", "TimeoutInMinutes"] {
                    if let Some(v) = props.get(k) {
                        s[k] = v.clone();
                    }
                }
                s["Tags"] = tag_list(props.get("Tags"));
                out.resources.insert(id.clone(), json!({"Type": "AWS::CloudFormation::Stack", "Properties": s}));
            }
            t if t.starts_with("AWS::Serverless::") => {
                return Err(invalid(id, format!("Resource type {t} is not supported by MWS.")));
            }
            _ => {
                out.resources.insert(id.clone(), r.clone());
            }
        }
    }
    // S3 events add notification configurations to their buckets.
    for (bucket, entry) in buckets {
        let Some(Value::Object(b)) = out.resources.get_mut(&bucket) else {
            return Err(invalid(&bucket, "S3 events must reference an S3 bucket in the same template."));
        };
        let props = b.entry("Properties").or_insert_with(|| json!({}));
        let n = props
            .as_object_mut()
            .ok_or_else(|| invalid(&bucket, "Properties must be an object."))?
            .entry("NotificationConfiguration")
            .or_insert_with(|| json!({}));
        let list = n
            .as_object_mut()
            .ok_or_else(|| invalid(&bucket, "NotificationConfiguration must be an object."))?
            .entry("LambdaConfigurations")
            .or_insert_with(|| json!([]));
        if let Value::Array(a) = list {
            a.push(entry["config"].clone());
        }
        let dep = entry["depends"].clone();
        match b.get_mut("DependsOn") {
            Some(Value::Array(a)) => a.push(dep),
            Some(other) => *other = json!([other.clone(), dep]),
            None => {
                b.insert("DependsOn".into(), json!([dep]));
            }
        }
    }
    top.insert("Resources".into(), Value::Object(out.resources));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn functions_get_roles_and_event_sources() {
        let mut t = json!({
            "Globals": {"Function": {"Runtime": "python3.12", "Environment": {"Variables": {"A": "1"}}}},
            "Resources": {"Fn": {"Type": "AWS::Serverless::Function", "Properties": {
                "Handler": "index.handler", "InlineCode": "x",
                "Environment": {"Variables": {"B": "2"}},
                "Policies": ["AmazonSQSFullAccess", {"SQSSendMessagePolicy": {"QueueName": "q"}}],
                "Events": {"Jobs": {"Type": "SQS", "Properties": {"Queue": "arn:aws:sqs:us-east-1:1:q", "BatchSize": 5}},
                           "Tick": {"Type": "Schedule", "Properties": {"Schedule": "rate(1 minute)"}}}}}}
        });
        expand(&mut t).unwrap();
        let r = &t["Resources"];
        assert_eq!(r["Fn"]["Type"], "AWS::Lambda::Function");
        assert_eq!(r["Fn"]["Properties"]["Runtime"], "python3.12");
        assert_eq!(r["Fn"]["Properties"]["Environment"]["Variables"], json!({"B": "2", "A": "1"}));
        assert_eq!(r["FnRole"]["Type"], "AWS::IAM::Role");
        assert_eq!(r["FnJobs"]["Type"], "AWS::Lambda::EventSourceMapping");
        assert_eq!(r["FnTick"]["Type"], "AWS::Events::Rule");
        assert_eq!(r["FnTickPermission"]["Type"], "AWS::Lambda::Permission");
        assert!(t.get("Globals").is_none());
    }
}

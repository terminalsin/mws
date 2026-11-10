//! Turning an API call into a CloudTrail record, the way AWS writes them.

use chrono::{DateTime, SecondsFormat, Utc};
use mws_core::trail::{ApiCall, HttpFacts};
use mws_core::{Caller, CallerKind, RequestContext};
use serde_json::{json, Map, Value};

/// The `eventVersion` MWS writes.
pub const EVENT_VERSION: &str = "1.11";

/// A recorded event and what delivery needs to know about it.
#[derive(Debug, Clone)]
pub struct Recorded {
    pub record: Value,
    /// The account the event belongs to (`recipientAccountId`).
    pub account: String,
    pub region: String,
    pub event_id: String,
    pub event_name: String,
    pub event_source: String,
    pub time: DateTime<Utc>,
    pub read_only: bool,
    pub management: bool,
    /// From a global service (IAM, STS's global endpoint, Route 53, ...).
    pub global: bool,
    /// `(type, ARN or name)` of the resources involved.
    pub resources: Vec<(String, String)>,
    pub access_key_id: Option<String>,
    pub username: Option<String>,
}

pub fn time_string(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Services whose events AWS logs as global (in us-east-1).
fn is_global(source: &str, region: &str) -> bool {
    matches!(
        source,
        "iam.amazonaws.com"
            | "route53.amazonaws.com"
            | "organizations.amazonaws.com"
            | "cloudfront.amazonaws.com"
            | "globalaccelerator.amazonaws.com"
            | "route53domains.amazonaws.com"
    ) || (source == "sts.amazonaws.com" && region == "us-east-1")
}

/// Whether an operation is a data event (object- or record-level),
/// which trails log only when their selectors ask for it.
pub fn data_event_type(source: &str, operation: &str) -> Option<&'static str> {
    match source {
        "s3.amazonaws.com" => {
            let object_level = operation.contains("Object")
                && !matches!(operation, "ListObjectLockConfiguration" | "PutObjectLockConfiguration")
                || operation.contains("MultipartUpload")
                || matches!(operation, "UploadPart" | "UploadPartCopy" | "ListParts" | "WriteGetObjectResponse");
            let object_level = object_level && !matches!(operation, "GetObjectLockConfiguration");
            object_level.then_some("AWS::S3::Object")
        }
        "s3express.amazonaws.com" => Some("AWS::S3Express::Object"),
        "lambda.amazonaws.com" => matches!(operation, "Invoke" | "InvokeAsync" | "InvokeWithResponseStream")
            .then_some("AWS::Lambda::Function"),
        "sqs.amazonaws.com" => matches!(
            operation,
            "SendMessage"
                | "SendMessageBatch"
                | "ReceiveMessage"
                | "DeleteMessage"
                | "DeleteMessageBatch"
                | "ChangeMessageVisibility"
                | "ChangeMessageVisibilityBatch"
        )
        .then_some("AWS::SQS::Queue"),
        "sns.amazonaws.com" => matches!(operation, "Publish" | "PublishBatch").then_some("AWS::SNS::Topic"),
        "kinesis.amazonaws.com" => {
            matches!(operation, "PutRecord" | "PutRecords" | "GetRecords" | "GetShardIterator" | "SubscribeToShard")
                .then_some("AWS::Kinesis::Stream")
        }
        "firehose.amazonaws.com" => {
            matches!(operation, "PutRecord" | "PutRecordBatch").then_some("AWS::KinesisFirehose::DeliveryStream")
        }
        "events.amazonaws.com" => (operation == "PutEvents").then_some("AWS::Events::EventBus"),
        "logs.amazonaws.com" => {
            matches!(operation, "PutLogEvents" | "GetLogEvents" | "FilterLogEvents" | "StartLiveTail" | "GetLogRecord")
                .then_some("AWS::Logs::LogStream")
        }
        "monitoring.amazonaws.com" => {
            matches!(operation, "PutMetricData" | "GetMetricData" | "GetMetricStatistics" | "ListMetrics")
                .then_some("AWS::CloudWatch::Metric")
        }
        _ => None,
    }
}

/// Read-only as CloudTrail reports it: the model's `@readonly`, or by the
/// operation's verb for models that do not mark it, plus the STS calls
/// CloudTrail counts as reads.
fn read_only(call: &ApiCall) -> bool {
    if call.read_only {
        return true;
    }
    if call.event_source == "sts.amazonaws.com" {
        return call.operation.starts_with("Assume")
            || matches!(call.operation, "GetCallerIdentity" | "GetSessionToken" | "GetFederationToken");
    }
    ["Get", "List", "Describe", "Head", "Lookup", "Search", "BatchGet", "Select"].iter().any(|p| {
        call.operation.starts_with(p) && call.operation[p.len()..].starts_with(|c: char| c.is_ascii_uppercase())
    })
}

pub fn user_identity(caller: &Caller, partition: &str) -> Value {
    let mut m = Map::new();
    let account = &caller.account_id;
    let session_attributes = || {
        let s = caller.session.as_ref();
        json!({
            "creationDate": s.map(|s| time_string(s.issued_at)),
            "mfaAuthenticated": s.is_some_and(|s| s.mfa_authenticated).to_string(),
        })
    };
    match &caller.kind {
        CallerKind::Root => {
            m.insert("type".into(), "Root".into());
            m.insert("principalId".into(), account.clone().into());
            m.insert("arn".into(), caller.arn.clone().into());
            m.insert("accountId".into(), account.clone().into());
            m.insert("accessKeyId".into(), caller.access_key_id.clone().into());
            if caller.session.is_some() {
                m.insert("sessionContext".into(), json!({ "attributes": session_attributes() }));
            }
        }
        CallerKind::User { name } => {
            m.insert("type".into(), "IAMUser".into());
            m.insert("principalId".into(), caller.user_id.clone().into());
            m.insert("arn".into(), caller.arn.clone().into());
            m.insert("accountId".into(), account.clone().into());
            m.insert("accessKeyId".into(), caller.access_key_id.clone().into());
            m.insert("userName".into(), name.clone().into());
            if caller.session.is_some() {
                m.insert("sessionContext".into(), json!({ "attributes": session_attributes() }));
            }
        }
        CallerKind::AssumedRole { role_name, .. } => {
            let role_id = caller.user_id.split(':').next().unwrap_or_default();
            m.insert("type".into(), "AssumedRole".into());
            m.insert("principalId".into(), caller.user_id.clone().into());
            m.insert("arn".into(), caller.arn.clone().into());
            m.insert("accountId".into(), account.clone().into());
            m.insert("accessKeyId".into(), caller.access_key_id.clone().into());
            let mut context = json!({
                "sessionIssuer": {
                    "type": "Role",
                    "principalId": role_id,
                    "arn": format!("arn:{partition}:iam::{account}:role/{role_name}"),
                    "accountId": account,
                    "userName": role_name,
                },
                "attributes": session_attributes(),
            });
            if let Some(si) = caller.session.as_ref().and_then(|s| s.source_identity.clone()) {
                context["sourceIdentity"] = si.into();
            }
            m.insert("sessionContext".into(), context);
        }
        CallerKind::FederatedUser { parent_user, .. } => {
            m.insert("type".into(), "FederatedUser".into());
            m.insert("principalId".into(), caller.user_id.clone().into());
            m.insert("arn".into(), caller.arn.clone().into());
            m.insert("accountId".into(), account.clone().into());
            m.insert("accessKeyId".into(), caller.access_key_id.clone().into());
            let issuer = match parent_user {
                Some(u) => json!({
                    "type": "IAMUser",
                    "arn": format!("arn:{partition}:iam::{account}:user/{u}"),
                    "accountId": account,
                    "userName": u,
                }),
                None => json!({
                    "type": "Root",
                    "principalId": account,
                    "arn": format!("arn:{partition}:iam::{account}:root"),
                    "accountId": account,
                }),
            };
            m.insert("sessionContext".into(), json!({ "sessionIssuer": issuer, "attributes": session_attributes() }));
        }
        CallerKind::Anonymous => {
            m.insert("type".into(), "Unknown".into());
            m.insert("principalId".into(), "".into());
        }
        CallerKind::Service { principal, .. } => {
            m.insert("type".into(), "AWSService".into());
            m.insert("invokedBy".into(), principal.clone().into());
        }
    }
    Value::Object(m)
}

/// The name `LookupEvents` reports and filters on as `Username`.
fn username(caller: &Caller) -> Option<String> {
    match &caller.kind {
        CallerKind::Root => Some("root".into()),
        CallerKind::User { name } => Some(name.clone()),
        CallerKind::AssumedRole { session_name, .. } => Some(session_name.clone()),
        CallerKind::FederatedUser { name, .. } => Some(name.clone()),
        CallerKind::Anonymous => None,
        CallerKind::Service { principal, .. } => Some(principal.clone()),
    }
}

fn param<'a>(params: &'a Option<Value>, key: &str) -> Option<&'a str> {
    params.as_ref()?.get(key)?.as_str()
}

/// The resources an event touched, as `(type, ARN or name)`, from its
/// parameters.
fn resources(
    call: &ApiCall,
    params: &Option<Value>,
    partition: &str,
    region: &str,
    account: &str,
) -> Vec<(String, String)> {
    let p = |k: &str| param(params, k).map(str::to_string);
    let mut out = Vec::new();
    let mut push = |t: &str, v: Option<String>| {
        if let Some(v) = v.filter(|v| !v.is_empty()) {
            out.push((t.to_string(), v));
        }
    };
    match call.event_source {
        "s3.amazonaws.com" => {
            let bucket = p("bucketName");
            if let (Some(b), Some(k)) = (&bucket, p("key")) {
                push("AWS::S3::Object", Some(format!("arn:{partition}:s3:::{b}/{k}")));
            }
            push("AWS::S3::Bucket", bucket.map(|b| format!("arn:{partition}:s3:::{b}")));
        }
        "iam.amazonaws.com" => {
            push("AWS::IAM::User", p("userName"));
            push("AWS::IAM::Role", p("roleName"));
            push("AWS::IAM::Group", p("groupName"));
            push("AWS::IAM::Policy", p("policyArn"));
            push("AWS::IAM::InstanceProfile", p("instanceProfileName"));
            push("AWS::IAM::AccessKey", p("accessKeyId"));
        }
        "sts.amazonaws.com" => push("AWS::IAM::Role", p("roleArn")),
        "kms.amazonaws.com" => {
            let key = p("keyId");
            push(
                "AWS::KMS::Key",
                key.map(|k| {
                    if k.starts_with("arn:") || k.starts_with("alias/") {
                        k
                    } else {
                        format!("arn:{partition}:kms:{region}:{account}:key/{k}")
                    }
                }),
            );
        }
        "lambda.amazonaws.com" => push(
            "AWS::Lambda::Function",
            p("functionName").map(|f| {
                if f.starts_with("arn:") {
                    f
                } else {
                    format!("arn:{partition}:lambda:{region}:{account}:function:{f}")
                }
            }),
        ),
        "sqs.amazonaws.com" => push(
            "AWS::SQS::Queue",
            p("queueUrl").map(|u| {
                let name = u.rsplit('/').next().unwrap_or_default();
                format!("arn:{partition}:sqs:{region}:{account}:{name}")
            }),
        ),
        "sns.amazonaws.com" => push("AWS::SNS::Topic", p("topicArn").or_else(|| p("targetArn"))),
        "kinesis.amazonaws.com" => {
            push("AWS::Kinesis::Stream", p("streamARN").or_else(|| p("streamName")));
        }
        "logs.amazonaws.com" => push("AWS::Logs::LogGroup", p("logGroupName").or_else(|| p("logGroupIdentifier"))),
        "secretsmanager.amazonaws.com" => push("AWS::SecretsManager::Secret", p("secretId").or_else(|| p("name"))),
        "ssm.amazonaws.com" => push("AWS::SSM::Parameter", p("name")),
        "events.amazonaws.com" => push("AWS::Events::Rule", p("rule").or_else(|| p("name"))),
        "cloudtrail.amazonaws.com" => {
            push("AWS::CloudTrail::Trail", p("name").or_else(|| p("trailName")));
            push("AWS::CloudTrail::EventDataStore", p("eventDataStore"));
        }
        "ec2.amazonaws.com" => {
            for (k, t) in [
                ("instanceId", "AWS::EC2::Instance"),
                ("vpcId", "AWS::EC2::VPC"),
                ("subnetId", "AWS::EC2::Subnet"),
                ("groupId", "AWS::EC2::SecurityGroup"),
                ("volumeId", "AWS::EC2::Volume"),
            ] {
                push(t, p(k));
            }
            if let Some(ids) = params.as_ref().and_then(|v| v.get("instanceIds")).and_then(Value::as_array) {
                for id in ids.iter().filter_map(Value::as_str) {
                    push("AWS::EC2::Instance", Some(id.to_string()));
                }
            }
        }
        "route53.amazonaws.com" => push("AWS::Route53::HostedZone", p("hostedZoneId").or_else(|| p("id"))),
        "acm.amazonaws.com" => push("AWS::ACM::Certificate", p("certificateArn")),
        "acm-pca.amazonaws.com" => push("AWS::ACMPCA::CertificateAuthority", p("certificateAuthorityArn")),
        "monitoring.amazonaws.com" => push("AWS::CloudWatch::Alarm", p("alarmName")),
        "firehose.amazonaws.com" => push("AWS::KinesisFirehose::DeliveryStream", p("deliveryStreamName")),
        _ => {}
    }
    out
}

/// S3 names its bucket parameter `bucketName` and adds the `Host`.
fn s3_parameters(params: Option<Value>, host: Option<&str>) -> Option<Value> {
    let mut m = match params {
        Some(Value::Object(m)) => m,
        other => return other,
    };
    if let Some(b) = m.remove("bucket") {
        m.insert("bucketName".into(), b);
    }
    if let Some(h) = host {
        m.insert("Host".into(), h.into());
    }
    let mut out = Map::new();
    for k in ["bucketName", "Host", "key"] {
        if let Some(v) = m.remove(k) {
            out.insert(k.into(), v);
        }
    }
    out.extend(m);
    Some(Value::Object(out))
}

/// Build the record for a call.
pub fn build(ctx: &RequestContext, call: &ApiCall, http: &HttpFacts) -> Option<Recorded> {
    let partition = &ctx.partition;
    let source = call.event_source;
    let mut params = call.request_parameters.clone();
    if source == "s3.amazonaws.com" {
        params = s3_parameters(params, http.host.as_deref());
    }
    let mut account = ctx.caller.account_id.clone();
    if account.is_empty() {
        // An unsigned call (AssumeRoleWithWebIdentity): it belongs to the
        // account of the role.
        account = param(&params, "roleArn").and_then(|a| a.split(':').nth(4)).unwrap_or_default().to_string();
    }
    if account.is_empty() {
        return None;
    }
    let region = ctx.region.clone();
    let global = is_global(source, &region);
    let data_type = data_event_type(source, call.operation);
    let read_only = read_only(call);
    let resources = resources(call, &params, partition, &region, &account);
    let event_id = uuid::Uuid::new_v4().to_string();
    let time = ctx.received_at;
    let mut r = Map::new();
    r.insert("eventVersion".into(), EVENT_VERSION.into());
    r.insert("userIdentity".into(), user_identity(&ctx.caller, partition));
    r.insert("eventTime".into(), time_string(time).into());
    r.insert("eventSource".into(), source.into());
    r.insert("eventName".into(), call.operation.into());
    r.insert("awsRegion".into(), region.clone().into());
    // Calls an AWS service makes as itself come from the service.
    let source_ip = match (&ctx.source_ip, ctx.caller.service_principal()) {
        (Some(ip), _) => ip.clone(),
        (None, Some(principal)) => principal.to_string(),
        (None, None) => "AWS Internal".to_string(),
    };
    r.insert("sourceIPAddress".into(), source_ip.into());
    r.insert("userAgent".into(), http.user_agent.clone().unwrap_or_default().into());
    if let Some((code, message)) = &call.error {
        r.insert("errorCode".into(), code.clone().into());
        r.insert("errorMessage".into(), message.clone().into());
    }
    r.insert("requestParameters".into(), params.unwrap_or(Value::Null));
    r.insert("responseElements".into(), call.response_elements.clone().unwrap_or(Value::Null));
    r.insert("requestID".into(), ctx.request_id.clone().into());
    r.insert("eventID".into(), event_id.clone().into());
    r.insert("readOnly".into(), read_only.into());
    let arn_resources: Vec<Value> = resources
        .iter()
        .filter(|(_, v)| v.starts_with("arn:"))
        .map(|(t, arn)| json!({ "accountId": account, "type": t, "ARN": arn }))
        .collect();
    if !arn_resources.is_empty() || data_type.is_some() {
        r.insert("resources".into(), Value::Array(arn_resources));
    }
    r.insert("eventType".into(), "AwsApiCall".into());
    r.insert("managementEvent".into(), data_type.is_none().into());
    r.insert("recipientAccountId".into(), account.clone().into());
    r.insert("eventCategory".into(), if data_type.is_some() { "Data" } else { "Management" }.into());
    Some(Recorded {
        record: Value::Object(r),
        account,
        region,
        event_id,
        event_name: call.operation.to_string(),
        event_source: source.to_string(),
        time,
        read_only,
        management: data_type.is_none(),
        global,
        resources,
        access_key_id: (!ctx.caller.access_key_id.is_empty()).then(|| ctx.caller.access_key_id.clone()),
        username: username(&ctx.caller),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s3_object_calls_are_data_events() {
        assert_eq!(data_event_type("s3.amazonaws.com", "PutObject"), Some("AWS::S3::Object"));
        assert_eq!(data_event_type("s3.amazonaws.com", "CreateMultipartUpload"), Some("AWS::S3::Object"));
        assert_eq!(data_event_type("s3.amazonaws.com", "CreateBucket"), None);
        assert_eq!(data_event_type("s3.amazonaws.com", "GetObjectLockConfiguration"), None);
        assert_eq!(data_event_type("iam.amazonaws.com", "CreateUser"), None);
    }

    #[test]
    fn verbs_mark_reads() {
        let call = |op: &'static str| ApiCall { event_source: "x.amazonaws.com", operation: op, ..ApiCall::default() };
        assert!(read_only(&call("DescribeTrails")));
        assert!(read_only(&call("GetObject")));
        assert!(!read_only(&call("Getaway")));
        assert!(!read_only(&call("CreateTrail")));
    }
}

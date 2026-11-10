//! Security Hub's security checks against the emulated services: the
//! evidence behind the controls it evaluates (AWS gathers it with AWS
//! Config, which MWS does not emulate), its service-linked role in IAM,
//! and the change trigger that re-runs checks after writes.
//!
//! Evidence is read through each service's own API (`invoke`), as a
//! session of `AWSServiceRoleForSecurityHub`, whose AWS managed policy
//! allows these reads; no caller policy applies.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use mws_core::trail::{ApiCall, HttpFacts};
use mws_core::{ApiCallObserver, RequestContext, Service};
use mws_securityhub::{ControlEvidence, ResourceEvaluation, SecurityHub};
use serde_json::{json, Value};

/// The controls MWS evaluates.
const EVALUATED: &[&str] = &[
    "CloudTrail.1",
    "CloudTrail.2",
    "EC2.2",
    "EC2.19",
    "GuardDuty.1",
    "IAM.1",
    "IAM.2",
    "IAM.4",
    "IAM.6",
    "IAM.9",
    "KMS.4",
    "Lambda.1",
    "RDS.3",
    "S3.1",
    "S3.5",
    "S3.8",
    "SecretsManager.1",
    "SNS.1",
    "SQS.1",
];

/// Ports EC2.19 treats as high risk.
const HIGH_RISK_PORTS: &[i64] = &[
    20, 21, 22, 23, 25, 110, 135, 143, 445, 1433, 1434, 3000, 3306, 3389, 4333, 5000, 5432, 5500, 5601, 8080, 8088,
    8888, 9200, 9300,
];

pub(crate) struct Evidence {
    pub iam: mws_iam::Iam,
    pub s3: mws_s3::S3,
    pub s3control: mws_s3control::S3Control,
    pub kms: mws_kms::Kms,
    pub cloudtrail: mws_cloudtrail::CloudTrail,
    pub sqs: mws_sqs::Sqs,
    pub sns: mws_sns::Sns,
    pub lambda: mws_lambda::Lambda,
    pub ec2: mws_ec2::Ec2,
    pub rds: mws_rds::Rds,
    pub secretsmanager: mws_secretsmanager::SecretsManager,
    pub guardduty: mws_guardduty::GuardDuty,
}

/// Wire Security Hub's checks, service-linked role and change trigger.
pub(crate) fn wire(securityhub: &SecurityHub, evidence: Evidence) {
    securityhub.set_service_linked_roles(Arc::new(Roles(evidence.iam.clone())));
    securityhub.set_control_evidence(Arc::new(evidence));
}

/// `AWSServiceRoleForSecurityHub`, through IAM.
struct Roles(mws_iam::Iam);

impl mws_securityhub::ServiceLinkedRoles for Roles {
    fn exists(&self, partition: &str, account: &str) -> bool {
        let arn = format!(
            "arn:{partition}:iam::{account}:role/aws-service-role/securityhub.amazonaws.com/AWSServiceRoleForSecurityHub"
        );
        self.0.role_by_arn(&arn).is_some()
    }

    fn create(&self, account: &str) {
        self.0.ensure_service_linked_role(account, "securityhub.amazonaws.com", "AWSSecurityHubServiceRolePolicy");
    }
}

/// Re-run Security Hub's checks after a successful write to another
/// service, as AWS Config's change-triggered rules do.
pub(crate) struct ChangeTrigger(pub SecurityHub);

impl ApiCallObserver for ChangeTrigger {
    fn observe(&self, ctx: &RequestContext, call: &ApiCall, _http: &HttpFacts) {
        if call.read_only || call.error.is_some() || call.event_source == "securityhub.amazonaws.com" {
            return;
        }
        self.0.note_change(&ctx.caller.account_id);
    }
}

/// Security Hub's service-linked role acting: no caller policy applies.
fn as_role(ctx: &RequestContext) -> RequestContext {
    RequestContext { authorizer: Arc::new(mws_core::AllowAll), ..ctx.clone() }
}

async fn call(
    svc: &dyn Service,
    ctx: &RequestContext,
    op: &str,
    input: Value,
) -> Result<Value, mws_core::ServiceError> {
    svc.invoke(as_role(ctx), op, input).await
}

fn arr<'v>(v: &'v Value, key: &str) -> &'v [Value] {
    v.get(key).and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default()
}

fn s<'v>(v: &'v Value, key: &str) -> &'v str {
    v.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s.eq_ignore_ascii_case("true"),
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0) != 0,
        _ => false,
    }
}

fn one_or_many(v: Option<&Value>) -> Vec<&Value> {
    match v {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(other) => vec![other],
        None => Vec::new(),
    }
}

/// A policy document, URL-encoded (as IAM returns it) or not.
fn parse_policy(doc: &str) -> Option<Value> {
    serde_json::from_str(doc).ok().or_else(|| serde_json::from_str(&percent_decode(doc)).ok())
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn statements(policy: &Value) -> Vec<&Value> {
    one_or_many(policy.get("Statement"))
}

fn has_str(v: Option<&Value>, wanted: &[&str]) -> bool {
    one_or_many(v).iter().any(|x| x.as_str().is_some_and(|s| wanted.iter().any(|w| s.eq_ignore_ascii_case(w))))
}

/// `"*"` or `{"AWS": "*"}`.
fn public_principal(st: &Value) -> bool {
    match st.get("Principal") {
        Some(Value::String(p)) => p == "*",
        Some(Value::Object(m)) => has_str(m.get("AWS"), &["*"]),
        _ => false,
    }
}

/// Whether a statement's condition limits it to an account,
/// organization or source.
fn restricted_by_condition(st: &Value) -> bool {
    const KEYS: &[&str] =
        &["aws:sourceaccount", "aws:sourcearn", "aws:principalorgid", "aws:sourceowner", "aws:principalaccount"];
    st.get("Condition").and_then(Value::as_object).is_some_and(|ops| {
        ops.values().filter_map(Value::as_object).any(|m| m.keys().any(|k| KEYS.contains(&k.to_lowercase().as_str())))
    })
}

fn account_id(ctx: &RequestContext) -> &str {
    &ctx.caller.account_id
}

impl Evidence {
    async fn iam(&self, ctx: &RequestContext, control: &str) -> Option<Vec<ResourceEvaluation>> {
        let iam: &dyn Service = &self.iam;
        let account = account_id(ctx);
        match control {
            "IAM.4" | "IAM.6" | "IAM.9" => {
                let summary = call(iam, ctx, "GetAccountSummary", json!({})).await.ok()?;
                let m = summary.get("SummaryMap").cloned().unwrap_or_default();
                let mfa = truthy(m.get("AccountMFAEnabled"));
                let passed = match control {
                    "IAM.4" => !truthy(m.get("AccountAccessKeysPresent")),
                    "IAM.9" => mfa,
                    _ => {
                        let virt = call(iam, ctx, "ListVirtualMFADevices", json!({"AssignmentStatus": "Assigned"}))
                            .await
                            .ok()?;
                        let root_virtual = arr(&virt, "VirtualMFADevices").iter().any(|d| {
                            s(d, "SerialNumber").ends_with(":mfa/root-account-mfa-device")
                                || d.get("User").is_some_and(|u| s(u, "Arn").ends_with(":root"))
                        });
                        mfa && !root_virtual
                    }
                };
                Some(vec![ResourceEvaluation::account(account, passed)])
            }
            "IAM.1" => {
                let listed = call(iam, ctx, "ListPolicies", json!({"Scope": "Local"})).await.ok()?;
                let mut out = Vec::new();
                for p in arr(&listed, "Policies") {
                    let v = call(
                        iam,
                        ctx,
                        "GetPolicyVersion",
                        json!({"PolicyArn": s(p, "Arn"), "VersionId": s(p, "DefaultVersionId")}),
                    )
                    .await
                    .ok()?;
                    let doc = v.get("PolicyVersion").map(|pv| s(pv, "Document")).and_then(parse_policy);
                    let admin = doc.as_ref().is_some_and(|d| {
                        statements(d).iter().any(|st| {
                            has_str(st.get("Effect"), &["Allow"])
                                && has_str(st.get("Action"), &["*"])
                                && has_str(st.get("Resource"), &["*"])
                        })
                    });
                    out.push(ResourceEvaluation::new("AwsIamPolicy", s(p, "Arn"), !admin));
                }
                Some(out)
            }
            "IAM.2" => {
                let users = call(iam, ctx, "ListUsers", json!({})).await.ok()?;
                let mut out = Vec::new();
                for u in arr(&users, "Users") {
                    let name = s(u, "UserName");
                    let attached = call(iam, ctx, "ListAttachedUserPolicies", json!({"UserName": name})).await.ok()?;
                    let inline = call(iam, ctx, "ListUserPolicies", json!({"UserName": name})).await.ok()?;
                    let none = arr(&attached, "AttachedPolicies").is_empty() && arr(&inline, "PolicyNames").is_empty();
                    out.push(ResourceEvaluation::new("AwsIamUser", s(u, "Arn"), none));
                }
                Some(out)
            }
            _ => None,
        }
    }

    /// The account's general purpose buckets in `ctx`'s Region.
    async fn buckets(&self, ctx: &RequestContext) -> Option<Vec<String>> {
        let s3: &dyn Service = &self.s3;
        let listed = call(s3, ctx, "ListBuckets", json!({})).await.ok()?;
        let mut out = Vec::new();
        for b in arr(&listed, "Buckets") {
            let name = s(b, "Name").to_string();
            let region = match b.get("BucketRegion").and_then(Value::as_str) {
                Some(r) if !r.is_empty() => r.to_string(),
                _ => {
                    let loc = call(s3, ctx, "GetBucketLocation", json!({"Bucket": name})).await.ok()?;
                    match s(&loc, "LocationConstraint") {
                        "" => "us-east-1".to_string(),
                        "EU" => "eu-west-1".to_string(),
                        r => r.to_string(),
                    }
                }
            };
            if region == ctx.region {
                out.push(name);
            }
        }
        Some(out)
    }

    async fn s3(&self, ctx: &RequestContext, control: &str) -> Option<Vec<ResourceEvaluation>> {
        let s3: &dyn Service = &self.s3;
        let account = account_id(ctx);
        let partition = ctx.partition.clone();
        let all_blocked = |v: &Value| {
            v.get("PublicAccessBlockConfiguration").is_some_and(|c| {
                ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
                    .iter()
                    .all(|k| truthy(c.get(*k)))
            })
        };
        match control {
            "S3.1" => {
                let control: &dyn Service = &self.s3control;
                let passed = match call(control, ctx, "GetPublicAccessBlock", json!({"AccountId": account})).await {
                    Ok(v) => all_blocked(&v),
                    Err(e) if e.code == "NoSuchPublicAccessBlockConfiguration" => false,
                    Err(_) => return None,
                };
                Some(vec![ResourceEvaluation::account(account, passed)])
            }
            "S3.8" | "S3.5" => {
                let mut out = Vec::new();
                for b in self.buckets(ctx).await? {
                    let arn = format!("arn:{partition}:s3:::{b}");
                    let passed = if control == "S3.8" {
                        match call(s3, ctx, "GetPublicAccessBlock", json!({"Bucket": b})).await {
                            Ok(v) => all_blocked(&v),
                            Err(e) if e.code == "NoSuchPublicAccessBlockConfiguration" => false,
                            Err(_) => return None,
                        }
                    } else {
                        match call(s3, ctx, "GetBucketPolicy", json!({"Bucket": b})).await {
                            Ok(v) => parse_policy(s(&v, "Policy")).is_some_and(|p| {
                                statements(&p).iter().any(|st| {
                                    has_str(st.get("Effect"), &["Deny"])
                                        && public_principal(st)
                                        && has_str(st.get("Action"), &["s3:*", "*"])
                                        && st
                                            .get("Condition")
                                            .and_then(|c| c.get("Bool"))
                                            .and_then(Value::as_object)
                                            .and_then(|m| {
                                                m.iter()
                                                    .find(|(k, _)| k.eq_ignore_ascii_case("aws:SecureTransport"))
                                                    .map(|(_, v)| v.clone())
                                            })
                                            .is_some_and(|v| !truthy(Some(&v)) && !v.is_null())
                                })
                            }),
                            Err(e) if e.code == "NoSuchBucketPolicy" => false,
                            Err(_) => return None,
                        }
                    };
                    out.push(ResourceEvaluation::new("AwsS3Bucket", arn, passed));
                }
                Some(out)
            }
            _ => None,
        }
    }

    async fn kms(&self, ctx: &RequestContext) -> Option<Vec<ResourceEvaluation>> {
        let kms: &dyn Service = &self.kms;
        let keys = call(kms, ctx, "ListKeys", json!({"Limit": 1000})).await.ok()?;
        let mut out = Vec::new();
        for k in arr(&keys, "Keys") {
            let d = call(kms, ctx, "DescribeKey", json!({"KeyId": s(k, "KeyId")})).await.ok()?;
            let m = d.get("KeyMetadata").cloned().unwrap_or_default();
            // Only customer managed symmetric keys with KMS key material,
            // and not ones pending deletion.
            if s(&m, "KeyManager") != "CUSTOMER"
                || s(&m, "KeySpec") != "SYMMETRIC_DEFAULT"
                || s(&m, "Origin") != "AWS_KMS"
                || s(&m, "KeyState") == "PendingDeletion"
            {
                continue;
            }
            let r = call(kms, ctx, "GetKeyRotationStatus", json!({"KeyId": s(k, "KeyId")})).await.ok()?;
            let on = truthy(r.get("KeyRotationEnabled"));
            out.push(ResourceEvaluation::new("AwsKmsKey", s(&m, "Arn"), on).with_details(json!({
                "AwsKmsKey": {
                    "KeyId": s(&m, "KeyId"),
                    "KeyManager": s(&m, "KeyManager"),
                    "KeyState": s(&m, "KeyState"),
                    "Origin": s(&m, "Origin"),
                    "KeyRotationStatus": on,
                }
            })));
        }
        Some(out)
    }

    async fn cloudtrail(&self, ctx: &RequestContext, control: &str) -> Option<Vec<ResourceEvaluation>> {
        let ct: &dyn Service = &self.cloudtrail;
        let trails = call(ct, ctx, "DescribeTrails", json!({"includeShadowTrails": true})).await.ok()?;
        let trails = arr(&trails, "trailList");
        if control == "CloudTrail.2" {
            return Some(
                trails
                    .iter()
                    .filter(|t| s(t, "HomeRegion").is_empty() || s(t, "HomeRegion") == ctx.region)
                    .map(|t| {
                        ResourceEvaluation::new("AwsCloudTrailTrail", s(t, "TrailARN"), !s(t, "KmsKeyId").is_empty())
                    })
                    .collect(),
            );
        }
        let mut ok = false;
        for t in trails.iter().filter(|t| truthy(t.get("IsMultiRegionTrail"))) {
            let arn = s(t, "TrailARN");
            let status = call(ct, ctx, "GetTrailStatus", json!({"Name": arn})).await.ok()?;
            if !truthy(status.get("IsLogging")) {
                continue;
            }
            let sel = call(ct, ctx, "GetEventSelectors", json!({"TrailName": arn})).await.ok()?;
            let basic = arr(&sel, "EventSelectors");
            let advanced = arr(&sel, "AdvancedEventSelectors");
            let all_management = if !advanced.is_empty() {
                advanced.iter().any(|a| {
                    let fields = arr(a, "FieldSelectors");
                    let management = fields
                        .iter()
                        .any(|f| s(f, "Field") == "eventCategory" && has_str(f.get("Equals"), &["Management"]));
                    let read_only_limited = fields.iter().any(|f| s(f, "Field") == "readOnly");
                    management && !read_only_limited
                })
            } else if basic.is_empty() {
                true
            } else {
                basic.iter().any(|b| {
                    (s(b, "ReadWriteType") == "All" || s(b, "ReadWriteType").is_empty())
                        && b.get("IncludeManagementEvents").is_none_or(|v| truthy(Some(v)))
                })
            };
            if all_management {
                ok = true;
                break;
            }
        }
        Some(vec![ResourceEvaluation::account(account_id(ctx), ok)])
    }

    async fn ec2(&self, ctx: &RequestContext, control: &str) -> Option<Vec<ResourceEvaluation>> {
        let ec2: &dyn Service = &self.ec2;
        let input = if control == "EC2.2" {
            json!({"Filters": [{"Name": "group-name", "Values": ["default"]}]})
        } else {
            json!({})
        };
        let groups = call(ec2, ctx, "DescribeSecurityGroups", input).await.ok()?;
        let mut out = Vec::new();
        for g in arr(&groups, "SecurityGroups") {
            let owner = match s(g, "OwnerId") {
                "" => account_id(ctx),
                o => o,
            };
            let arn = format!("arn:{}:ec2:{}:{owner}:security-group/{}", ctx.partition, ctx.region, s(g, "GroupId"));
            let passed = if control == "EC2.2" {
                if s(g, "GroupName") != "default" {
                    continue;
                }
                arr(g, "IpPermissions").is_empty() && arr(g, "IpPermissionsEgress").is_empty()
            } else {
                !arr(g, "IpPermissions").iter().any(|p| {
                    let open = arr(p, "IpRanges").iter().any(|r| s(r, "CidrIp") == "0.0.0.0/0")
                        || arr(p, "Ipv6Ranges").iter().any(|r| s(r, "CidrIpv6") == "::/0");
                    if !open {
                        return false;
                    }
                    let proto = s(p, "IpProtocol");
                    if proto == "-1" || proto == "all" {
                        return true;
                    }
                    if !matches!(proto, "tcp" | "udp" | "6" | "17") {
                        return false;
                    }
                    let from = p.get("FromPort").and_then(Value::as_i64).unwrap_or(0);
                    let to = p.get("ToPort").and_then(Value::as_i64).unwrap_or(65535);
                    HIGH_RISK_PORTS.iter().any(|port| (from..=to).contains(port))
                })
            };
            out.push(ResourceEvaluation::new("AwsEc2SecurityGroup", arn, passed));
        }
        Some(out)
    }

    async fn simple(
        &self,
        ctx: &RequestContext,
        control: &str,
        params: &BTreeMap<String, Value>,
    ) -> Option<Vec<ResourceEvaluation>> {
        match control {
            "SQS.1" => {
                let sqs: &dyn Service = &self.sqs;
                let queues = call(sqs, ctx, "ListQueues", json!({})).await.ok()?;
                let mut out = Vec::new();
                for url in arr(&queues, "QueueUrls").iter().filter_map(Value::as_str) {
                    let a = call(sqs, ctx, "GetQueueAttributes", json!({"QueueUrl": url, "AttributeNames": ["All"]}))
                        .await
                        .ok()?;
                    let attrs = a.get("Attributes").cloned().unwrap_or_default();
                    let encrypted =
                        truthy(attrs.get("SqsManagedSseEnabled")) || !s(&attrs, "KmsMasterKeyId").is_empty();
                    out.push(ResourceEvaluation::new("AwsSqsQueue", s(&attrs, "QueueArn"), encrypted));
                }
                Some(out)
            }
            "SNS.1" => {
                let sns: &dyn Service = &self.sns;
                let topics = call(sns, ctx, "ListTopics", json!({})).await.ok()?;
                let mut out = Vec::new();
                for t in arr(&topics, "Topics") {
                    let arn = s(t, "TopicArn");
                    let a = call(sns, ctx, "GetTopicAttributes", json!({"TopicArn": arn})).await.ok()?;
                    let key = a.get("Attributes").map(|m| s(m, "KmsMasterKeyId")).unwrap_or_default();
                    out.push(ResourceEvaluation::new("AwsSnsTopic", arn, !key.is_empty()));
                }
                Some(out)
            }
            "Lambda.1" => {
                let lambda: &dyn Service = &self.lambda;
                let fns = call(lambda, ctx, "ListFunctions", json!({})).await.ok()?;
                let mut out = Vec::new();
                for f in arr(&fns, "Functions") {
                    let public =
                        match call(lambda, ctx, "GetPolicy", json!({"FunctionName": s(f, "FunctionName")})).await {
                            Ok(p) => parse_policy(s(&p, "Policy")).is_some_and(|p| {
                                statements(&p).iter().any(|st| {
                                    has_str(st.get("Effect"), &["Allow"])
                                        && public_principal(st)
                                        && !restricted_by_condition(st)
                                })
                            }),
                            Err(e) if e.code == "ResourceNotFoundException" => false,
                            Err(_) => return None,
                        };
                    out.push(ResourceEvaluation::new("AwsLambdaFunction", s(f, "FunctionArn"), !public));
                }
                Some(out)
            }
            "RDS.3" => {
                let rds: &dyn Service = &self.rds;
                let dbs = call(rds, ctx, "DescribeDBInstances", json!({})).await.ok()?;
                Some(
                    arr(&dbs, "DBInstances")
                        .iter()
                        .map(|d| {
                            ResourceEvaluation::new(
                                "AwsRdsDbInstance",
                                s(d, "DBInstanceArn"),
                                truthy(d.get("StorageEncrypted")),
                            )
                        })
                        .collect(),
                )
            }
            "SecretsManager.1" => {
                let sm: &dyn Service = &self.secretsmanager;
                let secrets = call(sm, ctx, "ListSecrets", json!({})).await.ok()?;
                let max = params.get("maximumAllowedRotationFrequency").and_then(Value::as_i64);
                Some(
                    arr(&secrets, "SecretList")
                        .iter()
                        .map(|x| {
                            let days = x
                                .get("RotationRules")
                                .and_then(|r| r.get("AutomaticallyAfterDays"))
                                .and_then(Value::as_i64);
                            let ok =
                                truthy(x.get("RotationEnabled")) && max.is_none_or(|m| days.is_some_and(|d| d <= m));
                            ResourceEvaluation::new("AwsSecretsManagerSecret", s(x, "ARN"), ok)
                        })
                        .collect(),
                )
            }
            "GuardDuty.1" => {
                let gd: &dyn Service = &self.guardduty;
                let ids = call(gd, ctx, "ListDetectors", json!({})).await.ok()?;
                let mut enabled = false;
                for id in arr(&ids, "DetectorIds").iter().filter_map(Value::as_str) {
                    let d = call(gd, ctx, "GetDetector", json!({"DetectorId": id})).await.ok()?;
                    enabled |= s(&d, "Status") == "ENABLED";
                }
                Some(vec![ResourceEvaluation::account(account_id(ctx), enabled)])
            }
            _ => None,
        }
    }
}

#[async_trait]
impl ControlEvidence for Evidence {
    fn evaluated_controls(&self) -> &'static [&'static str] {
        EVALUATED
    }

    async fn evaluate(
        &self,
        ctx: &RequestContext,
        control_id: &str,
        parameters: &BTreeMap<String, Value>,
    ) -> Option<Vec<ResourceEvaluation>> {
        match control_id.split_once('.').map(|(svc, _)| svc).unwrap_or_default() {
            "IAM" => self.iam(ctx, control_id).await,
            "S3" => self.s3(ctx, control_id).await,
            "KMS" => self.kms(ctx).await,
            "CloudTrail" => self.cloudtrail(ctx, control_id).await,
            "EC2" => self.ec2(ctx, control_id).await,
            _ => self.simple(ctx, control_id, parameters).await,
        }
    }
}

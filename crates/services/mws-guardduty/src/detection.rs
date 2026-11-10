//! Threat detection from CloudTrail management events.
//!
//! Each management event CloudTrail records is fed to
//! [`GuardDuty::observe_management_event`]. In an account and Region whose
//! detector is enabled it may raise findings, which GuardDuty aggregates
//! by finding type, principal and affected resource (a repeat bumps
//! `service.count` and `service.eventLastSeen`):
//!
//! | Finding type | Event |
//! | --- | --- |
//! | `Policy:IAMUser/RootCredentialUsage` | any call made with root credentials |
//! | `Stealth:IAMUser/CloudTrailLoggingDisabled` | `StopLogging`, `DeleteTrail` |
//! | `Stealth:IAMUser/PasswordPolicyChange` | `DeleteAccountPasswordPolicy`, or `UpdateAccountPasswordPolicy` weakening the policy GuardDuty last saw |
//! | `Policy:S3/BucketBlockPublicAccessDisabled` | `PutPublicAccessBlock` on a bucket with a setting off, `DeletePublicAccessBlock` |
//! | `Policy:S3/AccountBlockPublicAccessDisabled` | the same for the account (S3 Control, or S3's `Put`/`DeleteAccountPublicAccessBlock`) |
//! | `Policy:S3/BucketAnonymousAccessGranted` | `PutBucketPolicy` allowing `*` without conditions, `PutBucketAcl` granting `AllUsers` |
//! | `Stealth:S3/ServerAccessLoggingDisabled` | `PutBucketLogging` without `LoggingEnabled` |
//! | `UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom` | a write call from an IP address on an active threat list |
//! | `Recon:IAMUser/MaliciousIPCaller.Custom` | a read-only call from such an address |
//!
//! Calls from addresses on an active trusted list (IP set or trusted
//! entity set) raise no findings. Configuration findings need the call to
//! have succeeded. GuardDuty's own API calls are not analysed.

use std::collections::BTreeMap;
use std::net::IpAddr;

use chrono::Duration;
use mws_core::RequestContext;
use serde_json::{json, Value};

use crate::common::{child_arn, iso, stable_id};
use crate::generated::types;
use crate::threatlists::contains;
use crate::GuardDuty;

/// How long after a detected finding is first seen it is published.
pub const NEW_FINDING_DELAY_SECONDS: i64 = 300;

/// A detector's `FindingPublishingFrequency` as a duration.
pub fn frequency(f: &str) -> Duration {
    match f {
        "FIFTEEN_MINUTES" => Duration::minutes(15),
        "ONE_HOUR" => Duration::hours(1),
        _ => Duration::hours(6),
    }
}

/// The principal a CloudTrail `userIdentity` names, as `accessKeyDetails`.
struct Principal {
    user_type: String,
    user_name: String,
    principal_id: String,
    access_key_id: Option<String>,
}

fn principal(identity: &Value) -> Option<Principal> {
    let text = |p: &str| identity.pointer(p).and_then(Value::as_str).map(str::to_string);
    let user_type = text("/type")?;
    let principal_id = text("/principalId").unwrap_or_default();
    let user_name = match user_type.as_str() {
        "Root" => "Root".to_string(),
        "IAMUser" => text("/userName")?,
        "AssumedRole" => text("/sessionContext/sessionIssuer/userName")
            .or_else(|| text("/arn").and_then(|a| a.split('/').nth(1).map(str::to_string)))?,
        "FederatedUser" => text("/arn").and_then(|a| a.rsplit('/').next().map(str::to_string))?,
        _ => return None,
    };
    Some(Principal {
        user_type,
        user_name,
        principal_id,
        access_key_id: text("/accessKeyId").filter(|k| !k.is_empty()),
    })
}

/// The value of `key` anywhere in `v`, ignoring case: MWS records
/// parameters in lowerCamelCase, AWS writes some in PascalCase.
fn find<'v>(v: &'v Value, key: &str) -> Option<&'v Value> {
    match v {
        Value::Object(m) => {
            if let Some((_, x)) = m.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)) {
                return Some(x);
            }
            m.values().find_map(|x| find(x, key))
        }
        Value::Array(items) => items.iter().find_map(|x| find(x, key)),
        _ => None,
    }
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

fn number(v: Option<&Value>) -> Option<i64> {
    match v? {
        Value::Number(n) => n.as_i64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

/// Whether a bucket policy (a JSON document, or its text) allows anyone
/// (`*`) without conditions.
fn policy_is_anonymous(policy: &Value) -> bool {
    let doc = match policy {
        Value::String(s) => serde_json::from_str::<Value>(s).unwrap_or(Value::Null),
        other => other.clone(),
    };
    let statements = match doc.get("Statement") {
        Some(Value::Array(a)) => a.clone(),
        Some(s @ Value::Object(_)) => vec![s.clone()],
        _ => return false,
    };
    statements.iter().any(|s| {
        let allow = s.get("Effect").and_then(Value::as_str) == Some("Allow");
        let star = |v: &Value| match v {
            Value::String(s) => s == "*",
            Value::Array(a) => a.iter().any(|x| x.as_str() == Some("*")),
            _ => false,
        };
        let anyone = match s.get("Principal") {
            Some(p @ Value::String(_)) => star(p),
            Some(Value::Object(m)) => m.get("AWS").is_some_and(star),
            _ => false,
        };
        let conditional = s.get("Condition").is_some_and(|c| c.as_object().is_some_and(|m| !m.is_empty()));
        allow && anyone && !conditional
    })
}

/// Whether the new password policy `new` is weaker than `old`.
fn weaker(old: &Value, new: &Value) -> bool {
    let n = |v: &Value, k: &str| number(find(v, k));
    if n(new, "minimumPasswordLength").unwrap_or(6) < n(old, "minimumPasswordLength").unwrap_or(6) {
        return true;
    }
    for k in ["requireSymbols", "requireNumbers", "requireUppercaseCharacters", "requireLowercaseCharacters"] {
        if truthy(find(old, k)) && !truthy(find(new, k)) {
            return true;
        }
    }
    if let Some(old_age) = n(old, "maxPasswordAge").filter(|a| *a > 0) {
        if n(new, "maxPasswordAge").filter(|a| *a > 0).is_none_or(|a| a > old_age) {
            return true;
        }
    }
    if let Some(old_reuse) = n(old, "passwordReusePrevention").filter(|r| *r > 0) {
        if n(new, "passwordReusePrevention").unwrap_or(0) < old_reuse {
            return true;
        }
    }
    false
}

/// A finding an event raises.
struct Hit {
    ty: &'static str,
    severity: f64,
    /// What the finding is about besides the principal: aggregation key.
    subject: String,
    title: String,
    description: String,
    bucket: Option<(String, bool)>,
    affected: BTreeMap<String, String>,
    threat_list: Option<String>,
}

impl Hit {
    fn new(ty: &'static str, severity: f64, subject: impl Into<String>, title: String, description: String) -> Self {
        Hit {
            ty,
            severity,
            subject: subject.into(),
            title,
            description,
            bucket: None,
            affected: BTreeMap::new(),
            threat_list: None,
        }
    }
}

/// An enabled detector's view of the account's lists.
struct Lists {
    /// `(list name, entries)` of active threat lists.
    threats: Vec<(String, Vec<String>)>,
    /// Entries of active trusted lists.
    trusted: Vec<String>,
    password_policy: Option<Value>,
}

impl GuardDuty {
    /// Analyse a CloudTrail management event (the record as CloudTrail
    /// writes it) for threats, in the account (`recipientAccountId`) and
    /// Region (`awsRegion`) it belongs to. `ctx` is the request that made
    /// the event; findings are published from it.
    pub fn observe_management_event(&self, ctx: &RequestContext, event: &Value) {
        self.remember(ctx);
        self.flush_due(ctx);
        let text = |k: &str| event.get(k).and_then(Value::as_str).unwrap_or_default();
        let (account, region, source) = (text("recipientAccountId"), text("awsRegion"), text("eventSource"));
        if account.is_empty() || region.is_empty() || source == crate::SERVICE_PRINCIPAL {
            return;
        }
        if event.get("managementEvent").and_then(Value::as_bool) == Some(false) {
            return;
        }
        let ctx = RequestContext { region: region.to_string(), ..ctx.clone() };
        let previous_policy = self.note_password_policy(account, event);
        self.settle_lists(&ctx);
        let lists = {
            let state = self.lock();
            let Some(d) = state.detector(account, region).filter(|d| d.enabled) else { return };
            let active = |m: &BTreeMap<String, crate::state::ThreatList>| {
                m.values()
                    .filter(|l| l.status == "ACTIVE")
                    .map(|l| (l.name.clone(), l.entries.clone()))
                    .collect::<Vec<_>>()
            };
            let mut threats = active(&d.threat_intel_sets);
            threats.extend(active(&d.threat_entity_sets));
            let mut trusted: Vec<String> = active(&d.ip_sets).into_iter().flat_map(|(_, e)| e).collect();
            trusted.extend(active(&d.trusted_entity_sets).into_iter().flat_map(|(_, e)| e));
            Lists { threats, trusted, password_policy: previous_policy }
        };
        let Some(who) = principal(event.get("userIdentity").unwrap_or(&Value::Null)) else { return };
        let ip: Option<IpAddr> = text("sourceIPAddress").parse().ok();
        if ip.is_some_and(|ip| lists.trusted.iter().any(|e| contains(e, ip))) {
            return;
        }
        let hits = self.analyse(&ctx, account, event, &who, ip, &lists);
        if hits.is_empty() {
            return;
        }
        let findings = {
            let state = self.lock();
            let Some(d) = state.detector(account, region) else { return };
            hits.into_iter()
                .map(|h| {
                    let id = stable_id(&[
                        "detected",
                        account,
                        region,
                        &d.id,
                        h.ty,
                        &who.principal_id,
                        &who.user_name,
                        &h.subject,
                    ]);
                    build(&ctx, account, &d.id, &id, event, &who, ip, h, d.findings.get(&id))
                })
                .collect::<Vec<_>>()
        };
        self.record_detected(&ctx, account, findings);
    }

    fn analyse(
        &self,
        ctx: &RequestContext,
        account: &str,
        event: &Value,
        who: &Principal,
        ip: Option<IpAddr>,
        lists: &Lists,
    ) -> Vec<Hit> {
        let text = |k: &str| event.get(k).and_then(Value::as_str).unwrap_or_default();
        let (api, source) = (text("eventName"), text("eventSource"));
        let ok = event.get("errorCode").is_none_or(Value::is_null);
        let params = event.get("requestParameters").cloned().unwrap_or(Value::Null);
        let by = format!("{} {}", who.user_type, who.user_name);
        let from = ip.map(|i| i.to_string()).unwrap_or_else(|| text("sourceIPAddress").to_string());
        let mut hits = Vec::new();
        let bucket = find(&params, "bucketName").and_then(Value::as_str).map(str::to_string);

        if who.user_type == "Root" && event.pointer("/userIdentity/invokedBy").is_none() {
            hits.push(Hit::new(
                "Policy:IAMUser/RootCredentialUsage",
                2.0,
                "",
                format!("API {api} was invoked using root credentials."),
                format!("API {api} was invoked using root credentials from IP address {from}."),
            ));
        }

        if ok && source == "cloudtrail.amazonaws.com" && matches!(api, "StopLogging" | "DeleteTrail") {
            let name = find(&params, "name").and_then(Value::as_str).unwrap_or_default();
            let arn = if name.starts_with("arn:") {
                name.to_string()
            } else {
                format!("arn:{}:cloudtrail:{}:{account}:trail/{name}", ctx.partition, ctx.region)
            };
            let mut h = Hit::new(
                "Stealth:IAMUser/CloudTrailLoggingDisabled",
                2.0,
                arn.clone(),
                format!("AWS CloudTrail trail {arn} was disabled."),
                format!(
                    "AWS CloudTrail trail {arn} was disabled by {by} calling {api}. This can be an attacker's attempt to cover their tracks by eliminating any trace of activity performed while they accessed your account."
                ),
            );
            h.affected.insert("AWS::CloudTrail::Trail".into(), arn);
            hits.push(h);
        }

        if ok && source == "iam.amazonaws.com" {
            let weakened = match api {
                "DeleteAccountPasswordPolicy" => true,
                "UpdateAccountPasswordPolicy" => lists.password_policy.as_ref().is_some_and(|old| weaker(old, &params)),
                _ => false,
            };
            if weakened {
                hits.push(Hit::new(
                    "Stealth:IAMUser/PasswordPolicyChange",
                    2.0,
                    "",
                    "Account password policy was weakened.".into(),
                    format!(
                        "The account password policy was weakened by {by} calling {api}. This can make the account's IAM users' passwords easier to guess."
                    ),
                ));
            }
        }

        let account_bpa = (source == "s3control.amazonaws.com"
            && matches!(api, "PutPublicAccessBlock" | "DeletePublicAccessBlock"))
            || (source == "s3.amazonaws.com"
                && matches!(api, "PutAccountPublicAccessBlock" | "DeleteAccountPublicAccessBlock"));
        let flags = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"];
        let bpa_off = |api: &str| {
            api.starts_with("Delete")
                || flags
                    .iter()
                    .any(|f| !truthy(find(&params, "PublicAccessBlockConfiguration").and_then(|c| find(c, f))))
        };
        if ok && account_bpa && bpa_off(api) {
            let mut h = Hit::new(
                "Policy:S3/AccountBlockPublicAccessDisabled",
                2.0,
                account.to_string(),
                format!("Amazon S3 Block Public Access was disabled for account {account}."),
                format!(
                    "Amazon S3 Block Public Access was disabled for account {account} by {by} calling {api}. If this behavior is not expected, it may indicate a configuration mistake or that your credentials are compromised."
                ),
            );
            h.bucket = Some((String::new(), false));
            hits.push(h);
        }

        if let (true, "s3.amazonaws.com", Some(b)) = (ok, source, bucket.as_deref()) {
            let arn = format!("arn:{}:s3:::{b}", ctx.partition);
            let mut push = |ty: &'static str, severity: f64, title: String, what: &str, public: bool| {
                let mut h = Hit::new(
                    ty,
                    severity,
                    b.to_string(),
                    title,
                    format!(
                        "{what} by {by} calling {api}. If this behavior is not expected, it may indicate a configuration mistake or that your credentials are compromised."
                    ),
                );
                h.bucket = Some((b.to_string(), public));
                h.affected.insert("AWS::S3::Bucket".into(), arn.clone());
                hits.push(h);
            };
            if matches!(
                api,
                "PutPublicAccessBlock"
                    | "PutBucketPublicAccessBlock"
                    | "DeletePublicAccessBlock"
                    | "DeleteBucketPublicAccessBlock"
            ) && bpa_off(api)
            {
                let what = format!("Amazon S3 Block Public Access was disabled for S3 bucket {b}");
                push("Policy:S3/BucketBlockPublicAccessDisabled", 2.0, format!("{what}."), &what, false);
            }
            let anonymous = match api {
                "PutBucketPolicy" => {
                    find(&params, "bucketPolicy").or_else(|| find(&params, "policy")).is_some_and(policy_is_anonymous)
                }
                "PutBucketAcl" => {
                    params.to_string().contains("acs.amazonaws.com/groups/global/AllUsers")
                        || find(&params, "acl")
                            .and_then(Value::as_str)
                            .is_some_and(|a| matches!(a, "public-read" | "public-read-write"))
                }
                _ => false,
            };
            if anonymous {
                let what = format!("The Amazon S3 bucket {b} was granted public anonymous access");
                push(
                    "Policy:S3/BucketAnonymousAccessGranted",
                    8.0,
                    format!("Amazon S3 Public Anonymous Access was granted for the S3 bucket {b}."),
                    &what,
                    true,
                );
            }
            if api == "PutBucketLogging" && find(&params, "LoggingEnabled").is_none_or(Value::is_null) {
                let what = format!("Amazon S3 Server Access Logging was disabled for S3 bucket {b}");
                push("Stealth:S3/ServerAccessLoggingDisabled", 2.0, format!("{what}."), &what, false);
            }
        }

        if let Some(ip) = ip {
            if let Some((list, _)) = lists.threats.iter().find(|(_, e)| e.iter().any(|e| contains(e, ip))) {
                let read_only = event.get("readOnly").and_then(Value::as_bool).unwrap_or(false);
                let mut h = if read_only {
                    Hit::new(
                        "Recon:IAMUser/MaliciousIPCaller.Custom",
                        5.0,
                        format!("{ip}|{list}"),
                        format!("Reconnaissance API {api} was invoked from an IP address {ip} on the custom threat list {list}."),
                        format!(
                            "API {api}, commonly used in reconnaissance attacks, was invoked from an IP address {ip} on the custom threat list {list}. Unauthorized actors perform this type of activity to gather information and discover resources like databases, S3 buckets, EC2 instances and IAM users."
                        ),
                    )
                } else {
                    Hit::new(
                        "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom",
                        5.0,
                        format!("{ip}|{list}"),
                        format!("API {api} was invoked from an IP address {ip} on the custom threat list {list}."),
                        format!(
                            "API {api} was invoked from an IP address {ip} on the custom threat list {list}. This could indicate unauthorized access to AWS resources."
                        ),
                    )
                };
                h.threat_list = Some(list.clone());
                hits.push(h);
            }
        }
        hits
    }

    /// Keep track of `account`'s password policy as successful
    /// `UpdateAccountPasswordPolicy` and `DeleteAccountPasswordPolicy`
    /// calls set it, whether or not GuardDuty is enabled: the policy it
    /// replaces, for such a call.
    fn note_password_policy(&self, account: &str, event: &Value) -> Option<Value> {
        let api = event.get("eventName").and_then(Value::as_str).unwrap_or_default();
        let ok = event.get("errorCode").is_none_or(Value::is_null);
        if !ok
            || event.get("eventSource").and_then(Value::as_str) != Some("iam.amazonaws.com")
            || !matches!(api, "UpdateAccountPasswordPolicy" | "DeleteAccountPasswordPolicy")
        {
            return None;
        }
        let mut state = self.lock();
        let previous = state.password_policies.remove(account);
        if api == "UpdateAccountPasswordPolicy" {
            let params = event.get("requestParameters").cloned().unwrap_or_else(|| json!({}));
            state.password_policies.insert(account.to_string(), params);
        }
        previous
    }

    /// Note `ctx` for background publishing, and start the loop that
    /// publishes detected findings when they are due.
    pub(crate) fn remember(&self, ctx: &RequestContext) {
        let offset = (ctx.received_at - chrono::Utc::now()).num_milliseconds().max(0);
        *self.background.template.lock().expect("GuardDuty template lock poisoned") = Some((ctx.clone(), offset));
        // Outside a runtime the loop cannot start yet; a later call made
        // inside one starts it.
        if tokio::runtime::Handle::try_current().is_err() || self.background.started.set(()).is_err() {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                let template = me.background.template.lock().expect("GuardDuty template lock poisoned").clone();
                if let Some((ctx, offset)) = template {
                    let now = chrono::Utc::now() + Duration::milliseconds(offset);
                    me.flush_due(&RequestContext { received_at: now, ..ctx });
                }
            }
        });
    }
}

fn remote_ip(ip: Option<IpAddr>) -> Option<types::RemoteIpDetails> {
    let ip = ip?;
    Some(types::RemoteIpDetails {
        ip_address_v4: ip.is_ipv4().then(|| ip.to_string()),
        ip_address_v6: ip.is_ipv6().then(|| ip.to_string()),
        organization: Some(types::Organization {
            asn: Some("0".into()),
            asn_org: Some("Unknown".into()),
            isp: Some("Unknown".into()),
            org: Some("Unknown".into()),
        }),
        ..Default::default()
    })
}

/// The finding `id` for `hit`: new, or `existing` updated.
#[allow(clippy::too_many_arguments)]
fn build(
    ctx: &RequestContext,
    account: &str,
    detector: &str,
    id: &str,
    event: &Value,
    who: &Principal,
    ip: Option<IpAddr>,
    hit: Hit,
    existing: Option<&types::Finding>,
) -> types::Finding {
    let now = ctx.received_at;
    let now_s = iso(now);
    let text = |k: &str| event.get(k).and_then(Value::as_str).unwrap_or_default().to_string();
    let api = text("eventName");
    let source_ip = text("sourceIPAddress");
    let action = types::Action {
        action_type: Some("AWS_API_CALL".into()),
        aws_api_call_action: Some(types::AwsApiCallAction {
            api: Some(api.clone()),
            caller_type: Some(if ip.is_some() { "Remote IP" } else { "Domain" }.into()),
            domain_details: ip.is_none().then(|| types::DomainDetails { domain: Some(source_ip.clone()) }),
            error_code: event.get("errorCode").and_then(Value::as_str).map(str::to_string),
            user_agent: Some(text("userAgent")),
            remote_ip_details: remote_ip(ip),
            service_name: Some(text("eventSource")),
            remote_account_details: None,
            affected_resources: Some(hit.affected.clone()),
        }),
        ..Default::default()
    };
    // `recentApiCalls`: how often each API raised this finding.
    let mut info = existing
        .and_then(|f| f.service.as_ref())
        .and_then(|s| s.additional_info.as_ref())
        .and_then(|i| i.value.as_deref())
        .and_then(|v| serde_json::from_str::<Value>(v).ok())
        .unwrap_or_else(|| json!({}));
    let mut calls: Vec<Value> = info.get("recentApiCalls").and_then(Value::as_array).cloned().unwrap_or_default();
    match calls.iter_mut().find(|c| c["api"] == api.as_str()) {
        Some(c) => c["count"] = json!(c["count"].as_i64().unwrap_or(0) + 1),
        None => calls.push(json!({ "api": api, "count": 1 })),
    }
    info["recentApiCalls"] = Value::Array(calls);
    if let Some(list) = &hit.threat_list {
        info["threatListName"] = list.clone().into();
    }
    let additional_info =
        Some(types::ServiceAdditionalInfo { value: Some(info.to_string()), r#type: Some("default".into()) });
    if let Some(prev) = existing {
        let mut f = prev.clone();
        f.updated_at = now_s.clone();
        f.title = Some(hit.title);
        f.description = Some(hit.description);
        if let Some(s) = f.service.as_mut() {
            s.count = Some(s.count.unwrap_or(1) + 1);
            s.event_last_seen = Some(now_s);
            s.action = Some(action);
            s.additional_info = additional_info;
        }
        return f;
    }
    let mut resource = types::Resource {
        access_key_details: Some(types::AccessKeyDetails {
            access_key_id: who.access_key_id.clone(),
            principal_id: Some(who.principal_id.clone()),
            user_name: Some(who.user_name.clone()),
            user_type: Some(who.user_type.clone()),
        }),
        resource_type: Some("AccessKey".into()),
        ..Default::default()
    };
    if let Some((bucket, public)) = &hit.bucket {
        resource.resource_type = Some("S3Bucket".into());
        if !bucket.is_empty() {
            resource.s3_bucket_details = Some(vec![types::S3BucketDetail {
                arn: Some(format!("arn:{}:s3:::{bucket}", ctx.partition)),
                name: Some(bucket.clone()),
                r#type: Some("Destination".into()),
                public_access: Some(types::PublicAccess {
                    permission_configuration: None,
                    effective_permission: Some(if *public { "PUBLIC" } else { "NOT_PUBLIC" }.into()),
                }),
                ..Default::default()
            }]);
        }
    }
    let first_seen = event
        .get("eventTime")
        .and_then(Value::as_str)
        .and_then(|t| chrono::DateTime::parse_from_rfc3339(t).ok())
        .map(|t| iso(t.with_timezone(&chrono::Utc)))
        .unwrap_or_else(|| now_s.clone());
    types::Finding {
        account_id: account.to_string(),
        arn: child_arn(ctx, account, detector, "finding", id),
        confidence: None,
        created_at: now_s.clone(),
        description: Some(hit.description),
        id: id.to_string(),
        partition: Some(ctx.partition.clone()),
        region: ctx.region.clone(),
        resource,
        schema_version: "2.0".into(),
        service: Some(types::Service {
            action: Some(action),
            evidence: hit.threat_list.as_ref().map(|list| types::Evidence {
                threat_intelligence_details: Some(vec![types::ThreatIntelligenceDetail {
                    threat_list_name: Some(list.clone()),
                    threat_names: Some(Vec::new()),
                    threat_file_sha256: None,
                }]),
            }),
            archived: Some(false),
            count: Some(1),
            detector_id: Some(detector.to_string()),
            event_first_seen: Some(first_seen.clone()),
            event_last_seen: Some(first_seen),
            resource_role: Some("TARGET".into()),
            service_name: Some("guardduty".into()),
            user_feedback: None,
            additional_info,
            feature_name: Some("CloudTrail".into()),
            ..Default::default()
        }),
        severity: hit.severity,
        title: Some(hit.title),
        r#type: hit.ty.to_string(),
        updated_at: now_s,
        associated_attack_sequence_arn: None,
        custom_detection_rule_name: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymous_policies() {
        let open = json!({"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*"}]});
        assert!(policy_is_anonymous(&Value::String(open.to_string())));
        let aws = json!({"Statement":{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":"s3:*","Resource":"*"}});
        assert!(policy_is_anonymous(&aws));
        let scoped = json!({"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"*",
            "Condition":{"StringEquals":{"aws:SourceVpce":"vpce-1"}}}]});
        assert!(!policy_is_anonymous(&scoped));
        let service =
            json!({"Statement":[{"Effect":"Allow","Principal":{"Service":"logs.amazonaws.com"},"Action":"*"}]});
        assert!(!policy_is_anonymous(&service));
    }

    #[test]
    fn password_policy_weakening() {
        let strong = json!({"minimumPasswordLength": 14, "requireSymbols": true, "maxPasswordAge": 90});
        assert!(weaker(&strong, &json!({"minimumPasswordLength": 8, "requireSymbols": true, "maxPasswordAge": 90})));
        assert!(weaker(&strong, &json!({"minimumPasswordLength": 14, "maxPasswordAge": 90})));
        assert!(weaker(&strong, &json!({"minimumPasswordLength": 14, "requireSymbols": true})));
        assert!(!weaker(&strong, &json!({"minimumPasswordLength": 16, "requireSymbols": true, "maxPasswordAge": 30})));
    }
}

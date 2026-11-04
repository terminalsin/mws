//! Message data protection: a topic's data protection policy acts on the
//! messages published to it (`Inbound`, judged against the publisher) and
//! on each delivery (`Outbound`, judged against the principal that
//! subscribed, `SubscriptionPrincipal`).
//!
//! - `Deny` rejects a Publish that carries sensitive data with
//!   `AuthorizationError`, or skips a delivery (logged as a 403 failure
//!   when delivery status logging is on).
//! - `Deidentify` masks (`MaskConfig`) or removes (`RedactConfig`) what
//!   the data identifiers match; a Publish whose whole message is
//!   sensitive is rejected with `AuthorizationError`.
//! - `Audit` writes a finding record for a sample (`SampleRate` percent)
//!   of inbound messages to the `FindingsDestination` or
//!   `NoFindingsDestination`: a CloudWatch Logs group (`/aws/vendedlogs/`),
//!   a Firehose stream, or an S3 bucket (as `delivery.logs.amazonaws.com`,
//!   so the bucket policy must allow it).
//!
//! Managed data identifiers MWS detects: EmailAddress, IpAddress, Ssn-US,
//! PhoneNumber-US, CreditCardNumber (Luhn-checked), AwsSecretKey,
//! OpenSshPrivateKey and PkcsPrivateKey, plus any `CustomDataIdentifier`.
//! Other managed identifiers are accepted but find nothing.
//!
//! Spec: <https://docs.aws.amazon.com/sns/latest/dg/sns-message-data-protection-operations.html>

use std::collections::BTreeMap;

use mws_core::{Caller, CallerKind, RequestContext, ServiceError};
use regex::Regex;
use serde_json::{json, Value};

use crate::errors;
use crate::publish::Outgoing;
use crate::state::{Subscription, Topic};
use crate::Sns;

/// Characters `MaskWithCharacter` may be.
const MASK_CHARACTERS: &str =
    "*ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 !$%&()+,-./\\#:;=<>@[]^_`|~";

fn managed_identifier(name: &str) -> Option<&'static str> {
    Some(match name {
        "EmailAddress" => r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        "IpAddress" => r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
        "Ssn-US" => r"\b\d{3}-\d{2}-\d{4}\b",
        "PhoneNumber-US" => r"(?:\+1[ -]?)?\(?\b\d{3}\)?[-. ]\d{3}[-. ]\d{4}\b",
        "CreditCardNumber" => r"\b(?:\d[ -]?){12,18}\d\b",
        "AwsSecretKey" => r"(?i)\b(?:aws_?secret_?(?:access_?)?key)\b\s*[:=]\s*[A-Za-z0-9/+=]{40}",
        "OpenSshPrivateKey" => r"-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----",
        "PkcsPrivateKey" => r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC )?PRIVATE KEY-----",
        _ => return None,
    })
}

fn luhn(digits: &str) -> bool {
    let d: Vec<u32> = digits.chars().filter_map(|c| c.to_digit(10)).collect();
    if d.len() < 13 {
        return false;
    }
    let sum: u32 = d
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &x)| {
            if i % 2 == 1 {
                let y = x * 2;
                if y > 9 {
                    y - 9
                } else {
                    y
                }
            } else {
                x
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

#[derive(Debug, Clone)]
pub(crate) enum Destination {
    Logs(String),
    Firehose(String),
    S3(String),
}

#[derive(Debug, Clone)]
enum Operation {
    Audit { sample_rate: u32, findings: Option<Destination>, no_findings: Option<Destination> },
    Deny,
    Mask(char),
    Redact,
}

#[derive(Debug, Clone)]
struct Identifier {
    name: String,
    /// `None` for managed identifiers MWS does not detect.
    regex: Option<Regex>,
}

#[derive(Debug, Clone)]
struct Statement {
    inbound: bool,
    principals: Vec<String>,
    identifiers: Vec<Identifier>,
    operation: Operation,
}

/// A parsed data protection policy.
#[derive(Debug, Clone)]
pub(crate) struct DataProtection {
    statements: Vec<Statement>,
}

/// One identifier's matches in a text, as byte ranges.
#[derive(Debug, Clone)]
struct Finding {
    name: String,
    ranges: Vec<(usize, usize)>,
}

fn fail(why: impl std::fmt::Display) -> ServiceError {
    errors::invalid(format!("DataProtectionPolicy Reason: {why}"))
}

fn destination(v: Option<&Value>, what: &str) -> Result<Option<Destination>, ServiceError> {
    let Some(v) = v else { return Ok(None) };
    let obj = v.as_object().ok_or_else(|| fail(format!("{what} must be an object")))?;
    let field = |service: &str, key: &str| {
        obj.get(service).map(|s| {
            s.get(key)
                .and_then(Value::as_str)
                .filter(|n| !n.is_empty())
                .map(str::to_string)
                .ok_or_else(|| fail(format!("{what}.{service}.{key} is required")))
        })
    };
    let mut found = Vec::new();
    if let Some(group) = field("CloudWatchLogs", "LogGroup") {
        let group = group?;
        if !group.starts_with("/aws/vendedlogs/") {
            return Err(fail(format!("{what}.CloudWatchLogs.LogGroup must start with /aws/vendedlogs/")));
        }
        found.push(Destination::Logs(group));
    }
    if let Some(stream) = field("Firehose", "DeliveryStream") {
        found.push(Destination::Firehose(stream?));
    }
    if let Some(bucket) = field("S3", "Bucket") {
        found.push(Destination::S3(bucket?));
    }
    match found.len() {
        0 => Ok(None),
        1 => Ok(found.pop()),
        _ => Err(fail(format!("{what} can have only one destination"))),
    }
}

impl DataProtection {
    /// Parse and check a policy document as `PutDataProtectionPolicy`
    /// does.
    pub(crate) fn parse(doc: &str) -> Result<Self, ServiceError> {
        let v: Value = serde_json::from_str(doc).map_err(|_| fail("Failed to parse JSON"))?;
        let obj = v.as_object().ok_or_else(|| fail("Policy must be a JSON object"))?;
        for key in ["Name", "Version", "Statement"] {
            if !obj.contains_key(key) {
                return Err(fail(format!("Missing required field {key}")));
            }
        }
        if obj.get("Version").and_then(Value::as_str) != Some("2021-06-01") {
            return Err(fail("Version must be 2021-06-01"));
        }
        let mut custom = BTreeMap::new();
        for c in v.pointer("/Configuration/CustomDataIdentifier").and_then(Value::as_array).into_iter().flatten() {
            let (Some(name), Some(re)) =
                (c.get("Name").and_then(Value::as_str), c.get("Regex").and_then(Value::as_str))
            else {
                return Err(fail("CustomDataIdentifier needs a Name and a Regex"));
            };
            let re = Regex::new(re).map_err(|_| fail(format!("Invalid regex for custom data identifier {name}")))?;
            custom.insert(name.to_string(), re);
        }
        let list = obj.get("Statement").and_then(Value::as_array).ok_or_else(|| fail("Statement must be a list"))?;
        if list.is_empty() {
            return Err(fail("Statement must not be empty"));
        }
        let mut statements = Vec::new();
        let mut audits = 0;
        for s in list {
            let Some(s) = s.as_object() else { return Err(fail("Statement must be a list of objects")) };
            for key in ["DataIdentifier", "Operation", "Principal", "DataDirection"] {
                if !s.contains_key(key) {
                    return Err(fail(format!("Statement is missing required field {key}")));
                }
            }
            let inbound = match s.get("DataDirection").and_then(Value::as_str) {
                Some("Inbound") => true,
                Some("Outbound") => false,
                _ => return Err(fail("DataDirection must be Inbound or Outbound")),
            };
            let strings = |key: &str| -> Result<Vec<String>, ServiceError> {
                let items = s
                    .get(key)
                    .and_then(Value::as_array)
                    .filter(|a| !a.is_empty())
                    .ok_or_else(|| fail(format!("{key} must be a non-empty list")))?;
                items
                    .iter()
                    .map(|i| {
                        i.as_str().map(str::to_string).ok_or_else(|| fail(format!("{key} must be a list of strings")))
                    })
                    .collect()
            };
            let principals = strings("Principal")?;
            let mut identifiers = Vec::new();
            for id in strings("DataIdentifier")? {
                if let Some(re) = custom.get(&id) {
                    identifiers.push(Identifier { name: id.clone(), regex: Some(re.clone()) });
                    continue;
                }
                let managed = id.split_once(":dataprotection::aws:data-identifier/");
                let Some((_, name)) = managed.filter(|(p, n)| p.starts_with("arn:") && !n.is_empty()) else {
                    return Err(fail(format!("Invalid data identifier {id}")));
                };
                let regex = managed_identifier(name).and_then(|r| Regex::new(r).ok());
                identifiers.push(Identifier { name: name.to_string(), regex });
            }
            let op =
                s.get("Operation").and_then(Value::as_object).ok_or_else(|| fail("Operation must be an object"))?;
            if op.len() != 1 {
                return Err(fail("Operation must have exactly one of Audit, Deidentify or Deny"));
            }
            let (kind, config) = op.iter().next().expect("one entry");
            let operation = match kind.as_str() {
                "Deny" => Operation::Deny,
                "Deidentify" => {
                    if let Some(mask) = config.get("MaskConfig") {
                        let c = match mask.get("MaskWithCharacter") {
                            None => '*',
                            Some(Value::String(c))
                                if c.chars().count() == 1 && MASK_CHARACTERS.contains(c.as_str()) =>
                            {
                                c.chars().next().expect("one char")
                            }
                            Some(_) => return Err(fail("MaskWithCharacter is not a supported mask character")),
                        };
                        Operation::Mask(c)
                    } else if config.get("RedactConfig").is_some() {
                        Operation::Redact
                    } else {
                        return Err(fail("Deidentify must have MaskConfig or RedactConfig"));
                    }
                }
                "Audit" => {
                    audits += 1;
                    if audits > 1 {
                        return Err(fail("Only one Audit statement is allowed"));
                    }
                    if !inbound {
                        return Err(fail("Audit operation is only supported for Inbound DataDirection"));
                    }
                    let rate = match config.get("SampleRate") {
                        None => 0,
                        Some(Value::Number(n)) => n.as_u64().unwrap_or(u64::MAX),
                        Some(Value::String(s)) => s.parse().unwrap_or(u64::MAX),
                        Some(_) => u64::MAX,
                    };
                    if rate > 99 {
                        return Err(fail("SampleRate must be an integer between 0 and 99"));
                    }
                    Operation::Audit {
                        sample_rate: rate as u32,
                        findings: destination(config.get("FindingsDestination"), "FindingsDestination")?,
                        no_findings: destination(config.get("NoFindingsDestination"), "NoFindingsDestination")?,
                    }
                }
                other => return Err(fail(format!("Unsupported operation {other}"))),
            };
            statements.push(Statement { inbound, principals, identifiers, operation });
        }
        Ok(Self { statements })
    }

    fn applying<'a>(&'a self, inbound: bool, principal: &'a str) -> impl Iterator<Item = &'a Statement> + 'a {
        self.statements.iter().filter(move |s| s.inbound == inbound && principal_matches(&s.principals, principal))
    }
}

/// The principals a statement's `Principal` entry could name for `arn`:
/// itself, its role (for an assumed-role session) and its account.
fn principal_matches(principals: &[String], arn: &str) -> bool {
    let mut names = vec![arn.to_string()];
    let parts: Vec<&str> = arn.splitn(6, ':').collect();
    if parts.len() == 6 {
        let (partition, account, resource) = (parts[1], parts[4], parts[5]);
        if let Some(rest) = resource.strip_prefix("assumed-role/") {
            if let Some((role, _)) = rest.split_once('/') {
                names.push(format!("arn:{partition}:iam::{account}:role/{role}"));
            }
        }
        if !account.is_empty() {
            names.push(account.to_string());
            names.push(format!("arn:{partition}:iam::{account}:root"));
        }
    }
    principals.iter().any(|p| p == "*" || names.iter().any(|n| n == p))
}

fn find(identifiers: &[Identifier], text: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    for id in identifiers {
        let Some(re) = &id.regex else { continue };
        let ranges: Vec<(usize, usize)> = re
            .find_iter(text)
            .filter(|m| id.name != "CreditCardNumber" || luhn(m.as_str()))
            .map(|m| (m.start(), m.end()))
            .collect();
        if !ranges.is_empty() {
            out.push(Finding { name: id.name.clone(), ranges });
        }
    }
    out
}

/// Mask or remove every match in `text`.
fn deidentify(text: &str, findings: &[Finding], mask: Option<char>) -> String {
    let mut ranges: Vec<(usize, usize)> = findings.iter().flat_map(|f| f.ranges.iter().copied()).collect();
    ranges.sort();
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for (start, end) in ranges {
        let start = start.max(at);
        if start >= end {
            continue;
        }
        out.push_str(&text[at..start]);
        if let Some(c) = mask {
            out.extend(std::iter::repeat_n(c, text[start..end].chars().count()));
        }
        at = end;
    }
    out.push_str(&text[at..]);
    out
}

/// Whether the matches cover all of `text` but whitespace.
fn entirely_sensitive(text: &str, findings: &[Finding]) -> bool {
    let mut covered = vec![false; text.len()];
    for f in findings {
        for &(s, e) in &f.ranges {
            covered[s..e].iter_mut().for_each(|c| *c = true);
        }
    }
    !findings.is_empty() && text.char_indices().all(|(i, c)| covered[i] || c.is_whitespace())
}

/// The texts of a message a policy scans: the message, or each
/// per-protocol message of a `json` structure.
struct Texts {
    message: String,
    structure: Option<BTreeMap<String, String>>,
}

impl Texts {
    fn each(&self) -> Vec<&str> {
        match &self.structure {
            Some(s) => s.values().map(String::as_str).collect(),
            None => vec![self.message.as_str()],
        }
    }

    fn map(&mut self, f: impl Fn(&str) -> String) {
        self.message = f(&self.message);
        if let Some(s) = &mut self.structure {
            for v in s.values_mut() {
                *v = f(v);
            }
        }
    }
}

fn denied() -> ServiceError {
    errors::authorization_error("The topic's data protection policy prohibits this message from being published")
}

/// What the inbound statements leave of a message: the (possibly
/// de-identified) message and structure, and the audit to write.
pub(crate) struct Inbound {
    pub message: String,
    pub structure: Option<BTreeMap<String, String>>,
    audit: Option<(Destination, Value)>,
}

impl Sns {
    /// The topic's policy, parsed.
    fn policy_of(topic: &Topic) -> Option<DataProtection> {
        DataProtection::parse(topic.data_protection_policy.as_deref()?).ok()
    }

    /// Apply the topic's inbound statements to a message `principal`
    /// publishes.
    pub(crate) fn protect_inbound(
        &self,
        ctx: &RequestContext,
        topic: &Topic,
        principal: &str,
        message: &str,
        structure: Option<BTreeMap<String, String>>,
    ) -> Result<Inbound, ServiceError> {
        let mut texts = Texts { message: message.to_string(), structure };
        let Some(policy) = Self::policy_of(topic) else {
            return Ok(Inbound { message: texts.message, structure: texts.structure, audit: None });
        };
        let mut audit = None;
        for s in policy.applying(true, principal) {
            match &s.operation {
                Operation::Deny => {
                    if texts.each().iter().any(|t| !find(&s.identifiers, t).is_empty()) {
                        return Err(denied());
                    }
                }
                Operation::Mask(_) | Operation::Redact => {
                    if texts.each().iter().any(|t| entirely_sensitive(t, &find(&s.identifiers, t))) {
                        return Err(denied());
                    }
                    let mask = match s.operation {
                        Operation::Mask(c) => Some(c),
                        _ => None,
                    };
                    texts.map(|t| deidentify(t, &find(&s.identifiers, t), mask));
                }
                Operation::Audit { sample_rate, findings, no_findings } => {
                    if *sample_rate == 0 || rand::random::<u32>() % 100 >= *sample_rate {
                        continue;
                    }
                    let found = find(&s.identifiers, message);
                    let dest = if found.is_empty() { no_findings } else { findings };
                    if let Some(dest) = dest {
                        let identifiers: Vec<Value> = found
                            .iter()
                            .map(|f| {
                                json!({
                                    "name": f.name,
                                    "count": f.ranges.len(),
                                    "detections": f.ranges.iter().map(|(s, e)| json!({"start": s, "end": e - 1})).collect::<Vec<_>>(),
                                })
                            })
                            .collect();
                        let record = json!({
                            "auditTimestamp": crate::delivery::timestamp(&ctx.received_at),
                            "callerPrincipal": principal,
                            "resourceArn": topic.arn,
                            "dataIdentifiers": identifiers,
                        });
                        audit = Some((dest.clone(), record));
                    }
                }
            }
        }
        Ok(Inbound { message: texts.message, structure: texts.structure, audit })
    }

    /// Write the audit finding of a message once it has its id.
    pub(crate) fn write_audit(&self, ctx: &RequestContext, topic: &Topic, inbound: &Inbound, message_id: &str) {
        let Some((dest, record)) = &inbound.audit else { return };
        let mut record = record.clone();
        record["messageId"] = Value::String(message_id.to_string());
        let line = record.to_string();
        let owner = RequestContext {
            caller: Caller {
                account_id: topic.account.clone(),
                arn: format!("arn:{}:iam::{}:root", ctx.partition, topic.account),
                user_id: topic.account.clone(),
                access_key_id: String::new(),
                kind: CallerKind::Root,
                session: None,
            },
            region: topic.region.clone(),
            source_ip: None,
            ..ctx.clone()
        };
        let result = match dest {
            Destination::Logs(group) => match self.inner.status_logs.get() {
                Some((logs, _)) => {
                    let event =
                        mws_logs::ServiceLogEvent { timestamp: ctx.received_at.timestamp_millis(), message: line };
                    logs.put_log_events_as_caller(&owner, group, &topic.name, vec![event]).map_err(|e| e.message)
                }
                None => Err("CloudWatch Logs is not wired in".to_string()),
            },
            Destination::Firehose(stream) => match self.inner.firehose.get() {
                Some(f) => f
                    .put_record(
                        &owner,
                        mws_firehose::generated::types::PutRecordInput {
                            delivery_stream_name: stream.clone(),
                            record: mws_firehose::generated::types::Record { data: format!("{line}\n").into_bytes() },
                        },
                    )
                    .map(|_| ())
                    .map_err(|e| e.message),
                None => Err("Firehose is not wired in".to_string()),
            },
            Destination::S3(bucket) => match self.inner.s3.get() {
                Some(s3) => {
                    let key = format!(
                        "AWSLogs/{}/SNSDataProtection/{}/{}/{}/{message_id}.log",
                        topic.account,
                        topic.region,
                        topic.name,
                        ctx.received_at.format("%Y/%m/%d/%H")
                    );
                    s3.put_object_as_service(mws_s3::ServicePutObject {
                        bucket,
                        key: &key,
                        body: format!("{line}\n").into_bytes(),
                        content_type: "application/json",
                        service_principal: "delivery.logs.amazonaws.com",
                        source_account: &topic.account,
                        source_arn: &topic.arn,
                        acl: Some("bucket-owner-full-control"),
                        partition: &ctx.partition,
                    })
                    .map(|_| ())
                    .map_err(|e| format!("{e:?}"))
                }
                None => Err("S3 is not wired in".to_string()),
            },
        };
        if let Err(e) = result {
            tracing::debug!(topic = %topic.arn, "data protection audit finding not written: {e}");
        }
    }

    /// Apply the topic's outbound statements to a delivery: `None` when a
    /// `Deny` statement blocks it, otherwise the message to deliver.
    pub(crate) fn protect_outbound(topic: &Topic, sub: &Subscription, msg: &Outgoing) -> Option<Outgoing> {
        let Some(policy) = Self::policy_of(topic) else { return Some(msg.clone()) };
        let mut texts = Texts { message: msg.message.clone(), structure: msg.structure.clone() };
        for s in policy.applying(false, &sub.principal) {
            match s.operation {
                Operation::Deny => {
                    if texts.each().iter().any(|t| !find(&s.identifiers, t).is_empty()) {
                        return None;
                    }
                }
                Operation::Mask(c) => texts.map(|t| deidentify(t, &find(&s.identifiers, t), Some(c))),
                Operation::Redact => texts.map(|t| deidentify(t, &find(&s.identifiers, t), None)),
                Operation::Audit { .. } => {}
            }
        }
        let mut out = msg.clone();
        out.message = texts.message;
        out.structure = texts.structure;
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY: &str = r##"{"Name":"p","Version":"2021-06-01","Statement":[
        {"DataDirection":"Inbound","Principal":["*"],"DataIdentifier":["arn:aws:dataprotection::aws:data-identifier/Ssn-US"],"Operation":{"Deidentify":{"MaskConfig":{"MaskWithCharacter":"#"}}}},
        {"DataDirection":"Inbound","Principal":["arn:aws:iam::123456789012:role/Blocked"],"DataIdentifier":["arn:aws:dataprotection::aws:data-identifier/EmailAddress"],"Operation":{"Deny":{}}}
    ]}"##;

    #[test]
    fn masks_and_denies() {
        let p = DataProtection::parse(POLICY).unwrap();
        let s: Vec<_> = p.applying(true, "arn:aws:iam::123456789012:user/alice").collect();
        assert_eq!(s.len(), 1);
        let f = find(&s[0].identifiers, "ssn: 123-45-6789");
        assert_eq!(deidentify("ssn: 123-45-6789", &f, Some('#')), "ssn: ###########");
        assert_eq!(deidentify("ssn: 123-45-6789", &f, None), "ssn: ");
        assert!(entirely_sensitive("123-45-6789", &find(&s[0].identifiers, "123-45-6789")));
        let s: Vec<_> = p.applying(true, "arn:aws:sts::123456789012:assumed-role/Blocked/session").collect();
        assert_eq!(s.len(), 2);
    }

    #[test]
    fn rejects_bad_policies() {
        let bad = |doc: &str| DataProtection::parse(doc).is_err();
        assert!(bad(
            r#"{"Name":"p","Version":"2021-06-01","Statement":[{"DataDirection":"Sideways","Principal":["*"],"DataIdentifier":["arn:aws:dataprotection::aws:data-identifier/Ssn-US"],"Operation":{"Deny":{}}}]}"#
        ));
        assert!(bad(
            r#"{"Name":"p","Version":"2021-06-01","Statement":[{"DataDirection":"Outbound","Principal":["*"],"DataIdentifier":["arn:aws:dataprotection::aws:data-identifier/Ssn-US"],"Operation":{"Audit":{"SampleRate":10}}}]}"#
        ));
        assert!(bad(
            r#"{"Name":"p","Version":"2021-06-01","Statement":[{"DataDirection":"Inbound","Principal":["*"],"DataIdentifier":["Unknown"],"Operation":{"Deny":{}}}]}"#
        ));
        assert!(bad(
            r#"{"Name":"p","Version":"2021-06-01","Statement":[{"DataDirection":"Inbound","Principal":["*"],"DataIdentifier":["arn:aws:dataprotection::aws:data-identifier/Ssn-US"],"Operation":{"Deidentify":{"MaskConfig":{"MaskWithCharacter":"?"}}}}]}"#
        ));
    }
}

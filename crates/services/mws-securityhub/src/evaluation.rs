//! Security checks: Security Hub evaluating its enabled controls against
//! the account's resources and keeping one control finding per control
//! and resource (`Compliance.Status` `PASSED`, `FAILED` or
//! `NOT_AVAILABLE`).
//!
//! AWS runs the checks through AWS Config rules, when a resource changes
//! and periodically (every 12 or 24 hours). MWS has no AWS Config: the
//! resources are read from the emulated services through a
//! [`ControlEvidence`] link, as the hub's service-linked role. A hub is
//! checked again before the next Security Hub request after
//!
//! * Security Hub is enabled, or a standard, control, control parameter or
//!   the control finding generator changes;
//! * any successful write to another service in the account
//!   ([`SecurityHub::note_change`], fed by every API call MWS handles);
//! * 12 hours on the emulated clock (`/_mws/clock`) since the last check.
//!
//! With the consolidated generator (`SECURITY_CONTROL`, the default) each
//! control yields one finding per resource, `GeneratorId`
//! `security-control/<ID>`, listing every enabled standard the control is
//! in. With `STANDARD_CONTROL` each enabled standard gets its own finding.
//! Findings of controls that are disabled, or of resources that are gone,
//! are archived.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Duration, Utc};
use mws_core::{Caller, CallerKind, RequestContext};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::catalog::{self, Control};
use crate::common::iso;
use crate::findings::{self, ImportScope};
use crate::generated::types;
use crate::state::{Hub, State};
use crate::{FindingEvent, SecurityHub};

/// How often AWS re-runs periodic checks.
pub const PERIODIC_HOURS: i64 = 12;

pub const SERVICE_PRINCIPAL: &str = "securityhub.amazonaws.com";
pub const SERVICE_LINKED_ROLE: &str = "AWSServiceRoleForSecurityHub";

/// When a hub was last checked, and whether something changed since.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct EvaluationRec {
    pub last: Option<DateTime<Utc>>,
    pub dirty: bool,
}

/// One resource's result for one control.
#[derive(Debug, Clone)]
pub struct ResourceEvaluation {
    /// The ASFF resource type: `AwsAccount`, `AwsKmsKey`, `AwsS3Bucket`, ...
    pub resource_type: String,
    /// The resource's ARN, or `AWS::::Account:<id>` for the account.
    pub resource_id: String,
    /// `PASSED`, `FAILED` or `NOT_AVAILABLE`.
    pub status: String,
    /// `(ReasonCode, Description)` for `Compliance.StatusReasons`.
    pub reason: Option<(String, String)>,
    /// `Resources[0].Details`, if any.
    pub details: Option<Value>,
}

impl ResourceEvaluation {
    pub fn new(resource_type: &str, resource_id: impl Into<String>, passed: bool) -> Self {
        Self {
            resource_type: resource_type.into(),
            resource_id: resource_id.into(),
            status: if passed { "PASSED" } else { "FAILED" }.into(),
            reason: None,
            details: None,
        }
    }

    pub fn account(account: &str, passed: bool) -> Self {
        Self::new("AwsAccount", format!("AWS::::Account:{account}"), passed)
    }

    pub fn not_available(resource_type: &str, resource_id: impl Into<String>, description: &str) -> Self {
        Self {
            resource_type: resource_type.into(),
            resource_id: resource_id.into(),
            status: "NOT_AVAILABLE".into(),
            reason: Some(("CONFIG_EVALUATIONS_EMPTY".into(), description.into())),
            details: None,
        }
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }
}

/// What Security Hub's checks read: the account's resources in the
/// emulated services. Implementations must not call back into Security
/// Hub.
#[async_trait::async_trait]
pub trait ControlEvidence: Send + Sync {
    /// The security control IDs this evidence can evaluate.
    fn evaluated_controls(&self) -> &'static [&'static str];
    /// Evaluate `control_id` in `ctx`'s account and Region (`ctx` is a
    /// session of Security Hub's service-linked role). `parameters` are
    /// the control's current parameter values by name. `None` when the
    /// control cannot be evaluated here.
    async fn evaluate(
        &self,
        ctx: &RequestContext,
        control_id: &str,
        parameters: &BTreeMap<String, Value>,
    ) -> Option<Vec<ResourceEvaluation>>;
}

/// The AWS Config rule behind each evaluated control (its name is
/// `securityhub-<rule>-<suffix>`).
fn config_rule(control_id: &str) -> &'static str {
    match control_id {
        "CloudTrail.1" => "multi-region-cloudtrail-enabled",
        "CloudTrail.2" => "cloud-trail-encryption-enabled",
        "EC2.2" => "vpc-default-security-group-closed",
        "EC2.19" => "restricted-common-ports",
        "GuardDuty.1" => "guardduty-enabled-centralized",
        "IAM.1" => "iam-policy-no-statements-with-admin-access",
        "IAM.2" => "iam-user-no-policies-check",
        "IAM.4" => "iam-root-access-key-check",
        "IAM.6" => "root-account-hardware-mfa-enabled",
        "IAM.9" => "root-account-mfa-enabled",
        "KMS.4" => "cmk-backing-key-rotation-enabled",
        "Lambda.1" => "lambda-function-public-access-prohibited",
        "RDS.3" => "rds-storage-encrypted",
        "S3.1" => "s3-account-level-public-access-blocks-periodic",
        "S3.5" => "s3-bucket-ssl-requests-only",
        "S3.8" => "s3-bucket-level-public-access-prohibited",
        "SecretsManager.1" => "secretsmanager-rotation-enabled-check",
        "SecurityHub.1" => "securityhub-enabled",
        "SNS.1" => "sns-encrypted-kms",
        "SQS.1" => "sqs-queue-encrypted",
        _ => "custom-rule",
    }
}

/// A stable hexadecimal suffix, as AWS gives each account's rules.
fn suffix(seed: &str) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    seed.hash(&mut h);
    format!("{:08x}", h.finish() as u32)
}

/// Whether a stored finding is one of Security Hub's control findings.
fn is_control_finding(f: &Value) -> bool {
    let id = f.get("Id").and_then(Value::as_str).unwrap_or_default();
    f.get("ProductArn").and_then(Value::as_str).is_some_and(|p| p.ends_with("::product/aws/securityhub"))
        && (id.contains(":security-control/") || id.contains(":subscription/"))
        && id.contains("/finding/")
}

fn str_at<'v>(f: &'v Value, path: &[&str]) -> Option<&'v str> {
    let mut v = f;
    for p in path {
        v = match p.parse::<usize>() {
            Ok(i) => v.get(i)?,
            Err(_) => v.get(p)?,
        };
    }
    v.as_str()
}

/// What one check of a hub covers.
struct Plan {
    key: String,
    account: String,
    region: String,
    periodic: bool,
    /// Controls enabled in at least one enabled standard, with their
    /// current parameters.
    controls: Vec<(&'static Control, BTreeMap<String, Value>)>,
}

fn parameter_json(v: &types::ParameterValue) -> Value {
    match v {
        types::ParameterValue::Integer(i) => json!(i),
        types::ParameterValue::IntegerList(l) => json!(l),
        types::ParameterValue::Double(d) => json!(d),
        types::ParameterValue::String(s) => json!(s),
        types::ParameterValue::StringList(l) => json!(l),
        types::ParameterValue::Boolean(b) => json!(b),
        types::ParameterValue::Enum(s) => json!(s),
        types::ParameterValue::EnumList(l) => json!(l),
    }
}

/// The enabled standards a control is enabled in: `(standard, standards
/// ARN, subscription ARN, the standard's control ID, requirements)`.
fn enabled_in(
    h: &Hub,
    partition: &str,
    c: &Control,
) -> Vec<(&'static catalog::Standard, String, String, &'static str, &'static [&'static str])> {
    c.in_standards
        .iter()
        .filter_map(|(key, cid, reqs)| {
            let s = catalog::standard(key)?;
            let standards_arn = catalog::standards_arn(partition, &h.region, s);
            let (sub_arn, _) = h.standards.iter().find(|(_, x)| x.standards_arn == standards_arn)?;
            let (status, _) = crate::standards::association_status(h, &standards_arn, c.id);
            (status == "ENABLED").then(|| (s, standards_arn.clone(), sub_arn.clone(), *cid, *reqs))
        })
        .collect()
}

fn standards_id(standards_arn: &str) -> String {
    standards_arn.splitn(6, ':').nth(5).unwrap_or_default().to_string()
}

impl SecurityHub {
    /// Something changed in `account` (a successful write to another
    /// service): check its hubs again before the next Security Hub call.
    pub fn note_change(&self, account: &str) {
        let Ok(mut state) = self.inner.state.try_write() else {
            // Security Hub itself is busy; mark it on the next call.
            self.inner.pending_changes.lock().expect("pending changes lock").insert(account.to_string());
            return;
        };
        for h in state.hubs.values_mut().filter(|h| h.account == account) {
            h.evaluation.dirty = true;
        }
    }

    /// Run the checks that are due, in every hub.
    pub(crate) async fn evaluate_due(&self, ctx: &RequestContext) {
        let Some(evidence) = self.inner.evidence.get().cloned() else { return };
        let now = ctx.received_at;
        let pending: BTreeSet<String> =
            std::mem::take(&mut *self.inner.pending_changes.lock().expect("pending changes lock"));
        let plans: Vec<Plan> = {
            let mut state = self.write();
            let evaluable = evidence.evaluated_controls();
            let partition = ctx.partition.clone();
            let mut plans = Vec::new();
            for (key, h) in state.hubs.iter_mut() {
                if pending.contains(&h.account) {
                    h.evaluation.dirty = true;
                }
                let periodic = h.evaluation.last.is_none_or(|t| now - t >= Duration::hours(PERIODIC_HOURS));
                if !periodic && !h.evaluation.dirty {
                    continue;
                }
                // Claimed now, so concurrent requests do not check it twice;
                // changes made meanwhile mark it again.
                let rechecked = h.evaluation.last.is_some();
                h.evaluation.dirty = false;
                h.evaluation.last = Some(now);
                let controls = catalog::controls()
                    .iter()
                    .filter(|c| evaluable.contains(&c.id) || c.id == "SecurityHub.1")
                    .filter(|c| !enabled_in(h, &partition, c).is_empty())
                    .map(|c| {
                        let params = crate::standards::current_parameters(h, c)
                            .into_iter()
                            .filter_map(|(k, v)| v.value.as_ref().map(|v| (k, parameter_json(v))))
                            .collect();
                        (c, params)
                    })
                    .collect();
                plans.push(Plan {
                    key: key.clone(),
                    account: h.account.clone(),
                    region: h.region.clone(),
                    periodic: periodic && rechecked,
                    controls,
                });
            }
            plans
        };
        for plan in plans {
            let hctx = service_linked_context(ctx, &plan.account, &plan.region);
            let mut results: BTreeMap<&'static str, Vec<ResourceEvaluation>> = BTreeMap::new();
            for (c, params) in &plan.controls {
                if c.id == "SecurityHub.1" {
                    results.insert(c.id, vec![ResourceEvaluation::account(&plan.account, true)]);
                    continue;
                }
                if let Some(r) = evidence.evaluate(&hctx, c.id, params).await {
                    results.insert(c.id, r);
                }
            }
            let events = {
                let mut state = self.write();
                apply(&mut state, &hctx, &plan, results, now)
            };
            self.publish(&hctx, events);
        }
    }
}

/// A session of Security Hub's service-linked role in `account`.
pub fn service_linked_context(ctx: &RequestContext, account: &str, region: &str) -> RequestContext {
    let role_id = format!("AROA{}", suffix(account).to_uppercase());
    RequestContext {
        region: region.to_string(),
        caller: Caller {
            account_id: account.to_string(),
            arn: format!("arn:{}:sts::{account}:assumed-role/{SERVICE_LINKED_ROLE}/securityhub", ctx.partition),
            user_id: format!("{role_id}:securityhub"),
            access_key_id: String::new(),
            kind: CallerKind::AssumedRole { role_name: SERVICE_LINKED_ROLE.into(), session_name: "securityhub".into() },
            session: None,
        },
        source_ip: None,
        ..ctx.clone()
    }
}

/// One control finding Security Hub wants to exist.
struct Desired {
    generator: String,
    resource_id: String,
    finding: Value,
}

/// Turn the results into findings: new, updated (status changed, or a
/// periodic check), and archived.
fn apply(
    state: &mut State,
    ctx: &RequestContext,
    plan: &Plan,
    results: BTreeMap<&'static str, Vec<ResourceEvaluation>>,
    now: DateTime<Utc>,
) -> Vec<FindingEvent> {
    let partition = ctx.partition.as_str();
    let Some(h) = state.hubs.get(&plan.key) else { return Vec::new() };
    let product_arn = format!("arn:{partition}:securityhub:{}::product/aws/securityhub", plan.region);
    let consolidated = h.control_finding_generator != "STANDARD_CONTROL";

    // Existing control findings by (generator, resource).
    let mut existing: BTreeMap<(String, String), Value> = BTreeMap::new();
    for rec in h.findings.values() {
        let f = &rec.finding;
        if !is_control_finding(f) {
            continue;
        }
        let g = f.get("GeneratorId").and_then(Value::as_str).unwrap_or_default().to_string();
        let r = str_at(f, &["Resources", "0", "Id"]).unwrap_or_default().to_string();
        existing.insert((g, r), f.clone());
    }

    let mut desired: Vec<Desired> = Vec::new();
    for (c, params) in &plan.controls {
        let Some(evals) = results.get(c.id) else { continue };
        let standards = enabled_in(h, partition, c);
        for e in evals {
            if consolidated {
                let generator = format!("security-control/{}", c.id);
                let requirements: Vec<&str> = {
                    let mut seen = BTreeSet::new();
                    standards.iter().flat_map(|s| s.4.iter().copied()).filter(|r| seen.insert(*r)).collect()
                };
                let associated: Vec<Value> =
                    standards.iter().map(|s| json!({"StandardsId": standards_id(&s.1)})).collect();
                let id_base =
                    format!("arn:{partition}:securityhub:{}:{}:security-control/{}", plan.region, plan.account, c.id);
                let mut pf = serde_json::Map::new();
                pf.insert(
                    "RelatedAWSResources:0/name".into(),
                    json!(format!(
                        "securityhub-{}-{}",
                        config_rule(c.id),
                        suffix(&format!("{}{}", plan.account, c.id))
                    )),
                );
                pf.insert("RelatedAWSResources:0/type".into(), json!("AWS::Config::ConfigRule"));
                pf.insert("Resources:0/Id".into(), json!(e.resource_id));
                let title = c.title.to_string();
                desired.push(Desired {
                    generator: generator.clone(),
                    resource_id: e.resource_id.clone(),
                    finding: build(
                        partition,
                        plan,
                        &product_arn,
                        &id_base,
                        &generator,
                        &title,
                        c,
                        e,
                        params,
                        Value::Object(pf),
                        json!(requirements),
                        json!(associated),
                        now,
                    ),
                });
            } else {
                for (s, standards_arn, sub_arn, cid, reqs) in &standards {
                    let generator =
                        if s.ruleset { format!("{standards_arn}/rule/{cid}") } else { format!("{}/{cid}", s.key) };
                    let id_base = format!("{sub_arn}/{cid}");
                    let mut pf = serde_json::Map::new();
                    if s.ruleset {
                        pf.insert("StandardsGuideArn".into(), json!(standards_arn));
                        pf.insert("StandardsGuideSubscriptionArn".into(), json!(sub_arn));
                        pf.insert("RuleId".into(), json!(cid));
                    } else {
                        pf.insert("StandardsArn".into(), json!(standards_arn));
                        pf.insert("StandardsSubscriptionArn".into(), json!(sub_arn));
                        pf.insert("ControlId".into(), json!(cid));
                        pf.insert(
                            "StandardsControlArn".into(),
                            json!(format!(
                                "arn:{partition}:securityhub:{}:{}:control/{}/{cid}",
                                plan.region, plan.account, s.key
                            )),
                        );
                    }
                    pf.insert("RecommendationUrl".into(), json!(catalog::remediation_url(c)));
                    pf.insert(
                        "RelatedAWSResources:0/name".into(),
                        json!(format!(
                            "securityhub-{}-{}",
                            config_rule(c.id),
                            suffix(&format!("{}{}", plan.account, c.id))
                        )),
                    );
                    pf.insert("RelatedAWSResources:0/type".into(), json!("AWS::Config::ConfigRule"));
                    pf.insert("Resources:0/Id".into(), json!(e.resource_id));
                    desired.push(Desired {
                        generator: generator.clone(),
                        resource_id: e.resource_id.clone(),
                        finding: build(
                            partition,
                            plan,
                            &product_arn,
                            &id_base,
                            &generator,
                            &format!("{cid} {}", c.title),
                            c,
                            e,
                            params,
                            Value::Object(pf),
                            json!(reqs),
                            json!([{"StandardsId": standards_id(standards_arn)}]),
                            now,
                        ),
                    });
                }
            }
        }
    }

    let enabled_ids: BTreeSet<&str> = plan.controls.iter().map(|(c, _)| c.id).collect();
    let evaluated_ids: BTreeSet<&str> = results.keys().copied().collect();
    let mut wanted: BTreeSet<(String, String)> = BTreeSet::new();
    let mut imports: Vec<(String, Value)> = Vec::new();
    for mut d in desired {
        let k = (d.generator.clone(), d.resource_id.clone());
        wanted.insert(k.clone());
        if let Some(old) = existing.get(&k) {
            let same = str_at(old, &["Compliance", "Status"]) == str_at(&d.finding, &["Compliance", "Status"])
                && str_at(old, &["RecordState"]) == Some("ACTIVE");
            if same && !plan.periodic {
                continue;
            }
            for field in ["Id", "CreatedAt", "FirstObservedAt"] {
                if let Some(v) = old.get(field) {
                    d.finding[field] = v.clone();
                }
            }
        }
        let id = d.finding["Id"].as_str().unwrap_or_default().to_string();
        imports.push((id, d.finding));
    }
    // Archive what is no longer checked: disabled controls, resources gone,
    // findings of the other generator.
    for ((g, r), old) in &existing {
        if wanted.contains(&(g.clone(), r.clone())) || str_at(old, &["RecordState"]) != Some("ACTIVE") {
            continue;
        }
        let control = str_at(old, &["Compliance", "SecurityControlId"]).unwrap_or_default();
        let generator_changed = consolidated != g.starts_with("security-control/");
        if enabled_ids.contains(control) && !evaluated_ids.contains(control) && !generator_changed {
            continue;
        }
        let mut f = old.clone();
        f["RecordState"] = json!("ARCHIVED");
        f["UpdatedAt"] = json!(iso(now));
        let id = f["Id"].as_str().unwrap_or_default().to_string();
        imports.push((id, f));
    }
    if imports.is_empty() {
        return Vec::new();
    }
    let scope =
        ImportScope { partition, account: &plan.account, region: &plan.region, now, identity: SERVICE_PRINCIPAL };
    let (result, events) = findings::import_all(state, &scope, imports);
    for (id, code, message) in result.failed {
        tracing::warn!(id, code, "Security Hub could not record a control finding: {message}");
    }
    events
}

#[allow(clippy::too_many_arguments)]
fn build(
    partition: &str,
    plan: &Plan,
    product_arn: &str,
    id_base: &str,
    generator: &str,
    title: &str,
    c: &Control,
    e: &ResourceEvaluation,
    params: &BTreeMap<String, Value>,
    product_fields: Value,
    requirements: Value,
    associated: Value,
    now: DateTime<Utc>,
) -> Value {
    let id = format!("{id_base}/finding/{}", uuid::Uuid::new_v4());
    let passed = e.status == "PASSED";
    let label = if passed { "INFORMATIONAL" } else { c.severity };
    let normalized = findings::normalized_for(label).unwrap_or(0);
    let mut resource = json!({
        "Type": e.resource_type,
        "Id": e.resource_id,
        "Partition": partition,
        "Region": plan.region,
    });
    if let Some(d) = &e.details {
        resource["Details"] = d.clone();
    }
    let mut compliance = json!({
        "Status": e.status,
        "SecurityControlId": c.id,
        "RelatedRequirements": requirements,
        "AssociatedStandards": associated,
    });
    if let Some((code, description)) = &e.reason {
        compliance["StatusReasons"] = json!([{"ReasonCode": code, "Description": description}]);
    }
    if !params.is_empty() {
        let ps: Vec<Value> = params
            .iter()
            .map(|(k, v)| {
                let values: Vec<String> = match v {
                    Value::Array(a) => {
                        a.iter().map(|x| x.as_str().map_or_else(|| x.to_string(), str::to_string)).collect()
                    }
                    Value::String(s) => vec![s.clone()],
                    other => vec![other.to_string()],
                };
                json!({"Name": k, "Value": values})
            })
            .collect();
        compliance["SecurityControlParameters"] = json!(ps);
    }
    let types = json!(["Software and Configuration Checks/Industry and Regulatory Standards"]);
    json!({
        "SchemaVersion": "2018-10-08",
        "Id": id,
        "ProductArn": product_arn,
        "GeneratorId": generator,
        "AwsAccountId": plan.account,
        "Types": types,
        "FirstObservedAt": iso(now),
        "LastObservedAt": iso(now),
        "CreatedAt": iso(now),
        "UpdatedAt": iso(now),
        "Severity": {"Label": label, "Normalized": normalized, "Original": c.severity},
        "Title": title,
        "Description": catalog::description(c),
        "Remediation": {"Recommendation": {
            "Text": "For information on how to correct this issue, consult the AWS Security Hub controls documentation.",
            "Url": catalog::remediation_url(c),
        }},
        "ProductFields": product_fields,
        "Resources": [resource],
        "Compliance": compliance,
        "RecordState": "ACTIVE",
        "FindingProviderFields": {"Severity": {"Label": label, "Original": c.severity}, "Types": types},
    })
}

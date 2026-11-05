//! Findings: import (ASFF), retrieval with filters and sorting, workflow
//! updates, history, insights, and the events they produce.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use mws_core::{RequestContext, ServiceError};
use serde_json::{json, Map, Value};

use crate::catalog;
use crate::common::{self, account, authorize, authorize_hub, hub, invalid_input, iso, not_found, paginate};
use crate::filters;
use crate::generated::{json_de, json_ser, types};
use crate::state::{FindingRec, HistoryRec, InsightRec, State};
use crate::{FindingEvent, SecurityHub};

pub const SCHEMA_VERSION: &str = "2018-10-08";
pub const IMPORTED: &str = "Security Hub Findings - Imported";

/// Fields `BatchUpdateFindings` owns: once a customer sets them, provider
/// imports no longer change them.
const CUSTOMER_FIELDS: &[&str] =
    &["Note", "UserDefinedFields", "VerificationState", "Workflow", "Severity", "Confidence", "Criticality", "Types", "RelatedFindings"];

/// What [`SecurityHub::import_findings_as_service`] did.
#[derive(Debug, Clone, Default)]
pub struct ServiceImportResult {
    pub success_count: usize,
    /// `(finding id, error code, message)`.
    pub failed: Vec<(String, String, String)>,
}

pub fn finding_key(product_arn: &str, id: &str) -> String {
    format!("{product_arn}\n{id}")
}

/// `aws/securityhub/FindingId`: the finding's global identifier.
pub fn finding_arn(product_arn: &str, id: &str) -> String {
    format!("{product_arn}/{id}")
}

pub fn label_for(normalized: i64) -> &'static str {
    match normalized {
        i64::MIN..=0 => "INFORMATIONAL",
        1..=39 => "LOW",
        40..=69 => "MEDIUM",
        70..=89 => "HIGH",
        _ => "CRITICAL",
    }
}

pub fn normalized_for(label: &str) -> Option<i64> {
    Some(match label {
        "INFORMATIONAL" => 0,
        "LOW" => 1,
        "MEDIUM" => 40,
        "HIGH" => 70,
        "CRITICAL" => 90,
        _ => return None,
    })
}

/// Fill in whichever of `Label` and `Normalized` is missing.
fn complete_severity(sev: &mut Map<String, Value>) {
    match (sev.get("Label").and_then(Value::as_str).map(str::to_string), sev.get("Normalized").and_then(Value::as_i64)) {
        (Some(l), None) => {
            if let Some(n) = normalized_for(&l) {
                sev.insert("Normalized".into(), json!(n));
            }
        }
        (None, Some(n)) => {
            sev.insert("Label".into(), json!(label_for(n)));
        }
        _ => {}
    }
}

pub fn to_wire(v: &Value) -> types::AwsSecurityFinding {
    let mut d = mws_proto_json::Decoder::new();
    json_de::de_aws_security_finding(&mut d, Some(v), "").unwrap_or_default()
}

/// The product a product ARN names: a catalogue product, or the account's
/// own default product (`product/<account>/default`).
pub enum ProductRef {
    Catalog(&'static catalog::Product),
    Default { account: String },
}

pub fn product_of(arn: &str, region: &str) -> Option<ProductRef> {
    let parts: Vec<&str> = arn.splitn(6, ':').collect();
    if parts.len() != 6 || parts[0] != "arn" || parts[2] != "securityhub" || parts[3] != region {
        return None;
    }
    let key = parts[5].strip_prefix("product/")?;
    if let Some((acct, "default")) = key.split_once('/') {
        if acct == parts[4] && common::is_account_id(acct) {
            return Some(ProductRef::Default { account: acct.to_string() });
        }
        return None;
    }
    if !parts[4].is_empty() {
        return None;
    }
    catalog::product(key).map(ProductRef::Catalog)
}

/// Product subscription ARN for a catalogue product in the caller's hub.
pub fn subscription_arn(partition: &str, region: &str, account: &str, key: &str) -> String {
    format!("arn:{partition}:securityhub:{region}:{account}:product-subscription/{key}")
}

/// The hubs whose findings an account sees from a Region: its own, its
/// enabled members', and (in a finding aggregation Region) the linked
/// Regions' of all of those.
pub fn visible_keys(state: &State, account: &str, region: &str) -> Vec<String> {
    let mut accounts = vec![account.to_string()];
    if let Some(members) = state.members.get(&crate::state::key(account, region)) {
        accounts.extend(members.iter().filter(|(_, m)| m.status == "Enabled").map(|(a, _)| a.clone()));
    }
    let mut regions = vec![region.to_string()];
    if let Some(agg) = state.hub(account, region).and_then(|h| h.finding_aggregator.as_ref()) {
        let mut all: BTreeSet<String> = BTreeSet::new();
        for k in state.hubs.keys() {
            if let Some((a, r)) = k.split_once('/') {
                if accounts.iter().any(|x| x == a) && r != region {
                    all.insert(r.to_string());
                }
            }
        }
        for r in all {
            let linked = match agg.region_linking_mode.as_str() {
                "ALL_REGIONS" => true,
                "ALL_REGIONS_EXCEPT_SPECIFIED" => !agg.regions.contains(&r),
                "SPECIFIED_REGIONS" => agg.regions.contains(&r),
                _ => false,
            };
            if linked {
                regions.push(r);
            }
        }
    }
    let mut out = Vec::new();
    for a in &accounts {
        for r in &regions {
            let k = crate::state::key(a, r);
            if state.hubs.contains_key(&k) {
                out.push(k);
            }
        }
    }
    out
}

/// Visible findings, as `(hub key, finding key, finding)`.
pub fn visible_findings<'s>(state: &'s State, account: &str, region: &str) -> Vec<(String, String, &'s FindingRec)> {
    let mut out = Vec::new();
    for k in visible_keys(state, account, region) {
        if let Some(h) = state.hubs.get(&k) {
            for (fk, f) in &h.findings {
                out.push((k.clone(), fk.clone(), f));
            }
        }
    }
    out
}

/// Flatten the history-relevant top-level fields of a finding into
/// `field -> JSON text`, one level into objects (`Workflow.Status`).
fn history_fields(f: &Value) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(obj) = f.as_object() else { return out };
    for (k, v) in obj {
        if matches!(k.as_str(), "ProcessedAt" | "ProductFields") {
            continue;
        }
        match v {
            Value::Object(inner) if k != "UserDefinedFields" && k != "Resources" => {
                for (ik, iv) in inner {
                    out.insert(format!("{k}.{ik}"), text(iv));
                }
            }
            v => {
                out.insert(k.clone(), text(v));
            }
        }
    }
    out
}

fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        v => v.to_string(),
    }
}

pub fn diff(old: &Value, new: &Value) -> Vec<(String, Option<String>, Option<String>)> {
    let a = history_fields(old);
    let b = history_fields(new);
    let keys: BTreeSet<&String> = a.keys().chain(b.keys()).collect();
    keys.into_iter()
        .filter(|k| a.get(*k) != b.get(*k))
        .map(|k| ((*k).clone(), a.get(k).cloned(), b.get(k).cloned()))
        .collect()
}

/// Everything an import needs to know about where it happens.
pub struct ImportScope<'a> {
    pub partition: &'a str,
    pub account: &'a str,
    pub region: &'a str,
    pub now: DateTime<Utc>,
    /// Who imported (caller ARN or service principal), for history.
    pub identity: &'a str,
}

/// Validate and shape one finding the way Security Hub does, merge it
/// with an existing one, run automation rules, store it and return the
/// event to publish. Errors are `(code, message)`.
pub fn import_one(state: &mut State, scope: &ImportScope<'_>, mut f: Value) -> Result<FindingEvent, (String, String)> {
    let bad = |m: &str| ("InvalidInput".to_string(), format!("Finding does not adhere to Amazon Security Finding Format. {m}"));
    let obj = f.as_object_mut().ok_or_else(|| bad("data should be object"))?;
    let id = obj.get("Id").and_then(Value::as_str).unwrap_or_default().to_string();
    let product_arn = obj.get("ProductArn").and_then(Value::as_str).unwrap_or_default().to_string();
    if obj.get("SchemaVersion").and_then(Value::as_str) != Some(SCHEMA_VERSION) {
        return Err(bad("data.SchemaVersion should be equal to one of the allowed values"));
    }
    if obj.get("AwsAccountId").and_then(Value::as_str) != Some(scope.account) {
        return Err((
            "AccessDeniedException".into(),
            format!("The AwsAccountId of the finding must be the account that imports it ({}).", scope.account),
        ));
    }
    for field in ["CreatedAt", "UpdatedAt", "FirstObservedAt", "LastObservedAt"] {
        if let Some(t) = obj.get(field) {
            if t.as_str().and_then(common::parse_time).is_none() {
                return Err(bad(&format!("data.{field} should match format \"date-time\"")));
            }
        }
    }
    let sev = obj.get("Severity").and_then(Value::as_object);
    if sev.is_none_or(|s| s.get("Label").is_none() && s.get("Normalized").is_none()) {
        return Err(bad("data.Severity should have required property 'Label'"));
    }
    if obj.get("Resources").and_then(Value::as_array).is_none_or(|r| r.is_empty()) {
        return Err(bad("data.Resources should NOT have fewer than 1 items"));
    }
    let key = crate::state::key(scope.account, scope.region);
    let hub = state.hubs.get(&key).ok_or_else(|| ("InvalidAccessException".to_string(), format!("Account {} is not subscribed to AWS Security Hub", scope.account)))?;
    let (product_name, company_name) = match product_of(&product_arn, scope.region) {
        Some(ProductRef::Default { .. }) => ("Default".to_string(), "Personal".to_string()),
        Some(ProductRef::Catalog(p)) => {
            if !hub.products.contains(&product_arn) {
                return Err((
                    "InvalidAccessException".into(),
                    format!("Product {product_arn} is not enabled for importing findings in account {}.", scope.account),
                ));
            }
            (p.name.to_string(), p.company.to_string())
        }
        None => return Err(("InvalidInput".into(), format!("Invalid ProductArn {product_arn}."))),
    };

    // Security Hub's own fields.
    obj.insert("ProductName".into(), json!(product_name));
    obj.insert("CompanyName".into(), json!(company_name));
    obj.insert("Region".into(), json!(scope.region));
    obj.insert("ProcessedAt".into(), json!(iso(scope.now)));
    let pf = obj.entry("ProductFields").or_insert_with(|| json!({}));
    if let Some(pf) = pf.as_object_mut() {
        pf.insert("aws/securityhub/FindingId".into(), json!(finding_arn(&product_arn, &id)));
        pf.insert("aws/securityhub/ProductName".into(), json!(product_name));
        pf.insert("aws/securityhub/CompanyName".into(), json!(company_name));
    }
    if let Some(sev) = obj.get_mut("Severity").and_then(Value::as_object_mut) {
        complete_severity(sev);
    }
    if !obj.contains_key("FindingProviderFields") {
        let mut fpf = Map::new();
        if let Some(sev) = obj.get("Severity").and_then(Value::as_object) {
            let mut s = Map::new();
            if let Some(l) = sev.get("Label") {
                s.insert("Label".into(), l.clone());
            }
            if let Some(o) = sev.get("Original") {
                s.insert("Original".into(), o.clone());
            }
            fpf.insert("Severity".into(), Value::Object(s));
        }
        for k in ["Types", "Confidence", "Criticality", "RelatedFindings"] {
            if let Some(v) = obj.get(k) {
                fpf.insert(k.into(), v.clone());
            }
        }
        obj.insert("FindingProviderFields".into(), Value::Object(fpf));
    }
    obj.entry("RecordState").or_insert_with(|| json!("ACTIVE"));

    let fkey = finding_key(&product_arn, &id);
    let existing = hub.findings.get(&fkey).cloned();
    let mut rec = match existing {
        None => {
            obj.entry("WorkflowState").or_insert_with(|| json!("NEW"));
            obj.entry("Workflow").or_insert_with(|| json!({"Status": "NEW"}));
            let mut rec = FindingRec { finding: f, history: Vec::new(), customer_fields: BTreeSet::new(), v2: Default::default() };
            rec.history.push(HistoryRec {
                time: scope.now,
                created: true,
                source_type: "BATCH_IMPORT_FINDINGS".into(),
                identity: scope.identity.to_string(),
                updates: Vec::new(),
            });
            rec
        }
        Some(mut old) => {
            let prev = old.finding.clone();
            for field in &old.customer_fields {
                match prev.get(field) {
                    Some(v) => {
                        obj.insert(field.clone(), v.clone());
                    }
                    None => {
                        obj.remove(field);
                    }
                }
            }
            // Fields only Security Hub and customers manage.
            for field in ["Workflow", "WorkflowState", "Note"] {
                if !obj.contains_key(field) {
                    if let Some(v) = prev.get(field) {
                        obj.insert(field.into(), v.clone());
                    }
                }
            }
            let status = |v: &Value, p: &str| filters::values_at(v, p).first().and_then(|x| x.as_str()).map(str::to_string);
            let was_archived = status(&prev, "RecordState").as_deref() == Some("ARCHIVED");
            let now_active = obj.get("RecordState").and_then(Value::as_str) == Some("ACTIVE");
            let old_compliance = status(&prev, "Compliance.Status");
            let new_compliance = obj.get("Compliance").and_then(|c| c.get("Status")).and_then(Value::as_str).map(str::to_string);
            let workflow = obj.get("Workflow").and_then(|w| w.get("Status")).and_then(Value::as_str).unwrap_or("NEW").to_string();
            let mut new_workflow = None;
            if matches!(workflow.as_str(), "NOTIFIED" | "RESOLVED") {
                let reopened = was_archived && now_active;
                let failing = old_compliance.as_deref() == Some("PASSED")
                    && matches!(new_compliance.as_deref(), Some("FAILED" | "WARNING" | "NOT_AVAILABLE"));
                if reopened || failing {
                    new_workflow = Some("NEW");
                }
            }
            if new_compliance.as_deref() == Some("PASSED") && matches!(workflow.as_str(), "NEW" | "NOTIFIED") {
                new_workflow = Some("RESOLVED");
            }
            if let Some(w) = new_workflow {
                obj.insert("Workflow".into(), json!({"Status": w}));
                obj.insert("WorkflowState".into(), json!(if w == "RESOLVED" { "RESOLVED" } else { "NEW" }));
            }
            let updates = diff(&prev, &f);
            old.finding = f;
            old.history.push(HistoryRec {
                time: scope.now,
                created: false,
                source_type: "BATCH_IMPORT_FINDINGS".into(),
                identity: scope.identity.to_string(),
                updates,
            });
            old
        }
    };

    crate::automation::apply_rules(state, scope, &mut rec);
    let event = finding_event(scope.partition, scope.account, scope.region, &rec.finding, scope.now);
    state.hubs.get_mut(&key).expect("hub exists").findings.insert(fkey, rec);
    Ok(event)
}

pub fn finding_event(partition: &str, account: &str, region: &str, finding: &Value, now: DateTime<Utc>) -> FindingEvent {
    let fid = finding
        .get("ProductFields")
        .and_then(|p| p.get("aws/securityhub/FindingId"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    FindingEvent {
        partition: partition.to_string(),
        account: account.to_string(),
        region: region.to_string(),
        detail_type: IMPORTED.into(),
        resources: vec![fid],
        detail: json!({ "findings": [finding] }),
        time: now,
    }
}

/// The customer-owned updates of `BatchUpdateFindings` (or an automation
/// rule's `FindingFieldsUpdate`), as ASFF JSON fields.
#[derive(Default)]
pub struct FieldUpdates {
    pub note: Option<(String, String)>,
    pub severity: Option<Map<String, Value>>,
    pub verification_state: Option<String>,
    pub confidence: Option<i32>,
    pub criticality: Option<i32>,
    pub types: Option<Vec<String>>,
    pub user_defined_fields: Option<BTreeMap<String, String>>,
    pub workflow_status: Option<String>,
    pub related_findings: Option<Vec<types::RelatedFinding>>,
}

impl FieldUpdates {
    pub fn is_empty(&self) -> bool {
        self.note.is_none()
            && self.severity.is_none()
            && self.verification_state.is_none()
            && self.confidence.is_none()
            && self.criticality.is_none()
            && self.types.is_none()
            && self.user_defined_fields.is_none()
            && self.workflow_status.is_none()
            && self.related_findings.is_none()
    }

    pub fn severity_from(normalized: Option<i32>, product: Option<f64>, label: Option<String>) -> Option<Map<String, Value>> {
        if normalized.is_none() && product.is_none() && label.is_none() {
            return None;
        }
        let mut m = Map::new();
        if let Some(n) = normalized {
            m.insert("Normalized".into(), json!(n));
        }
        if let Some(p) = product {
            m.insert("Product".into(), json!(p));
        }
        if let Some(l) = label {
            m.insert("Label".into(), json!(l));
        }
        Some(m)
    }

    /// Apply to a finding; returns the history updates.
    pub fn apply(&self, rec: &mut FindingRec, updated_by_default: &str, now: DateTime<Utc>) -> Vec<(String, Option<String>, Option<String>)> {
        let before = rec.finding.clone();
        let Some(obj) = rec.finding.as_object_mut() else { return Vec::new() };
        let mut touched = Vec::new();
        if let Some((text, by)) = &self.note {
            let by = if by.is_empty() { updated_by_default } else { by };
            obj.insert("Note".into(), json!({"Text": text, "UpdatedBy": by, "UpdatedAt": iso(now)}));
            touched.push("Note");
        }
        if let Some(sev) = &self.severity {
            let mut s = obj.get("Severity").and_then(Value::as_object).cloned().unwrap_or_default();
            let label_given = sev.contains_key("Label");
            let normalized_given = sev.contains_key("Normalized");
            for (k, v) in sev {
                s.insert(k.clone(), v.clone());
            }
            if label_given && !normalized_given {
                if let Some(n) = s.get("Label").and_then(Value::as_str).and_then(normalized_for) {
                    s.insert("Normalized".into(), json!(n));
                }
            } else if normalized_given && !label_given {
                if let Some(n) = s.get("Normalized").and_then(Value::as_i64) {
                    s.insert("Label".into(), json!(label_for(n)));
                }
            }
            obj.insert("Severity".into(), Value::Object(s));
            touched.push("Severity");
        }
        if let Some(v) = &self.verification_state {
            obj.insert("VerificationState".into(), json!(v));
            touched.push("VerificationState");
        }
        if let Some(v) = self.confidence {
            obj.insert("Confidence".into(), json!(v));
            touched.push("Confidence");
        }
        if let Some(v) = self.criticality {
            obj.insert("Criticality".into(), json!(v));
            touched.push("Criticality");
        }
        if let Some(v) = &self.types {
            obj.insert("Types".into(), json!(v));
            touched.push("Types");
        }
        if let Some(v) = &self.user_defined_fields {
            let mut m = obj.get("UserDefinedFields").and_then(Value::as_object).cloned().unwrap_or_default();
            for (k, val) in v {
                m.insert(k.clone(), json!(val));
            }
            obj.insert("UserDefinedFields".into(), Value::Object(m));
            touched.push("UserDefinedFields");
        }
        if let Some(v) = &self.workflow_status {
            obj.insert("Workflow".into(), json!({"Status": v}));
            let state = match v.as_str() {
                "NEW" => "NEW",
                "NOTIFIED" => "IN_PROGRESS",
                "SUPPRESSED" => "DEFERRED",
                _ => "RESOLVED",
            };
            obj.insert("WorkflowState".into(), json!(state));
            touched.push("Workflow");
        }
        if let Some(v) = &self.related_findings {
            let list: Vec<Value> = v.iter().map(|r| json!({"ProductArn": r.product_arn, "Id": r.id})).collect();
            obj.insert("RelatedFindings".into(), Value::Array(list));
            touched.push("RelatedFindings");
        }
        for t in touched {
            rec.customer_fields.insert(t.to_string());
        }
        diff(&before, &rec.finding)
    }
}

impl SecurityHub {
    pub(crate) fn batch_import_findings_op(
        &self,
        ctx: &RequestContext,
        input: types::BatchImportFindingsRequest,
    ) -> Result<types::BatchImportFindingsResponse, ServiceError> {
        if input.findings.is_empty() || input.findings.len() > 100 {
            return Err(invalid_input("BatchImportFindings accepts between 1 and 100 findings."));
        }
        let mut products: Vec<&str> = input.findings.iter().map(|f| f.product_arn.as_str()).collect();
        products.sort();
        products.dedup();
        for p in products {
            authorize(ctx, "BatchImportFindings", p)?;
        }
        let jsons: Vec<(String, Value)> =
            input.findings.iter().map(|f| (f.id.clone(), json_ser::ser_aws_security_finding(f))).collect();
        let (result, events) = {
            let mut state = self.write();
            hub(&state, ctx)?;
            let scope = ImportScope {
                partition: &ctx.partition,
                account: account(ctx),
                region: &ctx.region,
                now: ctx.received_at,
                identity: &ctx.caller.arn,
            };
            import_all(&mut state, &scope, jsons)
        };
        self.publish(ctx, events);
        Ok(types::BatchImportFindingsResponse {
            success_count: result.success_count as i32,
            failed_count: result.failed.len() as i32,
            failed_findings: Some(
                result
                    .failed
                    .into_iter()
                    .map(|(id, error_code, error_message)| types::ImportFindingsError { id, error_code, error_message })
                    .collect(),
            ),
        })
    }

    /// Import findings another AWS service produced (GuardDuty, ...) into
    /// `account`'s hub in `region`, as product `product_key`
    /// (`aws/guardduty`). Findings are ASFF JSON. Nothing is imported when
    /// the account has not enabled Security Hub there, or has turned off
    /// imports from the product.
    pub fn import_findings_as_service(
        &self,
        ctx: &RequestContext,
        account: &str,
        region: &str,
        product_key: &str,
        service_principal: &str,
        findings: Vec<Value>,
    ) -> ServiceImportResult {
        let mut result = ServiceImportResult::default();
        let product_arn = format!("arn:{}:securityhub:{region}::product/{product_key}", ctx.partition);
        let mut jsons = Vec::new();
        for f in findings {
            let id = f.get("Id").and_then(Value::as_str).unwrap_or_default().to_string();
            let mut d = mws_proto_json::Decoder::new();
            let typed = json_de::de_aws_security_finding(&mut d, Some(&f), "");
            match (typed, d.finish("InvalidInput")) {
                (Some(t), Ok(())) if t.product_arn == product_arn => {
                    jsons.push((id, json_ser::ser_aws_security_finding(&t)));
                }
                (_, Err(e)) => result.failed.push((id, "InvalidInput".into(), e.message)),
                _ => result.failed.push((id, "InvalidInput".into(), format!("ProductArn must be {product_arn}"))),
            }
        }
        let events = {
            let mut state = self.write();
            let Some(hub) = state.hub(account, region) else { return result };
            if !hub.products.contains(&product_arn) {
                return result;
            }
            let scope = ImportScope { partition: &ctx.partition, account, region, now: ctx.received_at, identity: service_principal };
            let (r, events) = import_all(&mut state, &scope, jsons);
            result.success_count = r.success_count;
            result.failed.extend(r.failed);
            events
        };
        let ctx = RequestContext { region: region.to_string(), ..ctx.clone() };
        self.publish(&ctx, events);
        result
    }

    pub(crate) fn publish(&self, ctx: &RequestContext, events: Vec<FindingEvent>) {
        if let Some(sink) = self.inner.events.get() {
            for e in events {
                let ctx = RequestContext { region: e.region.clone(), ..ctx.clone() };
                sink.finding_event(&ctx, e);
            }
        }
    }

    pub(crate) fn get_findings_op(
        &self,
        ctx: &RequestContext,
        input: types::GetFindingsRequest,
    ) -> Result<types::GetFindingsResponse, ServiceError> {
        authorize_hub(ctx, "GetFindings")?;
        self.sync_organization(ctx);
        let filters = input.filters.as_ref().map(filters::to_json).unwrap_or(Value::Null);
        let state = self.read();
        hub(&state, ctx)?;
        let mut docs: Vec<Value> = visible_findings(&state, account(ctx), &ctx.region)
            .into_iter()
            .map(|(_, _, f)| &f.finding)
            .filter(|f| filters::matches_asff(f, &filters, ctx.received_at))
            .cloned()
            .collect();
        drop(state);
        let criteria = sort_criteria(input.sort_criteria.as_deref(), "UpdatedAt");
        filters::sort(&mut docs, &criteria, true);
        let (page, next_token) = paginate(docs, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::GetFindingsResponse { findings: page.iter().map(to_wire).collect(), next_token })
    }

    pub(crate) fn update_findings_op(
        &self,
        ctx: &RequestContext,
        input: types::UpdateFindingsRequest,
    ) -> Result<types::UpdateFindingsResponse, ServiceError> {
        authorize_hub(ctx, "UpdateFindings")?;
        let filters = filters::to_json(&input.filters);
        let mut events = Vec::new();
        {
            let mut state = self.write();
            hub(&state, ctx)?;
            let keys = visible_keys(&state, account(ctx), &ctx.region);
            for k in keys {
                let (acct, region) = k.split_once('/').map(|(a, r)| (a.to_string(), r.to_string())).unwrap_or_default();
                let h = state.hubs.get_mut(&k).expect("visible hub exists");
                for rec in h.findings.values_mut() {
                    if !filters::matches_asff(&rec.finding, &filters, ctx.received_at) {
                        continue;
                    }
                    let before = rec.finding.clone();
                    if let Some(obj) = rec.finding.as_object_mut() {
                        if let Some(n) = &input.note {
                            obj.insert("Note".into(), json!({"Text": n.text, "UpdatedBy": n.updated_by, "UpdatedAt": iso(ctx.received_at)}));
                        }
                        if let Some(r) = &input.record_state {
                            obj.insert("RecordState".into(), json!(r));
                        }
                        obj.insert("UpdatedAt".into(), json!(iso(ctx.received_at)));
                    }
                    let updates = diff(&before, &rec.finding);
                    if updates.is_empty() {
                        continue;
                    }
                    rec.history.push(HistoryRec {
                        time: ctx.received_at,
                        created: false,
                        source_type: "BATCH_UPDATE_FINDINGS".into(),
                        identity: ctx.caller.arn.clone(),
                        updates,
                    });
                    events.push(finding_event(&ctx.partition, &acct, &region, &rec.finding, ctx.received_at));
                }
            }
        }
        self.publish(ctx, events);
        Ok(types::UpdateFindingsResponse {})
    }

    pub(crate) fn batch_update_findings_op(
        &self,
        ctx: &RequestContext,
        input: types::BatchUpdateFindingsRequest,
    ) -> Result<types::BatchUpdateFindingsResponse, ServiceError> {
        authorize_hub(ctx, "BatchUpdateFindings")?;
        if input.finding_identifiers.is_empty() || input.finding_identifiers.len() > 100 {
            return Err(invalid_input("FindingIdentifiers must contain between 1 and 100 findings."));
        }
        let updates = FieldUpdates {
            note: input.note.as_ref().map(|n| (n.text.clone(), n.updated_by.clone())),
            severity: input.severity.as_ref().and_then(|s| FieldUpdates::severity_from(s.normalized, s.product, s.label.clone())),
            verification_state: input.verification_state.clone(),
            confidence: input.confidence,
            criticality: input.criticality,
            types: input.types.clone(),
            user_defined_fields: input.user_defined_fields.clone(),
            workflow_status: input.workflow.as_ref().and_then(|w| w.status.clone()),
            related_findings: input.related_findings.clone(),
        };
        if updates.is_empty() {
            return Err(invalid_input("At least one field to update must be provided."));
        }
        let mut processed = Vec::new();
        let mut unprocessed = Vec::new();
        let mut events = Vec::new();
        {
            let mut state = self.write();
            hub(&state, ctx)?;
            let keys = visible_keys(&state, account(ctx), &ctx.region);
            for ident in input.finding_identifiers {
                let fkey = finding_key(&ident.product_arn, &ident.id);
                let Some(hk) = keys.iter().find(|k| state.hubs.get(*k).is_some_and(|h| h.findings.contains_key(&fkey))).cloned()
                else {
                    unprocessed.push(types::BatchUpdateFindingsUnprocessedFinding {
                        finding_identifier: ident,
                        error_code: "FindingNotFound".into(),
                        error_message: "Finding Not Found".into(),
                    });
                    continue;
                };
                let (acct, region) = hk.split_once('/').map(|(a, r)| (a.to_string(), r.to_string())).unwrap_or_default();
                let rec = state.hubs.get_mut(&hk).and_then(|h| h.findings.get_mut(&fkey)).expect("found above");
                let changes = updates.apply(rec, &ctx.caller.arn, ctx.received_at);
                if !changes.is_empty() {
                    rec.history.push(HistoryRec {
                        time: ctx.received_at,
                        created: false,
                        source_type: "BATCH_UPDATE_FINDINGS".into(),
                        identity: ctx.caller.arn.clone(),
                        updates: changes,
                    });
                    events.push(finding_event(&ctx.partition, &acct, &region, &rec.finding, ctx.received_at));
                }
                processed.push(ident);
            }
        }
        self.publish(ctx, events);
        Ok(types::BatchUpdateFindingsResponse { processed_findings: processed, unprocessed_findings: unprocessed })
    }

    pub(crate) fn get_finding_history_op(
        &self,
        ctx: &RequestContext,
        input: types::GetFindingHistoryRequest,
    ) -> Result<types::GetFindingHistoryResponse, ServiceError> {
        authorize_hub(ctx, "GetFindingHistory")?;
        let ident = input.finding_identifier;
        let fkey = finding_key(&ident.product_arn, &ident.id);
        let state = self.read();
        hub(&state, ctx)?;
        let rec = visible_findings(&state, account(ctx), &ctx.region)
            .into_iter()
            .find(|(_, k, _)| *k == fkey)
            .map(|(_, _, r)| r.clone())
            .ok_or_else(|| invalid_input("Finding not found"))?;
        drop(state);
        let mut records: Vec<types::FindingHistoryRecord> = rec
            .history
            .iter()
            .rev()
            .filter(|h| input.start_time.is_none_or(|s| h.time >= s) && input.end_time.is_none_or(|e| h.time <= e))
            .map(|h| types::FindingHistoryRecord {
                finding_identifier: Some(ident.clone()),
                update_time: Some(h.time),
                finding_created: Some(h.created),
                update_source: Some(types::FindingHistoryUpdateSource {
                    r#type: Some(h.source_type.clone()),
                    identity: Some(h.identity.clone()),
                }),
                updates: Some(
                    h.updates
                        .iter()
                        .map(|(f, o, n)| types::FindingHistoryUpdate {
                            updated_field: Some(f.clone()),
                            old_value: o.clone(),
                            new_value: n.clone(),
                        })
                        .collect(),
                ),
                next_token: None,
            })
            .collect();
        let (page, next_token) = paginate(std::mem::take(&mut records), input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::GetFindingHistoryResponse { records: Some(page), next_token })
    }

    // ---- insights ------------------------------------------------------------

    pub(crate) fn create_insight_op(
        &self,
        ctx: &RequestContext,
        input: types::CreateInsightRequest,
    ) -> Result<types::CreateInsightResponse, ServiceError> {
        authorize_hub(ctx, "CreateInsight")?;
        check_group_by(&input.group_by_attribute)?;
        let mut state = self.write();
        let acct = account(ctx).to_string();
        let h = common::hub_mut(&mut state, ctx)?;
        if h.insights.len() >= 100 {
            return Err(crate::generated::errors::limit_exceeded("The maximum number of custom insights (100) has been reached."));
        }
        let arn = common::arn(ctx, &format!("insight/{acct}/custom/{}", uuid::Uuid::new_v4()));
        h.insights.insert(
            arn.clone(),
            InsightRec {
                name: input.name,
                filters: serde_json::to_value(&input.filters).unwrap_or(Value::Null),
                group_by_attribute: input.group_by_attribute,
            },
        );
        Ok(types::CreateInsightResponse { insight_arn: arn })
    }

    pub(crate) fn get_insights_op(
        &self,
        ctx: &RequestContext,
        input: types::GetInsightsRequest,
    ) -> Result<types::GetInsightsResponse, ServiceError> {
        authorize_hub(ctx, "GetInsights")?;
        let state = self.read();
        let h = hub(&state, ctx)?;
        let all = all_insights(ctx, h);
        let insights: Vec<types::Insight> = match &input.insight_arns {
            Some(arns) if !arns.is_empty() => {
                let mut out = Vec::new();
                for a in arns {
                    match all.iter().find(|i| i.insight_arn == *a) {
                        Some(i) => out.push(i.clone()),
                        None => return Err(not_found(format!("Insight {a} not found"))),
                    }
                }
                out
            }
            _ => all.into_iter().filter(|i| h.insights.contains_key(&i.insight_arn)).collect(),
        };
        let (page, next_token) = paginate(insights, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::GetInsightsResponse { insights: page, next_token })
    }

    pub(crate) fn update_insight_op(
        &self,
        ctx: &RequestContext,
        input: types::UpdateInsightRequest,
    ) -> Result<types::UpdateInsightResponse, ServiceError> {
        authorize(ctx, "UpdateInsight", &input.insight_arn)?;
        if let Some(g) = &input.group_by_attribute {
            check_group_by(g)?;
        }
        let mut state = self.write();
        let h = common::hub_mut(&mut state, ctx)?;
        let i = h.insights.get_mut(&input.insight_arn).ok_or_else(|| not_found(format!("Insight {} not found", input.insight_arn)))?;
        if let Some(n) = input.name {
            i.name = n;
        }
        if let Some(f) = input.filters {
            i.filters = serde_json::to_value(&f).unwrap_or(Value::Null);
        }
        if let Some(g) = input.group_by_attribute {
            i.group_by_attribute = g;
        }
        Ok(types::UpdateInsightResponse {})
    }

    pub(crate) fn delete_insight_op(
        &self,
        ctx: &RequestContext,
        input: types::DeleteInsightRequest,
    ) -> Result<types::DeleteInsightResponse, ServiceError> {
        authorize(ctx, "DeleteInsight", &input.insight_arn)?;
        let mut state = self.write();
        let h = common::hub_mut(&mut state, ctx)?;
        h.insights.remove(&input.insight_arn).ok_or_else(|| not_found(format!("Insight {} not found", input.insight_arn)))?;
        Ok(types::DeleteInsightResponse { insight_arn: input.insight_arn })
    }

    pub(crate) fn get_insight_results_op(
        &self,
        ctx: &RequestContext,
        input: types::GetInsightResultsRequest,
    ) -> Result<types::GetInsightResultsResponse, ServiceError> {
        authorize_hub(ctx, "GetInsightResults")?;
        self.sync_organization(ctx);
        let state = self.read();
        let h = hub(&state, ctx)?;
        let insight = all_insights(ctx, h)
            .into_iter()
            .find(|i| i.insight_arn == input.insight_arn)
            .ok_or_else(|| not_found(format!("Insight {} not found", input.insight_arn)))?;
        let filters = filters::to_json(&insight.filters);
        let path = filters::asff_path(&insight.group_by_attribute).unwrap_or("Id");
        let mut counts: BTreeMap<String, i32> = BTreeMap::new();
        for (_, _, f) in visible_findings(&state, account(ctx), &ctx.region) {
            if filters::matches_asff(&f.finding, &filters, ctx.received_at) {
                for v in filters::group_values(&f.finding, path) {
                    *counts.entry(v).or_default() += 1;
                }
            }
        }
        let mut values: Vec<(String, i32)> = counts.into_iter().collect();
        values.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        values.truncate(100);
        Ok(types::GetInsightResultsResponse {
            insight_results: types::InsightResults {
                insight_arn: insight.insight_arn,
                group_by_attribute: insight.group_by_attribute,
                result_values: values
                    .into_iter()
                    .map(|(v, c)| types::InsightResultValue { group_by_attribute_value: v, count: c })
                    .collect(),
            },
        })
    }
}

/// Import findings one by one, collecting failures and events.
pub fn import_all(state: &mut State, scope: &ImportScope<'_>, findings: Vec<(String, Value)>) -> (ServiceImportResult, Vec<FindingEvent>) {
    let mut result = ServiceImportResult::default();
    let mut events = Vec::new();
    for (id, f) in findings {
        match import_one(state, scope, f) {
            Ok(e) => {
                result.success_count += 1;
                events.push(e);
            }
            Err((code, message)) => result.failed.push((id, code, message)),
        }
    }
    (result, events)
}

fn check_group_by(attr: &str) -> Result<(), ServiceError> {
    if filters::is_asff_attribute(attr) {
        Ok(())
    } else {
        Err(invalid_input(format!("Invalid GroupByAttribute: {attr}")))
    }
}

/// Custom insights of a hub followed by the managed insights.
fn all_insights(ctx: &RequestContext, h: &crate::state::Hub) -> Vec<types::Insight> {
    let mut out: Vec<types::Insight> = h
        .insights
        .iter()
        .map(|(arn, i)| types::Insight {
            insight_arn: arn.clone(),
            name: i.name.clone(),
            filters: serde_json::from_value(i.filters.clone()).unwrap_or_default(),
            group_by_attribute: i.group_by_attribute.clone(),
        })
        .collect();
    for (n, name, group_by, filters_json) in catalog::MANAGED_INSIGHTS {
        let wire: Value = serde_json::from_str(filters_json).unwrap_or(Value::Null);
        let mut d = mws_proto_json::Decoder::new();
        let filters = json_de::de_aws_security_finding_filters(&mut d, Some(&wire), "").unwrap_or_default();
        out.push(types::Insight {
            insight_arn: catalog::managed_insight_arn(&ctx.partition, *n),
            name: name.to_string(),
            filters,
            group_by_attribute: group_by.to_string(),
        });
    }
    out
}

/// Sort criteria as `(field, order)`, defaulting to `default` descending.
pub fn sort_criteria(criteria: Option<&[types::SortCriterion]>, default: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = criteria
        .unwrap_or_default()
        .iter()
        .filter_map(|c| Some((c.field.clone()?, c.sort_order.clone().unwrap_or_else(|| "asc".into()))))
        .collect();
    if out.is_empty() {
        out.push((default.to_string(), "desc".into()));
    }
    out
}

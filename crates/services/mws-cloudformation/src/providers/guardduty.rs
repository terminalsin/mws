//! GuardDuty resource types: detectors, IP sets, threat intel sets,
//! filters and malware protection plans.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::eks::camel;
use super::rds::coerce;
use super::{boolean, changed, gone_ok, req, s, text, Created, Cx, HResult, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::GuardDuty::Detector", Arc::new(Detector));
    m.insert("AWS::GuardDuty::IPSet", Arc::new(List(&IP_SET)));
    m.insert("AWS::GuardDuty::ThreatIntelSet", Arc::new(List(&THREAT_INTEL_SET)));
    m.insert("AWS::GuardDuty::Filter", Arc::new(Filter));
    m.insert("AWS::GuardDuty::MalwareProtectionPlan", Arc::new(MalwareProtectionPlan));
}

fn api(v: &Value) -> Value {
    let mut v = camel(v, &[]);
    coerce(&mut v, &["rank"], &["enable", "ebsVolumes", "activate"], &[]);
    v
}

/// Copy CloudFormation properties under their camelCase API names.
fn put(out: &mut Map<String, Value>, props: &Props, keys: &[&str]) {
    for k in keys {
        if let Some(v) = props.get(*k).filter(|v| !v.is_null()) {
            let mut one = Map::new();
            one.insert((*k).to_string(), v.clone());
            if let Value::Object(m) = api(&Value::Object(one)) {
                out.extend(m);
            }
        }
    }
}

async fn retag(cx: &Cx<'_>, arn: &str, old: &Props, new: &Props) -> HResult<()> {
    if !changed(old, new, "Tags") {
        return Ok(());
    }
    let (o, n) = (cx.tag_map(old), cx.tag_map(new));
    let removed: Vec<&String> = o.keys().filter(|k| !n.contains_key(*k)).collect();
    if !removed.is_empty() {
        cx.call("guardduty", "UntagResource", json!({"ResourceArn": arn, "TagKeys": removed})).await?;
    }
    let set: Map<String, Value> = n.into_iter().filter(|(k, v)| o.get(k) != Some(v)).collect();
    if !set.is_empty() {
        cx.call("guardduty", "TagResource", json!({"ResourceArn": arn, "tags": set})).await?;
    }
    Ok(())
}

fn tags(cx: &Cx<'_>, props: &Props, input: &mut Map<String, Value>) {
    let t = cx.tag_map(props);
    if !t.is_empty() {
        input.insert("tags".into(), Value::Object(t));
    }
}

// ---------------------------------------------------------------------
// Detectors.

struct Detector;

#[async_trait::async_trait]
impl Provider for Detector {
    fn required(&self) -> &'static [&'static str] {
        &["Enable"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Id"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = Map::new();
        input.insert("enable".into(), json!(boolean(props, "Enable").unwrap_or(true)));
        put(&mut input, props, &["FindingPublishingFrequency", "DataSources", "Features"]);
        tags(cx, props, &mut input);
        let out = cx.call("guardduty", "CreateDetector", Value::Object(input)).await?;
        let id = text(&out["detectorId"]);
        Ok(Created::new(&id).attr("Id", id.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        if ["Enable", "FindingPublishingFrequency", "DataSources", "Features"].iter().any(|k| changed(old, new, k)) {
            let mut input = Map::new();
            input.insert("DetectorId".into(), json!(id));
            input.insert("enable".into(), json!(boolean(new, "Enable").unwrap_or(true)));
            put(&mut input, new, &["FindingPublishingFrequency", "DataSources", "Features"]);
            cx.call("guardduty", "UpdateDetector", Value::Object(input)).await?;
        }
        retag(cx, &cx.arn("guardduty", &format!("detector/{id}")), old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_gd(cx.call("guardduty", "DeleteDetector", json!({"DetectorId": id})).await)
    }
}

// ---------------------------------------------------------------------
// IP sets and threat intel sets.

struct ListKind {
    noun: &'static str,
    id_member: &'static str,
    id_output: &'static str,
    arn_kind: &'static str,
}

const IP_SET: ListKind = ListKind { noun: "IPSet", id_member: "IpSetId", id_output: "ipSetId", arn_kind: "ipset" };
const THREAT_INTEL_SET: ListKind = ListKind {
    noun: "ThreatIntelSet",
    id_member: "ThreatIntelSetId",
    id_output: "threatIntelSetId",
    arn_kind: "threatintelset",
};

struct List(&'static ListKind);

#[async_trait::async_trait]
impl Provider for List {
    fn create_only(&self) -> &'static [&'static str] {
        &["DetectorId", "Format"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["DetectorId", "Format", "Location"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Id"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let detector = req(props, "DetectorId")?;
        let mut input = Map::new();
        input.insert("DetectorId".into(), json!(detector));
        input.insert("name".into(), json!(s(props, "Name").unwrap_or_else(|| cx.physical_name(300))));
        input.insert("activate".into(), json!(boolean(props, "Activate").unwrap_or(true)));
        put(&mut input, props, &["Format", "Location", "ExpectedBucketOwner"]);
        tags(cx, props, &mut input);
        let out = cx.call("guardduty", &format!("Create{}", self.0.noun), Value::Object(input)).await?;
        let id = text(&out[self.0.id_output]);
        Ok(Created::new(&id).attr("Id", id.clone()))
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let detector = req(new, "DetectorId")?;
        if ["Name", "Location", "Activate", "ExpectedBucketOwner"].iter().any(|k| changed(old, new, k)) {
            let mut input = Map::new();
            input.insert("DetectorId".into(), json!(detector));
            input.insert(self.0.id_member.into(), json!(id));
            input.insert("activate".into(), json!(boolean(new, "Activate").unwrap_or(true)));
            put(&mut input, new, &["Name", "Location", "ExpectedBucketOwner"]);
            cx.call("guardduty", &format!("Update{}", self.0.noun), Value::Object(input)).await?;
        }
        retag(cx, &cx.arn("guardduty", &format!("detector/{detector}/{}/{id}", self.0.arn_kind)), old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let detector = req(props, "DetectorId")?;
        gone_gd(
            cx.call(
                "guardduty",
                &format!("Delete{}", self.0.noun),
                json!({"DetectorId": detector, self.0.id_member: id}),
            )
            .await,
        )
    }
}

// ---------------------------------------------------------------------
// Filters.

/// `FindingCriteria.Criterion` keeps its field names; each condition's
/// operators become camelCase.
fn criteria(props: &Props) -> Value {
    let criterion = props.get("FindingCriteria").and_then(|c| c.get("Criterion")).and_then(Value::as_object);
    let mut out = Map::new();
    for (field, cond) in criterion.into_iter().flatten() {
        let mut c = camel(cond, &[]);
        coerce(
            &mut c,
            &["gt", "gte", "lt", "lte", "greaterThan", "greaterThanOrEqual", "lessThan", "lessThanOrEqual"],
            &[],
            &[],
        );
        out.insert(field.clone(), c);
    }
    json!({"criterion": out})
}

struct Filter;

#[async_trait::async_trait]
impl Provider for Filter {
    fn create_only(&self) -> &'static [&'static str] {
        &["DetectorId", "Name"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["DetectorId", "FindingCriteria"]
    }
    fn name_property(&self) -> Option<&'static str> {
        Some("Name")
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let detector = req(props, "DetectorId")?;
        let name = s(props, "Name").unwrap_or_else(|| cx.physical_name(64));
        let mut input = Map::new();
        input.insert("DetectorId".into(), json!(detector));
        input.insert("name".into(), json!(name));
        put(&mut input, props, &["Description", "Action", "Rank"]);
        input.insert("findingCriteria".into(), criteria(props));
        tags(cx, props, &mut input);
        let out = cx.call("guardduty", "CreateFilter", Value::Object(input)).await?;
        Ok(Created::new(text(&out["name"])))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let detector = req(new, "DetectorId")?;
        if ["Description", "Action", "Rank", "FindingCriteria"].iter().any(|k| changed(old, new, k)) {
            let mut input = Map::new();
            input.insert("DetectorId".into(), json!(detector));
            input.insert("FilterName".into(), json!(name));
            put(&mut input, new, &["Description", "Action", "Rank"]);
            input.insert("findingCriteria".into(), criteria(new));
            cx.call("guardduty", "UpdateFilter", Value::Object(input)).await?;
        }
        retag(cx, &cx.arn("guardduty", &format!("detector/{detector}/filter/{name}")), old, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, props: &Props, _attrs: &Props) -> HResult<()> {
        let detector = req(props, "DetectorId")?;
        gone_gd(cx.call("guardduty", "DeleteFilter", json!({"DetectorId": detector, "FilterName": name})).await)
    }
}

// ---------------------------------------------------------------------
// Malware protection plans.

struct MalwareProtectionPlan;

async fn plan_attributes(cx: &Cx<'_>, id: &str) -> HResult<Props> {
    let p = cx.call("guardduty", "GetMalwareProtectionPlan", json!({"MalwareProtectionPlanId": id})).await?;
    let mut a = Props::new();
    a.insert("Arn".into(), json!(text(&p["arn"])));
    a.insert("CreatedAt".into(), json!(text(&p["createdAt"])));
    a.insert("MalwareProtectionPlanId".into(), json!(id));
    a.insert("Status".into(), json!(text(&p["status"])));
    a.insert("StatusReasons".into(), p["statusReasons"].clone());
    Ok(a)
}

#[async_trait::async_trait]
impl Provider for MalwareProtectionPlan {
    fn required(&self) -> &'static [&'static str] {
        &["Role", "ProtectedResource"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn", "CreatedAt", "MalwareProtectionPlanId", "Status", "StatusReasons"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let mut input = Map::new();
        put(&mut input, props, &["Role", "ProtectedResource", "Actions"]);
        tags(cx, props, &mut input);
        let out = cx.call("guardduty", "CreateMalwareProtectionPlan", Value::Object(input)).await?;
        let id = text(&out["malwareProtectionPlanId"]);
        Ok(Created { physical_id: id.clone(), attributes: plan_attributes(cx, &id).await? })
    }

    async fn update(&self, cx: &Cx<'_>, id: &str, old: &Props, new: &Props, _attrs: &Props) -> HResult<Props> {
        if ["Role", "ProtectedResource", "Actions"].iter().any(|k| changed(old, new, k)) {
            let mut input = Map::new();
            input.insert("MalwareProtectionPlanId".into(), json!(id));
            put(&mut input, new, &["Role", "Actions"]);
            if changed(old, new, "ProtectedResource") {
                // Only the object prefixes change in place.
                if let Some(prefixes) = new.get("ProtectedResource").and_then(|r| r["S3Bucket"].get("ObjectPrefixes")) {
                    input.insert("protectedResource".into(), json!({"s3Bucket": {"objectPrefixes": prefixes}}));
                }
            }
            cx.call("guardduty", "UpdateMalwareProtectionPlan", Value::Object(input)).await?;
        }
        let a = plan_attributes(cx, id).await?;
        retag(cx, &text(&a["Arn"]), old, new).await?;
        Ok(a)
    }

    async fn delete(&self, cx: &Cx<'_>, id: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_gd(cx.call("guardduty", "DeleteMalwareProtectionPlan", json!({"MalwareProtectionPlanId": id})).await)
    }
}

/// [`gone_ok`], also for GuardDuty's answer when the detector (or the
/// list or filter under it) no longer exists: a `BadRequestException`,
/// which the GuardDuty resource handlers treat as NotFound.
fn gone_gd(r: HResult<Value>) -> HResult<()> {
    match r {
        Err(e)
            if e.code == "BadRequestException"
                && (e.message.contains("is not owned by the current account")
                    || e.message.contains("no such resource found")) =>
        {
            Ok(())
        }
        r => gone_ok(r),
    }
}

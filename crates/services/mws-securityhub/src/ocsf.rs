//! The OCSF view of findings that the Security Hub V2 API returns:
//! ASFF findings mapped to OCSF 1.5 finding classes (Detection,
//! Compliance or Vulnerability Finding), with V2 updates applied.

use serde_json::{json, Map, Value};

use crate::common::parse_time;
use crate::state::V2Overlay;

pub fn severity_name(id: i64) -> &'static str {
    match id {
        0 => "Unknown",
        1 => "Informational",
        2 => "Low",
        3 => "Medium",
        4 => "High",
        5 => "Critical",
        6 => "Fatal",
        _ => "Other",
    }
}

pub fn status_name(id: i64) -> &'static str {
    match id {
        0 => "Unknown",
        1 => "New",
        2 => "In Progress",
        3 => "Suppressed",
        4 => "Resolved",
        5 => "Archived",
        6 => "Deleted",
        _ => "Other",
    }
}

fn severity_id(label: &str) -> i64 {
    match label {
        "INFORMATIONAL" => 1,
        "LOW" => 2,
        "MEDIUM" => 3,
        "HIGH" => 4,
        "CRITICAL" => 5,
        _ => 0,
    }
}

fn status_id(workflow: &str, record_state: &str) -> i64 {
    if record_state == "ARCHIVED" {
        return 5;
    }
    match workflow {
        "NEW" => 1,
        "NOTIFIED" => 2,
        "SUPPRESSED" => 3,
        "RESOLVED" => 4,
        _ => 0,
    }
}

fn str_at<'a>(f: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cur = f;
    for p in path {
        cur = cur.get(*p)?;
    }
    cur.as_str()
}

fn millis(s: Option<&str>) -> Option<i64> {
    s.and_then(parse_time).map(|t| t.timestamp_millis())
}

/// The finding's `metadata.uid`: its Security Hub finding ARN.
pub fn metadata_uid(f: &Value) -> String {
    str_at(f, &["ProductFields", "aws/securityhub/FindingId"]).unwrap_or_default().to_string()
}

pub fn to_ocsf(f: &Value, overlay: &V2Overlay) -> Value {
    let (class_uid, class_name) = if f.get("Vulnerabilities").is_some() {
        (2002, "Vulnerability Finding")
    } else if f.get("Compliance").is_some() {
        (2003, "Compliance Finding")
    } else {
        (2004, "Detection Finding")
    };
    let sev = overlay
        .severity_id
        .map(i64::from)
        .unwrap_or_else(|| severity_id(str_at(f, &["Severity", "Label"]).unwrap_or("")));
    let status = overlay.status_id.map(i64::from).unwrap_or_else(|| {
        status_id(str_at(f, &["Workflow", "Status"]).unwrap_or("NEW"), str_at(f, &["RecordState"]).unwrap_or("ACTIVE"))
    });
    let created = str_at(f, &["CreatedAt"]);
    let updated = str_at(f, &["UpdatedAt"]);
    let mut finding_info = Map::new();
    finding_info.insert("uid".into(), json!(str_at(f, &["Id"])));
    finding_info.insert("title".into(), json!(str_at(f, &["Title"])));
    finding_info.insert("desc".into(), json!(str_at(f, &["Description"])));
    if let Some(t) = f.get("Types") {
        finding_info.insert("types".into(), t.clone());
    }
    finding_info.insert("created_time".into(), json!(millis(created)));
    finding_info.insert("created_time_dt".into(), json!(created));
    finding_info.insert("modified_time".into(), json!(millis(updated)));
    finding_info.insert("modified_time_dt".into(), json!(updated));
    if let Some(t) = str_at(f, &["FirstObservedAt"]) {
        finding_info.insert("first_seen_time_dt".into(), json!(t));
    }
    if let Some(t) = str_at(f, &["LastObservedAt"]) {
        finding_info.insert("last_seen_time_dt".into(), json!(t));
    }
    finding_info.insert("src_url".into(), json!(str_at(f, &["SourceUrl"])));
    let resources: Vec<Value> = f
        .get("Resources")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|r| {
            let tags: Vec<Value> = r
                .get("Tags")
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
                .map(|(k, v)| json!({"name": k, "value": v}))
                .collect();
            json!({
                "uid": r.get("Id"),
                "type": r.get("Type"),
                "region": r.get("Region"),
                "cloud_partition": r.get("Partition"),
                "owner": {"account": {"uid": str_at(f, &["AwsAccountId"])}},
                "tags": tags,
            })
        })
        .collect();
    let mut doc = json!({
        "activity_id": 1,
        "activity_name": "Create",
        "category_uid": 2,
        "category_name": "Findings",
        "class_uid": class_uid,
        "class_name": class_name,
        "type_uid": class_uid * 100 + 1,
        "cloud": {
            "account": {"uid": str_at(f, &["AwsAccountId"]), "type": "AWS Account", "type_id": 10, "name": str_at(f, &["AwsAccountName"])},
            "provider": "AWS",
            "region": str_at(f, &["Region"]),
        },
        "finding_info": Value::Object(finding_info),
        "metadata": {
            "uid": metadata_uid(f),
            "version": "1.5.0",
            "product": {
                "uid": str_at(f, &["ProductArn"]),
                "name": str_at(f, &["ProductName"]),
                "vendor_name": str_at(f, &["CompanyName"]),
            },
            "profiles": ["cloud", "datetime"],
        },
        "severity_id": sev,
        "severity": severity_name(sev),
        "status_id": status,
        "status": status_name(status),
        "resources": resources,
        "time": millis(updated),
        "time_dt": updated,
    });
    if let Some(r) = str_at(f, &["Remediation", "Recommendation", "Text"]) {
        doc["remediation"] = json!({"desc": r, "references": [str_at(f, &["Remediation", "Recommendation", "Url"])]});
    }
    if let Some(c) = f.get("Compliance") {
        doc["compliance"] = json!({
            "status": c.get("Status"),
            "control": c.get("SecurityControlId"),
            "requirements": c.get("RelatedRequirements"),
        });
    }
    if let Some(v) = f.get("Vulnerabilities").and_then(Value::as_array) {
        doc["vulnerabilities"] = Value::Array(
            v.iter()
                .map(|x| {
                    let packages: Vec<Value> = x
                        .get("VulnerablePackages")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .map(|p| json!({"name": p.get("Name"), "version": p.get("Version"), "type": p.get("PackageManager")}))
                        .collect();
                    json!({"cve": {"uid": x.get("Id")}, "affected_packages": packages, "fix_available": x.get("FixAvailable") == Some(&json!("YES"))})
                })
                .collect(),
        );
    }
    let comment = overlay.comment.clone().or_else(|| str_at(f, &["Note", "Text"]).map(str::to_string));
    if let Some(c) = comment {
        doc["comment"] = json!(c);
    }
    strip_nulls(doc)
}

fn strip_nulls(v: Value) -> Value {
    match v {
        Value::Object(m) => {
            Value::Object(m.into_iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k, strip_nulls(v))).collect())
        }
        Value::Array(a) => Value::Array(a.into_iter().map(strip_nulls).collect()),
        v => v,
    }
}

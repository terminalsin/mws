//! Finding filters, sorting and grouping, evaluated over findings as JSON.
//!
//! ASFF filters (`AwsSecurityFindingFilters`, `AutomationRulesFindingFilters`)
//! name finding attributes (`SeverityLabel`, `ResourceType`, ...); each name
//! maps to a path in the finding. OCSF filters (Security Hub V2) name the
//! path directly (`finding_info.title`). Filters on one attribute combine
//! the way Security Hub documents: positive comparisons (`EQUALS`,
//! `PREFIX`, `CONTAINS`) match if any matches, negative ones
//! (`NOT_EQUALS`, `PREFIX_NOT_EQUALS`, `NOT_CONTAINS`) must all hold, and
//! different attributes must all match.

use std::net::IpAddr;

use chrono::{DateTime, Duration, Utc};
use serde_json::Value;

use crate::common::parse_time;

/// ASFF filter names and the finding paths they read. `[]` steps into
/// every element of a list.
const ASFF_PATHS: &[(&str, &str)] = &[
    ("ProductArn", "ProductArn"),
    ("AwsAccountId", "AwsAccountId"),
    ("AwsAccountName", "AwsAccountName"),
    ("Id", "Id"),
    ("GeneratorId", "GeneratorId"),
    ("Region", "Region"),
    ("Type", "Types[]"),
    ("FirstObservedAt", "FirstObservedAt"),
    ("LastObservedAt", "LastObservedAt"),
    ("CreatedAt", "CreatedAt"),
    ("UpdatedAt", "UpdatedAt"),
    ("SeverityProduct", "Severity.Product"),
    ("SeverityNormalized", "Severity.Normalized"),
    ("SeverityLabel", "Severity.Label"),
    ("Confidence", "Confidence"),
    ("Criticality", "Criticality"),
    ("Title", "Title"),
    ("Description", "Description"),
    ("RecommendationText", "Remediation.Recommendation.Text"),
    ("SourceUrl", "SourceUrl"),
    ("ProductFields", "ProductFields"),
    ("ProductName", "ProductName"),
    ("CompanyName", "CompanyName"),
    ("UserDefinedFields", "UserDefinedFields"),
    ("MalwareName", "Malware[].Name"),
    ("MalwareType", "Malware[].Type"),
    ("MalwarePath", "Malware[].Path"),
    ("MalwareState", "Malware[].State"),
    ("NetworkDirection", "Network.Direction"),
    ("NetworkProtocol", "Network.Protocol"),
    ("NetworkSourceIpV4", "Network.SourceIpV4"),
    ("NetworkSourceIpV6", "Network.SourceIpV6"),
    ("NetworkSourcePort", "Network.SourcePort"),
    ("NetworkSourceDomain", "Network.SourceDomain"),
    ("NetworkSourceMac", "Network.SourceMac"),
    ("NetworkDestinationIpV4", "Network.DestinationIpV4"),
    ("NetworkDestinationIpV6", "Network.DestinationIpV6"),
    ("NetworkDestinationPort", "Network.DestinationPort"),
    ("NetworkDestinationDomain", "Network.DestinationDomain"),
    ("ProcessName", "Process.Name"),
    ("ProcessPath", "Process.Path"),
    ("ProcessPid", "Process.Pid"),
    ("ProcessParentPid", "Process.ParentPid"),
    ("ProcessLaunchedAt", "Process.LaunchedAt"),
    ("ProcessTerminatedAt", "Process.TerminatedAt"),
    ("ThreatIntelIndicatorType", "ThreatIntelIndicators[].Type"),
    ("ThreatIntelIndicatorValue", "ThreatIntelIndicators[].Value"),
    ("ThreatIntelIndicatorCategory", "ThreatIntelIndicators[].Category"),
    ("ThreatIntelIndicatorLastObservedAt", "ThreatIntelIndicators[].LastObservedAt"),
    ("ThreatIntelIndicatorSource", "ThreatIntelIndicators[].Source"),
    ("ThreatIntelIndicatorSourceUrl", "ThreatIntelIndicators[].SourceUrl"),
    ("ResourceType", "Resources[].Type"),
    ("ResourceId", "Resources[].Id"),
    ("ResourcePartition", "Resources[].Partition"),
    ("ResourceRegion", "Resources[].Region"),
    ("ResourceTags", "Resources[].Tags"),
    ("ResourceProvider", "Resources[].Provider"),
    ("ResourceOwnerAccountId", "Resources[].Owner.Account.Id"),
    ("ResourceOwnerOrgId", "Resources[].Owner.Org.Id"),
    ("ResourceApplicationName", "Resources[].ApplicationName"),
    ("ResourceApplicationArn", "Resources[].ApplicationArn"),
    ("ResourceAwsEc2InstanceType", "Resources[].Details.AwsEc2Instance.Type"),
    ("ResourceAwsEc2InstanceImageId", "Resources[].Details.AwsEc2Instance.ImageId"),
    ("ResourceAwsEc2InstanceIpV4Addresses", "Resources[].Details.AwsEc2Instance.IpV4Addresses[]"),
    ("ResourceAwsEc2InstanceIpV6Addresses", "Resources[].Details.AwsEc2Instance.IpV6Addresses[]"),
    ("ResourceAwsEc2InstanceKeyName", "Resources[].Details.AwsEc2Instance.KeyName"),
    ("ResourceAwsEc2InstanceIamInstanceProfileArn", "Resources[].Details.AwsEc2Instance.IamInstanceProfileArn"),
    ("ResourceAwsEc2InstanceVpcId", "Resources[].Details.AwsEc2Instance.VpcId"),
    ("ResourceAwsEc2InstanceSubnetId", "Resources[].Details.AwsEc2Instance.SubnetId"),
    ("ResourceAwsEc2InstanceLaunchedAt", "Resources[].Details.AwsEc2Instance.LaunchedAt"),
    ("ResourceAwsS3BucketOwnerId", "Resources[].Details.AwsS3Bucket.OwnerId"),
    ("ResourceAwsS3BucketOwnerName", "Resources[].Details.AwsS3Bucket.OwnerName"),
    ("ResourceAwsIamAccessKeyUserName", "Resources[].Details.AwsIamAccessKey.UserName"),
    ("ResourceAwsIamAccessKeyPrincipalName", "Resources[].Details.AwsIamAccessKey.PrincipalName"),
    ("ResourceAwsIamAccessKeyStatus", "Resources[].Details.AwsIamAccessKey.Status"),
    ("ResourceAwsIamAccessKeyCreatedAt", "Resources[].Details.AwsIamAccessKey.CreatedAt"),
    ("ResourceAwsIamUserUserName", "Resources[].Details.AwsIamUser.UserName"),
    ("ResourceContainerName", "Resources[].Details.Container.Name"),
    ("ResourceContainerImageId", "Resources[].Details.Container.ImageId"),
    ("ResourceContainerImageName", "Resources[].Details.Container.ImageName"),
    ("ResourceContainerLaunchedAt", "Resources[].Details.Container.LaunchedAt"),
    ("ResourceDetailsOther", "Resources[].Details.Other"),
    ("ComplianceStatus", "Compliance.Status"),
    ("ComplianceSecurityControlId", "Compliance.SecurityControlId"),
    ("ComplianceAssociatedStandardsId", "Compliance.AssociatedStandards[].StandardsId"),
    ("ComplianceSecurityControlParametersName", "Compliance.SecurityControlParameters[].Name"),
    ("ComplianceSecurityControlParametersValue", "Compliance.SecurityControlParameters[].Value[]"),
    ("VerificationState", "VerificationState"),
    ("WorkflowState", "WorkflowState"),
    ("WorkflowStatus", "Workflow.Status"),
    ("RecordState", "RecordState"),
    ("RelatedFindingsProductArn", "RelatedFindings[].ProductArn"),
    ("RelatedFindingsId", "RelatedFindings[].Id"),
    ("NoteText", "Note.Text"),
    ("NoteUpdatedAt", "Note.UpdatedAt"),
    ("NoteUpdatedBy", "Note.UpdatedBy"),
    ("FindingProviderFieldsConfidence", "FindingProviderFields.Confidence"),
    ("FindingProviderFieldsCriticality", "FindingProviderFields.Criticality"),
    ("FindingProviderFieldsRelatedFindingsId", "FindingProviderFields.RelatedFindings[].Id"),
    ("FindingProviderFieldsRelatedFindingsProductArn", "FindingProviderFields.RelatedFindings[].ProductArn"),
    ("FindingProviderFieldsSeverityLabel", "FindingProviderFields.Severity.Label"),
    ("FindingProviderFieldsSeverityOriginal", "FindingProviderFields.Severity.Original"),
    ("FindingProviderFieldsTypes", "FindingProviderFields.Types[]"),
    ("Sample", "Sample"),
    ("VulnerabilitiesExploitAvailable", "Vulnerabilities[].ExploitAvailable"),
    ("VulnerabilitiesFixAvailable", "Vulnerabilities[].FixAvailable"),
];

/// A filter structure as JSON (serde field names) without `null`s, the
/// form the matchers here read.
pub fn to_json<T: serde::Serialize>(filters: &T) -> Value {
    strip_nulls(serde_json::to_value(filters).unwrap_or(Value::Null))
}

fn strip_nulls(v: Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(m.into_iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k, strip_nulls(v))).collect()),
        Value::Array(a) => Value::Array(a.into_iter().map(strip_nulls).collect()),
        v => v,
    }
}

fn normalize(name: &str) -> String {
    name.chars().filter(|c| *c != '_').flat_map(char::to_lowercase).collect()
}

/// The finding path an ASFF filter name (`SeverityLabel`, or its
/// snake_case form) reads.
pub fn asff_path(name: &str) -> Option<&'static str> {
    let n = normalize(name);
    ASFF_PATHS.iter().find(|(k, _)| normalize(k) == n).map(|(_, p)| *p)
}

/// Whether `name` is an ASFF filter attribute.
pub fn is_asff_attribute(name: &str) -> bool {
    ASFF_PATHS.iter().any(|(k, _)| *k == name)
}

/// The values at `path` in `v` (`a.b[].c`; lists are flattened).
pub fn values_at<'v>(v: &'v Value, path: &str) -> Vec<&'v Value> {
    let mut cur = vec![v];
    for step in path.split('.') {
        let step = step.trim_end_matches("[]");
        let mut next = Vec::new();
        for c in cur {
            let c = match c {
                Value::Array(items) => {
                    for i in items {
                        if let Some(x) = i.get(step) {
                            next.push(x);
                        }
                    }
                    continue;
                }
                c => c,
            };
            if let Some(x) = c.get(step) {
                next.push(x);
            }
        }
        cur = next;
    }
    let mut out = Vec::new();
    for c in cur {
        match c {
            Value::Array(items) => out.extend(items.iter()),
            Value::Null => {}
            c => out.push(c),
        }
    }
    out
}

fn as_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

/// One string comparison.
fn string_cmp(value: &str, comparison: &str, target: &str) -> bool {
    match comparison {
        "EQUALS" | "NOT_EQUALS" => value == target,
        "PREFIX" | "PREFIX_NOT_EQUALS" => value.starts_with(target),
        "CONTAINS" | "NOT_CONTAINS" => value.contains(target),
        "CONTAINS_WORD" => value.split(|c: char| !c.is_alphanumeric()).any(|w| w == target),
        _ => false,
    }
}

fn negative(comparison: &str) -> bool {
    matches!(comparison, "NOT_EQUALS" | "PREFIX_NOT_EQUALS" | "NOT_CONTAINS")
}

/// String filters (serde JSON: `value`, `comparison`) against values.
pub fn match_strings(values: &[String], filters: &[(String, String)]) -> bool {
    let (neg, pos): (Vec<_>, Vec<_>) = filters.iter().partition(|(_, c)| negative(c));
    let pos_ok = pos.is_empty() || pos.iter().any(|(t, c)| values.iter().any(|v| string_cmp(v, c, t)));
    let neg_ok = neg.iter().all(|(t, c)| !values.iter().any(|v| string_cmp(v, c, t)));
    pos_ok && neg_ok
}

fn match_number(values: &[f64], f: &Value) -> bool {
    let get = |k: &str| f.get(k).and_then(Value::as_f64);
    values.iter().any(|v| {
        get("gte").is_none_or(|x| *v >= x)
            && get("lte").is_none_or(|x| *v <= x)
            && get("gt").is_none_or(|x| *v > x)
            && get("lt").is_none_or(|x| *v < x)
            && get("eq").is_none_or(|x| *v == x)
    })
}

fn match_date(values: &[DateTime<Utc>], f: &Value, now: DateTime<Utc>) -> bool {
    let start = f.get("start").and_then(Value::as_str).and_then(parse_time);
    let end = f.get("end").and_then(Value::as_str).and_then(parse_time);
    let range = f.get("date_range").and_then(|r| r.get("value")).and_then(Value::as_i64);
    values.iter().any(|v| {
        if let Some(days) = range {
            return *v >= now - Duration::days(days) && *v <= now;
        }
        start.is_none_or(|s| *v >= s) && end.is_none_or(|e| *v <= e)
    })
}

fn match_ip(values: &[String], cidr: &str) -> bool {
    let Some((net, bits)) = parse_cidr(cidr) else { return false };
    values.iter().filter_map(|v| v.parse::<IpAddr>().ok()).any(|ip| in_cidr(ip, net, bits))
}

fn parse_cidr(cidr: &str) -> Option<(IpAddr, u32)> {
    match cidr.split_once('/') {
        Some((a, b)) => Some((a.parse().ok()?, b.parse().ok()?)),
        None => {
            let ip: IpAddr = cidr.parse().ok()?;
            Some((ip, if ip.is_ipv4() { 32 } else { 128 }))
        }
    }
}

fn in_cidr(ip: IpAddr, net: IpAddr, bits: u32) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits.min(32)) };
            u32::from(a) & mask == u32::from(b) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits.min(128)) };
            u128::from(a) & mask == u128::from(b) & mask
        }
        _ => false,
    }
}

/// Map filters (`key`, `value`, `comparison`) against the maps at a path.
fn match_maps(maps: &[&Value], filters: &[&Value]) -> bool {
    let entry = |m: &Value, k: &str| m.get(k).and_then(as_text);
    let check = |f: &Value| {
        let key = f.get("key").and_then(Value::as_str).unwrap_or("");
        let target = f.get("value").and_then(Value::as_str).unwrap_or("");
        let comparison = f.get("comparison").and_then(Value::as_str).unwrap_or("EQUALS");
        (maps.iter().any(|m| entry(m, key).is_some_and(|v| string_cmp(&v, comparison, target))), negative(comparison))
    };
    let mut any_pos = false;
    let mut pos_hit = false;
    for f in filters {
        let (hit, neg) = check(f);
        if neg {
            if hit {
                return false;
            }
        } else {
            any_pos = true;
            pos_hit |= hit;
        }
    }
    !any_pos || pos_hit
}

/// Whether the filters for one attribute (as serde JSON) match the
/// values at `path` in `doc`.
pub fn match_attribute(doc: &Value, path: &str, filters: &[Value], now: DateTime<Utc>) -> bool {
    if filters.is_empty() {
        return true;
    }
    let values = values_at(doc, path);
    let first = &filters[0];
    if first.get("key").is_some() {
        let refs: Vec<&Value> = filters.iter().collect();
        return match_maps(&values, &refs);
    }
    if first.get("cidr").is_some() {
        let texts: Vec<String> = values.iter().filter_map(|v| as_text(v)).collect();
        return filters.iter().any(|f| f.get("cidr").and_then(Value::as_str).is_some_and(|c| match_ip(&texts, c)));
    }
    if ["gte", "lte", "gt", "lt", "eq"].iter().any(|k| first.get(*k).is_some()) {
        let nums: Vec<f64> = values.iter().filter_map(|v| v.as_f64().or_else(|| v.as_str()?.parse().ok())).collect();
        return filters.iter().any(|f| match_number(&nums, f));
    }
    if ["start", "end", "date_range"].iter().any(|k| first.get(*k).is_some()) {
        let dates: Vec<DateTime<Utc>> = values.iter().filter_map(|v| v.as_str().and_then(parse_time)).collect();
        return filters.iter().any(|f| match_date(&dates, f, now));
    }
    if first.get("value").is_some_and(Value::is_boolean) {
        return filters.iter().any(|f| values.iter().any(|v| v.as_bool() == f.get("value").and_then(Value::as_bool)));
    }
    let texts: Vec<String> = values.iter().filter_map(|v| as_text(v)).collect();
    let pairs: Vec<(String, String)> = filters
        .iter()
        .map(|f| {
            (
                f.get("value").and_then(Value::as_str).unwrap_or("").to_string(),
                f.get("comparison").and_then(Value::as_str).unwrap_or("EQUALS").to_string(),
            )
        })
        .collect();
    match_strings(&texts, &pairs)
}

/// Whether ASFF filters (any serde-serialized filters struct) match a
/// finding.
pub fn matches_asff(finding: &Value, filters: &Value, now: DateTime<Utc>) -> bool {
    let Some(obj) = filters.as_object() else { return true };
    obj.iter().all(|(name, list)| {
        let Some(list) = list.as_array() else { return true };
        if list.is_empty() {
            return true;
        }
        if normalize(name) == "keyword" {
            let text = finding.to_string();
            return list.iter().any(|f| f.get("value").and_then(Value::as_str).is_some_and(|k| text.contains(k)));
        }
        match asff_path(name) {
            Some(path) => match_attribute(finding, path, list, now),
            None => true,
        }
    })
}

/// Whether OCSF composite filters (serde JSON of `OcsfFindingFilters`,
/// `ResourcesFilters`, ...) match `doc`.
pub fn matches_composite(doc: &Value, filters: &Value, now: DateTime<Utc>) -> bool {
    let composites = filters.get("composite_filters").and_then(Value::as_array).cloned().unwrap_or_default();
    if composites.is_empty() {
        return true;
    }
    let or = filters.get("composite_operator").and_then(Value::as_str) == Some("OR");
    let mut results = composites.iter().map(|c| composite(doc, c, now));
    if or {
        results.any(|r| r)
    } else {
        results.all(|r| r)
    }
}

fn composite(doc: &Value, c: &Value, now: DateTime<Utc>) -> bool {
    let or = c.get("operator").and_then(Value::as_str) == Some("OR");
    let mut results = Vec::new();
    for kind in ["string_filters", "date_filters", "boolean_filters", "number_filters", "map_filters", "ip_filters"] {
        for f in c.get(kind).and_then(Value::as_array).into_iter().flatten() {
            let Some(field) = f.get("field_name").and_then(Value::as_str) else { continue };
            let Some(filter) = f.get("filter") else { continue };
            results.push(match_attribute(doc, field, std::slice::from_ref(filter), now));
        }
    }
    for nested in c.get("nested_composite_filters").and_then(Value::as_array).into_iter().flatten() {
        results.push(composite(doc, nested, now));
    }
    if results.is_empty() {
        return true;
    }
    if or {
        results.into_iter().any(|r| r)
    } else {
        results.into_iter().all(|r| r)
    }
}

/// The sort key of `doc` for `field` (an ASFF attribute or a path).
fn sort_key(doc: &Value, path: &str) -> Option<Value> {
    values_at(doc, path).first().map(|v| (*v).clone())
}

fn cmp_values(a: &Option<Value>, b: &Option<Value>) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (a, b) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(a), Some(b)) => match (a.as_f64(), b.as_f64()) {
            (Some(x), Some(y)) => x.partial_cmp(&y).unwrap_or(Ordering::Equal),
            _ => as_text(a).unwrap_or_default().cmp(&as_text(b).unwrap_or_default()),
        },
    }
}

/// Sort documents by `(field, order)` criteria. ASFF attribute names are
/// mapped to paths when `asff`.
pub fn sort(docs: &mut [Value], criteria: &[(String, String)], asff: bool) {
    let paths: Vec<(String, bool)> = criteria
        .iter()
        .map(|(f, o)| {
            let path = if asff { asff_path(f).map(str::to_string).unwrap_or_else(|| f.clone()) } else { f.clone() };
            (path, o.eq_ignore_ascii_case("desc"))
        })
        .collect();
    docs.sort_by(|a, b| {
        for (path, desc) in &paths {
            let o = cmp_values(&sort_key(a, path), &sort_key(b, path));
            let o = if *desc { o.reverse() } else { o };
            if o != std::cmp::Ordering::Equal {
                return o;
            }
        }
        std::cmp::Ordering::Equal
    });
}

/// The distinct text values at `path` in `doc` (for grouping).
pub fn group_values(doc: &Value, path: &str) -> Vec<String> {
    let mut out: Vec<String> = values_at(doc, path).into_iter().filter_map(as_text).collect();
    out.sort();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn strings_combine_like_security_hub() {
        let f = json!({"Severity": {"Label": "HIGH"}, "Resources": [{"Type": "AwsS3Bucket"}, {"Type": "AwsIamRole"}]});
        let now = Utc::now();
        assert!(matches_asff(&f, &json!({"severity_label": [{"value": "HIGH", "comparison": "EQUALS"}, {"value": "LOW", "comparison": "EQUALS"}]}), now));
        assert!(!matches_asff(&f, &json!({"severity_label": [{"value": "LOW", "comparison": "EQUALS"}]}), now));
        assert!(matches_asff(&f, &json!({"resource_type": [{"value": "AwsIam", "comparison": "PREFIX"}]}), now));
        assert!(!matches_asff(&f, &json!({"resource_type": [{"value": "AwsIamRole", "comparison": "NOT_EQUALS"}]}), now));
    }

    #[test]
    fn cidr_and_numbers() {
        let f = json!({"Network": {"SourceIpV4": "10.1.2.3"}, "Severity": {"Normalized": 70}});
        let now = Utc::now();
        assert!(matches_asff(&f, &json!({"network_source_ip_v4": [{"cidr": "10.0.0.0/8"}]}), now));
        assert!(!matches_asff(&f, &json!({"network_source_ip_v4": [{"cidr": "192.168.0.0/16"}]}), now));
        assert!(matches_asff(&f, &json!({"severity_normalized": [{"gte": 70.0}]}), now));
        assert!(!matches_asff(&f, &json!({"severity_normalized": [{"gt": 70.0}]}), now));
    }
}

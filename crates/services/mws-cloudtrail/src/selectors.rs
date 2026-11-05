//! Event selectors: which events a trail or event data store takes, and
//! checking selectors the way `PutEventSelectors` does.

use mws_core::ServiceError;
use serde_json::Value;

use crate::generated::{errors, types};
use crate::record::{data_event_type, Recorded};

/// Basic selectors when a trail has none: every management event.
pub fn default_selectors() -> Vec<types::EventSelector> {
    vec![types::EventSelector {
        read_write_type: Some("All".into()),
        include_management_events: Some(true),
        data_resources: Some(Vec::new()),
        exclude_management_event_sources: Some(Vec::new()),
    }]
}

/// Advanced selectors when an event data store is created without any.
pub fn default_advanced_selectors() -> Vec<types::AdvancedEventSelector> {
    vec![types::AdvancedEventSelector {
        name: Some("Default management events".into()),
        field_selectors: vec![types::AdvancedFieldSelector {
            field: "eventCategory".into(),
            equals: Some(vec!["Management".into()]),
            ..Default::default()
        }],
    }]
}

fn read_write_matches(rw: Option<&str>, read_only: bool) -> bool {
    match rw.unwrap_or("All") {
        "ReadOnly" => read_only,
        "WriteOnly" => !read_only,
        _ => true,
    }
}

/// Whether basic selectors take the event.
pub fn basic_matches(selectors: &[types::EventSelector], e: &Recorded) -> bool {
    selectors.iter().any(|s| {
        if !read_write_matches(s.read_write_type.as_deref(), e.read_only) {
            return false;
        }
        if e.management {
            s.include_management_events.unwrap_or(true)
                && !s.exclude_management_event_sources.iter().flatten().any(|x| x == &e.event_source)
        } else {
            let Some(kind) = data_event_type(&e.event_source, &e.event_name) else { return false };
            s.data_resources.iter().flatten().any(|d| {
                d.r#type.as_deref() == Some(kind)
                    && d.values
                        .iter()
                        .flatten()
                        .any(|v| e.resources.iter().any(|(t, arn)| t == kind && value_matches(kind, v, arn)))
            })
        }
    })
}

/// A data resource value: a prefix of the resource ARN; `arn:aws:s3` (or
/// `arn:aws:s3:::`) and `arn:aws:lambda` stand for all.
fn value_matches(kind: &str, value: &str, arn: &str) -> bool {
    if kind == "AWS::S3::Object" && value.ends_with(":::") {
        return true;
    }
    if value.matches(':').count() <= 2 {
        return arn.starts_with(value);
    }
    arn.starts_with(value)
}

/// The values of `field` in the event, for advanced selectors.
fn field_values(field: &str, e: &Recorded) -> Vec<String> {
    let r = &e.record;
    let s = |v: &Value| match v {
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null => None,
        other => Some(other.to_string()),
    };
    match field {
        "readOnly" => vec![e.read_only.to_string()],
        "eventCategory" => vec![if e.management { "Management" } else { "Data" }.to_string()],
        "resources.type" => {
            let mut v: Vec<String> = e.resources.iter().map(|(t, _)| t.clone()).collect();
            if let Some(kind) = data_event_type(&e.event_source, &e.event_name) {
                v.retain(|t| t == kind);
                if v.is_empty() {
                    v.push(kind.to_string());
                }
            }
            v
        }
        "resources.ARN" => {
            let kind = data_event_type(&e.event_source, &e.event_name);
            e.resources.iter().filter(|(t, _)| kind.is_none_or(|k| k == t)).map(|(_, a)| a.clone()).collect()
        }
        "userIdentity.arn" => r.pointer("/userIdentity/arn").and_then(s).into_iter().collect(),
        other => r.get(other).and_then(s).into_iter().collect(),
    }
}

fn field_matches(f: &types::AdvancedFieldSelector, values: &[String]) -> bool {
    let any = |list: &Option<Vec<String>>, test: &dyn Fn(&str, &str) -> bool| {
        list.as_ref().is_none_or(|l| l.iter().any(|x| values.iter().any(|v| test(v, x))))
    };
    let none = |list: &Option<Vec<String>>, test: &dyn Fn(&str, &str) -> bool| {
        list.as_ref().is_none_or(|l| !l.iter().any(|x| values.iter().any(|v| test(v, x))))
    };
    let eq = |v: &str, x: &str| v == x;
    let sw = |v: &str, x: &str| v.starts_with(x);
    let ew = |v: &str, x: &str| v.ends_with(x);
    any(&f.equals, &eq)
        && any(&f.starts_with, &sw)
        && any(&f.ends_with, &ew)
        && none(&f.not_equals, &eq)
        && none(&f.not_starts_with, &sw)
        && none(&f.not_ends_with, &ew)
}

/// Whether advanced selectors take the event: any selector whose field
/// selectors all match.
pub fn advanced_matches(selectors: &[types::AdvancedEventSelector], e: &Recorded) -> bool {
    selectors.iter().any(|s| s.field_selectors.iter().all(|f| field_matches(f, &field_values(&f.field, e))))
}

const MANAGEMENT_FIELDS: &[&str] = &["eventCategory", "readOnly", "eventSource", "eventName"];
const DATA_FIELDS: &[&str] = &[
    "eventCategory",
    "eventSource",
    "eventName",
    "eventType",
    "readOnly",
    "resources.type",
    "resources.ARN",
    "userIdentity.arn",
    "errorCode",
    "sessionCredentialFromConsole",
    "vpcEndpointId",
];

/// Check advanced selectors as AWS does.
pub fn validate_advanced(selectors: &[types::AdvancedEventSelector], for_trail: bool) -> Result<(), ServiceError> {
    let invalid = |m: String| errors::invalid_event_selectors(m);
    if selectors.is_empty() {
        return Err(invalid("No advanced event selectors were specified.".into()));
    }
    if selectors.len() > 500 {
        return Err(invalid("The number of advanced event selectors exceeds the limit.".into()));
    }
    for s in selectors {
        let category = s
            .field_selectors
            .iter()
            .find(|f| f.field == "eventCategory")
            .and_then(|f| f.equals.as_ref())
            .and_then(|e| e.first())
            .cloned();
        let Some(category) = category else {
            return Err(invalid(
                "Invalid request provided: eventCategory is a required field in an advanced event selector.".into(),
            ));
        };
        let allowed: &[&str] = match category.as_str() {
            "Management" => MANAGEMENT_FIELDS,
            "Data" => DATA_FIELDS,
            "NetworkActivity" | "ActivityAuditLog" | "ConfigurationItem" | "Insight" if !for_trail => DATA_FIELDS,
            "NetworkActivity" => DATA_FIELDS,
            other => {
                return Err(invalid(format!(
                    "Invalid request provided: The value {other} is not valid for the field eventCategory."
                )))
            }
        };
        for f in &s.field_selectors {
            if !allowed.contains(&f.field.as_str()) {
                return Err(invalid(format!(
                    "Invalid request provided: The field {} is not valid for {category} events.",
                    f.field
                )));
            }
            let ops = [&f.equals, &f.starts_with, &f.ends_with, &f.not_equals, &f.not_starts_with, &f.not_ends_with];
            if ops.iter().all(|o| o.as_ref().is_none_or(Vec::is_empty)) {
                return Err(invalid(format!(
                    "Invalid request provided: The field {} must have at least one operator.",
                    f.field
                )));
            }
            if f.field == "readOnly" {
                let bad = ops.iter().flat_map(|o| o.iter().flatten()).find(|v| *v != "true" && *v != "false");
                if let Some(v) = bad {
                    return Err(invalid(format!(
                        "Invalid request provided: The value {v} is not valid for the field readOnly."
                    )));
                }
            }
        }
        if category == "Data" && !s.field_selectors.iter().any(|f| f.field == "resources.type") {
            return Err(invalid(
                "Invalid request provided: resources.type is a required field for data events.".into(),
            ));
        }
    }
    Ok(())
}

const DATA_RESOURCE_TYPES: &[&str] = &["AWS::S3::Object", "AWS::Lambda::Function", "AWS::DynamoDB::Table"];

/// Check basic selectors as AWS does.
pub fn validate_basic(selectors: &[types::EventSelector]) -> Result<(), ServiceError> {
    if selectors.len() > 5 {
        return Err(errors::invalid_event_selectors(
            "You have exceeded the maximum number of event selectors for this trail.",
        ));
    }
    for s in selectors {
        if let Some(rw) = &s.read_write_type {
            if !["ReadOnly", "WriteOnly", "All"].contains(&rw.as_str()) {
                return Err(errors::invalid_event_selectors(format!("Value {rw} for ReadWriteType is invalid.")));
            }
        }
        for d in s.data_resources.iter().flatten() {
            let t = d.r#type.as_deref().unwrap_or_default();
            if !DATA_RESOURCE_TYPES.contains(&t) {
                return Err(errors::invalid_event_selectors(format!(
                    "Invalid request provided: {t} is not a valid data resource type for basic event selectors."
                )));
            }
            for v in d.values.iter().flatten() {
                let ok = match t {
                    "AWS::S3::Object" => v.starts_with("arn:") && v.contains(":s3:"),
                    "AWS::Lambda::Function" => v.starts_with("arn:") && v.contains(":lambda"),
                    _ => v.starts_with("arn:"),
                };
                if !ok {
                    return Err(errors::invalid_event_selectors(format!(
                        "Value {v} for DataResources.Values is invalid."
                    )));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;

    fn event(source: &str, name: &str, read_only: bool, resources: Vec<(&str, &str)>) -> Recorded {
        Recorded {
            record: json!({"eventSource": source, "eventName": name, "userIdentity": {"arn": "arn:aws:iam::1:user/a"}}),
            account: "1".into(),
            region: "us-east-1".into(),
            event_id: "e".into(),
            event_name: name.into(),
            event_source: source.into(),
            time: Utc::now(),
            read_only,
            management: data_event_type(source, name).is_none(),
            global: false,
            resources: resources.into_iter().map(|(a, b)| (a.to_string(), b.to_string())).collect(),
            access_key_id: None,
            username: None,
        }
    }

    #[test]
    fn default_selectors_take_management_events_only() {
        let d = default_selectors();
        assert!(basic_matches(&d, &event("iam.amazonaws.com", "CreateUser", false, vec![])));
        assert!(!basic_matches(
            &d,
            &event("s3.amazonaws.com", "PutObject", false, vec![("AWS::S3::Object", "arn:aws:s3:::b/k")])
        ));
    }

    #[test]
    fn data_resources_match_prefixes() {
        let s = vec![types::EventSelector {
            read_write_type: Some("WriteOnly".into()),
            include_management_events: Some(false),
            data_resources: Some(vec![types::DataResource {
                r#type: Some("AWS::S3::Object".into()),
                values: Some(vec!["arn:aws:s3:::b/logs/".into()]),
            }]),
            exclude_management_event_sources: None,
        }];
        let put = |k: &str| event("s3.amazonaws.com", "PutObject", false, vec![("AWS::S3::Object", k)]);
        assert!(basic_matches(&s, &put("arn:aws:s3:::b/logs/x")));
        assert!(!basic_matches(&s, &put("arn:aws:s3:::b/other")));
        assert!(!basic_matches(&s, &event("iam.amazonaws.com", "CreateUser", false, vec![])));
    }

    #[test]
    fn advanced_selectors_and_fields() {
        let s = vec![types::AdvancedEventSelector {
            name: None,
            field_selectors: vec![
                types::AdvancedFieldSelector {
                    field: "eventCategory".into(),
                    equals: Some(vec!["Management".into()]),
                    ..Default::default()
                },
                types::AdvancedFieldSelector {
                    field: "readOnly".into(),
                    equals: Some(vec!["false".into()]),
                    ..Default::default()
                },
                types::AdvancedFieldSelector {
                    field: "eventSource".into(),
                    not_equals: Some(vec!["kms.amazonaws.com".into()]),
                    ..Default::default()
                },
            ],
        }];
        assert!(advanced_matches(&s, &event("iam.amazonaws.com", "CreateUser", false, vec![])));
        assert!(!advanced_matches(&s, &event("iam.amazonaws.com", "GetUser", true, vec![])));
        assert!(!advanced_matches(&s, &event("kms.amazonaws.com", "CreateKey", false, vec![])));
        validate_advanced(&s, true).unwrap();
    }
}

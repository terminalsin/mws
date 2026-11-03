//! Parameter policies: `Expiration`, `ExpirationNotification` and
//! `NoChangeNotification`. Expiration really deletes the parameter once the
//! emulated clock passes its timestamp. The notification policies are
//! validated and stored; their EventBridge events are not delivered.

use chrono::{DateTime, Utc};
use mws_core::ServiceError;
use serde_json::Value;

use crate::generated::errors;
use crate::state::StoredPolicy;

const TYPES: &[&str] = &["Expiration", "ExpirationNotification", "NoChangeNotification"];

fn attribute_error(message: impl Into<String>) -> ServiceError {
    errors::invalid_policy_attribute(message)
}

fn positive_int(attrs: &Value, name: &str, policy: &str) -> Result<(), ServiceError> {
    let v =
        attrs.get(name).ok_or_else(|| attribute_error(format!("{policy} policy requires the {name} attribute.")))?;
    let n = match v {
        Value::String(s) => s.parse::<i64>().ok(),
        Value::Number(n) => n.as_i64(),
        _ => None,
    };
    if !n.is_some_and(|n| n > 0) {
        return Err(attribute_error(format!("{policy} policy attribute {name} must be a positive integer.")));
    }
    Ok(())
}

fn unit(attrs: &Value, policy: &str) -> Result<(), ServiceError> {
    match attrs.get("Unit").and_then(Value::as_str) {
        Some("Days" | "Hours") => Ok(()),
        _ => Err(attribute_error(format!("{policy} policy attribute Unit must be Days or Hours."))),
    }
}

/// The expiration timestamp of an `Expiration` policy.
pub fn expiration(p: &StoredPolicy) -> Option<DateTime<Utc>> {
    if p.policy_type != "Expiration" {
        return None;
    }
    let v: Value = serde_json::from_str(&p.text).ok()?;
    let ts = v.get("Attributes")?.get("Timestamp")?.as_str()?;
    DateTime::parse_from_rfc3339(ts).ok().map(|t| t.with_timezone(&Utc))
}

/// Parse and validate the `Policies` JSON array of `PutParameter`.
pub fn parse(text: &str, now: DateTime<Utc>) -> Result<Vec<StoredPolicy>, ServiceError> {
    let parsed: Value = serde_json::from_str(text)
        .map_err(|_| errors::validation("Invalid policies input: the policies must be a valid JSON array."))?;
    let Value::Array(items) = parsed else {
        return Err(errors::validation("Invalid policies input: the policies must be a valid JSON array."));
    };
    if items.len() > 10 {
        return Err(errors::policies_limit_exceeded(
            "You specified more than the maximum number of allowed policies for the parameter. The maximum is 10.",
        ));
    }
    let mut out: Vec<StoredPolicy> = Vec::new();
    for item in items {
        let ty = item.get("Type").and_then(Value::as_str).unwrap_or_default().to_string();
        if !TYPES.contains(&ty.as_str()) {
            return Err(errors::invalid_policy_type(format!(
                "The policy type {ty} isn't supported. Parameter Store supports the following policy types: Expiration, ExpirationNotification, and NoChangeNotification."
            )));
        }
        if item.get("Version").and_then(Value::as_str) != Some("1.0") {
            return Err(attribute_error(format!("{ty} policy Version must be 1.0.")));
        }
        let attrs = item.get("Attributes").cloned().unwrap_or(Value::Null);
        if !attrs.is_object() {
            return Err(attribute_error(format!("{ty} policy requires Attributes.")));
        }
        match ty.as_str() {
            "Expiration" => {
                let ts = attrs
                    .get("Timestamp")
                    .and_then(Value::as_str)
                    .and_then(|t| DateTime::parse_from_rfc3339(t).ok())
                    .ok_or_else(|| {
                        attribute_error("Expiration policy attribute Timestamp must be an ISO 8601 timestamp, for example 2026-12-02T21:34:33.000Z.")
                    })?;
                if ts.with_timezone(&Utc) <= now {
                    return Err(attribute_error("Expiration policy attribute Timestamp must be in the future."));
                }
            }
            "ExpirationNotification" => {
                positive_int(&attrs, "Before", &ty)?;
                unit(&attrs, &ty)?;
            }
            _ => {
                positive_int(&attrs, "After", &ty)?;
                unit(&attrs, &ty)?;
            }
        }
        if out.iter().any(|p| p.policy_type == ty) {
            return Err(errors::incompatible_policy(
                "There is a conflict in the policies specified for this parameter. You can't, for example, specify two Expiration policies for a parameter. Review your policies, and try again.",
            ));
        }
        out.push(StoredPolicy { text: item.to_string(), policy_type: ty, status: "Pending".into() });
    }
    if out.iter().any(|p| p.policy_type == "ExpirationNotification")
        && !out.iter().any(|p| p.policy_type == "Expiration")
    {
        return Err(errors::incompatible_policy(
            "An ExpirationNotification policy requires an Expiration policy on the same parameter.",
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates() {
        let now = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z").unwrap().with_timezone(&Utc);
        let ok = r#"[{"Type":"Expiration","Version":"1.0","Attributes":{"Timestamp":"2027-01-01T00:00:00.000Z"}},
                     {"Type":"ExpirationNotification","Version":"1.0","Attributes":{"Before":"15","Unit":"Days"}},
                     {"Type":"NoChangeNotification","Version":"1.0","Attributes":{"After":"20","Unit":"Hours"}}]"#;
        let p = parse(ok, now).unwrap();
        assert_eq!(p.len(), 3);
        assert!(expiration(&p[0]).is_some());
        assert_eq!(parse("[]", now).unwrap().len(), 0);
        let past = r#"[{"Type":"Expiration","Version":"1.0","Attributes":{"Timestamp":"2020-01-01T00:00:00Z"}}]"#;
        assert_eq!(parse(past, now).unwrap_err().code, "InvalidPolicyAttributeException");
        let bad = r#"[{"Type":"Nope","Version":"1.0","Attributes":{}}]"#;
        assert_eq!(parse(bad, now).unwrap_err().code, "InvalidPolicyTypeException");
        let twice = r#"[{"Type":"NoChangeNotification","Version":"1.0","Attributes":{"After":"1","Unit":"Days"}},
                        {"Type":"NoChangeNotification","Version":"1.0","Attributes":{"After":"2","Unit":"Days"}}]"#;
        assert_eq!(parse(twice, now).unwrap_err().code, "IncompatiblePolicyException");
    }
}

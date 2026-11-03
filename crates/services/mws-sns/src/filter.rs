//! Subscription filter policies: validation and matching, for both the
//! `MessageAttributes` and `MessageBody` scopes.

use std::collections::BTreeMap;
use std::net::IpAddr;

use mws_core::ServiceError;
use serde_json::Value;

use crate::errors;
use crate::generated::types::MessageAttributeValue;

const MAX_KEYS: usize = 5;
const MAX_COMBINATIONS: usize = 150;

fn bad(why: impl std::fmt::Display) -> ServiceError {
    errors::invalid(format!("FilterPolicy: {why}"))
}

/// Parse and check a filter policy. Returns the parsed document.
pub fn validate(doc: &str, body_scope: bool) -> Result<Value, ServiceError> {
    let v: Value = serde_json::from_str(doc).map_err(|_| bad("failed to parse JSON."))?;
    let obj = v.as_object().ok_or_else(|| bad("Filter policy must be a JSON object"))?;
    if obj.is_empty() {
        return Ok(v);
    }
    let mut keys = 0usize;
    let combos = check_object(obj, body_scope, &mut keys, 0)?;
    if keys > MAX_KEYS && !body_scope {
        return Err(bad("Filter policy can not have more than 5 keys"));
    }
    if combos > MAX_COMBINATIONS {
        return Err(bad("Filter policy is too complex"));
    }
    Ok(v)
}

/// Returns the number of value combinations the object allows.
fn check_object(
    obj: &serde_json::Map<String, Value>,
    body_scope: bool,
    keys: &mut usize,
    depth: usize,
) -> Result<usize, ServiceError> {
    if depth > 5 {
        return Err(bad("Filter policy is too deeply nested"));
    }
    let mut combos = 1usize;
    for (k, v) in obj {
        if k == "$or" {
            let alts =
                v.as_array().filter(|a| a.len() >= 2).ok_or_else(|| bad("$or must be a list of at least 2 objects"))?;
            let mut sum = 0usize;
            for alt in alts {
                let o = alt.as_object().ok_or_else(|| bad("$or must be a list of at least 2 objects"))?;
                sum = sum.saturating_add(check_object(o, body_scope, keys, depth + 1)?);
            }
            combos = combos.saturating_mul(sum);
            continue;
        }
        match v {
            Value::Array(conditions) => {
                *keys += 1;
                if conditions.is_empty() {
                    return Err(bad("Empty arrays are not allowed"));
                }
                for c in conditions {
                    check_condition(c)?;
                }
                combos = combos.saturating_mul(conditions.len());
            }
            Value::Object(nested) if body_scope => {
                combos = combos.saturating_mul(check_object(nested, body_scope, keys, depth + 1)?);
            }
            Value::Object(_) => {
                return Err(bad("Filter policy scope MessageAttributes does not support nested filter policy"));
            }
            _ => return Err(bad(format!("\"{k}\" must be an object or an array"))),
        }
    }
    Ok(combos)
}

fn check_condition(c: &Value) -> Result<(), ServiceError> {
    match c {
        Value::String(_) | Value::Number(_) | Value::Null | Value::Bool(_) => Ok(()),
        Value::Array(_) => Err(bad("Match value must be String, number, true, false, or null")),
        Value::Object(o) => {
            if o.len() != 1 {
                return Err(bad("Only one key allowed in match expression"));
            }
            let (op, arg) = o.iter().next().expect("one entry");
            match op.as_str() {
                "prefix" | "suffix" | "equals-ignore-case" => match arg {
                    Value::String(_) => Ok(()),
                    _ => Err(bad(format!("{op} match pattern must be a string"))),
                },
                "exists" => match arg {
                    Value::Bool(_) => Ok(()),
                    _ => Err(bad("exists match pattern must be either true or false.")),
                },
                "anything-but" => match arg {
                    Value::String(_) | Value::Number(_) => Ok(()),
                    Value::Array(a) if !a.is_empty() && a.iter().all(|x| x.is_string() || x.is_number()) => Ok(()),
                    Value::Object(inner) if inner.len() == 1 => {
                        let (k, v) = inner.iter().next().expect("one entry");
                        if matches!(k.as_str(), "prefix" | "suffix") && v.is_string() {
                            Ok(())
                        } else {
                            Err(bad(format!("Unsupported anything-but pattern: {k}")))
                        }
                    }
                    _ => Err(bad("Value of anything-but must be an array or single string/number value.")),
                },
                "numeric" => check_numeric(arg),
                "cidr" => match arg.as_str().and_then(parse_cidr) {
                    Some(_) => Ok(()),
                    None => Err(bad("Malformed CIDR, one '/' required")),
                },
                other => Err(bad(format!("Unrecognized match type {other}"))),
            }
        }
    }
}

fn check_numeric(arg: &Value) -> Result<(), ServiceError> {
    let a = arg.as_array().filter(|a| !a.is_empty()).ok_or_else(|| bad("Value of numeric must be an array."))?;
    let num = |v: &Value| v.as_f64().ok_or_else(|| bad("Value of numeric operator must be numeric"));
    match a.len() {
        2 => {
            let op = a[0].as_str().unwrap_or("");
            if !matches!(op, "=" | "<" | "<=" | ">" | ">=") {
                return Err(bad(format!("Unrecognized numeric range operator: {op}")));
            }
            num(&a[1])?;
        }
        4 => {
            let lo = a[0].as_str().unwrap_or("");
            let hi = a[2].as_str().unwrap_or("");
            if !matches!(lo, ">" | ">=") || !matches!(hi, "<" | "<=") {
                return Err(bad("Bad numeric range operator"));
            }
            if num(&a[1])? >= num(&a[3])? {
                return Err(bad("Bottom must be less than top"));
            }
        }
        _ => return Err(bad("Value of numeric must be an array of 2 or 4 items")),
    }
    Ok(())
}

/// The value a message attribute exposes to filters.
enum Field {
    Missing,
    Values(Vec<Value>),
}

fn attribute_values(a: &MessageAttributeValue) -> Option<Vec<Value>> {
    let ty = a.data_type.split('.').next().unwrap_or("");
    let s = a.string_value.as_deref()?;
    if a.data_type.starts_with("String.Array") {
        return match serde_json::from_str::<Value>(s) {
            Ok(Value::Array(items)) => Some(items),
            _ => None,
        };
    }
    match ty {
        "String" => Some(vec![Value::String(s.to_string())]),
        "Number" => Some(vec![s
            .parse::<f64>()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map(Value::Number)
            .unwrap_or_else(|| Value::String(s.to_string()))]),
        _ => None,
    }
}

/// Whether a message passes `policy`.
pub fn matches(
    policy: &Value,
    body_scope: bool,
    attributes: &BTreeMap<String, MessageAttributeValue>,
    body: &str,
) -> bool {
    let Some(obj) = policy.as_object() else { return true };
    if obj.is_empty() {
        return true;
    }
    if body_scope {
        let Ok(doc) = serde_json::from_str::<Value>(body) else { return false };
        match_body(obj, &doc)
    } else {
        match_attributes(obj, attributes)
    }
}

fn match_attributes(
    obj: &serde_json::Map<String, Value>,
    attributes: &BTreeMap<String, MessageAttributeValue>,
) -> bool {
    obj.iter().all(|(k, conds)| {
        if k == "$or" {
            return conds.as_array().is_some_and(|alts| {
                alts.iter().any(|a| a.as_object().is_some_and(|o| match_attributes(o, attributes)))
            });
        }
        let field = match attributes.get(k).and_then(attribute_values) {
            Some(v) => Field::Values(v),
            None => Field::Missing,
        };
        conds.as_array().is_some_and(|cs| cs.iter().any(|c| condition_matches(c, &field)))
    })
}

fn match_body(obj: &serde_json::Map<String, Value>, doc: &Value) -> bool {
    obj.iter().all(|(k, conds)| {
        if k == "$or" {
            return conds
                .as_array()
                .is_some_and(|alts| alts.iter().any(|a| a.as_object().is_some_and(|o| match_body(o, doc))));
        }
        let child = doc.get(k);
        match conds {
            Value::Object(nested) => match child {
                Some(Value::Array(items)) => items.iter().any(|i| match_body(nested, i)),
                Some(c) => match_body(nested, c),
                None => match_body(nested, &Value::Null),
            },
            Value::Array(cs) => {
                let field = match child {
                    None => Field::Missing,
                    Some(Value::Array(items)) => Field::Values(items.clone()),
                    Some(Value::Object(_)) => Field::Missing,
                    Some(v) => Field::Values(vec![v.clone()]),
                };
                cs.iter().any(|c| condition_matches(c, &field))
            }
            _ => false,
        }
    })
}

fn condition_matches(cond: &Value, field: &Field) -> bool {
    if let Value::Object(o) = cond {
        if let Some(Value::Bool(want)) = o.get("exists") {
            return matches!(field, Field::Values(_)) == *want;
        }
    }
    let Field::Values(values) = field else { return false };
    if let Some(Value::Object(o)) = Some(cond) {
        if let Some(arg) = o.get("anything-but") {
            // anything-but holds when no value is excluded.
            return !values.is_empty() && values.iter().all(|v| !anything_but_excludes(arg, v));
        }
    }
    values.iter().any(|v| value_matches(cond, v))
}

fn anything_but_excludes(arg: &Value, v: &Value) -> bool {
    match arg {
        Value::Array(items) => items.iter().any(|i| equal(i, v)),
        Value::Object(inner) => {
            let s = v.as_str().unwrap_or("");
            match (inner.get("prefix"), inner.get("suffix")) {
                (Some(Value::String(p)), _) => v.is_string() && s.starts_with(p.as_str()),
                (_, Some(Value::String(x))) => v.is_string() && s.ends_with(x.as_str()),
                _ => false,
            }
        }
        other => equal(other, v),
    }
}

fn equal(cond: &Value, v: &Value) -> bool {
    match (cond, v) {
        (Value::Number(a), Value::Number(b)) => a.as_f64() == b.as_f64(),
        (Value::Number(a), Value::String(b)) => b.parse::<f64>().ok() == a.as_f64(),
        (a, b) => a == b,
    }
}

fn value_matches(cond: &Value, v: &Value) -> bool {
    match cond {
        Value::Object(o) => {
            let Some((op, arg)) = o.iter().next() else { return false };
            let s = v.as_str();
            match op.as_str() {
                "prefix" => s.zip(arg.as_str()).is_some_and(|(s, p)| s.starts_with(p)),
                "suffix" => s.zip(arg.as_str()).is_some_and(|(s, p)| s.ends_with(p)),
                "equals-ignore-case" => s.zip(arg.as_str()).is_some_and(|(s, p)| s.eq_ignore_ascii_case(p)),
                "numeric" => {
                    let n = match v {
                        Value::Number(n) => n.as_f64(),
                        Value::String(s) => s.parse::<f64>().ok(),
                        _ => None,
                    };
                    n.is_some_and(|n| numeric_matches(arg, n))
                }
                "cidr" => match (s.and_then(|s| s.parse::<IpAddr>().ok()), arg.as_str().and_then(parse_cidr)) {
                    (Some(ip), Some((net, bits))) => in_cidr(ip, net, bits),
                    _ => false,
                },
                _ => false,
            }
        }
        other => equal(other, v),
    }
}

fn numeric_matches(arg: &Value, n: f64) -> bool {
    let Some(a) = arg.as_array() else { return false };
    a.chunks(2).all(|pair| {
        let (Some(op), Some(x)) = (pair.first().and_then(Value::as_str), pair.get(1).and_then(Value::as_f64)) else {
            return false;
        };
        match op {
            "=" => n == x,
            "<" => n < x,
            "<=" => n <= x,
            ">" => n > x,
            ">=" => n >= x,
            _ => false,
        }
    })
}

fn parse_cidr(s: &str) -> Option<(IpAddr, u8)> {
    let (ip, bits) = s.split_once('/')?;
    let ip: IpAddr = ip.parse().ok()?;
    let bits: u8 = bits.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    (bits <= max).then_some((ip, bits))
}

fn in_cidr(ip: IpAddr, net: IpAddr, bits: u8) -> bool {
    match (ip, net) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            (u32::from(a) & mask) == (u32::from(b) & mask)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            (u128::from(a) & mask) == (u128::from(b) & mask)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attrs(pairs: &[(&str, &str, &str)]) -> BTreeMap<String, MessageAttributeValue> {
        pairs
            .iter()
            .map(|(k, t, v)| {
                (
                    k.to_string(),
                    MessageAttributeValue {
                        data_type: t.to_string(),
                        string_value: Some(v.to_string()),
                        binary_value: None,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn attribute_scope() {
        let p = validate(r#"{"store":["example_corp"],"price_usd":[{"numeric":[">=",100]}]}"#, false).unwrap();
        assert!(matches(&p, false, &attrs(&[("store", "String", "example_corp"), ("price_usd", "Number", "150")]), ""));
        assert!(!matches(&p, false, &attrs(&[("store", "String", "example_corp"), ("price_usd", "Number", "50")]), ""));
        assert!(!matches(&p, false, &attrs(&[("price_usd", "Number", "150")]), ""));
        let p = validate(r#"{"customer_interests":["rugby"]}"#, false).unwrap();
        assert!(matches(&p, false, &attrs(&[("customer_interests", "String.Array", r#"["soccer","rugby"]"#)]), ""));
        let p = validate(r#"{"event":[{"anything-but":["a","b"]}],"x":[{"exists":false}]}"#, false).unwrap();
        assert!(matches(&p, false, &attrs(&[("event", "String", "c")]), ""));
        assert!(!matches(&p, false, &attrs(&[("event", "String", "a")]), ""));
        assert!(!matches(&p, false, &attrs(&[("event", "String", "c"), ("x", "String", "1")]), ""));
        let p =
            validate(r#"{"ip":[{"cidr":"10.0.0.0/24"}],"$or":[{"a":["1"]},{"b":[{"prefix":"x"}]}]}"#, false).unwrap();
        assert!(matches(&p, false, &attrs(&[("ip", "String", "10.0.0.7"), ("b", "String", "xyz")]), ""));
        assert!(!matches(&p, false, &attrs(&[("ip", "String", "10.0.1.7"), ("b", "String", "xyz")]), ""));
    }

    #[test]
    fn body_scope() {
        let p = validate(r#"{"patient":{"age":[{"numeric":[">",18]}],"name":[{"suffix":"son"}]}}"#, true).unwrap();
        assert!(matches(&p, true, &BTreeMap::new(), r#"{"patient":{"age":20,"name":"Jackson"}}"#));
        assert!(!matches(&p, true, &BTreeMap::new(), r#"{"patient":{"age":12,"name":"Jackson"}}"#));
        assert!(!matches(&p, true, &BTreeMap::new(), "not json"));
    }

    #[test]
    fn rejects_bad_policies() {
        assert!(validate("[]", false).is_err());
        assert!(validate(r#"{"a":"b"}"#, false).is_err());
        assert!(validate(r#"{"a":[{"bogus":1}]}"#, false).is_err());
        assert!(validate(r#"{"a":{"b":["c"]}}"#, false).is_err());
        assert!(validate(r#"{"a":[{"numeric":[">",5,"<",1]}]}"#, false).is_err());
        assert!(validate(r#"{"a":["1"],"b":["1"],"c":["1"],"d":["1"],"e":["1"],"f":["1"]}"#, false).is_err());
    }
}

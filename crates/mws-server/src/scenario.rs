//! Scenario files: a list of API calls that set up state.
//!
//! Each step names a service by its signing name, an operation by its wire
//! name, and the operation's input as JSON keyed by Smithy member names (the
//! same shape `aws <service> <command> --cli-input-json` takes). Steps run
//! in order through the services' own handlers, so they are validated and
//! authorized exactly like SDK calls. A step with an `id` makes its output
//! available to later steps as `${id.Path.To.Field}`. A reference can end
//! in filters: `|basename` keeps the text after the last `/` (Route 53 ids
//! come back as `/hostedzone/Z...` but go in bare, as the SDKs strip them)
//! and `|base64` encodes text for blob members (a CSR or certificate PEM).
//!
//! ```json
//! {
//!   "steps": [
//!     { "service": "iam", "action": "CreateUser", "input": { "UserName": "alice" } },
//!     { "id": "zone", "service": "route53", "action": "CreateHostedZone",
//!       "input": { "Name": "example.com", "CallerReference": "seed" } },
//!     { "service": "route53", "action": "ChangeResourceRecordSets",
//!       "input": { "HostedZoneId": "${zone.HostedZone.Id|basename}", "ChangeBatch": { "Changes": [] } } }
//!   ]
//! }
//! ```

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value;

/// A parsed scenario file.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Scenario {
    /// Free text; ignored.
    #[serde(default)]
    pub description: Option<String>,
    /// Region for steps that do not name one. Defaults to the gateway's.
    #[serde(default)]
    pub region: Option<String>,
    pub steps: Vec<Step>,
}

/// One API call.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Step {
    /// Name under which later steps can refer to this step's output.
    #[serde(default)]
    pub id: Option<String>,
    /// Free text; ignored.
    #[serde(default)]
    pub description: Option<String>,
    /// The service's signing name: `iam`, `sts`, `route53`, `acm-pca`, ...
    pub service: String,
    /// The operation's wire name, e.g. `CreateUser`.
    pub action: String,
    #[serde(default = "empty_object")]
    pub input: Value,
    #[serde(default)]
    pub region: Option<String>,
    /// Run as this access key instead of the gateway's scenario principal
    /// (normally the account root). Supports `${...}` references.
    #[serde(default)]
    pub access_key_id: Option<String>,
    /// Session token to go with a temporary `access_key_id`.
    #[serde(default)]
    pub session_token: Option<String>,
}

fn empty_object() -> Value {
    Value::Object(Default::default())
}

impl Scenario {
    pub fn parse(text: &str) -> Result<Self, String> {
        serde_json::from_str(text).map_err(|e| format!("invalid scenario: {e}"))
    }
}

/// Outputs of steps that had an `id`, by id.
pub type Outputs = BTreeMap<String, Value>;

/// Replace `${id.path}` references in every string inside `value`. A string
/// that is exactly one reference takes the referenced value whatever its
/// type; references inside longer strings are spliced in as text. `$${`
/// stands for a literal `${`.
pub fn interpolate(value: &Value, outputs: &Outputs) -> Result<Value, String> {
    Ok(match value {
        Value::String(s) => interpolate_str(s, outputs)?,
        Value::Array(a) => Value::Array(a.iter().map(|v| interpolate(v, outputs)).collect::<Result<_, _>>()?),
        Value::Object(o) => Value::Object(
            o.iter().map(|(k, v)| Ok((k.clone(), interpolate(v, outputs)?))).collect::<Result<_, String>>()?,
        ),
        other => other.clone(),
    })
}

/// Interpolate a string that must stay a string (credentials).
pub fn interpolate_string(s: &str, outputs: &Outputs) -> Result<String, String> {
    match interpolate_str(s, outputs)? {
        Value::String(s) => Ok(s),
        other => Ok(text_of(&other)),
    }
}

fn interpolate_str(s: &str, outputs: &Outputs) -> Result<Value, String> {
    if let Some(inner) = s.strip_prefix("${").and_then(|r| r.strip_suffix('}')) {
        if !inner.contains('}') && !inner.contains("${") {
            return lookup(inner, outputs);
        }
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(pos) = rest.find('$') {
        out.push_str(&rest[..pos]);
        let after = &rest[pos..];
        if let Some(r) = after.strip_prefix("$${") {
            out.push_str("${");
            rest = r;
        } else if let Some(r) = after.strip_prefix("${") {
            let end = r.find('}').ok_or_else(|| format!("unterminated reference in {s:?}"))?;
            out.push_str(&text_of(&lookup(&r[..end], outputs)?));
            rest = &r[end + 1..];
        } else {
            out.push('$');
            rest = &after[1..];
        }
    }
    out.push_str(rest);
    Ok(Value::String(out))
}

fn text_of(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn lookup(reference: &str, outputs: &Outputs) -> Result<Value, String> {
    let mut filters = reference.split('|');
    let path = filters.next().unwrap_or_default().trim();
    let mut v = lookup_path(path, outputs)?.clone();
    for filter in filters {
        v = match filter.trim() {
            "base64" => {
                use base64::Engine;
                Value::String(base64::engine::general_purpose::STANDARD.encode(text_of(&v)))
            }
            "basename" => {
                let t = text_of(&v);
                Value::String(t.rsplit('/').next().unwrap_or_default().to_string())
            }
            other => return Err(format!("${{{reference}}}: unknown filter {other:?}; use base64 or basename")),
        };
    }
    Ok(v)
}

fn lookup_path<'a>(reference: &str, outputs: &'a Outputs) -> Result<&'a Value, String> {
    let mut parts = reference.split('.');
    let id = parts.next().unwrap_or_default();
    let mut v = outputs.get(id).ok_or_else(|| format!("${{{reference}}}: no earlier step has id {id:?}"))?;
    for part in parts {
        v = match v {
            Value::Object(o) => o.get(part),
            Value::Array(a) => part.parse::<usize>().ok().and_then(|i| a.get(i)),
            _ => None,
        }
        .ok_or_else(|| format!("${{{reference}}}: the output of step {id:?} has nothing at {part:?}"))?;
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn outputs() -> Outputs {
        let mut o = Outputs::new();
        o.insert("zone".into(), json!({"HostedZone": {"Id": "/hostedzone/Z1", "Count": 3}, "List": ["a", "b"]}));
        o
    }

    #[test]
    fn whole_string_reference_keeps_type() {
        let v = interpolate(&json!({"n": "${zone.HostedZone.Count}", "id": "${zone.HostedZone.Id}"}), &outputs());
        assert_eq!(v.unwrap(), json!({"n": 3, "id": "/hostedzone/Z1"}));
    }

    #[test]
    fn spliced_references_and_escapes() {
        let v =
            interpolate(&json!(["x-${zone.List.1}-${zone.HostedZone.Count}", "$${literal}", "cost $5"]), &outputs());
        assert_eq!(v.unwrap(), json!(["x-b-3", "${literal}", "cost $5"]));
    }

    #[test]
    fn filters() {
        let v = interpolate(&json!(["${zone.HostedZone.Id|basename}", "${zone.List.0 | base64}"]), &outputs());
        assert_eq!(v.unwrap(), json!(["Z1", "YQ=="]));
        assert!(interpolate(&json!("${zone.List.0|rot13}"), &outputs()).unwrap_err().contains("unknown filter"));
    }

    #[test]
    fn unknown_references_fail() {
        assert!(interpolate(&json!("${nope.X}"), &outputs()).unwrap_err().contains("no earlier step"));
        assert!(interpolate(&json!("${zone.Missing}"), &outputs()).unwrap_err().contains("nothing at \"Missing\""));
        assert!(interpolate(&json!("a ${zone"), &outputs()).unwrap_err().contains("unterminated"));
    }

    #[test]
    fn parses_and_rejects_typos() {
        let s = Scenario::parse(r#"{"steps":[{"service":"iam","action":"CreateUser","input":{"UserName":"a"}}]}"#);
        assert_eq!(s.unwrap().steps[0].action, "CreateUser");
        let bad = Scenario::parse(r#"{"steps":[{"service":"iam","acton":"CreateUser"}]}"#);
        assert!(bad.unwrap_err().contains("unknown field"));
    }
}

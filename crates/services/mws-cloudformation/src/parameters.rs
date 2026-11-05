//! Template parameters: types, defaults, constraints and SSM parameter
//! types.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::template::Template;

const AWS_SPECIFIC: &[&str] = &[
    "AWS::EC2::AvailabilityZone::Name",
    "AWS::EC2::Image::Id",
    "AWS::EC2::Instance::Id",
    "AWS::EC2::KeyPair::KeyName",
    "AWS::EC2::SecurityGroup::GroupName",
    "AWS::EC2::SecurityGroup::Id",
    "AWS::EC2::Subnet::Id",
    "AWS::EC2::Volume::Id",
    "AWS::EC2::VPC::Id",
    "AWS::Route53::HostedZone::Id",
];

fn plain_type(t: &str) -> bool {
    matches!(t, "String" | "Number" | "List<Number>" | "CommaDelimitedList")
        || AWS_SPECIFIC.contains(&t)
        || t.strip_prefix("List<").and_then(|r| r.strip_suffix('>')).is_some_and(|i| AWS_SPECIFIC.contains(&i))
}

pub fn valid_type(t: &str) -> bool {
    if plain_type(t) || t == "AWS::SSM::Parameter::Name" {
        return true;
    }
    match ssm_value_type(t) {
        Some(inner) => inner == "String" || inner == "List<String>" || (plain_type(inner) && inner != "Number"),
        None => false,
    }
}

/// `T` of `AWS::SSM::Parameter::Value<T>`.
pub fn ssm_value_type(t: &str) -> Option<&str> {
    t.strip_prefix("AWS::SSM::Parameter::Value<").and_then(|r| r.strip_suffix('>'))
}

fn is_list(t: &str) -> bool {
    let t = ssm_value_type(t).unwrap_or(t);
    t.starts_with("List<") || t == "CommaDelimitedList"
}

/// A parameter's value on a stack.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct StackParameter {
    pub key: String,
    pub value: String,
    /// The value an SSM parameter type resolved to.
    pub resolved: Option<String>,
    pub no_echo: bool,
    pub ty: String,
}

impl Default for StackParameter {
    fn default() -> Self {
        Self { key: String::new(), value: String::new(), resolved: None, no_echo: false, ty: "String".into() }
    }
}

impl StackParameter {
    /// What `Ref` returns.
    pub fn ref_value(&self) -> Value {
        let v = self.resolved.as_deref().unwrap_or(&self.value);
        if is_list(&self.ty) {
            if v.is_empty() {
                return Value::Array(Vec::new());
            }
            Value::Array(v.split(',').map(|s| Value::String(s.trim().to_string())).collect())
        } else {
            Value::String(v.to_string())
        }
    }
}

/// A value the caller passed: a value, or `UsePreviousValue`.
#[derive(Debug, Clone)]
pub struct Provided {
    pub key: String,
    pub value: Option<String>,
    pub use_previous: bool,
}

/// Values for every template parameter, before SSM types are resolved.
pub fn assign(
    template: &Template,
    provided: &[Provided],
    previous: &[StackParameter],
) -> Result<Vec<StackParameter>, String> {
    let declared = template.parameters();
    let unknown: Vec<&str> = provided
        .iter()
        .filter(|p| !declared.iter().any(|(k, _)| k == &p.key))
        .map(|p| p.key.as_str())
        .collect();
    if !unknown.is_empty() {
        return Err(format!("Parameters: [{}] do not exist in the template", unknown.join(", ")));
    }
    let mut out = Vec::new();
    let mut missing = Vec::new();
    for (key, decl) in &declared {
        let ty = decl.get("Type").and_then(Value::as_str).unwrap_or("String").to_string();
        let no_echo = match decl.get("NoEcho") {
            Some(Value::Bool(b)) => *b,
            Some(Value::String(s)) => s.eq_ignore_ascii_case("true"),
            _ => false,
        };
        let given = provided.iter().find(|p| &p.key == key);
        let value = match given {
            Some(p) if p.use_previous => match previous.iter().find(|q| &q.key == key) {
                Some(q) => Some(q.value.clone()),
                None => {
                    return Err(format!(
                        "Invalid input for parameter key {key}. Cannot specify usePreviousValue as true for a parameter key not in the previous template"
                    ))
                }
            },
            Some(p) => p.value.clone(),
            None => decl.get("Default").map(scalar_text),
        };
        let Some(value) = value else {
            missing.push(key.clone());
            continue;
        };
        check_constraints(key, &ty, decl, &value)?;
        out.push(StackParameter { key: key.clone(), value, resolved: None, no_echo, ty });
    }
    if !missing.is_empty() {
        return Err(format!("Parameters: [{}] must have values", missing.join(", ")));
    }
    Ok(out)
}

fn scalar_text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().map(scalar_text).collect::<Vec<_>>().join(","),
        other => other.to_string(),
    }
}

fn number(v: Option<&Value>) -> Option<f64> {
    match v? {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    }
}

fn check_constraints(key: &str, ty: &str, decl: &Map<String, Value>, value: &str) -> Result<(), String> {
    let custom = decl.get("ConstraintDescription").and_then(Value::as_str);
    let fail = |default: String| -> String {
        match custom {
            Some(c) => format!("Parameter '{key}' failed to satisfy constraint: {c}"),
            None => default,
        }
    };
    let items: Vec<&str> = if is_list(ty) { value.split(',').map(str::trim).collect() } else { vec![value] };
    let numeric = ty == "Number" || ty == "List<Number>";
    for item in &items {
        if numeric && item.parse::<f64>().is_err() {
            return Err(format!("Parameter '{key}' must be a number."));
        }
        if let Some(allowed) = decl.get("AllowedValues").and_then(Value::as_array) {
            if !allowed.iter().any(|a| scalar_text(a) == *item) {
                return Err(fail(format!("Parameter '{key}' must be one of AllowedValues")));
            }
        }
        if let Some(pattern) = decl.get("AllowedPattern").and_then(Value::as_str) {
            let re = regex::Regex::new(&format!("^(?:{pattern})$"))
                .map_err(|_| format!("Parameter '{key}' has an invalid AllowedPattern"))?;
            if !re.is_match(item) {
                return Err(fail(format!("Parameter '{key}' must match pattern {pattern}")));
            }
        }
        if let Some(min) = number(decl.get("MinLength")) {
            if (item.chars().count() as f64) < min {
                return Err(fail(format!("Parameter '{key}' must contain at least {min} characters")));
            }
        }
        if let Some(max) = number(decl.get("MaxLength")) {
            if (item.chars().count() as f64) > max {
                return Err(fail(format!("Parameter '{key}' must contain at most {max} characters")));
            }
        }
        if numeric {
            let n: f64 = item.parse().unwrap_or_default();
            if let Some(min) = number(decl.get("MinValue")) {
                if n < min {
                    return Err(fail(format!("Parameter '{key}' must be a number not less than {min}")));
                }
            }
            if let Some(max) = number(decl.get("MaxValue")) {
                if n > max {
                    return Err(fail(format!("Parameter '{key}' must be a number not greater than {max}")));
                }
            }
        }
    }
    Ok(())
}

/// Parameter values by name, for `Ref`.
pub fn ref_values(params: &[StackParameter]) -> BTreeMap<String, Value> {
    params.iter().map(|p| (p.key.clone(), p.ref_value())).collect()
}

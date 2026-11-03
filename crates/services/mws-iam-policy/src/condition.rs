//! The `Condition` element: operators, set qualifiers, `...IfExists`, and
//! policy variables.

use std::collections::BTreeMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::glob::{arn_matches, glob_matches};
use crate::PolicyError;

/// Request context keys and values. Key lookup is case-insensitive, as in
/// IAM; values are case-sensitive.
#[derive(Debug, Clone, Default)]
pub struct ConditionContext {
    entries: BTreeMap<String, Vec<String>>,
}

impl ConditionContext {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: impl AsRef<str>, values: Vec<String>) {
        self.entries.insert(key.as_ref().to_ascii_lowercase(), values);
    }

    pub fn get(&self, key: &str) -> Option<&[String]> {
        self.entries.get(&key.to_ascii_lowercase()).map(Vec::as_slice)
    }

    pub fn contains(&self, key: &str) -> bool {
        self.entries.contains_key(&key.to_ascii_lowercase())
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.entries.keys()
    }
}

impl<K: AsRef<str>> FromIterator<(K, Vec<String>)> for ConditionContext {
    fn from_iter<T: IntoIterator<Item = (K, Vec<String>)>>(iter: T) -> Self {
        let mut c = Self::new();
        for (k, v) in iter {
            c.insert(k, v);
        }
        c
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Qualifier {
    None,
    ForAllValues,
    ForAnyValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Op {
    StringEquals,
    StringNotEquals,
    StringEqualsIgnoreCase,
    StringNotEqualsIgnoreCase,
    StringLike,
    StringNotLike,
    NumericEquals,
    NumericNotEquals,
    NumericLessThan,
    NumericLessThanEquals,
    NumericGreaterThan,
    NumericGreaterThanEquals,
    DateEquals,
    DateNotEquals,
    DateLessThan,
    DateLessThanEquals,
    DateGreaterThan,
    DateGreaterThanEquals,
    Bool,
    BinaryEquals,
    IpAddress,
    NotIpAddress,
    ArnEquals,
    ArnLike,
    ArnNotEquals,
    ArnNotLike,
    Null,
}

impl Op {
    fn parse(s: &str) -> Option<Self> {
        use Op::*;
        Some(match s {
            "StringEquals" => StringEquals,
            "StringNotEquals" => StringNotEquals,
            "StringEqualsIgnoreCase" => StringEqualsIgnoreCase,
            "StringNotEqualsIgnoreCase" => StringNotEqualsIgnoreCase,
            "StringLike" => StringLike,
            "StringNotLike" => StringNotLike,
            "NumericEquals" => NumericEquals,
            "NumericNotEquals" => NumericNotEquals,
            "NumericLessThan" => NumericLessThan,
            "NumericLessThanEquals" => NumericLessThanEquals,
            "NumericGreaterThan" => NumericGreaterThan,
            "NumericGreaterThanEquals" => NumericGreaterThanEquals,
            "DateEquals" => DateEquals,
            "DateNotEquals" => DateNotEquals,
            "DateLessThan" => DateLessThan,
            "DateLessThanEquals" => DateLessThanEquals,
            "DateGreaterThan" => DateGreaterThan,
            "DateGreaterThanEquals" => DateGreaterThanEquals,
            "Bool" => Bool,
            "BinaryEquals" => BinaryEquals,
            "IpAddress" => IpAddress,
            "NotIpAddress" => NotIpAddress,
            "ArnEquals" => ArnEquals,
            "ArnLike" => ArnLike,
            "ArnNotEquals" => ArnNotEquals,
            "ArnNotLike" => ArnNotLike,
            "Null" => Null,
            _ => return None,
        })
    }

    /// Negated operators match when the value matches *none* of the policy
    /// values, and are true when the key is absent.
    fn negated(self) -> bool {
        use Op::*;
        matches!(
            self,
            StringNotEquals
                | StringNotEqualsIgnoreCase
                | StringNotLike
                | NumericNotEquals
                | DateNotEquals
                | NotIpAddress
                | ArnNotEquals
                | ArnNotLike
        )
    }

    fn positive(self) -> Self {
        use Op::*;
        match self {
            StringNotEquals => StringEquals,
            StringNotEqualsIgnoreCase => StringEqualsIgnoreCase,
            StringNotLike => StringLike,
            NumericNotEquals => NumericEquals,
            DateNotEquals => DateEquals,
            NotIpAddress => IpAddress,
            ArnNotEquals => ArnEquals,
            ArnNotLike => ArnLike,
            other => other,
        }
    }

    fn expands_variables(self) -> bool {
        use Op::*;
        matches!(self.positive(), StringEquals | StringEqualsIgnoreCase | StringLike | ArnEquals | ArnLike)
    }
}

/// One `operator: { key: values }` entry.
#[derive(Debug, Clone, PartialEq)]
pub struct Condition {
    pub operator: String,
    op: Op,
    qualifier: Qualifier,
    if_exists: bool,
    pub key: String,
    pub values: Vec<String>,
}

pub(crate) fn parse_block(v: &Value) -> Result<Vec<Condition>, PolicyError> {
    let obj = v.as_object().ok_or_else(|| PolicyError("Syntax errors in policy.".into()))?;
    let mut out = Vec::new();
    for (operator, body) in obj {
        let (qualifier, rest) = if let Some(r) = operator.strip_prefix("ForAllValues:") {
            (Qualifier::ForAllValues, r)
        } else if let Some(r) = operator.strip_prefix("ForAnyValue:") {
            (Qualifier::ForAnyValue, r)
        } else {
            (Qualifier::None, operator.as_str())
        };
        let (base, if_exists) = match rest.strip_suffix("IfExists") {
            Some(b) if b != "Null" => (b, true),
            _ => (rest, false),
        };
        let op = Op::parse(base).ok_or_else(|| PolicyError(format!("Invalid Condition type : {operator}.")))?;
        let entries = body.as_object().ok_or_else(|| PolicyError("Syntax errors in policy.".into()))?;
        for (key, values) in entries {
            let values = match values {
                Value::String(s) => vec![s.clone()],
                Value::Bool(b) => vec![b.to_string()],
                Value::Number(n) => vec![n.to_string()],
                Value::Array(a) => a
                    .iter()
                    .map(|x| match x {
                        Value::String(s) => Ok(s.clone()),
                        Value::Bool(b) => Ok(b.to_string()),
                        Value::Number(n) => Ok(n.to_string()),
                        _ => Err(PolicyError("Syntax errors in policy.".into())),
                    })
                    .collect::<Result<_, _>>()?,
                _ => return Err(PolicyError("Syntax errors in policy.".into())),
            };
            out.push(Condition { operator: operator.clone(), op, qualifier, if_exists, key: key.clone(), values });
        }
    }
    Ok(out)
}

impl Condition {
    pub fn evaluate(&self, ctx: &ConditionContext, vars: bool) -> bool {
        let present = ctx.get(&self.key);
        if self.op == Op::Null {
            let want_null = self.values.iter().any(|v| v.eq_ignore_ascii_case("true"));
            let is_null = present.is_none_or(|v| v.is_empty());
            return want_null == is_null;
        }
        let policy_values: Vec<String> = if vars && self.op.expands_variables() {
            self.values.iter().filter_map(|v| substitute(v, ctx)).collect()
        } else {
            self.values.clone()
        };
        let Some(ctx_values) = present else {
            return match self.qualifier {
                Qualifier::ForAllValues => true,
                Qualifier::ForAnyValue => false,
                Qualifier::None => self.if_exists || self.op.negated(),
            };
        };
        let positive = self.op.positive();
        let matches_one = |cv: &str| policy_values.iter().any(|pv| compare(positive, pv, cv));
        match self.qualifier {
            Qualifier::ForAllValues => {
                // Every request value must (not) match some policy value.
                ctx_values.iter().all(|cv| matches_one(cv) != self.op.negated())
            }
            Qualifier::ForAnyValue => ctx_values.iter().any(|cv| matches_one(cv) != self.op.negated()),
            Qualifier::None => {
                let any = ctx_values.iter().any(|cv| matches_one(cv));
                any != self.op.negated()
            }
        }
    }
}

fn compare(op: Op, policy: &str, actual: &str) -> bool {
    use Op::*;
    match op {
        StringEquals => policy == actual,
        StringEqualsIgnoreCase => policy.eq_ignore_ascii_case(actual),
        StringLike => glob_matches(policy, actual),
        NumericEquals | NumericLessThan | NumericLessThanEquals | NumericGreaterThan | NumericGreaterThanEquals => {
            let (Ok(p), Ok(a)) = (policy.parse::<f64>(), actual.parse::<f64>()) else { return false };
            match op {
                NumericEquals => a == p,
                NumericLessThan => a < p,
                NumericLessThanEquals => a <= p,
                NumericGreaterThan => a > p,
                _ => a >= p,
            }
        }
        DateEquals | DateLessThan | DateLessThanEquals | DateGreaterThan | DateGreaterThanEquals => {
            let (Some(p), Some(a)) = (parse_date(policy), parse_date(actual)) else { return false };
            match op {
                DateEquals => a == p,
                DateLessThan => a < p,
                DateLessThanEquals => a <= p,
                DateGreaterThan => a > p,
                _ => a >= p,
            }
        }
        Bool => policy.eq_ignore_ascii_case(actual),
        BinaryEquals => {
            use base64::Engine;
            let e = base64::engine::general_purpose::STANDARD;
            match (e.decode(policy), e.decode(actual)) {
                (Ok(p), Ok(a)) => p == a,
                _ => policy == actual,
            }
        }
        IpAddress => ip_in_cidr(actual, policy),
        ArnEquals | ArnLike => arn_matches(policy, actual),
        _ => false,
    }
}

fn parse_date(s: &str) -> Option<DateTime<Utc>> {
    if let Ok(t) = DateTime::parse_from_rfc3339(s) {
        return Some(t.with_timezone(&Utc));
    }
    if let Ok(d) = chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return d.and_hms_opt(0, 0, 0).map(|t| t.and_utc());
    }
    s.parse::<i64>().ok().and_then(|e| DateTime::from_timestamp(e, 0))
}

fn ip_in_cidr(ip: &str, cidr: &str) -> bool {
    let (net, bits) = match cidr.split_once('/') {
        Some((n, b)) => (n, b.parse::<u32>().ok()),
        None => (cidr, None),
    };
    let (Ok(ip), Ok(net)) = (ip.parse::<IpAddr>(), net.parse::<IpAddr>()) else { return false };
    match (ip, net) {
        (IpAddr::V4(i), IpAddr::V4(n)) => {
            let bits = bits.unwrap_or(32).min(32);
            let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            (u32::from(i) & mask) == (u32::from(n) & mask)
        }
        (IpAddr::V6(i), IpAddr::V6(n)) => {
            let bits = bits.unwrap_or(128).min(128);
            let mask = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            (u128::from(i) & mask) == (u128::from(n) & mask)
        }
        _ => false,
    }
}

/// Expand `${key}` policy variables (and the `${*}`, `${?}`, `${$}` escapes).
/// Returns `None` if a variable has no single value in the context, which
/// makes the element not match.
pub fn substitute(s: &str, ctx: &ConditionContext) -> Option<String> {
    if !s.contains("${") {
        return Some(s.to_string());
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find('}')?;
        let inner = &after[..end];
        // `${key, 'default'}`
        let (key, default) = match inner.split_once(',') {
            Some((k, d)) => (k.trim(), Some(d.trim().trim_matches('\'').to_string())),
            None => (inner.trim(), None),
        };
        let value = match key {
            "*" => Some("*".to_string()),
            "?" => Some("?".to_string()),
            "$" => Some("$".to_string()),
            k => ctx.get(k).and_then(|v| v.first().cloned()).or(default),
        };
        out.push_str(&value?);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Some(out)
}

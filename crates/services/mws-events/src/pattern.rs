//! Event patterns: compiled from their JSON form with EventBridge's
//! validation, and matched against events the way EventBridge does.
//!
//! Supported: exact values (strings, numbers, booleans, `null`), `prefix`
//! and `suffix` (optionally `equals-ignore-case`), `equals-ignore-case`,
//! `wildcard`, `anything-but` (values, lists, `prefix`, `suffix`,
//! `wildcard`, `equals-ignore-case`), `numeric` ranges, `exists`, `cidr`
//! and `$or`. Arrays in the event match when any element matches; nested
//! patterns under an array of objects must match within one element.

use std::net::IpAddr;

use serde_json::{Map, Value};

/// A compiled event pattern.
#[derive(Debug, Clone)]
pub struct Pattern {
    root: Node,
}

#[derive(Debug, Clone, Default)]
struct Node {
    fields: Vec<(String, Field)>,
    /// Each `$or` in this object: at least one alternative must match.
    ors: Vec<Vec<Node>>,
}

#[derive(Debug, Clone)]
enum Field {
    Nested(Node),
    Leaf(Vec<Matcher>),
}

#[derive(Debug, Clone)]
enum Scalar {
    Str(String),
    Num(f64),
    Bool(bool),
    Null,
}

#[derive(Debug, Clone)]
enum Matcher {
    Exact(Scalar),
    Prefix { value: String, ignore_case: bool },
    Suffix { value: String, ignore_case: bool },
    EqualsIgnoreCase(String),
    Wildcard(String),
    AnythingBut(AnythingBut),
    Numeric(Vec<(NumOp, f64)>),
    Exists(bool),
    Cidr(Cidr),
}

#[derive(Debug, Clone)]
enum AnythingBut {
    Values(Vec<Scalar>),
    Prefix(String),
    Suffix(String),
    Wildcard(Vec<String>),
    IgnoreCase(Vec<String>),
}

#[derive(Debug, Clone, Copy)]
enum NumOp {
    Lt,
    Le,
    Eq,
    Ge,
    Gt,
}

#[derive(Debug, Clone)]
struct Cidr {
    network: IpAddr,
    prefix: u8,
}

/// Why a pattern is invalid, worded like EventBridge's
/// `Event pattern is not valid. Reason: ...`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatternError(pub String);

impl std::fmt::Display for PatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

fn err<T>(m: impl Into<String>) -> Result<T, PatternError> {
    Err(PatternError(m.into()))
}

impl Pattern {
    pub fn parse(source: &str) -> Result<Self, PatternError> {
        let value: Value = match serde_json::from_str(source) {
            Ok(v) => v,
            Err(e) => return err(format!("Filter is not valid JSON: {e}")),
        };
        let Value::Object(map) = value else { return err("Filter is not an object") };
        let root = compile_object(&map, 0)?;
        Ok(Pattern { root })
    }

    /// The values a pattern requires for a top-level field such as `source`
    /// or `detail-type`, when it gives them as plain strings (the
    /// `events:source` and `events:detail-type` condition keys).
    pub fn exact_strings(source: &str, field: &str) -> Vec<String> {
        let Ok(Value::Object(map)) = serde_json::from_str::<Value>(source) else { return Vec::new() };
        match map.get(field) {
            Some(Value::Array(items)) => items.iter().filter_map(|v| v.as_str().map(str::to_string)).collect(),
            _ => Vec::new(),
        }
    }

    pub fn matches(&self, event: &Value) -> bool {
        match event {
            Value::Object(map) => match_node(&self.root, Some(map)),
            _ => false,
        }
    }
}

const MAX_DEPTH: usize = 50;

fn compile_object(map: &Map<String, Value>, depth: usize) -> Result<Node, PatternError> {
    if depth > MAX_DEPTH {
        return err("Filter is nested too deeply");
    }
    if map.is_empty() && depth > 0 {
        return err("Empty objects are not allowed");
    }
    let mut node = Node::default();
    for (key, value) in map {
        if key == "$or" {
            let Value::Array(alternatives) = value else { return err("Or relationship must be an array of objects") };
            if alternatives.len() < 2 {
                return err("Or relationship must have at least two alternatives");
            }
            let mut compiled = Vec::new();
            for alt in alternatives {
                let Value::Object(m) = alt else { return err("Or relationship must be an array of objects") };
                if m.is_empty() {
                    return err("Empty objects are not allowed");
                }
                compiled.push(compile_object(m, depth + 1)?);
            }
            node.ors.push(compiled);
            continue;
        }
        let field = match value {
            Value::Object(m) => Field::Nested(compile_object(m, depth + 1)?),
            Value::Array(items) => {
                if items.is_empty() {
                    return err("Empty arrays are not allowed");
                }
                let mut matchers = Vec::new();
                for item in items {
                    matchers.push(compile_matcher(item)?);
                }
                Field::Leaf(matchers)
            }
            _ => return err(format!("\"{key}\" must be an object or an array")),
        };
        node.fields.push((key.clone(), field));
    }
    Ok(node)
}

fn scalar(v: &Value) -> Option<Scalar> {
    Some(match v {
        Value::String(s) => Scalar::Str(s.clone()),
        Value::Number(n) => Scalar::Num(n.as_f64()?),
        Value::Bool(b) => Scalar::Bool(*b),
        Value::Null => Scalar::Null,
        _ => return None,
    })
}

fn compile_matcher(item: &Value) -> Result<Matcher, PatternError> {
    let Value::Object(m) = item else {
        return match scalar(item) {
            Some(s) => Ok(Matcher::Exact(s)),
            None => err("Match value must be String, number, true, false, or null"),
        };
    };
    if m.len() != 1 {
        return err("Only one key allowed in match expression");
    }
    let (op, arg) = m.iter().next().expect("one entry");
    match op.as_str() {
        "prefix" | "suffix" => {
            let (value, ignore_case) = match arg {
                Value::String(s) => (s.clone(), false),
                Value::Object(o) if o.len() == 1 => match o.get("equals-ignore-case") {
                    Some(Value::String(s)) => (s.clone(), true),
                    _ => return err(format!("{op} match pattern must be a string")),
                },
                _ => return err(format!("{op} match pattern must be a string")),
            };
            Ok(if op == "prefix" {
                Matcher::Prefix { value, ignore_case }
            } else {
                Matcher::Suffix { value, ignore_case }
            })
        }
        "equals-ignore-case" => match arg {
            Value::String(s) => Ok(Matcher::EqualsIgnoreCase(s.clone())),
            _ => err("equals-ignore-case match pattern must be a string"),
        },
        "wildcard" => match arg {
            Value::String(s) => {
                check_wildcard(s)?;
                Ok(Matcher::Wildcard(s.clone()))
            }
            _ => err("wildcard match pattern must be a string"),
        },
        "exists" => match arg {
            Value::Bool(b) => Ok(Matcher::Exists(*b)),
            _ => err("exists match pattern must be either true or false."),
        },
        "numeric" => compile_numeric(arg),
        "cidr" => match arg {
            Value::String(s) => Ok(Matcher::Cidr(parse_cidr(s)?)),
            _ => err("cidr match pattern must be a string"),
        },
        "anything-but" => compile_anything_but(arg),
        other => err(format!("Unrecognized match type {other}")),
    }
}

fn compile_anything_but(arg: &Value) -> Result<Matcher, PatternError> {
    let strings = |v: &Value, what: &str| -> Result<Vec<String>, PatternError> {
        match v {
            Value::String(s) => Ok(vec![s.clone()]),
            Value::Array(items) if !items.is_empty() => items
                .iter()
                .map(|i| match i {
                    Value::String(s) => Ok(s.clone()),
                    _ => err(format!("Inside {what} list, number|start|null|boolean is not supported.")),
                })
                .collect(),
            _ => err(format!("{what} must be a string or a non-empty array of strings")),
        }
    };
    let but = match arg {
        Value::String(_) | Value::Number(_) => AnythingBut::Values(vec![scalar(arg).expect("scalar")]),
        Value::Array(items) => {
            if items.is_empty() {
                return err("Empty arrays are not allowed");
            }
            let mut values = Vec::new();
            let mut kind = None;
            for i in items {
                let k = match i {
                    Value::String(_) => "string",
                    Value::Number(_) => "number",
                    _ => return err("Inside anything but list, start|null|boolean is not supported."),
                };
                if kind.is_some_and(|prev| prev != k) {
                    return err("Inside anything but list, all values must be of the same type");
                }
                kind = Some(k);
                values.push(scalar(i).expect("scalar"));
            }
            AnythingBut::Values(values)
        }
        Value::Object(o) => {
            if o.len() != 1 {
                return err("Only one key allowed in match expression");
            }
            let (op, v) = o.iter().next().expect("one entry");
            match op.as_str() {
                "prefix" => match v {
                    Value::String(s) if !s.is_empty() => AnythingBut::Prefix(s.clone()),
                    Value::String(_) => return err("Null prefix/suffix not allowed"),
                    _ => return err("prefix match pattern must be a string"),
                },
                "suffix" => match v {
                    Value::String(s) if !s.is_empty() => AnythingBut::Suffix(s.clone()),
                    Value::String(_) => return err("Null prefix/suffix not allowed"),
                    _ => return err("suffix match pattern must be a string"),
                },
                "wildcard" => {
                    let w = strings(v, "anything-but/wildcard")?;
                    for p in &w {
                        check_wildcard(p)?;
                    }
                    AnythingBut::Wildcard(w)
                }
                "equals-ignore-case" => AnythingBut::IgnoreCase(strings(v, "anything-but/ignore-case")?),
                other => return err(format!("Unsupported anything-but pattern: {other}")),
            }
        }
        _ => return err("Value of anything-but must be an array or single string/number value."),
    };
    Ok(Matcher::AnythingBut(but))
}

fn compile_numeric(arg: &Value) -> Result<Matcher, PatternError> {
    let Value::Array(items) = arg else { return err("Value of numeric must be an array.") };
    if items.is_empty() || items.len() % 2 != 0 {
        return err("Value of numeric must be an array of operator and value pairs.");
    }
    let mut conditions = Vec::new();
    let (mut lower, mut upper) = (false, false);
    for pair in items.chunks(2) {
        let Value::String(op) = &pair[0] else { return err("Unrecognized numeric range operator") };
        let op = match op.as_str() {
            "<" => NumOp::Lt,
            "<=" => NumOp::Le,
            "=" => NumOp::Eq,
            ">=" => NumOp::Ge,
            ">" => NumOp::Gt,
            other => return err(format!("Unrecognized numeric range operator: {other}")),
        };
        let Some(n) = pair[1].as_f64() else {
            return err(format!("Value of {} must be numeric", op_name(op)));
        };
        match op {
            NumOp::Lt | NumOp::Le => {
                if upper {
                    return err("Multiple upper bounds are not allowed");
                }
                upper = true;
            }
            NumOp::Gt | NumOp::Ge => {
                if lower {
                    return err("Multiple lower bounds are not allowed");
                }
                lower = true;
            }
            NumOp::Eq => {
                if items.len() != 2 {
                    return err("Numeric equality cannot be combined with a range");
                }
            }
        }
        conditions.push((op, n));
    }
    let low = conditions.iter().find(|(o, _)| matches!(o, NumOp::Gt | NumOp::Ge)).map(|c| c.1);
    let high = conditions.iter().find(|(o, _)| matches!(o, NumOp::Lt | NumOp::Le)).map(|c| c.1);
    if let (Some(l), Some(h)) = (low, high) {
        if l >= h {
            return err("Bottom must be less than top");
        }
    }
    Ok(Matcher::Numeric(conditions))
}

fn op_name(op: NumOp) -> &'static str {
    match op {
        NumOp::Lt => "<",
        NumOp::Le => "<=",
        NumOp::Eq => "=",
        NumOp::Ge => ">=",
        NumOp::Gt => ">",
    }
}

fn check_wildcard(p: &str) -> Result<(), PatternError> {
    let chars: Vec<char> = p.chars().collect();
    let mut i = 0;
    let mut prev_star = false;
    while i < chars.len() {
        match chars[i] {
            '\\' => {
                match chars.get(i + 1) {
                    Some('*') | Some('\\') => {}
                    _ => return err(format!("Invalid escape character at pos {i}")),
                }
                i += 2;
                prev_star = false;
                continue;
            }
            '*' => {
                if prev_star {
                    return err(format!("Consecutive wildcard characters at pos {i}"));
                }
                prev_star = true;
            }
            _ => prev_star = false,
        }
        i += 1;
    }
    Ok(())
}

fn parse_cidr(s: &str) -> Result<Cidr, PatternError> {
    let bad = || PatternError(format!("Nonstandard IP address: {s}"));
    let (ip, prefix) = match s.split_once('/') {
        Some((ip, p)) => (ip, Some(p)),
        None => (s, None),
    };
    let network: IpAddr = ip.parse().map_err(|_| bad())?;
    let max = if network.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(p) => p.parse::<u8>().ok().filter(|p| *p <= max).ok_or_else(bad)?,
        None => max,
    };
    Ok(Cidr { network, prefix })
}

// ----- matching -----

fn match_node(node: &Node, obj: Option<&Map<String, Value>>) -> bool {
    for (key, field) in &node.fields {
        if !match_field(field, obj.and_then(|o| o.get(key))) {
            return false;
        }
    }
    node.ors.iter().all(|alts| alts.iter().any(|alt| match_node(alt, obj)))
}

fn match_field(field: &Field, value: Option<&Value>) -> bool {
    match field {
        Field::Nested(node) => match value {
            Some(Value::Object(m)) => match_node(node, Some(m)),
            Some(Value::Array(items)) => {
                let objects: Vec<&Map<String, Value>> = items.iter().filter_map(Value::as_object).collect();
                if objects.is_empty() {
                    match_node(node, None)
                } else {
                    objects.into_iter().any(|m| match_node(node, Some(m)))
                }
            }
            _ => match_node(node, None),
        },
        Field::Leaf(matchers) => {
            let leaves: Vec<&Value> = match value {
                None | Some(Value::Object(_)) => Vec::new(),
                Some(Value::Array(items)) => items.iter().filter(|v| !v.is_object() && !v.is_array()).collect(),
                Some(v) => vec![v],
            };
            if leaves.is_empty() {
                return matchers.iter().any(|m| matches!(m, Matcher::Exists(false)));
            }
            matchers.iter().any(|m| leaves.iter().any(|v| match_scalar(m, v)))
        }
    }
}

fn number_eq(a: f64, b: f64) -> bool {
    // EventBridge compares numbers with six decimal places of precision.
    (a - b).abs() < 5e-7
}

fn scalar_eq(s: &Scalar, v: &Value) -> bool {
    match (s, v) {
        (Scalar::Str(a), Value::String(b)) => a == b,
        (Scalar::Num(a), Value::Number(b)) => b.as_f64().is_some_and(|b| number_eq(*a, b)),
        (Scalar::Bool(a), Value::Bool(b)) => a == b,
        (Scalar::Null, Value::Null) => true,
        _ => false,
    }
}

fn lower(s: &str) -> String {
    s.to_lowercase()
}

fn match_scalar(m: &Matcher, v: &Value) -> bool {
    match m {
        Matcher::Exact(s) => scalar_eq(s, v),
        Matcher::Exists(e) => *e,
        Matcher::Prefix { value, ignore_case } => v.as_str().is_some_and(|s| {
            if *ignore_case {
                lower(s).starts_with(&lower(value))
            } else {
                s.starts_with(value.as_str())
            }
        }),
        Matcher::Suffix { value, ignore_case } => v.as_str().is_some_and(|s| {
            if *ignore_case {
                lower(s).ends_with(&lower(value))
            } else {
                s.ends_with(value.as_str())
            }
        }),
        Matcher::EqualsIgnoreCase(p) => v.as_str().is_some_and(|s| lower(s) == lower(p)),
        Matcher::Wildcard(p) => v.as_str().is_some_and(|s| wildcard_match(p, s)),
        Matcher::Numeric(conditions) => v.as_f64().is_some_and(|n| {
            conditions.iter().all(|(op, x)| match op {
                NumOp::Lt => n < *x && !number_eq(n, *x),
                NumOp::Le => n <= *x || number_eq(n, *x),
                NumOp::Eq => number_eq(n, *x),
                NumOp::Ge => n >= *x || number_eq(n, *x),
                NumOp::Gt => n > *x && !number_eq(n, *x),
            })
        }),
        Matcher::Cidr(c) => v.as_str().and_then(|s| s.parse::<IpAddr>().ok()).is_some_and(|ip| in_cidr(c, ip)),
        Matcher::AnythingBut(but) => match but {
            AnythingBut::Values(values) => !values.iter().any(|s| scalar_eq(s, v)),
            AnythingBut::Prefix(p) => v.as_str().is_some_and(|s| !s.starts_with(p.as_str())),
            AnythingBut::Suffix(p) => v.as_str().is_some_and(|s| !s.ends_with(p.as_str())),
            AnythingBut::Wildcard(ps) => v.as_str().is_some_and(|s| !ps.iter().any(|p| wildcard_match(p, s))),
            AnythingBut::IgnoreCase(ps) => v.as_str().is_some_and(|s| !ps.iter().any(|p| lower(p) == lower(s))),
        },
    }
}

fn in_cidr(c: &Cidr, ip: IpAddr) -> bool {
    match (c.network, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => {
            let mask = if c.prefix == 0 { 0 } else { u32::MAX << (32 - c.prefix as u32) };
            (u32::from(n) & mask) == (u32::from(i) & mask)
        }
        (IpAddr::V6(n), IpAddr::V6(i)) => {
            let mask = if c.prefix == 0 { 0 } else { u128::MAX << (128 - c.prefix as u32) };
            (u128::from(n) & mask) == (u128::from(i) & mask)
        }
        _ => false,
    }
}

/// `*` matches any run of characters; `\*` is a literal star.
fn wildcard_match(pattern: &str, s: &str) -> bool {
    #[derive(Clone, Copy, PartialEq)]
    enum Tok {
        Star,
        Ch(char),
    }
    let mut toks = Vec::new();
    let mut it = pattern.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\\' => {
                if let Some(n) = it.next() {
                    toks.push(Tok::Ch(n));
                }
            }
            '*' => toks.push(Tok::Star),
            c => toks.push(Tok::Ch(c)),
        }
    }
    let text: Vec<char> = s.chars().collect();
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while t < text.len() {
        if p < toks.len() && toks[p] == Tok::Ch(text[t]) {
            p += 1;
            t += 1;
        } else if p < toks.len() && toks[p] == Tok::Star {
            star = Some(p);
            mark = t;
            p += 1;
        } else if let Some(sp) = star {
            p = sp + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    while p < toks.len() && toks[p] == Tok::Star {
        p += 1;
    }
    p == toks.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn m(p: Value, e: Value) -> bool {
        Pattern::parse(&p.to_string()).unwrap().matches(&e)
    }

    #[test]
    fn exact_and_arrays() {
        assert!(m(json!({"source": ["aws.ec2"]}), json!({"source": "aws.ec2"})));
        assert!(!m(json!({"source": ["aws.ec2"]}), json!({"source": "aws.s3"})));
        assert!(m(json!({"resources": ["b"]}), json!({"resources": ["a", "b"]})));
        assert!(m(json!({"detail": {"n": [5]}}), json!({"detail": {"n": 5.0}})));
        assert!(!m(json!({"detail": {"n": ["5"]}}), json!({"detail": {"n": 5}})));
        assert!(m(json!({"detail": {"v": [null]}}), json!({"detail": {"v": null}})));
        assert!(!m(json!({"detail": {"v": [null]}}), json!({"detail": {}})));
    }

    #[test]
    fn operators() {
        let e = json!({"detail": {"name": "Prod-Server", "ip": "10.0.1.7", "n": 12, "tags": ["x", "y"]}});
        assert!(m(json!({"detail": {"name": [{"prefix": "Prod"}]}}), e.clone()));
        assert!(m(json!({"detail": {"name": [{"prefix": {"equals-ignore-case": "prod"}}]}}), e.clone()));
        assert!(m(json!({"detail": {"name": [{"suffix": "Server"}]}}), e.clone()));
        assert!(m(json!({"detail": {"name": [{"equals-ignore-case": "prod-server"}]}}), e.clone()));
        assert!(m(json!({"detail": {"name": [{"wildcard": "P*-S*r"}]}}), e.clone()));
        assert!(!m(json!({"detail": {"name": [{"wildcard": "P*-X*"}]}}), e.clone()));
        assert!(m(json!({"detail": {"ip": [{"cidr": "10.0.0.0/16"}]}}), e.clone()));
        assert!(!m(json!({"detail": {"ip": [{"cidr": "10.1.0.0/16"}]}}), e.clone()));
        assert!(m(json!({"detail": {"n": [{"numeric": [">", 10, "<=", 12]}]}}), e.clone()));
        assert!(!m(json!({"detail": {"n": [{"numeric": [">", 12]}]}}), e.clone()));
        assert!(m(json!({"detail": {"name": [{"anything-but": ["a", "b"]}]}}), e.clone()));
        assert!(!m(json!({"detail": {"name": [{"anything-but": {"prefix": "Prod"}}]}}), e.clone()));
        assert!(!m(json!({"detail": {"missing": [{"anything-but": "x"}]}}), e.clone()));
        assert!(m(json!({"detail": {"missing": [{"exists": false}]}}), e.clone()));
        assert!(m(json!({"detail": {"name": [{"exists": true}]}}), e.clone()));
        assert!(m(json!({"nope": {"deeper": [{"exists": false}]}}), e.clone()));
        assert!(m(json!({"detail": {"tags": [{"anything-but": "x"}]}}), e.clone()));
        assert!(m(json!({"$or": [{"detail": {"n": [1]}}, {"detail": {"n": [12]}}]}), e.clone()));
        assert!(!m(json!({"$or": [{"detail": {"n": [1]}}, {"detail": {"n": [2]}}]}), e));
    }

    #[test]
    fn arrays_of_objects() {
        let e = json!({"detail": {"items": [{"a": 1, "b": 2}, {"a": 3, "b": 4}]}});
        assert!(m(json!({"detail": {"items": {"a": [3], "b": [4]}}}), e.clone()));
        assert!(!m(json!({"detail": {"items": {"a": [1], "b": [4]}}}), e));
    }

    #[test]
    fn invalid() {
        assert_eq!(Pattern::parse("[]").unwrap_err().0, "Filter is not an object");
        assert_eq!(Pattern::parse(r#"{"source":"x"}"#).unwrap_err().0, "\"source\" must be an object or an array");
        assert!(Pattern::parse(r#"{"source":[]}"#).is_err());
        assert!(Pattern::parse(r#"{"source":[{"foo":"x"}]}"#).is_err());
        assert!(Pattern::parse(r#"{"source":[{"wildcard":"a**"}]}"#).is_err());
        assert!(Pattern::parse(r#"{"n":[{"numeric":[">", "x"]}]}"#).is_err());
    }

    #[test]
    fn wildcards() {
        assert!(wildcard_match("*", ""));
        assert!(wildcard_match("a*c", "abbbc"));
        assert!(wildcard_match("a\\*c", "a*c"));
        assert!(!wildcard_match("a\\*c", "abc"));
        assert!(wildcard_match("*.png", "dir/x.png"));
    }
}

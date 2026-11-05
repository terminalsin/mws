//! Intrinsic functions, pseudo parameters and conditions.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine;
use serde_json::{Map, Value};

use crate::template::{format_error, Template};

/// Stands for `AWS::NoValue` until the enclosing object or list drops it.
const NO_VALUE: &str = "\u{1}AWS::NoValue";

const PSEUDO: &[&str] = &[
    "AWS::AccountId",
    "AWS::NotificationARNs",
    "AWS::NoValue",
    "AWS::Partition",
    "AWS::Region",
    "AWS::StackId",
    "AWS::StackName",
    "AWS::URLSuffix",
];

pub fn is_pseudo(name: &str) -> bool {
    PSEUDO.contains(&name)
}

/// Values of the pseudo parameters.
#[derive(Debug, Clone, Default)]
pub struct Pseudo {
    pub account: String,
    pub region: String,
    pub partition: String,
    pub stack_id: String,
    pub stack_name: String,
    pub notification_arns: Vec<String>,
}

impl Pseudo {
    pub fn url_suffix(&self) -> &'static str {
        match self.partition.as_str() {
            "aws-cn" => "amazonaws.com.cn",
            _ => "amazonaws.com",
        }
    }

    fn get(&self, name: &str) -> Option<Value> {
        Some(match name {
            "AWS::AccountId" => Value::String(self.account.clone()),
            "AWS::Region" => Value::String(self.region.clone()),
            "AWS::Partition" => Value::String(self.partition.clone()),
            "AWS::StackId" => Value::String(self.stack_id.clone()),
            "AWS::StackName" => Value::String(self.stack_name.clone()),
            "AWS::URLSuffix" => Value::String(self.url_suffix().into()),
            "AWS::NotificationARNs" => {
                Value::Array(self.notification_arns.iter().cloned().map(Value::String).collect())
            }
            "AWS::NoValue" => Value::String(NO_VALUE.into()),
            _ => return None,
        })
    }
}

/// What a lookup of a resource's `Ref` or attribute found.
pub enum Lookup {
    Value(Value),
    /// The resource does not exist yet (change set previews).
    Unknown,
    /// An error message.
    Error(String),
}

/// Access to the stack's resources while evaluating.
pub trait Resources {
    fn ref_value(&self, logical_id: &str) -> Lookup;
    fn attribute(&self, logical_id: &str, attribute: &str) -> Lookup;
}

/// No resources (conditions, parameter checks).
pub struct NoResources;

impl Resources for NoResources {
    fn ref_value(&self, logical_id: &str) -> Lookup {
        Lookup::Error(format_error(format!(
            "Unresolved resource dependencies [{logical_id}] in the Resources block of the template"
        )))
    }
    fn attribute(&self, logical_id: &str, _attribute: &str) -> Lookup {
        Lookup::Error(format!("Template error: instance of Fn::GetAtt references undefined resource {logical_id}"))
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum EvalError {
    /// Known only once a resource it depends on exists.
    Unknown,
    Error(String),
}

impl From<String> for EvalError {
    fn from(s: String) -> Self {
        EvalError::Error(s)
    }
}

impl EvalError {
    pub fn message(self) -> String {
        match self {
            EvalError::Unknown => "Template error: a value is not yet known".into(),
            EvalError::Error(m) => m,
        }
    }
}

type R<T> = Result<T, EvalError>;

fn err<T>(m: impl Into<String>) -> R<T> {
    Err(EvalError::Error(m.into()))
}

pub struct Evaluator<'a> {
    pub params: &'a BTreeMap<String, Value>,
    pub pseudo: &'a Pseudo,
    pub mappings: Option<&'a Map<String, Value>>,
    pub conditions: &'a BTreeMap<String, bool>,
    pub resources: &'a dyn Resources,
    pub exports: &'a BTreeMap<String, String>,
    pub azs: &'a [String],
    pub language_extensions: bool,
}

impl Evaluator<'_> {
    /// Evaluate every intrinsic function in `v`.
    pub fn eval(&self, v: &Value) -> R<Value> {
        let out = self.eval_inner(v)?;
        Ok(match out {
            Value::String(s) if s == NO_VALUE => Value::Null,
            other => other,
        })
    }

    /// Evaluate a resource's `Properties` (dropping `AWS::NoValue`).
    pub fn eval_properties(&self, v: Option<&Value>) -> R<Map<String, Value>> {
        match v {
            None => Ok(Map::new()),
            Some(v) => match self.eval_inner(v)? {
                Value::Object(o) => Ok(o),
                _ => err(format_error("Every Properties member must be an object.")),
            },
        }
    }

    fn eval_inner(&self, v: &Value) -> R<Value> {
        match v {
            Value::Object(o) if o.len() == 1 => {
                let (k, arg) = o.iter().next().expect("one entry");
                if k == "Ref" || k.starts_with("Fn::") {
                    return self.function(k, arg);
                }
                let inner = self.eval_inner(arg)?;
                let mut m = Map::new();
                if !is_no_value(&inner) {
                    m.insert(k.clone(), inner);
                }
                Ok(Value::Object(m))
            }
            Value::Object(o) => {
                let mut m = Map::new();
                for (k, x) in o {
                    let x = self.eval_inner(x)?;
                    if !is_no_value(&x) {
                        m.insert(k.clone(), x);
                    }
                }
                Ok(Value::Object(m))
            }
            Value::Array(a) => {
                let mut out = Vec::with_capacity(a.len());
                for x in a {
                    let x = self.eval_inner(x)?;
                    if !is_no_value(&x) {
                        out.push(x);
                    }
                }
                Ok(Value::Array(out))
            }
            other => Ok(other.clone()),
        }
    }

    fn string_arg(&self, f: &str, v: &Value) -> R<String> {
        match self.eval_inner(v)? {
            Value::String(s) => Ok(s),
            Value::Number(n) => Ok(n.to_string()),
            Value::Bool(b) => Ok(b.to_string()),
            _ => err(format!("Template error: every {f} object requires a string parameter")),
        }
    }

    fn list_arg(&self, f: &str, v: &Value) -> R<Vec<Value>> {
        match self.eval_inner(v)? {
            Value::Array(a) => Ok(a),
            _ => err(format!("Template error: every {f} object requires a list parameter")),
        }
    }

    fn function(&self, f: &str, arg: &Value) -> R<Value> {
        match f {
            "Ref" => {
                let Some(name) = arg.as_str() else {
                    return err("Template error: every Ref object must have a single String value.");
                };
                self.reference(name)
            }
            "Fn::GetAtt" => {
                let (res, attr) = match arg {
                    Value::String(s) => match s.split_once('.') {
                        Some((r, a)) => (r.to_string(), a.to_string()),
                        None => {
                            return err("Template error: every Fn::GetAtt object requires two non-empty parameters")
                        }
                    },
                    Value::Array(a) if a.len() == 2 => {
                        let r = a[0].as_str().map(str::to_string);
                        let attr = self.string_arg(f, &a[1])?;
                        match r {
                            Some(r) => (r, attr),
                            None => {
                                return err("Template error: every Fn::GetAtt object requires two non-empty parameters")
                            }
                        }
                    }
                    _ => return err("Template error: every Fn::GetAtt object requires two non-empty parameters"),
                };
                match self.resources.attribute(&res, &attr) {
                    Lookup::Value(v) => Ok(v),
                    Lookup::Unknown => Err(EvalError::Unknown),
                    Lookup::Error(e) => err(e),
                }
            }
            "Fn::Join" => {
                let a = arg.as_array().filter(|a| a.len() == 2);
                let Some(a) = a else {
                    return err("Template error: every Fn::Join object requires two parameters, (1) a string delimiter and (2) a list of strings to be joined or a function that returns a list of strings (such as Fn::GetAZs) to be joined.");
                };
                let delim = a[0].as_str().unwrap_or_default().to_string();
                let items = self.list_arg(f, &a[1])?;
                let mut parts = Vec::new();
                for i in items {
                    parts.push(match i {
                        Value::String(s) => s,
                        Value::Number(n) => n.to_string(),
                        Value::Bool(b) => b.to_string(),
                        _ => return err("Template error: every Fn::Join object requires two parameters, (1) a string delimiter and (2) a list of strings to be joined or a function that returns a list of strings (such as Fn::GetAZs) to be joined."),
                    });
                }
                Ok(Value::String(parts.join(&delim)))
            }
            "Fn::Sub" => self.sub(arg),
            "Fn::Select" => {
                let a = arg.as_array().filter(|a| a.len() == 2);
                let Some(a) = a else {
                    return err("Template error: Fn::Select requires a list argument with two elements: an integer index and a list");
                };
                let idx = self.string_arg(f, &a[0])?;
                let idx: usize = idx.parse().map_err(|_| {
                    EvalError::Error("Template error: Fn::Select requires a list argument with two elements: an integer index and a list".into())
                })?;
                let list = self.list_arg(f, &a[1])?;
                list.get(idx).cloned().ok_or_else(|| {
                    EvalError::Error(format!(
                        "Template error: Fn::Select cannot select nonexistent value at index {idx}"
                    ))
                })
            }
            "Fn::Split" => {
                let a = arg.as_array().filter(|a| a.len() == 2);
                let Some(a) = a else {
                    return err("Template error: every Fn::Split object requires two parameters, (1) a string delimiter and (2) a string to be split or a function that returns a string to be split.");
                };
                let delim = a[0].as_str().unwrap_or_default();
                let s = self.string_arg(f, &a[1])?;
                if delim.is_empty() {
                    return err("Template error: every Fn::Split object requires two parameters, (1) a string delimiter and (2) a string to be split or a function that returns a string to be split.");
                }
                Ok(Value::Array(s.split(delim).map(|p| Value::String(p.to_string())).collect()))
            }
            "Fn::If" => {
                let a = arg.as_array().filter(|a| a.len() == 3);
                let Some(a) = a else {
                    return err("Template error: Fn::If requires a list argument with three elements");
                };
                let c = a[0].as_str().unwrap_or_default();
                let Some(holds) = self.conditions.get(c) else {
                    return err(format!("Template error: unresolved condition dependency {c} in Fn::If"));
                };
                self.eval_inner(if *holds { &a[1] } else { &a[2] })
            }
            "Fn::FindInMap" => {
                let a = arg.as_array().filter(|a| a.len() == 3 || (a.len() == 4 && self.language_extensions));
                let Some(a) = a else {
                    return err("Template error: every Fn::FindInMap object requires three parameters, the map name, map key and the attribute for return value");
                };
                let map = self.string_arg(f, &a[0])?;
                let top = self.string_arg(f, &a[1])?;
                let second = self.string_arg(f, &a[2])?;
                let found = self
                    .mappings
                    .and_then(|m| m.get(&map))
                    .and_then(|m| m.get(&top))
                    .and_then(|m| m.get(&second))
                    .cloned();
                match found {
                    Some(v) => Ok(v),
                    None => match a.get(3).and_then(|d| d.get("DefaultValue")) {
                        Some(d) => self.eval_inner(d),
                        None => err(format!("Template error: Unable to get mapping for {map}::{top}::{second}")),
                    },
                }
            }
            "Fn::GetAZs" => {
                let region = self.string_arg(f, arg)?;
                if !region.is_empty() && region != self.pseudo.region {
                    return Ok(Value::Array(
                        ["a", "b", "c"].iter().map(|s| Value::String(format!("{region}{s}"))).collect(),
                    ));
                }
                Ok(Value::Array(self.azs.iter().cloned().map(Value::String).collect()))
            }
            "Fn::Base64" => {
                let s = self.string_arg(f, arg)?;
                Ok(Value::String(base64::engine::general_purpose::STANDARD.encode(s)))
            }
            "Fn::ImportValue" => {
                let name = self.string_arg(f, arg)?;
                match self.exports.get(&name) {
                    Some(v) => Ok(Value::String(v.clone())),
                    None => err(format!("No export named {name} found")),
                }
            }
            "Fn::Cidr" => {
                let a = arg.as_array().filter(|a| a.len() == 3);
                let Some(a) = a else { return err("Template error: Fn::Cidr requires three parameters") };
                let block = self.string_arg(f, &a[0])?;
                let count: u32 = self
                    .string_arg(f, &a[1])?
                    .parse()
                    .map_err(|_| EvalError::Error("Template error: Fn::Cidr count must be a number".into()))?;
                let bits: u32 = self
                    .string_arg(f, &a[2])?
                    .parse()
                    .map_err(|_| EvalError::Error("Template error: Fn::Cidr cidrBits must be a number".into()))?;
                cidr(&block, count, bits)
                    .map(|v| Value::Array(v.into_iter().map(Value::String).collect()))
                    .map_err(EvalError::Error)
            }
            "Fn::Length" if self.language_extensions => Ok(Value::from(self.list_arg(f, arg)?.len())),
            "Fn::ToJsonString" if self.language_extensions => {
                let v = self.eval_inner(arg)?;
                Ok(Value::String(serde_json::to_string(&v).unwrap_or_default()))
            }
            "Fn::Transform" => err("Template error: Fn::Transform is not supported by MWS"),
            "Fn::Equals" | "Fn::And" | "Fn::Or" | "Fn::Not" => {
                Ok(Value::Bool(self.condition_value(&single(f, arg.clone()))?))
            }
            other => err(format!("Template format error: Unrecognized function {other}")),
        }
    }

    fn reference(&self, name: &str) -> R<Value> {
        if let Some(v) = self.pseudo.get(name) {
            return Ok(v);
        }
        if let Some(v) = self.params.get(name) {
            return Ok(v.clone());
        }
        match self.resources.ref_value(name) {
            Lookup::Value(v) => Ok(v),
            Lookup::Unknown => Err(EvalError::Unknown),
            Lookup::Error(e) => err(e),
        }
    }

    fn sub(&self, arg: &Value) -> R<Value> {
        let (text, vars) = match arg {
            Value::String(s) => (s.clone(), Map::new()),
            Value::Array(a) if a.len() == 2 => {
                let Some(text) = a[0].as_str() else { return err("Template error: One or more Fn::Sub intrinsic functions don't specify expected arguments. Specify a string as first argument, and an optional second argument to specify a mapping of values to replace in the string") };
                let vars = match self.eval_inner(&a[1])? {
                    Value::Object(o) => o,
                    _ => return err("Template error: One or more Fn::Sub intrinsic functions don't specify expected arguments. Specify a string as first argument, and an optional second argument to specify a mapping of values to replace in the string"),
                };
                (text.to_string(), vars)
            }
            _ => return err("Template error: One or more Fn::Sub intrinsic functions don't specify expected arguments. Specify a string as first argument, and an optional second argument to specify a mapping of values to replace in the string"),
        };
        let mut out = String::new();
        let mut rest = text.as_str();
        while let Some(pos) = rest.find("${") {
            out.push_str(&rest[..pos]);
            let after = &rest[pos + 2..];
            let Some(end) = after.find('}') else {
                out.push_str(&rest[pos..]);
                rest = "";
                break;
            };
            let var = &after[..end];
            if let Some(lit) = var.strip_prefix('!') {
                out.push_str("${");
                out.push_str(lit);
                out.push('}');
            } else {
                let var = var.trim();
                let v = if let Some(v) = vars.get(var) {
                    v.clone()
                } else if let (Some((r, a)), false) = (var.split_once('.'), var.starts_with("AWS::")) {
                    match self.resources.attribute(r, a) {
                        Lookup::Value(v) => v,
                        Lookup::Unknown => return Err(EvalError::Unknown),
                        Lookup::Error(e) => return err(e),
                    }
                } else {
                    self.reference(var)?
                };
                match v {
                    Value::String(s) => out.push_str(&s),
                    Value::Number(n) => out.push_str(&n.to_string()),
                    Value::Bool(b) => out.push_str(&b.to_string()),
                    Value::Array(a) => out.push_str(
                        &a.iter()
                            .map(|x| x.as_str().map(str::to_string).unwrap_or_else(|| x.to_string()))
                            .collect::<Vec<_>>()
                            .join(","),
                    ),
                    _ => {
                        return err(format!(
                            "Template error: variable {var} in Fn::Sub expression does not resolve to a string"
                        ))
                    }
                }
            }
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        Ok(Value::String(out))
    }

    /// Evaluate a condition expression.
    pub fn condition_value(&self, v: &Value) -> R<bool> {
        let Some((f, arg)) = v.as_object().filter(|o| o.len() == 1).and_then(|o| o.iter().next()) else {
            return match v {
                Value::Bool(b) => Ok(*b),
                Value::String(s) if s == "true" || s == "false" => Ok(s == "true"),
                _ => err("Template format error: Conditions can only be boolean operations on parameters and other conditions"),
            };
        };
        match f.as_str() {
            "Fn::Equals" => {
                let a = arg.as_array().filter(|a| a.len() == 2);
                let Some(a) = a else {
                    return err("Template error: Fn::Equals requires a list argument with two elements");
                };
                let l = self.eval(&a[0])?;
                let r = self.eval(&a[1])?;
                Ok(text(&l) == text(&r))
            }
            "Fn::And" | "Fn::Or" => {
                let a = arg.as_array().filter(|a| (2..=10).contains(&a.len()));
                let Some(a) = a else {
                    return err(format!("Template error: every {f} object requires a list of at least 2 and at most 10 boolean parameters."));
                };
                let mut vals = Vec::new();
                for x in a {
                    vals.push(self.condition_value(x)?);
                }
                Ok(if f == "Fn::And" { vals.iter().all(|b| *b) } else { vals.iter().any(|b| *b) })
            }
            "Fn::Not" => {
                let a = arg.as_array().filter(|a| a.len() == 1);
                let Some(a) = a else {
                    return err("Template error: Fn::Not requires a list argument with one element");
                };
                Ok(!self.condition_value(&a[0])?)
            }
            "Condition" => {
                let name = arg.as_str().unwrap_or_default();
                if let Some(v) = self.conditions.get(name) {
                    return Ok(*v);
                }
                err(format!("Template error: unresolved condition dependency {name} in Fn::If"))
            }
            _ => {
                let v = self.eval(v)?;
                match v {
                    Value::Bool(b) => Ok(b),
                    Value::String(s) if s == "true" || s == "false" => Ok(s == "true"),
                    _ => err("Template format error: Conditions can only be boolean operations on parameters and other conditions"),
                }
            }
        }
    }
}

fn single(k: &str, v: Value) -> Value {
    let mut m = Map::new();
    m.insert(k.to_string(), v);
    Value::Object(m)
}

fn is_no_value(v: &Value) -> bool {
    matches!(v, Value::String(s) if s == NO_VALUE)
}

fn text(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(a) => a.iter().map(text).collect::<Vec<_>>().join(","),
        other => other.to_string(),
    }
}

/// Evaluate the template's `Conditions` section.
pub fn evaluate_conditions(
    template: &Template,
    params: &BTreeMap<String, Value>,
    pseudo: &Pseudo,
    language_extensions: bool,
) -> Result<BTreeMap<String, bool>, String> {
    let Some(conds) = template.section("Conditions") else { return Ok(BTreeMap::new()) };
    let mut done: BTreeMap<String, bool> = BTreeMap::new();
    fn resolve(
        name: &str,
        conds: &Map<String, Value>,
        done: &mut BTreeMap<String, bool>,
        stack: &mut Vec<String>,
        ctx: (&Template, &BTreeMap<String, Value>, &Pseudo, bool),
    ) -> Result<bool, String> {
        if let Some(v) = done.get(name) {
            return Ok(*v);
        }
        if stack.iter().any(|s| s == name) {
            return Err(format_error(format!("Circular dependency between conditions: [{}]", stack.join(", "))));
        }
        let Some(expr) = conds.get(name) else {
            return Err(format!("Template error: unresolved condition dependency {name} in Fn::If"));
        };
        stack.push(name.to_string());
        let mut needed = BTreeSet::new();
        crate::template::references(expr).conditions.into_iter().for_each(|c| {
            needed.insert(c);
        });
        for c in &needed {
            resolve(c, conds, done, stack, ctx)?;
        }
        stack.pop();
        let exports = BTreeMap::new();
        let ev = Evaluator {
            params: ctx.1,
            pseudo: ctx.2,
            mappings: ctx.0.section("Mappings"),
            conditions: done,
            resources: &NoResources,
            exports: &exports,
            azs: &[],
            language_extensions: ctx.3,
        };
        let v = ev.condition_value(expr).map_err(EvalError::message)?;
        done.insert(name.to_string(), v);
        Ok(v)
    }
    for name in conds.keys() {
        resolve(name, conds, &mut done, &mut Vec::new(), (template, params, pseudo, language_extensions))?;
    }
    Ok(done)
}

/// `Fn::Cidr`.
fn cidr(block: &str, count: u32, bits: u32) -> Result<Vec<String>, String> {
    let bad = || format!("Template error: Fn::Cidr {block} is not a valid CIDR block");
    let (addr, prefix) = block.split_once('/').ok_or_else(bad)?;
    let prefix: u32 = prefix.parse().map_err(|_| bad())?;
    if !(1..=256).contains(&count) {
        return Err("Template error: Fn::Cidr count must be between 1 and 256".into());
    }
    if let Ok(v4) = addr.parse::<std::net::Ipv4Addr>() {
        if bits == 0 || bits > 32 || prefix > 32 || 32 - bits < prefix {
            return Err(format!("Template error: Fn::Cidr cidrBits {bits} is not valid for {block}"));
        }
        let new_prefix = 32 - bits;
        let base = u32::from(v4) & (if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) });
        let available = 1u64 << (new_prefix - prefix);
        if count as u64 > available {
            return Err(format!("Template error: Fn::Cidr cannot split {block} into {count} blocks of {bits} bits"));
        }
        return Ok((0..count)
            .map(|i| {
                let a = base as u64 + ((i as u64) << bits);
                format!("{}/{new_prefix}", std::net::Ipv4Addr::from(a as u32))
            })
            .collect());
    }
    let v6: std::net::Ipv6Addr = addr.parse().map_err(|_| bad())?;
    if bits == 0 || bits > 128 || prefix > 128 || 128 - bits < prefix {
        return Err(format!("Template error: Fn::Cidr cidrBits {bits} is not valid for {block}"));
    }
    let new_prefix = 128 - bits;
    let base = u128::from(v6) & (if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) });
    if new_prefix - prefix < 64 && count as u128 > (1u128 << (new_prefix - prefix)) {
        return Err(format!("Template error: Fn::Cidr cannot split {block} into {count} blocks of {bits} bits"));
    }
    Ok((0..count).map(|i| format!("{}/{new_prefix}", std::net::Ipv6Addr::from(base + ((i as u128) << bits)))).collect())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn eval(v: Value) -> R<Value> {
        let mut params = BTreeMap::new();
        params.insert("Env".to_string(), json!("prod"));
        params.insert("Subnets".to_string(), json!(["a", "b"]));
        let pseudo = Pseudo {
            account: "123456789012".into(),
            region: "us-east-1".into(),
            partition: "aws".into(),
            stack_name: "s".into(),
            ..Default::default()
        };
        let mut conditions = BTreeMap::new();
        conditions.insert("IsProd".to_string(), true);
        let mappings = json!({"M": {"us-east-1": {"Ami": "ami-1"}}});
        let exports = BTreeMap::new();
        let azs = vec!["us-east-1a".to_string(), "us-east-1b".to_string()];
        Evaluator {
            params: &params,
            pseudo: &pseudo,
            mappings: mappings.as_object(),
            conditions: &conditions,
            resources: &NoResources,
            exports: &exports,
            azs: &azs,
            language_extensions: true,
        }
        .eval(&v)
    }

    #[test]
    fn functions() {
        assert_eq!(eval(json!({"Fn::Sub": "${AWS::Region}-${Env}-${!Lit}"})).unwrap(), json!("us-east-1-prod-${Lit}"));
        assert_eq!(eval(json!({"Fn::Sub": ["${X}/${Env}", {"X": "y"}]})).unwrap(), json!("y/prod"));
        assert_eq!(eval(json!({"Fn::Join": [",", {"Ref": "Subnets"}]})).unwrap(), json!("a,b"));
        assert_eq!(eval(json!({"Fn::Select": ["1", {"Fn::GetAZs": ""}]})).unwrap(), json!("us-east-1b"));
        assert_eq!(eval(json!({"Fn::Split": ["|", "a|b"]})).unwrap(), json!(["a", "b"]));
        assert_eq!(eval(json!({"Fn::FindInMap": ["M", {"Ref": "AWS::Region"}, "Ami"]})).unwrap(), json!("ami-1"));
        assert_eq!(eval(json!({"Fn::If": ["IsProd", "big", "small"]})).unwrap(), json!("big"));
        assert_eq!(
            eval(json!({"a": {"Ref": "AWS::NoValue"}, "b": [1, {"Ref": "AWS::NoValue"}]})).unwrap(),
            json!({"b": [1]})
        );
        assert_eq!(eval(json!({"Fn::Base64": "hi"})).unwrap(), json!("aGk="));
        assert_eq!(
            eval(json!({"Fn::Cidr": ["10.0.0.0/16", 3, 8]})).unwrap(),
            json!(["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24"])
        );
        assert_eq!(eval(json!({"Fn::Length": [1, 2, 3]})).unwrap(), json!(3));
        assert_eq!(eval(json!({"Fn::ToJsonString": {"a": 1}})).unwrap(), json!("{\"a\":1}"));
        assert_eq!(
            eval(json!({"Fn::Select": [5, ["a"]]})).unwrap_err(),
            EvalError::Error("Template error: Fn::Select cannot select nonexistent value at index 5".into())
        );
    }
}

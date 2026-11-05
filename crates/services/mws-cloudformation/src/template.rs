//! Templates: parsing JSON and YAML (with the short-form `!Ref` tags),
//! structural validation, conditions and the resource dependency graph.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::intrinsics;

/// The sections a template may have.
const SECTIONS: &[&str] = &[
    "AWSTemplateFormatVersion",
    "Description",
    "Metadata",
    "Parameters",
    "Rules",
    "Mappings",
    "Conditions",
    "Transform",
    "Resources",
    "Outputs",
    "Hooks",
];

/// The attributes a resource declaration may have.
const RESOURCE_ATTRIBUTES: &[&str] = &[
    "Type",
    "Properties",
    "DependsOn",
    "Metadata",
    "Condition",
    "DeletionPolicy",
    "UpdateReplacePolicy",
    "CreationPolicy",
    "UpdatePolicy",
    "Version",
];

/// Transforms MWS applies. `AWS::LanguageExtensions` only unlocks the
/// intrinsic functions it adds.
pub const LANGUAGE_EXTENSIONS: &str = "AWS::LanguageExtensions";

pub fn format_error(message: impl std::fmt::Display) -> String {
    format!("Template format error: {message}")
}

/// A parsed template.
#[derive(Debug, Clone)]
pub struct Template {
    pub body: String,
    pub root: Map<String, Value>,
}

impl Template {
    /// Parse a template body (JSON or YAML) and check its structure.
    pub fn parse(body: &str) -> Result<Self, String> {
        let root = parse_document(body)?;
        let Value::Object(root) = root else {
            return Err(format_error("JSON not well-formed. (line 1, column 1)"));
        };
        let t = Self { body: body.to_string(), root };
        t.check_structure()?;
        Ok(t)
    }

    pub fn section(&self, name: &str) -> Option<&Map<String, Value>> {
        self.root.get(name).and_then(Value::as_object)
    }

    pub fn description(&self) -> Option<String> {
        self.root.get("Description").and_then(Value::as_str).map(str::to_string)
    }

    pub fn resources(&self) -> &Map<String, Value> {
        static EMPTY: std::sync::OnceLock<Map<String, Value>> = std::sync::OnceLock::new();
        self.section("Resources").unwrap_or_else(|| EMPTY.get_or_init(Map::new))
    }

    pub fn resource(&self, logical_id: &str) -> Option<&Map<String, Value>> {
        self.resources().get(logical_id).and_then(Value::as_object)
    }

    pub fn resource_type(&self, logical_id: &str) -> Option<&str> {
        self.resource(logical_id).and_then(|r| r.get("Type")).and_then(Value::as_str)
    }

    pub fn parameters(&self) -> Vec<(String, Map<String, Value>)> {
        self.section("Parameters")
            .map(|p| {
                p.iter().map(|(k, v)| (k.clone(), v.as_object().cloned().unwrap_or_default())).collect::<Vec<_>>()
            })
            .unwrap_or_default()
    }

    pub fn transforms(&self) -> Vec<String> {
        match self.root.get("Transform") {
            Some(Value::String(s)) => vec![s.clone()],
            Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(str::to_string).collect(),
            _ => Vec::new(),
        }
    }

    pub fn has_language_extensions(&self) -> bool {
        self.transforms().iter().any(|t| t == LANGUAGE_EXTENSIONS)
    }

    fn check_structure(&self) -> Result<(), String> {
        let unknown: Vec<&str> =
            self.root.keys().map(String::as_str).filter(|k| !SECTIONS.contains(k)).collect::<Vec<_>>();
        if !unknown.is_empty() {
            return Err(format_error(format!("Invalid template property or properties [{}]", unknown.join(", "))));
        }
        if let Some(v) = self.root.get("AWSTemplateFormatVersion") {
            let ok = match v {
                Value::String(s) => s == "2010-09-09",
                _ => false,
            };
            if !ok {
                let text = match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                return Err(format_error(format!("'{text}' is not a valid template version")));
            }
        }
        if let Some(d) = self.root.get("Description") {
            if !d.is_string() {
                return Err(format_error("Every Description member must be a string."));
            }
        }
        for t in self.transforms() {
            if t != LANGUAGE_EXTENSIONS {
                return Err(format!(
                    "Transform {t} is not supported by MWS. Expand the template before deploying it (for SAM: `sam build` and `sam package`, then deploy the processed template)."
                ));
            }
        }
        let resources = match self.root.get("Resources") {
            Some(Value::Object(r)) if !r.is_empty() => r,
            _ => return Err(format_error("At least one Resources member must be defined.")),
        };
        for (name, r) in resources {
            check_logical_id(name)?;
            let Some(r) = r.as_object() else {
                return Err(format_error(format!("[/Resources/{name}] Every Resources object must contain a Type member.")));
            };
            match r.get("Type") {
                Some(Value::String(_)) => {}
                _ => {
                    return Err(format_error(format!(
                        "[/Resources/{name}] Every Resources object must contain a Type member."
                    )))
                }
            }
            for k in r.keys() {
                if !RESOURCE_ATTRIBUTES.contains(&k.as_str()) {
                    return Err(format_error(format!("[/Resources/{name}] Invalid template resource property '{k}'")));
                }
            }
            if let Some(p) = r.get("Properties") {
                if !p.is_object() {
                    return Err(format_error(format!(
                        "[/Resources/{name}/Properties] Every Properties member must be an object."
                    )));
                }
            }
            for policy in ["DeletionPolicy", "UpdateReplacePolicy"] {
                if let Some(v) = r.get(policy) {
                    match v.as_str() {
                        Some("Delete" | "Retain" | "Snapshot" | "RetainExceptOnCreate") => {}
                        _ => {
                            return Err(format_error(format!(
                                "[/Resources/{name}/{policy}] {policy} must be one of Delete, Retain, RetainExceptOnCreate or Snapshot"
                            )))
                        }
                    }
                }
            }
        }
        if let Some(params) = self.root.get("Parameters") {
            let Some(params) = params.as_object() else {
                return Err(format_error("Every Parameters member must be an object."));
            };
            for (name, p) in params {
                check_logical_id(name)?;
                let ty = p.get("Type").and_then(Value::as_str);
                match ty {
                    None => return Err(format_error("Every Parameters object must contain a Type member.")),
                    Some(t) if !crate::parameters::valid_type(t) => {
                        return Err(format_error(format!("Unrecognized parameter type: {t}")))
                    }
                    _ => {}
                }
            }
        }
        if let Some(outputs) = self.root.get("Outputs") {
            let Some(outputs) = outputs.as_object() else {
                return Err(format_error("Every Outputs member must be an object."));
            };
            for (name, o) in outputs {
                check_logical_id(name)?;
                if o.get("Value").is_none() {
                    return Err(format_error("Every Outputs member must contain a Value object"));
                }
            }
        }
        if let Some(m) = self.root.get("Mappings") {
            let Some(m) = m.as_object() else {
                return Err(format_error("Every Mappings member must be an object."));
            };
            for (name, v) in m {
                let ok = v.as_object().is_some_and(|o| o.values().all(Value::is_object));
                if !ok {
                    return Err(format_error(format!(
                        "Every Mappings member {name} must contain a map as its value"
                    )));
                }
            }
        }
        if let Some(c) = self.root.get("Conditions") {
            if !c.is_object() {
                return Err(format_error("Every Conditions member must be an object."));
            }
        }
        Ok(())
    }

    /// Check references: every `Ref`, `Fn::GetAtt`, `Fn::Sub` variable,
    /// `DependsOn` and `Condition` must name something the template
    /// declares.
    pub fn check_references(&self) -> Result<(), String> {
        let params: BTreeSet<String> = self.parameters().into_iter().map(|(k, _)| k).collect();
        let resources: BTreeSet<String> = self.resources().keys().cloned().collect();
        let conditions: BTreeSet<String> =
            self.section("Conditions").map(|c| c.keys().cloned().collect()).unwrap_or_default();
        let mut unresolved = BTreeSet::new();
        for (name, r) in self.resources() {
            let r = r.as_object().expect("checked");
            if let Some(c) = r.get("Condition") {
                let c = c.as_str().unwrap_or_default();
                if !conditions.contains(c) {
                    return Err(format_error(format!("Unresolved dependencies [{c}]. Cannot reference resources in the Conditions block of the template")));
                }
            }
            for dep in depends_on(r) {
                if !resources.contains(&dep) {
                    unresolved.insert(dep);
                }
            }
            if let Some(p) = r.get("Properties") {
                let refs = references(p);
                for name in refs.refs {
                    if !params.contains(&name) && !resources.contains(&name) && !intrinsics::is_pseudo(&name) {
                        unresolved.insert(name);
                    }
                }
                for (res, _) in refs.get_atts {
                    if !resources.contains(&res) {
                        return Err(format!("Template error: instance of Fn::GetAtt references undefined resource {res}"));
                    }
                }
                for c in refs.conditions {
                    if !conditions.contains(&c) {
                        return Err(format!("Template error: unresolved condition dependency {c} in Fn::If"));
                    }
                }
            }
            let _ = name;
        }
        if !unresolved.is_empty() {
            return Err(format_error(format!(
                "Unresolved resource dependencies [{}] in the Resources block of the template",
                unresolved.into_iter().collect::<Vec<_>>().join(", ")
            )));
        }
        if let Some(outputs) = self.section("Outputs") {
            for o in outputs.values() {
                let refs = references(o);
                for name in refs.refs {
                    if !params.contains(&name) && !resources.contains(&name) && !intrinsics::is_pseudo(&name) {
                        return Err(format_error(format!(
                            "Unresolved resource dependencies [{name}] in the Outputs block of the template"
                        )));
                    }
                }
                for (res, _) in refs.get_atts {
                    if !resources.contains(&res) {
                        return Err(format!("Template error: instance of Fn::GetAtt references undefined resource {res}"));
                    }
                }
                if let Some(c) = o.get("Condition").and_then(Value::as_str) {
                    if !conditions.contains(c) {
                        return Err(format_error(format!("Unresolved dependencies [{c}]. Cannot reference resources in the Conditions block of the template")));
                    }
                }
            }
        }
        if let Some(conds) = self.section("Conditions") {
            for c in conds.values() {
                let refs = references(c);
                for name in refs.refs {
                    if resources.contains(&name) {
                        return Err(format_error(format!(
                            "Unresolved dependencies [{name}]. Cannot reference resources in the Conditions block of the template"
                        )));
                    }
                    if !params.contains(&name) && !intrinsics::is_pseudo(&name) {
                        return Err(format_error(format!(
                            "Unresolved dependencies [{name}]. Cannot reference resources in the Conditions block of the template"
                        )));
                    }
                }
            }
        }
        Ok(())
    }

    /// Resource logical ids in creation order: every resource after the
    /// ones it depends on, otherwise in template order. `included` limits
    /// the graph to resources whose condition holds.
    pub fn creation_order(&self, included: &dyn Fn(&str) -> bool) -> Result<Vec<String>, String> {
        let names: Vec<String> = self.resources().keys().filter(|k| included(k)).cloned().collect();
        let set: BTreeSet<&String> = names.iter().collect();
        let deps: BTreeMap<String, Vec<String>> = names
            .iter()
            .map(|n| {
                let d = self.dependencies(n).into_iter().filter(|d| set.contains(d) && d != n).collect();
                (n.clone(), d)
            })
            .collect();
        let mut order = Vec::new();
        let mut done = BTreeSet::new();
        let mut visiting = Vec::new();
        fn visit(
            n: &String,
            deps: &BTreeMap<String, Vec<String>>,
            done: &mut BTreeSet<String>,
            visiting: &mut Vec<String>,
            order: &mut Vec<String>,
        ) -> Result<(), String> {
            if done.contains(n) {
                return Ok(());
            }
            if let Some(pos) = visiting.iter().position(|v| v == n) {
                let mut cycle: Vec<String> = visiting[pos..].to_vec();
                cycle.sort();
                return Err(format!("Circular dependency between resources: [{}]", cycle.join(", ")));
            }
            visiting.push(n.clone());
            for d in &deps[n] {
                visit(d, deps, done, visiting, order)?;
            }
            visiting.pop();
            done.insert(n.clone());
            order.push(n.clone());
            Ok(())
        }
        for n in &names {
            visit(n, &deps, &mut done, &mut visiting, &mut order)?;
        }
        Ok(order)
    }

    /// The resources `logical_id` refers to or depends on.
    pub fn dependencies(&self, logical_id: &str) -> BTreeSet<String> {
        let Some(r) = self.resource(logical_id) else { return BTreeSet::new() };
        let resources = self.resources();
        let mut out: BTreeSet<String> = depends_on(r).into_iter().collect();
        if let Some(p) = r.get("Properties") {
            let refs = references(p);
            out.extend(refs.refs.into_iter().filter(|r| resources.contains_key(r)));
            out.extend(refs.get_atts.into_iter().map(|(r, _)| r));
        }
        out
    }
}

fn check_logical_id(name: &str) -> Result<(), String> {
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(format_error(format!("Resource name {name} is non alphanumeric.")));
    }
    Ok(())
}

/// `DependsOn` as a list.
pub fn depends_on(r: &Map<String, Value>) -> Vec<String> {
    match r.get("DependsOn") {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).map(str::to_string).collect(),
        _ => Vec::new(),
    }
}

/// What a fragment of template refers to.
#[derive(Debug, Default)]
pub struct References {
    pub refs: BTreeSet<String>,
    pub get_atts: BTreeSet<(String, String)>,
    pub conditions: BTreeSet<String>,
}

pub fn references(v: &Value) -> References {
    let mut out = References::default();
    collect_references(v, &mut out);
    out
}

fn collect_references(v: &Value, out: &mut References) {
    match v {
        Value::Object(o) if o.len() == 1 => {
            let (k, arg) = o.iter().next().expect("one entry");
            match k.as_str() {
                "Ref" => {
                    if let Some(s) = arg.as_str() {
                        out.refs.insert(s.to_string());
                    }
                    return;
                }
                "Fn::GetAtt" => {
                    if let Some((r, a)) = get_att_target(arg) {
                        out.get_atts.insert((r, a));
                    }
                    if let Some(a) = arg.as_array() {
                        for x in a.iter().skip(1) {
                            collect_references(x, out);
                        }
                    }
                    return;
                }
                "Fn::Sub" => {
                    let (text, vars) = match arg {
                        Value::String(s) => (s.as_str(), None),
                        Value::Array(a) => (a.first().and_then(Value::as_str).unwrap_or_default(), a.get(1)),
                        _ => ("", None),
                    };
                    let local: BTreeSet<String> = vars
                        .and_then(Value::as_object)
                        .map(|m| m.keys().cloned().collect())
                        .unwrap_or_default();
                    for var in sub_variables(text) {
                        if local.contains(&var) {
                            continue;
                        }
                        match var.split_once('.') {
                            Some((r, a)) if !var.starts_with("AWS::") => {
                                out.get_atts.insert((r.to_string(), a.to_string()));
                            }
                            _ => {
                                out.refs.insert(var);
                            }
                        }
                    }
                    if let Some(vars) = vars {
                        collect_references(vars, out);
                    }
                    return;
                }
                "Fn::If" => {
                    if let Some(c) = arg.as_array().and_then(|a| a.first()).and_then(Value::as_str) {
                        out.conditions.insert(c.to_string());
                    }
                    if let Some(a) = arg.as_array() {
                        for x in a.iter().skip(1) {
                            collect_references(x, out);
                        }
                    }
                    return;
                }
                "Condition" => {
                    if let Some(c) = arg.as_str() {
                        out.conditions.insert(c.to_string());
                    }
                    return;
                }
                _ => {}
            }
            collect_references(arg, out);
        }
        Value::Object(o) => o.values().for_each(|x| collect_references(x, out)),
        Value::Array(a) => a.iter().for_each(|x| collect_references(x, out)),
        _ => {}
    }
}

/// `Fn::GetAtt`'s resource and attribute, when they are literal.
pub fn get_att_target(arg: &Value) -> Option<(String, String)> {
    match arg {
        Value::String(s) => s.split_once('.').map(|(r, a)| (r.to_string(), a.to_string())),
        Value::Array(a) => {
            let r = a.first()?.as_str()?;
            let attr = a.get(1).and_then(Value::as_str).unwrap_or("*");
            Some((r.to_string(), attr.to_string()))
        }
        _ => None,
    }
}

/// The `${...}` variables of an `Fn::Sub` string (not `${!Literal}`).
pub fn sub_variables(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(pos) = rest.find("${") {
        let after = &rest[pos + 2..];
        let Some(end) = after.find('}') else { break };
        let var = &after[..end];
        if !var.starts_with('!') {
            out.push(var.trim().to_string());
        }
        rest = &after[end + 1..];
    }
    out
}

/// Parse a template document as JSON, or as YAML when it is not JSON.
pub fn parse_document(body: &str) -> Result<Value, String> {
    let trimmed = body.trim_start();
    if trimmed.starts_with('{') {
        return serde_json::from_str(body).map_err(|e| {
            format_error(format!("JSON not well-formed. (line {}, column {})", e.line(), e.column()))
        });
    }
    let yaml: serde_yaml::Value = serde_yaml::from_str(body).map_err(|e| {
        let (line, col) = e.location().map(|l| (l.line(), l.column())).unwrap_or((1, 1));
        format_error(format!("YAML not well-formed. (line {line}, column {col})"))
    })?;
    yaml_to_json(yaml)
}

fn yaml_to_json(v: serde_yaml::Value) -> Result<Value, String> {
    use serde_yaml::Value as Y;
    Ok(match v {
        Y::Null => Value::Null,
        Y::Bool(b) => Value::Bool(b),
        Y::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::from(i)
            } else if let Some(u) = n.as_u64() {
                Value::from(u)
            } else {
                serde_json::Number::from_f64(n.as_f64().unwrap_or_default()).map(Value::Number).unwrap_or(Value::Null)
            }
        }
        Y::String(s) => Value::String(s),
        Y::Sequence(s) => Value::Array(s.into_iter().map(yaml_to_json).collect::<Result<_, _>>()?),
        Y::Mapping(m) => {
            let mut out = Map::new();
            for (k, v) in m {
                let key = match k {
                    Y::String(s) => s,
                    Y::Number(n) => n.to_string(),
                    Y::Bool(b) => b.to_string(),
                    other => return Err(format_error(format!("YAML key {other:?} is not a string"))),
                };
                out.insert(key, yaml_to_json(v)?);
            }
            Value::Object(out)
        }
        Y::Tagged(t) => {
            let tag = t.tag.to_string();
            let tag = tag.trim_start_matches('!');
            let inner = yaml_to_json(t.value)?;
            match tag {
                "Ref" => single("Ref", inner),
                "Condition" => single("Condition", inner),
                "GetAtt" => {
                    let arg = match inner {
                        Value::String(s) => match s.split_once('.') {
                            Some((r, a)) => Value::Array(vec![Value::String(r.into()), Value::String(a.into())]),
                            None => Value::String(s),
                        },
                        other => other,
                    };
                    single("Fn::GetAtt", arg)
                }
                other => single(&format!("Fn::{other}"), inner),
            }
        }
    })
}

fn single(k: &str, v: Value) -> Value {
    let mut m = Map::new();
    m.insert(k.to_string(), v);
    Value::Object(m)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn yaml_short_forms() {
        let t = Template::parse(
            "Resources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties:\n      BucketName: !Sub '${AWS::StackName}-x'\n      Tags:\n        - Key: k\n          Value: !GetAtt Q.Arn\n  Q:\n    Type: AWS::SQS::Queue\n",
        )
        .unwrap();
        let b = t.resource("B").unwrap();
        assert_eq!(b["Properties"]["BucketName"], json!({"Fn::Sub": "${AWS::StackName}-x"}));
        assert_eq!(b["Properties"]["Tags"][0]["Value"], json!({"Fn::GetAtt": ["Q", "Arn"]}));
        assert_eq!(t.creation_order(&|_| true).unwrap(), vec!["Q", "B"]);
    }

    #[test]
    fn cycles_are_reported() {
        let t = Template::parse(
            r#"{"Resources":{"A":{"Type":"AWS::SQS::Queue","DependsOn":"B"},"B":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":{"Ref":"A"}}}}}"#,
        )
        .unwrap();
        assert_eq!(t.creation_order(&|_| true).unwrap_err(), "Circular dependency between resources: [A, B]");
    }

    #[test]
    fn unresolved_refs() {
        let t = Template::parse(r#"{"Resources":{"A":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":{"Ref":"Nope"}}}}}"#)
            .unwrap();
        assert_eq!(
            t.check_references().unwrap_err(),
            "Template format error: Unresolved resource dependencies [Nope] in the Resources block of the template"
        );
    }

    #[test]
    fn bad_documents() {
        assert!(Template::parse("{").unwrap_err().starts_with("Template format error: JSON not well-formed."));
        assert_eq!(
            Template::parse("Description: x").unwrap_err(),
            "Template format error: At least one Resources member must be defined."
        );
    }
}

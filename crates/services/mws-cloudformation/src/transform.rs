//! Template transforms, which CloudFormation runs server-side before it
//! deploys a template: `Fn::Transform` snippets (`AWS::Include` and user
//! macros), then the template-level transforms in the order they are
//! listed (`AWS::LanguageExtensions`' `Fn::ForEach`,
//! `AWS::Serverless-2016-10-31`, user macros).

use std::collections::BTreeMap;

use base64::Engine;
use mws_core::RequestContext;
use serde_json::{json, Map, Value};

use crate::intrinsics::{EvalError, Evaluator, NoResources, Pseudo};
use crate::parameters::{self, StackParameter};
use crate::template::{format_error, is_for_each, Template, INCLUDE, LANGUAGE_EXTENSIONS, SERVERLESS};
use crate::CloudFormation;

/// The key under which a stack's macros are stored.
pub(crate) fn macro_key(account: &str, region: &str, name: &str) -> String {
    format!("{account}|{region}|{name}")
}

struct Processor<'a> {
    cfn: &'a CloudFormation,
    ctx: &'a RequestContext,
    params: BTreeMap<String, Value>,
    /// Parameter values as macros see them (`templateParameterValues`).
    template_params: Map<String, Value>,
    pseudo: Pseudo,
    mappings: Option<Map<String, Value>>,
}

impl Processor<'_> {
    fn eval(&self, v: &Value) -> Result<Value, String> {
        let conditions = BTreeMap::new();
        let exports = BTreeMap::new();
        let ev = Evaluator {
            params: &self.params,
            pseudo: &self.pseudo,
            mappings: self.mappings.as_ref(),
            conditions: &conditions,
            resources: &NoResources,
            exports: &exports,
            azs: &[],
            language_extensions: true,
        };
        ev.eval(v).map_err(EvalError::message)
    }

    async fn include(&self, params: &Map<String, Value>) -> Result<Value, String> {
        let location = params
            .get("Location")
            .and_then(Value::as_str)
            .ok_or_else(|| "Transform AWS::Include failed with: Location parameter is missing".to_string())?;
        let url = match location.strip_prefix("s3://") {
            Some(rest) => match rest.split_once('/') {
                Some((bucket, key)) => format!("https://{bucket}.s3.amazonaws.com/{key}"),
                None => return Err(format!("Transform AWS::Include failed with: Invalid S3 location {location}")),
            },
            None => location.to_string(),
        };
        let text = self
            .cfn
            .fetch_s3(self.ctx, &url)
            .await
            .map_err(|e| format!("Transform AWS::Include failed with: {}", e.message))?;
        crate::template::parse_document(&text).map_err(|e| format!("Transform AWS::Include failed with: {e}"))
    }

    /// Run a user macro over `fragment`.
    async fn run_macro(&self, name: &str, fragment: Value, params: Value) -> Result<Value, String> {
        let account = &self.pseudo.account;
        let id = format!("{account}::{name}");
        let def = self.cfn.state().macros.get(&macro_key(account, &self.pseudo.region, name)).cloned();
        let Some(def) = def else { return Err(format!("No transform named {id} found.")) };
        let request_id = uuid::Uuid::new_v4().to_string();
        let event = json!({
            "region": self.pseudo.region,
            "accountId": account,
            "fragment": fragment,
            "transformId": id,
            "params": params,
            "requestId": request_id,
            "templateParameterValues": self.template_params,
        });
        let out = self
            .cfn
            .call(
                self.ctx,
                "lambda",
                "Invoke",
                json!({
                    "FunctionName": def.function_name,
                    "Payload": base64::engine::general_purpose::STANDARD.encode(event.to_string()),
                }),
            )
            .await
            .map_err(|e| format!("Transform {id} failed with: {}", e.message))?;
        let payload = out["Payload"]
            .as_str()
            .and_then(|p| base64::engine::general_purpose::STANDARD.decode(p).ok())
            .unwrap_or_default();
        let body: Value = serde_json::from_slice(&payload).unwrap_or(Value::Null);
        if out.get("FunctionError").is_some_and(|e| !e.is_null()) {
            return Err(format!(
                "Transform {id} failed with: {}",
                body.get("errorMessage").and_then(Value::as_str).unwrap_or("The macro function failed")
            ));
        }
        let status = body.get("status").and_then(Value::as_str).unwrap_or_default();
        if !status.eq_ignore_ascii_case("success") {
            let message = body
                .get("errorMessage")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| format!("Macro returned status {status}"));
            return Err(format!("Transform {id} failed with: {message}"));
        }
        if body.get("requestId").and_then(Value::as_str) != Some(request_id.as_str()) {
            return Err(format!("Transform {id} failed with: Response from macro does not match the requestId"));
        }
        body.get("fragment").cloned().ok_or_else(|| format!("Transform {id} failed with: Fragment is missing"))
    }

    /// Expand every `Fn::Transform`, innermost first.
    async fn snippets(&self, root: &mut Value) -> Result<(), String> {
        for _ in 0..1000 {
            let Some(path) = innermost_transform(root, String::new()) else { return Ok(()) };
            let target = root.pointer_mut(&path).expect("found above");
            let Value::Object(o) = target else { unreachable!("transforms sit in objects") };
            let spec = o.remove("Fn::Transform").unwrap_or_default();
            let (name, params) = match &spec {
                Value::Object(s) => (
                    s.get("Name").and_then(Value::as_str).unwrap_or_default().to_string(),
                    s.get("Parameters").cloned().unwrap_or_else(|| json!({})),
                ),
                _ => return Err(format_error("Fn::Transform must be an object with a Name")),
            };
            let params = self.eval(&params)?;
            let siblings = Value::Object(std::mem::take(o));
            let result = if name == INCLUDE {
                let included = self.include(params.as_object().unwrap_or(&Map::new())).await?;
                match (siblings, included) {
                    (Value::Object(s), included) if s.is_empty() => included,
                    (Value::Object(mut s), Value::Object(inc)) => {
                        s.extend(inc);
                        Value::Object(s)
                    }
                    _ => return Err("Transform AWS::Include failed with: The included snippet must be a map".into()),
                }
            } else {
                self.run_macro(&name, siblings, params).await?
            };
            *root.pointer_mut(&path).expect("found above") = result;
        }
        Err(format_error("Too many nested Fn::Transform functions"))
    }
}

/// The JSON pointer of an object holding an `Fn::Transform` that holds
/// none itself.
fn innermost_transform(v: &Value, here: String) -> Option<String> {
    match v {
        Value::Object(o) => {
            for (k, child) in o {
                let p = format!("{here}/{}", k.replace('~', "~0").replace('/', "~1"));
                if let Some(found) = innermost_transform(child, p) {
                    return Some(found);
                }
            }
            o.contains_key("Fn::Transform").then_some(here)
        }
        Value::Array(a) => a.iter().enumerate().find_map(|(i, x)| innermost_transform(x, format!("{here}/{i}"))),
        _ => None,
    }
}

/// Expand `Fn::ForEach` loops (`AWS::LanguageExtensions`).
fn expand_for_each(v: &mut Value, p: &Processor<'_>) -> Result<(), String> {
    match v {
        Value::Object(o) => {
            if o.keys().any(|k| is_for_each(k)) {
                let mut out = Map::new();
                for (k, val) in std::mem::take(o) {
                    if is_for_each(&k) {
                        for (nk, nv) in expand_loop(&k, val, p)? {
                            if out.contains_key(&nk) {
                                return Err(format_error(format!("{k}: Fn::ForEach produced the duplicate key {nk}")));
                            }
                            out.insert(nk, nv);
                        }
                    } else {
                        out.insert(k, val);
                    }
                }
                *o = out;
            }
            for child in o.values_mut() {
                expand_for_each(child, p)?;
            }
        }
        Value::Array(a) => {
            for x in a {
                expand_for_each(x, p)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn expand_loop(key: &str, val: Value, p: &Processor<'_>) -> Result<Vec<(String, Value)>, String> {
    let bad = || format_error(format!("{key}: Fn::ForEach requires an identifier, a collection and an output map"));
    let Value::Array(parts) = val else { return Err(bad()) };
    let [id, collection, output] = <[Value; 3]>::try_from(parts).map_err(|_| bad())?;
    let id = id.as_str().ok_or_else(bad)?.to_string();
    if !output.is_object() {
        return Err(bad());
    }
    let items = match p.eval(&collection)? {
        Value::Array(a) => a,
        Value::String(s) => s.split(',').map(|x| Value::String(x.to_string())).collect(),
        _ => {
            return Err(format_error(format!("{key}: the Fn::ForEach collection must be a list of strings")));
        }
    };
    let mut out = Vec::new();
    for item in items {
        let item = match item {
            Value::String(s) => s,
            other => other.to_string(),
        };
        let mut body = output.clone();
        substitute(&mut body, &id, &item);
        // Nested loops expand per iteration, so their keys stay distinct.
        expand_for_each(&mut body, p)?;
        if let Value::Object(m) = body {
            out.extend(m);
        }
    }
    Ok(out)
}

/// Replace a loop identifier: `{"Ref": id}`, and `${id}` / `&{id}`
/// (alphanumeric characters only) in keys and strings, as in
/// `!Ref "Queue&{Name}"` or `!Sub "q-${Name}"`.
fn substitute(v: &mut Value, id: &str, item: &str) {
    let dollar = format!("${{{id}}}");
    let amp = format!("&{{{id}}}");
    let alnum: String = item.chars().filter(char::is_ascii_alphanumeric).collect();
    match v {
        Value::Object(o) => {
            if o.len() == 1 && o.get("Ref").and_then(Value::as_str) == Some(id) {
                *v = Value::String(item.to_string());
                return;
            }
            let renamed: Map<String, Value> = std::mem::take(o)
                .into_iter()
                .map(|(k, mut child)| {
                    substitute(&mut child, id, item);
                    (k.replace(&dollar, item).replace(&amp, &alnum), child)
                })
                .collect();
            *o = renamed;
        }
        Value::Array(a) => a.iter_mut().for_each(|x| substitute(x, id, item)),
        Value::String(s) => *s = s.replace(&dollar, item).replace(&amp, &alnum),
        _ => {}
    }
}

/// Run a template's transforms. The result keeps
/// `Transform: AWS::LanguageExtensions` when the template declared it,
/// because its intrinsic functions are evaluated at deployment.
pub(crate) async fn process(
    cfn: &CloudFormation,
    ctx: &RequestContext,
    raw: &Template,
    params: &[StackParameter],
    stack_name: &str,
    stack_id: &str,
) -> Result<Template, String> {
    let template_params: Map<String, Value> = params
        .iter()
        .map(|p| (p.key.clone(), p.ref_value()))
        .map(|(k, v)| (k, if v.is_array() { v } else { Value::String(crate::providers::text(&v)) }))
        .collect();
    let p = Processor {
        cfn,
        ctx,
        params: parameters::ref_values(params),
        template_params,
        pseudo: Pseudo {
            account: ctx.caller.account_id.clone(),
            region: ctx.region.clone(),
            partition: ctx.partition.clone(),
            stack_id: stack_id.to_string(),
            stack_name: stack_name.to_string(),
            notification_arns: Vec::new(),
        },
        mappings: raw.section("Mappings").cloned(),
    };
    let mut root = Value::Object(raw.root.clone());
    p.snippets(&mut root).await?;
    let transforms = raw.transforms();
    if let Value::Object(o) = &mut root {
        o.remove("Transform");
    }
    for t in &transforms {
        match t.as_str() {
            LANGUAGE_EXTENSIONS => expand_for_each(&mut root, &p)?,
            SERVERLESS => crate::sam::expand(&mut root)?,
            INCLUDE => {
                return Err(format!("Transform {INCLUDE} failed with: {INCLUDE} can only be used with Fn::Transform"));
            }
            name => {
                let params = json!({});
                root = p.run_macro(name, root, params).await?;
                if !root.is_object() {
                    return Err(format!("Transform {}::{name} failed with: Fragment is not a map", p.pseudo.account));
                }
            }
        }
    }
    if let Value::Object(o) = &mut root {
        if transforms.iter().any(|t| t == LANGUAGE_EXTENSIONS) {
            o.insert("Transform".into(), json!(LANGUAGE_EXTENSIONS));
        }
    }
    let leftover = |v: &Value| -> bool {
        fn has(v: &Value) -> bool {
            match v {
                Value::Object(o) => o.iter().any(|(k, v)| is_for_each(k) || has(v)),
                Value::Array(a) => a.iter().any(has),
                _ => false,
            }
        }
        has(v)
    };
    if leftover(&root) {
        return Err(format_error(format!("Fn::ForEach requires the {LANGUAGE_EXTENSIONS} transform")));
    }
    let body = serde_json::to_string(&root).unwrap_or_default();
    Template::parse(&body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitutes_identifiers() {
        let mut v = json!({"Q${Name}": {"Type": "AWS::SQS::Queue", "Properties": {
            "QueueName": {"Fn::Sub": "q-${Name}"}, "Tag": {"Ref": "Name"}}}, "&{Name}X": 1});
        substitute(&mut v, "Name", "a-b");
        assert_eq!(
            v,
            json!({"Qa-b": {"Type": "AWS::SQS::Queue", "Properties": {
            "QueueName": {"Fn::Sub": "q-a-b"}, "Tag": "a-b"}}, "abX": 1})
        );
    }

    #[test]
    fn finds_innermost_transform() {
        let v = json!({"Resources": {"A": {"Properties": {"Fn::Transform": {"Name": "M", "Parameters": {
            "X": {"Fn::Transform": {"Name": "AWS::Include"}}}}}}}});
        assert_eq!(
            innermost_transform(&v, String::new()).as_deref(),
            Some("/Resources/A/Properties/Fn::Transform/Parameters/X")
        );
    }
}

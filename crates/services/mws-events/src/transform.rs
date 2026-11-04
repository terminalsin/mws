//! What a target receives: the event itself, constant `Input`, the part
//! of the event `InputPath` selects, or an `InputTransformer`'s template
//! filled from the event.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::generated::types;

/// A JSONPath as EventBridge accepts it: `$`, `$.a.b`, `$.a[0]`, `$['a']`.
pub fn parse_path(path: &str) -> Option<Vec<Step>> {
    let rest = path.strip_prefix('$')?;
    let chars: Vec<char> = rest.chars().collect();
    let mut steps = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '.' => {
                let start = i + 1;
                let mut j = start;
                while j < chars.len() && chars[j] != '.' && chars[j] != '[' {
                    j += 1;
                }
                if j == start {
                    return None;
                }
                steps.push(Step::Key(chars[start..j].iter().collect()));
                i = j;
            }
            '[' => {
                let close = chars[i..].iter().position(|c| *c == ']')? + i;
                let inner: String = chars[i + 1..close].iter().collect();
                let inner = inner.trim();
                if let Some(q) = inner.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
                    steps.push(Step::Key(q.to_string()));
                } else if let Some(q) = inner.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                    steps.push(Step::Key(q.to_string()));
                } else {
                    steps.push(Step::Index(inner.parse().ok()?));
                }
                i = close + 1;
            }
            _ => return None,
        }
    }
    Some(steps)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    Key(String),
    Index(usize),
}

pub fn select<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let mut v = value;
    for step in parse_path(path)? {
        v = match step {
            Step::Key(k) => v.get(&k)?,
            Step::Index(n) => v.get(n)?,
        };
    }
    Some(v)
}

/// Facts the reserved `<aws.events.*>` template variables expand to.
pub struct Reserved<'a> {
    pub rule_arn: &'a str,
    pub rule_name: &'a str,
    pub ingestion_time: &'a str,
}

/// The payload for a target, as text.
pub fn payload(target: &types::Target, event: &Value, reserved: &Reserved<'_>) -> String {
    if let Some(input) = &target.input {
        return input.clone();
    }
    if let Some(path) = &target.input_path {
        return select(event, path).map(|v| v.to_string()).unwrap_or_default();
    }
    if let Some(t) = &target.input_transformer {
        return render(t, event, reserved);
    }
    event.to_string()
}

fn render(t: &types::InputTransformer, event: &Value, reserved: &Reserved<'_>) -> String {
    let mut values: BTreeMap<String, Value> = BTreeMap::new();
    for (name, path) in t.input_paths_map.iter().flatten() {
        values.insert(name.clone(), select(event, path).cloned().unwrap_or(Value::Null));
    }
    values.insert("aws.events.rule-arn".into(), Value::String(reserved.rule_arn.into()));
    values.insert("aws.events.rule-name".into(), Value::String(reserved.rule_name.into()));
    values.insert("aws.events.event.ingestion-time".into(), Value::String(reserved.ingestion_time.into()));
    // `<aws.events.event>` is the envelope without `detail`;
    // `<aws.events.event.json>` is the whole event.
    let mut envelope = event.clone();
    if let Value::Object(m) = &mut envelope {
        m.remove("detail");
    }
    values.insert("aws.events.event".into(), envelope);
    values.insert("aws.events.event.json".into(), event.clone());

    let template: Vec<char> = t.input_template.chars().collect();
    let mut out = String::new();
    let mut in_string = false;
    let mut i = 0;
    while i < template.len() {
        let c = template[i];
        if c == '\\' && in_string {
            out.push(c);
            if let Some(n) = template.get(i + 1) {
                out.push(*n);
            }
            i += 2;
            continue;
        }
        if c == '"' {
            in_string = !in_string;
            out.push(c);
            i += 1;
            continue;
        }
        if c == '<' {
            if let Some(len) = template[i + 1..].iter().position(|c| *c == '>') {
                let name: String = template[i + 1..i + 1 + len].iter().collect();
                if let Some(v) = values.get(&name) {
                    if in_string {
                        // Inside quotes the value is spliced in as text.
                        let text = match v {
                            Value::String(s) => s.clone(),
                            Value::Null => String::new(),
                            other => other.to_string(),
                        };
                        let quoted = Value::String(text).to_string();
                        out.push_str(&quoted[1..quoted.len() - 1]);
                    } else {
                        out.push_str(&v.to_string());
                    }
                    i += len + 2;
                    continue;
                }
            }
        }
        out.push(c);
        i += 1;
    }
    out
}

/// Check an input transformer the way `PutTargets` does.
pub fn validate(t: &types::InputTransformer) -> Result<(), String> {
    let map = t.input_paths_map.clone().unwrap_or_default();
    if map.len() > 100 {
        return Err("InputPathsMap has more than 100 entries.".into());
    }
    for (name, path) in &map {
        if name.starts_with("aws.events.") {
            return Err(format!("InputTransformer.InputPathsMap key {name} is reserved."));
        }
        if parse_path(path).is_none() {
            return Err(format!("InputTransformer.InputPathsMap value {path} is not a valid JSON path."));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn transforms() {
        let event = json!({"detail": {"instance": "i-1", "state": "running", "n": 3}, "id": "e1"});
        let r = Reserved { rule_arn: "arn:r", rule_name: "r", ingestion_time: "t" };
        let mk = |tpl: &str| types::InputTransformer {
            input_paths_map: Some(
                [("i".to_string(), "$.detail.instance".to_string()), ("n".to_string(), "$.detail.n".to_string())]
                    .into_iter()
                    .collect(),
            ),
            input_template: tpl.to_string(),
        };
        assert_eq!(render(&mk(r#"{"id": <i>, "count": <n>}"#), &event, &r), r#"{"id": "i-1", "count": 3}"#);
        assert_eq!(render(&mk(r#""instance <i> has <n>""#), &event, &r), r#""instance i-1 has 3""#);
        assert_eq!(render(&mk(r#"{"rule": "<aws.events.rule-name>"}"#), &event, &r), r#"{"rule": "r"}"#);
        assert_eq!(render(&mk("<aws.events.event>"), &event, &r), r#"{"id":"e1"}"#);
        assert_eq!(
            render(&mk("<aws.events.event.json>"), &event, &r),
            r#"{"detail":{"instance":"i-1","state":"running","n":3},"id":"e1"}"#
        );
        assert_eq!(select(&event, "$.detail.state"), Some(&json!("running")));
        assert_eq!(select(&event, "$['detail']['n']"), Some(&json!(3)));
    }
}

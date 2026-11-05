//! YAML documents (AWSTOE components, workflows) as JSON values.

use serde_json::{Map, Value};
use yaml_rust2::{Yaml, YamlLoader};

/// Parse a YAML (or JSON) document.
pub fn parse(text: &str) -> Result<Value, String> {
    let docs = YamlLoader::load_from_str(text).map_err(|e| e.to_string())?;
    let doc = docs.into_iter().next().ok_or_else(|| "the document is empty".to_string())?;
    Ok(to_json(doc))
}

fn to_json(y: Yaml) -> Value {
    match y {
        Yaml::Real(s) => {
            s.parse::<f64>().ok().and_then(serde_json::Number::from_f64).map(Value::Number).unwrap_or(Value::String(s))
        }
        Yaml::Integer(i) => Value::from(i),
        Yaml::String(s) => Value::String(s),
        Yaml::Boolean(b) => Value::Bool(b),
        Yaml::Array(a) => Value::Array(a.into_iter().map(to_json).collect()),
        Yaml::Hash(h) => {
            let mut m = Map::new();
            for (k, v) in h {
                let key = match k {
                    Yaml::String(s) => s,
                    Yaml::Integer(i) => i.to_string(),
                    Yaml::Real(r) => r,
                    Yaml::Boolean(b) => b.to_string(),
                    _ => continue,
                };
                m.insert(key, to_json(v));
            }
            Value::Object(m)
        }
        Yaml::Alias(_) | Yaml::Null | Yaml::BadValue => Value::Null,
    }
}

/// A scalar as text (YAML often gives numbers where text is meant).
pub fn text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses() {
        let v = super::parse("name: x\nschemaVersion: 1.0\nphases:\n  - name: build\n    steps: []\n").unwrap();
        assert_eq!(v["name"], "x");
        assert_eq!(super::text(&v["schemaVersion"]).unwrap(), "1.0");
        assert!(v["phases"].is_array());
    }
}

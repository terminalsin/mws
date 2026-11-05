//! Stack policies: which resources an update may modify, replace or
//! delete.

use serde_json::Value;

/// Check a stack policy document. Validation of the document itself is
/// [`validate`]'s job.
pub fn check(policy: &str, action: &str, logical_id: &str, resource_type: &str) -> Result<(), String> {
    let doc: Value = serde_json::from_str(policy).unwrap_or(Value::Null);
    let statements = match doc.get("Statement") {
        Some(Value::Array(a)) => a.clone(),
        Some(s @ Value::Object(_)) => vec![s.clone()],
        _ => Vec::new(),
    };
    let resource = format!("LogicalResourceId/{logical_id}");
    let mut allowed = false;
    for (i, st) in statements.iter().enumerate() {
        if !matches(st, "Action", "NotAction", action) || !matches(st, "Resource", "NotResource", &resource) {
            continue;
        }
        if !condition_holds(st.get("Condition"), resource_type) {
            continue;
        }
        match st.get("Effect").and_then(Value::as_str) {
            Some("Deny") => {
                return Err(format!(
                    "Action denied by stack policy: Statement [#{}] does not allow [{action}] for resource [{resource}]",
                    i + 1
                ))
            }
            Some("Allow") => allowed = true,
            _ => {}
        }
    }
    if allowed {
        Ok(())
    } else {
        Err(format!("Action not allowed by stack policy: No statement allows [{action}] for resource [{resource}]"))
    }
}

/// Check a policy document's structure.
pub fn validate(policy: &str) -> Result<(), String> {
    let doc: Value = serde_json::from_str(policy).map_err(|_| "Error validating stack policy: Invalid stack policy".to_string())?;
    let ok = match doc.get("Statement") {
        Some(Value::Array(a)) => a.iter().all(|s| {
            matches!(s.get("Effect").and_then(Value::as_str), Some("Allow" | "Deny"))
                && (s.get("Action").is_some() || s.get("NotAction").is_some())
        }),
        Some(Value::Object(_)) => true,
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err("Error validating stack policy: Invalid stack policy".into())
    }
}

fn values(v: Option<&Value>) -> Option<Vec<String>> {
    match v? {
        Value::String(s) => Some(vec![s.clone()]),
        Value::Array(a) => Some(a.iter().filter_map(Value::as_str).map(str::to_string).collect()),
        _ => None,
    }
}

fn matches(st: &Value, key: &str, not_key: &str, value: &str) -> bool {
    if let Some(patterns) = values(st.get(key)) {
        return patterns.iter().any(|p| glob(p, value));
    }
    if let Some(patterns) = values(st.get(not_key)) {
        return !patterns.iter().any(|p| glob(p, value));
    }
    false
}

fn condition_holds(cond: Option<&Value>, resource_type: &str) -> bool {
    let Some(Value::Object(ops)) = cond else { return true };
    for (op, body) in ops {
        let Some(want) = values(body.get("ResourceType")) else { continue };
        let hit = match op.as_str() {
            "StringEquals" => want.iter().any(|w| w == resource_type),
            "StringNotEquals" => !want.iter().any(|w| w == resource_type),
            "StringLike" => want.iter().any(|w| glob(w, resource_type)),
            "StringNotLike" => !want.iter().any(|w| glob(w, resource_type)),
            _ => false,
        };
        if !hit {
            return false;
        }
    }
    true
}

fn glob(pattern: &str, value: &str) -> bool {
    fn go(p: &[u8], v: &[u8]) -> bool {
        match (p.first(), v.first()) {
            (None, None) => true,
            (Some(b'*'), _) => go(&p[1..], v) || (!v.is_empty() && go(p, &v[1..])),
            (Some(b'?'), Some(_)) => go(&p[1..], &v[1..]),
            (Some(a), Some(b)) if a == b => go(&p[1..], &v[1..]),
            _ => false,
        }
    }
    go(pattern.as_bytes(), value.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_wins_and_default_denies() {
        let p = r#"{"Statement":[{"Effect":"Allow","Action":"Update:*","Principal":"*","Resource":"*"},
            {"Effect":"Deny","Action":"Update:Replace","Principal":"*","Resource":"LogicalResourceId/Db"}]}"#;
        assert!(check(p, "Update:Modify", "Db", "AWS::SQS::Queue").is_ok());
        assert!(check(p, "Update:Replace", "Db", "AWS::SQS::Queue").unwrap_err().contains("Statement [#2]"));
        let only_db = r#"{"Statement":[{"Effect":"Allow","Action":"Update:*","Principal":"*","Resource":"LogicalResourceId/Db"}]}"#;
        assert!(check(only_db, "Update:Modify", "Other", "AWS::SQS::Queue").is_err());
    }
}

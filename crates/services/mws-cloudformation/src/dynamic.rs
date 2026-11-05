//! Dynamic references: `{{resolve:ssm:...}}`, `{{resolve:ssm-secure:...}}`
//! and `{{resolve:secretsmanager:...}}` in property values, read from
//! Parameter Store and Secrets Manager as the stack's identity.

use mws_core::RequestContext;
use serde_json::{json, Value};

use crate::CloudFormation;

pub async fn resolve(cfn: &CloudFormation, ctx: &RequestContext, v: Value) -> Result<Value, String> {
    Ok(match v {
        Value::String(s) if s.contains("{{resolve:") => Value::String(resolve_str(cfn, ctx, &s).await?),
        Value::Array(a) => {
            let mut out = Vec::with_capacity(a.len());
            for x in a {
                out.push(Box::pin(resolve(cfn, ctx, x)).await?);
            }
            Value::Array(out)
        }
        Value::Object(o) => {
            let mut out = serde_json::Map::new();
            for (k, x) in o {
                out.insert(k, Box::pin(resolve(cfn, ctx, x)).await?);
            }
            Value::Object(out)
        }
        other => other,
    })
}

async fn resolve_str(cfn: &CloudFormation, ctx: &RequestContext, s: &str) -> Result<String, String> {
    let mut out = String::new();
    let mut rest = s;
    while let Some(pos) = rest.find("{{resolve:") {
        out.push_str(&rest[..pos]);
        let after = &rest[pos + "{{resolve:".len()..];
        let Some(end) = after.find("}}") else {
            out.push_str(&rest[pos..]);
            rest = "";
            break;
        };
        out.push_str(&reference(cfn, ctx, &after[..end]).await?);
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

async fn reference(cfn: &CloudFormation, ctx: &RequestContext, r: &str) -> Result<String, String> {
    let (service, rest) = r.split_once(':').unwrap_or((r, ""));
    match service {
        "ssm" | "ssm-secure" => {
            let input = json!({"Name": rest, "WithDecryption": service == "ssm-secure"});
            match cfn.call(ctx, "ssm", "GetParameter", input).await {
                Ok(out) => Ok(out["Parameter"]["Value"].as_str().unwrap_or_default().to_string()),
                Err(e) if e.code == "ParameterNotFound" || e.code == "ParameterVersionNotFound" => {
                    Err(format!("Parameters: [{service}:{rest}] cannot be found."))
                }
                Err(e) => Err(e.message),
            }
        }
        "secretsmanager" => {
            // secret-id may be an ARN, which has colons of its own.
            let parts: Vec<&str> = rest.split(':').collect();
            let (id, tail) = if rest.starts_with("arn:") && parts.len() >= 7 {
                (parts[..7].join(":"), parts[7..].to_vec())
            } else {
                (parts.first().copied().unwrap_or_default().to_string(), parts.get(1..).unwrap_or_default().to_vec())
            };
            let field = tail.first().copied().filter(|f| !f.is_empty()).unwrap_or("SecretString");
            if field != "SecretString" {
                return Err(format!("Could not parse SecretString JSON for {rest}: only SecretString can be referenced"));
            }
            let key = tail.get(1).copied().filter(|k| !k.is_empty());
            let stage = tail.get(2).copied().filter(|k| !k.is_empty());
            let version = tail.get(3).copied().filter(|k| !k.is_empty());
            let mut input = json!({"SecretId": id});
            if let Some(s) = stage {
                input["VersionStage"] = json!(s);
            }
            if let Some(v) = version {
                input["VersionId"] = json!(v);
            }
            let out = cfn.call(ctx, "secretsmanager", "GetSecretValue", input).await.map_err(|e| e.message)?;
            let secret = out["SecretString"].as_str().unwrap_or_default().to_string();
            match key {
                None => Ok(secret),
                Some(k) => {
                    let parsed: Value = serde_json::from_str(&secret)
                        .map_err(|_| format!("Could not parse SecretString JSON for secret {id}"))?;
                    match parsed.get(k) {
                        Some(Value::String(s)) => Ok(s.clone()),
                        Some(other) => Ok(other.to_string()),
                        None => Err(format!("Could not find SecretString JSON key {k} in secret {id}")),
                    }
                }
            }
        }
        other => Err(format!("Template error: dynamic reference service {other} is not supported")),
    }
}

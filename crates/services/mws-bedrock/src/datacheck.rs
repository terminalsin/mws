//! Checking the data Bedrock jobs read from S3: training and validation
//! JSONL for model customization, model weights for import, and prompt
//! datasets for evaluation. The messages are the job's `failureMessage`.

use serde_json::{Map, Value};

use crate::catalog::Family;
use crate::storage::{objects, RoleStorage};

/// Read one JSONL object (a training, validation or dataset file).
pub fn read_jsonl(io: &dyn RoleStorage, uri: &str, what: &str) -> Result<Vec<Map<String, Value>>, String> {
    let (bucket, key) = crate::storage::s3_location(uri).ok_or_else(|| format!("The S3 URI {uri} is invalid."))?;
    let body = io.get(&bucket, &key).map_err(|e| format!("Unable to read the {what} at {uri}: {e}"))?;
    let text = String::from_utf8(body).map_err(|_| format!("The {what} at {uri} is not UTF-8 encoded JSON Lines."))?;
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()) {
        match serde_json::from_str::<Value>(line) {
            Ok(Value::Object(m)) => out.push(m),
            _ => return Err(format!("Malformed {what} at {uri}: line {} is not a valid JSON object.", i + 1)),
        }
    }
    if out.is_empty() {
        return Err(format!("The {what} at {uri} contains no records."));
    }
    Ok(out)
}

fn is_str(m: &Map<String, Value>, k: &str) -> bool {
    m.get(k).is_some_and(Value::is_string)
}

/// Check the records of a customization data file against the format the
/// base model and customization type take.
pub fn training_format(
    records: &[Map<String, Value>],
    family: Family,
    customization: &str,
    uri: &str,
    what: &str,
) -> Result<(), String> {
    for (i, r) in records.iter().enumerate() {
        let line = i + 1;
        let ok = match customization {
            "CONTINUED_PRE_TRAINING" => is_str(r, "input"),
            "DISTILLATION" => r.get("messages").is_some_and(Value::is_array) || is_str(r, "prompt"),
            _ => match family {
                Family::Anthropic | Family::Nova => r.get("messages").is_some_and(|m| {
                    m.as_array().is_some_and(|a| !a.is_empty() && a.iter().all(|x| x.get("role").is_some()))
                }),
                _ => (is_str(r, "prompt") && is_str(r, "completion")) || r.get("messages").is_some_and(Value::is_array),
            },
        };
        if !ok {
            let want = match customization {
                "CONTINUED_PRE_TRAINING" => "an \"input\" string",
                "DISTILLATION" => "\"messages\" or a \"prompt\"",
                _ if matches!(family, Family::Anthropic | Family::Nova) => "a non-empty \"messages\" array",
                _ => "\"prompt\" and \"completion\" strings",
            };
            return Err(format!("Malformed {what} at {uri}: line {line} must have {want}."));
        }
    }
    Ok(())
}

/// Model architectures Custom Model Import accepts (`model_type` in
/// `config.json`).
const ARCHITECTURES: &[&str] = &["llama", "mistral", "mixtral", "t5", "gpt_bigcode", "qwen2", "qwen2_vl", "qwen3"];

/// Check imported model weights: a `config.json` naming a supported
/// architecture, a tokenizer and `.safetensors` weights. Returns the
/// architecture.
pub fn model_weights(io: &dyn RoleStorage, uri: &str) -> Result<String, String> {
    let objs = objects(io, &format!("{}/", uri.trim_end_matches('/')))
        .map_err(|e| format!("Unable to read the model data at {uri}: {e}"))?;
    if objs.is_empty() {
        return Err(format!("No model files were found at {uri}."));
    }
    let name = |k: &str| k.rsplit('/').next().unwrap_or(k).to_string();
    let config = objs
        .iter()
        .find(|(_, k)| name(k) == "config.json")
        .ok_or_else(|| format!("The model data at {uri} doesn't contain a config.json file."))?;
    if !objs.iter().any(|(_, k)| k.ends_with(".safetensors")) {
        return Err(format!("The model data at {uri} doesn't contain model weights in the .safetensors format."));
    }
    if !objs.iter().any(|(_, k)| name(k).starts_with("tokenizer")) {
        return Err(format!("The model data at {uri} doesn't contain tokenizer files."));
    }
    let body = io.get(&config.0, &config.1).map_err(|e| format!("Unable to read the model data at {uri}: {e}"))?;
    let cfg: Value =
        serde_json::from_slice(&body).map_err(|_| format!("The config.json file at {uri} is not valid JSON."))?;
    let arch = cfg.get("model_type").and_then(Value::as_str).unwrap_or_default().to_ascii_lowercase();
    if !ARCHITECTURES.contains(&arch.as_str()) {
        return Err(format!(
            "The model architecture {} is not supported. Supported architectures: {}.",
            if arch.is_empty() { "(none)" } else { &arch },
            ARCHITECTURES.join(", ")
        ));
    }
    Ok(arch)
}

/// Check an evaluation dataset: JSONL records with a `prompt`.
pub fn eval_dataset(io: &dyn RoleStorage, uri: &str) -> Result<Vec<Map<String, Value>>, String> {
    let records = read_jsonl(io, uri, "dataset")?;
    for (i, r) in records.iter().enumerate() {
        if !is_str(r, "prompt") {
            return Err(format!("Malformed dataset at {uri}: line {} must have a \"prompt\" string.", i + 1));
        }
    }
    if records.len() > 1000 {
        return Err(format!("The dataset at {uri} has {} prompts; a dataset can have at most 1000.", records.len()));
    }
    Ok(records)
}

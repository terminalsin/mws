//! Destination configurations: what `CreateDeliveryStream` and
//! `UpdateDestination` accept, and the descriptions
//! `DescribeDeliveryStream` derives from them.
//!
//! Configurations are kept as JSON in the generated types' serde form, so
//! one set of rules (renames, defaults, secrets left out) serves every
//! destination type.

use serde_json::{json, Map, Value};

use crate::generated::types;
use mws_core::ServiceError;

/// Destination kinds, by the prefix of their member names
/// (`<kind>_destination_configuration`, `_description`, `_update`).
pub const KINDS: &[&str] = &[
    "extended_s3",
    "redshift",
    "elasticsearch",
    "amazonopensearchservice",
    "splunk",
    "http_endpoint",
    "amazon_open_search_serverless",
    "snowflake",
    "iceberg",
];

/// Fields the descriptions never show.
const SECRETS: &[&str] = &["password", "private_key", "key_passphrase", "access_key"];

/// The destination configuration of a create request: `(kind, config,
/// plain_s3)`, or an error unless exactly one is given.
pub fn destination_of(input: &Value) -> Result<(String, Value, bool), ServiceError> {
    let mut found = Vec::new();
    if let Some(v) = input.get("s3_destination_configuration").filter(|v| !v.is_null()) {
        found.push(("extended_s3".to_string(), v.clone(), true));
    }
    for kind in KINDS {
        if let Some(v) = input.get(format!("{kind}_destination_configuration")).filter(|v| !v.is_null()) {
            found.push((kind.to_string(), v.clone(), false));
        }
    }
    match found.len() {
        1 => Ok(found.pop().expect("one")),
        0 => Err(crate::names::invalid_argument("A destination configuration must be specified.")),
        _ => Err(crate::names::invalid_argument(
            "Exactly one destination configuration is supported for a Firehose stream.",
        )),
    }
}

/// The update an `UpdateDestination` request carries: `(kind, update,
/// plain_s3)`.
pub fn update_of(input: &Value) -> Result<(String, Value, bool), ServiceError> {
    let mut found = Vec::new();
    if let Some(v) = input.get("s3_destination_update").filter(|v| !v.is_null()) {
        found.push(("extended_s3".to_string(), v.clone(), true));
    }
    for kind in KINDS {
        if let Some(v) = input.get(format!("{kind}_destination_update")).filter(|v| !v.is_null()) {
            found.push((kind.to_string(), v.clone(), false));
        }
    }
    match found.len() {
        1 => Ok(found.pop().expect("one")),
        0 => Err(crate::names::invalid_argument("A destination update must be specified.")),
        _ => Err(crate::names::invalid_argument("Exactly one destination update is supported.")),
    }
}

/// Drop JSON nulls, recursively.
pub fn strip_nulls(v: Value) -> Value {
    match v {
        Value::Object(m) => {
            Value::Object(m.into_iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k, strip_nulls(v))).collect())
        }
        Value::Array(a) => Value::Array(a.into_iter().map(strip_nulls).collect()),
        other => other,
    }
}

/// Merge an update into a configuration: objects merge, anything else
/// replaces. Update member names map onto configuration ones.
pub fn merge(config: &mut Value, update: Value) {
    let Value::Object(update) = update else {
        *config = update;
        return;
    };
    if !config.is_object() {
        *config = Value::Object(Map::new());
    }
    let target = config.as_object_mut().expect("object");
    for (k, v) in update {
        let k = match k.as_str() {
            "s3_update" => "s3_configuration".to_string(),
            "s3_backup_update" => "s3_backup_configuration".to_string(),
            _ => k,
        };
        if v.is_null() {
            continue;
        }
        match target.get_mut(&k) {
            Some(existing) if existing.is_object() && v.is_object() => merge(existing, v),
            _ => {
                target.insert(k, v);
            }
        }
    }
}

fn set_default(m: &mut Map<String, Value>, key: &str, value: Value) {
    match (m.get_mut(key), value) {
        (Some(Value::Object(have)), Value::Object(defaults)) => {
            for (k, v) in defaults {
                have.entry(k).or_insert(v);
            }
        }
        (Some(v), _) if !v.is_null() => {}
        (_, value) => {
            m.insert(key.to_string(), value);
        }
    }
}

/// An S3 configuration as described, with AWS's defaults filled in.
fn s3_description(v: &Value) -> Value {
    let mut m = v.as_object().cloned().unwrap_or_default();
    set_default(&mut m, "buffering_hints", json!({"size_in_m_bs": 5, "interval_in_seconds": 300}));
    set_default(&mut m, "compression_format", json!("UNCOMPRESSED"));
    set_default(&mut m, "encryption_configuration", json!({"no_encryption_config": "NoEncryption"}));
    set_default(&mut m, "cloud_watch_logging_options", json!({"enabled": false}));
    Value::Object(m)
}

/// The defaults each destination type describes when not configured.
fn kind_defaults(kind: &str, m: &mut Map<String, Value>) {
    let buffering = |size: i32, interval: i32| json!({"size_in_m_bs": size, "interval_in_seconds": interval});
    match kind {
        "extended_s3" => {
            set_default(m, "s3_backup_mode", json!("Disabled"));
        }
        "http_endpoint" => {
            set_default(m, "buffering_hints", buffering(5, 300));
            set_default(m, "retry_options", json!({"duration_in_seconds": 300}));
            set_default(m, "s3_backup_mode", json!("FailedDataOnly"));
            set_default(m, "request_configuration", json!({"content_encoding": "NONE"}));
        }
        "splunk" => {
            set_default(m, "buffering_hints", buffering(5, 60));
            set_default(m, "retry_options", json!({"duration_in_seconds": 300}));
            set_default(m, "s3_backup_mode", json!("FailedEventsOnly"));
            set_default(m, "hec_acknowledgment_timeout_in_seconds", json!(180));
        }
        "elasticsearch" | "amazonopensearchservice" => {
            set_default(m, "buffering_hints", buffering(5, 300));
            set_default(m, "retry_options", json!({"duration_in_seconds": 300}));
            set_default(m, "s3_backup_mode", json!("FailedDocumentsOnly"));
            set_default(m, "index_rotation_period", json!("OneDay"));
        }
        "amazon_open_search_serverless" => {
            set_default(m, "buffering_hints", buffering(5, 300));
            set_default(m, "retry_options", json!({"duration_in_seconds": 300}));
            set_default(m, "s3_backup_mode", json!("FailedDocumentsOnly"));
        }
        "redshift" => {
            set_default(m, "retry_options", json!({"duration_in_seconds": 3600}));
            set_default(m, "s3_backup_mode", json!("Disabled"));
        }
        "snowflake" => {
            set_default(m, "buffering_hints", buffering(1, 0));
            set_default(m, "retry_options", json!({"duration_in_seconds": 60}));
            set_default(m, "s3_backup_mode", json!("FailedDataOnly"));
            set_default(m, "data_loading_option", json!("JSON_MAPPING"));
        }
        "iceberg" => {
            set_default(m, "buffering_hints", buffering(5, 300));
            set_default(m, "retry_options", json!({"duration_in_seconds": 300}));
            set_default(m, "s3_backup_mode", json!("FailedDataOnly"));
        }
        _ => {}
    }
    set_default(m, "cloud_watch_logging_options", json!({"enabled": false}));
}

/// Whether an Extended S3 configuration enables dynamic partitioning.
pub fn dynamic_partitioning(config: &Value) -> bool {
    config.pointer("/dynamic_partitioning_configuration/enabled").and_then(Value::as_bool).unwrap_or(false)
}

/// Whether an Extended S3 configuration enables data format conversion
/// (`Enabled` defaults to true when the configuration is given).
pub fn format_conversion(config: &Value) -> bool {
    config
        .get("data_format_conversion_configuration")
        .filter(|c| c.is_object())
        .is_some_and(|c| c.get("enabled").and_then(Value::as_bool).unwrap_or(true))
}

/// The configuration with defaults applied, as delivery reads it.
pub fn effective(kind: &str, config: &Value) -> Value {
    let mut m = config.as_object().cloned().unwrap_or_default();
    if kind == "extended_s3" {
        // Dynamic partitioning and format conversion buffer 128 MiB by
        // default.
        let config = Value::Object(m.clone());
        if (dynamic_partitioning(&config) || format_conversion(&config))
            && config.pointer("/buffering_hints/size_in_m_bs").is_none()
        {
            set_default(&mut m, "buffering_hints", json!({"size_in_m_bs": 128}));
        }
        m = s3_description(&Value::Object(m)).as_object().cloned().unwrap_or_default();
    }
    kind_defaults(kind, &mut m);
    for key in ["s3_configuration", "s3_backup_configuration"] {
        if let Some(v) = m.get(key).cloned() {
            m.insert(key.to_string(), s3_description(&v));
        }
    }
    Value::Object(m)
}

fn remove_secrets(v: &mut Value) {
    if let Value::Object(m) = v {
        for s in SECRETS {
            m.remove(*s);
        }
        for (_, child) in m.iter_mut() {
            remove_secrets(child);
        }
    }
}

/// How `DescribeDeliveryStream` shows a destination.
pub fn describe(id: &str, kind: &str, config: &Value, plain_s3: bool) -> types::DestinationDescription {
    let mut d = effective(kind, config);
    remove_secrets(&mut d);
    if let Value::Object(m) = &mut d {
        if let Some(v) = m.remove("s3_configuration") {
            m.insert("s3_destination_description".into(), v);
        }
        if let Some(v) = m.remove("s3_backup_configuration") {
            m.insert("s3_backup_description".into(), v);
        }
    }
    let mut out = Map::new();
    out.insert("destination_id".into(), json!(id));
    if plain_s3 {
        out.insert("s3_destination_description".into(), d.clone());
    }
    out.insert(format!("{kind}_destination_description"), d);
    serde_json::from_value(Value::Object(out)).unwrap_or_else(|e| {
        tracing::warn!("could not describe a {kind} destination: {e}");
        types::DestinationDescription { destination_id: id.to_string(), ..Default::default() }
    })
}

/// A typed view of a configuration (with defaults).
pub fn typed<T: serde::de::DeserializeOwned + Default>(kind: &str, config: &Value) -> T {
    serde_json::from_value(effective(kind, config)).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s3_destinations_describe_with_defaults_and_both_ways() {
        let config = json!({"role_arn": "arn:aws:iam::1:role/r", "bucket_arn": "arn:aws:s3:::b"});
        let d = describe("destinationId-000000000001", "extended_s3", &config, true);
        let s3 = d.s3_destination_description.unwrap();
        assert_eq!(s3.compression_format, "UNCOMPRESSED");
        assert_eq!(s3.buffering_hints.size_in_m_bs, Some(5));
        assert_eq!(s3.encryption_configuration.no_encryption_config.as_deref(), Some("NoEncryption"));
        let ext = d.extended_s3_destination_description.unwrap();
        assert_eq!(ext.s3_backup_mode.as_deref(), Some("Disabled"));
    }

    #[test]
    fn updates_merge_and_secrets_stay_hidden() {
        let mut config = json!({
            "endpoint_configuration": {"url": "https://x", "access_key": "secret"},
            "s3_configuration": {"role_arn": "r", "bucket_arn": "arn:aws:s3:::b"},
        });
        merge(&mut config, json!({"s3_update": {"prefix": "p/"}, "endpoint_configuration": {"name": "n"}}));
        assert_eq!(config["s3_configuration"]["prefix"], "p/");
        assert_eq!(config["endpoint_configuration"]["access_key"], "secret");
        let d = describe("d", "http_endpoint", &config, false);
        let h = d.http_endpoint_destination_description.unwrap();
        assert_eq!(h.endpoint_configuration.unwrap().name.as_deref(), Some("n"));
        assert_eq!(h.s3_destination_description.unwrap().prefix.as_deref(), Some("p/"));
        assert_eq!(h.s3_backup_mode.as_deref(), Some("FailedDataOnly"));
    }
}

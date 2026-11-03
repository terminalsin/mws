use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, NaiveDateTime, Utc};
use mws_core::ServiceError;
use regex::Regex;

/// Flat awsQuery request parameters, e.g. `Tags.member.1.Key -> "env"`.
#[derive(Debug, Clone, Default)]
pub struct Params {
    map: BTreeMap<String, String>,
}

impl Params {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn extend_from_urlencoded(&mut self, input: &[u8]) {
        for (k, v) in form_urlencoded::parse(input) {
            self.map.insert(k.into_owned(), v.into_owned());
        }
    }

    pub fn insert(&mut self, k: impl Into<String>, v: impl Into<String>) {
        self.map.insert(k.into(), v.into());
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.map.get(key).map(String::as_str)
    }

    /// Whether `key` itself or anything nested under `key.` is present.
    pub fn has_prefix(&self, key: &str) -> bool {
        if self.map.contains_key(key) {
            return true;
        }
        let prefix = format!("{key}.");
        self.map.range(prefix.clone()..).next().is_some_and(|(k, _)| k.starts_with(&prefix))
    }

    /// The distinct numeric indexes `N` that appear as `prefix.N` or
    /// `prefix.N.*`, in ascending order.
    pub fn indexes(&self, prefix: &str) -> Vec<usize> {
        let p = format!("{prefix}.");
        let mut out = BTreeSet::new();
        for (k, _) in self.map.range(p.clone()..) {
            let Some(rest) = k.strip_prefix(&p) else { break };
            let idx = rest.split('.').next().unwrap_or_default();
            if let Ok(n) = idx.parse::<usize>() {
                out.insert(n);
            }
        }
        out.into_iter().collect()
    }
}

/// Decodes typed values out of [`Params`] while collecting validation errors
/// in the same wording AWS uses.
#[derive(Debug)]
pub struct Decoder<'a> {
    pub params: &'a Params,
    errors: Vec<String>,
}

impl<'a> Decoder<'a> {
    pub fn new(params: &'a Params) -> Self {
        Self { params, errors: Vec::new() }
    }

    /// Turn collected errors into AWS's `ValidationError`, if any.
    pub fn finish(self) -> Result<(), ServiceError> {
        if self.errors.is_empty() {
            return Ok(());
        }
        let n = self.errors.len();
        let noun = if n == 1 { "error" } else { "errors" };
        Err(ServiceError::client(
            "ValidationError",
            400,
            format!("{n} validation {noun} detected: {}", self.errors.join("; ")),
        ))
    }

    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    pub fn push_error(&mut self, message: String) {
        self.errors.push(message);
    }

    pub fn has_prefix(&self, key: &str) -> bool {
        self.params.has_prefix(key)
    }

    pub fn indexes(&self, prefix: &str) -> Vec<usize> {
        self.params.indexes(prefix)
    }

    /// A list or map serialized as `Key=` (present, empty value) is empty.
    pub fn is_explicitly_empty(&self, key: &str) -> bool {
        self.params.get(key) == Some("")
    }

    // ---- scalars ------------------------------------------------------------

    pub fn string(&mut self, key: &str) -> Option<String> {
        self.params.get(key).map(str::to_string)
    }

    pub fn boolean(&mut self, key: &str, path: &str) -> Option<bool> {
        let raw = self.params.get(key)?;
        match raw {
            "true" => Some(true),
            "false" => Some(false),
            _ => {
                self.invalid(path, raw, "boolean");
                None
            }
        }
    }

    pub fn number<T: std::str::FromStr>(&mut self, key: &str, path: &str) -> Option<T> {
        let raw = self.params.get(key)?;
        match raw.parse::<T>() {
            Ok(v) => Some(v),
            Err(_) => {
                self.invalid(path, raw, "number");
                None
            }
        }
    }

    pub fn timestamp(&mut self, key: &str, path: &str) -> Option<DateTime<Utc>> {
        let raw = self.params.get(key)?;
        if let Ok(t) = DateTime::parse_from_rfc3339(raw) {
            return Some(t.with_timezone(&Utc));
        }
        if let Ok(t) = NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S") {
            return Some(t.and_utc());
        }
        if let Ok(secs) = raw.parse::<f64>() {
            if let Some(t) = DateTime::from_timestamp_millis((secs * 1000.0) as i64) {
                return Some(t);
            }
        }
        self.invalid(path, raw, "timestamp");
        None
    }

    pub fn blob(&mut self, key: &str, path: &str) -> Option<Vec<u8>> {
        use base64::Engine;
        let raw = self.params.get(key)?;
        match base64::engine::general_purpose::STANDARD.decode(raw) {
            Ok(v) => Some(v),
            Err(_) => {
                self.invalid(path, raw, "base64 blob");
                None
            }
        }
    }

    fn invalid(&mut self, path: &str, raw: &str, kind: &str) {
        self.errors
            .push(format!("Value '{raw}' at '{path}' failed to satisfy constraint: Member must be a valid {kind}"));
    }

    // ---- constraints --------------------------------------------------------

    pub fn required<T>(&mut self, value: &Option<T>, path: &str) {
        if value.is_none() {
            self.errors.push(format!("Value null at '{path}' failed to satisfy constraint: Member must not be null"));
        }
    }

    pub fn check_length(&mut self, path: &str, shown: &str, len: usize, min: Option<u64>, max: Option<u64>) {
        let len = len as u64;
        if let Some(min) = min {
            if len < min {
                self.errors.push(format!(
                    "Value '{shown}' at '{path}' failed to satisfy constraint: Member must have length greater than or equal to {min}"
                ));
            }
        }
        if let Some(max) = max {
            if len > max {
                self.errors.push(format!(
                    "Value '{shown}' at '{path}' failed to satisfy constraint: Member must have length less than or equal to {max}"
                ));
            }
        }
    }

    pub fn check_range(&mut self, path: &str, value: f64, min: Option<f64>, max: Option<f64>) {
        let shown = trim_float(value);
        if let Some(min) = min {
            if value < min {
                self.errors.push(format!(
                    "Value '{shown}' at '{path}' failed to satisfy constraint: Member must have value greater than or equal to {}",
                    trim_float(min)
                ));
            }
        }
        if let Some(max) = max {
            if value > max {
                self.errors.push(format!(
                    "Value '{shown}' at '{path}' failed to satisfy constraint: Member must have value less than or equal to {}",
                    trim_float(max)
                ));
            }
        }
    }

    pub fn check_pattern(&mut self, path: &str, value: &str, re: &Regex, pattern: &str) {
        if !re.is_match(value) {
            self.errors.push(format!(
                "Value '{value}' at '{path}' failed to satisfy constraint: Member must satisfy regular expression pattern: {pattern}"
            ));
        }
    }

    pub fn check_enum(&mut self, path: &str, value: &str, allowed: &[&str]) {
        if !allowed.contains(&value) {
            self.errors.push(format!(
                "Value '{value}' at '{path}' failed to satisfy constraint: Member must satisfy enum value set: [{}]",
                allowed.join(", ")
            ));
        }
    }
}

/// How AWS renders a list value inside a validation message.
pub fn render_list<T: std::fmt::Debug>(items: &[T]) -> String {
    let parts: Vec<String> = items
        .iter()
        .map(|i| {
            let s = format!("{i:?}");
            s.strip_prefix('"').and_then(|s| s.strip_suffix('"')).map(str::to_string).unwrap_or(s)
        })
        .collect();
    format!("[{}]", parts.join(", "))
}

fn trim_float(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        v.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexes_and_prefixes() {
        let mut p = Params::new();
        p.extend_from_urlencoded(b"Action=X&Tags.member.2.Key=b&Tags.member.1.Key=a&Tags.member.10.Key=c&TagsOther=1");
        assert_eq!(p.indexes("Tags.member"), vec![1, 2, 10]);
        assert!(p.has_prefix("Tags"));
        assert!(!p.has_prefix("Tag"));
        assert!(p.has_prefix("TagsOther"));
    }

    #[test]
    fn validation_message_matches_aws() {
        let p = Params::new();
        let mut d = Decoder::new(&p);
        d.required::<String>(&None, "userName");
        d.check_length("path", "x", 1, Some(2), None);
        let err = d.finish().unwrap_err();
        assert_eq!(err.code, "ValidationError");
        assert_eq!(
            err.message,
            "2 validation errors detected: Value null at 'userName' failed to satisfy constraint: Member must not be null; Value 'x' at 'path' failed to satisfy constraint: Member must have length greater than or equal to 2"
        );
    }

    #[test]
    fn form_plus_is_space() {
        let mut p = Params::new();
        p.extend_from_urlencoded(b"A=a+b%2Bc");
        assert_eq!(p.get("A"), Some("a b+c"));
    }
}

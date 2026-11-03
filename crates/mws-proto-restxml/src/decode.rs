use chrono::{DateTime, NaiveDateTime, Utc};
use mws_core::{ServiceError, Validator};
use roxmltree::Node;

use mws_xml::roxmltree;

/// Parses scalars out of labels, query values, headers and XML text while
/// collecting validation errors. Constraint checks come from the shared
/// [`Validator`] it derefs to.
#[derive(Debug, Default)]
pub struct Decoder {
    validator: Validator,
}

impl std::ops::Deref for Decoder {
    type Target = Validator;
    fn deref(&self) -> &Validator {
        &self.validator
    }
}

impl std::ops::DerefMut for Decoder {
    fn deref_mut(&mut self) -> &mut Validator {
        &mut self.validator
    }
}

impl Decoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn finish(self, code: &'static str) -> Result<(), ServiceError> {
        self.validator.finish(code)
    }

    pub fn string(&mut self, raw: Option<&str>) -> Option<String> {
        raw.map(str::to_string)
    }

    pub fn boolean(&mut self, raw: Option<&str>, path: &str) -> Option<bool> {
        let raw = raw?.trim();
        match raw {
            "true" => Some(true),
            "false" => Some(false),
            _ => {
                self.validator.invalid(path, raw, "boolean");
                None
            }
        }
    }

    pub fn number<T: std::str::FromStr>(&mut self, raw: Option<&str>, path: &str) -> Option<T> {
        let raw = raw?.trim();
        match raw.parse::<T>() {
            Ok(v) => Some(v),
            Err(_) => {
                self.validator.invalid(path, raw, "number");
                None
            }
        }
    }

    /// ISO 8601 (the restXml default), HTTP dates (headers) and epoch seconds.
    pub fn timestamp(&mut self, raw: Option<&str>, path: &str) -> Option<DateTime<Utc>> {
        let raw = raw?.trim();
        if let Ok(t) = DateTime::parse_from_rfc3339(raw) {
            return Some(t.with_timezone(&Utc));
        }
        if let Ok(t) = NaiveDateTime::parse_from_str(raw, "%Y-%m-%dT%H:%M:%S") {
            return Some(t.and_utc());
        }
        if let Ok(t) = DateTime::parse_from_rfc2822(raw) {
            return Some(t.with_timezone(&Utc));
        }
        if let Ok(secs) = raw.parse::<f64>() {
            if let Some(t) = DateTime::from_timestamp_millis((secs * 1000.0) as i64) {
                return Some(t);
            }
        }
        self.validator.invalid(path, raw, "timestamp");
        None
    }

    pub fn blob(&mut self, raw: Option<&str>, path: &str) -> Option<Vec<u8>> {
        use base64::Engine;
        let raw = raw?.trim();
        match base64::engine::general_purpose::STANDARD.decode(raw) {
            Ok(v) => Some(v),
            Err(_) => {
                self.validator.invalid(path, raw, "base64 blob");
                None
            }
        }
    }
}

/// The first child element of `node` with local name `name`.
pub fn child<'a, 'i>(node: Node<'a, 'i>, name: &str) -> Option<Node<'a, 'i>> {
    node.children().find(|c| c.is_element() && c.tag_name().name() == name)
}

/// Every child element of `node` with local name `name` (flattened lists).
pub fn children<'a, 'i>(node: Node<'a, 'i>, name: &str) -> Vec<Node<'a, 'i>> {
    node.children().filter(|c| c.is_element() && c.tag_name().name() == name).collect()
}

/// Every child element of `node` (wrapped list items).
pub fn elements<'a, 'i>(node: Node<'a, 'i>) -> Vec<Node<'a, 'i>> {
    node.children().filter(Node::is_element).collect()
}

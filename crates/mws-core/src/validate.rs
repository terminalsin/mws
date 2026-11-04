//! Smithy constraint checks with AWS's validation-error wording, shared by
//! every protocol runtime.

use crate::ServiceError;

/// Collects constraint violations while a request is decoded, then turns
/// them into one AWS-style validation error.
///
/// Messages follow AWS: `1 validation error detected: Value 'x' at 'userName'
/// failed to satisfy constraint: Member must have length greater than or
/// equal to 2`.
#[derive(Debug, Default)]
pub struct Validator {
    errors: Vec<String>,
}

impl Validator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn has_errors(&self) -> bool {
        !self.errors.is_empty()
    }

    pub fn push_error(&mut self, message: String) {
        self.errors.push(message);
    }

    /// Turn collected errors into a validation error with the protocol's
    /// error code (`ValidationError`, `InvalidInput`, `ValidationException`).
    pub fn finish(self, code: &'static str) -> Result<(), ServiceError> {
        if self.errors.is_empty() {
            return Ok(());
        }
        let n = self.errors.len();
        let noun = if n == 1 { "error" } else { "errors" };
        Err(ServiceError::client(code, 400, format!("{n} validation {noun} detected: {}", self.errors.join("; "))))
    }

    /// A value that could not be parsed as the modeled type.
    pub fn invalid(&mut self, path: &str, raw: &str, kind: &str) {
        self.errors
            .push(format!("Value '{raw}' at '{path}' failed to satisfy constraint: Member must be a valid {kind}"));
    }

    pub fn required<T>(&mut self, value: &Option<T>, path: &str) {
        if value.is_none() {
            self.errors.push(format!("Value null at '{path}' failed to satisfy constraint: Member must not be null"));
        }
    }

    pub fn check_length(&mut self, path: &str, shown: &str, len: usize, min: Option<u64>, max: Option<u64>) {
        self.length(&format!("Value '{shown}' at '{path}'"), len, min, max);
    }

    /// `check_length` for a `@sensitive` member: AWS leaves the value out
    /// (`Value at 'plaintext' failed to satisfy constraint: ...`).
    pub fn check_length_redacted(&mut self, path: &str, len: usize, min: Option<u64>, max: Option<u64>) {
        self.length(&format!("Value at '{path}'"), len, min, max);
    }

    fn length(&mut self, subject: &str, len: usize, min: Option<u64>, max: Option<u64>) {
        let len = len as u64;
        if let Some(min) = min {
            if len < min {
                self.errors.push(format!(
                    "{subject} failed to satisfy constraint: Member must have length greater than or equal to {min}"
                ));
            }
        }
        if let Some(max) = max {
            if len > max {
                self.errors.push(format!(
                    "{subject} failed to satisfy constraint: Member must have length less than or equal to {max}"
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

    pub fn check_pattern(&mut self, path: &str, value: &str, re: &regex::Regex, pattern: &str) {
        if !re.is_match(value) {
            self.errors.push(format!(
                "Value '{value}' at '{path}' failed to satisfy constraint: Member must satisfy regular expression pattern: {pattern}"
            ));
        }
    }

    /// `check_pattern` for a `@sensitive` member, which AWS leaves out of
    /// the message.
    pub fn check_pattern_redacted(&mut self, path: &str, value: &str, re: &regex::Regex, pattern: &str) {
        if !re.is_match(value) {
            self.errors.push(format!(
                "Value at '{path}' failed to satisfy constraint: Member must satisfy regular expression pattern: {pattern}"
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
    fn sensitive_values_are_left_out() {
        let mut v = Validator::new();
        v.check_length_redacted("plaintext", 4097, Some(1), Some(4096));
        let e = v.finish("ValidationException").unwrap_err();
        assert_eq!(
            e.message,
            "1 validation error detected: Value at 'plaintext' failed to satisfy constraint: Member must have length less than or equal to 4096"
        );
    }

    #[test]
    fn validation_message_matches_aws() {
        let mut v = Validator::new();
        v.required::<String>(&None, "userName");
        v.check_length("path", "x", 1, Some(2), None);
        let err = v.finish("ValidationError").unwrap_err();
        assert_eq!(err.code, "ValidationError");
        assert_eq!(
            err.message,
            "2 validation errors detected: Value null at 'userName' failed to satisfy constraint: Member must not be null; Value 'x' at 'path' failed to satisfy constraint: Member must have length greater than or equal to 2"
        );
    }
}

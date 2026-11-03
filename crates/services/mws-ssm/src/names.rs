//! Parameter names, ARNs, selectors, labels and pagination tokens.

use base64::Engine;
use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::errors;

/// The prefix of Secrets Manager references.
pub const SECRETS_PREFIX: &str = "/aws/reference/secretsmanager/";

pub fn now(ctx: &RequestContext) -> DateTime<Utc> {
    ctx.received_at
}

/// How Parameter Store keys a name: a leading slash is optional for names
/// outside a hierarchy (`foo` and `/foo` are the same parameter).
pub fn key(name: &str) -> String {
    match name.strip_prefix('/') {
        Some(rest) if !rest.contains('/') => rest.to_string(),
        _ => name.to_string(),
    }
}

/// The name with a leading slash, for path matching.
pub fn rooted(name: &str) -> String {
    format!("/{}", name.trim_start_matches('/'))
}

/// A version or label after `:` in a name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selector {
    Version(i64),
    Label(String),
}

impl Selector {
    fn parse(s: &str) -> Selector {
        match s.parse::<i64>() {
            Ok(v) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => Selector::Version(v),
            _ => Selector::Label(s.to_string()),
        }
    }

    pub fn text(&self) -> String {
        match self {
            Selector::Version(v) => format!(":{v}"),
            Selector::Label(l) => format!(":{l}"),
        }
    }
}

/// A parameter addressed by name or ARN, resolved to its account and Region.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParamRef {
    pub partition: String,
    pub account: String,
    pub region: String,
    pub name: String,
    pub selector: Option<Selector>,
    /// Whether the caller named it by ARN (responses then name it so too).
    pub by_arn: bool,
}

impl ParamRef {
    /// A parameter in the caller's account and Region.
    pub fn own(ctx: &RequestContext, name: &str) -> ParamRef {
        ParamRef {
            partition: ctx.partition.clone(),
            account: ctx.caller.account_id.clone(),
            region: ctx.region.clone(),
            name: name.to_string(),
            selector: None,
            by_arn: false,
        }
    }

    /// Parse a name or ARN, with an optional `:version` or `:label`.
    /// `None` when it can't name any parameter.
    pub fn parse(ctx: &RequestContext, input: &str) -> Option<ParamRef> {
        let input = input.trim();
        let (mut r, rest) = if let Some(arn) = input.strip_prefix("arn:") {
            let parts: Vec<&str> = arn.splitn(5, ':').collect();
            if parts.len() != 5 || parts[1] != "ssm" {
                return None;
            }
            let resource = parts[4].strip_prefix("parameter/")?;
            let r = ParamRef {
                partition: parts[0].to_string(),
                account: parts[3].to_string(),
                region: parts[2].to_string(),
                name: String::new(),
                selector: None,
                by_arn: true,
            };
            let rest = if resource.split(':').next().unwrap_or("").contains('/') {
                format!("/{resource}")
            } else {
                resource.to_string()
            };
            (r, rest)
        } else {
            (ParamRef::own(ctx, ""), input.to_string())
        };
        let mut pieces = rest.split(':');
        r.name = pieces.next().unwrap_or_default().to_string();
        if let Some(sel) = pieces.next() {
            r.selector = Some(Selector::parse(sel));
        }
        if pieces.next().is_some() || r.name.is_empty() {
            return None;
        }
        Some(r)
    }

    pub fn key(&self) -> String {
        key(&self.name)
    }

    pub fn arn(&self) -> String {
        arn(&self.partition, &self.region, &self.account, &self.name)
    }

    /// The name responses show: the ARN when the caller used one.
    pub fn shown(&self) -> String {
        if self.by_arn {
            self.arn()
        } else {
            self.name.clone()
        }
    }
}

pub fn arn(partition: &str, region: &str, account: &str, name: &str) -> String {
    format!("arn:{partition}:ssm:{region}:{account}:parameter/{}", name.strip_prefix('/').unwrap_or(name))
}

fn reserved(first_segment: &str) -> bool {
    let l = first_segment.to_ascii_lowercase();
    l.starts_with("aws") || l.starts_with("ssm")
}

const PREFIX_MESSAGE: &str = "Parameter name: can't be prefixed with \"aws\" or \"ssm\" (case-insensitive).";
const PATH_MESSAGE: &str = "Parameter name: can't be prefixed with \"ssm\" (case-insensitive). If formed as a path, it can consist of sub-paths divided by slash symbol; each sub-path can be formed as a mix of letters, numbers and the following 3 symbols .-_";

/// Check a name for `PutParameter`.
pub fn validate_new_name(ctx: &RequestContext, name: &str) -> Result<(), ServiceError> {
    if name.starts_with("arn:") {
        return Err(errors::validation(
            "Parameter name: can't be an ARN. Use the parameter name itself, not its Amazon Resource Name (ARN).",
        ));
    }
    let is_path = name.starts_with('/') && name[1..].contains('/');
    if name.contains('/') && !name.starts_with('/') {
        return Err(errors::validation("Parameter name must be a fully qualified name."));
    }
    let first = name.trim_start_matches('/').split('/').next().unwrap_or("");
    if reserved(first) {
        if is_path && first.eq_ignore_ascii_case("aws") {
            return Err(ServiceError::client(
                "AccessDeniedException",
                400,
                format!("No access to reserved parameter name: {name}."),
            ));
        }
        return Err(errors::validation(if is_path { PATH_MESSAGE } else { PREFIX_MESSAGE }));
    }
    let valid_chars = name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'/'));
    if !valid_chars || name.contains("//") || (name.len() > 1 && name.ends_with('/')) || name == "/" {
        return Err(errors::validation(PATH_MESSAGE));
    }
    if name.matches('/').count() > 15 {
        return Err(errors::hierarchy_level_limit_exceeded(
            "A hierarchy can have a maximum of 15 levels. For more information, see Requirements and constraints for parameter names in the AWS Systems Manager User Guide.",
        ));
    }
    let prefix = arn(&ctx.partition, &ctx.region, &ctx.caller.account_id, "");
    if prefix.len() + name.trim_start_matches('/').len() > 1011 {
        return Err(errors::validation(format!(
            "Parameter name: the maximum length is 1011 characters, including the {} characters of the ARN prefix {prefix}.",
            prefix.len()
        )));
    }
    Ok(())
}

/// Check a path for `GetParametersByPath` and `Path` filters.
pub fn validate_path(path: &str) -> Result<(), ServiceError> {
    let ok = path.starts_with('/')
        && !path.contains("//")
        && path.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'/'));
    if !ok {
        return Err(errors::validation(
            "The parameter doesn't meet the parameter name requirements. The parameter name must begin with a forward slash \"/\". It can't be prefixed with \"aws\" or \"ssm\" (case-insensitive). It must use only letters, numbers, or the following symbols: . (period), - (hyphen), _ (underscore). Special characters are not allowed. All sub-paths, if specified, must use the forward slash symbol \"/\". Valid example: /get/parameters2-/by1./path0_.",
        ));
    }
    Ok(())
}

/// Whether `name` sits under `path`, directly or (recursively) deeper.
pub fn under_path(name: &str, path: &str, recursive: bool) -> bool {
    let name = rooted(name);
    let prefix = if path == "/" { "/".to_string() } else { format!("{}/", path.trim_end_matches('/')) };
    match name.strip_prefix(&prefix) {
        Some(rest) => !rest.is_empty() && (recursive || !rest.contains('/')),
        None => false,
    }
}

/// Whether a label is one Parameter Store accepts.
pub fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 100
        && !label.as_bytes()[0].is_ascii_digit()
        && !reserved(label)
        && label.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

pub fn not_found(name: &str) -> ServiceError {
    errors::parameter_not_found(format!("Parameter {name} not found."))
}

pub fn version_not_found(name: &str, version: &str) -> ServiceError {
    errors::parameter_version_not_found(format!(
        "Systems Manager could not find version {version} of {name}. Verify the version and try again."
    ))
}

/// Conditions for tags in a request (`aws:RequestTag/*`, `aws:TagKeys`).
pub fn request_tag_conditions<'a>(tags: impl IntoIterator<Item = (&'a String, &'a String)>) -> ConditionContext {
    let mut c = ConditionContext::new();
    let mut keys = Vec::new();
    for (k, v) in tags {
        c.insert(format!("aws:RequestTag/{k}"), vec![v.clone()]);
        keys.push(k.clone());
    }
    c.insert("aws:TagKeys".into(), keys);
    c
}

/// Conditions for a resource's tags (`aws:ResourceTag/*`).
pub fn resource_tag_conditions<'a>(tags: impl IntoIterator<Item = (&'a String, &'a String)>) -> ConditionContext {
    tags.into_iter().map(|(k, v)| (format!("aws:ResourceTag/{k}"), vec![v.clone()])).collect()
}

// ---- pagination -------------------------------------------------------------

fn encode_token(offset: usize) -> String {
    base64::engine::general_purpose::STANDARD.encode(format!("mws-ssm:{offset}"))
}

fn decode_token(token: &str) -> Option<usize> {
    let raw = base64::engine::general_purpose::STANDARD.decode(token).ok()?;
    String::from_utf8(raw).ok()?.strip_prefix("mws-ssm:")?.parse().ok()
}

/// One page of `items` starting at `token`, and the token for the next.
pub fn page<T>(items: Vec<T>, token: Option<&str>, limit: usize) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match token.filter(|t| !t.is_empty()) {
        Some(t) => decode_token(t).ok_or_else(|| errors::invalid_next_token("The specified token isn't valid."))?,
        None => 0,
    };
    let start = start.min(items.len());
    let end = (start + limit.max(1)).min(items.len());
    let next = (end < items.len()).then(|| encode_token(end));
    Ok((items.into_iter().skip(start).take(end - start).collect(), next))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_and_paths() {
        assert_eq!(key("/foo"), "foo");
        assert_eq!(key("foo"), "foo");
        assert_eq!(key("/a/b"), "/a/b");
        assert!(under_path("/a/b", "/a", false));
        assert!(under_path("/a/b", "/a/", false));
        assert!(!under_path("/a/b/c", "/a", false));
        assert!(under_path("/a/b/c", "/a", true));
        assert!(under_path("foo", "/", false));
        assert!(!under_path("/a", "/a", true));
        assert!(!under_path("/ab/c", "/a", true));
    }

    #[test]
    fn labels() {
        assert!(valid_label("prod"));
        assert!(valid_label("Prod-1.x_y"));
        assert!(!valid_label("1prod"));
        assert!(!valid_label("awsprod"));
        assert!(!valid_label("SSMx"));
        assert!(!valid_label("a b"));
    }
}

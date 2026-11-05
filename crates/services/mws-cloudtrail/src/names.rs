//! ARNs, names and the checks AWS applies to them.

use mws_core::{RequestContext, ServiceError};

use crate::generated::errors;

pub fn trail_arn(ctx: &RequestContext, region: &str, account: &str, name: &str) -> String {
    format!("arn:{}:cloudtrail:{region}:{account}:trail/{name}", ctx.partition)
}

pub fn eds_arn(ctx: &RequestContext, id: &str) -> String {
    format!("arn:{}:cloudtrail:{}:{}:eventdatastore/{id}", ctx.partition, ctx.region, ctx.caller.account_id)
}

pub fn channel_arn(ctx: &RequestContext, id: &str) -> String {
    format!("arn:{}:cloudtrail:{}:{}:channel/{id}", ctx.partition, ctx.region, ctx.caller.account_id)
}

pub fn dashboard_arn(ctx: &RequestContext, name: &str) -> String {
    format!("arn:{}:cloudtrail:{}:{}:dashboard/{name}", ctx.partition, ctx.region, ctx.caller.account_id)
}

/// A parsed CloudTrail ARN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arn {
    pub region: String,
    pub account: String,
    /// `trail`, `eventdatastore`, `channel` or `dashboard`.
    pub kind: String,
    pub name: String,
}

pub fn parse_arn(arn: &str) -> Option<Arn> {
    let parts: Vec<&str> = arn.splitn(6, ':').collect();
    if parts.len() != 6 || parts[0] != "arn" || parts[2] != "cloudtrail" {
        return None;
    }
    let (kind, name) = parts[5].split_once('/')?;
    if parts[3].is_empty() || parts[4].len() != 12 || name.is_empty() {
        return None;
    }
    Some(Arn { region: parts[3].into(), account: parts[4].into(), kind: kind.into(), name: name.into() })
}

/// Check a trail name as `CreateTrail` does.
pub fn validate_trail_name(name: &str) -> Result<(), ServiceError> {
    let invalid = |m: String| Err(errors::invalid_trail_name(m));
    let len = name.chars().count();
    if len < 3 {
        return invalid(format!(
            "Trail name too short. Minimum allowed length: 3 characters. Specified name length: {len} characters."
        ));
    }
    if len > 128 {
        return invalid(format!(
            "Trail name too long. Maximum allowed length: 128 characters. Specified name length: {len} characters."
        ));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')) {
        return invalid(
            "Trail name or ARN can only contain uppercase letters, lowercase letters, numbers, periods (.), hyphens (-), and underscores (_)."
                .into(),
        );
    }
    if !name.starts_with(|c: char| c.is_ascii_alphanumeric()) {
        return invalid("Trail name must starts with a letter or number.".into());
    }
    if !name.ends_with(|c: char| c.is_ascii_alphanumeric()) {
        return invalid("Trail name must ends with a letter or number.".into());
    }
    let b = name.as_bytes();
    if b.windows(2).any(|w| matches!(w[0], b'.' | b'-' | b'_') && matches!(w[1], b'.' | b'-' | b'_')) {
        return invalid(
            "Trail name cannot have adjacent periods, underscores or dashes. Examples: \"my-_namespace\" and \"my--namespace\" are invalid."
                .into(),
        );
    }
    if name.split('.').count() == 4 && name.split('.').all(|p| p.parse::<u8>().is_ok()) {
        return invalid("Trail name cannot be formatted as an IP address.".into());
    }
    Ok(())
}

/// Check a Lake resource name (event data stores, channels, dashboards).
pub fn validate_lake_name(name: &str, what: &str) -> Result<(), ServiceError> {
    let len = name.chars().count();
    let ok = (3..=128).contains(&len)
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        && name.starts_with(|c: char| c.is_ascii_alphanumeric());
    if ok {
        Ok(())
    } else {
        Err(errors::invalid_parameter(format!(
            "{what} name must be between 3 and 128 characters, start with a letter or number, and contain only letters, numbers, periods, underscores and hyphens."
        )))
    }
}

pub fn not_found_trail(arn: &str, account: &str) -> ServiceError {
    errors::trail_not_found(format!("Unknown trail: {arn} for the user: {account}"))
}

/// A page of `items` from `token` (an index), and the next token.
pub fn page<T: Clone>(items: &[T], token: Option<&str>, max: usize) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match token {
        None | Some("") => 0,
        Some(t) => t
            .strip_prefix("mws-")
            .and_then(|n| n.parse::<usize>().ok())
            .filter(|n| *n <= items.len())
            .ok_or_else(|| errors::invalid_next_token("Invalid NextToken."))?,
    };
    let end = (start + max.max(1)).min(items.len());
    let next = (end < items.len()).then(|| format!("mws-{end}"));
    Ok((items[start..end].to_vec(), next))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trail_names() {
        assert!(validate_trail_name("my-trail.1_a").is_ok());
        assert_eq!(validate_trail_name("ab").unwrap_err().code, "InvalidTrailNameException");
        assert!(validate_trail_name("-ab").is_err());
        assert!(validate_trail_name("a--b").is_err());
        assert!(validate_trail_name("a b c").is_err());
        assert!(validate_trail_name("10.0.0.1").is_err());
    }

    #[test]
    fn arns() {
        let a = parse_arn("arn:aws:cloudtrail:us-east-1:123456789012:trail/t1").unwrap();
        assert_eq!((a.region.as_str(), a.kind.as_str(), a.name.as_str()), ("us-east-1", "trail", "t1"));
        assert!(parse_arn("t1").is_none());
    }
}

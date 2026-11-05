//! Identifiers, ARNs, errors, filters and paging shared by the operations.

use mws_core::{ConditionContext, RequestContext, ServiceError};
use sha2::{Digest, Sha256};

use crate::generated::types as t;

pub fn invalid_parameter(message: impl Into<String>) -> ServiceError {
    ServiceError::client("InvalidParameterValue", 400, message)
}

pub fn invalid_combination(message: impl Into<String>) -> ServiceError {
    ServiceError::client("InvalidParameterCombination", 400, message)
}

pub fn missing(name: &str) -> ServiceError {
    invalid_parameter(format!("The parameter {name} must be provided and must not be blank."))
}

/// The account a request works in.
pub fn account_of(ctx: &RequestContext) -> String {
    match ctx.caller.account_id.as_str() {
        "" => "000000000000".to_string(),
        a => a.to_string(),
    }
}

/// `arn:<partition>:rds:<region>:<account>:<kind>:<name>`.
pub fn arn(ctx: &RequestContext, kind: &str, name: &str) -> String {
    format!("arn:{}:rds:{}:{}:{kind}:{name}", ctx.partition, ctx.region, account_of(ctx))
}

/// The parts of an RDS ARN: (region, account, kind, name).
pub fn parse_arn(arn: &str) -> Option<(String, String, String, String)> {
    let parts: Vec<&str> = arn.splitn(7, ':').collect();
    if parts.len() != 7 || parts[0] != "arn" || parts[2] != "rds" {
        return None;
    }
    Some((parts[3].to_string(), parts[4].to_string(), parts[5].to_string(), parts[6].to_string()))
}

/// A resource name or ARN, as the name. RDS accepts either for most
/// identifiers.
pub fn name_of(id_or_arn: &str) -> String {
    match parse_arn(id_or_arn) {
        Some((_, _, _, name)) => name,
        None => id_or_arn.to_string(),
    }
}

/// Check an instance, cluster or snapshot identifier and lower-case it, as
/// RDS stores identifiers.
pub fn identifier(param: &str, value: &str, max: usize) -> Result<String, ServiceError> {
    let v = value.to_ascii_lowercase();
    let ok = !v.is_empty()
        && v.len() <= max
        && v.starts_with(|c: char| c.is_ascii_alphabetic())
        && v.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !v.ends_with('-')
        && !v.contains("--");
    if ok {
        Ok(v)
    } else {
        Err(invalid_parameter(format!(
            "The parameter {param} is not a valid identifier. Identifiers must begin with a letter; must contain only ASCII letters, digits, and hyphens; and must not end with a hyphen or contain two consecutive hyphens."
        )))
    }
}

/// Group names (subnet, parameter and option groups) keep their case
/// rules: letters, digits, hyphens (and for subnet groups periods,
/// underscores and spaces).
pub fn group_name(param: &str, value: &str, extra: &[char]) -> Result<String, ServiceError> {
    let v = value.to_ascii_lowercase();
    let ok = !v.is_empty()
        && v.len() <= 255
        && v.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || extra.contains(&c))
        && !v.ends_with('-')
        && !v.contains("--");
    if ok {
        Ok(v)
    } else {
        Err(invalid_parameter(format!(
            "The parameter {param} is not a valid identifier. Identifiers must begin with a letter; must contain only ASCII letters, digits, and hyphens; and must not end with a hyphen or contain two consecutive hyphens."
        )))
    }
}

/// A stable lower-case base-36 string of `len` characters derived from
/// `seed` (the per-account-and-Region part of RDS endpoint names).
pub fn stable_token(seed: &str, len: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let digest = Sha256::digest(seed.as_bytes());
    digest.iter().cycle().take(len).map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char).collect()
}

/// A random upper-case resource id (`db-ABC...`, `cluster-...`).
pub fn resource_id(prefix: &str) -> String {
    use rand::Rng;
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    let s: String = (0..26).map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char).collect();
    format!("{prefix}{s}")
}

/// The host name suffix RDS gives endpoints in an account and Region:
/// `<token>.<region>.rds.amazonaws.com`.
pub fn endpoint_suffix(ctx: &RequestContext) -> String {
    let token = stable_token(&format!("{}/{}", account_of(ctx), ctx.region), 12);
    let domain = if ctx.region.starts_with("cn-") { "rds.amazonaws.com.cn" } else { "rds.amazonaws.com" };
    format!("{token}.{}.{domain}", ctx.region)
}

/// Route 53 hosted zone of RDS endpoints in a Region.
pub fn hosted_zone_id(region: &str) -> &'static str {
    match region {
        "us-east-1" => "Z2R2ITUGPM61AM",
        "us-east-2" => "Z2XHWR1WZ565X2",
        "us-west-1" => "Z10WI91S59XXQN",
        "us-west-2" => "Z1PVIF0B656C1W",
        "eu-west-1" => "Z29XKXDKYMONMX",
        "eu-west-2" => "Z1TTGA775OQIYO",
        "eu-central-1" => "Z1RLNUO7B9Q6NB",
        "ap-southeast-1" => "Z2G0U3KFCY8NZ5",
        "ap-southeast-2" => "Z32T0VRHXEXS0V",
        "ap-northeast-1" => "Z24O6O9L7SGTNB",
        _ => "Z2R2ITUGPM61AM",
    }
}

/// Availability zones of a Region (`a`, `b`, `c`, ...), as EC2 names them.
pub fn zones(region: &str) -> Vec<String> {
    let n = match region {
        "us-east-1" => 6,
        "us-west-1" => 2,
        _ => 3,
    };
    (0..n).map(|i| format!("{region}{}", (b'a' + i as u8) as char)).collect()
}

/// A deterministic 30-minute window `hh:mm-hh:mm` (backups) or
/// `ddd:hh:mm-ddd:hh:mm` (maintenance) for `seed`, as RDS picks them.
pub fn backup_window(seed: &str) -> String {
    let h = Sha256::digest(seed.as_bytes());
    let start = (h[0] as u32 % 48) * 30;
    let end = start + 30;
    format!("{:02}:{:02}-{:02}:{:02}", start / 60 % 24, start % 60, end / 60 % 24, end % 60)
}

pub fn maintenance_window(seed: &str) -> String {
    const DAYS: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
    let h = Sha256::digest(seed.as_bytes());
    let day = DAYS[h[1] as usize % 7];
    let start = (h[2] as u32 % 48) * 30;
    let end = start + 30;
    let end_day = if end >= 24 * 60 { DAYS[(h[1] as usize + 1) % 7] } else { day };
    format!("{day}:{:02}:{:02}-{end_day}:{:02}:{:02}", start / 60, start % 60, end / 60 % 24, end % 60)
}

/// Validate a `hh24:mi-hh24:mi` backup window.
pub fn check_backup_window(w: &str) -> Result<(), ServiceError> {
    let ok = w.len() == 11
        && w.split('-').all(|p| {
            let mut it = p.split(':');
            matches!((it.next().and_then(|h| h.parse::<u32>().ok()), it.next().and_then(|m| m.parse::<u32>().ok())),
                (Some(h), Some(m)) if h < 24 && m < 60)
        });
    if ok {
        Ok(())
    } else {
        Err(invalid_parameter("The backup window must be in the format hh24:mi-hh24:mi."))
    }
}

/// Validate a `ddd:hh24:mi-ddd:hh24:mi` maintenance window.
pub fn check_maintenance_window(w: &str) -> Result<String, ServiceError> {
    let w = w.to_ascii_lowercase();
    let ok = w.split('-').count() == 2
        && w.split('-').all(|p| {
            let f: Vec<&str> = p.split(':').collect();
            f.len() == 3
                && ["sun", "mon", "tue", "wed", "thu", "fri", "sat"].contains(&f[0])
                && f[1].parse::<u32>().is_ok_and(|h| h < 24)
                && f[2].parse::<u32>().is_ok_and(|m| m < 60)
        });
    if ok {
        Ok(w)
    } else {
        Err(invalid_parameter("Invalid maintenance window format: must be in the format ddd:hh24:mi-ddd:hh24:mi"))
    }
}

// ---- tags --------------------------------------------------------------

/// Tags from `Tags` and `TagSpecifications` (whose resource type must be
/// `kind`).
pub fn tags_from(tags: &Option<Vec<t::Tag>>) -> Result<Vec<t::Tag>, ServiceError> {
    let tags = tags.clone().unwrap_or_default();
    check_tags(&tags)?;
    Ok(tags)
}

pub fn check_tags(tags: &[t::Tag]) -> Result<(), ServiceError> {
    for tag in tags {
        let key = tag.key.as_deref().unwrap_or_default();
        if key.is_empty() || key.len() > 128 {
            return Err(invalid_parameter("Tag keys must be between 1 and 128 characters in length."));
        }
        if key.to_ascii_lowercase().starts_with("aws:") || key.to_ascii_lowercase().starts_with("rds:") {
            return Err(invalid_parameter("Tag keys cannot start with 'aws:' or 'rds:'."));
        }
        if tag.value.as_deref().unwrap_or_default().len() > 256 {
            return Err(invalid_parameter("Tag values must be between 0 and 256 characters in length."));
        }
    }
    if tags.len() > 50 {
        return Err(ServiceError::client("TagQuotaPerResource", 400, "Cannot add more than 50 tags to a resource."));
    }
    Ok(())
}

/// Merge `add` into `tags` (same key replaces).
pub fn merge_tags(tags: &mut Vec<t::Tag>, add: &[t::Tag]) {
    for tag in add {
        match tags.iter_mut().find(|t| t.key == tag.key) {
            Some(t) => t.value = tag.value.clone(),
            None => tags.push(tag.clone()),
        }
    }
}

/// `aws:RequestTag/*` and `aws:TagKeys` for tags in a request.
pub fn request_tag_context(tags: &[t::Tag]) -> ConditionContext {
    let mut c = ConditionContext::new();
    for tag in tags {
        if let Some(k) = &tag.key {
            c.insert(format!("aws:RequestTag/{k}"), vec![tag.value.clone().unwrap_or_default()]);
            c.insert(format!("rds:req-tag/{k}"), vec![tag.value.clone().unwrap_or_default()]);
        }
    }
    if !tags.is_empty() {
        c.insert("aws:TagKeys".into(), tags.iter().filter_map(|t| t.key.clone()).collect());
    }
    c
}

/// `aws:ResourceTag/*` and the `rds:<kind>-tag/*` keys for an existing
/// resource.
pub fn resource_tag_context(kind: &str, tags: &Option<Vec<t::Tag>>) -> ConditionContext {
    let mut c = ConditionContext::new();
    for tag in tags.iter().flatten() {
        if let Some(k) = &tag.key {
            let v = vec![tag.value.clone().unwrap_or_default()];
            c.insert(format!("aws:ResourceTag/{k}"), v.clone());
            c.insert(format!("rds:{kind}-tag/{k}"), v);
        }
    }
    c
}

// ---- filters and paging -------------------------------------------------

/// `Filters` of a Describe call, checked against the names it supports.
pub struct Filters(Vec<(String, Vec<String>)>);

impl Filters {
    pub fn new(filters: &Option<Vec<t::Filter>>, supported: &[&str]) -> Result<Self, ServiceError> {
        let mut out = Vec::new();
        for f in filters.iter().flatten() {
            if !supported.contains(&f.name.as_str()) {
                return Err(invalid_parameter(format!("Unrecognized filter name: {}", f.name)));
            }
            if f.values.is_empty() {
                return Err(invalid_parameter(format!("Filter {} must have at least one value.", f.name)));
            }
            out.push((f.name.clone(), f.values.clone()));
        }
        Ok(Self(out))
    }

    /// Whether every filter matches: `value(name)` gives the item's values
    /// for a filter.
    pub fn matches(&self, value: impl Fn(&str) -> Vec<String>) -> bool {
        self.0.iter().all(|(name, wanted)| {
            let have = value(name);
            wanted.iter().any(|w| have.iter().any(|h| h == w || name_of(w) == *h))
        })
    }
}

pub fn opt(v: &Option<String>) -> Vec<String> {
    v.iter().cloned().collect()
}

/// One page of `items` from `marker`, `max_records` (20 to 100, default
/// 100) at a time. Returns the page and the next marker.
pub fn paginate<T: Clone>(
    items: Vec<T>,
    marker: &Option<String>,
    max_records: Option<i32>,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let max = match max_records {
        None => 100,
        Some(m) if (20..=100).contains(&m) => m as usize,
        Some(m) => {
            return Err(invalid_parameter(format!("Invalid value {m} for MaxRecords. Must be between 20 and 100")))
        }
    };
    let start = match marker {
        None => 0,
        Some(m) => m.parse::<usize>().map_err(|_| invalid_parameter(format!("Invalid marker: {m}")))?,
    };
    let page: Vec<T> = items.iter().skip(start).take(max).cloned().collect();
    let next = (start + max < items.len()).then(|| (start + max).to_string());
    Ok((page, next))
}

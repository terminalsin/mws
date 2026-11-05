//! ARNs, ids, addresses, pagination and the other small things every
//! operation needs.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};
use rand::Rng;

use crate::state::{region_key, Region, State};

pub fn arn(ctx: &RequestContext, resource: &str) -> String {
    arn_in(&ctx.partition, &ctx.region, &ctx.caller.account_id, resource)
}

pub fn arn_in(partition: &str, region: &str, account: &str, resource: &str) -> String {
    format!("arn:{partition}:ses:{region}:{account}:{resource}")
}

pub fn identity_arn(ctx: &RequestContext, identity: &str) -> String {
    arn(ctx, &format!("identity/{identity}"))
}

/// The caller's state in the request's Region.
pub fn region<'a>(st: &'a mut State, ctx: &RequestContext) -> &'a mut Region {
    st.regions.entry(region_key(&ctx.caller.account_id, &ctx.region)).or_default()
}

/// The caller's state in the request's Region, if any.
pub fn region_ref<'a>(st: &'a State, ctx: &RequestContext) -> Option<&'a Region> {
    st.regions.get(&region_key(&ctx.caller.account_id, &ctx.region))
}

/// `ses:ApiVersion` and nothing else.
pub fn api_version(v: &str) -> ConditionContext {
    let mut c = ConditionContext::new();
    c.insert("ses:ApiVersion".into(), vec![v.into()]);
    c
}

pub fn authorize(ctx: &RequestContext, version: &str, action: &str, resource: &str) -> Result<(), ServiceError> {
    ctx.authorize(&format!("ses:{action}"), resource, api_version(version))
}

/// Authorize an action on a resource tagged `tags`.
pub fn authorize_tagged(
    ctx: &RequestContext,
    version: &str,
    action: &str,
    resource: &str,
    tags: &BTreeMap<String, String>,
) -> Result<(), ServiceError> {
    let mut c = api_version(version);
    for (k, v) in tags {
        c.insert(format!("aws:ResourceTag/{k}"), vec![v.clone()]);
    }
    ctx.authorize(&format!("ses:{action}"), resource, c)
}

/// Authorize creating a resource with `tags`.
pub fn authorize_create(
    ctx: &RequestContext,
    action: &str,
    resource: &str,
    tags: &[(String, String)],
) -> Result<(), ServiceError> {
    let mut c = api_version("2");
    if !tags.is_empty() {
        c.insert("aws:TagKeys".into(), tags.iter().map(|(k, _)| k.clone()).collect());
        for (k, v) in tags {
            c.insert(format!("aws:RequestTag/{k}"), vec![v.clone()]);
        }
    }
    ctx.authorize(&format!("ses:{action}"), resource, c)
}

/// A message id in SES's shape:
/// `0100018c2e9d7a4b-3f1c8a52-7d4e-4b8f-9a61-2c5d0e7f8a91-000000`.
pub fn message_id(ctx: &RequestContext) -> String {
    format!(
        "0100{:012x}-{}-000000",
        ctx.received_at.timestamp_millis().max(0) as u64 & 0xffff_ffff_ffff,
        uuid::Uuid::new_v4()
    )
}

/// A lower-case token from SES's DKIM/verification alphabet.
pub fn token(len: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut rng = rand::thread_rng();
    (0..len).map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char).collect()
}

/// A base64-looking v1 domain verification token.
pub fn verification_token() -> String {
    use base64::Engine;
    let bytes: [u8; 32] = rand::thread_rng().gen();
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The address part of `Name <addr@domain>` or `addr@domain`.
pub fn bare_address(raw: &str) -> String {
    let raw = raw.trim();
    if let (Some(open), Some(close)) = (raw.rfind('<'), raw.rfind('>')) {
        if open < close {
            return raw[open + 1..close].trim().to_string();
        }
    }
    raw.trim_matches('"').to_string()
}

/// The display name of `Name <addr@domain>`, if any.
pub fn display_name(raw: &str) -> Option<String> {
    let raw = raw.trim();
    let open = raw.rfind('<')?;
    let name = raw[..open].trim().trim_matches('"').trim();
    (!name.is_empty()).then(|| name.to_string())
}

/// The domain of an address, lower-cased.
pub fn domain_of(address: &str) -> Option<String> {
    let addr = bare_address(address);
    let (_, domain) = addr.rsplit_once('@')?;
    (!domain.is_empty()).then(|| domain.to_ascii_lowercase())
}

/// Check an address the way SES does, with its error wording.
pub fn check_address(raw: &str) -> Result<(), String> {
    let addr = bare_address(raw);
    if addr.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("Local address contains control or whitespace".into());
    }
    let Some((local, domain)) = addr.rsplit_once('@') else {
        return Err("Missing final '@domain'".into());
    };
    if local.is_empty() {
        return Err("Missing local name".into());
    }
    if domain.is_empty() || domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return Err("Domain starts with dot".into());
    }
    if !domain.chars().all(|c| c.is_alphanumeric() || matches!(c, '-' | '.' | '[' | ']' | ':')) {
        return Err("Domain contains illegal character".into());
    }
    Ok(())
}

/// Whether `s` is a plausible domain name.
pub fn is_domain(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 253
        && !s.contains('@')
        && s.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.chars().all(|c| c.is_alphanumeric() || c == '-'))
}

/// Canonical identity name: domains lower-cased, addresses as given with
/// their domain lower-cased.
pub fn canonical_identity(s: &str) -> String {
    match s.rsplit_once('@') {
        Some((local, domain)) => format!("{local}@{}", domain.to_ascii_lowercase()),
        None => s.trim_end_matches('.').to_ascii_lowercase(),
    }
}

/// The mailbox simulator's domain.
pub const SIMULATOR_DOMAIN: &str = "simulator.amazonses.com";

pub fn is_simulator(address: &str) -> bool {
    domain_of(address).is_some_and(|d| d == SIMULATOR_DOMAIN)
}

/// A page of `items` after `token` (an index), and the next token.
pub fn paginate<T: Clone>(
    items: &[T],
    token: Option<&str>,
    max: Option<i32>,
    default: usize,
) -> (Vec<T>, Option<String>) {
    let start = token.and_then(|t| t.parse::<usize>().ok()).unwrap_or(0).min(items.len());
    let size = max.filter(|m| *m > 0).map(|m| m as usize).unwrap_or(default);
    let end = (start + size).min(items.len());
    let next = (end < items.len()).then(|| end.to_string());
    (items[start..end].to_vec(), next)
}

/// A next token SES will accept back: an index this API produced.
pub fn check_token(token: Option<&str>) -> Result<(), ServiceError> {
    match token {
        Some(t) if t.parse::<usize>().is_err() => {
            Err(crate::v2::errors::bad_request(format!("Invalid NextToken value: {t}")))
        }
        _ => Ok(()),
    }
}

pub fn tags_pairs(tags: Option<&[crate::v2::types::Tag]>) -> Vec<(String, String)> {
    tags.unwrap_or_default().iter().map(|t| (t.key.clone(), t.value.clone())).collect()
}

pub fn tag_list(tags: &BTreeMap<String, String>) -> Vec<crate::v2::types::Tag> {
    tags.iter().map(|(k, v)| crate::v2::types::Tag { key: k.clone(), value: v.clone() }).collect()
}

/// Validate v2 tags (at most 50, keys 1-128, values up to 256).
pub fn check_tags(tags: &[(String, String)]) -> Result<(), ServiceError> {
    if tags.len() > 50 {
        return Err(crate::v2::errors::bad_request("Too many tags. The maximum number of tags is 50."));
    }
    for (k, v) in tags {
        if k.is_empty() || k.len() > 128 || v.len() > 256 || k.starts_with("aws:") {
            return Err(crate::v2::errors::bad_request(format!("Invalid tag: {k}")));
        }
    }
    Ok(())
}

/// Names of configuration sets, templates, rule sets and the like: ASCII
/// letters, digits, `_` and `-`, at most 64 characters.
pub fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// v1 `InvalidParameterValue`.
pub fn invalid_parameter(message: impl Into<String>) -> ServiceError {
    ServiceError::client("InvalidParameterValue", 400, message)
}

/// The region in SES's error wording (`US-EAST-1`).
pub fn upper_region(ctx: &RequestContext) -> String {
    ctx.region.to_ascii_uppercase()
}

pub fn iso(t: chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

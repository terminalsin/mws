//! `ClientToken` idempotency. A create call that carries a client token
//! remembers the token, a fingerprint of its parameters and the resource it
//! made. Repeating the call with the same token and parameters returns that
//! resource; the same token with other parameters is
//! `IdempotentParameterMismatch`. Tokens are scoped to the account, Region
//! and operation.

use mws_core::ServiceError;
use serde::{Deserialize, Serialize};

use crate::state::RegionState;
use crate::util::err;

/// What a client token was used for.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TokenRecord {
    /// A hash of the request's parameters (without the token and `DryRun`).
    pub fingerprint: String,
    /// The resource (or reservation) the request made.
    pub resource_id: String,
}

/// The error AWS returns for a token reused with other parameters.
pub(crate) fn mismatch() -> ServiceError {
    err(
        "IdempotentParameterMismatch",
        "The request uses the same client token as a previous, but non-identical request. Do not reuse a client token with different requests, unless the requests are identical.",
    )
}

/// A stable fingerprint of a request's parameters, leaving out the client
/// token and `DryRun`.
pub(crate) fn fingerprint<T: Serialize>(input: &T) -> String {
    let mut v = serde_json::to_value(input).unwrap_or_default();
    if let Some(o) = v.as_object_mut() {
        o.remove("client_token");
        o.remove("dry_run");
    }
    // FNV-1a: stable across builds, so saved state keeps matching.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in v.to_string().bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{h:016x}")
}

fn key(op: &str, token: &str) -> String {
    format!("{op}/{token}")
}

fn token_of(token: Option<&str>) -> Option<&str> {
    token.filter(|t| !t.is_empty())
}

/// The resource an earlier `op` call with this token made, if any, as long
/// as `exists` still finds it. Fails when the token was used with other
/// parameters.
pub(crate) fn replay(
    r: &RegionState,
    op: &str,
    token: Option<&str>,
    fingerprint: &str,
    exists: impl Fn(&str) -> bool,
) -> Result<Option<String>, ServiceError> {
    let Some(token) = token_of(token) else { return Ok(None) };
    let Some(rec) = r.client_tokens.get(&key(op, token)) else { return Ok(None) };
    if rec.fingerprint != fingerprint {
        return Err(mismatch());
    }
    Ok(exists(&rec.resource_id).then(|| rec.resource_id.clone()))
}

/// Remember that `op` with this token made `resource_id`.
pub(crate) fn remember(r: &mut RegionState, op: &str, token: Option<&str>, fingerprint: &str, resource_id: &str) {
    if let Some(token) = token_of(token) {
        r.client_tokens.insert(
            key(op, token),
            TokenRecord { fingerprint: fingerprint.to_string(), resource_id: resource_id.to_string() },
        );
    }
}

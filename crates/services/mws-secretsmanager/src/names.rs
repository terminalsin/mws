//! ARNs, secret identifiers, condition keys and the errors most operations
//! share.

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use rand::Rng;

use crate::generated::errors;
use crate::state::{Secret, State};
use crate::SecretsManager;

pub const SERVICE_PRINCIPAL: &str = "secretsmanager.amazonaws.com";

/// The account a request acts in.
pub fn account_of(ctx: &RequestContext) -> String {
    if ctx.caller.account_id.is_empty() {
        "000000000000".into()
    } else {
        ctx.caller.account_id.clone()
    }
}

/// A new secret ARN: the name plus a hyphen and six random characters.
pub fn new_arn(partition: &str, region: &str, account: &str, name: &str) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::thread_rng();
    let suffix: String = (0..6).map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char).collect();
    format!("arn:{partition}:secretsmanager:{region}:{account}:secret:{name}-{suffix}")
}

/// The same secret's ARN in another Region (replicas keep the suffix).
pub fn arn_in_region(arn: &str, region: &str) -> String {
    let mut parts: Vec<&str> = arn.splitn(6, ':').collect();
    if parts.len() == 6 {
        parts[3] = region;
    }
    parts.join(":")
}

pub fn not_found() -> ServiceError {
    errors::resource_not_found("Secrets Manager can't find the specified secret.")
}

pub fn marked_for_deletion() -> ServiceError {
    errors::invalid_request("You can't perform this operation on the secret because it was marked for deletion.")
}

pub fn replica_read_only() -> ServiceError {
    errors::invalid_request(
        "Operation not permitted on a replica secret. Call must be made in primary secret's region.",
    )
}

/// A fresh version id (`ClientRequestToken`), as the SDKs generate them.
pub fn new_token() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// `LastAccessedDate` is kept to the day.
pub fn day(t: DateTime<Utc>) -> DateTime<Utc> {
    t.date_naive().and_hms_opt(0, 0, 0).expect("midnight exists").and_utc()
}

/// Find a secret by name, full ARN or partial ARN (the ARN without the
/// random suffix). Names resolve in the caller's account and Region.
pub fn resolve(st: &State, ctx: &RequestContext, secret_id: &str) -> Result<String, ServiceError> {
    if st.secrets.contains_key(secret_id) {
        return Ok(secret_id.to_string());
    }
    if let Some(rest) = secret_id.strip_prefix("arn:") {
        let parts: Vec<&str> = rest.splitn(5, ':').collect();
        if parts.len() != 5 || parts[1] != "secretsmanager" {
            return Err(not_found());
        }
        let (region, account) = (parts[2], parts[3]);
        let Some(name) = parts[4].strip_prefix("secret:") else { return Err(not_found()) };
        return st
            .secrets
            .values()
            .find(|s| s.account == account && s.region == region && s.name == name)
            .map(|s| s.arn.clone())
            .ok_or_else(not_found);
    }
    let account = account_of(ctx);
    st.secrets
        .values()
        .find(|s| s.account == account && s.region == ctx.region && s.name == secret_id)
        .map(|s| s.arn.clone())
        .ok_or_else(not_found)
}

/// The condition keys a secret contributes to every request on it.
pub fn resource_context(s: &Secret) -> ConditionContext {
    let mut c = ConditionContext::new();
    c.insert("secretsmanager:SecretId".into(), vec![s.arn.clone()]);
    c.insert("aws:ResourceAccount".into(), vec![s.account.clone()]);
    c.insert(
        "secretsmanager:SecretPrimaryRegion".into(),
        vec![s.primary_region.clone().unwrap_or_else(|| s.region.clone())],
    );
    if let Some(l) = &s.rotation.lambda_arn {
        c.insert("secretsmanager:resource/AllowRotationLambdaArn".into(), vec![l.clone()]);
    }
    for (k, v) in s.tag_map() {
        c.insert(format!("secretsmanager:ResourceTag/{k}"), vec![v.clone()]);
        c.insert(format!("aws:ResourceTag/{k}"), vec![v]);
    }
    c
}

/// `aws:RequestTag` and `aws:TagKeys` for tags in a request.
pub fn request_tag_context(tags: &[crate::generated::types::Tag]) -> ConditionContext {
    let mut c = ConditionContext::new();
    let mut keys = Vec::new();
    for t in tags {
        let k = t.key.clone().unwrap_or_default();
        c.insert(format!("aws:RequestTag/{k}"), vec![t.value.clone().unwrap_or_default()]);
        keys.push(k);
    }
    if !keys.is_empty() {
        c.insert("aws:TagKeys".into(), keys);
    }
    c
}

impl SecretsManager {
    /// Look up a secret and authorize `action` on it with its resource
    /// policy. Returns a snapshot; the state lock is not held.
    pub(crate) fn find(
        &self,
        ctx: &RequestContext,
        secret_id: &str,
        action: &str,
        extra: ConditionContext,
    ) -> Result<Secret, ServiceError> {
        let secret = {
            let st = self.lock();
            let arn = resolve(&st, ctx, secret_id)?;
            st.secrets[&arn].clone()
        };
        self.authorize(ctx, action, &secret, extra)?;
        Ok(secret)
    }

    pub(crate) fn authorize(
        &self,
        ctx: &RequestContext,
        action: &str,
        s: &Secret,
        extra: ConditionContext,
    ) -> Result<(), ServiceError> {
        let mut c = resource_context(s);
        c.extend(extra);
        ctx.authorize_with_resource_policy(action, &s.arn, s.policy.as_deref(), c)
    }

    /// Run `f` on the stored secret `arn` under the state lock.
    pub(crate) fn update<T>(
        &self,
        arn: &str,
        f: impl FnOnce(&mut Secret) -> Result<T, ServiceError>,
    ) -> Result<T, ServiceError> {
        let mut st = self.lock();
        let s = st.secrets.get_mut(arn).ok_or_else(not_found)?;
        f(s)
    }
}

/// A context for KMS calls about a secret in `region` (replicas use their
/// own Region's keys).
pub fn in_region(ctx: &RequestContext, region: &str) -> RequestContext {
    RequestContext { region: region.to_string(), ..ctx.clone() }
}

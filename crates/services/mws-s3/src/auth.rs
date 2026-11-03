//! Authorizing S3 requests: IAM identity policies and the bucket policy
//! (through the IAM authorizer), Block Public Access, and ACL grants.

use mws_core::{AuthzDecision, CallerKind, ConditionContext, RequestContext, ServiceError};
use mws_iam_policy::{Effect, Policy, PolicyKind};
use sha2::Digest;

use crate::acl::{self, Permission};
use crate::errors;
use crate::state::Bucket;
use crate::{AuthType, Call};

/// The canonical user id S3 reports for an account.
pub fn canonical_id(account_id: &str) -> String {
    hex::encode(sha2::Sha256::digest(format!("mws-s3-canonical-user:{account_id}").as_bytes()))
}

pub fn bucket_arn(ctx: &RequestContext, bucket: &str) -> String {
    format!("arn:{}:s3:::{bucket}", ctx.partition)
}

pub fn object_arn(ctx: &RequestContext, bucket: &str, key: &str) -> String {
    format!("arn:{}:s3:::{bucket}/{key}", ctx.partition)
}

/// What the request touches, for ACL fallbacks and error wording.
pub enum Resource<'a> {
    Bucket,
    Object { key: &'a str, grants: Option<&'a [crate::generated::types::Grant]> },
}

impl Call {
    /// Condition keys every S3 request carries.
    fn s3_context(&self, bucket: &Bucket) -> ConditionContext {
        let mut c = ConditionContext::new();
        let (auth, sig) = match self.auth {
            AuthType::Header => ("REST-HEADER", true),
            AuthType::Query { age_ms } => {
                c.insert("s3:signatureAge".into(), vec![age_ms.max(0).to_string()]);
                ("REST-QUERY-STRING", true)
            }
            AuthType::Anonymous => ("", false),
        };
        if sig {
            c.insert("s3:authType".into(), vec![auth.into()]);
            c.insert("s3:signatureversion".into(), vec!["AWS4-HMAC-SHA256".into()]);
        }
        if let Some(h) = &self.content_sha256 {
            c.insert("s3:x-amz-content-sha256".into(), vec![h.clone()]);
        }
        c.insert("s3:ResourceAccount".into(), vec![bucket.owner.clone()]);
        // Bucket ARNs carry no account: tell IAM whose bucket this is, so
        // cross-account requests need both identity and bucket policies.
        c.insert("aws:ResourceAccount".into(), vec![bucket.owner.clone()]);
        c
    }

    /// Authorize `action` (e.g. `s3:GetObject`) on `bucket` or one of its
    /// objects. Returns S3's AccessDenied on denial.
    pub fn authorize(
        &self,
        ctx: &RequestContext,
        action: &str,
        bucket: &Bucket,
        resource: Resource<'_>,
        extra: ConditionContext,
    ) -> Result<(), ServiceError> {
        if self.allowed(ctx, action, bucket, &resource, extra.clone()) {
            return Ok(());
        }
        let arn = match resource {
            Resource::Bucket => bucket_arn(ctx, &bucket.name),
            Resource::Object { key, .. } => object_arn(ctx, &bucket.name, key),
        };
        Err(self.denied(ctx, action, &arn, bucket, extra))
    }

    /// Whether `action` is allowed, without building an error.
    pub fn allowed(
        &self,
        ctx: &RequestContext,
        action: &str,
        bucket: &Bucket,
        resource: &Resource<'_>,
        extra: ConditionContext,
    ) -> bool {
        let arn = match resource {
            Resource::Bucket => bucket_arn(ctx, &bucket.name),
            Resource::Object { key, .. } => object_arn(ctx, &bucket.name, key),
        };
        let mut context = self.s3_context(bucket);
        context.extend(extra);
        let policy = self.effective_policy(ctx, bucket);
        match ctx.check(action, &arn, policy.as_deref(), mws_core::ResourcePolicyMode::Optional, context.clone()) {
            AuthzDecision::Allow => true,
            AuthzDecision::Deny { explicit: true, .. } => false,
            AuthzDecision::Deny { explicit: false, .. } => {
                if !self.acl_allows(ctx, action, bucket, resource) {
                    return false;
                }
                // An ACL grant to another account works like a bucket policy
                // naming that account: its identity policies must allow too.
                let cross_account = ctx.caller.kind != CallerKind::Anonymous && ctx.caller.account_id != bucket.owner;
                !cross_account || {
                    let grant = serde_json::json!({
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"AWS": format!("arn:{}:iam::{}:root", ctx.partition, ctx.caller.account_id)},
                            "Action": action,
                            "Resource": arn,
                        }]
                    })
                    .to_string();
                    matches!(
                        ctx.check(action, &arn, Some(&grant), mws_core::ResourcePolicyMode::Optional, context),
                        AuthzDecision::Allow
                    )
                }
            }
        }
    }

    fn denied(
        &self,
        ctx: &RequestContext,
        action: &str,
        arn: &str,
        bucket: &Bucket,
        extra: ConditionContext,
    ) -> ServiceError {
        if ctx.caller.kind == CallerKind::Anonymous {
            return errors::access_denied("Access Denied");
        }
        let mut context = self.s3_context(bucket);
        context.extend(extra);
        let policy = self.effective_policy(ctx, bucket);
        let reason = match ctx.check(action, arn, policy.as_deref(), mws_core::ResourcePolicyMode::Optional, context) {
            AuthzDecision::Deny { reason, .. } if !reason.is_empty() => format!(" {reason}"),
            _ => String::new(),
        };
        errors::access_denied(format!(
            "User: {} is not authorized to perform: {action} on resource: \"{arn}\"{reason}",
            ctx.caller.arn
        ))
    }

    /// The bucket policy as evaluated for this caller: with
    /// RestrictPublicBuckets, a public policy only grants access to
    /// principals of the bucket owner's account.
    fn effective_policy(&self, ctx: &RequestContext, bucket: &Bucket) -> Option<String> {
        let policy = bucket.policy.clone()?;
        let restrict = bucket.pab().restrict_public_buckets.unwrap_or(false);
        let outsider = ctx.caller.kind == CallerKind::Anonymous || ctx.caller.account_id != bucket.owner;
        if restrict && outsider && policy_is_public(&policy) {
            return None;
        }
        Some(policy)
    }

    /// ACL grants: only consulted when nothing denied explicitly and the
    /// bucket's ownership controls allow ACLs.
    fn acl_allows(&self, ctx: &RequestContext, action: &str, bucket: &Bucket, resource: &Resource<'_>) -> bool {
        if !bucket.acls_enabled() {
            return false;
        }
        let ignore_public = bucket.pab().ignore_public_acls.unwrap_or(false);
        let (grants, needed) = match resource {
            Resource::Bucket => (bucket.acl.as_slice(), acl::bucket_permission(action)),
            Resource::Object { grants: Some(g), .. } if acl::object_permission(action).is_some() => {
                (*g, acl::object_permission(action))
            }
            // Writing objects is governed by the bucket's WRITE grant.
            Resource::Object { .. } => (bucket.acl.as_slice(), acl::bucket_permission(action)),
        };
        let Some(needed) = needed else { return false };
        grants.iter().any(|g| {
            let Some(grantee) = &g.grantee else { return false };
            let permits = match g.permission.as_deref().and_then(Permission::parse) {
                Some(p) => p.covers(needed),
                None => false,
            };
            permits && acl::grantee_matches(grantee, &ctx.caller, ignore_public)
        })
    }
}

/// Condition keys whose fixed values make a statement non-public.
const RESTRICTING_KEYS: &[&str] = &[
    "aws:sourcearn",
    "aws:sourcevpc",
    "aws:sourcevpce",
    "aws:sourceaccount",
    "aws:sourceowner",
    "aws:sourceorgid",
    "aws:sourceorgpaths",
    "aws:principalarn",
    "aws:principalaccount",
    "aws:principalorgid",
    "aws:principalorgpaths",
    "aws:principalservicename",
    "aws:userid",
    "aws:sourceip",
    "s3:dataaccesspointarn",
    "s3:dataaccesspointaccount",
];

/// Whether a bucket policy grants access to everyone, as Block Public
/// Access and `GetBucketPolicyStatus` judge it: an `Allow` for principal
/// `*` that no fixed-value condition on a restricting key narrows.
pub fn policy_is_public(document: &str) -> bool {
    let Ok(policy) = Policy::parse(document, PolicyKind::Resource) else { return false };
    policy.statements.iter().any(|s| {
        if s.effect != Effect::Allow {
            return false;
        }
        let Some(p) = &s.principal else { return false };
        let everyone =
            p.negated || p.any || p.aws.iter().any(|a| a == "*") || p.canonical_user.iter().any(|a| a == "*");
        if !everyone {
            return false;
        }
        !s.conditions.iter().any(|c| {
            let key = c.key.to_ascii_lowercase();
            RESTRICTING_KEYS.contains(&key.as_str())
                && !c.operator.starts_with("StringNotEquals")
                && !c.operator.starts_with("ArnNot")
                && !c.operator.starts_with("NotIpAddress")
                && c.values.iter().all(|v| !v.contains('*') && v != "0.0.0.0/0" && v != "::/0")
        })
    })
}

/// Check a bucket policy the way PutBucketPolicy does.
pub fn validate_policy(document: &str, partition: &str, bucket: &str) -> Result<(), ServiceError> {
    let value: serde_json::Value =
        serde_json::from_str(document).map_err(|_| errors::malformed_policy("This policy contains invalid Json"))?;
    let statements = match value.get("Statement") {
        Some(serde_json::Value::Array(a)) => a.clone(),
        Some(s @ serde_json::Value::Object(_)) => vec![s.clone()],
        _ => return Err(errors::malformed_policy("Missing required field Statement")),
    };
    for s in &statements {
        let Some(obj) = s.as_object() else {
            return Err(errors::malformed_policy("This policy contains invalid Json"));
        };
        for k in obj.keys() {
            if !matches!(
                k.as_str(),
                "Sid"
                    | "Effect"
                    | "Principal"
                    | "NotPrincipal"
                    | "Action"
                    | "NotAction"
                    | "Resource"
                    | "NotResource"
                    | "Condition"
            ) {
                return Err(errors::malformed_policy(&format!("Unknown field {k}")));
            }
        }
        if !obj.contains_key("Effect") {
            return Err(errors::malformed_policy("Missing required field Effect"));
        }
        if !obj.contains_key("Principal") && !obj.contains_key("NotPrincipal") {
            return Err(errors::malformed_policy("Missing required field Principal"));
        }
        if !obj.contains_key("Action") && !obj.contains_key("NotAction") {
            return Err(errors::malformed_policy("Missing required field Action"));
        }
        if !obj.contains_key("Resource") && !obj.contains_key("NotResource") {
            return Err(errors::malformed_policy("Missing required field Resource"));
        }
        for a in strings(obj.get("Action").or_else(|| obj.get("NotAction"))) {
            if a != "*" && !a.to_ascii_lowercase().starts_with("s3:") {
                return Err(errors::malformed_policy("Policy has invalid action"));
            }
        }
        let prefix = format!("arn:{partition}:s3:::");
        for r in strings(obj.get("Resource").or_else(|| obj.get("NotResource"))) {
            let Some(rest) = r.strip_prefix(&prefix) else {
                return Err(errors::malformed_policy("Policy has invalid resource"));
            };
            let name = rest.split('/').next().unwrap_or_default();
            if !mws_iam_policy_glob(name, bucket) {
                return Err(errors::malformed_policy("Policy has invalid resource"));
            }
        }
    }
    Policy::parse(document, PolicyKind::Resource).map_err(|e| {
        let m = e.0;
        if m.contains("principal") || m.contains("Principal") {
            errors::malformed_policy("Invalid principal in policy")
        } else if m.contains("ondition") {
            errors::malformed_policy("Policy has an invalid condition key")
        } else {
            errors::malformed_policy(&m)
        }
    })?;
    Ok(())
}

fn strings(v: Option<&serde_json::Value>) -> Vec<String> {
    match v {
        Some(serde_json::Value::String(s)) => vec![s.clone()],
        Some(serde_json::Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
        _ => Vec::new(),
    }
}

/// `*`/`?` wildcard match, as policy resources use.
fn mws_iam_policy_glob(pattern: &str, value: &str) -> bool {
    fn go(p: &[u8], v: &[u8]) -> bool {
        match (p.first(), v.first()) {
            (None, None) => true,
            (Some(b'*'), _) => go(&p[1..], v) || (!v.is_empty() && go(p, &v[1..])),
            (Some(b'?'), Some(_)) => go(&p[1..], &v[1..]),
            (Some(a), Some(b)) if a == b => go(&p[1..], &v[1..]),
            _ => false,
        }
    }
    go(pattern.as_bytes(), value.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_policies() {
        let public = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}"#;
        assert!(policy_is_public(public));
        let scoped = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*","Condition":{"StringEquals":{"aws:SourceAccount":"123456789012"}}}]}"#;
        assert!(!policy_is_public(scoped));
        let account = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::123456789012:root"},"Action":"s3:*","Resource":"arn:aws:s3:::b/*"}]}"#;
        assert!(!policy_is_public(account));
    }

    #[test]
    fn policy_validation() {
        assert!(validate_policy("{", "aws", "b").is_err());
        let wrong_bucket = r#"{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::other/*"}]}"#;
        assert_eq!(validate_policy(wrong_bucket, "aws", "b").unwrap_err().message, "Policy has invalid resource");
        let ok = r#"{"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}"#;
        assert!(validate_policy(ok, "aws", "b").is_ok());
    }
}

//! Errors, identifiers, paging, and who may call what.
//!
//! Every operation is authorized twice, as in AWS: IAM decides whether the
//! caller's policies (and SCPs) allow the action, then Organizations decides
//! whether the caller's account may perform it: the management account may
//! do everything, member accounts only a few things, and delegated
//! administrators and principals the organization's resource policy names a
//! little more.

use mws_core::{CallerKind, ConditionContext, ErrorValue, RequestContext, ServiceError};
use mws_iam_policy::{Policy, PolicyKind, PrincipalInfo, Request};
use rand::Rng;

use crate::generated::errors;
use crate::state::{Org, State, Tags};
use crate::structure::ORGANIZATIONS_PRINCIPAL;
use crate::Organizations;

pub(crate) const MAX_TAGS: usize = 50;
const DEFAULT_PAGE: usize = 20;

// ---- errors ------------------------------------------------------------------

pub(crate) fn not_in_use() -> ServiceError {
    errors::aws_organizations_not_in_use("Your account is not a member of an organization.")
}

pub(crate) fn access_denied() -> ServiceError {
    errors::access_denied("You don't have permissions to access this resource.")
}

fn with_reason(e: ServiceError, reason: &str) -> ServiceError {
    e.with_field("Reason", ErrorValue::String(reason.to_string()))
}

pub(crate) fn constraint(reason: &str, message: impl Into<String>) -> ServiceError {
    with_reason(errors::constraint_violation(message), reason)
}

pub(crate) fn invalid(reason: &str, message: impl Into<String>) -> ServiceError {
    with_reason(errors::invalid_input(message), reason)
}

pub(crate) fn handshake_constraint(reason: &str, message: impl Into<String>) -> ServiceError {
    with_reason(errors::handshake_constraint_violation(message), reason)
}

pub(crate) fn account_not_found() -> ServiceError {
    errors::account_not_found("You specified an account that doesn't exist.")
}

pub(crate) fn ou_not_found() -> ServiceError {
    errors::organizational_unit_not_found("You specified an organizational unit that doesn't exist.")
}

pub(crate) fn parent_not_found() -> ServiceError {
    errors::parent_not_found("You specified a parent that doesn't exist.")
}

pub(crate) fn policy_not_found() -> ServiceError {
    errors::policy_not_found("You specified a policy that doesn't exist.")
}

pub(crate) fn target_not_found() -> ServiceError {
    errors::target_not_found("You specified a target that doesn't exist.")
}

pub(crate) fn root_not_found() -> ServiceError {
    errors::root_not_found("You specified a root that doesn't exist.")
}

pub(crate) fn handshake_not_found() -> ServiceError {
    errors::handshake_not_found("You specified a handshake that doesn't exist.")
}

// ---- identifiers -------------------------------------------------------------

pub(crate) fn random(alphabet: &[u8], len: usize) -> String {
    let mut rng = rand::thread_rng();
    (0..len).map(|_| alphabet[rng.gen_range(0..alphabet.len())] as char).collect()
}

const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

pub(crate) fn new_id(prefix: &str, len: usize) -> String {
    format!("{prefix}{}", random(LOWER, len))
}

pub(crate) fn new_account_id() -> String {
    let mut id = random(b"0123456789", 12);
    // Account ids never start with 0 in practice.
    id.replace_range(0..1, &random(b"123456789", 1));
    id
}

// ---- paging ------------------------------------------------------------------

/// One page of `items`. Tokens are opaque offsets.
pub(crate) fn page<T>(
    items: Vec<T>,
    next_token: Option<&str>,
    max_results: Option<i32>,
) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match next_token {
        None => 0,
        Some(t) => t
            .strip_prefix("mws-")
            .and_then(|n| n.parse::<usize>().ok())
            .filter(|n| *n <= items.len())
            .ok_or_else(|| invalid("INVALID_PAGINATION_TOKEN", "The specified NextToken is not valid."))?,
    };
    let size = max_results.map(|m| m.max(1) as usize).unwrap_or(DEFAULT_PAGE);
    let end = (start + size).min(items.len());
    let next = (end < items.len()).then(|| format!("mws-{end}"));
    Ok((items.into_iter().skip(start).take(end - start).collect(), next))
}

// ---- tags --------------------------------------------------------------------

pub(crate) fn tags_from(tags: Option<Vec<crate::generated::types::Tag>>) -> Result<Tags, ServiceError> {
    let tags = tags.unwrap_or_default();
    let mut out = Tags::new();
    for t in tags {
        if out.insert(t.key.clone(), t.value).is_some() {
            return Err(invalid("DUPLICATE_TAG_KEY", "You provided duplicate tag keys."));
        }
    }
    if out.len() > MAX_TAGS {
        return Err(constraint(
            "MAX_TAG_LIMIT_EXCEEDED",
            "You have exceeded the number of tags allowed on this resource.",
        ));
    }
    Ok(out)
}

pub(crate) fn tags_to_wire(tags: &Tags) -> Vec<crate::generated::types::Tag> {
    tags.iter().map(|(k, v)| crate::generated::types::Tag { key: k.clone(), value: v.clone() }).collect()
}

pub(crate) fn request_tag_context(tags: &Tags) -> ConditionContext {
    let mut ctx = ConditionContext::new();
    if tags.is_empty() {
        return ctx;
    }
    for (k, v) in tags {
        ctx.insert(format!("aws:RequestTag/{k}"), vec![v.clone()]);
    }
    ctx.insert("aws:TagKeys".into(), tags.keys().cloned().collect());
    ctx
}

pub(crate) fn resource_tag_context(tags: &Tags) -> ConditionContext {
    tags.iter().map(|(k, v)| (format!("aws:ResourceTag/{k}"), vec![v.clone()])).collect()
}

pub(crate) fn single(key: &str, value: impl Into<String>) -> ConditionContext {
    let mut ctx = ConditionContext::new();
    ctx.insert(key.into(), vec![value.into()]);
    ctx
}

// ---- who may call what -------------------------------------------------------

/// What an operation requires of the caller's account.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Need {
    /// Only the management account.
    Management,
    /// The management account, or an account the organization's resource
    /// policy delegates the action to.
    Delegable,
    /// The management account, a delegated administrator, or an account
    /// the resource policy delegates the action to.
    Read,
}

impl Organizations {
    /// IAM's half: the caller's policies (and SCPs) must allow the action.
    /// Never call this while holding the state lock.
    pub(crate) fn authorize(
        &self,
        ctx: &RequestContext,
        action: &str,
        resource: &str,
        context: ConditionContext,
    ) -> Result<(), ServiceError> {
        ctx.authorize(&format!("organizations:{action}"), resource, context)
    }

    /// Creating a resource with tags also needs `organizations:TagResource`
    /// on it, as AWS documents for every operation that takes `Tags`.
    pub(crate) fn authorize_tagging(&self, ctx: &RequestContext, arn: &str, tags: &Tags) -> Result<(), ServiceError> {
        if tags.is_empty() {
            return Ok(());
        }
        self.authorize(ctx, "TagResource", arn, request_tag_context(tags))
    }

    /// Organizations creates `AWSServiceRoleForOrganizations` in `account`
    /// on the caller's behalf (CreateOrganization, accepting an invitation to
    /// an organization with all features), so the caller needs
    /// `iam:CreateServiceLinkedRole` unless the role is already there.
    pub(crate) fn authorize_service_linked_role(
        &self,
        ctx: &RequestContext,
        account: &str,
    ) -> Result<(), ServiceError> {
        let arn = format!(
            "arn:{}:iam::{account}:role/aws-service-role/{ORGANIZATIONS_PRINCIPAL}/AWSServiceRoleForOrganizations",
            ctx.partition
        );
        if self.iam.role_by_arn(&arn).is_some() {
            return Ok(());
        }
        ctx.authorize("iam:CreateServiceLinkedRole", &arn, single("iam:AWSServiceName", ORGANIZATIONS_PRINCIPAL))
    }

    /// Organizations' half: the organization the caller belongs to, if the
    /// caller's account may perform `action` in it.
    pub(crate) fn caller_org<'a>(
        &self,
        state: &'a State,
        ctx: &RequestContext,
        action: &str,
        resource: &str,
        need: Need,
    ) -> Result<&'a Org, ServiceError> {
        let account = &ctx.caller.account_id;
        let org = state.org_of(account).ok_or_else(not_in_use)?;
        if org.management_account == *account {
            return Ok(org);
        }
        if need == Need::Read && org.delegated.contains_key(account) {
            return Ok(org);
        }
        if need != Need::Management && resource_policy_allows(org, ctx, action, resource) {
            return Ok(org);
        }
        Err(access_denied())
    }
}

/// Whether the organization's resource policy lets the caller perform
/// `action` on `resource`.
fn resource_policy_allows(org: &Org, ctx: &RequestContext, action: &str, resource: &str) -> bool {
    let Some(rp) = &org.resource_policy else { return false };
    let Ok(policy) = Policy::parse(&rp.content, PolicyKind::Resource) else { return false };
    let caller = &ctx.caller;
    let mut arns = vec![caller.arn.clone()];
    if let CallerKind::AssumedRole { role_name, .. } = &caller.kind {
        arns.push(format!("arn:{}:iam::{}:role/{role_name}", ctx.partition, caller.account_id));
    }
    let principal = PrincipalInfo { account_id: caller.account_id.clone(), arns, ..Default::default() };
    let mut context = mws_iam_policy::ConditionContext::new();
    for (k, v) in ctx.global_condition_context() {
        context.insert(k, v);
    }
    let action = format!("organizations:{action}");
    let eval = policy.evaluate(&Request { action: &action, resource, principal: &principal, context: &context });
    eval.allowed() && !eval.denied()
}

/// Validate an organization resource policy document.
pub(crate) fn validate_resource_policy(content: &str) -> Result<(), ServiceError> {
    let policy = Policy::parse(content, PolicyKind::Resource).map_err(|e| {
        invalid("INVALID_RESOURCE_POLICY_JSON", format!("The provided resource policy is not valid: {e}"))
    })?;
    for s in &policy.statements {
        for a in &s.action.patterns {
            let ok = a == "*" || a.to_ascii_lowercase().starts_with("organizations:");
            if !ok {
                return Err(invalid(
                    "UNSUPPORTED_ACTION_IN_RESOURCE_POLICY",
                    format!("The resource policy contains an unsupported action: {a}"),
                ));
            }
        }
    }
    Ok(())
}

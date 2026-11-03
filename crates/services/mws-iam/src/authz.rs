//! The IAM authorizer: evaluates the caller's policies for every request to
//! every MWS service.

use std::sync::Arc;

use mws_core::{Authorizer, AuthzDecision, AuthzRequest, Caller, CallerKind, ResourcePolicyMode};
use mws_iam_policy::{decide, ConditionContext, Policy, PolicyKind, PolicySet, PrincipalInfo, Request, SourcedPolicy};

use crate::state::State;
use crate::Inner;

pub(crate) struct IamAuthorizer {
    pub inner: Arc<Inner>,
}

/// Services whose resources resource control policies protect.
const RCP_SERVICES: &[&str] =
    &["s3", "sts", "kms", "sqs", "secretsmanager", "cognito-identity", "ecr", "aoss", "logs", "dynamodb"];

/// The account a resource belongs to: `aws:ResourceAccount` when the service
/// supplies it, else the ARN's account field.
fn resource_account(req: &AuthzRequest<'_>) -> Option<String> {
    if let Some(a) = req.context.get("aws:ResourceAccount").and_then(|v| v.first()) {
        return Some(a.clone());
    }
    let account = req.resource.split(':').nth(4)?;
    (account.len() == 12 && account.bytes().all(|b| b.is_ascii_digit())).then(|| account.to_string())
}

pub(crate) fn parse_levels(levels: &[crate::org::PolicyLevel], kind: PolicyKind) -> Vec<Vec<SourcedPolicy>> {
    levels
        .iter()
        .map(|level| {
            level
                .iter()
                .filter_map(|(id, doc)| {
                    Policy::parse(doc, kind).ok().map(|policy| SourcedPolicy { source_id: id.clone(), policy })
                })
                .collect()
        })
        .collect()
}

impl Authorizer for IamAuthorizer {
    fn authorize(&self, req: &AuthzRequest<'_>) -> AuthzDecision {
        // Ask Organizations first: it must not be asked under the IAM lock.
        let orgs = self.inner.organizations.get();
        let caller_account = req.caller.account_id.as_str();
        let caller_org = orgs.and_then(|o| o.account(caller_account));
        let resource_account = resource_account(req);
        let resource_org = match resource_account.as_deref() {
            Some(a) if a == caller_account => caller_org.clone(),
            Some(a) => orgs.and_then(|o| o.account(a)),
            None => None,
        };

        if caller_org.as_ref().is_some_and(|o| o.suspended) {
            return AuthzDecision::Deny { reason: String::new(), explicit: true };
        }
        let state = self.inner.read_account(caller_account);
        let (mut set, principal, mut context) = principal_policies(&state, req.caller, caller_account);
        for (k, v) in &req.context {
            context.insert(k, v.clone());
        }
        let role = role_arn(&state, req.caller);
        // Access advisor: every authenticated attempt counts, allowed or not.
        let entity = match &req.caller.kind {
            CallerKind::User { .. } => Some(req.caller.arn.clone()),
            CallerKind::AssumedRole { .. } => role.clone(),
            _ => None,
        };
        self.inner.note_activity(req, entity);
        if let Some(arn) = role {
            context.insert("aws:PrincipalArn", vec![arn]);
        }
        if let Some(o) = &caller_org {
            context.insert("aws:PrincipalOrgID", vec![o.organization_id.clone()]);
            context.insert("aws:PrincipalOrgPaths", vec![o.org_path.clone()]);
        }
        if let Some(a) = &resource_account {
            context.insert("aws:ResourceAccount", vec![a.clone()]);
        }
        if let Some(o) = &resource_org {
            context.insert("aws:ResourceOrgID", vec![o.organization_id.clone()]);
            context.insert("aws:ResourceOrgPaths", vec![o.org_path.clone()]);
        }
        // SCPs never restrict service-linked roles.
        let service_linked = match &req.caller.kind {
            CallerKind::AssumedRole { role_name, .. } => {
                state.role(role_name).is_some_and(|r| r.path.starts_with("/aws-service-role/"))
            }
            _ => false,
        };
        if !service_linked {
            if let Some(levels) = caller_org.as_ref().and_then(|o| o.service_control_policies.as_ref()) {
                set.service_control = Some(parse_levels(levels, PolicyKind::ServiceControl));
            }
            let service = req.action.split(':').next().unwrap_or_default().to_ascii_lowercase();
            if RCP_SERVICES.contains(&service.as_str()) {
                if let Some(levels) = resource_org.as_ref().and_then(|o| o.resource_control_policies.as_ref()) {
                    set.resource_control = Some(parse_levels(levels, PolicyKind::ResourceControl));
                }
            }
        }
        // Organizations decides who may read an organization itself (its
        // resources all carry the management account's id), and STS decides
        // who may start root sessions in member accounts.
        let service_decides = req.resource.split(':').nth(2) == Some("organizations")
            || req.action.eq_ignore_ascii_case("sts:AssumeRoot");
        // Anonymous callers have no identity policies to consult: a resource
        // policy alone decides, whoever owns the resource.
        let anonymous = req.caller.kind == CallerKind::Anonymous;
        set.cross_account =
            !service_decides && !anonymous && resource_account.as_deref().is_some_and(|a| a != caller_account);
        if let Some(doc) = req.resource_policy {
            let kind = if req.resource_policy_mode == ResourcePolicyMode::Trust {
                PolicyKind::Trust
            } else {
                PolicyKind::Resource
            };
            if let Ok(policy) = Policy::parse(doc, kind) {
                set.resource = Some(SourcedPolicy { source_id: "resource".into(), policy });
            }
        }
        set.resource_required = req.resource_policy_mode != ResourcePolicyMode::Optional;
        let decision = decide(
            &set,
            &Request { action: req.action, resource: req.resource, principal: &principal, context: &context },
        );
        if decision.allowed {
            AuthzDecision::Allow
        } else {
            let explicit = decision.deny_reason.as_ref().is_some_and(|r| r.is_explicit());
            let reason = match decision.deny_reason {
                // AWS gives no reason when a trust policy does not allow.
                Some(mws_iam_policy::DenyReason::NoResourceAllow)
                    if req.resource_policy_mode == ResourcePolicyMode::Trust =>
                {
                    String::new()
                }
                Some(r) => r.message(req.action),
                None => String::new(),
            };
            AuthzDecision::Deny { reason, explicit }
        }
    }
}

fn role_arn(state: &State, caller: &Caller) -> Option<String> {
    match &caller.kind {
        CallerKind::AssumedRole { role_name, .. } => state.role(role_name).map(|r| r.arn.clone()),
        _ => None,
    }
}

fn parse_all(docs: impl IntoIterator<Item = (String, String)>) -> Vec<SourcedPolicy> {
    docs.into_iter()
        .filter_map(|(id, doc)| {
            Policy::parse(&doc, PolicyKind::Identity).ok().map(|policy| SourcedPolicy { source_id: id, policy })
        })
        .collect()
}

/// Identity-based policies of a user: inline, attached, and from groups.
pub(crate) fn user_policy_docs(state: &State, name: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Some(user) = state.user(name) else { return out };
    for (n, d) in &user.inline {
        out.push((n.clone(), d.clone()));
    }
    for arn in &user.attached {
        if let Some(p) = state.policies.get(arn) {
            out.push((arn.clone(), p.default_document().to_string()));
        }
    }
    for g in state.groups_for_user(name) {
        for (n, d) in &g.inline {
            out.push((n.clone(), d.clone()));
        }
        for arn in &g.attached {
            if let Some(p) = state.policies.get(arn) {
                out.push((arn.clone(), p.default_document().to_string()));
            }
        }
    }
    out
}

pub(crate) fn role_policy_docs(state: &State, name: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let Some(role) = state.role(name) else { return out };
    for (n, d) in &role.inline {
        out.push((n.clone(), d.clone()));
    }
    for arn in &role.attached {
        if let Some(p) = state.policies.get(arn) {
            out.push((arn.clone(), p.default_document().to_string()));
        }
    }
    out
}

pub(crate) fn boundary_doc(state: &State, arn: &Option<String>) -> Option<SourcedPolicy> {
    let arn = arn.as_ref()?;
    let doc = state.policies.get(arn).map(|p| p.default_document().to_string()).unwrap_or_else(|| "{}".into());
    // A boundary that cannot be parsed allows nothing.
    let policy = Policy::parse(&doc, PolicyKind::Identity).unwrap_or(Policy {
        version: "2012-10-17".into(),
        id: None,
        statements: vec![],
    });
    Some(SourcedPolicy { source_id: arn.clone(), policy })
}

/// Everything needed to evaluate `caller`'s requests.
pub(crate) fn principal_policies(
    state: &State,
    caller: &Caller,
    account_id: &str,
) -> (PolicySet, PrincipalInfo, ConditionContext) {
    let mut set = PolicySet::default();
    let mut principal =
        PrincipalInfo { account_id: caller.account_id.clone(), arns: vec![caller.arn.clone()], ..Default::default() };
    let mut ctx = ConditionContext::new();
    match &caller.kind {
        CallerKind::Root => {
            set.is_root = true;
            principal.arns.push(format!("arn:aws:iam::{account_id}:root"));
        }
        CallerKind::User { name } => {
            set.identity = parse_all(user_policy_docs(state, name));
            if let Some(u) = state.user(name) {
                set.boundary = boundary_doc(state, &u.permissions_boundary);
                for (k, v) in &u.tags {
                    ctx.insert(format!("aws:PrincipalTag/{k}"), vec![v.clone()]);
                }
            }
        }
        CallerKind::AssumedRole { role_name, .. } => {
            set.identity = parse_all(role_policy_docs(state, role_name));
            if let Some(r) = state.role(role_name) {
                principal.arns.push(r.arn.clone());
                set.boundary = boundary_doc(state, &r.permissions_boundary);
                for (k, v) in &r.tags {
                    ctx.insert(format!("aws:PrincipalTag/{k}"), vec![v.clone()]);
                }
            }
        }
        CallerKind::FederatedUser { parent_user, .. } => {
            match parent_user {
                Some(u) => {
                    set.identity = parse_all(user_policy_docs(state, u));
                    if let Some(user) = state.user(u) {
                        set.boundary = boundary_doc(state, &user.permissions_boundary);
                    }
                }
                None => set.is_root = true,
            }
            set.session_required = true;
        }
        CallerKind::Anonymous => principal.anonymous = true,
    }
    if let Some(session) = &caller.session {
        set.session =
            parse_all(session.policies.iter().enumerate().map(|(i, d)| (format!("session-policy-{i}"), d.clone())));
        for (k, v) in &session.tags {
            ctx.insert(format!("aws:PrincipalTag/{k}"), vec![v.clone()]);
        }
    }
    (set, principal, ctx)
}

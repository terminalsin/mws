//! The IAM authorizer: evaluates the caller's policies for every request to
//! every MWS service.

use std::sync::Arc;

use mws_core::{Authorizer, AuthzDecision, AuthzRequest, Caller, CallerKind};
use mws_iam_policy::{decide, ConditionContext, Policy, PolicyKind, PolicySet, PrincipalInfo, Request, SourcedPolicy};

use crate::state::State;
use crate::Inner;

pub(crate) struct IamAuthorizer {
    pub inner: Arc<Inner>,
}

impl Authorizer for IamAuthorizer {
    fn authorize(&self, req: &AuthzRequest<'_>) -> AuthzDecision {
        let state = self.inner.state.read().expect("IAM state lock poisoned");
        let (mut set, principal, mut context) = principal_policies(&state, req.caller, &self.inner.config.account_id);
        for (k, v) in &req.context {
            context.insert(k, v.clone());
        }
        if let Some(arn) = role_arn(&state, req.caller) {
            context.insert("aws:PrincipalArn", vec![arn]);
        }
        if let Some(doc) = req.resource_policy {
            let kind = if req.resource_policy_required { PolicyKind::Trust } else { PolicyKind::Resource };
            if let Ok(policy) = Policy::parse(doc, kind) {
                set.resource = Some(SourcedPolicy { source_id: "resource".into(), policy });
            }
        }
        set.resource_required = req.resource_policy_required;
        let decision = decide(
            &set,
            &Request { action: req.action, resource: req.resource, principal: &principal, context: &context },
        );
        if decision.allowed {
            AuthzDecision::Allow
        } else {
            let reason = match decision.deny_reason {
                // AWS gives no reason when a trust policy does not allow.
                Some(mws_iam_policy::DenyReason::NoResourceAllow) => String::new(),
                Some(r) => r.message(req.action),
                None => String::new(),
            };
            AuthzDecision::Deny { reason }
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

//! Combining policies into one decision, following IAM's policy evaluation
//! logic for requests within a single account:
//! <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html>

use crate::{Evaluation, Policy, Request};

/// A parsed policy plus where it came from, for reporting.
#[derive(Debug, Clone)]
pub struct SourcedPolicy {
    /// e.g. a policy ARN, `user/bob/inline-name`, or `session`.
    pub source_id: String,
    pub policy: Policy,
}

/// Everything that applies to one principal and one request.
#[derive(Debug, Clone, Default)]
pub struct PolicySet {
    pub identity: Vec<SourcedPolicy>,
    /// `None` means no boundary is set (not "a boundary that allows
    /// nothing").
    pub boundary: Option<SourcedPolicy>,
    /// Session policies; empty means none were passed.
    pub session: Vec<SourcedPolicy>,
    pub resource: Option<SourcedPolicy>,
    /// The account root user bypasses identity policies.
    pub is_root: bool,
    /// Sessions that must be allowed by a session policy even when none was
    /// passed (e.g. `GetFederationToken` without a policy grants nothing).
    pub session_required: bool,
    /// The resource policy must allow the principal (directly or through its
    /// account), as role trust policies require.
    pub resource_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    ExplicitIdentity,
    ExplicitResource,
    ExplicitBoundary,
    ExplicitSession,
    NoIdentityAllow,
    NoBoundaryAllow,
    NoSessionAllow,
    NoResourceAllow,
}

impl DenyReason {
    /// Wording AWS appends to `AccessDenied` messages.
    pub fn message(&self, action: &str) -> String {
        match self {
            DenyReason::ExplicitIdentity => "with an explicit deny in an identity-based policy".into(),
            DenyReason::ExplicitResource => "with an explicit deny in a resource-based policy".into(),
            DenyReason::ExplicitBoundary => "with an explicit deny in a permissions boundary".into(),
            DenyReason::ExplicitSession => "with an explicit deny in a session policy".into(),
            DenyReason::NoIdentityAllow => format!("because no identity-based policy allows the {action} action"),
            DenyReason::NoBoundaryAllow => format!("because no permissions boundary allows the {action} action"),
            DenyReason::NoSessionAllow => format!("because no session policy allows the {action} action"),
            DenyReason::NoResourceAllow => format!("because no resource-based policy allows the {action} action"),
        }
    }

    pub fn is_explicit(&self) -> bool {
        matches!(
            self,
            DenyReason::ExplicitIdentity
                | DenyReason::ExplicitResource
                | DenyReason::ExplicitBoundary
                | DenyReason::ExplicitSession
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub allowed: bool,
    pub deny_reason: Option<DenyReason>,
    /// `(source_id, statement index)` for every statement that decided the
    /// outcome (all matching denies, or the allows that granted access).
    pub matched: Vec<(String, usize)>,
}

fn eval_all(policies: &[SourcedPolicy], req: &Request<'_>) -> Vec<(String, Evaluation)> {
    policies.iter().map(|p| (p.source_id.clone(), p.policy.evaluate(req))).collect()
}

pub fn decide(set: &PolicySet, req: &Request<'_>) -> Decision {
    let identity = eval_all(&set.identity, req);
    let boundary = set.boundary.as_ref().map(|b| (b.source_id.clone(), b.policy.evaluate(req)));
    let session = eval_all(&set.session, req);
    let resource = set.resource.as_ref().map(|r| (r.source_id.clone(), r.policy.evaluate(req)));

    // 1. Any explicit deny wins.
    let mut denies = Vec::new();
    let mut first_reason = None;
    let mut collect = |evals: &[(String, Evaluation)], reason: DenyReason| {
        for (src, e) in evals {
            if e.denied() {
                first_reason.get_or_insert(reason.clone());
                denies.extend(e.denies.iter().map(|i| (src.clone(), *i)));
            }
        }
    };
    collect(&identity, DenyReason::ExplicitIdentity);
    collect(resource.as_slice(), DenyReason::ExplicitResource);
    collect(boundary.as_slice(), DenyReason::ExplicitBoundary);
    collect(&session, DenyReason::ExplicitSession);
    if !denies.is_empty() {
        return Decision { allowed: false, deny_reason: first_reason, matched: denies };
    }

    let allows_of = |evals: &[(String, Evaluation)]| -> Vec<(String, usize)> {
        evals.iter().flat_map(|(s, e)| e.allows.iter().map(move |(i, _)| (s.clone(), *i))).collect()
    };
    let session_ok = (set.session.is_empty() && !set.session_required) || session.iter().any(|(_, e)| e.allowed());

    // 2. A resource-based policy that names the principal directly grants
    //    access on its own (subject only to session policies).
    if let Some((src, e)) = &resource {
        if e.allowed_directly() && session_ok {
            let matched = e.allows.iter().map(|(i, _)| (src.clone(), *i)).collect();
            return Decision { allowed: true, deny_reason: None, matched };
        }
    }

    if set.resource_required && !resource.as_ref().is_some_and(|(_, e)| e.allowed()) {
        return Decision { allowed: false, deny_reason: Some(DenyReason::NoResourceAllow), matched: vec![] };
    }

    // 3. Otherwise identity policies must allow, within the boundary and the
    //    session policies. The root user has implicit full identity access.
    let identity_allows = set.is_root || identity.iter().any(|(_, e)| e.allowed());
    if !identity_allows {
        return Decision { allowed: false, deny_reason: Some(DenyReason::NoIdentityAllow), matched: vec![] };
    }
    if let Some((_, b)) = &boundary {
        if !b.allowed() {
            return Decision { allowed: false, deny_reason: Some(DenyReason::NoBoundaryAllow), matched: vec![] };
        }
    }
    if !session_ok {
        return Decision { allowed: false, deny_reason: Some(DenyReason::NoSessionAllow), matched: vec![] };
    }
    let mut matched = allows_of(&identity);
    if let Some((src, e)) = &resource {
        matched.extend(e.allows.iter().map(|(i, _)| (src.clone(), *i)));
    }
    Decision { allowed: true, deny_reason: None, matched }
}

//! Combining policies into one decision, following IAM's policy evaluation
//! logic, including AWS Organizations guardrails (SCPs and RCPs) and
//! cross-account requests:
//! <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html>

use crate::{Evaluation, Policy, PrincipalMatch, Request};

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
    /// Service control policies that apply to the principal, one entry per
    /// level of the organization tree (root first, account last). Every
    /// level must allow the action. `None` when no SCPs apply.
    pub service_control: Option<Vec<Vec<SourcedPolicy>>>,
    /// Resource control policies that apply to the resource, likewise.
    pub resource_control: Option<Vec<Vec<SourcedPolicy>>>,
    /// The resource belongs to another account: both the resource policy and
    /// the principal's identity policies must allow.
    pub cross_account: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    ExplicitServiceControl,
    ExplicitResourceControl,
    NoServiceControlAllow,
    NoResourceControlAllow,
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
            DenyReason::ExplicitServiceControl => "with an explicit deny in a service control policy".into(),
            DenyReason::ExplicitResourceControl => "with an explicit deny in a resource control policy".into(),
            DenyReason::NoServiceControlAllow => {
                format!("because no service control policy allows the {action} action")
            }
            DenyReason::NoResourceControlAllow => {
                format!("because no resource control policy allows the {action} action")
            }
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
            DenyReason::ExplicitServiceControl
                | DenyReason::ExplicitResourceControl
                | DenyReason::ExplicitIdentity
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
    let levels = |l: &Option<Vec<Vec<SourcedPolicy>>>| -> Option<Vec<Vec<(String, Evaluation)>>> {
        l.as_ref().map(|levels| levels.iter().map(|level| eval_all(level, req)).collect())
    };
    let scp = levels(&set.service_control);
    let rcp = levels(&set.resource_control);

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
    for level in rcp.iter().flatten() {
        collect(level, DenyReason::ExplicitResourceControl);
    }
    for level in scp.iter().flatten() {
        collect(level, DenyReason::ExplicitServiceControl);
    }
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
    // 2. Organizations guardrails: every level of the tree must allow.
    let every_level_allows = |levels: &Option<Vec<Vec<(String, Evaluation)>>>| {
        levels.as_ref().is_none_or(|levels| levels.iter().all(|level| level.iter().any(|(_, e)| e.allowed())))
    };
    if !every_level_allows(&rcp) {
        return Decision { allowed: false, deny_reason: Some(DenyReason::NoResourceControlAllow), matched: vec![] };
    }
    if !every_level_allows(&scp) {
        return Decision { allowed: false, deny_reason: Some(DenyReason::NoServiceControlAllow), matched: vec![] };
    }

    let session_ok = (set.session.is_empty() && !set.session_required) || session.iter().any(|(_, e)| e.allowed());

    // 3. Within one account, a resource-based policy that names the
    //    principal directly grants access on its own (subject only to session
    //    policies). Across accounts, both sides must allow.
    if set.cross_account && !resource.as_ref().is_some_and(|(_, e)| e.allowed()) {
        return Decision { allowed: false, deny_reason: Some(DenyReason::NoResourceAllow), matched: vec![] };
    }
    //    A grant to the user or the role session itself is not limited by
    //    the permissions boundary or session policies; a grant to the role a
    //    session belongs to is limited by both, since it joins the role's
    //    permissions before the session is created.
    //    <https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html>
    let boundary_ok = boundary.as_ref().is_none_or(|(_, b)| b.allowed());
    if let Some((src, e)) = resource.as_ref().filter(|_| !set.cross_account) {
        let granted = e.allowed_as(PrincipalMatch::Direct)
            || (e.allowed_as(PrincipalMatch::Wildcard) && session_ok)
            || (e.allowed_as(PrincipalMatch::Role) && session_ok && boundary_ok);
        if granted {
            let matched = e.allows.iter().map(|(i, _)| (src.clone(), *i)).collect();
            return Decision { allowed: true, deny_reason: None, matched };
        }
    }

    if set.resource_required && !resource.as_ref().is_some_and(|(_, e)| e.allowed()) {
        return Decision { allowed: false, deny_reason: Some(DenyReason::NoResourceAllow), matched: vec![] };
    }

    // 4. Otherwise identity policies must allow, within the boundary and the
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

//! The IAM policy language.
//!
//! [`Policy::parse`] validates a JSON policy document the way IAM does when it
//! is stored; [`Policy::evaluate`] answers whether its statements allow or
//! deny one request. Combining several policies into a final decision (deny
//! wins, boundaries, session policies, resource policies) lives in
//! [`decide`].
//!
//! Reference: <https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html>

mod condition;
mod decide;
mod glob;

use serde_json::Value;

pub use condition::{Condition, ConditionContext};
pub use decide::{decide, Decision, DenyReason, PolicySet, SourcedPolicy};
pub use glob::{arn_matches, glob_matches};

/// Where a policy is used. This changes which elements are required or
/// prohibited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyKind {
    /// Attached to a user, group or role, or used as a permissions boundary
    /// or session policy. Must not have `Principal`; must have `Resource`.
    Identity,
    /// A role trust policy. Must have `Principal`; must not have `Resource`.
    Trust,
    /// Attached to a resource. Must have `Principal`.
    Resource,
    /// An AWS Organizations service control policy. Must not have
    /// `Principal`; `Resource` defaults to every resource.
    ServiceControl,
    /// An AWS Organizations resource control policy. Must have `Principal`.
    ResourceControl,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyError(pub String);

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PolicyError {}

fn err<T>(msg: impl Into<String>) -> Result<T, PolicyError> {
    Err(PolicyError(msg.into()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    Allow,
    Deny,
}

/// A list element that may be negated (`NotAction`, `NotResource`, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matcher {
    pub negated: bool,
    pub patterns: Vec<String>,
}

/// `Principal` / `NotPrincipal`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrincipalMatcher {
    pub negated: bool,
    /// `"Principal": "*"`.
    pub any: bool,
    pub aws: Vec<String>,
    pub service: Vec<String>,
    pub federated: Vec<String>,
    pub canonical_user: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Statement {
    pub sid: Option<String>,
    pub effect: Effect,
    pub principal: Option<PrincipalMatcher>,
    pub action: Matcher,
    pub resource: Option<Matcher>,
    pub conditions: Vec<Condition>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Policy {
    pub version: String,
    pub id: Option<String>,
    pub statements: Vec<Statement>,
}

/// Who is making the request, as policy `Principal` elements see it.
#[derive(Debug, Clone, Default)]
pub struct PrincipalInfo {
    /// The account of the principal.
    pub account_id: String,
    /// ARNs that identify the principal directly: a user ARN, an
    /// assumed-role session ARN, a federated user ARN.
    pub arns: Vec<String>,
    /// For an assumed-role session, the ARN of its role.
    pub role_arn: Option<String>,
    /// Set for AWS service principals, e.g. `ec2.amazonaws.com`.
    pub service: Option<String>,
    /// Set for web identity / SAML federation: the provider ARN.
    pub federated: Option<String>,
    /// Unauthenticated callers only match `*`.
    pub anonymous: bool,
}

/// One authorization question.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    pub action: &'a str,
    pub resource: &'a str,
    pub principal: &'a PrincipalInfo,
    pub context: &'a ConditionContext,
}

/// How a statement's `Principal` matched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalMatch {
    /// The statement names the principal itself: the user, or the role
    /// session (not its role).
    Direct,
    /// The statement matches everyone (`*`).
    Wildcard,
    /// The statement names the IAM role an assumed-role session belongs to.
    /// Session policies and the role's permissions boundary still limit
    /// what such a grant allows.
    Role,
    /// The statement names the principal's whole account, delegating the
    /// decision to the account's identity policies.
    Account,
}

/// The statements of one policy that apply to a request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Evaluation {
    /// Indexes of matching `Deny` statements.
    pub denies: Vec<usize>,
    /// Indexes of matching `Allow` statements, with how the principal matched
    /// (always `Direct` for identity policies).
    pub allows: Vec<(usize, PrincipalMatch)>,
}

impl Evaluation {
    pub fn denied(&self) -> bool {
        !self.denies.is_empty()
    }
    pub fn allowed(&self) -> bool {
        !self.allows.is_empty()
    }
    /// Some allow statement names the principal (not just its account).
    pub fn allowed_directly(&self) -> bool {
        self.allows.iter().any(|(_, m)| *m != PrincipalMatch::Account)
    }

    /// Whether some allow statement matched the principal in `how`.
    pub fn allowed_as(&self, how: PrincipalMatch) -> bool {
        self.allows.iter().any(|(_, m)| *m == how)
    }
}

const VERSIONS: &[&str] = &["2012-10-17", "2008-10-17"];

impl Policy {
    /// Parse and validate a policy document.
    pub fn parse(document: &str, kind: PolicyKind) -> Result<Self, PolicyError> {
        let root: Value = serde_json::from_str(document).or_else(|_| err("Syntax errors in policy."))?;
        let obj = root.as_object().ok_or_else(|| PolicyError("Syntax errors in policy.".into()))?;
        for key in obj.keys() {
            if !matches!(key.as_str(), "Version" | "Id" | "Statement") {
                return err("Syntax errors in policy.");
            }
        }
        let version = match obj.get("Version") {
            None => "2008-10-17".to_string(),
            Some(Value::String(v)) if VERSIONS.contains(&v.as_str()) => v.clone(),
            Some(_) => return err("The policy failed legacy parsing"),
        };
        let id = match obj.get("Id") {
            None => None,
            Some(Value::String(s)) => Some(s.clone()),
            Some(_) => return err("Syntax errors in policy."),
        };
        let statements = match obj.get("Statement") {
            Some(Value::Array(a)) => a.iter().map(|s| parse_statement(s, kind)).collect::<Result<Vec<_>, _>>()?,
            Some(s @ Value::Object(_)) => vec![parse_statement(s, kind)?],
            _ => return err("Syntax errors in policy."),
        };
        let mut sids = std::collections::HashSet::new();
        for s in &statements {
            if let Some(sid) = &s.sid {
                if !sids.insert(sid.clone()) {
                    return err("Statement IDs (SID) in a single policy must be unique.");
                }
            }
        }
        Ok(Self { version, id, statements })
    }

    /// Which statements apply to `req`. Policy variables are only expanded in
    /// version `2012-10-17` documents.
    pub fn evaluate(&self, req: &Request<'_>) -> Evaluation {
        let vars = self.version == "2012-10-17";
        let mut out = Evaluation::default();
        for (i, s) in self.statements.iter().enumerate() {
            let principal_match = match &s.principal {
                None => Some(PrincipalMatch::Direct),
                Some(p) => match_principal(p, req.principal),
            };
            let Some(pm) = principal_match else { continue };
            if !matches_action(&s.action, req.action) {
                continue;
            }
            if let Some(r) = &s.resource {
                if !matches_resource(r, req.resource, req.context, vars) {
                    continue;
                }
            }
            if !s.conditions.iter().all(|c| c.evaluate(req.context, vars)) {
                continue;
            }
            match s.effect {
                Effect::Deny => out.denies.push(i),
                Effect::Allow => out.allows.push((i, pm)),
            }
        }
        out
    }
}

/// Count characters the way IAM does for policy size quotas (whitespace is
/// not counted).
pub fn policy_size(document: &str) -> usize {
    document.chars().filter(|c| !c.is_whitespace()).count()
}

fn string_or_list(v: &Value) -> Result<Vec<String>, PolicyError> {
    match v {
        Value::String(s) => Ok(vec![s.clone()]),
        Value::Array(a) => a
            .iter()
            .map(|x| x.as_str().map(str::to_string).ok_or_else(|| PolicyError("Syntax errors in policy.".into())))
            .collect(),
        _ => err("Syntax errors in policy."),
    }
}

fn parse_statement(v: &Value, kind: PolicyKind) -> Result<Statement, PolicyError> {
    let obj = v.as_object().ok_or_else(|| PolicyError("Syntax errors in policy.".into()))?;
    for key in obj.keys() {
        if !matches!(
            key.as_str(),
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
            return err("Syntax errors in policy.");
        }
    }
    let sid = match obj.get("Sid") {
        None => None,
        Some(Value::String(s)) => {
            if !s.chars().all(|c| c.is_ascii_alphanumeric()) && kind == PolicyKind::Identity {
                return err("Statement IDs (SID) must be alpha-numeric. Check that your input satisfies the regular expression [0-9A-Za-z]*");
            }
            Some(s.clone())
        }
        Some(_) => return err("Syntax errors in policy."),
    };
    let effect = match obj.get("Effect").and_then(Value::as_str) {
        Some("Allow") => Effect::Allow,
        Some("Deny") => Effect::Deny,
        Some(_) => return err("Invalid effect: must be Allow or Deny"),
        None => return err("Missing required field Effect"),
    };

    let principal = match (obj.get("Principal"), obj.get("NotPrincipal")) {
        (Some(_), Some(_)) => return err("Syntax errors in policy."),
        (Some(p), None) => Some(parse_principal(p, false)?),
        (None, Some(p)) => Some(parse_principal(p, true)?),
        (None, None) => None,
    };
    match kind {
        PolicyKind::Identity | PolicyKind::ServiceControl if principal.is_some() => {
            return err("Policy document should not specify a principal.")
        }
        PolicyKind::Trust | PolicyKind::Resource | PolicyKind::ResourceControl if principal.is_none() => {
            return err("Missing required field Principal")
        }
        _ => {}
    }

    let action = match (obj.get("Action"), obj.get("NotAction")) {
        (Some(_), Some(_)) => return err("Syntax errors in policy."),
        (Some(a), None) => Matcher { negated: false, patterns: string_or_list(a)? },
        (None, Some(a)) => Matcher { negated: true, patterns: string_or_list(a)? },
        (None, None) => return err("Policy statement must contain actions."),
    };
    for a in &action.patterns {
        if a != "*" && !a.contains(':') {
            return err("Actions/Conditions must be prefaced by a vendor, e.g., iam, sdb, ec2, etc.");
        }
    }

    let resource = match (obj.get("Resource"), obj.get("NotResource")) {
        (Some(_), Some(_)) => return err("Syntax errors in policy."),
        (Some(r), None) => Some(Matcher { negated: false, patterns: string_or_list(r)? }),
        (None, Some(r)) => Some(Matcher { negated: true, patterns: string_or_list(r)? }),
        (None, None) => None,
    };
    match kind {
        PolicyKind::Identity if resource.is_none() => return err("Policy statement must contain resources."),
        PolicyKind::Trust if resource.is_some() => return err("Has prohibited field Resource"),
        _ => {}
    }
    if let Some(r) = &resource {
        for p in &r.patterns {
            if p != "*" && !p.starts_with("arn:") {
                return err(format!("Resource {p} must be in ARN format or \"*\"."));
            }
        }
    }

    let conditions = match obj.get("Condition") {
        None => Vec::new(),
        Some(c) => condition::parse_block(c)?,
    };
    Ok(Statement { sid, effect, principal, action, resource, conditions })
}

fn parse_principal(v: &Value, negated: bool) -> Result<PrincipalMatcher, PolicyError> {
    let mut p = PrincipalMatcher {
        negated,
        any: false,
        aws: vec![],
        service: vec![],
        federated: vec![],
        canonical_user: vec![],
    };
    match v {
        Value::String(s) if s == "*" => p.any = true,
        Value::Object(map) => {
            for (k, val) in map {
                let list = string_or_list(val)?;
                match k.as_str() {
                    "AWS" => p.aws = list,
                    "Service" => p.service = list,
                    "Federated" => p.federated = list,
                    "CanonicalUser" => p.canonical_user = list,
                    _ => return err("Syntax errors in policy."),
                }
            }
        }
        _ => return err("Syntax errors in policy."),
    }
    for a in &p.aws {
        // IAM allows `*` on its own, never as part of an ARN; unique ids
        // (`AIDA...`, `AROA...`) are how IAM shows principals that have been
        // deleted since the policy was saved.
        let ok = a == "*"
            || (a.len() == 12 && a.chars().all(|c| c.is_ascii_digit()))
            || (a.starts_with("arn:") && !a.contains(['*', '?']))
            || is_unique_id(a);
        if !ok {
            return err(format!("Invalid principal in policy: \"AWS\":\"{a}\""));
        }
    }
    Ok(p)
}

/// An IAM unique id such as `AIDAJQABLZS4A3QDU576Q`.
pub fn is_unique_id(s: &str) -> bool {
    s.len() == 21 && s.starts_with('A') && s.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

fn match_principal(p: &PrincipalMatcher, who: &PrincipalInfo) -> Option<PrincipalMatch> {
    let m = principal_match_inner(p, who);
    if p.negated {
        // NotPrincipal applies to everyone *except* the listed principals.
        return if m.is_some() { None } else { Some(PrincipalMatch::Direct) };
    }
    m
}

fn principal_match_inner(p: &PrincipalMatcher, who: &PrincipalInfo) -> Option<PrincipalMatch> {
    if p.any {
        return Some(PrincipalMatch::Wildcard);
    }
    if who.anonymous {
        return p.aws.iter().any(|a| a == "*").then_some(PrincipalMatch::Wildcard);
    }
    if let Some(svc) = &who.service {
        if p.service.iter().any(|s| s == svc) {
            return Some(PrincipalMatch::Direct);
        }
    }
    if let Some(fed) = &who.federated {
        if p.federated.iter().any(|f| f == fed) {
            return Some(PrincipalMatch::Direct);
        }
    }
    let mut best = None;
    for a in &p.aws {
        if a == "*" {
            return Some(PrincipalMatch::Wildcard);
        }
        if who.arns.iter().any(|arn| arn == a) {
            return Some(PrincipalMatch::Direct);
        }
        if who.role_arn.as_deref() == Some(a.as_str()) {
            best = Some(PrincipalMatch::Role);
            continue;
        }
        let account_root = is_account_root(a);
        if account_root.as_deref() == Some(who.account_id.as_str()) && !who.account_id.is_empty() && best.is_none() {
            best = Some(PrincipalMatch::Account);
        }
    }
    best
}

/// `123456789012` or `arn:aws:iam::123456789012:root` → the account id.
fn is_account_root(principal: &str) -> Option<String> {
    if principal.len() == 12 && principal.chars().all(|c| c.is_ascii_digit()) {
        return Some(principal.to_string());
    }
    let parts: Vec<&str> = principal.splitn(6, ':').collect();
    if parts.len() == 6 && parts[2] == "iam" && parts[5] == "root" {
        return Some(parts[4].to_string());
    }
    None
}

fn matches_action(m: &Matcher, action: &str) -> bool {
    let hit = m.patterns.iter().any(|p| glob::glob_matches_ci(p, action));
    hit != m.negated
}

fn matches_resource(m: &Matcher, resource: &str, ctx: &ConditionContext, vars: bool) -> bool {
    let hit = m.patterns.iter().any(|p| {
        let pattern = if vars {
            match condition::substitute(p, ctx) {
                Some(p) => p,
                None => return false,
            }
        } else {
            p.clone()
        };
        glob::arn_matches(&pattern, resource)
    });
    hit != m.negated
}

#[cfg(test)]
mod tests;

//! The policy simulator, backed by the same engine that authorizes requests.

use std::collections::BTreeSet;

use mws_core::{RequestContext, ServiceError};
use mws_iam_policy::{decide, ConditionContext, Policy, PolicyKind, PolicySet, PrincipalInfo, Request, SourcedPolicy};

use crate::authz::boundary_doc;
use crate::common::*;
use crate::generated::{errors, types};
use crate::Iam;

struct SimInput {
    set: PolicySet,
    principal: PrincipalInfo,
    actions: Vec<String>,
    resources: Vec<String>,
    context: ConditionContext,
    max_items: Option<i32>,
    marker: Option<String>,
}

fn parse_inputs(docs: &[String], prefix: &str) -> Result<Vec<SourcedPolicy>, ServiceError> {
    docs.iter()
        .enumerate()
        .map(|(i, d)| {
            Policy::parse(d, PolicyKind::Identity)
                .map(|policy| SourcedPolicy { source_id: format!("{prefix}{}", i + 1), policy })
                .map_err(|e| errors::policy_evaluation(format!("Error parsing policy: {}", e.0)))
        })
        .collect()
}

fn context_from(entries: Option<Vec<types::ContextEntry>>) -> ConditionContext {
    let mut ctx = ConditionContext::new();
    for e in entries.unwrap_or_default() {
        if let Some(k) = e.context_key_name {
            ctx.insert(k, e.context_key_values.unwrap_or_default());
        }
    }
    ctx
}

fn run(sim: SimInput) -> Result<types::SimulatePolicyResponse, ServiceError> {
    let mut results = Vec::new();
    for action in &sim.actions {
        for resource in &sim.resources {
            let d = decide(&sim.set, &Request { action, resource, principal: &sim.principal, context: &sim.context });
            let decision = if d.allowed {
                "allowed"
            } else if d.deny_reason.as_ref().is_some_and(|r| r.is_explicit()) {
                "explicitDeny"
            } else {
                "implicitDeny"
            };
            let matched: Vec<types::Statement> = d
                .matched
                .iter()
                .map(|(src, _)| types::Statement {
                    source_policy_id: Some(src.clone()),
                    source_policy_type: Some("IAM Policy".into()),
                    start_position: None,
                    end_position: None,
                })
                .collect();
            let missing: BTreeSet<String> = sim
                .set
                .identity
                .iter()
                .chain(sim.set.boundary.iter())
                .chain(sim.set.resource.iter())
                .flat_map(|p| p.policy.statements.iter())
                .flat_map(|s| s.conditions.iter().map(|c| c.key.clone()))
                .filter(|k| !sim.context.contains(k))
                .collect();
            use mws_iam_policy::DenyReason;
            let reason = d.deny_reason.as_ref();
            // Present only when SCPs or a boundary took part.
            let organizations = sim.set.service_control.as_ref().map(|_| types::OrganizationsDecisionDetail {
                allowed_by_organizations: !matches!(
                    reason,
                    Some(DenyReason::ExplicitServiceControl | DenyReason::NoServiceControlAllow)
                ),
            });
            let boundary = sim.set.boundary.as_ref().map(|_| types::PermissionsBoundaryDecisionDetail {
                allowed_by_permissions_boundary: !matches!(
                    reason,
                    Some(DenyReason::ExplicitBoundary | DenyReason::NoBoundaryAllow)
                ),
            });
            results.push(types::EvaluationResult {
                eval_action_name: action.clone(),
                eval_resource_name: Some(resource.clone()),
                eval_decision: decision.into(),
                matched_statements: Some(matched),
                missing_context_values: Some(missing.into_iter().collect()),
                organizations_decision_detail: organizations,
                permissions_boundary_decision_detail: boundary,
                ..Default::default()
            });
        }
    }
    let indexed: Vec<(usize, types::EvaluationResult)> = results.into_iter().enumerate().collect();
    let (page, truncated, marker) =
        paginate(&indexed, |(i, _)| format!("{i:010}"), sim.marker.as_deref(), sim.max_items)?;
    Ok(types::SimulatePolicyResponse {
        evaluation_results: Some(page.into_iter().map(|(_, r)| r).collect()),
        is_truncated: truncated,
        marker,
    })
}

fn condition_keys(policies: &[SourcedPolicy]) -> Vec<String> {
    let keys: BTreeSet<String> = policies
        .iter()
        .flat_map(|p| p.policy.statements.iter())
        .flat_map(|s| s.conditions.iter().map(|c| c.key.clone()))
        .collect();
    keys.into_iter().collect()
}

/// A principal's identity policies with their origins, its boundary, and
/// the principal itself.
type PrincipalPolicies = (Vec<(SourcedPolicy, Origin)>, Option<SourcedPolicy>, PrincipalInfo);

/// Where a principal's identity policy comes from, for PolicyExclusionList.
enum Origin {
    Inline { kind: &'static str, owner: String },
    Managed { aws: bool },
}

/// Glob with `*` (any run) and `?` (one character), as exclusions use.
fn glob(pattern: &str, text: &str) -> bool {
    match (pattern.chars().next(), text.chars().next()) {
        (None, None) => true,
        (Some('*'), _) => {
            glob(&pattern[1..], text)
                || (!text.is_empty() && glob(pattern, &text[text.chars().next().map_or(0, char::len_utf8)..]))
        }
        (Some('?'), Some(c)) => glob(&pattern[1..], &text[c.len_utf8()..]),
        (Some(p), Some(c)) if p == c => glob(&pattern[p.len_utf8()..], &text[c.len_utf8()..]),
        _ => false,
    }
}

fn validate_exclusion(e: &types::PolicyIdentifier) -> Result<(), ServiceError> {
    let bad = |what: &str| Err(errors::invalid_input(format!("Invalid PolicyExclusionList entry: {what}")));
    match e {
        types::PolicyIdentifier::PolicyArn(arn) => {
            let parts: Vec<&str> = arn.splitn(6, ':').collect();
            if parts.len() != 6 || parts[0] != "arn" || parts[2] != "iam" || !parts[5].starts_with("policy/") {
                return bad(arn);
            }
            // Wildcards only in the resource name, at most one `*`.
            if parts[..5].iter().any(|p| p.contains(['*', '?'])) || parts[5].matches('*').count() > 1 {
                return bad(arn);
            }
        }
        types::PolicyIdentifier::InlinePolicyIdentifier(i) => {
            if i.attachment_name.matches('*').count() > 1 {
                return bad(&i.attachment_name);
            }
        }
        types::PolicyIdentifier::PolicyType(_) => {}
    }
    Ok(())
}

fn excludes(e: &types::PolicyIdentifier, id: &str, origin: &Origin) -> bool {
    match (e, origin) {
        (types::PolicyIdentifier::PolicyType(t), Origin::Inline { .. }) => t == "inline",
        (types::PolicyIdentifier::PolicyType(t), Origin::Managed { aws }) => {
            t == if *aws { "aws-managed" } else { "user-managed" }
        }
        (types::PolicyIdentifier::PolicyArn(arn), Origin::Managed { .. }) => glob(arn, id),
        (types::PolicyIdentifier::InlinePolicyIdentifier(i), Origin::Inline { kind, owner }) => {
            i.policy_name == id && i.attachment_type == *kind && glob(&i.attachment_name, owner)
        }
        _ => false,
    }
}

impl Iam {
    /// Identity policies (each with where it comes from), boundary and
    /// principal for a user/group/role ARN.
    fn source_policies(&self, arn: &str) -> Result<PrincipalPolicies, ServiceError> {
        let state = self.read();
        let resource = arn.splitn(6, ':').nth(5).unwrap_or_default();
        let name = resource.rsplit('/').next().unwrap_or_default();
        let principal = PrincipalInfo {
            account_id: self.account_id().to_string(),
            arns: vec![arn.to_string()],
            ..Default::default()
        };
        let mut docs: Vec<(String, String, Origin)> = vec![];
        let mut add = |inline: &std::collections::BTreeMap<String, String>,
                       attached: &std::collections::BTreeSet<String>,
                       kind: &'static str,
                       owner: &str| {
            for (n, d) in inline {
                docs.push((n.clone(), d.clone(), Origin::Inline { kind, owner: owner.to_string() }));
            }
            for p in attached {
                if let Some(mp) = state.policies.get(p) {
                    docs.push((p.clone(), mp.default_document().to_string(), Origin::Managed { aws: mp.aws_managed }));
                }
            }
        };
        let boundary = if resource.starts_with("user/") {
            let u = state.user(name).filter(|u| u.arn == arn).ok_or_else(|| no_such_user(name))?;
            add(&u.inline, &u.attached, "user", &u.name);
            for g in state.groups_for_user(name) {
                add(&g.inline, &g.attached, "group", &g.name);
            }
            boundary_doc(&state, &u.permissions_boundary)
        } else if resource.starts_with("role/") {
            let r = state.role(name).filter(|r| r.arn == arn).ok_or_else(|| no_such_role(name))?;
            add(&r.inline, &r.attached, "role", &r.name);
            boundary_doc(&state, &r.permissions_boundary)
        } else if resource.starts_with("group/") {
            let g = state.group(name).filter(|g| g.arn == arn).ok_or_else(|| no_such_group(name))?;
            add(&g.inline, &g.attached, "group", &g.name);
            None
        } else {
            return Err(errors::no_such_entity(format!("The entity with ARN {arn} cannot be found.")));
        };
        let identity = docs
            .into_iter()
            .filter_map(|(id, d, origin)| {
                Policy::parse(&d, PolicyKind::Identity)
                    .ok()
                    .map(|policy| (SourcedPolicy { source_id: id, policy }, origin))
            })
            .collect();
        Ok((identity, boundary, principal))
    }

    pub fn simulate_principal_policy(
        &self,
        ctx: &RequestContext,
        input: types::SimulatePrincipalPolicyRequest,
    ) -> Result<types::SimulatePolicyResponse, ServiceError> {
        self.authorize(ctx, "SimulatePrincipalPolicy", &input.policy_source_arn)?;
        // SCPs that apply to the principal's account (asked before the IAM
        // lock is taken).
        let account = input.policy_source_arn.split(':').nth(4).unwrap_or_default().to_string();
        let service_control = self
            .organization_of(&account)
            .and_then(|o| o.service_control_policies)
            .map(|levels| crate::authz::parse_levels(&levels, PolicyKind::ServiceControl));
        let (sourced, mut boundary, principal) = self.source_policies(&input.policy_source_arn)?;
        let mut service_control = service_control;
        let excluded = input.policy_exclusion_list.unwrap_or_default();
        for e in &excluded {
            validate_exclusion(e)?;
        }
        let is_excluded = |p: &SourcedPolicy, o: &Origin| excluded.iter().any(|e| excludes(e, &p.source_id, o));
        let mut identity: Vec<SourcedPolicy> =
            sourced.into_iter().filter(|(p, o)| !is_excluded(p, o)).map(|(p, _)| p).collect();
        for e in &excluded {
            match e {
                types::PolicyIdentifier::PolicyType(t) if t == "permission-boundary" => boundary = None,
                types::PolicyIdentifier::PolicyType(t) if t == "scp" => service_control = None,
                _ => {}
            }
        }
        identity.extend(parse_inputs(&input.policy_input_list.unwrap_or_default(), "PolicyInputList.")?);
        if let Some(b) = input.permissions_boundary_policy_input_list {
            boundary = parse_inputs(&b, "PermissionsBoundaryPolicyInputList.")?.into_iter().next();
        }
        let resource = match input.resource_policy {
            Some(doc) => Some(SourcedPolicy {
                source_id: "ResourcePolicy".into(),
                policy: Policy::parse(&doc, PolicyKind::Resource).map_err(|e| errors::policy_evaluation(e.0))?,
            }),
            None => None,
        };
        run(SimInput {
            set: PolicySet { identity, boundary, resource, service_control, ..Default::default() },
            principal,
            actions: input.action_names,
            resources: input.resource_arns.unwrap_or_else(|| vec!["*".into()]),
            context: context_from(input.context_entries),
            max_items: input.max_items,
            marker: input.marker,
        })
    }

    pub fn simulate_custom_policy(
        &self,
        ctx: &RequestContext,
        input: types::SimulateCustomPolicyRequest,
    ) -> Result<types::SimulatePolicyResponse, ServiceError> {
        self.authorize(ctx, "SimulateCustomPolicy", "*")?;
        let identity = parse_inputs(&input.policy_input_list, "PolicyInputList.")?;
        let boundary = match input.permissions_boundary_policy_input_list {
            Some(b) => parse_inputs(&b, "PermissionsBoundaryPolicyInputList.")?.into_iter().next(),
            None => None,
        };
        let resource = match input.resource_policy {
            Some(doc) => Some(SourcedPolicy {
                source_id: "ResourcePolicy".into(),
                policy: Policy::parse(&doc, PolicyKind::Resource).map_err(|e| errors::policy_evaluation(e.0))?,
            }),
            None => None,
        };
        let caller = input.caller_arn.unwrap_or_else(|| self.arn("user/simulated"));
        let service_control = match input.ordered_organization_policy_input_list {
            Some(levels) if !levels.is_empty() => Some(
                levels
                    .iter()
                    .enumerate()
                    .map(|(i, level)| {
                        level
                            .service_control_policy_input_list
                            .iter()
                            .flatten()
                            .enumerate()
                            .map(|(j, d)| {
                                Policy::parse(d, PolicyKind::ServiceControl)
                                    .map(|policy| SourcedPolicy {
                                        source_id: format!("OrderedOrganizationPolicyInputList.{}.{}", i + 1, j + 1),
                                        policy,
                                    })
                                    .map_err(|e| errors::policy_evaluation(format!("Error parsing policy: {}", e.0)))
                            })
                            .collect::<Result<Vec<_>, _>>()
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            ),
            _ => None,
        };
        run(SimInput {
            set: PolicySet { identity, boundary, resource, service_control, ..Default::default() },
            principal: PrincipalInfo {
                account_id: self.account_id().to_string(),
                arns: vec![caller],
                ..Default::default()
            },
            actions: input.action_names,
            resources: input.resource_arns.unwrap_or_else(|| vec!["*".into()]),
            context: context_from(input.context_entries),
            max_items: input.max_items,
            marker: input.marker,
        })
    }

    pub fn get_context_keys_for_custom_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetContextKeysForCustomPolicyRequest,
    ) -> Result<types::GetContextKeysForPolicyResponse, ServiceError> {
        self.authorize(ctx, "GetContextKeysForCustomPolicy", "*")?;
        let policies = parse_inputs(&input.policy_input_list, "PolicyInputList.")?;
        Ok(types::GetContextKeysForPolicyResponse { context_key_names: Some(condition_keys(&policies)) })
    }

    pub fn get_context_keys_for_principal_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetContextKeysForPrincipalPolicyRequest,
    ) -> Result<types::GetContextKeysForPolicyResponse, ServiceError> {
        self.authorize(ctx, "GetContextKeysForPrincipalPolicy", &input.policy_source_arn)?;
        let (sourced, _, _) = self.source_policies(&input.policy_source_arn)?;
        let mut policies: Vec<SourcedPolicy> = sourced.into_iter().map(|(p, _)| p).collect();
        policies.extend(parse_inputs(&input.policy_input_list.unwrap_or_default(), "PolicyInputList.")?);
        Ok(types::GetContextKeysForPolicyResponse { context_key_names: Some(condition_keys(&policies)) })
    }
}

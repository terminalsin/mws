//! The policy simulator, backed by the same engine that authorizes requests.

use std::collections::BTreeSet;

use mws_core::{RequestContext, ServiceError};
use mws_iam_policy::{decide, ConditionContext, Policy, PolicyKind, PolicySet, PrincipalInfo, Request, SourcedPolicy};

use crate::authz::{boundary_doc, role_policy_docs, user_policy_docs};
use crate::common::*;
use crate::generated::{errors, types};
use crate::Iam;

struct SimInput {
    set: PolicySet,
    principal: PrincipalInfo,
    actions: Vec<String>,
    resources: Vec<String>,
    context: ConditionContext,
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

fn run(sim: SimInput) -> types::SimulatePolicyResponse {
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
            results.push(types::EvaluationResult {
                eval_action_name: action.clone(),
                eval_resource_name: Some(resource.clone()),
                eval_decision: decision.into(),
                matched_statements: Some(matched),
                missing_context_values: Some(missing.into_iter().collect()),
                ..Default::default()
            });
        }
    }
    types::SimulatePolicyResponse { evaluation_results: Some(results), is_truncated: false, marker: None }
}

fn condition_keys(policies: &[SourcedPolicy]) -> Vec<String> {
    let keys: BTreeSet<String> = policies
        .iter()
        .flat_map(|p| p.policy.statements.iter())
        .flat_map(|s| s.conditions.iter().map(|c| c.key.clone()))
        .collect();
    keys.into_iter().collect()
}

impl Iam {
    /// Identity policies, boundary and principal for a user/group/role ARN.
    fn source_policies(
        &self,
        arn: &str,
    ) -> Result<(Vec<SourcedPolicy>, Option<SourcedPolicy>, PrincipalInfo), ServiceError> {
        let state = self.read();
        let resource = arn.splitn(6, ':').nth(5).unwrap_or_default();
        let name = resource.rsplit('/').next().unwrap_or_default();
        let parse = |docs: Vec<(String, String)>| -> Vec<SourcedPolicy> {
            docs.into_iter()
                .filter_map(|(id, d)| {
                    Policy::parse(&d, PolicyKind::Identity).ok().map(|policy| SourcedPolicy { source_id: id, policy })
                })
                .collect()
        };
        let principal = PrincipalInfo {
            account_id: self.account_id().to_string(),
            arns: vec![arn.to_string()],
            ..Default::default()
        };
        if resource.starts_with("user/") {
            let u = state.user(name).filter(|u| u.arn == arn).ok_or_else(|| no_such_user(name))?;
            Ok((parse(user_policy_docs(&state, name)), boundary_doc(&state, &u.permissions_boundary), principal))
        } else if resource.starts_with("role/") {
            let r = state.role(name).filter(|r| r.arn == arn).ok_or_else(|| no_such_role(name))?;
            Ok((parse(role_policy_docs(&state, name)), boundary_doc(&state, &r.permissions_boundary), principal))
        } else if resource.starts_with("group/") {
            let g = state.group(name).filter(|g| g.arn == arn).ok_or_else(|| no_such_group(name))?;
            let mut docs: Vec<(String, String)> = g.inline.iter().map(|(n, d)| (n.clone(), d.clone())).collect();
            for p in &g.attached {
                if let Some(mp) = state.policies.get(p) {
                    docs.push((p.clone(), mp.default_document().to_string()));
                }
            }
            Ok((parse(docs), None, principal))
        } else {
            Err(errors::no_such_entity(format!("The entity with ARN {arn} cannot be found.")))
        }
    }

    pub fn simulate_principal_policy(
        &self,
        ctx: &RequestContext,
        input: types::SimulatePrincipalPolicyRequest,
    ) -> Result<types::SimulatePolicyResponse, ServiceError> {
        self.authorize(ctx, "SimulatePrincipalPolicy", &input.policy_source_arn)?;
        let (mut identity, mut boundary, principal) = self.source_policies(&input.policy_source_arn)?;
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
        Ok(run(SimInput {
            set: PolicySet { identity, boundary, resource, ..Default::default() },
            principal,
            actions: input.action_names,
            resources: input.resource_arns.unwrap_or_else(|| vec!["*".into()]),
            context: context_from(input.context_entries),
        }))
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
        Ok(run(SimInput {
            set: PolicySet { identity, boundary, resource, ..Default::default() },
            principal: PrincipalInfo {
                account_id: self.account_id().to_string(),
                arns: vec![caller],
                ..Default::default()
            },
            actions: input.action_names,
            resources: input.resource_arns.unwrap_or_else(|| vec!["*".into()]),
            context: context_from(input.context_entries),
        }))
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
        let (mut policies, _, _) = self.source_policies(&input.policy_source_arn)?;
        policies.extend(parse_inputs(&input.policy_input_list.unwrap_or_default(), "PolicyInputList.")?);
        Ok(types::GetContextKeysForPolicyResponse { context_key_names: Some(condition_keys(&policies)) })
    }
}

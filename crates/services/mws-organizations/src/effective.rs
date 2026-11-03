//! Effective management policies (tag, backup, AI opt-out, chatbot,
//! declarative, ... policies): the result of merging every policy of a type
//! from the root down to an account with the inheritance operators
//! (`@@assign`, `@@append`, `@@remove`, `@@operators_allowed_for_child_policies`).
//! <https://docs.aws.amazon.com/organizations/latest/userguide/policy-operators.html>

use chrono::Utc;
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::{Map, Value};

use crate::access::*;
use crate::generated::{errors, types};
use crate::state::Org;
use crate::Organizations;

const ASSIGN: &str = "@@assign";
const APPEND: &str = "@@append";
const REMOVE: &str = "@@remove";
const CHILD_OPERATORS: &str = "@@operators_allowed_for_child_policies";

fn not_found() -> ServiceError {
    errors::effective_policy_not_found(
        "If you ran this action on the management account, this policy type is not enabled. If you ran the action on a member account, the account doesn't have an effective policy of this type. Contact the administrator of your organization.",
    )
}

/// Whether a parent's `@@operators_allowed_for_child_policies` lets a child
/// use `op`.
fn allowed(node: &Map<String, Value>, op: &str) -> bool {
    match node.get(CHILD_OPERATORS).and_then(Value::as_array) {
        None => true,
        Some(ops) => ops.iter().any(|o| o == op || o == "@@all"),
    }
}

fn as_list(v: Option<&Value>) -> Vec<Value> {
    match v {
        Some(Value::Array(a)) => a.clone(),
        Some(Value::Null) | None => vec![],
        Some(other) => vec![other.clone()],
    }
}

/// Apply one policy (or a part of one) on top of what the levels above set.
fn apply(effective: &mut Map<String, Value>, policy: &Map<String, Value>) {
    for (key, value) in policy {
        match key.as_str() {
            ASSIGN => {
                if allowed(effective, ASSIGN) {
                    effective.insert(ASSIGN.into(), value.clone());
                }
            }
            APPEND => {
                if allowed(effective, APPEND) {
                    let mut list = as_list(effective.get(ASSIGN));
                    for v in as_list(Some(value)) {
                        if !list.contains(&v) {
                            list.push(v);
                        }
                    }
                    effective.insert(ASSIGN.into(), Value::Array(list));
                }
            }
            REMOVE => {
                if allowed(effective, REMOVE) {
                    let remove = as_list(Some(value));
                    let list: Vec<Value> =
                        as_list(effective.get(ASSIGN)).into_iter().filter(|v| !remove.contains(v)).collect();
                    effective.insert(ASSIGN.into(), Value::Array(list));
                }
            }
            CHILD_OPERATORS => {
                effective.insert(CHILD_OPERATORS.into(), value.clone());
            }
            _ => match value {
                Value::Object(child) => {
                    let entry = effective.entry(key.clone()).or_insert_with(|| Value::Object(Map::new()));
                    if !entry.is_object() {
                        *entry = Value::Object(Map::new());
                    }
                    if let Value::Object(e) = entry {
                        apply(e, child);
                    }
                }
                other => {
                    effective.insert(key.clone(), other.clone());
                }
            },
        }
    }
}

/// Strip operators: `{"@@assign": x}` becomes `x`.
fn finalize(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            if let Some(assigned) = m.get(ASSIGN) {
                return finalize(assigned);
            }
            Value::Object(
                m.iter().filter(|(k, _)| !k.starts_with("@@")).map(|(k, v)| (k.clone(), finalize(v))).collect(),
            )
        }
        Value::Array(a) => Value::Array(a.iter().map(finalize).collect()),
        other => other.clone(),
    }
}

/// The effective policy of `ty` for `account`, or `None` if no policy of the
/// type applies.
pub(crate) fn effective_policy(org: &Org, account: &str, ty: &str) -> Option<String> {
    if !org.type_enabled(ty) {
        return None;
    }
    let mut merged = Map::new();
    let mut any = false;
    for target in org.lineage(account) {
        for p in org.attached(&target).iter().filter_map(|id| org.policy(id)).filter(|p| p.ty == ty) {
            if let Ok(Value::Object(doc)) = serde_json::from_str::<Value>(&p.content) {
                apply(&mut merged, &doc);
                any = true;
            }
        }
    }
    any.then(|| finalize(&Value::Object(merged)).to_string())
}

impl Organizations {
    pub(crate) fn describe_effective_policy(
        &self,
        ctx: &RequestContext,
        input: types::DescribeEffectivePolicyRequest,
    ) -> Result<types::DescribeEffectivePolicyResponse, ServiceError> {
        let caller = ctx.caller.account_id.clone();
        let target = input.target_id.clone().unwrap_or_else(|| caller.clone());
        let arn = {
            let state = self.lock();
            let org = state.org_of(&caller).ok_or_else(not_in_use)?;
            if target == org.root_id || org.is_ou(&target) {
                return Err(invalid(
                    "TARGET_NOT_SUPPORTED",
                    "You can't perform this operation on the specified target. Specify an account.",
                ));
            }
            if !org.members.contains_key(&target) {
                return Err(target_not_found());
            }
            org.account_arn(&ctx.partition, &target)
        };
        self.authorize(
            ctx,
            "DescribeEffectivePolicy",
            &arn,
            [("organizations:PolicyType".to_string(), vec![input.policy_type.clone()])].into_iter().collect(),
        )?;
        let state = self.lock();
        let org = if target == caller {
            state.org_of(&caller).ok_or_else(not_in_use)?
        } else {
            self.caller_org(&state, ctx, "DescribeEffectivePolicy", &arn, Need::Read)?
        };
        let content = effective_policy(org, &target, &input.policy_type).ok_or_else(not_found)?;
        Ok(types::DescribeEffectivePolicyResponse {
            effective_policy: Some(types::EffectivePolicy {
                policy_content: Some(content),
                last_updated_timestamp: Some(Utc::now()),
                target_id: Some(target),
                policy_type: Some(input.policy_type),
            }),
        })
    }

    pub(crate) fn list_accounts_with_invalid_effective_policy(
        &self,
        ctx: &RequestContext,
        input: types::ListAccountsWithInvalidEffectivePolicyRequest,
    ) -> Result<types::ListAccountsWithInvalidEffectivePolicyResponse, ServiceError> {
        self.authorize(ctx, "ListAccountsWithInvalidEffectivePolicy", "*", ConditionContext::new())?;
        let state = self.lock();
        let org = self.caller_org(&state, ctx, "ListAccountsWithInvalidEffectivePolicy", "*", Need::Read)?;
        if !org.type_enabled(&input.policy_type) {
            return Err(not_found());
        }
        // Merging never fails in MWS, so no account has an invalid policy.
        let (accounts, next_token) =
            page(Vec::<types::Account>::new(), input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListAccountsWithInvalidEffectivePolicyResponse {
            accounts: Some(accounts),
            policy_type: Some(input.policy_type),
            next_token,
        })
    }

    pub(crate) fn list_effective_policy_validation_errors(
        &self,
        ctx: &RequestContext,
        input: types::ListEffectivePolicyValidationErrorsRequest,
    ) -> Result<types::ListEffectivePolicyValidationErrorsResponse, ServiceError> {
        self.authorize(ctx, "ListEffectivePolicyValidationErrors", "*", ConditionContext::new())?;
        let state = self.lock();
        let org = self.caller_org(&state, ctx, "ListEffectivePolicyValidationErrors", "*", Need::Read)?;
        if !org.members.contains_key(&input.account_id) {
            return Err(account_not_found());
        }
        if effective_policy(org, &input.account_id, &input.policy_type).is_none() {
            return Err(not_found());
        }
        let (errors, next_token) =
            page(Vec::<types::EffectivePolicyValidationError>::new(), input.next_token.as_deref(), input.max_results)?;
        Ok(types::ListEffectivePolicyValidationErrorsResponse {
            account_id: Some(input.account_id.clone()),
            policy_type: Some(input.policy_type),
            path: Some(org.account_path(&input.account_id)),
            evaluation_timestamp: Some(Utc::now()),
            next_token,
            effective_policy_validation_errors: Some(errors),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn merge(docs: &[&str]) -> Value {
        let mut m = Map::new();
        for d in docs {
            let Value::Object(o) = serde_json::from_str(d).unwrap() else { panic!() };
            apply(&mut m, &o);
        }
        finalize(&Value::Object(m))
    }

    #[test]
    fn inheritance_operators() {
        let root =
            r#"{"tags":{"costcenter":{"tag_key":{"@@assign":"CostCenter"},"tag_value":{"@@assign":["100","200"]}}}}"#;
        let ou = r#"{"tags":{"costcenter":{"tag_value":{"@@append":["300"]}}}}"#;
        let acct = r#"{"tags":{"costcenter":{"tag_value":{"@@remove":["100"]}}}}"#;
        assert_eq!(
            merge(&[root, ou, acct]),
            serde_json::json!({"tags":{"costcenter":{"tag_key":"CostCenter","tag_value":["200","300"]}}})
        );
    }

    #[test]
    fn parents_can_lock_children_out() {
        let root =
            r#"{"tags":{"env":{"tag_key":{"@@assign":"Env","@@operators_allowed_for_child_policies":["@@none"]}}}}"#;
        let child = r#"{"tags":{"env":{"tag_key":{"@@assign":"Environment"}}}}"#;
        assert_eq!(merge(&[root, child]), serde_json::json!({"tags":{"env":{"tag_key":"Env"}}}));
    }
}

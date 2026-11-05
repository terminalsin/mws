//! Turning shares into resource-based policies, and installing them.

use std::collections::BTreeSet;

use chrono::Duration;
use mws_core::RequestContext;
use serde_json::{json, Map, Value};

use crate::catalog;
use crate::principals::PrincipalKind;
use crate::state::{Share, State};
use crate::Ram;

/// How long an invitation stays open.
pub const INVITATION_DAYS: i64 = 7;

/// The statements of a permission template: a single statement or a
/// document with a `Statement` list.
pub fn template_statements(template: &str) -> Vec<Value> {
    match serde_json::from_str::<Value>(template) {
        Ok(Value::Object(o)) => match o.get("Statement") {
            Some(Value::Array(a)) => a.clone(),
            Some(one @ Value::Object(_)) => vec![one.clone()],
            _ => vec![Value::Object(o)],
        },
        Ok(Value::Array(a)) => a,
        _ => Vec::new(),
    }
}

fn add_condition(statement: &mut Value, operator: &str, key: &str, value: Value) {
    let conditions = statement
        .as_object_mut()
        .expect("statement is an object")
        .entry("Condition")
        .or_insert_with(|| Value::Object(Map::new()));
    let Some(conditions) = conditions.as_object_mut() else { return };
    let op = conditions.entry(operator.to_string()).or_insert_with(|| Value::Object(Map::new()));
    if let Some(op) = op.as_object_mut() {
        op.insert(key.to_string(), value);
    }
}

impl State {
    /// The template of `arn` at `version` (AWS managed or customer managed).
    pub fn permission_template(&self, partition: &str, arn: &str, version: u32) -> Option<String> {
        if let Some(m) = catalog::find(arn) {
            return Some(m.template(partition));
        }
        self.permissions.get(arn)?.versions.get(&version).map(|v| v.template.clone())
    }
}

impl Ram {
    /// The policy RAM's standard shares give `resource`, if any share
    /// grants anything on it.
    pub(crate) fn policy_for(&self, st: &State, partition: &str, resource: &str) -> Option<String> {
        let mut statements = Vec::new();
        for share in st.shares.values() {
            if share.status != "ACTIVE" || share.feature_set != "STANDARD" {
                continue;
            }
            let Some(assoc) = share.resources.iter().find(|r| r.entity == resource && r.status == "ASSOCIATED") else {
                continue;
            };
            let ty = assoc.resource_type.clone().unwrap_or_default();
            let principals: Vec<&str> =
                share.principals.iter().filter(|p| p.status == "ASSOCIATED").map(|p| p.entity.as_str()).collect();
            if principals.is_empty() {
                continue;
            }
            let id = share.arn.rsplit('/').next().unwrap_or_default().replace('-', "");
            let mut n = 0;
            for perm in share.permissions.iter().filter(|p| p.resource_type == ty) {
                let Some(template) = st.permission_template(partition, &perm.arn, perm.version) else { continue };
                for base in template_statements(&template) {
                    for principal in &principals {
                        n += 1;
                        let mut s = base.clone();
                        if !s.is_object() {
                            continue;
                        }
                        s["Sid"] = json!(format!("RAM{id}{n}"));
                        s["Resource"] = json!(resource);
                        self.bind_principal(&mut s, share, principal, partition);
                        statements.push(s);
                    }
                }
            }
        }
        (!statements.is_empty()).then(|| json!({ "Version": "2012-10-17", "Statement": statements }).to_string())
    }

    fn bind_principal(&self, s: &mut Value, share: &Share, principal: &str, partition: &str) {
        match PrincipalKind::parse(principal) {
            Ok(PrincipalKind::Account(a)) => s["Principal"] = json!({ "AWS": format!("arn:{partition}:iam::{a}:root") }),
            Ok(PrincipalKind::Iam { arn, .. }) => s["Principal"] = json!({ "AWS": arn }),
            Ok(PrincipalKind::Organization { org_id }) => {
                s["Principal"] = json!("*");
                add_condition(s, "StringEquals", "aws:PrincipalOrgID", json!(org_id));
                add_condition(s, "StringNotEquals", "aws:PrincipalAccount", json!(share.owner));
            }
            Ok(PrincipalKind::OrganizationalUnit { org_id, ou_id }) => {
                s["Principal"] = json!("*");
                add_condition(s, "ForAnyValue:StringLike", "aws:PrincipalOrgPaths", json!(format!("{org_id}/*/{ou_id}/*")));
                add_condition(s, "StringNotEquals", "aws:PrincipalAccount", json!(share.owner));
            }
            Ok(PrincipalKind::Service(svc)) => {
                s["Principal"] = json!({ "Service": svc });
                let sources = |ty: &str| -> Vec<String> {
                    share
                        .sources
                        .iter()
                        .filter(|x| x.status == "ASSOCIATED" && x.source_type.as_deref() == Some(ty))
                        .map(|x| x.entity.clone())
                        .collect()
                };
                let (accounts, arns) = (sources("ACCOUNT"), sources("ARN"));
                if !accounts.is_empty() {
                    add_condition(s, "StringEquals", "aws:SourceAccount", json!(accounts));
                }
                if !arns.is_empty() {
                    add_condition(s, "ArnLike", "aws:SourceArn", json!(arns));
                }
            }
            Err(_) => s["Principal"] = json!({ "AWS": principal }),
        }
    }

    /// Recompute and install the policies of `resources`. Takes the state
    /// lock itself; call without holding it.
    pub(crate) fn push_policies(&self, partition: &str, resources: impl IntoIterator<Item = String>) {
        let resources: BTreeSet<String> = resources.into_iter().collect();
        let policies: Vec<(String, Option<String>)> = {
            let st = self.lock();
            resources.into_iter().map(|r| (r.clone(), self.policy_for(&st, partition, &r))).collect()
        };
        for (resource, policy) in policies {
            if let Some(ty) = self.type_for_arn(&resource) {
                ty.set_shared_policy(&resource, policy);
            }
        }
    }

    /// Reinstall every shared resource's policy (after importing state).
    pub(crate) fn push_all_policies(&self) {
        let (resources, partition): (Vec<String>, String) = {
            let st = self.lock();
            let resources = st.shares.values().flat_map(|s| s.resources.iter().map(|r| r.entity.clone())).collect();
            let partition = st
                .shares
                .keys()
                .next()
                .and_then(|a| a.split(':').nth(1))
                .unwrap_or("aws")
                .to_string();
            (resources, partition)
        };
        self.push_policies(&partition, resources);
    }

    /// Resources in `share`, for pushing after a change.
    pub(crate) fn share_resources(&self, share_arn: &str) -> Vec<String> {
        self.lock().shares.get(share_arn).map(|s| s.resources.iter().map(|r| r.entity.clone()).collect()).unwrap_or_default()
    }

    /// Expire invitations that have been pending too long.
    pub(crate) fn advance(&self, ctx: &RequestContext) {
        let now = ctx.received_at;
        let mut st = self.lock();
        let expired: Vec<(String, String, String)> = st
            .invitations
            .values()
            .filter(|i| i.status == "PENDING" && i.created.is_some_and(|c| now - c > Duration::days(INVITATION_DAYS)))
            .map(|i| (i.arn.clone(), i.share_arn.clone(), i.receiver_arn.clone().unwrap_or_else(|| i.receiver.clone())))
            .collect();
        for (arn, share, receiver) in expired {
            if let Some(i) = st.invitations.get_mut(&arn) {
                i.status = "EXPIRED".into();
            }
            if let Some(s) = st.shares.get_mut(&share) {
                for p in s.principals.iter_mut().filter(|p| p.entity == receiver && p.status == "ASSOCIATING") {
                    p.status = "FAILED".into();
                    p.status_message = Some("The invitation expired before it was accepted.".into());
                    p.updated = now;
                }
            }
        }
    }
}

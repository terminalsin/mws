//! Access entries (which IAM principals reach the cluster, as which
//! Kubernetes user and groups) and the access policies associated with
//! them.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::catalog;
use crate::generated::{errors, types};
use crate::state::{AccessEntryRec, ClusterRec};
use crate::util::{self, text};
use crate::Eks;

const TYPES: &[&str] =
    &["STANDARD", "EC2_LINUX", "EC2_WINDOWS", "FARGATE_LINUX", "EC2", "HYBRID_LINUX", "HYPERPOD_LINUX"];
const RESERVED: &[&str] = &["system:", "eks:", "aws:", "amazon:", "iam:"];

/// A new access entry for `principal` (an IAM role or user ARN).
pub(crate) fn new_entry(
    ctx: &RequestContext,
    cluster: &str,
    principal: &str,
    kind: &str,
    username: Option<String>,
    groups: Vec<String>,
    tags: Option<BTreeMap<String, String>>,
) -> types::AccessEntry {
    let (acct, iam_kind, name) = util::iam_principal(principal).unwrap_or((util::account(ctx), "user", "root"));
    let username = username.unwrap_or_else(|| default_username(&ctx.partition, principal, kind));
    let now = ctx.received_at;
    types::AccessEntry {
        cluster_name: Some(cluster.into()),
        principal_arn: Some(principal.into()),
        kubernetes_groups: Some(groups),
        access_entry_arn: Some(util::arn(
            ctx,
            &format!("access-entry/{cluster}/{iam_kind}/{acct}/{name}/{}", util::uuid()),
        )),
        created_at: Some(now),
        modified_at: Some(now),
        tags: Some(tags.unwrap_or_default()),
        username: Some(username),
        r#type: Some(kind.into()),
    }
}

fn default_username(partition: &str, principal: &str, kind: &str) -> String {
    match kind {
        "EC2_LINUX" | "EC2_WINDOWS" => "system:node:{{EC2PrivateDNSName}}".into(),
        "FARGATE_LINUX" | "HYBRID_LINUX" | "HYPERPOD_LINUX" => "system:node:{{SessionName}}".into(),
        "EC2" => "system:node:{{EC2PrivateDNSName}}".into(),
        _ => match util::iam_principal(principal) {
            Some((acct, "role", name)) => {
                format!("arn:{partition}:sts::{acct}:assumed-role/{name}/{{{{SessionName}}}}")
            }
            _ => principal.into(),
        },
    }
}

/// When a cluster's authentication mode moves to an API mode, EKS gives
/// managed node groups and Fargate profiles their access entries.
pub(crate) fn backfill_node_entries(ctx: &RequestContext, rec: &mut ClusterRec) {
    let cluster = rec.cluster.name.clone().unwrap_or_default();
    let mut wanted: Vec<(String, &str)> = Vec::new();
    for n in rec.nodegroups.values() {
        if let Some(role) = &n.nodegroup.node_role {
            let kind = if n.nodegroup.ami_type.as_deref().is_some_and(|a| a.starts_with("WINDOWS")) {
                "EC2_WINDOWS"
            } else {
                "EC2_LINUX"
            };
            wanted.push((role.clone(), kind));
        }
    }
    for f in rec.fargate_profiles.values() {
        if let Some(role) = &f.pod_execution_role_arn {
            wanted.push((role.clone(), "FARGATE_LINUX"));
        }
    }
    for (role, kind) in wanted {
        ensure_node_entry(ctx, rec, &cluster, &role, kind);
    }
}

/// Add an access entry for a node role, if the cluster uses access entries
/// and the role has none.
pub(crate) fn ensure_node_entry(ctx: &RequestContext, rec: &mut ClusterRec, cluster: &str, role: &str, kind: &str) {
    let mode =
        rec.cluster.access_config.as_ref().and_then(|a| a.authentication_mode.as_deref()).unwrap_or("CONFIG_MAP");
    if mode == "CONFIG_MAP" || rec.access_entries.contains_key(role) {
        return;
    }
    let entry = new_entry(ctx, cluster, role, kind, None, Vec::new(), None);
    rec.access_entries.insert(role.into(), AccessEntryRec { entry, policies: BTreeMap::new() });
}

fn not_found(principal: &str) -> ServiceError {
    errors::resource_not_found(format!("The specified access entry resource is not found: {principal}"))
}

fn require_api_mode(rec: &ClusterRec, cluster: &str) -> Result<(), ServiceError> {
    let mode =
        rec.cluster.access_config.as_ref().and_then(|a| a.authentication_mode.as_deref()).unwrap_or("CONFIG_MAP");
    if mode == "CONFIG_MAP" {
        return Err(errors::invalid_request(
            "The cluster's authentication mode must be set to one of [API, API_AND_CONFIG_MAP] to perform this operation.",
        )
        .with_field("clusterName", text(cluster)));
    }
    Ok(())
}

fn check_identity(username: Option<&str>, groups: &[String]) -> Result<(), ServiceError> {
    if let Some(u) = username {
        if RESERVED.iter().any(|p| u.starts_with(p)) {
            return Err(errors::invalid_parameter(
                "The username can't start with system:, eks:, aws:, amazon:, or iam:.",
            ));
        }
    }
    if groups.iter().any(|g| RESERVED.iter().any(|p| g.starts_with(p))) {
        return Err(errors::invalid_parameter(
            "The kubernetesGroups can't start with system:, eks:, aws:, amazon:, or iam:.",
        ));
    }
    Ok(())
}

fn entry_conditions(principal: &str, username: Option<&str>, groups: &[String]) -> ConditionContext {
    let mut c = ConditionContext::new();
    c.insert("eks:principalArn".into(), vec![principal.into()]);
    if let Some(u) = username {
        c.insert("eks:username".into(), vec![u.into()]);
    }
    if !groups.is_empty() {
        c.insert("eks:kubernetesGroups".into(), groups.to_vec());
    }
    c
}

impl Eks {
    pub(crate) async fn create_access_entry(
        &self,
        ctx: &RequestContext,
        input: types::CreateAccessEntryRequest,
    ) -> Result<types::CreateAccessEntryResponse, ServiceError> {
        let cluster = input.cluster_name.clone();
        let arn = util::cluster_arn(ctx, &cluster);
        let groups = input.kubernetes_groups.clone().unwrap_or_default();
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &cluster)?;
        util::authorize(
            ctx,
            "CreateAccessEntry",
            &arn,
            rec.cluster.tags.as_ref(),
            input.tags.as_ref(),
            entry_conditions(&input.principal_arn, input.username.as_deref(), &groups),
        )?;
        util::check_create_tags(input.tags.as_ref())?;
        require_api_mode(rec, &cluster)?;
        let kind = input.r#type.clone().unwrap_or_else(|| "STANDARD".into());
        if !TYPES.contains(&kind.as_str()) {
            return Err(errors::invalid_parameter(format!(
                "The access entry type {kind} is invalid. Valid types are: {}",
                TYPES.join(", ")
            )));
        }
        let principal = util::iam_principal(&input.principal_arn);
        let Some((_, iam_kind, _)) = principal else {
            return Err(errors::invalid_parameter(format!(
                "The specified principalArn is invalid: {}. It must be the ARN of an IAM role or user.",
                input.principal_arn
            )));
        };
        if kind != "STANDARD" {
            if iam_kind != "role" {
                return Err(errors::invalid_parameter(format!(
                    "Access entries of type {kind} must be for an IAM role."
                )));
            }
            if input.username.is_some() || !groups.is_empty() {
                return Err(errors::invalid_parameter(format!(
                    "The username and kubernetesGroups can't be specified for access entries of type {kind}."
                )));
            }
        } else {
            check_identity(input.username.as_deref(), &groups)?;
        }
        if rec.access_entries.contains_key(&input.principal_arn) {
            return Err(errors::resource_in_use(
                "The specified access entry resource is already in use on this cluster.",
            )
            .with_field("clusterName", text(&cluster)));
        }
        let entry =
            new_entry(ctx, &cluster, &input.principal_arn, &kind, input.username.clone(), groups, input.tags.clone());
        rec.access_entries
            .insert(input.principal_arn.clone(), AccessEntryRec { entry: entry.clone(), policies: BTreeMap::new() });
        Ok(types::CreateAccessEntryResponse { access_entry: Some(entry) })
    }

    pub(crate) async fn describe_access_entry(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAccessEntryRequest,
    ) -> Result<types::DescribeAccessEntryResponse, ServiceError> {
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        let e = rec.access_entries.get(&input.principal_arn).ok_or_else(|| not_found(&input.principal_arn))?;
        util::authorize(
            ctx,
            "DescribeAccessEntry",
            e.entry.access_entry_arn.as_deref().unwrap_or_default(),
            e.entry.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        Ok(types::DescribeAccessEntryResponse { access_entry: Some(e.entry.clone()) })
    }

    pub(crate) async fn list_access_entries(
        &self,
        ctx: &RequestContext,
        input: types::ListAccessEntriesRequest,
    ) -> Result<types::ListAccessEntriesResponse, ServiceError> {
        let arn = util::cluster_arn(ctx, &input.cluster_name);
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        util::authorize(ctx, "ListAccessEntries", &arn, rec.cluster.tags.as_ref(), None, ConditionContext::new())?;
        require_api_mode(rec, &input.cluster_name)?;
        let names: Vec<String> = rec
            .access_entries
            .iter()
            .filter(|(_, e)| input.associated_policy_arn.as_ref().is_none_or(|p| e.policies.contains_key(p)))
            .map(|(k, _)| k.clone())
            .collect();
        let (items, next) = util::page(&names, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListAccessEntriesResponse { access_entries: Some(items), next_token: next })
    }

    pub(crate) async fn update_access_entry(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAccessEntryRequest,
    ) -> Result<types::UpdateAccessEntryResponse, ServiceError> {
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        let e = rec.access_entries.get_mut(&input.principal_arn).ok_or_else(|| not_found(&input.principal_arn))?;
        let groups = input.kubernetes_groups.clone();
        util::authorize(
            ctx,
            "UpdateAccessEntry",
            e.entry.access_entry_arn.as_deref().unwrap_or_default(),
            e.entry.tags.as_ref(),
            None,
            entry_conditions(&input.principal_arn, input.username.as_deref(), groups.as_deref().unwrap_or_default()),
        )?;
        let kind = e.entry.r#type.clone().unwrap_or_default();
        if kind != "STANDARD" && (input.username.is_some() || groups.is_some()) {
            return Err(errors::invalid_parameter(format!(
                "The username and kubernetesGroups can't be specified for access entries of type {kind}."
            )));
        }
        check_identity(input.username.as_deref(), groups.as_deref().unwrap_or_default())?;
        if let Some(u) = input.username {
            e.entry.username = Some(u);
        }
        if let Some(g) = groups {
            e.entry.kubernetes_groups = Some(g);
        }
        e.entry.modified_at = Some(ctx.received_at);
        Ok(types::UpdateAccessEntryResponse { access_entry: Some(e.entry.clone()) })
    }

    pub(crate) async fn delete_access_entry(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessEntryRequest,
    ) -> Result<types::DeleteAccessEntryResponse, ServiceError> {
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        let e = rec.access_entries.get(&input.principal_arn).ok_or_else(|| not_found(&input.principal_arn))?;
        util::authorize(
            ctx,
            "DeleteAccessEntry",
            e.entry.access_entry_arn.as_deref().unwrap_or_default(),
            e.entry.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        rec.access_entries.remove(&input.principal_arn);
        Ok(types::DeleteAccessEntryResponse {})
    }

    pub(crate) async fn associate_access_policy(
        &self,
        ctx: &RequestContext,
        input: types::AssociateAccessPolicyRequest,
    ) -> Result<types::AssociateAccessPolicyResponse, ServiceError> {
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        let e = rec.access_entries.get_mut(&input.principal_arn).ok_or_else(|| not_found(&input.principal_arn))?;
        let scope = &input.access_scope;
        let namespaces = scope.namespaces.clone().unwrap_or_default();
        let mut c = ConditionContext::new();
        c.insert("eks:policyArn".into(), vec![input.policy_arn.clone()]);
        c.insert("eks:accessScope".into(), vec![scope.r#type.clone().unwrap_or_default()]);
        if !namespaces.is_empty() {
            c.insert("eks:namespaces".into(), namespaces.clone());
        }
        util::authorize(
            ctx,
            "AssociateAccessPolicy",
            e.entry.access_entry_arn.as_deref().unwrap_or_default(),
            e.entry.tags.as_ref(),
            None,
            c,
        )?;
        let known =
            catalog::ACCESS_POLICIES.iter().any(|p| catalog::access_policy_arn(&ctx.partition, p) == input.policy_arn);
        if !known {
            return Err(errors::resource_not_found(format!(
                "The specified policy arn {} is not found",
                input.policy_arn
            )));
        }
        if e.entry.r#type.as_deref().is_some_and(|t| t != "STANDARD") {
            return Err(errors::invalid_request(format!(
                "Access policies can't be associated with access entries of type {}.",
                e.entry.r#type.as_deref().unwrap_or_default()
            )));
        }
        match scope.r#type.as_deref() {
            Some("namespace") if namespaces.is_empty() => {
                return Err(errors::invalid_parameter("At least one namespace is required for namespace access scope."))
            }
            Some("cluster") if !namespaces.is_empty() => {
                return Err(errors::invalid_parameter("Namespaces can't be specified for cluster access scope."))
            }
            None => return Err(errors::invalid_parameter("The access scope type is required.")),
            _ => {}
        }
        let now = ctx.received_at;
        let associated_at = e.policies.get(&input.policy_arn).and_then(|p| p.associated_at).unwrap_or(now);
        let policy = types::AssociatedAccessPolicy {
            policy_arn: Some(input.policy_arn.clone()),
            access_scope: Some(types::AccessScope { r#type: scope.r#type.clone(), namespaces: Some(namespaces) }),
            associated_at: Some(associated_at),
            modified_at: Some(now),
        };
        e.policies.insert(input.policy_arn.clone(), policy.clone());
        Ok(types::AssociateAccessPolicyResponse {
            cluster_name: Some(input.cluster_name.clone()),
            principal_arn: Some(input.principal_arn.clone()),
            associated_access_policy: Some(policy),
        })
    }

    pub(crate) async fn disassociate_access_policy(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateAccessPolicyRequest,
    ) -> Result<types::DisassociateAccessPolicyResponse, ServiceError> {
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        let e = rec.access_entries.get_mut(&input.principal_arn).ok_or_else(|| not_found(&input.principal_arn))?;
        let mut c = ConditionContext::new();
        c.insert("eks:policyArn".into(), vec![input.policy_arn.clone()]);
        util::authorize(
            ctx,
            "DisassociateAccessPolicy",
            e.entry.access_entry_arn.as_deref().unwrap_or_default(),
            e.entry.tags.as_ref(),
            None,
            c,
        )?;
        if e.policies.remove(&input.policy_arn).is_none() {
            return Err(errors::resource_not_found(format!(
                "The specified policy {} is not associated with the access entry.",
                input.policy_arn
            )));
        }
        Ok(types::DisassociateAccessPolicyResponse {})
    }

    pub(crate) async fn list_associated_access_policies(
        &self,
        ctx: &RequestContext,
        input: types::ListAssociatedAccessPoliciesRequest,
    ) -> Result<types::ListAssociatedAccessPoliciesResponse, ServiceError> {
        let mut st = self.write();
        let rec = util::cluster(&mut st, ctx, &input.cluster_name)?;
        let e = rec.access_entries.get(&input.principal_arn).ok_or_else(|| not_found(&input.principal_arn))?;
        util::authorize(
            ctx,
            "ListAssociatedAccessPolicies",
            e.entry.access_entry_arn.as_deref().unwrap_or_default(),
            e.entry.tags.as_ref(),
            None,
            ConditionContext::new(),
        )?;
        let all: Vec<_> = e.policies.values().cloned().collect();
        let (items, next) = util::page(&all, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListAssociatedAccessPoliciesResponse {
            cluster_name: Some(input.cluster_name.clone()),
            principal_arn: Some(input.principal_arn.clone()),
            next_token: next,
            associated_access_policies: Some(items),
        })
    }

    pub(crate) async fn list_access_policies(
        &self,
        ctx: &RequestContext,
        input: types::ListAccessPoliciesRequest,
    ) -> Result<types::ListAccessPoliciesResponse, ServiceError> {
        util::authorize(ctx, "ListAccessPolicies", "*", None, None, ConditionContext::new())?;
        let all: Vec<types::AccessPolicy> = catalog::ACCESS_POLICIES
            .iter()
            .map(|p| types::AccessPolicy {
                name: Some(p.to_string()),
                arn: Some(catalog::access_policy_arn(&ctx.partition, p)),
            })
            .collect();
        let (items, next) = util::page(&all, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListAccessPoliciesResponse { access_policies: Some(items), next_token: next })
    }
}

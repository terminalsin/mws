//! Central configuration: configuration policies the delegated
//! administrator associates with accounts, OUs or the root, and that
//! Security Hub applies to the accounts they cover (enabling or disabling
//! Security Hub, the standards, controls and their parameters).

use std::collections::BTreeMap;

use mws_core::{RequestContext, ServiceError};

use crate::catalog;
use crate::common::{self, account, authorize_hub, hub, hub_mut, invalid_input, not_found, paginate};
use crate::generated::{errors, types};
use crate::hub::{enable_standard, ensure_hub};
use crate::state::{key, AssociationRec, ConfigurationPolicyRec, State};
use crate::{OrgInfo, SecurityHub};

pub const SELF_MANAGED: &str = "SELF_MANAGED_SECURITY_HUB";

fn target_of(t: &types::Target) -> (String, &'static str) {
    match t {
        types::Target::AccountId(a) => (a.clone(), "ACCOUNT"),
        types::Target::OrganizationalUnitId(o) => (o.clone(), "ORGANIZATIONAL_UNIT"),
        types::Target::RootId(r) => (r.clone(), "ROOT"),
    }
}

/// Check a target exists in the organization.
fn check_target(org: &OrgInfo, id: &str, ty: &str) -> Result<(), ServiceError> {
    let ok = match ty {
        "ACCOUNT" => org.accounts.iter().any(|a| a.id == id),
        _ => org.accounts.iter().any(|a| a.path.split('/').any(|p| p == id)),
    };
    if ok {
        return Ok(());
    }
    Err(match ty {
        "ACCOUNT" => not_found(format!("Account {id} is not part of the organization.")),
        _ => errors::organizational_unit_not_found(format!("The target {id} was not found in the organization.")),
    })
}

/// The association that applies to an account: its own, else its nearest
/// OU's, else the root's. `(policy id, applied directly, target id)`.
fn effective(h: &crate::state::Hub, path: &str, account: &str) -> Option<(String, bool, String)> {
    if let Some(a) = h.policy_associations.get(account) {
        return Some((a.policy_id.clone(), true, account.to_string()));
    }
    let containers: Vec<&str> =
        path.split('/').filter(|p| !p.is_empty() && *p != account && !p.starts_with("o-")).collect();
    for c in containers.iter().rev() {
        if let Some(a) = h.policy_associations.get(*c) {
            return Some((a.policy_id.clone(), false, c.to_string()));
        }
    }
    None
}

fn find_policy<'h>(h: &'h crate::state::Hub, identifier: &str) -> Option<&'h ConfigurationPolicyRec> {
    h.configuration_policies.values().find(|p| p.id == identifier || p.arn == identifier)
}

fn validate_policy(p: &types::Policy, partition: &str, region: &str) -> Result<(), ServiceError> {
    let types::Policy::SecurityHub(sh) = p;
    for s in sh.enabled_standard_identifiers.iter().flatten() {
        let ok = catalog::standard_from_arn(s).is_some_and(|st| catalog::standards_arn(partition, region, st) == *s);
        if !ok {
            return Err(invalid_input(format!("Invalid standard identifier: {s}")));
        }
    }
    if let Some(c) = &sh.security_controls_configuration {
        if c.enabled_security_control_identifiers.is_some() && c.disabled_security_control_identifiers.is_some() {
            return Err(invalid_input(
                "Specify either EnabledSecurityControlIdentifiers or DisabledSecurityControlIdentifiers, not both.",
            ));
        }
        for id in c
            .enabled_security_control_identifiers
            .iter()
            .chain(c.disabled_security_control_identifiers.iter())
            .flatten()
        {
            if catalog::control(id).is_none() {
                return Err(invalid_input(format!("Invalid security control identifier: {id}")));
            }
        }
        for p in c.security_control_custom_parameters.iter().flatten() {
            let id = p.security_control_id.clone().unwrap_or_default();
            let control = catalog::control(&id)
                .ok_or_else(|| invalid_input(format!("Invalid security control identifier: {id}")))?;
            crate::standards::validate_parameters(control, &p.parameters.clone().unwrap_or_default())
                .map_err(invalid_input)?;
        }
    }
    if sh.service_enabled == Some(true) && sh.enabled_standard_identifiers.is_none() {
        return Err(invalid_input("EnabledStandardIdentifiers is required when ServiceEnabled is true."));
    }
    Ok(())
}

/// Apply a policy to one account's hub.
fn apply_policy(
    state: &mut State,
    partition: &str,
    account: &str,
    region: &str,
    policy: &types::Policy,
    now: chrono::DateTime<chrono::Utc>,
) {
    let types::Policy::SecurityHub(sh) = policy;
    if sh.service_enabled == Some(false) {
        let k = key(account, region);
        if state.administrator_of(account, region).is_none() || state.hubs.contains_key(&k) {
            state.hubs.remove(&k);
        }
        return;
    }
    ensure_hub(state, partition, account, region, now, false);
    let h = state.hub_mut(account, region).expect("just ensured");
    let wanted: Vec<&String> = sh.enabled_standard_identifiers.iter().flatten().collect();
    h.standards.retain(|_, s| wanted.contains(&&s.standards_arn));
    for w in wanted {
        if let Some(s) = catalog::standard_from_arn(w) {
            enable_standard(h, partition, s, BTreeMap::new(), now);
        }
    }
    let c = sh.security_controls_configuration.clone().unwrap_or_default();
    crate::standards::apply_control_policy(
        h,
        partition,
        c.enabled_security_control_identifiers.as_deref(),
        c.disabled_security_control_identifiers.as_deref(),
        now,
    );
    h.security_controls.clear();
    for p in c.security_control_custom_parameters.into_iter().flatten() {
        let Some(id) = p.security_control_id else { continue };
        let rec = h.security_controls.entry(id).or_default();
        rec.parameters = p.parameters.unwrap_or_default();
        rec.last_update_reason = Some("Configuration policy".into());
    }
}

impl SecurityHub {
    /// The delegated administrator using central configuration.
    fn central_admin(&self, ctx: &RequestContext) -> Result<OrgInfo, ServiceError> {
        let org = self.require_delegated_admin(ctx)?;
        let state = self.read();
        hub(&state, ctx)?;
        let central =
            state.org_configs.get(&key(account(ctx), &ctx.region)).is_some_and(|c| c.configuration_type == "CENTRAL");
        if !central {
            return Err(errors::access_denied(
                "The operation requires central configuration. Update the organization configuration to use CENTRAL configuration first.",
            ));
        }
        Ok(org)
    }

    /// Re-apply the effective policies to every organization account.
    fn reapply(&self, ctx: &RequestContext, org: &OrgInfo) {
        let mut state = self.write();
        let Some(h) = state.hub(account(ctx), &ctx.region).cloned() else { return };
        for a in org.accounts.iter().filter(|a| a.active) {
            let Some((policy_id, _, _)) = effective(&h, &a.path, &a.id) else { continue };
            if policy_id == SELF_MANAGED {
                continue;
            }
            if let Some(p) = h.configuration_policies.get(&policy_id) {
                apply_policy(&mut state, &ctx.partition, &a.id, &ctx.region, &p.policy, ctx.received_at);
            }
        }
    }

    pub(crate) fn create_configuration_policy_op(
        &self,
        ctx: &RequestContext,
        input: types::CreateConfigurationPolicyRequest,
    ) -> Result<types::CreateConfigurationPolicyResponse, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        common::authorize_with(
            ctx,
            "CreateConfigurationPolicy",
            &common::hub_arn(ctx, account(ctx)),
            common::tag_conditions(&tags),
        )?;
        self.central_admin(ctx)?;
        validate_policy(&input.configuration_policy, &ctx.partition, &ctx.region)?;
        let mut state = self.write();
        let h = hub_mut(&mut state, ctx)?;
        if h.configuration_policies.values().any(|p| p.name == input.name) {
            return Err(errors::resource_conflict(format!(
                "A configuration policy named {} already exists.",
                input.name
            )));
        }
        if h.configuration_policies.len() >= 20 {
            return Err(errors::limit_exceeded("You can't create more than 20 configuration policies."));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let arn = common::arn(ctx, &format!("configuration-policy/{id}"));
        let rec = ConfigurationPolicyRec {
            id: id.clone(),
            arn: arn.clone(),
            name: input.name,
            description: input.description,
            policy: input.configuration_policy,
            created_at: ctx.received_at,
            updated_at: ctx.received_at,
        };
        if !tags.is_empty() {
            h.resource_tags.insert(arn, tags);
        }
        h.configuration_policies.insert(id, rec.clone());
        Ok(types::CreateConfigurationPolicyResponse {
            arn: Some(rec.arn),
            id: Some(rec.id),
            name: Some(rec.name),
            description: rec.description,
            updated_at: Some(rec.updated_at),
            created_at: Some(rec.created_at),
            configuration_policy: Some(rec.policy),
        })
    }

    pub(crate) fn get_configuration_policy_op(
        &self,
        ctx: &RequestContext,
        input: types::GetConfigurationPolicyRequest,
    ) -> Result<types::GetConfigurationPolicyResponse, ServiceError> {
        authorize_hub(ctx, "GetConfigurationPolicy")?;
        self.central_admin(ctx)?;
        let state = self.read();
        let h = hub(&state, ctx)?;
        let p = find_policy(h, &input.identifier).ok_or_else(|| policy_not_found(&input.identifier))?.clone();
        Ok(types::GetConfigurationPolicyResponse {
            arn: Some(p.arn),
            id: Some(p.id),
            name: Some(p.name),
            description: p.description,
            updated_at: Some(p.updated_at),
            created_at: Some(p.created_at),
            configuration_policy: Some(p.policy),
        })
    }

    pub(crate) fn update_configuration_policy_op(
        &self,
        ctx: &RequestContext,
        input: types::UpdateConfigurationPolicyRequest,
    ) -> Result<types::UpdateConfigurationPolicyResponse, ServiceError> {
        authorize_hub(ctx, "UpdateConfigurationPolicy")?;
        let org = self.central_admin(ctx)?;
        if let Some(p) = &input.configuration_policy {
            validate_policy(p, &ctx.partition, &ctx.region)?;
        }
        let rec = {
            let mut state = self.write();
            let h = hub_mut(&mut state, ctx)?;
            let id = find_policy(h, &input.identifier).ok_or_else(|| policy_not_found(&input.identifier))?.id.clone();
            if let Some(n) = &input.name {
                if h.configuration_policies.values().any(|p| p.name == *n && p.id != id) {
                    return Err(errors::resource_conflict(format!("A configuration policy named {n} already exists.")));
                }
            }
            let p = h.configuration_policies.get_mut(&id).expect("found");
            if let Some(n) = input.name {
                p.name = n;
            }
            if input.description.is_some() {
                p.description = input.description;
            }
            if let Some(c) = input.configuration_policy {
                p.policy = c;
            }
            p.updated_at = ctx.received_at;
            p.clone()
        };
        self.reapply(ctx, &org);
        Ok(types::UpdateConfigurationPolicyResponse {
            arn: Some(rec.arn),
            id: Some(rec.id),
            name: Some(rec.name),
            description: rec.description,
            updated_at: Some(rec.updated_at),
            created_at: Some(rec.created_at),
            configuration_policy: Some(rec.policy),
        })
    }

    pub(crate) fn delete_configuration_policy_op(
        &self,
        ctx: &RequestContext,
        input: types::DeleteConfigurationPolicyRequest,
    ) -> Result<types::DeleteConfigurationPolicyResponse, ServiceError> {
        authorize_hub(ctx, "DeleteConfigurationPolicy")?;
        self.central_admin(ctx)?;
        let mut state = self.write();
        let h = hub_mut(&mut state, ctx)?;
        let p = find_policy(h, &input.identifier).ok_or_else(|| policy_not_found(&input.identifier))?.clone();
        if h.policy_associations.values().any(|a| a.policy_id == p.id) {
            return Err(errors::resource_in_use(
                "The configuration policy is associated with one or more targets. Disassociate it before deleting it.",
            ));
        }
        h.configuration_policies.remove(&p.id);
        h.resource_tags.remove(&p.arn);
        Ok(types::DeleteConfigurationPolicyResponse {})
    }

    pub(crate) fn list_configuration_policies_op(
        &self,
        ctx: &RequestContext,
        input: types::ListConfigurationPoliciesRequest,
    ) -> Result<types::ListConfigurationPoliciesResponse, ServiceError> {
        authorize_hub(ctx, "ListConfigurationPolicies")?;
        self.central_admin(ctx)?;
        let state = self.read();
        let h = hub(&state, ctx)?;
        let all: Vec<types::ConfigurationPolicySummary> = h
            .configuration_policies
            .values()
            .map(|p| {
                let types::Policy::SecurityHub(sh) = &p.policy;
                types::ConfigurationPolicySummary {
                    arn: Some(p.arn.clone()),
                    id: Some(p.id.clone()),
                    name: Some(p.name.clone()),
                    description: p.description.clone(),
                    updated_at: Some(p.updated_at),
                    service_enabled: sh.service_enabled,
                }
            })
            .collect();
        drop(state);
        let (page, next_token) = paginate(all, input.max_results, 20, input.next_token.as_deref())?;
        Ok(types::ListConfigurationPoliciesResponse { configuration_policy_summaries: Some(page), next_token })
    }

    fn association_summary(
        &self,
        ctx: &RequestContext,
        org: &OrgInfo,
        target_id: &str,
        target_type: &str,
    ) -> Result<types::ConfigurationPolicyAssociationSummary, ServiceError> {
        let state = self.read();
        let h = hub(&state, ctx)?;
        let (policy_id, applied, updated_at) = if target_type == "ACCOUNT" {
            let path = org.accounts.iter().find(|a| a.id == target_id).map(|a| a.path.clone()).unwrap_or_default();
            match effective(h, &path, target_id) {
                Some((p, direct, from)) => (p, direct, h.policy_associations.get(&from).map(|a| a.updated_at)),
                None => (SELF_MANAGED.to_string(), false, None),
            }
        } else {
            match h.policy_associations.get(target_id) {
                Some(a) => (a.policy_id.clone(), true, Some(a.updated_at)),
                None => {
                    let path = org
                        .accounts
                        .iter()
                        .find_map(|a| a.path.find(target_id).map(|i| a.path[..i + target_id.len()].to_string()))
                        .unwrap_or_default();
                    match effective(h, &format!("{path}/"), "") {
                        Some((p, _, from)) if from != target_id => {
                            (p, false, h.policy_associations.get(&from).map(|a| a.updated_at))
                        }
                        _ => (SELF_MANAGED.to_string(), false, None),
                    }
                }
            }
        };
        Ok(types::ConfigurationPolicyAssociationSummary {
            configuration_policy_id: Some(policy_id),
            target_id: Some(target_id.to_string()),
            target_type: Some(target_type.to_string()),
            association_type: Some(if applied { "APPLIED" } else { "INHERITED" }.into()),
            updated_at: updated_at.or(Some(ctx.received_at)),
            association_status: Some("SUCCESS".into()),
            association_status_message: None,
        })
    }

    pub(crate) fn start_configuration_policy_association_op(
        &self,
        ctx: &RequestContext,
        input: types::StartConfigurationPolicyAssociationRequest,
    ) -> Result<types::StartConfigurationPolicyAssociationResponse, ServiceError> {
        authorize_hub(ctx, "StartConfigurationPolicyAssociation")?;
        let org = self.central_admin(ctx)?;
        let (target_id, target_type) = target_of(&input.target);
        check_target(&org, &target_id, target_type)?;
        {
            let mut state = self.write();
            let h = hub_mut(&mut state, ctx)?;
            let policy_id = if input.configuration_policy_identifier == SELF_MANAGED {
                SELF_MANAGED.to_string()
            } else {
                find_policy(h, &input.configuration_policy_identifier)
                    .ok_or_else(|| policy_not_found(&input.configuration_policy_identifier))?
                    .id
                    .clone()
            };
            h.policy_associations.insert(
                target_id.clone(),
                AssociationRec { policy_id, target_type: target_type.into(), updated_at: ctx.received_at },
            );
        }
        self.reapply(ctx, &org);
        let s = self.association_summary(ctx, &org, &target_id, target_type)?;
        Ok(types::StartConfigurationPolicyAssociationResponse {
            configuration_policy_id: s.configuration_policy_id,
            target_id: s.target_id,
            target_type: s.target_type,
            association_type: s.association_type,
            updated_at: s.updated_at,
            association_status: s.association_status,
            association_status_message: s.association_status_message,
        })
    }

    pub(crate) fn start_configuration_policy_disassociation_op(
        &self,
        ctx: &RequestContext,
        input: types::StartConfigurationPolicyDisassociationRequest,
    ) -> Result<types::StartConfigurationPolicyDisassociationResponse, ServiceError> {
        authorize_hub(ctx, "StartConfigurationPolicyDisassociation")?;
        let org = self.central_admin(ctx)?;
        {
            let mut state = self.write();
            let h = hub_mut(&mut state, ctx)?;
            let policy_id = if input.configuration_policy_identifier == SELF_MANAGED {
                SELF_MANAGED.to_string()
            } else {
                find_policy(h, &input.configuration_policy_identifier)
                    .ok_or_else(|| policy_not_found(&input.configuration_policy_identifier))?
                    .id
                    .clone()
            };
            match &input.target {
                Some(t) => {
                    let (target_id, _) = target_of(t);
                    if h.policy_associations.get(&target_id).is_none_or(|a| a.policy_id != policy_id) {
                        return Err(not_found(format!("The configuration policy isn't associated with {target_id}.")));
                    }
                    h.policy_associations.remove(&target_id);
                }
                None => h.policy_associations.retain(|_, a| a.policy_id != policy_id),
            }
        }
        self.reapply(ctx, &org);
        Ok(types::StartConfigurationPolicyDisassociationResponse {})
    }

    pub(crate) fn get_configuration_policy_association_op(
        &self,
        ctx: &RequestContext,
        input: types::GetConfigurationPolicyAssociationRequest,
    ) -> Result<types::GetConfigurationPolicyAssociationResponse, ServiceError> {
        authorize_hub(ctx, "GetConfigurationPolicyAssociation")?;
        let org = self.central_admin(ctx)?;
        let (target_id, target_type) = target_of(&input.target);
        check_target(&org, &target_id, target_type)?;
        let s = self.association_summary(ctx, &org, &target_id, target_type)?;
        Ok(types::GetConfigurationPolicyAssociationResponse {
            configuration_policy_id: s.configuration_policy_id,
            target_id: s.target_id,
            target_type: s.target_type,
            association_type: s.association_type,
            updated_at: s.updated_at,
            association_status: s.association_status,
            association_status_message: s.association_status_message,
        })
    }

    pub(crate) fn batch_get_configuration_policy_associations_op(
        &self,
        ctx: &RequestContext,
        input: types::BatchGetConfigurationPolicyAssociationsRequest,
    ) -> Result<types::BatchGetConfigurationPolicyAssociationsResponse, ServiceError> {
        authorize_hub(ctx, "BatchGetConfigurationPolicyAssociations")?;
        let org = self.central_admin(ctx)?;
        let mut found = Vec::new();
        let mut unprocessed = Vec::new();
        for ident in input.configuration_policy_association_identifiers {
            let Some(t) = &ident.target else {
                unprocessed.push(types::UnprocessedConfigurationPolicyAssociation {
                    configuration_policy_association_identifiers: Some(ident.clone()),
                    error_code: Some("INVALID_INPUT".into()),
                    error_reason: Some("A target is required.".into()),
                });
                continue;
            };
            let (target_id, target_type) = target_of(t);
            match check_target(&org, &target_id, target_type)
                .and_then(|_| self.association_summary(ctx, &org, &target_id, target_type))
            {
                Ok(s) => found.push(s),
                Err(e) => unprocessed.push(types::UnprocessedConfigurationPolicyAssociation {
                    configuration_policy_association_identifiers: Some(ident.clone()),
                    error_code: Some("RESOURCE_NOT_FOUND".into()),
                    error_reason: Some(e.message),
                }),
            }
        }
        Ok(types::BatchGetConfigurationPolicyAssociationsResponse {
            configuration_policy_associations: Some(found),
            unprocessed_configuration_policy_associations: Some(unprocessed),
        })
    }

    pub(crate) fn list_configuration_policy_associations_op(
        &self,
        ctx: &RequestContext,
        input: types::ListConfigurationPolicyAssociationsRequest,
    ) -> Result<types::ListConfigurationPolicyAssociationsResponse, ServiceError> {
        authorize_hub(ctx, "ListConfigurationPolicyAssociations")?;
        let org = self.central_admin(ctx)?;
        let mut all = Vec::new();
        for a in org.accounts.iter().filter(|a| a.id != account(ctx)) {
            all.push(self.association_summary(ctx, &org, &a.id, "ACCOUNT")?);
        }
        let explicit: Vec<(String, String)> = {
            let state = self.read();
            hub(&state, ctx)?
                .policy_associations
                .iter()
                .filter(|(_, a)| a.target_type != "ACCOUNT")
                .map(|(t, a)| (t.clone(), a.target_type.clone()))
                .collect()
        };
        for (t, ty) in explicit {
            all.push(self.association_summary(ctx, &org, &t, &ty)?);
        }
        if let Some(f) = &input.filters {
            all.retain(|s| {
                f.configuration_policy_id.as_ref().is_none_or(|p| s.configuration_policy_id.as_ref() == Some(p))
                    && f.association_type.as_ref().is_none_or(|t| s.association_type.as_ref() == Some(t))
                    && f.association_status.as_ref().is_none_or(|t| s.association_status.as_ref() == Some(t))
            });
        }
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListConfigurationPolicyAssociationsResponse {
            configuration_policy_association_summaries: Some(page),
            next_token,
        })
    }
}

fn policy_not_found(id: &str) -> ServiceError {
    not_found(format!("Configuration policy {id} not found."))
}

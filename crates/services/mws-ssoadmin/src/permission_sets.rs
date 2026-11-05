//! Permission sets and the policies they carry.

use mws_core::{RequestContext, ServiceError};

use crate::common::*;
use crate::generated::{errors, types};
use crate::state::{Instance, PermissionSet};
use crate::SsoAdmin;

const MAX_MANAGED: usize = 20;
const MAX_PERMISSION_SETS: usize = 2000;

fn check_session_duration(d: &str) -> Result<(), ServiceError> {
    match duration_seconds(d) {
        Some(s) if (3600..=43200).contains(&s) => Ok(()),
        _ => Err(errors::validation(format!(
            "The session duration {d} is invalid. It must be between PT1H and PT12H."
        ))),
    }
}

fn view(p: &PermissionSet) -> types::PermissionSet {
    types::PermissionSet {
        name: Some(p.name.clone()),
        permission_set_arn: Some(p.arn.clone()),
        description: p.description.clone(),
        created_date: Some(p.created),
        session_duration: Some(p.session_duration.clone()),
        relay_state: p.relay_state.clone(),
    }
}

fn policy_name(arn: &str) -> String {
    arn.rsplit('/').next().unwrap_or(arn).to_string()
}

fn ps_mut<'a>(i: &'a mut Instance, arn: &str) -> Result<&'a mut PermissionSet, ServiceError> {
    i.permission_sets.get_mut(arn).ok_or_else(|| permission_set_not_found(arn))
}

impl SsoAdmin {
    /// Check the caller may act on `ps_arn` in `instance_arn`, and that the
    /// permission set exists.
    pub(crate) fn permission_set(
        &self,
        ctx: &RequestContext,
        instance_arn: &str,
        ps_arn: &str,
        action: &str,
    ) -> Result<InstanceRef, ServiceError> {
        let r = self.instance(ctx, instance_arn, action, Some(ps_arn))?;
        self.with_instance(&r.arn, |i| ps_mut(i, ps_arn).map(|_| ()))?;
        Ok(r)
    }

    /// Run `f` on a permission set, bumping its version when `f` says it
    /// changed something provisioning has to apply.
    fn edit(
        &self,
        r: &InstanceRef,
        ps_arn: &str,
        f: impl FnOnce(&mut PermissionSet) -> Result<bool, ServiceError>,
    ) -> Result<(), ServiceError> {
        self.with_instance(&r.arn, |i| {
            let p = ps_mut(i, ps_arn)?;
            if f(p)? {
                p.version += 1;
            }
            Ok(())
        })
    }

    pub(crate) fn create_permission_set(
        &self,
        ctx: &RequestContext,
        input: types::CreatePermissionSetRequest,
    ) -> Result<types::CreatePermissionSetResponse, ServiceError> {
        let r = self.instance(ctx, &input.instance_arn, "sso:CreatePermissionSet", None)?;
        let session_duration = input.session_duration.unwrap_or_else(|| "PT1H".into());
        check_session_duration(&session_duration)?;
        let tags = tags_from(input.tags)?;
        self.with_instance(&r.arn, |i| {
            if !i.permission_sets_enabled {
                return Err(errors::validation("Permission sets are not enabled for this instance."));
            }
            if i.permission_sets.values().any(|p| p.name == input.name) {
                return Err(errors::conflict(format!(
                    "PermissionSet with name {} already exists.",
                    input.name
                )));
            }
            if i.permission_sets.len() >= MAX_PERMISSION_SETS {
                return Err(errors::service_quota_exceeded("The instance has reached the maximum number of permission sets."));
            }
            let arn = format!("arn:{}:sso:::permissionSet/{}/ps-{}", ctx.partition, i.id, hex(16));
            let p = PermissionSet {
                arn: arn.clone(),
                name: input.name,
                description: input.description,
                created: ctx.received_at,
                session_duration,
                relay_state: input.relay_state,
                tags,
                ..Default::default()
            };
            let out = view(&p);
            i.permission_sets.insert(arn, p);
            Ok(types::CreatePermissionSetResponse { permission_set: Some(out) })
        })
    }

    pub(crate) fn describe_permission_set(
        &self,
        ctx: &RequestContext,
        input: types::DescribePermissionSetRequest,
    ) -> Result<types::DescribePermissionSetResponse, ServiceError> {
        let r =
            self.permission_set(ctx, &input.instance_arn, &input.permission_set_arn, "sso:DescribePermissionSet")?;
        self.with_instance(&r.arn, |i| {
            Ok(types::DescribePermissionSetResponse {
                permission_set: Some(view(ps_mut(i, &input.permission_set_arn)?)),
            })
        })
    }

    pub(crate) fn update_permission_set(
        &self,
        ctx: &RequestContext,
        input: types::UpdatePermissionSetRequest,
    ) -> Result<types::UpdatePermissionSetResponse, ServiceError> {
        let r = self.permission_set(ctx, &input.instance_arn, &input.permission_set_arn, "sso:UpdatePermissionSet")?;
        if let Some(d) = &input.session_duration {
            check_session_duration(d)?;
        }
        self.edit(&r, &input.permission_set_arn, |p| {
            let mut changed = false;
            if let Some(d) = input.description {
                p.description = Some(d);
            }
            if let Some(d) = input.session_duration {
                changed |= d != p.session_duration;
                p.session_duration = d;
            }
            if let Some(s) = input.relay_state {
                p.relay_state = Some(s);
            }
            Ok(changed)
        })?;
        Ok(types::UpdatePermissionSetResponse {})
    }

    pub(crate) fn delete_permission_set(
        &self,
        ctx: &RequestContext,
        input: types::DeletePermissionSetRequest,
    ) -> Result<types::DeletePermissionSetResponse, ServiceError> {
        let r = self.permission_set(ctx, &input.instance_arn, &input.permission_set_arn, "sso:DeletePermissionSet")?;
        let ps = input.permission_set_arn.clone();
        let roles = self.with_instance(&r.arn, |i| {
            if i.assignments.iter().any(|a| a.permission_set == ps) {
                return Err(errors::conflict(
                    "The permission set is still assigned to principals in one or more accounts. Delete the account assignments first.",
                ));
            }
            i.permission_sets.remove(&ps);
            let keys: Vec<_> = i.provisioned.keys().filter(|(p, _)| *p == ps).cloned().collect();
            Ok(keys.into_iter().filter_map(|k| i.provisioned.remove(&k).map(|v| (k.1, v.role_name))).collect::<Vec<_>>())
        })?;
        for (account, role) in roles {
            self.iam.delete_reserved_role(&account, &role);
        }
        Ok(types::DeletePermissionSetResponse {})
    }

    pub(crate) fn list_permission_sets(
        &self,
        ctx: &RequestContext,
        input: types::ListPermissionSetsRequest,
    ) -> Result<types::ListPermissionSetsResponse, ServiceError> {
        let r = self.instance(ctx, &input.instance_arn, "sso:ListPermissionSets", None)?;
        let all = self.with_instance(&r.arn, |i| {
            let mut v: Vec<_> = i.permission_sets.values().map(|p| (p.created, p.arn.clone())).collect();
            v.sort();
            Ok(v.into_iter().map(|(_, a)| a).collect::<Vec<_>>())
        })?;
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListPermissionSetsResponse { permission_sets: Some(page), next_token })
    }

    pub(crate) fn attach_managed_policy_to_permission_set(
        &self,
        ctx: &RequestContext,
        input: types::AttachManagedPolicyToPermissionSetRequest,
    ) -> Result<types::AttachManagedPolicyToPermissionSetResponse, ServiceError> {
        let r = self.permission_set(
            ctx,
            &input.instance_arn,
            &input.permission_set_arn,
            "sso:AttachManagedPolicyToPermissionSet",
        )?;
        let arn = input.managed_policy_arn;
        self.edit(&r, &input.permission_set_arn, |p| {
            if p.managed.contains(&arn) {
                return Err(errors::conflict(format!("Managed policy {arn} is already attached to the permission set.")));
            }
            if p.managed.len() + p.customer_managed.len() >= MAX_MANAGED {
                return Err(errors::service_quota_exceeded(
                    "The permission set has reached the maximum number of attached managed policies.",
                ));
            }
            p.managed.push(arn);
            Ok(true)
        })?;
        Ok(types::AttachManagedPolicyToPermissionSetResponse {})
    }

    pub(crate) fn detach_managed_policy_from_permission_set(
        &self,
        ctx: &RequestContext,
        input: types::DetachManagedPolicyFromPermissionSetRequest,
    ) -> Result<types::DetachManagedPolicyFromPermissionSetResponse, ServiceError> {
        let r = self.permission_set(
            ctx,
            &input.instance_arn,
            &input.permission_set_arn,
            "sso:DetachManagedPolicyFromPermissionSet",
        )?;
        let arn = input.managed_policy_arn;
        self.edit(&r, &input.permission_set_arn, |p| {
            let before = p.managed.len();
            p.managed.retain(|m| *m != arn);
            if p.managed.len() == before {
                return Err(not_found(format!("Managed policy {arn} is not attached to the permission set.")));
            }
            Ok(true)
        })?;
        Ok(types::DetachManagedPolicyFromPermissionSetResponse {})
    }

    pub(crate) fn list_managed_policies_in_permission_set(
        &self,
        ctx: &RequestContext,
        input: types::ListManagedPoliciesInPermissionSetRequest,
    ) -> Result<types::ListManagedPoliciesInPermissionSetResponse, ServiceError> {
        let r = self.permission_set(
            ctx,
            &input.instance_arn,
            &input.permission_set_arn,
            "sso:ListManagedPoliciesInPermissionSet",
        )?;
        let all = self.with_instance(&r.arn, |i| {
            Ok(ps_mut(i, &input.permission_set_arn)?
                .managed
                .iter()
                .map(|a| types::AttachedManagedPolicy { name: Some(policy_name(a)), arn: Some(a.clone()) })
                .collect::<Vec<_>>())
        })?;
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListManagedPoliciesInPermissionSetResponse { attached_managed_policies: Some(page), next_token })
    }

    pub(crate) fn attach_customer_managed_policy_reference_to_permission_set(
        &self,
        ctx: &RequestContext,
        input: types::AttachCustomerManagedPolicyReferenceToPermissionSetRequest,
    ) -> Result<types::AttachCustomerManagedPolicyReferenceToPermissionSetResponse, ServiceError> {
        let r = self.permission_set(
            ctx,
            &input.instance_arn,
            &input.permission_set_arn,
            "sso:AttachCustomerManagedPolicyReferenceToPermissionSet",
        )?;
        let reference = input.customer_managed_policy_reference;
        let entry = (reference.name, reference.path.unwrap_or_else(|| "/".into()));
        self.edit(&r, &input.permission_set_arn, |p| {
            if p.customer_managed.contains(&entry) {
                return Err(errors::conflict(format!(
                    "Customer managed policy reference {}{} is already attached to the permission set.",
                    entry.1, entry.0
                )));
            }
            if p.managed.len() + p.customer_managed.len() >= MAX_MANAGED {
                return Err(errors::service_quota_exceeded(
                    "The permission set has reached the maximum number of attached managed policies.",
                ));
            }
            p.customer_managed.push(entry);
            Ok(true)
        })?;
        Ok(types::AttachCustomerManagedPolicyReferenceToPermissionSetResponse {})
    }

    pub(crate) fn detach_customer_managed_policy_reference_from_permission_set(
        &self,
        ctx: &RequestContext,
        input: types::DetachCustomerManagedPolicyReferenceFromPermissionSetRequest,
    ) -> Result<types::DetachCustomerManagedPolicyReferenceFromPermissionSetResponse, ServiceError> {
        let r = self.permission_set(
            ctx,
            &input.instance_arn,
            &input.permission_set_arn,
            "sso:DetachCustomerManagedPolicyReferenceFromPermissionSet",
        )?;
        let reference = input.customer_managed_policy_reference;
        let entry = (reference.name, reference.path.unwrap_or_else(|| "/".into()));
        self.edit(&r, &input.permission_set_arn, |p| {
            let before = p.customer_managed.len();
            p.customer_managed.retain(|c| *c != entry);
            if p.customer_managed.len() == before {
                return Err(not_found(format!(
                    "Customer managed policy reference {}{} is not attached to the permission set.",
                    entry.1, entry.0
                )));
            }
            Ok(true)
        })?;
        Ok(types::DetachCustomerManagedPolicyReferenceFromPermissionSetResponse {})
    }

    pub(crate) fn list_customer_managed_policy_references_in_permission_set(
        &self,
        ctx: &RequestContext,
        input: types::ListCustomerManagedPolicyReferencesInPermissionSetRequest,
    ) -> Result<types::ListCustomerManagedPolicyReferencesInPermissionSetResponse, ServiceError> {
        let r = self.permission_set(
            ctx,
            &input.instance_arn,
            &input.permission_set_arn,
            "sso:ListCustomerManagedPolicyReferencesInPermissionSet",
        )?;
        let all = self.with_instance(&r.arn, |i| {
            Ok(ps_mut(i, &input.permission_set_arn)?
                .customer_managed
                .iter()
                .map(|(name, path)| types::CustomerManagedPolicyReference { name: name.clone(), path: Some(path.clone()) })
                .collect::<Vec<_>>())
        })?;
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListCustomerManagedPolicyReferencesInPermissionSetResponse {
            customer_managed_policy_references: Some(page),
            next_token,
        })
    }

    pub(crate) fn put_inline_policy_to_permission_set(
        &self,
        ctx: &RequestContext,
        input: types::PutInlinePolicyToPermissionSetRequest,
    ) -> Result<types::PutInlinePolicyToPermissionSetResponse, ServiceError> {
        let r = self.permission_set(
            ctx,
            &input.instance_arn,
            &input.permission_set_arn,
            "sso:PutInlinePolicyToPermissionSet",
        )?;
        self.iam.validate_identity_policy(&input.inline_policy).map_err(|e| errors::validation(e.message))?;
        let doc = input.inline_policy;
        self.edit(&r, &input.permission_set_arn, |p| {
            p.inline = Some(doc);
            Ok(true)
        })?;
        Ok(types::PutInlinePolicyToPermissionSetResponse {})
    }

    pub(crate) fn get_inline_policy_for_permission_set(
        &self,
        ctx: &RequestContext,
        input: types::GetInlinePolicyForPermissionSetRequest,
    ) -> Result<types::GetInlinePolicyForPermissionSetResponse, ServiceError> {
        let r = self.permission_set(
            ctx,
            &input.instance_arn,
            &input.permission_set_arn,
            "sso:GetInlinePolicyForPermissionSet",
        )?;
        self.with_instance(&r.arn, |i| {
            Ok(types::GetInlinePolicyForPermissionSetResponse {
                inline_policy: Some(ps_mut(i, &input.permission_set_arn)?.inline.clone().unwrap_or_default()),
            })
        })
    }

    pub(crate) fn delete_inline_policy_from_permission_set(
        &self,
        ctx: &RequestContext,
        input: types::DeleteInlinePolicyFromPermissionSetRequest,
    ) -> Result<types::DeleteInlinePolicyFromPermissionSetResponse, ServiceError> {
        let r = self.permission_set(
            ctx,
            &input.instance_arn,
            &input.permission_set_arn,
            "sso:DeleteInlinePolicyFromPermissionSet",
        )?;
        self.edit(&r, &input.permission_set_arn, |p| Ok(p.inline.take().is_some()))?;
        Ok(types::DeleteInlinePolicyFromPermissionSetResponse {})
    }

    pub(crate) fn put_permissions_boundary_to_permission_set(
        &self,
        ctx: &RequestContext,
        input: types::PutPermissionsBoundaryToPermissionSetRequest,
    ) -> Result<types::PutPermissionsBoundaryToPermissionSetResponse, ServiceError> {
        let r = self.permission_set(
            ctx,
            &input.instance_arn,
            &input.permission_set_arn,
            "sso:PutPermissionsBoundaryToPermissionSet",
        )?;
        let b = input.permissions_boundary;
        if b.managed_policy_arn.is_some() == b.customer_managed_policy_reference.is_some() {
            return Err(errors::validation(
                "Specify either a CustomerManagedPolicyReference or a ManagedPolicyArn for the permissions boundary.",
            ));
        }
        self.edit(&r, &input.permission_set_arn, |p| {
            p.boundary = Some(b);
            Ok(true)
        })?;
        Ok(types::PutPermissionsBoundaryToPermissionSetResponse {})
    }

    pub(crate) fn get_permissions_boundary_for_permission_set(
        &self,
        ctx: &RequestContext,
        input: types::GetPermissionsBoundaryForPermissionSetRequest,
    ) -> Result<types::GetPermissionsBoundaryForPermissionSetResponse, ServiceError> {
        let r = self.permission_set(
            ctx,
            &input.instance_arn,
            &input.permission_set_arn,
            "sso:GetPermissionsBoundaryForPermissionSet",
        )?;
        self.with_instance(&r.arn, |i| {
            let b = ps_mut(i, &input.permission_set_arn)?.boundary.clone().ok_or_else(|| {
                not_found("The permission set doesn't have a permissions boundary.")
            })?;
            Ok(types::GetPermissionsBoundaryForPermissionSetResponse { permissions_boundary: Some(b) })
        })
    }

    pub(crate) fn delete_permissions_boundary_from_permission_set(
        &self,
        ctx: &RequestContext,
        input: types::DeletePermissionsBoundaryFromPermissionSetRequest,
    ) -> Result<types::DeletePermissionsBoundaryFromPermissionSetResponse, ServiceError> {
        let r = self.permission_set(
            ctx,
            &input.instance_arn,
            &input.permission_set_arn,
            "sso:DeletePermissionsBoundaryFromPermissionSet",
        )?;
        self.edit(&r, &input.permission_set_arn, |p| {
            p.boundary.take().ok_or_else(|| not_found("The permission set doesn't have a permissions boundary."))?;
            Ok(true)
        })?;
        Ok(types::DeletePermissionsBoundaryFromPermissionSetResponse {})
    }
}

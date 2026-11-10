//! Roles and instance profiles.

use chrono::Utc;
use mws_core::{ConditionContext, RequestContext, ServiceError};
use mws_iam_policy::PolicyKind;

use crate::common::*;
use crate::generated::{errors, types};
use crate::state::{InstanceProfile, Role};
use crate::{ids, wire, Iam};

const DEFAULT_MAX_SESSION: i32 = 3600;

impl Iam {
    /// Validate a role trust policy as IAM does when storing one: the
    /// policy grammar, its size quota, STS-only actions, and that every IAM
    /// user or role it names as a principal exists. Don't call this while
    /// holding the state lock.
    pub(crate) fn validate_trust_policy(&self, document: &str) -> Result<(), ServiceError> {
        let policy = validate_policy(document, PolicyKind::Trust)?;
        if mws_iam_policy::policy_size(document) > TRUST_POLICY_MAX_SIZE {
            return Err(errors::limit_exceeded(format!(
                "Cannot exceed quota for ACLSizePerRole: {TRUST_POLICY_MAX_SIZE}"
            )));
        }
        for s in &policy.statements {
            let sts_only = s.action.negated
                || s.action
                    .patterns
                    .iter()
                    .all(|a| a == "*" || a.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("sts:")));
            if !sts_only {
                return Err(errors::malformed_policy_document(
                    "AssumeRole policy may only specify STS AssumeRole actions.",
                ));
            }
            for a in s.principal.iter().flat_map(|p| &p.aws) {
                if !self.principal_exists(a) {
                    return Err(errors::malformed_policy_document(format!(
                        "Invalid principal in policy: \"AWS\":\"{a}\""
                    )));
                }
            }
        }
        Ok(())
    }

    /// Whether an IAM user or role ARN names an entity that exists. Other
    /// principals (accounts, sessions, ids) and accounts MWS knows nothing
    /// about are taken as given. Resource policies of other services (KMS
    /// key policies) are checked with it too.
    pub fn principal_exists(&self, principal: &str) -> bool {
        let parts: Vec<&str> = principal.splitn(6, ':').collect();
        let [_, _, "iam", _, account, resource] = parts[..] else { return true };
        let Some(kind) = ["user/", "role/"].into_iter().find(|k| resource.starts_with(k)) else { return true };
        let accounts = self.inner.accounts.read().expect("IAM state lock poisoned");
        let Some(state) = accounts.get(account) else { return true };
        let name = resource.rsplit('/').next().unwrap_or_default();
        match kind {
            "user/" => state.user(name).is_some_and(|u| u.arn == principal),
            _ => state.role(name).is_some_and(|r| r.arn == principal),
        }
    }

    fn role_resource_ctx(&self, name: &str) -> (String, ConditionContext) {
        let s = self.read();
        match s.role(name) {
            Some(r) => (r.arn.clone(), resource_tag_context(&r.tags)),
            None => (self.entity_arn("role", "/", name), ConditionContext::new()),
        }
    }

    pub fn create_role(
        &self,
        ctx: &RequestContext,
        input: types::CreateRoleRequest,
    ) -> Result<types::CreateRoleResponse, ServiceError> {
        let path = input.path.unwrap_or_else(|| "/".into());
        let arn = self.entity_arn("role", &path, &input.role_name);
        let tags = tags_from_wire(input.tags)?;
        let mut cond = request_tag_context(&tags);
        if let Some(b) = &input.permissions_boundary {
            cond.insert("iam:PermissionsBoundary".into(), vec![b.clone()]);
        }
        self.authorize_with(ctx, "CreateRole", &arn, cond)?;
        self.validate_trust_policy(&input.assume_role_policy_document)?;
        if tags.len() > MAX_TAGS {
            return Err(errors::limit_exceeded(format!("Cannot exceed quota for TagsPerRole: {MAX_TAGS}")));
        }
        if let Some(b) = &input.permissions_boundary {
            self.check_boundary_exists(b)?;
        }
        let limit = self.quota(ctx, ROLES_QUOTA);
        let mut state = self.write();
        let key = input.role_name.to_lowercase();
        if state.roles.contains_key(&key) {
            return Err(errors::entity_already_exists(format!("Role with name {} already exists.", input.role_name)));
        }
        if state.roles.len() >= limit {
            return Err(errors::limit_exceeded(format!("Cannot exceed quota for RolesPerAccount: {limit}")));
        }
        let role = Role {
            name: input.role_name,
            path,
            id: ids::unique_id("AROA"),
            arn,
            created: Utc::now(),
            trust_policy: input.assume_role_policy_document,
            description: input.description,
            max_session_duration: input.max_session_duration.unwrap_or(DEFAULT_MAX_SESSION),
            permissions_boundary: input.permissions_boundary,
            tags,
            inline: Default::default(),
            attached: Default::default(),
            last_used: None,
        };
        let mut out = wire::role(&role);
        out.role_last_used = None;
        state.roles.insert(key, role);
        Ok(types::CreateRoleResponse { role: out })
    }

    pub fn get_role(
        &self,
        ctx: &RequestContext,
        input: types::GetRoleRequest,
    ) -> Result<types::GetRoleResponse, ServiceError> {
        let (arn, cond) = self.role_resource_ctx(&input.role_name);
        self.authorize_with(ctx, "GetRole", &arn, cond)?;
        let state = self.read();
        let role = state.role(&input.role_name).ok_or_else(|| no_such_role(&input.role_name))?;
        Ok(types::GetRoleResponse { role: wire::role(role) })
    }

    pub fn list_roles(
        &self,
        ctx: &RequestContext,
        input: types::ListRolesRequest,
    ) -> Result<types::ListRolesResponse, ServiceError> {
        self.authorize(ctx, "ListRoles", &self.arn("role/"))?;
        let prefix = input.path_prefix.unwrap_or_else(|| "/".into());
        let roles: Vec<Role> = self.read().roles.values().filter(|r| r.path.starts_with(&prefix)).cloned().collect();
        let (page, is_truncated, marker) =
            paginate(&roles, |r| r.name.to_lowercase(), input.marker.as_deref(), input.max_items)?;
        Ok(types::ListRolesResponse { roles: page.iter().map(wire::role_summary).collect(), is_truncated, marker })
    }

    pub fn update_role(
        &self,
        ctx: &RequestContext,
        input: types::UpdateRoleRequest,
    ) -> Result<types::UpdateRoleResponse, ServiceError> {
        let (arn, cond) = self.role_resource_ctx(&input.role_name);
        self.authorize_with(ctx, "UpdateRole", &arn, cond)?;
        let mut state = self.write();
        let role = state.role_mut(&input.role_name).ok_or_else(|| no_such_role(&input.role_name))?;
        if is_reserved(role) {
            return Err(crate::ops::service_roles::protected(&role.name));
        }
        if let Some(d) = input.description {
            role.description = Some(d);
        }
        if let Some(m) = input.max_session_duration {
            role.max_session_duration = m;
        }
        Ok(types::UpdateRoleResponse {})
    }

    pub fn update_role_description(
        &self,
        ctx: &RequestContext,
        input: types::UpdateRoleDescriptionRequest,
    ) -> Result<types::UpdateRoleDescriptionResponse, ServiceError> {
        let (arn, cond) = self.role_resource_ctx(&input.role_name);
        self.authorize_with(ctx, "UpdateRoleDescription", &arn, cond)?;
        let mut state = self.write();
        let role = state.role_mut(&input.role_name).ok_or_else(|| no_such_role(&input.role_name))?;
        if is_reserved(role) {
            return Err(crate::ops::service_roles::protected(&role.name));
        }
        role.description = Some(input.description);
        Ok(types::UpdateRoleDescriptionResponse { role: Some(wire::role(role)) })
    }

    pub fn update_assume_role_policy(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAssumeRolePolicyRequest,
    ) -> Result<(), ServiceError> {
        let (arn, cond) = self.role_resource_ctx(&input.role_name);
        self.authorize_with(ctx, "UpdateAssumeRolePolicy", &arn, cond)?;
        self.validate_trust_policy(&input.policy_document)?;
        let mut state = self.write();
        let role = state.role_mut(&input.role_name).ok_or_else(|| no_such_role(&input.role_name))?;
        if is_reserved(role) {
            return Err(crate::ops::service_roles::protected(&role.name));
        }
        role.trust_policy = input.policy_document;
        Ok(())
    }

    pub fn delete_role(&self, ctx: &RequestContext, input: types::DeleteRoleRequest) -> Result<(), ServiceError> {
        let (arn, cond) = self.role_resource_ctx(&input.role_name);
        self.authorize_with(ctx, "DeleteRole", &arn, cond)?;
        let mut state = self.write();
        let key = input.role_name.to_lowercase();
        let role = state.role(&input.role_name).ok_or_else(|| no_such_role(&input.role_name))?;
        if role.path.starts_with("/aws-service-role/") || is_reserved(role) {
            return Err(crate::ops::service_roles::protected(&role.name));
        }
        if state.instance_profiles.values().any(|ip| ip.roles.contains(&key)) {
            return Err(errors::delete_conflict(
                "Cannot delete entity, must remove roles from instance profile first.",
            ));
        }
        if !role.inline.is_empty() {
            return Err(errors::delete_conflict("Cannot delete entity, must delete policies first."));
        }
        if !role.attached.is_empty() {
            return Err(errors::delete_conflict("Cannot delete entity, must detach all policies first."));
        }
        let (arn, id) = (role.arn.clone(), role.id.clone());
        state.roles.remove(&key);
        retire_principal(state.every_account(), &arn, &id);
        Ok(())
    }

    pub fn tag_role(&self, ctx: &RequestContext, input: types::TagRoleRequest) -> Result<(), ServiceError> {
        let (arn, mut cond) = self.role_resource_ctx(&input.role_name);
        let tags = tags_from_wire(Some(input.tags))?;
        cond.extend(request_tag_context(&tags));
        self.authorize_with(ctx, "TagRole", &arn, cond)?;
        let mut state = self.write();
        let role = state.role_mut(&input.role_name).ok_or_else(|| no_such_role(&input.role_name))?;
        if is_reserved(role) {
            return Err(crate::ops::service_roles::protected(&role.name));
        }
        merge_tags(&mut role.tags, tags, "TagsPerRole")
    }

    pub fn untag_role(&self, ctx: &RequestContext, input: types::UntagRoleRequest) -> Result<(), ServiceError> {
        let (arn, mut cond) = self.role_resource_ctx(&input.role_name);
        cond.insert("aws:TagKeys".into(), input.tag_keys.clone());
        self.authorize_with(ctx, "UntagRole", &arn, cond)?;
        let mut state = self.write();
        let role = state.role_mut(&input.role_name).ok_or_else(|| no_such_role(&input.role_name))?;
        if is_reserved(role) {
            return Err(crate::ops::service_roles::protected(&role.name));
        }
        remove_tags(&mut role.tags, &input.tag_keys);
        Ok(())
    }

    pub fn list_role_tags(
        &self,
        ctx: &RequestContext,
        input: types::ListRoleTagsRequest,
    ) -> Result<types::ListRoleTagsResponse, ServiceError> {
        let (arn, cond) = self.role_resource_ctx(&input.role_name);
        self.authorize_with(ctx, "ListRoleTags", &arn, cond)?;
        let tags = self.read().role(&input.role_name).ok_or_else(|| no_such_role(&input.role_name))?.tags.clone();
        let (page, is_truncated, marker) =
            paginate(&tags, |(k, _)| k.clone(), input.marker.as_deref(), input.max_items)?;
        Ok(types::ListRoleTagsResponse { tags: tags_list(&page), is_truncated, marker })
    }

    pub fn put_role_permissions_boundary(
        &self,
        ctx: &RequestContext,
        input: types::PutRolePermissionsBoundaryRequest,
    ) -> Result<(), ServiceError> {
        let (arn, mut cond) = self.role_resource_ctx(&input.role_name);
        cond.insert("iam:PermissionsBoundary".into(), vec![input.permissions_boundary.clone()]);
        self.authorize_with(ctx, "PutRolePermissionsBoundary", &arn, cond)?;
        self.check_boundary_exists(&input.permissions_boundary)?;
        let mut state = self.write();
        let role = state.role_mut(&input.role_name).ok_or_else(|| no_such_role(&input.role_name))?;
        if is_reserved(role) {
            return Err(crate::ops::service_roles::protected(&role.name));
        }
        role.permissions_boundary = Some(input.permissions_boundary);
        Ok(())
    }

    pub fn delete_role_permissions_boundary(
        &self,
        ctx: &RequestContext,
        input: types::DeleteRolePermissionsBoundaryRequest,
    ) -> Result<(), ServiceError> {
        let (arn, cond) = self.role_resource_ctx(&input.role_name);
        self.authorize_with(ctx, "DeleteRolePermissionsBoundary", &arn, cond)?;
        let mut state = self.write();
        let role = state.role_mut(&input.role_name).ok_or_else(|| no_such_role(&input.role_name))?;
        if is_reserved(role) {
            return Err(crate::ops::service_roles::protected(&role.name));
        }
        role.permissions_boundary = None;
        Ok(())
    }

    // ---- instance profiles --------------------------------------------------

    pub fn create_instance_profile(
        &self,
        ctx: &RequestContext,
        input: types::CreateInstanceProfileRequest,
    ) -> Result<types::CreateInstanceProfileResponse, ServiceError> {
        let path = input.path.unwrap_or_else(|| "/".into());
        let arn = self.entity_arn("instance-profile", &path, &input.instance_profile_name);
        let tags = tags_from_wire(input.tags)?;
        self.authorize_with(ctx, "CreateInstanceProfile", &arn, request_tag_context(&tags))?;
        let mut state = self.write();
        let key = input.instance_profile_name.to_lowercase();
        if state.instance_profiles.contains_key(&key) {
            return Err(errors::entity_already_exists(format!(
                "Instance Profile {} already exists.",
                input.instance_profile_name
            )));
        }
        let ip = InstanceProfile {
            name: input.instance_profile_name,
            path,
            id: ids::unique_id("AIPA"),
            arn,
            created: Utc::now(),
            roles: vec![],
            tags,
        };
        let out = wire::instance_profile(&ip, &state);
        state.instance_profiles.insert(key, ip);
        Ok(types::CreateInstanceProfileResponse { instance_profile: out })
    }

    pub fn get_instance_profile(
        &self,
        ctx: &RequestContext,
        input: types::GetInstanceProfileRequest,
    ) -> Result<types::GetInstanceProfileResponse, ServiceError> {
        self.authorize(ctx, "GetInstanceProfile", &self.instance_profile_arn_or_default(&input.instance_profile_name))?;
        let state = self.read();
        let ip = state
            .instance_profile(&input.instance_profile_name)
            .ok_or_else(|| no_such_instance_profile(&input.instance_profile_name))?;
        Ok(types::GetInstanceProfileResponse { instance_profile: wire::instance_profile(ip, &state) })
    }

    pub fn list_instance_profiles(
        &self,
        ctx: &RequestContext,
        input: types::ListInstanceProfilesRequest,
    ) -> Result<types::ListInstanceProfilesResponse, ServiceError> {
        self.authorize(ctx, "ListInstanceProfiles", &self.arn("instance-profile/"))?;
        let prefix = input.path_prefix.unwrap_or_else(|| "/".into());
        let state = self.read();
        let ips: Vec<InstanceProfile> =
            state.instance_profiles.values().filter(|i| i.path.starts_with(&prefix)).cloned().collect();
        let (page, is_truncated, marker) =
            paginate(&ips, |i| i.name.to_lowercase(), input.marker.as_deref(), input.max_items)?;
        Ok(types::ListInstanceProfilesResponse {
            instance_profiles: page.iter().map(|i| wire::instance_profile(i, &state)).collect(),
            is_truncated,
            marker,
        })
    }

    pub fn list_instance_profiles_for_role(
        &self,
        ctx: &RequestContext,
        input: types::ListInstanceProfilesForRoleRequest,
    ) -> Result<types::ListInstanceProfilesForRoleResponse, ServiceError> {
        let (arn, cond) = self.role_resource_ctx(&input.role_name);
        self.authorize_with(ctx, "ListInstanceProfilesForRole", &arn, cond)?;
        let state = self.read();
        state.role(&input.role_name).ok_or_else(|| no_such_role(&input.role_name))?;
        let key = input.role_name.to_lowercase();
        let ips: Vec<InstanceProfile> =
            state.instance_profiles.values().filter(|i| i.roles.contains(&key)).cloned().collect();
        let (page, is_truncated, marker) =
            paginate(&ips, |i| i.name.to_lowercase(), input.marker.as_deref(), input.max_items)?;
        Ok(types::ListInstanceProfilesForRoleResponse {
            instance_profiles: page.iter().map(|i| wire::instance_profile(i, &state)).collect(),
            is_truncated,
            marker,
        })
    }

    pub fn add_role_to_instance_profile(
        &self,
        ctx: &RequestContext,
        input: types::AddRoleToInstanceProfileRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(
            ctx,
            "AddRoleToInstanceProfile",
            &self.instance_profile_arn_or_default(&input.instance_profile_name),
        )?;
        let mut state = self.write();
        state.role(&input.role_name).ok_or_else(|| no_such_role(&input.role_name))?;
        let ip = state
            .instance_profiles
            .get_mut(&input.instance_profile_name.to_lowercase())
            .ok_or_else(|| no_such_instance_profile(&input.instance_profile_name))?;
        let key = input.role_name.to_lowercase();
        if ip.roles.contains(&key) {
            return Err(errors::entity_already_exists(format!(
                "The role {} is already added to this instance profile.",
                input.role_name
            )));
        }
        if !ip.roles.is_empty() {
            return Err(errors::limit_exceeded("Cannot exceed quota for InstanceSessionsPerInstanceProfile: 1"));
        }
        ip.roles.push(key);
        Ok(())
    }

    pub fn remove_role_from_instance_profile(
        &self,
        ctx: &RequestContext,
        input: types::RemoveRoleFromInstanceProfileRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(
            ctx,
            "RemoveRoleFromInstanceProfile",
            &self.instance_profile_arn_or_default(&input.instance_profile_name),
        )?;
        let mut state = self.write();
        let ip = state
            .instance_profiles
            .get_mut(&input.instance_profile_name.to_lowercase())
            .ok_or_else(|| no_such_instance_profile(&input.instance_profile_name))?;
        let key = input.role_name.to_lowercase();
        if !ip.roles.contains(&key) {
            return Err(no_such_role(&input.role_name));
        }
        ip.roles.retain(|r| *r != key);
        Ok(())
    }

    pub fn delete_instance_profile(
        &self,
        ctx: &RequestContext,
        input: types::DeleteInstanceProfileRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(
            ctx,
            "DeleteInstanceProfile",
            &self.instance_profile_arn_or_default(&input.instance_profile_name),
        )?;
        let mut state = self.write();
        let key = input.instance_profile_name.to_lowercase();
        let ip =
            state.instance_profiles.get(&key).ok_or_else(|| no_such_instance_profile(&input.instance_profile_name))?;
        if !ip.roles.is_empty() {
            return Err(errors::delete_conflict(
                "Cannot delete entity, must remove roles from instance profile first.",
            ));
        }
        state.instance_profiles.remove(&key);
        Ok(())
    }

    pub fn tag_instance_profile(
        &self,
        ctx: &RequestContext,
        input: types::TagInstanceProfileRequest,
    ) -> Result<(), ServiceError> {
        let tags = tags_from_wire(Some(input.tags))?;
        self.authorize_with(
            ctx,
            "TagInstanceProfile",
            &self.instance_profile_arn_or_default(&input.instance_profile_name),
            request_tag_context(&tags),
        )?;
        let mut state = self.write();
        let ip = state
            .instance_profiles
            .get_mut(&input.instance_profile_name.to_lowercase())
            .ok_or_else(|| no_such_instance_profile(&input.instance_profile_name))?;
        merge_tags(&mut ip.tags, tags, "TagsPerInstanceProfile")
    }

    pub fn untag_instance_profile(
        &self,
        ctx: &RequestContext,
        input: types::UntagInstanceProfileRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(
            ctx,
            "UntagInstanceProfile",
            &self.instance_profile_arn_or_default(&input.instance_profile_name),
        )?;
        let mut state = self.write();
        let ip = state
            .instance_profiles
            .get_mut(&input.instance_profile_name.to_lowercase())
            .ok_or_else(|| no_such_instance_profile(&input.instance_profile_name))?;
        remove_tags(&mut ip.tags, &input.tag_keys);
        Ok(())
    }

    pub fn list_instance_profile_tags(
        &self,
        ctx: &RequestContext,
        input: types::ListInstanceProfileTagsRequest,
    ) -> Result<types::ListInstanceProfileTagsResponse, ServiceError> {
        self.authorize(
            ctx,
            "ListInstanceProfileTags",
            &self.instance_profile_arn_or_default(&input.instance_profile_name),
        )?;
        let tags = self
            .read()
            .instance_profile(&input.instance_profile_name)
            .ok_or_else(|| no_such_instance_profile(&input.instance_profile_name))?
            .tags
            .clone();
        let (page, is_truncated, marker) =
            paginate(&tags, |(k, _)| k.clone(), input.marker.as_deref(), input.max_items)?;
        Ok(types::ListInstanceProfileTagsResponse { tags: tags_list(&page), is_truncated, marker })
    }
}

/// Service Quotas' "Roles per account".
const ROLES_QUOTA: &str = "L-FE177D64";
/// A role IAM Identity Center provisioned (`AWSReservedSSO_*`): only AWS may
/// change it.
pub(crate) fn is_reserved(role: &crate::state::Role) -> bool {
    role.path.starts_with("/aws-reserved/")
}

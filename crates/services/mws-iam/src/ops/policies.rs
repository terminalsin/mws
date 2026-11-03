//! Managed policies, their versions and attachments, and inline policies.

use std::collections::{BTreeMap, BTreeSet};

use chrono::Utc;
use mws_core::{RequestContext, ServiceError};
use mws_iam_policy::{policy_size, PolicyKind};

use crate::common::*;
use crate::generated::{errors, types};
use crate::state::{ManagedPolicy, PolicyVersion, State};
use crate::{ids, wire, Iam};

/// The three kinds of IAM identity that hold policies.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Holder {
    User,
    Group,
    Role,
}

impl Holder {
    fn word(self) -> &'static str {
        match self {
            Holder::User => "user",
            Holder::Group => "group",
            Holder::Role => "role",
        }
    }
    fn title(self) -> &'static str {
        match self {
            Holder::User => "User",
            Holder::Group => "Group",
            Holder::Role => "Role",
        }
    }
    fn inline_limit(self) -> usize {
        match self {
            Holder::User => 2048,
            Holder::Group => 5120,
            Holder::Role => 10240,
        }
    }
    fn not_found(self, name: &str) -> ServiceError {
        match self {
            Holder::User => no_such_user(name),
            Holder::Group => no_such_group(name),
            Holder::Role => no_such_role(name),
        }
    }
    fn parts<'s>(
        self,
        state: &'s mut State,
        name: &str,
    ) -> Option<(&'s mut BTreeMap<String, String>, &'s mut BTreeSet<String>)> {
        match self {
            Holder::User => state.user_mut(name).map(|e| (&mut e.inline, &mut e.attached)),
            Holder::Group => state.group_mut(name).map(|e| (&mut e.inline, &mut e.attached)),
            Holder::Role => state.role_mut(name).map(|e| (&mut e.inline, &mut e.attached)),
        }
    }
    fn parts_ref<'s>(
        self,
        state: &'s State,
        name: &str,
    ) -> Option<(&'s BTreeMap<String, String>, &'s BTreeSet<String>, String)> {
        match self {
            Holder::User => state.user(name).map(|e| (&e.inline, &e.attached, e.name.clone())),
            Holder::Group => state.group(name).map(|e| (&e.inline, &e.attached, e.name.clone())),
            Holder::Role => state.role(name).map(|e| (&e.inline, &e.attached, e.name.clone())),
        }
    }
}

impl Iam {
    fn holder_arn(&self, h: Holder, name: &str) -> String {
        match h {
            Holder::User => self.user_arn_or_default(name),
            Holder::Group => self.group_arn_or_default(name),
            Holder::Role => self.role_arn_or_default(name),
        }
    }

    /// Add the AWS managed policies MWS knows to `state`, keeping any that
    /// are already there (restored state keeps their ids).
    pub(crate) fn seed_aws_managed_policies(&self, state: &mut crate::State) {
        seed_aws_managed_policies(&self.inner.config.partition, state)
    }
}

/// Add every AWS managed policy MWS knows to an account's namespace.
pub(crate) fn seed_aws_managed_policies(partition: &str, state: &mut crate::State) {
    {
        let created = chrono::DateTime::parse_from_rfc3339("2015-02-06T18:39:46Z").unwrap().with_timezone(&Utc);
        for p in crate::managed::POLICIES {
            let arn = format!("arn:{partition}:iam::aws:policy{}{}", p.path, p.name);
            if state.policies.contains_key(&arn) {
                continue;
            }
            state.policies.insert(
                arn.clone(),
                ManagedPolicy {
                    name: p.name.into(),
                    path: p.path.into(),
                    id: ids::unique_id("ANPA"),
                    arn,
                    created,
                    updated: created,
                    description: Some(p.description.into()),
                    default_version: "v1".into(),
                    versions: vec![PolicyVersion { id: "v1".into(), document: p.document.into(), created }],
                    next_version: 2,
                    tags: vec![],
                    aws_managed: true,
                },
            );
        }
    }
}

impl Iam {
    // ---- managed policies ---------------------------------------------------

    pub fn create_policy(
        &self,
        ctx: &RequestContext,
        input: types::CreatePolicyRequest,
    ) -> Result<types::CreatePolicyResponse, ServiceError> {
        let path = input.path.unwrap_or_else(|| "/".into());
        let arn = self.arn(&format!("policy{path}{}", input.policy_name));
        let tags = tags_from_wire(input.tags);
        self.authorize_with(ctx, "CreatePolicy", &arn, request_tag_context(&tags))?;
        validate_policy(&input.policy_document, PolicyKind::Identity)?;
        if policy_size(&input.policy_document) > MANAGED_POLICY_MAX_SIZE {
            return Err(errors::limit_exceeded(format!(
                "Cannot exceed quota for PolicySize: {MANAGED_POLICY_MAX_SIZE}"
            )));
        }
        let mut state = self.write();
        if state.policies.values().any(|p| !p.aws_managed && p.name.eq_ignore_ascii_case(&input.policy_name)) {
            return Err(errors::entity_already_exists(format!(
                "A policy called {} already exists. Duplicate names are not allowed.",
                input.policy_name
            )));
        }
        let now = Utc::now();
        let p = ManagedPolicy {
            name: input.policy_name,
            path,
            id: ids::unique_id("ANPA"),
            arn: arn.clone(),
            created: now,
            updated: now,
            description: input.description,
            default_version: "v1".into(),
            versions: vec![PolicyVersion { id: "v1".into(), document: input.policy_document, created: now }],
            next_version: 2,
            tags,
            aws_managed: false,
        };
        state.policies.insert(arn, p.clone());
        let mut out = wire::policy(&p, &state);
        out.description = None;
        Ok(types::CreatePolicyResponse { policy: Some(out) })
    }

    pub fn get_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetPolicyRequest,
    ) -> Result<types::GetPolicyResponse, ServiceError> {
        self.authorize(ctx, "GetPolicy", &input.policy_arn)?;
        let state = self.read();
        let p = state.policies.get(&input.policy_arn).ok_or_else(|| no_such_policy(&input.policy_arn))?;
        Ok(types::GetPolicyResponse { policy: Some(wire::policy(p, &state)) })
    }

    pub fn list_policies(
        &self,
        ctx: &RequestContext,
        input: types::ListPoliciesRequest,
    ) -> Result<types::ListPoliciesResponse, ServiceError> {
        self.authorize(ctx, "ListPolicies", &self.arn("policy/"))?;
        let state = self.read();
        let scope = input.scope.unwrap_or_else(|| "All".into());
        let prefix = input.path_prefix.unwrap_or_else(|| "/".into());
        let mut items: Vec<&ManagedPolicy> = state
            .policies
            .values()
            .filter(|p| match scope.as_str() {
                "AWS" => p.aws_managed,
                "Local" => !p.aws_managed,
                _ => true,
            })
            .filter(|p| p.path.starts_with(&prefix))
            .filter(|p| !input.only_attached || state.attachment_count(&p.arn) > 0)
            .filter(|p| match input.policy_usage_filter.as_deref() {
                Some("PermissionsBoundary") => state.boundary_usage_count(&p.arn) > 0,
                Some("PermissionsPolicy") => state.attachment_count(&p.arn) > 0,
                _ => true,
            })
            .collect();
        items.sort_by_key(|p| (p.name.to_lowercase(), p.arn.clone()));
        let (page, is_truncated, marker) = paginate(
            &items,
            |p| format!("{}|{}", p.name.to_lowercase(), p.arn),
            input.marker.as_deref(),
            input.max_items,
        )?;
        Ok(types::ListPoliciesResponse {
            policies: Some(
                page.iter()
                    .map(|p| types::Policy { tags: None, description: None, ..wire::policy(p, &state) })
                    .collect(),
            ),
            is_truncated,
            marker,
        })
    }

    pub fn delete_policy(&self, ctx: &RequestContext, input: types::DeletePolicyRequest) -> Result<(), ServiceError> {
        self.authorize(ctx, "DeletePolicy", &input.policy_arn)?;
        let mut state = self.write();
        let p = state.policies.get(&input.policy_arn).ok_or_else(|| no_such_policy(&input.policy_arn))?;
        if p.aws_managed {
            return Err(ServiceError::client("AccessDenied", 403, "AWS managed policies cannot be deleted."));
        }
        if state.attachment_count(&input.policy_arn) > 0 || state.boundary_usage_count(&input.policy_arn) > 0 {
            return Err(errors::delete_conflict("Cannot delete a policy attached to entities."));
        }
        if p.versions.len() > 1 {
            return Err(errors::delete_conflict(
                "This policy has more than one version. Before you delete a policy, you must delete the policy's versions. The default version is deleted with the policy.",
            ));
        }
        state.policies.remove(&input.policy_arn);
        Ok(())
    }

    pub fn create_policy_version(
        &self,
        ctx: &RequestContext,
        input: types::CreatePolicyVersionRequest,
    ) -> Result<types::CreatePolicyVersionResponse, ServiceError> {
        self.authorize(ctx, "CreatePolicyVersion", &input.policy_arn)?;
        validate_policy(&input.policy_document, PolicyKind::Identity)?;
        if policy_size(&input.policy_document) > MANAGED_POLICY_MAX_SIZE {
            return Err(errors::limit_exceeded(format!(
                "Cannot exceed quota for PolicySize: {MANAGED_POLICY_MAX_SIZE}"
            )));
        }
        let mut state = self.write();
        let p = state.policies.get_mut(&input.policy_arn).ok_or_else(|| no_such_policy(&input.policy_arn))?;
        if p.aws_managed {
            return Err(ServiceError::client("AccessDenied", 403, "AWS managed policies cannot be modified."));
        }
        if p.versions.len() >= MAX_POLICY_VERSIONS {
            return Err(errors::limit_exceeded(
                "A managed policy can have up to 5 versions. Before you create a new version, you must delete an existing version.",
            ));
        }
        let now = Utc::now();
        let v = PolicyVersion { id: format!("v{}", p.next_version), document: input.policy_document, created: now };
        p.next_version += 1;
        if input.set_as_default {
            p.default_version = v.id.clone();
        }
        p.updated = now;
        p.versions.push(v.clone());
        Ok(types::CreatePolicyVersionResponse { policy_version: Some(wire::policy_version(p, &v, false)) })
    }

    pub fn get_policy_version(
        &self,
        ctx: &RequestContext,
        input: types::GetPolicyVersionRequest,
    ) -> Result<types::GetPolicyVersionResponse, ServiceError> {
        self.authorize(ctx, "GetPolicyVersion", &input.policy_arn)?;
        let state = self.read();
        let p = state.policies.get(&input.policy_arn).ok_or_else(|| no_such_policy(&input.policy_arn))?;
        let v = p.versions.iter().find(|v| v.id == input.version_id).ok_or_else(|| {
            errors::no_such_entity(format!(
                "Policy {} version {} does not exist or is not attachable.",
                input.policy_arn, input.version_id
            ))
        })?;
        Ok(types::GetPolicyVersionResponse { policy_version: Some(wire::policy_version(p, v, true)) })
    }

    pub fn list_policy_versions(
        &self,
        ctx: &RequestContext,
        input: types::ListPolicyVersionsRequest,
    ) -> Result<types::ListPolicyVersionsResponse, ServiceError> {
        self.authorize(ctx, "ListPolicyVersions", &input.policy_arn)?;
        let state = self.read();
        let p = state.policies.get(&input.policy_arn).ok_or_else(|| no_such_policy(&input.policy_arn))?;
        let mut versions = p.versions.clone();
        versions.reverse();
        let (page, is_truncated, marker) = paginate(
            &versions,
            |v| format!("{:010}", u32::MAX - v.id[1..].parse::<u32>().unwrap_or(0)),
            input.marker.as_deref(),
            input.max_items,
        )?;
        Ok(types::ListPolicyVersionsResponse {
            versions: Some(page.iter().map(|v| wire::policy_version(p, v, false)).collect()),
            is_truncated,
            marker,
        })
    }

    pub fn delete_policy_version(
        &self,
        ctx: &RequestContext,
        input: types::DeletePolicyVersionRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "DeletePolicyVersion", &input.policy_arn)?;
        let mut state = self.write();
        let p = state.policies.get_mut(&input.policy_arn).ok_or_else(|| no_such_policy(&input.policy_arn))?;
        if p.default_version == input.version_id {
            return Err(errors::delete_conflict("Cannot delete the default version of a policy."));
        }
        let before = p.versions.len();
        p.versions.retain(|v| v.id != input.version_id);
        if p.versions.len() == before {
            return Err(errors::no_such_entity(format!(
                "Policy {} version {} does not exist.",
                input.policy_arn, input.version_id
            )));
        }
        Ok(())
    }

    pub fn set_default_policy_version(
        &self,
        ctx: &RequestContext,
        input: types::SetDefaultPolicyVersionRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "SetDefaultPolicyVersion", &input.policy_arn)?;
        let mut state = self.write();
        let p = state.policies.get_mut(&input.policy_arn).ok_or_else(|| no_such_policy(&input.policy_arn))?;
        if !p.versions.iter().any(|v| v.id == input.version_id) {
            return Err(errors::no_such_entity(format!(
                "Policy {} version {} does not exist.",
                input.policy_arn, input.version_id
            )));
        }
        p.default_version = input.version_id;
        p.updated = Utc::now();
        Ok(())
    }

    pub fn tag_policy(&self, ctx: &RequestContext, input: types::TagPolicyRequest) -> Result<(), ServiceError> {
        let tags = tags_from_wire(Some(input.tags));
        self.authorize_with(ctx, "TagPolicy", &input.policy_arn, request_tag_context(&tags))?;
        let mut state = self.write();
        let p = state.policies.get_mut(&input.policy_arn).ok_or_else(|| no_such_policy(&input.policy_arn))?;
        merge_tags(&mut p.tags, tags, "TagsPerPolicy")
    }

    pub fn untag_policy(&self, ctx: &RequestContext, input: types::UntagPolicyRequest) -> Result<(), ServiceError> {
        self.authorize(ctx, "UntagPolicy", &input.policy_arn)?;
        let mut state = self.write();
        let p = state.policies.get_mut(&input.policy_arn).ok_or_else(|| no_such_policy(&input.policy_arn))?;
        remove_tags(&mut p.tags, &input.tag_keys);
        Ok(())
    }

    pub fn list_policy_tags(
        &self,
        ctx: &RequestContext,
        input: types::ListPolicyTagsRequest,
    ) -> Result<types::ListPolicyTagsResponse, ServiceError> {
        self.authorize(ctx, "ListPolicyTags", &input.policy_arn)?;
        let tags =
            self.read().policies.get(&input.policy_arn).ok_or_else(|| no_such_policy(&input.policy_arn))?.tags.clone();
        let (page, is_truncated, marker) =
            paginate(&tags, |(k, _)| k.clone(), input.marker.as_deref(), input.max_items)?;
        Ok(types::ListPolicyTagsResponse { tags: tags_list(&page), is_truncated, marker })
    }

    pub fn list_entities_for_policy(
        &self,
        ctx: &RequestContext,
        input: types::ListEntitiesForPolicyRequest,
    ) -> Result<types::ListEntitiesForPolicyResponse, ServiceError> {
        self.authorize(ctx, "ListEntitiesForPolicy", &input.policy_arn)?;
        let state = self.read();
        state.policies.get(&input.policy_arn).ok_or_else(|| no_such_policy(&input.policy_arn))?;
        let arn = &input.policy_arn;
        let prefix = input.path_prefix.unwrap_or_else(|| "/".into());
        let boundary = input.policy_usage_filter.as_deref() == Some("PermissionsBoundary");
        let filter = input.entity_filter.as_deref();
        let want = |kind: &str| {
            filter.is_none()
                || filter == Some(kind)
                || (filter == Some("LocalManagedPolicy") || filter == Some("AWSManagedPolicy"))
        };
        let users: Vec<types::PolicyUser> = state
            .users
            .values()
            .filter(|u| want("User") && u.path.starts_with(&prefix))
            .filter(|u| {
                if boundary {
                    u.permissions_boundary.as_deref() == Some(arn.as_str())
                } else {
                    u.attached.contains(arn)
                }
            })
            .map(|u| types::PolicyUser { user_name: Some(u.name.clone()), user_id: Some(u.id.clone()) })
            .collect();
        let groups: Vec<types::PolicyGroup> = state
            .groups
            .values()
            .filter(|g| !boundary && want("Group") && g.path.starts_with(&prefix) && g.attached.contains(arn))
            .map(|g| types::PolicyGroup { group_name: Some(g.name.clone()), group_id: Some(g.id.clone()) })
            .collect();
        let roles: Vec<types::PolicyRole> = state
            .roles
            .values()
            .filter(|r| want("Role") && r.path.starts_with(&prefix))
            .filter(|r| {
                if boundary {
                    r.permissions_boundary.as_deref() == Some(arn.as_str())
                } else {
                    r.attached.contains(arn)
                }
            })
            .map(|r| types::PolicyRole { role_name: Some(r.name.clone()), role_id: Some(r.id.clone()) })
            .collect();
        Ok(types::ListEntitiesForPolicyResponse {
            policy_groups: Some(groups),
            policy_users: Some(users),
            policy_roles: Some(roles),
            is_truncated: false,
            marker: None,
        })
    }

    // ---- attachments --------------------------------------------------------

    fn attach(&self, ctx: &RequestContext, h: Holder, name: &str, policy_arn: &str) -> Result<(), ServiceError> {
        self.authorize_with(
            ctx,
            &format!("Attach{}Policy", h.title()),
            &self.holder_arn(h, name),
            single("iam:PolicyARN", policy_arn),
        )?;
        let mut state = self.write();
        if !state.policies.contains_key(policy_arn) {
            return Err(errors::no_such_entity(format!("Policy {policy_arn} does not exist or is not attachable.")));
        }
        let (_, attached) = h.parts(&mut state, name).ok_or_else(|| h.not_found(name))?;
        if !attached.contains(policy_arn) && attached.len() >= MAX_MANAGED_POLICIES_PER_ENTITY {
            return Err(errors::limit_exceeded(format!(
                "Cannot exceed quota for PoliciesPer{}: {MAX_MANAGED_POLICIES_PER_ENTITY}",
                h.title()
            )));
        }
        attached.insert(policy_arn.to_string());
        Ok(())
    }

    fn detach(&self, ctx: &RequestContext, h: Holder, name: &str, policy_arn: &str) -> Result<(), ServiceError> {
        self.authorize_with(
            ctx,
            &format!("Detach{}Policy", h.title()),
            &self.holder_arn(h, name),
            single("iam:PolicyARN", policy_arn),
        )?;
        let mut state = self.write();
        let (_, attached) = h.parts(&mut state, name).ok_or_else(|| h.not_found(name))?;
        if !attached.remove(policy_arn) {
            return Err(errors::no_such_entity(format!("Policy {policy_arn} was not found.")));
        }
        Ok(())
    }

    fn list_attached(
        &self,
        ctx: &RequestContext,
        h: Holder,
        name: &str,
        prefix: Option<String>,
        marker: Option<String>,
        max: Option<i32>,
    ) -> Result<(Vec<types::AttachedPolicy>, bool, Option<String>), ServiceError> {
        self.authorize(ctx, &format!("ListAttached{}Policies", h.title()), &self.holder_arn(h, name))?;
        let state = self.read();
        let (_, attached, _) = h.parts_ref(&state, name).ok_or_else(|| h.not_found(name))?;
        let prefix = prefix.unwrap_or_else(|| "/".into());
        let items: Vec<types::AttachedPolicy> = wire::attached(attached, &state)
            .into_iter()
            .filter(|a| {
                a.policy_arn
                    .as_ref()
                    .and_then(|arn| state.policies.get(arn))
                    .is_some_and(|p| p.path.starts_with(&prefix))
            })
            .collect();
        paginate(&items, |a| a.policy_arn.clone().unwrap_or_default(), marker.as_deref(), max)
    }

    pub fn attach_user_policy(
        &self,
        ctx: &RequestContext,
        i: types::AttachUserPolicyRequest,
    ) -> Result<(), ServiceError> {
        self.attach(ctx, Holder::User, &i.user_name, &i.policy_arn)
    }
    pub fn attach_group_policy(
        &self,
        ctx: &RequestContext,
        i: types::AttachGroupPolicyRequest,
    ) -> Result<(), ServiceError> {
        self.attach(ctx, Holder::Group, &i.group_name, &i.policy_arn)
    }
    pub fn attach_role_policy(
        &self,
        ctx: &RequestContext,
        i: types::AttachRolePolicyRequest,
    ) -> Result<(), ServiceError> {
        self.attach(ctx, Holder::Role, &i.role_name, &i.policy_arn)
    }
    pub fn detach_user_policy(
        &self,
        ctx: &RequestContext,
        i: types::DetachUserPolicyRequest,
    ) -> Result<(), ServiceError> {
        self.detach(ctx, Holder::User, &i.user_name, &i.policy_arn)
    }
    pub fn detach_group_policy(
        &self,
        ctx: &RequestContext,
        i: types::DetachGroupPolicyRequest,
    ) -> Result<(), ServiceError> {
        self.detach(ctx, Holder::Group, &i.group_name, &i.policy_arn)
    }
    pub fn detach_role_policy(
        &self,
        ctx: &RequestContext,
        i: types::DetachRolePolicyRequest,
    ) -> Result<(), ServiceError> {
        self.detach(ctx, Holder::Role, &i.role_name, &i.policy_arn)
    }
    pub fn list_attached_user_policies(
        &self,
        ctx: &RequestContext,
        i: types::ListAttachedUserPoliciesRequest,
    ) -> Result<types::ListAttachedUserPoliciesResponse, ServiceError> {
        let (p, t, m) = self.list_attached(ctx, Holder::User, &i.user_name, i.path_prefix, i.marker, i.max_items)?;
        Ok(types::ListAttachedUserPoliciesResponse { attached_policies: Some(p), is_truncated: t, marker: m })
    }
    pub fn list_attached_group_policies(
        &self,
        ctx: &RequestContext,
        i: types::ListAttachedGroupPoliciesRequest,
    ) -> Result<types::ListAttachedGroupPoliciesResponse, ServiceError> {
        let (p, t, m) = self.list_attached(ctx, Holder::Group, &i.group_name, i.path_prefix, i.marker, i.max_items)?;
        Ok(types::ListAttachedGroupPoliciesResponse { attached_policies: Some(p), is_truncated: t, marker: m })
    }
    pub fn list_attached_role_policies(
        &self,
        ctx: &RequestContext,
        i: types::ListAttachedRolePoliciesRequest,
    ) -> Result<types::ListAttachedRolePoliciesResponse, ServiceError> {
        let (p, t, m) = self.list_attached(ctx, Holder::Role, &i.role_name, i.path_prefix, i.marker, i.max_items)?;
        Ok(types::ListAttachedRolePoliciesResponse { attached_policies: Some(p), is_truncated: t, marker: m })
    }

    // ---- inline policies ----------------------------------------------------

    fn put_inline(
        &self,
        ctx: &RequestContext,
        h: Holder,
        name: &str,
        policy_name: String,
        doc: String,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, &format!("Put{}Policy", h.title()), &self.holder_arn(h, name))?;
        validate_policy(&doc, PolicyKind::Identity)?;
        let mut state = self.write();
        let (inline, _) = h.parts(&mut state, name).ok_or_else(|| h.not_found(name))?;
        let mut total: usize =
            inline.iter().filter(|(k, _)| !k.eq_ignore_ascii_case(&policy_name)).map(|(_, d)| policy_size(d)).sum();
        total += policy_size(&doc);
        if total > h.inline_limit() {
            return Err(errors::limit_exceeded(format!(
                "Maximum policy size of {} bytes exceeded for {} {name}",
                h.inline_limit(),
                h.word()
            )));
        }
        inline.retain(|k, _| !k.eq_ignore_ascii_case(&policy_name));
        inline.insert(policy_name, doc);
        Ok(())
    }

    fn get_inline(
        &self,
        ctx: &RequestContext,
        h: Holder,
        name: &str,
        policy_name: &str,
    ) -> Result<(String, String, String), ServiceError> {
        self.authorize(ctx, &format!("Get{}Policy", h.title()), &self.holder_arn(h, name))?;
        let state = self.read();
        let (inline, _, real_name) = h.parts_ref(&state, name).ok_or_else(|| h.not_found(name))?;
        let (pname, doc) = inline.iter().find(|(k, _)| k.eq_ignore_ascii_case(policy_name)).ok_or_else(|| {
            errors::no_such_entity(format!("The {} policy with name {policy_name} cannot be found.", h.word()))
        })?;
        Ok((real_name, pname.clone(), encode_document(doc)))
    }

    fn delete_inline(
        &self,
        ctx: &RequestContext,
        h: Holder,
        name: &str,
        policy_name: &str,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, &format!("Delete{}Policy", h.title()), &self.holder_arn(h, name))?;
        let mut state = self.write();
        let (inline, _) = h.parts(&mut state, name).ok_or_else(|| h.not_found(name))?;
        let before = inline.len();
        inline.retain(|k, _| !k.eq_ignore_ascii_case(policy_name));
        if inline.len() == before {
            return Err(errors::no_such_entity(format!(
                "The {} policy with name {policy_name} cannot be found.",
                h.word()
            )));
        }
        Ok(())
    }

    fn list_inline(
        &self,
        ctx: &RequestContext,
        h: Holder,
        name: &str,
        marker: Option<String>,
        max: Option<i32>,
    ) -> Result<(Vec<String>, bool, Option<String>), ServiceError> {
        self.authorize(ctx, &format!("List{}Policies", h.title()), &self.holder_arn(h, name))?;
        let state = self.read();
        let (inline, _, _) = h.parts_ref(&state, name).ok_or_else(|| h.not_found(name))?;
        let names: Vec<String> = inline.keys().cloned().collect();
        paginate(&names, |n| n.clone(), marker.as_deref(), max)
    }

    pub fn put_user_policy(&self, ctx: &RequestContext, i: types::PutUserPolicyRequest) -> Result<(), ServiceError> {
        self.put_inline(ctx, Holder::User, &i.user_name, i.policy_name, i.policy_document)
    }
    pub fn put_group_policy(&self, ctx: &RequestContext, i: types::PutGroupPolicyRequest) -> Result<(), ServiceError> {
        self.put_inline(ctx, Holder::Group, &i.group_name, i.policy_name, i.policy_document)
    }
    pub fn put_role_policy(&self, ctx: &RequestContext, i: types::PutRolePolicyRequest) -> Result<(), ServiceError> {
        self.put_inline(ctx, Holder::Role, &i.role_name, i.policy_name, i.policy_document)
    }
    pub fn get_user_policy(
        &self,
        ctx: &RequestContext,
        i: types::GetUserPolicyRequest,
    ) -> Result<types::GetUserPolicyResponse, ServiceError> {
        let (user_name, policy_name, policy_document) =
            self.get_inline(ctx, Holder::User, &i.user_name, &i.policy_name)?;
        Ok(types::GetUserPolicyResponse { user_name, policy_name, policy_document })
    }
    pub fn get_group_policy(
        &self,
        ctx: &RequestContext,
        i: types::GetGroupPolicyRequest,
    ) -> Result<types::GetGroupPolicyResponse, ServiceError> {
        let (group_name, policy_name, policy_document) =
            self.get_inline(ctx, Holder::Group, &i.group_name, &i.policy_name)?;
        Ok(types::GetGroupPolicyResponse { group_name, policy_name, policy_document })
    }
    pub fn get_role_policy(
        &self,
        ctx: &RequestContext,
        i: types::GetRolePolicyRequest,
    ) -> Result<types::GetRolePolicyResponse, ServiceError> {
        let (role_name, policy_name, policy_document) =
            self.get_inline(ctx, Holder::Role, &i.role_name, &i.policy_name)?;
        Ok(types::GetRolePolicyResponse { role_name, policy_name, policy_document })
    }
    pub fn delete_user_policy(
        &self,
        ctx: &RequestContext,
        i: types::DeleteUserPolicyRequest,
    ) -> Result<(), ServiceError> {
        self.delete_inline(ctx, Holder::User, &i.user_name, &i.policy_name)
    }
    pub fn delete_group_policy(
        &self,
        ctx: &RequestContext,
        i: types::DeleteGroupPolicyRequest,
    ) -> Result<(), ServiceError> {
        self.delete_inline(ctx, Holder::Group, &i.group_name, &i.policy_name)
    }
    pub fn delete_role_policy(
        &self,
        ctx: &RequestContext,
        i: types::DeleteRolePolicyRequest,
    ) -> Result<(), ServiceError> {
        self.delete_inline(ctx, Holder::Role, &i.role_name, &i.policy_name)
    }
    pub fn list_user_policies(
        &self,
        ctx: &RequestContext,
        i: types::ListUserPoliciesRequest,
    ) -> Result<types::ListUserPoliciesResponse, ServiceError> {
        let (policy_names, is_truncated, marker) =
            self.list_inline(ctx, Holder::User, &i.user_name, i.marker, i.max_items)?;
        Ok(types::ListUserPoliciesResponse { policy_names, is_truncated, marker })
    }
    pub fn list_group_policies(
        &self,
        ctx: &RequestContext,
        i: types::ListGroupPoliciesRequest,
    ) -> Result<types::ListGroupPoliciesResponse, ServiceError> {
        let (policy_names, is_truncated, marker) =
            self.list_inline(ctx, Holder::Group, &i.group_name, i.marker, i.max_items)?;
        Ok(types::ListGroupPoliciesResponse { policy_names, is_truncated, marker })
    }
    pub fn list_role_policies(
        &self,
        ctx: &RequestContext,
        i: types::ListRolePoliciesRequest,
    ) -> Result<types::ListRolePoliciesResponse, ServiceError> {
        let (policy_names, is_truncated, marker) =
            self.list_inline(ctx, Holder::Role, &i.role_name, i.marker, i.max_items)?;
        Ok(types::ListRolePoliciesResponse { policy_names, is_truncated, marker })
    }
}

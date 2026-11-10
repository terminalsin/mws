//! Users, login profiles and access keys.

use mws_core::{CallerKind, RequestContext, ServiceError};

use crate::common::*;
use crate::generated::{errors, types};
use crate::state::{AccessKey, LoginProfile, User};
use crate::{ids, wire, Iam};

const MAX_ACCESS_KEYS_PER_USER: usize = 2;

/// Who an operation without an explicit `UserName` acts on.
pub(crate) enum Subject {
    Root,
    User(String),
}

impl Iam {
    pub(crate) fn subject(&self, ctx: &RequestContext, user_name: Option<String>) -> Result<Subject, ServiceError> {
        if let Some(name) = user_name {
            return Ok(Subject::User(name));
        }
        match &ctx.caller.kind {
            CallerKind::Root => Ok(Subject::Root),
            CallerKind::User { name } => Ok(Subject::User(name.clone())),
            _ => Err(validation("Must specify userName when calling with non-User credentials")),
        }
    }

    fn subject_arn(&self, ctx: &RequestContext, subject: &Subject) -> String {
        match subject {
            Subject::Root => ctx.caller.arn.clone(),
            Subject::User(name) => self.user_arn_or_default(name),
        }
    }

    pub(crate) fn check_boundary_exists(&self, arn: &str) -> Result<(), ServiceError> {
        if self.read().policies.contains_key(arn) {
            Ok(())
        } else {
            Err(errors::no_such_entity(format!("Policy {arn} does not exist or is not attachable.")))
        }
    }

    pub fn create_user(
        &self,
        ctx: &RequestContext,
        input: types::CreateUserRequest,
    ) -> Result<types::CreateUserResponse, ServiceError> {
        let path = input.path.unwrap_or_else(|| "/".into());
        let arn = self.entity_arn("user", &path, &input.user_name);
        let tags = tags_from_wire(input.tags)?;
        let mut cond = request_tag_context(&tags);
        if let Some(b) = &input.permissions_boundary {
            cond.insert("iam:PermissionsBoundary".into(), vec![b.clone()]);
        }
        self.authorize_with(ctx, "CreateUser", &arn, cond)?;
        self.authorize_tagging(ctx, "TagUser", &arn, &tags)?;
        if tags.len() > MAX_TAGS {
            return Err(errors::limit_exceeded(format!("Cannot exceed quota for TagsPerUser: {MAX_TAGS}")));
        }
        if let Some(b) = &input.permissions_boundary {
            self.check_boundary_exists(b)?;
        }
        let limit = self.limit(ctx, &USERS_PER_ACCOUNT);
        let mut state = self.write();
        let key = input.user_name.to_lowercase();
        if state.users.contains_key(&key) {
            return Err(errors::entity_already_exists(format!("User with name {} already exists.", input.user_name)));
        }
        if state.users.len() >= limit {
            return Err(quota_exceeded(USERS_PER_ACCOUNT.name, limit));
        }
        let user = User {
            name: input.user_name,
            path,
            id: ids::unique_id("AIDA"),
            arn,
            created: ctx.received_at,
            permissions_boundary: input.permissions_boundary,
            tags,
            inline: Default::default(),
            attached: Default::default(),
            login_profile: None,
            password_last_used: None,
        };
        let out = wire::user(&user);
        state.users.insert(key, user);
        Ok(types::CreateUserResponse { user: Some(out) })
    }

    pub fn get_user(
        &self,
        ctx: &RequestContext,
        input: types::GetUserRequest,
    ) -> Result<types::GetUserResponse, ServiceError> {
        match self.subject(ctx, input.user_name)? {
            Subject::Root => {
                let arn = ctx.caller.arn.clone();
                self.authorize(ctx, "GetUser", &arn)?;
                Ok(types::GetUserResponse {
                    user: types::User {
                        user_id: self.account_id().to_string(),
                        arn,
                        create_date: self.inner.created_at,
                        ..Default::default()
                    },
                })
            }
            Subject::User(name) => {
                let (arn, tags) = {
                    let s = self.read();
                    match s.user(&name) {
                        Some(u) => (u.arn.clone(), u.tags.clone()),
                        None => (self.entity_arn("user", "/", &name), vec![]),
                    }
                };
                self.authorize_with(ctx, "GetUser", &arn, resource_tag_context(&tags))?;
                let s = self.read();
                let user = s.user(&name).ok_or_else(|| no_such_user(&name))?;
                Ok(types::GetUserResponse { user: wire::user(user) })
            }
        }
    }

    pub fn list_users(
        &self,
        ctx: &RequestContext,
        input: types::ListUsersRequest,
    ) -> Result<types::ListUsersResponse, ServiceError> {
        self.authorize(ctx, "ListUsers", &self.arn("user/"))?;
        let prefix = input.path_prefix.unwrap_or_else(|| "/".into());
        let users: Vec<User> = self.read().users.values().filter(|u| u.path.starts_with(&prefix)).cloned().collect();
        let (page, is_truncated, marker) =
            paginate(&users, |u| u.name.to_lowercase(), input.marker.as_deref(), input.max_items)?;
        Ok(types::ListUsersResponse { users: page.iter().map(wire::user_summary).collect(), is_truncated, marker })
    }

    pub fn update_user(&self, ctx: &RequestContext, input: types::UpdateUserRequest) -> Result<(), ServiceError> {
        let arn = self.user_arn_or_default(&input.user_name);
        self.authorize(ctx, "UpdateUser", &arn)?;
        let mut state = self.write();
        let mut user = state.user(&input.user_name).cloned().ok_or_else(|| no_such_user(&input.user_name))?;
        let old_key = user.name.to_lowercase();
        if let Some(new_name) = &input.new_user_name {
            let new_key = new_name.to_lowercase();
            if new_key != old_key && state.users.contains_key(&new_key) {
                return Err(errors::entity_already_exists(format!("User with name {new_name} already exists.")));
            }
            user.name = new_name.clone();
        }
        if let Some(p) = input.new_path {
            user.path = p;
        }
        user.arn = self.entity_arn("user", &user.path, &user.name);
        let new_key = user.name.to_lowercase();
        state.users.remove(&old_key);
        if new_key != old_key {
            for g in state.groups.values_mut() {
                if g.members.remove(&old_key) {
                    g.members.insert(new_key.clone());
                }
            }
            for k in state.access_keys.values_mut() {
                if k.user_name.as_deref().map(str::to_lowercase).as_deref() == Some(old_key.as_str()) {
                    k.user_name = Some(user.name.clone());
                }
            }
            for d in state.mfa_devices.values_mut().filter(|d| d.user.as_deref() == Some(old_key.as_str())) {
                d.user = Some(new_key.clone());
            }
            for k in state.ssh_keys.values_mut().filter(|k| k.user == old_key) {
                k.user = new_key.clone();
            }
            for c in state.signing_certificates.values_mut().filter(|c| c.user.as_deref() == Some(old_key.as_str())) {
                c.user = Some(new_key.clone());
            }
            for c in state.service_credentials.values_mut().filter(|c| c.user == old_key) {
                c.user = new_key.clone();
            }
        }
        state.users.insert(new_key, user);
        Ok(())
    }

    pub fn delete_user(&self, ctx: &RequestContext, input: types::DeleteUserRequest) -> Result<(), ServiceError> {
        let arn = self.user_arn_or_default(&input.user_name);
        self.authorize(ctx, "DeleteUser", &arn)?;
        let mut state = self.write();
        let user = state.user(&input.user_name).ok_or_else(|| no_such_user(&input.user_name))?;
        let conflict = |what: &str| errors::delete_conflict(format!("Cannot delete entity, must {what} first."));
        if user.login_profile.is_some() {
            return Err(conflict("delete login profile"));
        }
        if !state.keys_for(Some(&input.user_name)).is_empty() {
            return Err(conflict("delete access keys"));
        }
        if !user.inline.is_empty() {
            return Err(conflict("delete policies"));
        }
        if !user.attached.is_empty() {
            return Err(conflict("detach all policies"));
        }
        if !state.groups_for_user(&input.user_name).is_empty() {
            return Err(conflict("remove user from all groups"));
        }
        let key = input.user_name.to_lowercase();
        if state.signing_certificates.values().any(|c| c.user.as_deref() == Some(key.as_str())) {
            return Err(conflict("delete signing certificates"));
        }
        if state.ssh_keys.values().any(|k| k.user == key) {
            return Err(conflict("delete SSH public keys"));
        }
        if state.service_credentials.values().any(|c| c.user == key) {
            return Err(conflict("delete service specific credentials"));
        }
        if state.mfa_devices.values().any(|d| d.user.as_deref() == Some(key.as_str())) {
            return Err(conflict("delete MFA device"));
        }
        if let Some(user) = state.users.remove(&input.user_name.to_lowercase()) {
            retire_principal(state.every_account(), &user.arn, &user.id);
        }
        Ok(())
    }

    pub fn tag_user(&self, ctx: &RequestContext, input: types::TagUserRequest) -> Result<(), ServiceError> {
        let arn = self.user_arn_or_default(&input.user_name);
        let tags = tags_from_wire(Some(input.tags))?;
        self.authorize_with(ctx, "TagUser", &arn, request_tag_context(&tags))?;
        let mut state = self.write();
        let user = state.user_mut(&input.user_name).ok_or_else(|| no_such_user(&input.user_name))?;
        merge_tags(&mut user.tags, tags, "TagsPerUser")
    }

    pub fn untag_user(&self, ctx: &RequestContext, input: types::UntagUserRequest) -> Result<(), ServiceError> {
        let arn = self.user_arn_or_default(&input.user_name);
        let mut cond = mws_core::ConditionContext::new();
        cond.insert("aws:TagKeys".into(), input.tag_keys.clone());
        self.authorize_with(ctx, "UntagUser", &arn, cond)?;
        let mut state = self.write();
        let user = state.user_mut(&input.user_name).ok_or_else(|| no_such_user(&input.user_name))?;
        remove_tags(&mut user.tags, &input.tag_keys);
        Ok(())
    }

    pub fn list_user_tags(
        &self,
        ctx: &RequestContext,
        input: types::ListUserTagsRequest,
    ) -> Result<types::ListUserTagsResponse, ServiceError> {
        let arn = self.user_arn_or_default(&input.user_name);
        self.authorize(ctx, "ListUserTags", &arn)?;
        let tags = self.read().user(&input.user_name).ok_or_else(|| no_such_user(&input.user_name))?.tags.clone();
        let (page, is_truncated, marker) =
            paginate(&tags, |(k, _)| k.clone(), input.marker.as_deref(), input.max_items)?;
        Ok(types::ListUserTagsResponse { tags: tags_list(&page), is_truncated, marker })
    }

    pub fn put_user_permissions_boundary(
        &self,
        ctx: &RequestContext,
        input: types::PutUserPermissionsBoundaryRequest,
    ) -> Result<(), ServiceError> {
        let arn = self.user_arn_or_default(&input.user_name);
        self.authorize_with(
            ctx,
            "PutUserPermissionsBoundary",
            &arn,
            single("iam:PermissionsBoundary", &input.permissions_boundary),
        )?;
        self.check_boundary_exists(&input.permissions_boundary)?;
        let mut state = self.write();
        let user = state.user_mut(&input.user_name).ok_or_else(|| no_such_user(&input.user_name))?;
        user.permissions_boundary = Some(input.permissions_boundary);
        Ok(())
    }

    pub fn delete_user_permissions_boundary(
        &self,
        ctx: &RequestContext,
        input: types::DeleteUserPermissionsBoundaryRequest,
    ) -> Result<(), ServiceError> {
        let arn = self.user_arn_or_default(&input.user_name);
        self.authorize(ctx, "DeleteUserPermissionsBoundary", &arn)?;
        let mut state = self.write();
        let user = state.user_mut(&input.user_name).ok_or_else(|| no_such_user(&input.user_name))?;
        user.permissions_boundary = None;
        Ok(())
    }

    // ---- login profiles -----------------------------------------------------

    pub fn create_login_profile(
        &self,
        ctx: &RequestContext,
        input: types::CreateLoginProfileRequest,
    ) -> Result<types::CreateLoginProfileResponse, ServiceError> {
        let Subject::User(name) = self.subject(ctx, input.user_name)? else {
            return Err(validation("The root user's password is managed in the console."));
        };
        self.authorize(ctx, "CreateLoginProfile", &self.user_arn_or_default(&name))?;
        let mut state = self.write();
        let policy = state.password_policy.clone();
        let user = state.user_mut(&name).ok_or_else(|| no_such_user(&name))?;
        if user.login_profile.is_some() {
            return Err(errors::entity_already_exists(format!("Login Profile for user {name} already exists.")));
        }
        if let Some(pw) = &input.password {
            crate::ops::settings::check_password(policy.as_ref(), pw, &[])?;
        }
        let now = ctx.received_at;
        let profile = LoginProfile {
            created: now,
            password: input.password.unwrap_or_default(),
            reset_required: input.password_reset_required,
            changed: Some(now),
            history: vec![],
        };
        let out = types::LoginProfile {
            user_name: user.name.clone(),
            create_date: profile.created,
            password_reset_required: profile.reset_required,
        };
        user.login_profile = Some(profile);
        Ok(types::CreateLoginProfileResponse { login_profile: out })
    }

    pub fn get_login_profile(
        &self,
        ctx: &RequestContext,
        input: types::GetLoginProfileRequest,
    ) -> Result<types::GetLoginProfileResponse, ServiceError> {
        let Subject::User(name) = self.subject(ctx, input.user_name)? else {
            return Err(errors::no_such_entity("Login Profile for the root user cannot be found."));
        };
        self.authorize(ctx, "GetLoginProfile", &self.user_arn_or_default(&name))?;
        let state = self.read();
        let user = state.user(&name).ok_or_else(|| no_such_user(&name))?;
        let p = user
            .login_profile
            .as_ref()
            .ok_or_else(|| errors::no_such_entity(format!("Login Profile for User {name} cannot be found.")))?;
        Ok(types::GetLoginProfileResponse {
            login_profile: types::LoginProfile {
                user_name: user.name.clone(),
                create_date: p.created,
                password_reset_required: p.reset_required,
            },
        })
    }

    pub fn update_login_profile(
        &self,
        ctx: &RequestContext,
        input: types::UpdateLoginProfileRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "UpdateLoginProfile", &self.user_arn_or_default(&input.user_name))?;
        let mut state = self.write();
        let policy = state.password_policy.clone();
        let user = state.user_mut(&input.user_name).ok_or_else(|| no_such_user(&input.user_name))?;
        let name = user.name.clone();
        let p = user
            .login_profile
            .as_mut()
            .ok_or_else(|| errors::no_such_entity(format!("Login Profile for User {name} cannot be found.")))?;
        if let Some(pw) = input.password {
            let mut history = p.history.clone();
            history.push(p.password.clone());
            crate::ops::settings::check_password(policy.as_ref(), &pw, &history)?;
            p.set_password(pw, ctx.received_at);
        }
        if let Some(r) = input.password_reset_required {
            p.reset_required = r;
        }
        Ok(())
    }

    pub fn delete_login_profile(
        &self,
        ctx: &RequestContext,
        input: types::DeleteLoginProfileRequest,
    ) -> Result<(), ServiceError> {
        let Subject::User(name) = self.subject(ctx, input.user_name)? else {
            return Err(errors::no_such_entity("Login Profile for the root user cannot be found."));
        };
        self.authorize(ctx, "DeleteLoginProfile", &self.user_arn_or_default(&name))?;
        let mut state = self.write();
        let user = state.user_mut(&name).ok_or_else(|| no_such_user(&name))?;
        if user.login_profile.take().is_none() {
            return Err(errors::no_such_entity(format!("Login Profile for User {name} cannot be found.")));
        }
        Ok(())
    }

    // ---- access keys --------------------------------------------------------

    pub fn create_access_key(
        &self,
        ctx: &RequestContext,
        input: types::CreateAccessKeyRequest,
    ) -> Result<types::CreateAccessKeyResponse, ServiceError> {
        let subject = self.subject(ctx, input.user_name)?;
        self.authorize(ctx, "CreateAccessKey", &self.subject_arn(ctx, &subject))?;
        let mut state = self.write();
        let user_name = match &subject {
            Subject::Root => None,
            Subject::User(name) => Some(state.user(name).ok_or_else(|| no_such_user(name))?.name.clone()),
        };
        if state.keys_for(user_name.as_deref()).len() >= MAX_ACCESS_KEYS_PER_USER {
            return Err(errors::limit_exceeded(format!(
                "Cannot exceed quota for AccessKeysPerUser: {MAX_ACCESS_KEYS_PER_USER}"
            )));
        }
        let key = AccessKey {
            id: ids::access_key_id(&ctx.caller.account_id),
            secret: ids::secret_access_key(),
            user_name: user_name.clone(),
            active: true,
            created: ctx.received_at,
            last_used: None,
        };
        let out = types::AccessKey {
            user_name: user_name.unwrap_or_default(),
            access_key_id: key.id.clone(),
            status: "Active".into(),
            secret_access_key: key.secret.clone(),
            create_date: Some(key.created),
        };
        state.access_keys.insert(key.id.clone(), key);
        Ok(types::CreateAccessKeyResponse { access_key: out })
    }

    pub fn list_access_keys(
        &self,
        ctx: &RequestContext,
        input: types::ListAccessKeysRequest,
    ) -> Result<types::ListAccessKeysResponse, ServiceError> {
        let subject = self.subject(ctx, input.user_name)?;
        self.authorize(ctx, "ListAccessKeys", &self.subject_arn(ctx, &subject))?;
        let state = self.read();
        let user_name = match &subject {
            Subject::Root => None,
            Subject::User(name) => Some(state.user(name).ok_or_else(|| no_such_user(name))?.name.clone()),
        };
        let keys: Vec<AccessKey> = state.keys_for(user_name.as_deref()).into_iter().cloned().collect();
        let (page, is_truncated, marker) = paginate(&keys, |k| k.id.clone(), input.marker.as_deref(), input.max_items)?;
        Ok(types::ListAccessKeysResponse {
            access_key_metadata: page
                .iter()
                .map(|k| types::AccessKeyMetadata {
                    user_name: k.user_name.clone(),
                    access_key_id: Some(k.id.clone()),
                    status: Some(status_str(k.active).into()),
                    create_date: Some(k.created),
                })
                .collect(),
            is_truncated,
            marker,
        })
    }

    pub fn delete_access_key(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessKeyRequest,
    ) -> Result<(), ServiceError> {
        let subject = self.subject(ctx, input.user_name)?;
        self.authorize(ctx, "DeleteAccessKey", &self.subject_arn(ctx, &subject))?;
        let mut state = self.write();
        check_key_owner(&state, &subject, &input.access_key_id)?;
        state.access_keys.remove(&input.access_key_id);
        Ok(())
    }

    pub fn update_access_key(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAccessKeyRequest,
    ) -> Result<(), ServiceError> {
        let subject = self.subject(ctx, input.user_name)?;
        self.authorize(ctx, "UpdateAccessKey", &self.subject_arn(ctx, &subject))?;
        let mut state = self.write();
        check_key_owner(&state, &subject, &input.access_key_id)?;
        if let Some(k) = state.access_keys.get_mut(&input.access_key_id) {
            k.active = input.status == "Active";
        }
        Ok(())
    }

    pub fn get_access_key_last_used(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessKeyLastUsedRequest,
    ) -> Result<types::GetAccessKeyLastUsedResponse, ServiceError> {
        let (user_name, last_used) = {
            let s = self.read();
            let k = s.access_keys.get(&input.access_key_id).ok_or_else(|| {
                errors::no_such_entity(format!("The Access Key with id {} cannot be found.", input.access_key_id))
            })?;
            (k.user_name.clone(), k.last_used.clone())
        };
        let arn = match &user_name {
            Some(n) => self.user_arn_or_default(n),
            None => self.arn("root"),
        };
        self.authorize(ctx, "GetAccessKeyLastUsed", &arn)?;
        Ok(types::GetAccessKeyLastUsedResponse {
            user_name: Some(user_name.unwrap_or_else(|| "root".into())),
            access_key_last_used: Some(match last_used {
                Some((t, svc, region)) => {
                    types::AccessKeyLastUsed { last_used_date: Some(t), service_name: svc, region }
                }
                None => {
                    types::AccessKeyLastUsed { last_used_date: None, service_name: "N/A".into(), region: "N/A".into() }
                }
            }),
        })
    }
}

fn check_key_owner(state: &crate::State, subject: &Subject, key_id: &str) -> Result<(), ServiceError> {
    let not_found = || errors::no_such_entity(format!("The Access Key with id {key_id} cannot be found."));
    let key = state.access_keys.get(key_id).ok_or_else(not_found)?;
    match subject {
        Subject::Root if key.user_name.is_none() => Ok(()),
        Subject::Root => Err(not_found()),
        Subject::User(name) => {
            state.user(name).ok_or_else(|| no_such_user(name))?;
            if key.user_name.as_deref().map(str::to_lowercase) == Some(name.to_lowercase()) {
                Ok(())
            } else {
                Err(not_found())
            }
        }
    }
}

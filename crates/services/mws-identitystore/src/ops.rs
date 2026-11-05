//! The Identity Store API.

use mws_core::{ConditionContext, ErrorValue, RequestContext, ServiceError};

use crate::generated::{errors, types, Handler};
use crate::state::{Membership, Store};
use crate::{attrs, IdentityStore};

fn not_found(kind: &str, id: &str, message: impl Into<String>) -> ServiceError {
    errors::resource_not_found(message)
        .with_field("ResourceType", ErrorValue::String(kind.into()))
        .with_field("ResourceId", ErrorValue::String(id.into()))
}

fn conflict(reason: &str, message: impl Into<String>) -> ServiceError {
    errors::conflict(message).with_field("Reason", ErrorValue::String(reason.into()))
}

fn store_not_found(id: &str) -> ServiceError {
    not_found("IDENTITY_STORE", id, format!("Identity store {id} doesn't exist."))
}

fn user_not_found(id: &str) -> ServiceError {
    not_found("USER", id, format!("USER not found: {id}"))
}

fn group_not_found(id: &str) -> ServiceError {
    not_found("GROUP", id, format!("GROUP not found: {id}"))
}

fn membership_not_found(id: &str) -> ServiceError {
    not_found("GROUP_MEMBERSHIP", id, format!("GROUP_MEMBERSHIP not found: {id}"))
}

/// The bare id of an identity store given by id or ARN.
fn store_id(raw: &str) -> &str {
    raw.rsplit('/').next().unwrap_or(raw)
}

/// The bare id of a user, group or membership given by id or ARN.
fn resource_id(raw: &str) -> &str {
    raw.rsplit('/').next().unwrap_or(raw)
}

pub(crate) fn new_resource_id() -> String {
    let prefix: String = uuid::Uuid::new_v4().simple().to_string()[..10].to_string();
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

fn paginate<T>(items: Vec<T>, max: i32, token: Option<&str>) -> Result<(Vec<T>, Option<String>), ServiceError> {
    let start = match token {
        Some(t) => t
            .strip_prefix("mws-")
            .and_then(|n| n.parse::<usize>().ok())
            .ok_or_else(|| errors::validation("The NextToken provided is invalid."))?,
        None => 0,
    };
    let max = if max > 0 { max as usize } else { 100 };
    let total = items.len();
    let page: Vec<T> = items.into_iter().skip(start).take(max).collect();
    let next = (start + max < total).then(|| format!("mws-{}", start + max));
    Ok((page, next))
}

fn member_user(m: &types::MemberId) -> &str {
    match m {
        types::MemberId::UserId(id) => id.as_str(),
    }
}

/// How an operation may reach a store.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Access {
    /// Only the account that owns the store.
    Write,
    /// The owner, or any account of its organization.
    Read,
}

impl IdentityStore {
    /// Look up the store, check the caller's account may reach it, then
    /// authorize `action` on `resource` (the store's ARN when `None`).
    fn gate(
        &self,
        ctx: &RequestContext,
        raw_store: &str,
        action: &str,
        access: Access,
        resource: Option<String>,
    ) -> Result<String, ServiceError> {
        let id = store_id(raw_store).to_string();
        let (owner, arn) = {
            let st = self.lock();
            let s = st.stores.get(&id).ok_or_else(|| store_not_found(&id))?;
            (s.account.clone(), s.arn())
        };
        let caller = ctx.caller.account_id.as_str();
        if caller != owner {
            let same_org = || {
                let mine = self.iam.organization_of(caller);
                let theirs = self.iam.organization_of(&owner);
                matches!((mine, theirs), (Some(a), Some(b)) if a.organization_id == b.organization_id)
            };
            if access == Access::Write || !same_org() {
                return Err(errors::access_denied(format!(
                    "User: {} is not authorized to perform: {action} on resource: {arn}",
                    ctx.caller.arn
                )));
            }
        }
        ctx.authorize(action, &resource.unwrap_or(arn), ConditionContext::new())?;
        Ok(id)
    }

    fn with_store<T>(&self, id: &str, f: impl FnOnce(&mut Store) -> Result<T, ServiceError>) -> Result<T, ServiceError> {
        let mut st = self.lock();
        let s = st.stores.get_mut(id).ok_or_else(|| store_not_found(id))?;
        f(s)
    }

    fn user_arn_for(&self, _store: &str, user: &str) -> String {
        format!("arn:{}:identitystore:::user/{}", self.iam.partition(), resource_id(user))
    }

    fn group_arn_for(&self, group: &str) -> String {
        format!("arn:{}:identitystore:::group/{}", self.iam.partition(), resource_id(group))
    }

    fn membership_arn_for(&self, membership: &str) -> String {
        format!("arn:{}:identitystore:::membership/{}", self.iam.partition(), resource_id(membership))
    }
}

fn check_revision(current: &str, given: Option<&str>) -> Result<(), ServiceError> {
    match given {
        Some(r) if r != current => Err(conflict(
            "CONCURRENT_MODIFICATION",
            "The resource was modified since the revision you provided. Retrieve the latest revision and try again.",
        )),
        _ => Ok(()),
    }
}

fn bump(revision: &str) -> String {
    (revision.parse::<u64>().unwrap_or(0) + 1).to_string()
}

fn user_name_taken(s: &Store, name: &str, except: Option<&str>) -> bool {
    s.users.values().any(|u| {
        Some(u.user_id.as_str()) != except && u.user_name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case(name))
    })
}

fn group_name_taken(s: &Store, name: &str, except: Option<&str>) -> bool {
    s.groups.values().any(|g| {
        Some(g.group_id.as_str()) != except && g.display_name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case(name))
    })
}

fn duplicate_user() -> ServiceError {
    conflict("UNIQUENESS_CONSTRAINT_VIOLATION", "Duplicate UserName")
}

fn duplicate_group() -> ServiceError {
    conflict("UNIQUENESS_CONSTRAINT_VIOLATION", "Duplicate GroupDisplayName")
}

/// A user with only the extensions the caller asked for.
fn with_extensions(mut u: types::User, wanted: Option<&[String]>) -> types::User {
    u.extensions = match (u.extensions.take(), wanted) {
        (Some(all), Some(wanted)) => {
            let picked: std::collections::BTreeMap<_, _> =
                all.into_iter().filter(|(k, _)| wanted.iter().any(|w| w == k)).collect();
            (!picked.is_empty()).then_some(picked)
        }
        _ => None,
    };
    u
}

fn membership_view(s: &Store, m: &Membership) -> types::GroupMembership {
    types::GroupMembership {
        identity_store_id: s.id.clone(),
        membership_id: m.id.clone(),
        membership_arn: s.membership_arn(&m.id),
        group_id: Some(m.group_id.clone()),
        member_id: Some(types::MemberId::UserId(m.user_id.clone())),
        created_at: m.created_at,
        updated_at: m.created_at,
        created_by: m.created_by.clone(),
        updated_by: m.created_by.clone(),
    }
}

#[async_trait::async_trait]
impl Handler for IdentityStore {
    async fn create_user(
        &self,
        ctx: &RequestContext,
        input: types::CreateUserRequest,
    ) -> Result<types::CreateUserResponse, ServiceError> {
        let id = self.gate(ctx, &input.identity_store_id, "identitystore:CreateUser", Access::Write, None)?;
        let user_name = input
            .user_name
            .clone()
            .ok_or_else(|| errors::validation("UserName is a required attribute and cannot be null."))?;
        if let Some(ext) = &input.extensions {
            if let Some(bad) = ext.keys().find(|k| k.as_str() != "aws:identitystore:enterprise") {
                return Err(errors::validation(format!("Invalid extension name: {bad}")));
            }
        }
        let now = ctx.received_at;
        self.with_store(&id, |s| {
            if user_name_taken(s, &user_name, None) {
                return Err(duplicate_user());
            }
            let user_id = new_resource_id();
            let user = types::User {
                identity_store_id: s.id.clone(),
                user_id: user_id.clone(),
                user_arn: s.user_arn(&user_id),
                revision: "1".into(),
                user_name: Some(user_name),
                external_ids: None,
                name: input.name,
                display_name: input.display_name,
                nick_name: input.nick_name,
                profile_url: input.profile_url,
                emails: input.emails,
                addresses: input.addresses,
                phone_numbers: input.phone_numbers,
                user_type: input.user_type,
                title: input.title,
                preferred_language: input.preferred_language,
                locale: input.locale,
                timezone: input.timezone,
                user_status: Some("ENABLED".into()),
                photos: input.photos,
                website: input.website,
                birthdate: input.birthdate,
                roles: input.roles,
                created_at: Some(now),
                created_by: Some(ctx.caller.arn.clone()),
                updated_at: Some(now),
                updated_by: Some(ctx.caller.arn.clone()),
                extensions: input.extensions.filter(|e| !e.is_empty()),
            };
            let out = types::CreateUserResponse {
                identity_store_id: s.id.clone(),
                user_id: user_id.clone(),
                user_arn: user.user_arn.clone(),
                revision: user.revision.clone(),
            };
            s.users.insert(user_id, user);
            Ok(out)
        })
    }

    async fn describe_user(
        &self,
        ctx: &RequestContext,
        input: types::DescribeUserRequest,
    ) -> Result<types::DescribeUserResponse, ServiceError> {
        let arn = self.user_arn_for(&input.identity_store_id, &input.user_id);
        let id = self.gate(ctx, &input.identity_store_id, "identitystore:DescribeUser", Access::Read, Some(arn))?;
        let user_id = resource_id(&input.user_id).to_string();
        self.with_store(&id, |s| {
            let u = s.users.get(&user_id).cloned().ok_or_else(|| user_not_found(&user_id))?;
            let u = with_extensions(u, input.extensions.as_deref());
            Ok(types::DescribeUserResponse {
                identity_store_id: u.identity_store_id,
                user_id: u.user_id,
                user_arn: u.user_arn,
                revision: u.revision,
                user_name: u.user_name,
                external_ids: u.external_ids,
                name: u.name,
                display_name: u.display_name,
                nick_name: u.nick_name,
                profile_url: u.profile_url,
                emails: u.emails,
                addresses: u.addresses,
                phone_numbers: u.phone_numbers,
                user_type: u.user_type,
                title: u.title,
                preferred_language: u.preferred_language,
                locale: u.locale,
                timezone: u.timezone,
                user_status: u.user_status,
                photos: u.photos,
                website: u.website,
                birthdate: u.birthdate,
                roles: u.roles,
                created_at: u.created_at,
                created_by: u.created_by,
                updated_at: u.updated_at,
                updated_by: u.updated_by,
                extensions: u.extensions,
            })
        })
    }

    async fn update_user(
        &self,
        ctx: &RequestContext,
        input: types::UpdateUserRequest,
    ) -> Result<types::UpdateUserResponse, ServiceError> {
        let arn = self.user_arn_for(&input.identity_store_id, &input.user_id);
        let id = self.gate(ctx, &input.identity_store_id, "identitystore:UpdateUser", Access::Write, Some(arn))?;
        let user_id = resource_id(&input.user_id).to_string();
        if input.operations.is_empty() {
            return Err(errors::validation("Operations must contain at least one operation."));
        }
        self.with_store(&id, |s| {
            let mut u = s.users.get(&user_id).cloned().ok_or_else(|| user_not_found(&user_id))?;
            check_revision(&u.revision, input.revision.as_deref())?;
            for op in &input.operations {
                attrs::update_user(&mut u, op).map_err(errors::validation)?;
            }
            if let Some(name) = u.user_name.clone() {
                if user_name_taken(s, &name, Some(&user_id)) {
                    return Err(duplicate_user());
                }
            }
            u.revision = bump(&u.revision);
            u.updated_at = Some(ctx.received_at);
            u.updated_by = Some(ctx.caller.arn.clone());
            let out = types::UpdateUserResponse {
                identity_store_id: s.id.clone(),
                user_id: u.user_id.clone(),
                user_arn: u.user_arn.clone(),
                revision: u.revision.clone(),
            };
            s.users.insert(user_id, u);
            Ok(out)
        })
    }

    async fn delete_user(
        &self,
        ctx: &RequestContext,
        input: types::DeleteUserRequest,
    ) -> Result<types::DeleteUserResponse, ServiceError> {
        let arn = self.user_arn_for(&input.identity_store_id, &input.user_id);
        let id = self.gate(ctx, &input.identity_store_id, "identitystore:DeleteUser", Access::Write, Some(arn))?;
        let user_id = resource_id(&input.user_id).to_string();
        self.with_store(&id, |s| {
            let u = s.users.get(&user_id).ok_or_else(|| user_not_found(&user_id))?;
            check_revision(&u.revision, input.revision.as_deref())?;
            s.users.remove(&user_id);
            s.memberships.retain(|_, m| m.user_id != user_id);
            Ok(types::DeleteUserResponse {})
        })
    }

    async fn list_users(
        &self,
        ctx: &RequestContext,
        input: types::ListUsersRequest,
    ) -> Result<types::ListUsersResponse, ServiceError> {
        let id = self.gate(ctx, &input.identity_store_id, "identitystore:ListUsers", Access::Read, None)?;
        let filters = input.filters.unwrap_or_default();
        if filters.len() > 1 {
            return Err(errors::validation("Only one filter is supported."));
        }
        for f in &filters {
            if !f.attribute_path.eq_ignore_ascii_case("UserName") {
                return Err(errors::validation(format!("Invalid filter attribute path {}.", f.attribute_path)));
            }
        }
        let users = self.with_store(&id, |s| {
            Ok(s.users
                .values()
                .filter(|u| {
                    filters.iter().all(|f| {
                        u.user_name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case(&f.attribute_value))
                    })
                })
                .cloned()
                .map(|u| with_extensions(u, input.extensions.as_deref()))
                .collect::<Vec<_>>())
        })?;
        let (users, next_token) = paginate(users, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListUsersResponse { users, next_token })
    }

    async fn get_user_id(
        &self,
        ctx: &RequestContext,
        input: types::GetUserIdRequest,
    ) -> Result<types::GetUserIdResponse, ServiceError> {
        let id = self.gate(ctx, &input.identity_store_id, "identitystore:GetUserId", Access::Read, None)?;
        self.with_store(&id, |s| {
            let found = match &input.alternate_identifier {
                types::AlternateIdentifier::UniqueAttribute(a) => {
                    if !attrs::is_unique_user_attribute(&a.attribute_path) {
                        return Err(errors::validation(format!(
                            "{} is not a unique attribute.",
                            a.attribute_path
                        )));
                    }
                    let want: serde_json::Value =
                        serde_json::from_str(&a.attribute_value).unwrap_or(serde_json::Value::Null);
                    let want = want.as_str().unwrap_or_default().to_string();
                    s.users.values().find(|u| {
                        attrs::user_value(u, &a.attribute_path).iter().any(|v| v.eq_ignore_ascii_case(&want))
                    })
                }
                types::AlternateIdentifier::ExternalId(e) => s.users.values().find(|u| {
                    u.external_ids.iter().flatten().any(|x| x.issuer == e.issuer && x.id == e.id)
                }),
            };
            let u = found.ok_or_else(|| not_found("USER", "", "USER not found."))?;
            Ok(types::GetUserIdResponse {
                identity_store_id: s.id.clone(),
                user_id: u.user_id.clone(),
                user_arn: u.user_arn.clone(),
            })
        })
    }

    async fn create_group(
        &self,
        ctx: &RequestContext,
        input: types::CreateGroupRequest,
    ) -> Result<types::CreateGroupResponse, ServiceError> {
        let id = self.gate(ctx, &input.identity_store_id, "identitystore:CreateGroup", Access::Write, None)?;
        let display_name = input
            .display_name
            .ok_or_else(|| errors::validation("DisplayName is a required attribute and cannot be null."))?;
        let now = ctx.received_at;
        self.with_store(&id, |s| {
            if group_name_taken(s, &display_name, None) {
                return Err(duplicate_group());
            }
            let group_id = new_resource_id();
            let group = types::Group {
                identity_store_id: s.id.clone(),
                group_id: group_id.clone(),
                group_arn: s.group_arn(&group_id),
                revision: "1".into(),
                display_name: Some(display_name),
                external_ids: None,
                description: input.description,
                created_at: Some(now),
                updated_at: Some(now),
                created_by: Some(ctx.caller.arn.clone()),
                updated_by: Some(ctx.caller.arn.clone()),
            };
            let out = types::CreateGroupResponse {
                identity_store_id: s.id.clone(),
                group_id: group_id.clone(),
                group_arn: group.group_arn.clone(),
                revision: group.revision.clone(),
            };
            s.groups.insert(group_id, group);
            Ok(out)
        })
    }

    async fn describe_group(
        &self,
        ctx: &RequestContext,
        input: types::DescribeGroupRequest,
    ) -> Result<types::DescribeGroupResponse, ServiceError> {
        let arn = self.group_arn_for(&input.group_id);
        let id = self.gate(ctx, &input.identity_store_id, "identitystore:DescribeGroup", Access::Read, Some(arn))?;
        let group_id = resource_id(&input.group_id).to_string();
        self.with_store(&id, |s| {
            let g = s.groups.get(&group_id).cloned().ok_or_else(|| group_not_found(&group_id))?;
            Ok(types::DescribeGroupResponse {
                identity_store_id: g.identity_store_id,
                group_id: g.group_id,
                group_arn: g.group_arn,
                revision: g.revision,
                display_name: g.display_name,
                external_ids: g.external_ids,
                description: g.description,
                created_at: g.created_at,
                updated_at: g.updated_at,
                created_by: g.created_by,
                updated_by: g.updated_by,
            })
        })
    }

    async fn update_group(
        &self,
        ctx: &RequestContext,
        input: types::UpdateGroupRequest,
    ) -> Result<types::UpdateGroupResponse, ServiceError> {
        let arn = self.group_arn_for(&input.group_id);
        let id = self.gate(ctx, &input.identity_store_id, "identitystore:UpdateGroup", Access::Write, Some(arn))?;
        let group_id = resource_id(&input.group_id).to_string();
        if input.operations.is_empty() {
            return Err(errors::validation("Operations must contain at least one operation."));
        }
        self.with_store(&id, |s| {
            let mut g = s.groups.get(&group_id).cloned().ok_or_else(|| group_not_found(&group_id))?;
            check_revision(&g.revision, input.revision.as_deref())?;
            for op in &input.operations {
                attrs::update_group(&mut g, op).map_err(errors::validation)?;
            }
            if let Some(name) = g.display_name.clone() {
                if group_name_taken(s, &name, Some(&group_id)) {
                    return Err(duplicate_group());
                }
            }
            g.revision = bump(&g.revision);
            g.updated_at = Some(ctx.received_at);
            g.updated_by = Some(ctx.caller.arn.clone());
            let out = types::UpdateGroupResponse {
                identity_store_id: s.id.clone(),
                group_id: g.group_id.clone(),
                group_arn: g.group_arn.clone(),
                revision: g.revision.clone(),
            };
            s.groups.insert(group_id, g);
            Ok(out)
        })
    }

    async fn delete_group(
        &self,
        ctx: &RequestContext,
        input: types::DeleteGroupRequest,
    ) -> Result<types::DeleteGroupResponse, ServiceError> {
        let arn = self.group_arn_for(&input.group_id);
        let id = self.gate(ctx, &input.identity_store_id, "identitystore:DeleteGroup", Access::Write, Some(arn))?;
        let group_id = resource_id(&input.group_id).to_string();
        self.with_store(&id, |s| {
            let g = s.groups.get(&group_id).ok_or_else(|| group_not_found(&group_id))?;
            check_revision(&g.revision, input.revision.as_deref())?;
            s.groups.remove(&group_id);
            s.memberships.retain(|_, m| m.group_id != group_id);
            Ok(types::DeleteGroupResponse {})
        })
    }

    async fn list_groups(
        &self,
        ctx: &RequestContext,
        input: types::ListGroupsRequest,
    ) -> Result<types::ListGroupsResponse, ServiceError> {
        let id = self.gate(ctx, &input.identity_store_id, "identitystore:ListGroups", Access::Read, None)?;
        let filters = input.filters.unwrap_or_default();
        if filters.len() > 1 {
            return Err(errors::validation("Only one filter is supported."));
        }
        for f in &filters {
            if !f.attribute_path.eq_ignore_ascii_case("DisplayName") {
                return Err(errors::validation(format!("Invalid filter attribute path {}.", f.attribute_path)));
            }
        }
        let groups = self.with_store(&id, |s| {
            Ok(s.groups
                .values()
                .filter(|g| {
                    filters.iter().all(|f| {
                        g.display_name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case(&f.attribute_value))
                    })
                })
                .cloned()
                .collect::<Vec<_>>())
        })?;
        let (groups, next_token) = paginate(groups, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListGroupsResponse { groups, next_token })
    }

    async fn get_group_id(
        &self,
        ctx: &RequestContext,
        input: types::GetGroupIdRequest,
    ) -> Result<types::GetGroupIdResponse, ServiceError> {
        let id = self.gate(ctx, &input.identity_store_id, "identitystore:GetGroupId", Access::Read, None)?;
        self.with_store(&id, |s| {
            let found = match &input.alternate_identifier {
                types::AlternateIdentifier::UniqueAttribute(a) => {
                    if !a.attribute_path.eq_ignore_ascii_case("displayName") {
                        return Err(errors::validation(format!(
                            "{} is not a unique attribute.",
                            a.attribute_path
                        )));
                    }
                    let want: serde_json::Value =
                        serde_json::from_str(&a.attribute_value).unwrap_or(serde_json::Value::Null);
                    let want = want.as_str().unwrap_or_default().to_string();
                    s.groups.values().find(|g| g.display_name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case(&want)))
                }
                types::AlternateIdentifier::ExternalId(e) => s.groups.values().find(|g| {
                    g.external_ids.iter().flatten().any(|x| x.issuer == e.issuer && x.id == e.id)
                }),
            };
            let g = found.ok_or_else(|| not_found("GROUP", "", "GROUP not found."))?;
            Ok(types::GetGroupIdResponse {
                identity_store_id: s.id.clone(),
                group_id: g.group_id.clone(),
                group_arn: g.group_arn.clone(),
            })
        })
    }

    async fn create_group_membership(
        &self,
        ctx: &RequestContext,
        input: types::CreateGroupMembershipRequest,
    ) -> Result<types::CreateGroupMembershipResponse, ServiceError> {
        let arn = self.group_arn_for(&input.group_id);
        let id =
            self.gate(ctx, &input.identity_store_id, "identitystore:CreateGroupMembership", Access::Write, Some(arn))?;
        let group_id = resource_id(&input.group_id).to_string();
        let user_id = resource_id(member_user(&input.member_id)).to_string();
        self.with_store(&id, |s| {
            if !s.groups.contains_key(&group_id) {
                return Err(group_not_found(&group_id));
            }
            if !s.users.contains_key(&user_id) {
                return Err(user_not_found(&user_id));
            }
            if s.memberships.values().any(|m| m.group_id == group_id && m.user_id == user_id) {
                return Err(conflict(
                    "UNIQUENESS_CONSTRAINT_VIOLATION",
                    format!("Member {user_id} already exists in group {group_id}"),
                ));
            }
            let membership_id = uuid::Uuid::new_v4().to_string();
            let m = Membership {
                id: membership_id.clone(),
                group_id,
                user_id,
                created_at: Some(ctx.received_at),
                created_by: Some(ctx.caller.arn.clone()),
            };
            s.memberships.insert(membership_id.clone(), m);
            Ok(types::CreateGroupMembershipResponse {
                identity_store_id: s.id.clone(),
                membership_arn: s.membership_arn(&membership_id),
                membership_id,
            })
        })
    }

    async fn describe_group_membership(
        &self,
        ctx: &RequestContext,
        input: types::DescribeGroupMembershipRequest,
    ) -> Result<types::DescribeGroupMembershipResponse, ServiceError> {
        let arn = self.membership_arn_for(&input.membership_id);
        let id = self.gate(
            ctx,
            &input.identity_store_id,
            "identitystore:DescribeGroupMembership",
            Access::Read,
            Some(arn),
        )?;
        let mid = resource_id(&input.membership_id).to_string();
        self.with_store(&id, |s| {
            let m = s.memberships.get(&mid).ok_or_else(|| membership_not_found(&mid))?;
            let v = membership_view(s, m);
            Ok(types::DescribeGroupMembershipResponse {
                identity_store_id: v.identity_store_id,
                membership_id: v.membership_id,
                membership_arn: v.membership_arn,
                group_id: v.group_id.unwrap_or_default(),
                member_id: v.member_id.unwrap_or_default(),
                created_at: v.created_at,
                updated_at: v.updated_at,
                created_by: v.created_by,
                updated_by: v.updated_by,
            })
        })
    }

    async fn delete_group_membership(
        &self,
        ctx: &RequestContext,
        input: types::DeleteGroupMembershipRequest,
    ) -> Result<types::DeleteGroupMembershipResponse, ServiceError> {
        let arn = self.membership_arn_for(&input.membership_id);
        let id =
            self.gate(ctx, &input.identity_store_id, "identitystore:DeleteGroupMembership", Access::Write, Some(arn))?;
        let mid = resource_id(&input.membership_id).to_string();
        self.with_store(&id, |s| {
            s.memberships.remove(&mid).ok_or_else(|| membership_not_found(&mid))?;
            Ok(types::DeleteGroupMembershipResponse {})
        })
    }

    async fn get_group_membership_id(
        &self,
        ctx: &RequestContext,
        input: types::GetGroupMembershipIdRequest,
    ) -> Result<types::GetGroupMembershipIdResponse, ServiceError> {
        let id = self.gate(ctx, &input.identity_store_id, "identitystore:GetGroupMembershipId", Access::Read, None)?;
        let group_id = resource_id(&input.group_id).to_string();
        let user_id = resource_id(member_user(&input.member_id)).to_string();
        self.with_store(&id, |s| {
            let m = s
                .memberships
                .values()
                .find(|m| m.group_id == group_id && m.user_id == user_id)
                .ok_or_else(|| not_found("GROUP_MEMBERSHIP", "", "GROUP_MEMBERSHIP not found."))?;
            Ok(types::GetGroupMembershipIdResponse {
                identity_store_id: s.id.clone(),
                membership_id: m.id.clone(),
                membership_arn: s.membership_arn(&m.id),
            })
        })
    }

    async fn list_group_memberships(
        &self,
        ctx: &RequestContext,
        input: types::ListGroupMembershipsRequest,
    ) -> Result<types::ListGroupMembershipsResponse, ServiceError> {
        let arn = self.group_arn_for(&input.group_id);
        let id =
            self.gate(ctx, &input.identity_store_id, "identitystore:ListGroupMemberships", Access::Read, Some(arn))?;
        let group_id = resource_id(&input.group_id).to_string();
        let items = self.with_store(&id, |s| {
            if !s.groups.contains_key(&group_id) {
                return Err(group_not_found(&group_id));
            }
            Ok(s.memberships.values().filter(|m| m.group_id == group_id).map(|m| membership_view(s, m)).collect())
        })?;
        let (group_memberships, next_token) = paginate(items, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListGroupMembershipsResponse { group_memberships, next_token })
    }

    async fn list_group_memberships_for_member(
        &self,
        ctx: &RequestContext,
        input: types::ListGroupMembershipsForMemberRequest,
    ) -> Result<types::ListGroupMembershipsForMemberResponse, ServiceError> {
        let user_id = resource_id(member_user(&input.member_id)).to_string();
        let arn = self.user_arn_for(&input.identity_store_id, &user_id);
        let id = self.gate(
            ctx,
            &input.identity_store_id,
            "identitystore:ListGroupMembershipsForMember",
            Access::Read,
            Some(arn),
        )?;
        let items = self.with_store(&id, |s| {
            if !s.users.contains_key(&user_id) {
                return Err(user_not_found(&user_id));
            }
            Ok(s.memberships.values().filter(|m| m.user_id == user_id).map(|m| membership_view(s, m)).collect())
        })?;
        let (group_memberships, next_token) = paginate(items, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListGroupMembershipsForMemberResponse { group_memberships, next_token })
    }

    async fn is_member_in_groups(
        &self,
        ctx: &RequestContext,
        input: types::IsMemberInGroupsRequest,
    ) -> Result<types::IsMemberInGroupsResponse, ServiceError> {
        let id = self.gate(ctx, &input.identity_store_id, "identitystore:IsMemberInGroups", Access::Read, None)?;
        let user_id = resource_id(member_user(&input.member_id)).to_string();
        self.with_store(&id, |s| {
            if !s.users.contains_key(&user_id) {
                return Err(user_not_found(&user_id));
            }
            let results = input
                .group_ids
                .iter()
                .map(|g| {
                    let g = resource_id(g).to_string();
                    let exists = s.memberships.values().any(|m| m.group_id == g && m.user_id == user_id);
                    types::GroupMembershipExistenceResult {
                        group_id: Some(g),
                        member_id: Some(types::MemberId::UserId(user_id.clone())),
                        membership_exists: exists,
                    }
                })
                .collect();
            Ok(types::IsMemberInGroupsResponse { results })
        })
    }

    async fn describe_identity_store(
        &self,
        ctx: &RequestContext,
        input: types::DescribeIdentityStoreRequest,
    ) -> Result<types::DescribeIdentityStoreResponse, ServiceError> {
        let id = self.gate(ctx, &input.identity_store_id, "identitystore:DescribeIdentityStore", Access::Read, None)?;
        self.with_store(&id, |s| {
            Ok(types::DescribeIdentityStoreResponse {
                identity_store_id: s.id.clone(),
                identity_store_arn: s.arn(),
                network_configuration: s.network.clone(),
            })
        })
    }

    async fn update_identity_store(
        &self,
        ctx: &RequestContext,
        input: types::UpdateIdentityStoreRequest,
    ) -> Result<types::UpdateIdentityStoreResponse, ServiceError> {
        let id = self.gate(ctx, &input.identity_store_id, "identitystore:UpdateIdentityStore", Access::Write, None)?;
        self.with_store(&id, |s| {
            if let Some(n) = input.network_configuration {
                s.network = Some(types::NetworkConfigurationDetails {
                    vpce_access_required: n.vpce_access_required,
                    api_restrict_source_vpcs: n.api_restrict_source_vpcs,
                    api_allow_source_ips: n.api_allow_source_ips,
                    scim_allow_source_ips: n.scim_allow_source_ips,
                });
            }
            Ok(types::UpdateIdentityStoreResponse { identity_store_id: s.id.clone(), identity_store_arn: s.arn() })
        })
    }

    async fn list_identity_stores(
        &self,
        ctx: &RequestContext,
        input: types::ListIdentityStoresRequest,
    ) -> Result<types::ListIdentityStoresResponse, ServiceError> {
        ctx.authorize("identitystore:ListIdentityStores", "*", ConditionContext::new())?;
        let caller = ctx.caller.account_id.clone();
        let stores: Vec<types::IdentityStore> = self
            .lock()
            .stores
            .values()
            .filter(|s| s.account == caller)
            .map(|s| types::IdentityStore { identity_store_id: s.id.clone(), identity_store_arn: s.arn() })
            .collect();
        let (identity_stores, next_token) =
            paginate(stores, input.max_results.unwrap_or(0), input.next_token.as_deref())?;
        Ok(types::ListIdentityStoresResponse { identity_stores, next_token })
    }
}

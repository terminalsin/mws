//! IAM operation behaviour. Validation of shapes, lengths and patterns has
//! already happened in the generated decoder by the time these run.

use chrono::Utc;
use mws_core::{CallerKind, ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types, Handler};
use crate::state::{AccessKey, User};
use crate::{ids, Iam};

const MAX_ACCESS_KEYS_PER_USER: usize = 2;
const DEFAULT_MAX_ITEMS: usize = 100;

/// Who an operation without an explicit `UserName` acts on.
enum Subject {
    Root,
    User(String),
}

impl Iam {
    fn subject(&self, ctx: &RequestContext, user_name: Option<String>) -> Result<Subject, ServiceError> {
        if let Some(name) = user_name {
            return Ok(Subject::User(name));
        }
        match &ctx.caller.kind {
            CallerKind::Root => Ok(Subject::Root),
            CallerKind::User { name } => Ok(Subject::User(name.clone())),
            _ => Err(ServiceError::client(
                "ValidationError",
                400,
                "Must specify userName when calling with non-User credentials",
            )),
        }
    }

    fn user_arn(&self, path: &str, name: &str) -> String {
        self.arn(&format!("user{path}{name}"))
    }

    fn authorize(&self, ctx: &RequestContext, action: &str, resource: &str) -> Result<(), ServiceError> {
        ctx.authorize(&format!("iam:{action}"), resource, ConditionContext::new())
    }

    fn no_such_user(name: &str) -> ServiceError {
        errors::no_such_entity(format!("The user with name {name} cannot be found."))
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, crate::State> {
        self.inner.state.read().expect("IAM state lock poisoned")
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, crate::State> {
        self.inner.state.write().expect("IAM state lock poisoned")
    }
}

fn user_to_wire(u: &User) -> types::User {
    types::User {
        path: u.path.clone(),
        user_name: u.name.clone(),
        user_id: u.id.clone(),
        arn: u.arn.clone(),
        create_date: u.created,
        password_last_used: None,
        permissions_boundary: u.permissions_boundary.as_ref().map(|arn| types::AttachedPermissionsBoundary {
            permissions_boundary_type: Some("PermissionsBoundaryPolicy".into()),
            permissions_boundary_arn: Some(arn.clone()),
        }),
        tags: (!u.tags.is_empty())
            .then(|| u.tags.iter().map(|(k, v)| types::Tag { key: k.clone(), value: v.clone() }).collect()),
    }
}

fn key_metadata(k: &AccessKey) -> types::AccessKeyMetadata {
    types::AccessKeyMetadata {
        user_name: k.user_name.clone(),
        access_key_id: Some(k.id.clone()),
        status: Some(status_str(k.active).into()),
        create_date: Some(k.created),
    }
}

fn status_str(active: bool) -> &'static str {
    if active {
        "Active"
    } else {
        "Inactive"
    }
}

/// IAM-style `Marker`/`MaxItems` pagination over items sorted by `key`.
/// Returns the page, whether it is truncated, and the next marker.
pub(crate) fn paginate<T: Clone>(
    items: &[T],
    key: impl Fn(&T) -> String,
    marker: Option<&str>,
    max_items: Option<i32>,
) -> Result<(Vec<T>, bool, Option<String>), ServiceError> {
    let start = match marker {
        None => 0,
        Some(m) => {
            let after =
                decode_marker(m).ok_or_else(|| ServiceError::client("ValidationError", 400, "Invalid Marker."))?;
            items.iter().position(|i| key(i) >= after).unwrap_or(items.len())
        }
    };
    let max = max_items.map(|m| m as usize).unwrap_or(DEFAULT_MAX_ITEMS);
    let end = (start + max).min(items.len());
    let page = items[start..end].to_vec();
    let truncated = end < items.len();
    let next = truncated.then(|| encode_marker(&key(&items[end])));
    Ok((page, truncated, next))
}

fn encode_marker(key: &str) -> String {
    key.bytes().map(|b| format!("{b:02X}")).collect()
}

fn decode_marker(marker: &str) -> Option<String> {
    if !marker.len().is_multiple_of(2) {
        return None;
    }
    let bytes: Option<Vec<u8>> =
        (0..marker.len()).step_by(2).map(|i| u8::from_str_radix(marker.get(i..i + 2)?, 16).ok()).collect();
    String::from_utf8(bytes?).ok()
}

#[async_trait::async_trait]
impl Handler for Iam {
    async fn create_user(
        &self,
        ctx: &RequestContext,
        input: types::CreateUserRequest,
    ) -> Result<types::CreateUserResponse, ServiceError> {
        let path = input.path.unwrap_or_else(|| "/".into());
        let arn = self.user_arn(&path, &input.user_name);
        self.authorize(ctx, "CreateUser", &arn)?;
        let mut state = self.write();
        let key = input.user_name.to_lowercase();
        if state.users.contains_key(&key) {
            return Err(errors::entity_already_exists(format!("User with name {} already exists.", input.user_name)));
        }
        let user = User {
            name: input.user_name,
            path,
            id: ids::unique_id("AIDA"),
            arn,
            created: Utc::now(),
            permissions_boundary: input.permissions_boundary,
            tags: input.tags.unwrap_or_default().into_iter().map(|t| (t.key, t.value)).collect(),
        };
        let wire = user_to_wire(&user);
        state.users.insert(key, user);
        Ok(types::CreateUserResponse { user: Some(wire) })
    }

    async fn get_user(
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
                        user_id: self.inner.config.account_id.clone(),
                        arn,
                        create_date: self.inner.created_at,
                        ..Default::default()
                    },
                })
            }
            Subject::User(name) => {
                let state = self.read();
                let user = state.user(&name).ok_or_else(|| Self::no_such_user(&name))?;
                self.authorize(ctx, "GetUser", &user.arn)?;
                Ok(types::GetUserResponse { user: user_to_wire(user) })
            }
        }
    }

    async fn list_users(
        &self,
        ctx: &RequestContext,
        input: types::ListUsersRequest,
    ) -> Result<types::ListUsersResponse, ServiceError> {
        self.authorize(ctx, "ListUsers", &self.arn("user/"))?;
        let prefix = input.path_prefix.unwrap_or_else(|| "/".into());
        let users: Vec<User> = self.read().users.values().filter(|u| u.path.starts_with(&prefix)).cloned().collect();
        let (page, is_truncated, marker) =
            paginate(&users, |u| u.name.to_lowercase(), input.marker.as_deref(), input.max_items)?;
        Ok(types::ListUsersResponse { users: page.iter().map(user_to_wire).collect(), is_truncated, marker })
    }

    async fn delete_user(&self, ctx: &RequestContext, input: types::DeleteUserRequest) -> Result<(), ServiceError> {
        let mut state = self.write();
        let user = state.user(&input.user_name).ok_or_else(|| Self::no_such_user(&input.user_name))?;
        self.authorize(ctx, "DeleteUser", &user.arn)?;
        if !state.keys_for(Some(&input.user_name)).is_empty() {
            return Err(errors::delete_conflict("Cannot delete entity, must delete access keys first."));
        }
        state.users.remove(&input.user_name.to_lowercase());
        Ok(())
    }

    async fn create_access_key(
        &self,
        ctx: &RequestContext,
        input: types::CreateAccessKeyRequest,
    ) -> Result<types::CreateAccessKeyResponse, ServiceError> {
        let subject = self.subject(ctx, input.user_name)?;
        let mut state = self.write();
        let (user_name, arn) = match &subject {
            Subject::Root => (None, ctx.caller.arn.clone()),
            Subject::User(name) => {
                let user = state.user(name).ok_or_else(|| Self::no_such_user(name))?;
                (Some(user.name.clone()), user.arn.clone())
            }
        };
        self.authorize(ctx, "CreateAccessKey", &arn)?;
        if state.keys_for(user_name.as_deref()).len() >= MAX_ACCESS_KEYS_PER_USER {
            return Err(errors::limit_exceeded(format!(
                "Cannot exceed quota for AccessKeysPerUser: {MAX_ACCESS_KEYS_PER_USER}"
            )));
        }
        let key = AccessKey {
            id: ids::access_key_id(),
            secret: ids::secret_access_key(),
            user_name: user_name.clone(),
            active: true,
            created: Utc::now(),
        };
        let wire = types::AccessKey {
            user_name: user_name.unwrap_or_default(),
            access_key_id: key.id.clone(),
            status: "Active".into(),
            secret_access_key: key.secret.clone(),
            create_date: Some(key.created),
        };
        state.access_keys.insert(key.id.clone(), key);
        Ok(types::CreateAccessKeyResponse { access_key: wire })
    }

    async fn list_access_keys(
        &self,
        ctx: &RequestContext,
        input: types::ListAccessKeysRequest,
    ) -> Result<types::ListAccessKeysResponse, ServiceError> {
        let subject = self.subject(ctx, input.user_name)?;
        let state = self.read();
        let (user_name, arn) = match &subject {
            Subject::Root => (None, ctx.caller.arn.clone()),
            Subject::User(name) => {
                let user = state.user(name).ok_or_else(|| Self::no_such_user(name))?;
                (Some(user.name.clone()), user.arn.clone())
            }
        };
        self.authorize(ctx, "ListAccessKeys", &arn)?;
        let keys: Vec<AccessKey> = state.keys_for(user_name.as_deref()).into_iter().cloned().collect();
        let (page, is_truncated, marker) = paginate(&keys, |k| k.id.clone(), input.marker.as_deref(), input.max_items)?;
        Ok(types::ListAccessKeysResponse {
            access_key_metadata: page.iter().map(key_metadata).collect(),
            is_truncated,
            marker,
        })
    }

    async fn delete_access_key(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessKeyRequest,
    ) -> Result<(), ServiceError> {
        let subject = self.subject(ctx, input.user_name)?;
        let mut state = self.write();
        let arn = self.key_owner_arn(ctx, &state, &subject, &input.access_key_id)?;
        self.authorize(ctx, "DeleteAccessKey", &arn)?;
        state.access_keys.remove(&input.access_key_id);
        Ok(())
    }

    async fn update_access_key(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAccessKeyRequest,
    ) -> Result<(), ServiceError> {
        let subject = self.subject(ctx, input.user_name)?;
        let mut state = self.write();
        let arn = self.key_owner_arn(ctx, &state, &subject, &input.access_key_id)?;
        self.authorize(ctx, "UpdateAccessKey", &arn)?;
        if let Some(k) = state.access_keys.get_mut(&input.access_key_id) {
            k.active = input.status == "Active";
        }
        Ok(())
    }
}

impl Iam {
    /// Check that `key_id` belongs to `subject` and return the owner's ARN.
    fn key_owner_arn(
        &self,
        ctx: &RequestContext,
        state: &crate::State,
        subject: &Subject,
        key_id: &str,
    ) -> Result<String, ServiceError> {
        let not_found = || errors::no_such_entity(format!("The Access Key with id {key_id} cannot be found."));
        let key = state.access_keys.get(key_id).ok_or_else(not_found)?;
        match subject {
            Subject::Root => {
                if key.user_name.is_some() {
                    return Err(not_found());
                }
                Ok(ctx.caller.arn.clone())
            }
            Subject::User(name) => {
                let user = state.user(name).ok_or_else(|| Self::no_such_user(name))?;
                if key.user_name.as_deref().map(str::to_lowercase) != Some(name.to_lowercase()) {
                    return Err(not_found());
                }
                Ok(user.arn.clone())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pagination_round_trips_markers() {
        let items: Vec<String> = (0..5).map(|i| format!("u{i}")).collect();
        let (p1, t1, m1) = paginate(&items, |s| s.clone(), None, Some(2)).unwrap();
        assert_eq!((p1, t1), (vec!["u0".to_string(), "u1".to_string()], true));
        let (p2, _, m2) = paginate(&items, |s| s.clone(), m1.as_deref(), Some(2)).unwrap();
        assert_eq!(p2, vec!["u2".to_string(), "u3".to_string()]);
        let (p3, t3, m3) = paginate(&items, |s| s.clone(), m2.as_deref(), Some(2)).unwrap();
        assert_eq!((p3, t3, m3), (vec!["u4".to_string()], false, None));
        assert!(paginate(&items, |s| s.clone(), Some("zz"), None).is_err());
    }
}

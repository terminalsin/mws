//! What IAM Identity Center's other services use: creating the store that
//! comes with an instance, and reading users and their groups.

use crate::generated::types;
use crate::state::Store;
use crate::{attrs, IdentityStore};

/// An identity store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreInfo {
    pub id: String,
    pub arn: String,
    /// The account that owns it (the instance's).
    pub account: String,
    pub region: String,
}

/// A user, as other services see it.
#[derive(Debug, Clone)]
pub struct UserInfo {
    pub store_id: String,
    pub user_id: String,
    pub user_name: String,
    pub display_name: Option<String>,
    /// The primary email first.
    pub emails: Vec<String>,
    user: types::User,
}

impl UserInfo {
    /// The user's values at an attribute path (`userName`, `name.givenName`,
    /// `emails.value`, `aws:identitystore:enterprise.department`, ...).
    pub fn attribute(&self, path: &str) -> Vec<String> {
        attrs::user_value(&self.user, path)
    }
}

fn user_info(store: &str, u: &types::User) -> UserInfo {
    UserInfo {
        store_id: store.to_string(),
        user_id: u.user_id.clone(),
        user_name: u.user_name.clone().unwrap_or_default(),
        display_name: u.display_name.clone(),
        emails: attrs::user_value(u, "emails.value"),
        user: u.clone(),
    }
}

impl IdentityStore {
    /// Create the identity store of a new IAM Identity Center instance and
    /// return its id (`d-` and ten hex digits).
    pub fn create_store(&self, account: &str, region: &str) -> String {
        let mut st = self.lock();
        let id = loop {
            let id = format!("d-{}", &uuid::Uuid::new_v4().simple().to_string()[..10]);
            if !st.stores.contains_key(&id) {
                break id;
            }
        };
        st.stores.insert(
            id.clone(),
            Store {
                id: id.clone(),
                account: account.to_string(),
                region: region.to_string(),
                partition: self.iam.partition().to_string(),
                ..Default::default()
            },
        );
        id
    }

    /// Delete a store and everything in it (its instance was deleted).
    pub fn delete_store(&self, id: &str) {
        self.lock().stores.remove(id);
    }

    pub fn store(&self, id: &str) -> Option<StoreInfo> {
        let st = self.lock();
        let s = st.stores.get(id)?;
        Some(StoreInfo { id: s.id.clone(), arn: s.arn(), account: s.account.clone(), region: s.region.clone() })
    }

    pub fn user(&self, store: &str, user_id: &str) -> Option<UserInfo> {
        let st = self.lock();
        st.stores.get(store)?.users.get(user_id).map(|u| user_info(store, u))
    }

    /// A user by user name (case-insensitive) or primary email.
    pub fn find_user(&self, store: &str, name_or_email: &str) -> Option<UserInfo> {
        let st = self.lock();
        let s = st.stores.get(store)?;
        let by_name =
            s.users.values().find(|u| u.user_name.as_deref().is_some_and(|n| n.eq_ignore_ascii_case(name_or_email)));
        let by_email = || {
            s.users.values().find(|u| {
                attrs::user_value(u, "emails.value").first().is_some_and(|e| e.eq_ignore_ascii_case(name_or_email))
            })
        };
        by_name.or_else(by_email).map(|u| user_info(store, u))
    }

    pub fn group_exists(&self, store: &str, group_id: &str) -> bool {
        self.lock().stores.get(store).is_some_and(|s| s.groups.contains_key(group_id))
    }

    pub fn user_exists(&self, store: &str, user_id: &str) -> bool {
        self.lock().stores.get(store).is_some_and(|s| s.users.contains_key(user_id))
    }

    /// The ids of the groups `user_id` belongs to.
    pub fn groups_of(&self, store: &str, user_id: &str) -> Vec<String> {
        self.lock().stores.get(store).map(|s| s.groups_of(user_id)).unwrap_or_default()
    }
}

impl IdentityStore {
    /// The user whose attribute at `path` (`userName`, `emails.value`,
    /// `externalIds`... as trusted token issuers map claims) equals `value`
    /// (case-insensitively).
    pub fn find_user_by_attribute(&self, store: &str, path: &str, value: &str) -> Option<UserInfo> {
        let st = self.lock();
        let s = st.stores.get(store)?;
        s.users
            .values()
            .find(|u| attrs::user_value(u, path).iter().any(|v| v.eq_ignore_ascii_case(value)))
            .map(|u| user_info(store, u))
    }
}

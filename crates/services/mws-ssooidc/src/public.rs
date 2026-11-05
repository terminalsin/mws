//! What the AWS access portal reads: who an access token stands for.

use chrono::{DateTime, Utc};

use crate::tokens::ACCOUNT_ACCESS_SCOPE;
use crate::SsoOidc;

/// The user an access token was issued to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenOwner {
    pub identity_store_id: String,
    pub user_id: String,
    pub expires_at: DateTime<Utc>,
}

impl SsoOidc {
    /// The user behind an unexpired access token that may reach the AWS
    /// access portal (it carries `sso:account:access`, or no scopes at all
    /// as the AWS CLI's legacy tokens do).
    pub fn portal_token_owner(&self, token: &str, now: DateTime<Utc>) -> Option<TokenOwner> {
        let st = self.lock();
        let t = st.tokens.get(token).filter(|t| t.expires_at > now)?;
        let s = &t.session;
        if s.application_arn.is_some() || !(s.scopes.is_empty() || s.scopes.iter().any(|x| x == ACCOUNT_ACCESS_SCOPE)) {
            return None;
        }
        Some(TokenOwner {
            identity_store_id: s.identity_store_id.clone(),
            user_id: s.user_id.clone(),
            expires_at: t.expires_at,
        })
    }

    /// End the session an access token belongs to (`sso:Logout`): the token
    /// and refresh tokens of the same client and user stop working.
    pub fn revoke(&self, token: &str) {
        let mut st = self.lock();
        let Some(t) = st.tokens.remove(token) else { return };
        let s = t.session;
        st.tokens.retain(|_, x| !(x.session.client_id == s.client_id && x.session.user_id == s.user_id));
        st.refresh.retain(|_, x| !(x.client_id == s.client_id && x.user_id == s.user_id));
    }
}

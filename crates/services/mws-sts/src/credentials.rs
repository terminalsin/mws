use std::sync::Arc;

use chrono::{DateTime, Utc};
use mws_core::{CredentialError, CredentialStore, ResolvedCredential};

use crate::Inner;

pub(crate) struct StsCredentials {
    pub inner: Arc<Inner>,
}

impl CredentialStore for StsCredentials {
    fn resolve(
        &self,
        access_key_id: &str,
        session_token: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<Option<ResolvedCredential>, CredentialError> {
        let sessions = self.inner.sessions.lock().expect("STS session lock poisoned");
        let Some(s) = sessions.get(access_key_id) else { return Ok(None) };
        if session_token != Some(s.session_token.as_str()) {
            return Err(CredentialError::Invalid);
        }
        if now >= s.expires_at {
            return Err(CredentialError::Expired);
        }
        Ok(Some(ResolvedCredential { secret_access_key: s.secret_access_key.clone(), caller: s.caller.clone() }))
    }
}

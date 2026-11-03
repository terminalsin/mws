use std::sync::Arc;

use chrono::{DateTime, Utc};
use mws_core::{Caller, CallerKind, CredentialError, CredentialStore, ResolvedCredential};

use crate::Inner;

pub(crate) struct IamCredentials {
    pub inner: Arc<Inner>,
}

impl CredentialStore for IamCredentials {
    fn resolve(
        &self,
        access_key_id: &str,
        session_token: Option<&str>,
        _now: DateTime<Utc>,
    ) -> Result<Option<ResolvedCredential>, CredentialError> {
        let cfg = &self.inner.config;
        let root_arn = format!("arn:{}:iam::{}:root", cfg.partition, cfg.account_id);
        if access_key_id == cfg.root_access_key_id {
            return Ok(Some(ResolvedCredential {
                secret_access_key: cfg.root_secret_access_key.clone(),
                caller: Caller {
                    account_id: cfg.account_id.clone(),
                    arn: root_arn,
                    user_id: cfg.account_id.clone(),
                    access_key_id: access_key_id.to_string(),
                    kind: CallerKind::Root,
                    session: None,
                },
            }));
        }
        let state = self.inner.state.read().expect("IAM state lock poisoned");
        let Some(key) = state.access_keys.get(access_key_id) else { return Ok(None) };
        // Long-term keys never carry a session token.
        if !key.active || session_token.is_some() {
            return Err(CredentialError::Invalid);
        }
        let caller = match &key.user_name {
            None => Caller {
                account_id: cfg.account_id.clone(),
                arn: root_arn,
                user_id: cfg.account_id.clone(),
                access_key_id: access_key_id.to_string(),
                kind: CallerKind::Root,
                session: None,
            },
            Some(name) => {
                let user = state.user(name).ok_or(CredentialError::Invalid)?;
                Caller {
                    account_id: cfg.account_id.clone(),
                    arn: user.arn.clone(),
                    user_id: user.id.clone(),
                    access_key_id: access_key_id.to_string(),
                    kind: CallerKind::User { name: user.name.clone() },
                    session: None,
                }
            }
        };
        Ok(Some(ResolvedCredential { secret_access_key: key.secret.clone(), caller }))
    }
}

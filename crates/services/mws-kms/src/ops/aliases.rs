//! Aliases: friendly names for keys, scoped to an account and Region.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use super::{alias_arn, page, require_not_pending_deletion, Access};
use crate::generated::{errors, types};
use crate::state::Alias;
use crate::Kms;

fn check_name(name: &str) -> Result<(), ServiceError> {
    if !name.starts_with("alias/") || name.len() <= "alias/".len() {
        return Err(errors::invalid_alias_name(
            "Alias must start with the prefix \"alias/\". Please see https://docs.aws.amazon.com/kms/latest/developerguide/kms-alias.html",
        ));
    }
    if name.starts_with("alias/aws/") {
        return Err(errors::invalid_alias_name(
            "Alias names cannot begin with alias/aws/. That prefix is reserved for AWS managed keys.",
        ));
    }
    Ok(())
}

impl Kms {
    /// `kms:{action}` on the alias itself; aliases have no policy of their
    /// own, so only identity policies apply.
    fn authorize_alias(&self, ctx: &RequestContext, action: &str, arn: &str) -> Result<(), ServiceError> {
        let mut cond = ConditionContext::new();
        cond.insert("kms:CallerAccount".into(), vec![ctx.caller.account_id.clone()]);
        ctx.authorize(&format!("kms:{action}"), arn, cond)
    }

    pub(crate) fn create_alias(
        &self,
        ctx: &RequestContext,
        input: types::CreateAliasRequest,
    ) -> Result<(), ServiceError> {
        check_name(&input.alias_name)?;
        let arn = alias_arn(&ctx.partition, &ctx.region, &ctx.caller.account_id, &input.alias_name);
        self.authorize_alias(ctx, "CreateAlias", &arn)?;
        let t = self.authorize_key(ctx, &input.target_key_id, Access::new("CreateAlias"))?;
        let mut st = self.lock();
        let key = st.key(&t.arn)?;
        require_not_pending_deletion(key)?;
        if key.account != ctx.caller.account_id {
            return Err(errors::not_found(format!("Key '{}' does not exist", t.arn)));
        }
        let key_id = key.key_id.clone();
        if st.aliases.contains_key(&arn) {
            return Err(errors::already_exists(format!("An alias with the name {arn} already exists")));
        }
        let now = ctx.received_at;
        st.aliases.insert(
            arn.clone(),
            Alias { arn, name: input.alias_name, target_key_id: key_id, created_at: now, updated_at: now },
        );
        Ok(())
    }

    pub(crate) fn update_alias(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAliasRequest,
    ) -> Result<(), ServiceError> {
        check_name(&input.alias_name)?;
        let arn = alias_arn(&ctx.partition, &ctx.region, &ctx.caller.account_id, &input.alias_name);
        self.authorize_alias(ctx, "UpdateAlias", &arn)?;
        let current = {
            let st = self.lock();
            let alias = st.aliases.get(&arn).ok_or_else(|| errors::not_found(format!("Alias {arn} is not found.")))?;
            super::key_arn(&ctx.partition, &ctx.region, &ctx.caller.account_id, &alias.target_key_id)
        };
        self.authorize_key(ctx, &current, Access::new("UpdateAlias"))?;
        let t = self.authorize_key(ctx, &input.target_key_id, Access::new("UpdateAlias"))?;
        let mut st = self.lock();
        let new = st.key(&t.arn)?;
        require_not_pending_deletion(new)?;
        if let Ok(old) = st.key(&current) {
            let class = |k: &crate::state::Key| (k.is_symmetric(), k.key_spec.starts_with("HMAC"), k.key_usage.clone());
            if class(old) != class(new) {
                return Err(super::validation(format!(
                    "{} and {} are not the same type of KMS key or do not have the same key usage.",
                    old.arn, new.arn
                )));
            }
        }
        let key_id = new.key_id.clone();
        let alias = st.aliases.get_mut(&arn).ok_or_else(|| errors::not_found(format!("Alias {arn} is not found.")))?;
        alias.target_key_id = key_id;
        alias.updated_at = ctx.received_at;
        Ok(())
    }

    pub(crate) fn delete_alias(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAliasRequest,
    ) -> Result<(), ServiceError> {
        check_name(&input.alias_name)?;
        let arn = alias_arn(&ctx.partition, &ctx.region, &ctx.caller.account_id, &input.alias_name);
        self.authorize_alias(ctx, "DeleteAlias", &arn)?;
        let target = {
            let st = self.lock();
            let alias = st.aliases.get(&arn).ok_or_else(|| errors::not_found(format!("Alias {arn} is not found.")))?;
            super::key_arn(&ctx.partition, &ctx.region, &ctx.caller.account_id, &alias.target_key_id)
        };
        if self.lock().keys.contains_key(&target) {
            self.authorize_key(ctx, &target, Access::new("DeleteAlias"))?;
        }
        self.lock().aliases.remove(&arn);
        Ok(())
    }

    pub(crate) fn list_aliases(
        &self,
        ctx: &RequestContext,
        input: types::ListAliasesRequest,
    ) -> Result<types::ListAliasesResponse, ServiceError> {
        let filter = match &input.key_id {
            Some(k) => Some(self.authorize_key(ctx, k, Access::new("ListAliases"))?.arn),
            None => {
                self.authorize_account(ctx, "ListAliases", ConditionContext::new())?;
                None
            }
        };
        let st = self.lock();
        let prefix = format!("arn:{}:kms:{}:{}:", ctx.partition, ctx.region, ctx.caller.account_id);
        let items = st
            .aliases
            .values()
            .filter(|a| a.arn.starts_with(&prefix))
            .filter(|a| {
                filter.as_ref().is_none_or(|f| {
                    *f == super::key_arn(&ctx.partition, &ctx.region, &ctx.caller.account_id, &a.target_key_id)
                })
            })
            .map(|a| {
                (
                    a.name.clone(),
                    types::AliasListEntry {
                        alias_name: Some(a.name.clone()),
                        alias_arn: Some(a.arn.clone()),
                        target_key_id: Some(a.target_key_id.clone()),
                        creation_date: Some(a.created_at),
                        last_updated_date: Some(a.updated_at),
                    },
                )
            })
            .collect();
        let (aliases, next_marker, truncated) = page(items, input.limit, 50, input.marker.as_deref())?;
        Ok(types::ListAliasesResponse { aliases: Some(aliases), next_marker, truncated })
    }
}

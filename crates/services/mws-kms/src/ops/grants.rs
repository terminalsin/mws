//! Grants: delegated permissions on one key for one grantee.

use base64::Engine;
use mws_core::{ConditionContext, RequestContext, ServiceError};

use super::{caller_principals, page, require_not_pending_deletion, spec, validation, Access};
use crate::crypto::{self, Spec};
use crate::generated::{errors, types};
use crate::state::{Grant, Key};
use crate::Kms;

const COMMON_OPS: &[&str] = &["CreateGrant", "RetireGrant", "DescribeKey"];

/// Grant operations that make sense for `key`.
fn valid_ops(key: &Key) -> Vec<&'static str> {
    let mut ops: Vec<&str> = COMMON_OPS.to_vec();
    let s = spec(key);
    ops.extend(match key.key_usage.as_str() {
        "ENCRYPT_DECRYPT" if s == Spec::Symmetric => &[
            "Encrypt",
            "Decrypt",
            "GenerateDataKey",
            "GenerateDataKeyWithoutPlaintext",
            "GenerateDataKeyPair",
            "GenerateDataKeyPairWithoutPlaintext",
            "ReEncryptFrom",
            "ReEncryptTo",
        ][..],
        "ENCRYPT_DECRYPT" => &["Encrypt", "Decrypt", "ReEncryptFrom", "ReEncryptTo", "GetPublicKey"][..],
        "SIGN_VERIFY" => &["Sign", "Verify", "GetPublicKey"][..],
        "GENERATE_VERIFY_MAC" => &["GenerateMac", "VerifyMac"][..],
        "KEY_AGREEMENT" => &["DeriveSharedSecret", "GetPublicKey"][..],
        "ENCAPSULATE_DECAPSULATE" => &["Encapsulate", "Decapsulate", "GetPublicKey"][..],
        _ => &[][..],
    });
    ops
}

fn check_principal(p: &str) -> Result<(), ServiceError> {
    let parts: Vec<&str> = p.splitn(6, ':').collect();
    if parts.len() != 6 || parts[0] != "arn" || !matches!(parts[2], "iam" | "sts") {
        return Err(validation(format!("Invalid principal: {p}")));
    }
    Ok(())
}

/// Whether `child` constraints allow no more than `parent` ones.
fn at_least_as_strict(child: Option<&types::GrantConstraints>, parent: Option<&types::GrantConstraints>) -> bool {
    let Some(parent) = parent else { return true };
    let Some(child) = child else {
        return parent.encryption_context_equals.is_none() && parent.encryption_context_subset.is_none();
    };
    if let Some(equals) = &parent.encryption_context_equals {
        return child.encryption_context_equals.as_ref() == Some(equals);
    }
    if let Some(subset) = &parent.encryption_context_subset {
        let contains = |m: &std::collections::BTreeMap<String, String>| subset.iter().all(|(k, v)| m.get(k) == Some(v));
        return child.encryption_context_equals.as_ref().is_some_and(contains)
            || child.encryption_context_subset.as_ref().is_some_and(contains);
    }
    true
}

fn new_token() -> String {
    base64::engine::general_purpose::STANDARD.encode(crypto::random_bytes(96))
}

fn entry(g: &Grant) -> types::GrantListEntry {
    types::GrantListEntry {
        key_id: Some(g.key_arn.clone()),
        grant_id: Some(g.grant_id.clone()),
        name: Some(g.name.clone().unwrap_or_default()),
        creation_date: Some(g.created_at),
        grantee_principal: g.grantee_principal.clone(),
        retiring_principal: g.retiring_principal.clone(),
        issuing_account: Some(g.issuing_account.clone()),
        operations: Some(g.operations.clone()),
        constraints: g.constraints.clone(),
        grantee_service_principal: g.grantee_service_principal.clone(),
        retiring_service_principal: g.retiring_service_principal.clone(),
    }
}

impl Kms {
    pub(crate) fn create_grant(
        &self,
        ctx: &RequestContext,
        input: types::CreateGrantRequest,
    ) -> Result<types::CreateGrantResponse, ServiceError> {
        let mut cond = ConditionContext::new();
        cond.insert("kms:GrantOperations".into(), input.operations.clone());
        if let Some(g) = &input.grantee_principal {
            cond.insert("kms:GranteePrincipal".into(), vec![g.clone()]);
        }
        if let Some(r) = &input.retiring_principal {
            cond.insert("kms:RetiringPrincipal".into(), vec![r.clone()]);
        }
        if let Some(c) = &input.constraints {
            let mut types = vec![];
            if c.encryption_context_equals.is_some() {
                types.push("EncryptionContextEquals".to_string());
            }
            if c.encryption_context_subset.is_some() {
                types.push("EncryptionContextSubset".to_string());
            }
            cond.insert("kms:GrantConstraintType".into(), types);
        }
        cond.insert("kms:GrantIsForAWSResource".into(), vec!["false".into()]);
        // A grantee creating grants through a grant can hand on only the
        // operations it has, under constraints at least as strict as its own.
        let subset = |parent: &Grant| {
            input.operations.iter().all(|o| parent.operations.contains(o))
                && at_least_as_strict(input.constraints.as_ref(), parent.constraints.as_ref())
        };
        let mut access = Access::new("CreateGrant").grant("CreateGrant");
        access.grant_filter = Some(&subset);
        access.extra = cond;
        let t = self.authorize_key(ctx, &input.key_id, access)?;

        if input.grantee_principal.is_none() && input.grantee_service_principal.is_none() {
            return Err(validation("GranteePrincipal is required."));
        }
        for p in input.grantee_principal.iter().chain(input.retiring_principal.iter()) {
            check_principal(p)?;
        }
        if input.operations.is_empty() {
            return Err(validation("Operations must contain at least one grant operation."));
        }
        let mut st = self.lock();
        let key = st.key(&t.arn)?;
        require_not_pending_deletion(key)?;
        let valid = valid_ops(key);
        let bad: Vec<&String> = input.operations.iter().filter(|o| !valid.contains(&o.as_str())).collect();
        if !bad.is_empty() {
            return Err(validation(format!(
                "Grant operations {} are not valid for a {} KMS key with key usage {}.",
                bad.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
                key.key_spec,
                key.key_usage
            )));
        }
        if input.constraints.is_some() && !key.is_symmetric() {
            return Err(validation("Grant constraints are supported only for symmetric encryption KMS keys."));
        }
        if input.dry_run == Some(true) {
            return Err(super::dry_run());
        }
        let token = new_token();
        if let Some(name) = &input.name {
            let same = st.grants.values_mut().find(|g| {
                g.key_arn == t.arn
                    && g.name.as_ref() == Some(name)
                    && g.grantee_principal == input.grantee_principal
                    && g.retiring_principal == input.retiring_principal
                    && g.operations == input.operations
                    && g.constraints == input.constraints
            });
            if let Some(g) = same {
                g.tokens.push(token.clone());
                return Ok(types::CreateGrantResponse { grant_token: Some(token), grant_id: Some(g.grant_id.clone()) });
            }
        }
        let grant_id = crypto::random_hex(32);
        st.grants.insert(
            grant_id.clone(),
            Grant {
                grant_id: grant_id.clone(),
                key_arn: t.arn,
                name: input.name,
                created_at: ctx.received_at,
                grantee_principal: input.grantee_principal,
                retiring_principal: input.retiring_principal,
                grantee_service_principal: input.grantee_service_principal,
                retiring_service_principal: input.retiring_service_principal,
                issuing_account: format!("arn:{}:iam::{}:root", ctx.partition, ctx.caller.account_id),
                operations: input.operations,
                constraints: input.constraints,
                tokens: vec![token.clone()],
            },
        );
        Ok(types::CreateGrantResponse { grant_token: Some(token), grant_id: Some(grant_id) })
    }

    pub(crate) fn list_grants(
        &self,
        ctx: &RequestContext,
        input: types::ListGrantsRequest,
    ) -> Result<types::ListGrantsResponse, ServiceError> {
        let t = self.authorize_key(ctx, &input.key_id, Access::new("ListGrants"))?;
        let st = self.lock();
        let items = st
            .grants
            .values()
            .filter(|g| g.key_arn == t.arn)
            .filter(|g| input.grant_id.as_ref().is_none_or(|id| *id == g.grant_id))
            .filter(|g| input.grantee_principal.as_ref().is_none_or(|p| g.grantee_principal.as_ref() == Some(p)))
            .filter(|g| {
                input.grantee_service_principal.as_ref().is_none_or(|p| g.grantee_service_principal.as_ref() == Some(p))
            })
            .map(|g| (format!("{}{}", g.created_at.timestamp_micros(), g.grant_id), entry(g)))
            .collect::<Vec<_>>();
        let mut items = items;
        items.sort_by(|a, b| a.0.cmp(&b.0));
        let (grants, next_marker, truncated) = page(items, input.limit, 50, input.marker.as_deref())?;
        Ok(types::ListGrantsResponse { grants: Some(grants), next_marker, truncated })
    }

    pub(crate) fn list_retirable_grants(
        &self,
        ctx: &RequestContext,
        input: types::ListRetirableGrantsRequest,
    ) -> Result<types::ListGrantsResponse, ServiceError> {
        self.authorize_account(ctx, "ListRetirableGrants", ConditionContext::new())?;
        if input.retiring_principal.is_none() && input.retiring_service_principal.is_none() {
            return Err(validation("RetiringPrincipal is required."));
        }
        let st = self.lock();
        let mut items = st
            .grants
            .values()
            .filter(|g| input.retiring_principal.as_ref().is_none_or(|p| g.retiring_principal.as_ref() == Some(p)))
            .filter(|g| {
                input
                    .retiring_service_principal
                    .as_ref()
                    .is_none_or(|p| g.retiring_service_principal.as_ref() == Some(p))
            })
            .map(|g| (format!("{}{}", g.created_at.timestamp_micros(), g.grant_id), entry(g)))
            .collect::<Vec<_>>();
        items.sort_by(|a, b| a.0.cmp(&b.0));
        let (grants, next_marker, truncated) = page(items, input.limit, 50, input.marker.as_deref())?;
        Ok(types::ListGrantsResponse { grants: Some(grants), next_marker, truncated })
    }

    pub(crate) fn retire_grant(
        &self,
        ctx: &RequestContext,
        input: types::RetireGrantRequest,
    ) -> Result<(), ServiceError> {
        let grant = {
            let st = self.lock();
            match (&input.grant_token, &input.key_id, &input.grant_id) {
                (Some(token), _, _) => st
                    .grants
                    .values()
                    .find(|g| g.tokens.iter().any(|t| t == token))
                    .cloned()
                    .ok_or_else(|| errors::invalid_grant_token("Grant token is not valid."))?,
                (None, Some(key_id), Some(grant_id)) => {
                    let t = st.resolve(ctx, key_id, false)?;
                    st.grants
                        .get(grant_id)
                        .filter(|g| g.key_arn == t.arn)
                        .cloned()
                        .ok_or_else(|| errors::invalid_grant_id(format!("Grant ID {grant_id} is not valid.")))?
                }
                _ => return Err(validation("Either GrantToken or both KeyId and GrantId must be specified.")),
            }
        };
        let principals = caller_principals(ctx);
        let retiring = grant.retiring_principal.as_ref().is_some_and(|r| principals.contains(r));
        let grantee = grant.grantee_principal.as_ref().is_some_and(|g| principals.contains(g))
            && grant.operations.iter().any(|o| o == "RetireGrant");
        if !retiring && !grantee {
            self.authorize_key(ctx, &grant.key_arn, Access::new("RetireGrant"))?;
        }
        if input.dry_run == Some(true) {
            return Err(super::dry_run());
        }
        self.lock().grants.remove(&grant.grant_id);
        Ok(())
    }

    pub(crate) fn revoke_grant(
        &self,
        ctx: &RequestContext,
        input: types::RevokeGrantRequest,
    ) -> Result<(), ServiceError> {
        let t = self.authorize_key(ctx, &input.key_id, Access::new("RevokeGrant"))?;
        let mut st = self.lock();
        if !st.grants.get(&input.grant_id).is_some_and(|g| g.key_arn == t.arn) {
            return Err(errors::not_found(format!("Grant ID {} not found for key {}.", input.grant_id, t.arn)));
        }
        if input.dry_run == Some(true) {
            return Err(super::dry_run());
        }
        st.grants.remove(&input.grant_id);
        Ok(())
    }
}

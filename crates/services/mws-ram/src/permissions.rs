//! Managed permissions: the AWS managed library, customer managed
//! permissions and their versions, and which shares use them.

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::Value;

use crate::catalog::{self, Managed};
use crate::generated::{errors, types};
use crate::state::{Permission, PermissionVersion, ReplaceWork, SharePermission, State};
use crate::util::{self, paginate, wire_tags};
use crate::Ram;

const MAX_VERSIONS: usize = 5;

fn not_found(arn: &str) -> ServiceError {
    errors::unknown_resource(format!("Permission {arn} could not be found."))
}

fn managed_detail(m: &Managed, partition: &str) -> types::ResourceSharePermissionDetail {
    types::ResourceSharePermissionDetail {
        arn: Some(m.arn(partition)),
        version: Some("1".into()),
        default_version: Some(true),
        name: Some(m.name.into()),
        resource_type: Some(m.resource_type.into()),
        permission: Some(m.template(partition)),
        creation_time: Some(catalog::published()),
        last_updated_time: Some(catalog::published()),
        is_resource_type_default: Some(m.is_default),
        permission_type: Some("AWS_MANAGED".into()),
        feature_set: Some("STANDARD".into()),
        status: Some("ATTACHABLE".into()),
        tags: None,
    }
}

fn summary_of(d: types::ResourceSharePermissionDetail) -> types::ResourceSharePermissionSummary {
    types::ResourceSharePermissionSummary {
        arn: d.arn,
        version: d.version,
        default_version: d.default_version,
        name: d.name,
        resource_type: d.resource_type,
        status: d.status,
        creation_time: d.creation_time,
        last_updated_time: d.last_updated_time,
        is_resource_type_default: d.is_resource_type_default,
        permission_type: d.permission_type,
        feature_set: d.feature_set,
        tags: d.tags,
    }
}

impl Permission {
    fn detail(&self, version: u32) -> types::ResourceSharePermissionDetail {
        let v = self.versions.get(&version);
        types::ResourceSharePermissionDetail {
            arn: Some(self.arn.clone()),
            version: Some(version.to_string()),
            default_version: Some(version == self.default_version),
            name: Some(self.name.clone()),
            resource_type: Some(self.resource_type.clone()),
            permission: v.map(|v| v.template.clone()),
            creation_time: v.and_then(|v| v.created),
            last_updated_time: v.and_then(|v| v.updated),
            is_resource_type_default: Some(false),
            permission_type: Some("CUSTOMER_MANAGED".into()),
            feature_set: Some(self.feature_set.clone()),
            status: Some(if self.status == "DELETED" {
                "DELETED".into()
            } else {
                v.map(|v| v.status.clone()).unwrap_or_default()
            }),
            tags: wire_tags(&self.tags),
        }
    }
}

impl Ram {
    /// A permission the caller may attach: `(resource type, version)`.
    pub(crate) fn attachable_permission(
        &self,
        st: &State,
        ctx: &RequestContext,
        arn: &str,
        version: Option<i32>,
    ) -> Result<(String, u32), ServiceError> {
        util::check_arn(arn)?;
        if let Some(m) = catalog::find(arn) {
            if self.type_named(m.resource_type).is_none() {
                return Err(not_found(arn));
            }
            if version.is_some_and(|v| v != 1) {
                return Err(errors::invalid_parameter(format!(
                    "Version {} of {arn} doesn't exist.",
                    version.unwrap_or(0)
                )));
            }
            return Ok((m.resource_type.into(), 1));
        }
        let p = self.owned_permission(st, ctx, arn)?;
        if p.status != "ATTACHABLE" {
            return Err(errors::operation_not_permitted(format!(
                "The permission {arn} can't be attached ({}).",
                p.status
            )));
        }
        let version = match version {
            Some(v) if v > 0 && p.versions.contains_key(&(v as u32)) => v as u32,
            Some(v) => return Err(errors::invalid_parameter(format!("Version {v} of {arn} doesn't exist."))),
            None => p.default_version,
        };
        Ok((p.resource_type.clone(), version))
    }

    fn owned_permission<'s>(
        &self,
        st: &'s State,
        ctx: &RequestContext,
        arn: &str,
    ) -> Result<&'s Permission, ServiceError> {
        util::check_arn(arn)?;
        st.permissions
            .get(arn)
            .filter(|p| p.owner == ctx.caller.account_id && p.region == ctx.region && p.status != "DELETED")
            .ok_or_else(|| not_found(arn))
    }

    fn validate_template(&self, resource_type: &str, template: &str) -> Result<(), ServiceError> {
        let ty = self
            .type_named(resource_type)
            .ok_or_else(|| errors::invalid_parameter(format!("The resource type {resource_type} is not valid.")))?;
        let bad = |why: String| errors::malformed_policy_template(format!("The policy template is malformed: {why}"));
        let doc: Value = serde_json::from_str(template).map_err(|e| bad(e.to_string()))?;
        let Value::Object(o) = &doc else { return Err(bad("it must be a JSON object.".into())) };
        for k in o.keys() {
            if !matches!(k.as_str(), "Effect" | "Action" | "Condition") {
                return Err(bad(format!(
                    "the element {k} isn't allowed; a template has only Effect, Action and Condition."
                )));
            }
        }
        if o.get("Effect").and_then(Value::as_str) != Some("Allow") {
            return Err(bad("Effect must be Allow.".into()));
        }
        let actions: Vec<&str> = match o.get("Action") {
            Some(Value::String(s)) => vec![s.as_str()],
            Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        if actions.is_empty() {
            return Err(bad("Action must name at least one action.".into()));
        }
        for a in actions {
            if !ty.shareable_actions().iter().any(|x| x.eq_ignore_ascii_case(a)) {
                return Err(bad(format!("the action {a} can't be granted on {resource_type} resources.")));
            }
        }
        if o.get("Condition").is_some_and(|c| !c.is_object()) {
            return Err(bad("Condition must be an object.".into()));
        }
        Ok(())
    }

    fn authorize_permission(&self, ctx: &RequestContext, action: &str, arn: &str) -> Result<(), ServiceError> {
        let tags = self.lock().permissions.get(arn).map(|p| p.tags.clone()).unwrap_or_default();
        let mut cond = util::resource_tag_context(&tags);
        cond.insert("ram:PermissionArn".into(), vec![arn.to_string()]);
        ctx.authorize(&format!("ram:{action}"), arn, cond)
    }

    pub(crate) fn create_permission(
        &self,
        ctx: &RequestContext,
        input: types::CreatePermissionRequest,
    ) -> Result<types::CreatePermissionResponse, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        let arn = util::ram_arn(ctx, "permission", &input.name);
        let mut cond = util::request_tag_context(&tags);
        cond.insert("ram:PermissionResourceType".into(), vec![input.resource_type.clone()]);
        ctx.authorize("ram:CreatePermission", &arn, cond)?;
        self.validate_template(&input.resource_type, &input.policy_template)?;
        let resource_type =
            self.type_named(&input.resource_type).map(|t| t.resource_type().to_string()).unwrap_or_default();
        let mut st = self.lock();
        if let Some(existing) = util::idempotent(&st, ctx, input.client_token.as_deref()) {
            if let Some(p) = st.permissions.get(&existing) {
                return Ok(types::CreatePermissionResponse {
                    permission: Some(summary_of(p.detail(p.default_version))),
                    client_token: input.client_token,
                });
            }
        }
        if st.permissions.get(&arn).is_some_and(|p| p.status != "DELETED") {
            return Err(errors::permission_already_exists(format!(
                "A permission named {} already exists.",
                input.name
            )));
        }
        let now = ctx.received_at;
        let mut p = Permission {
            arn: arn.clone(),
            name: input.name,
            owner: ctx.caller.account_id.clone(),
            region: ctx.region.clone(),
            resource_type,
            feature_set: "STANDARD".into(),
            status: "ATTACHABLE".into(),
            default_version: 1,
            created: Some(now),
            updated: Some(now),
            ..Default::default()
        };
        util::merge_tags(&mut p.tags, &tags)?;
        p.versions.insert(1, version(input.policy_template, now));
        let summary = summary_of(p.detail(1));
        st.permissions.insert(arn.clone(), p);
        util::remember_token(&mut st, ctx, input.client_token.as_deref(), &arn);
        Ok(types::CreatePermissionResponse { permission: Some(summary), client_token: input.client_token })
    }

    pub(crate) fn create_permission_version(
        &self,
        ctx: &RequestContext,
        input: types::CreatePermissionVersionRequest,
    ) -> Result<types::CreatePermissionVersionResponse, ServiceError> {
        let arn = &input.permission_arn;
        self.authorize_permission(ctx, "CreatePermissionVersion", arn)?;
        let resource_type = {
            let st = self.lock();
            let p = self.owned_permission(&st, ctx, arn)?;
            if p.feature_set != "STANDARD" {
                return Err(errors::operation_not_permitted(format!(
                    "You can't add versions to {arn}; promote it first."
                )));
            }
            if p.versions.len() >= MAX_VERSIONS {
                return Err(errors::permission_versions_limit_exceeded(format!(
                    "The permission {arn} already has {MAX_VERSIONS} versions. Delete one first."
                )));
            }
            p.resource_type.clone()
        };
        self.validate_template(&resource_type, &input.policy_template)?;
        let mut st = self.lock();
        let p = st.permissions.get_mut(arn).ok_or_else(|| not_found(arn))?;
        let next = p.versions.keys().max().copied().unwrap_or(0) + 1;
        p.versions.insert(next, version(input.policy_template, ctx.received_at));
        p.updated = Some(ctx.received_at);
        Ok(types::CreatePermissionVersionResponse {
            permission: Some(p.detail(next)),
            client_token: input.client_token,
        })
    }

    pub(crate) fn get_permission(
        &self,
        ctx: &RequestContext,
        input: types::GetPermissionRequest,
    ) -> Result<types::GetPermissionResponse, ServiceError> {
        let arn = &input.permission_arn;
        self.authorize_permission(ctx, "GetPermission", arn)?;
        if let Some(m) = catalog::find(arn).filter(|m| self.type_named(m.resource_type).is_some()) {
            if input.permission_version.is_some_and(|v| v != 1) {
                return Err(errors::invalid_parameter(format!(
                    "Version {} of {arn} doesn't exist.",
                    input.permission_version.unwrap_or(0)
                )));
            }
            return Ok(types::GetPermissionResponse { permission: Some(managed_detail(&m, &ctx.partition)) });
        }
        let st = self.lock();
        let p = self.permission_visible(&st, ctx, arn)?;
        let v = match input.permission_version {
            Some(v) if v > 0 && p.versions.contains_key(&(v as u32)) => v as u32,
            Some(v) => return Err(errors::invalid_parameter(format!("Version {v} of {arn} doesn't exist."))),
            None => p.default_version,
        };
        Ok(types::GetPermissionResponse { permission: Some(p.detail(v)) })
    }

    /// A customer managed permission the caller owns, or one used by a share
    /// that is shared with the caller.
    fn permission_visible<'s>(
        &self,
        st: &'s State,
        ctx: &RequestContext,
        arn: &str,
    ) -> Result<&'s Permission, ServiceError> {
        util::check_arn(arn)?;
        let p = st.permissions.get(arn).filter(|p| p.status != "DELETED").ok_or_else(|| not_found(arn))?;
        let account = ctx.caller.account_id.as_str();
        let visible = p.owner == account
            || st.shares.values().any(|s| s.permissions.iter().any(|x| x.arn == arn) && self.shared_with(s, account));
        if visible {
            Ok(p)
        } else {
            Err(not_found(arn))
        }
    }

    pub(crate) fn list_permissions(
        &self,
        ctx: &RequestContext,
        input: types::ListPermissionsRequest,
    ) -> Result<types::ListPermissionsResponse, ServiceError> {
        ctx.authorize("ram:ListPermissions", "*", ConditionContext::new())?;
        if let Some(t) = &input.resource_type {
            if self.type_named(t).is_none() {
                return Err(errors::invalid_parameter(format!("The resource type {t} is not valid.")));
            }
        }
        let filter = input.permission_type.as_deref().unwrap_or("ALL");
        let wanted = |ty: &str| input.resource_type.as_ref().is_none_or(|t| t.eq_ignore_ascii_case(ty));
        let mut out = Vec::new();
        if filter != "CUSTOMER_MANAGED" {
            for m in catalog::all() {
                if self.type_named(m.resource_type).is_some() && wanted(m.resource_type) {
                    out.push(summary_of(managed_detail(&m, &ctx.partition)));
                }
            }
        }
        if filter != "AWS_MANAGED" {
            let st = self.lock();
            for p in st.permissions.values() {
                if p.owner == ctx.caller.account_id
                    && p.region == ctx.region
                    && p.status != "DELETED"
                    && wanted(&p.resource_type)
                {
                    out.push(summary_of(p.detail(p.default_version)));
                }
            }
        }
        let (page, next) = paginate(out, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListPermissionsResponse { permissions: Some(page), next_token: next })
    }

    pub(crate) fn list_permission_versions(
        &self,
        ctx: &RequestContext,
        input: types::ListPermissionVersionsRequest,
    ) -> Result<types::ListPermissionVersionsResponse, ServiceError> {
        let arn = &input.permission_arn;
        self.authorize_permission(ctx, "ListPermissionVersions", arn)?;
        let out = if let Some(m) = catalog::find(arn).filter(|m| self.type_named(m.resource_type).is_some()) {
            vec![summary_of(managed_detail(&m, &ctx.partition))]
        } else {
            let st = self.lock();
            let p = self.permission_visible(&st, ctx, arn)?;
            p.versions.keys().map(|v| summary_of(p.detail(*v))).collect()
        };
        let (page, next) = paginate(out, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListPermissionVersionsResponse { permissions: Some(page), next_token: next })
    }

    pub(crate) fn set_default_permission_version(
        &self,
        ctx: &RequestContext,
        input: types::SetDefaultPermissionVersionRequest,
    ) -> Result<types::SetDefaultPermissionVersionResponse, ServiceError> {
        let arn = &input.permission_arn;
        self.authorize_permission(ctx, "SetDefaultPermissionVersion", arn)?;
        let mut st = self.lock();
        self.owned_permission(&st, ctx, arn)?;
        let p = st.permissions.get_mut(arn).expect("checked above");
        let v = input.permission_version;
        if v <= 0 || !p.versions.contains_key(&(v as u32)) {
            return Err(errors::invalid_parameter(format!("Version {v} of {arn} doesn't exist.")));
        }
        p.default_version = v as u32;
        p.updated = Some(ctx.received_at);
        Ok(types::SetDefaultPermissionVersionResponse { return_value: Some(true), client_token: input.client_token })
    }

    fn in_use(st: &State, arn: &str, version: Option<u32>) -> bool {
        st.shares.values().any(|s| {
            s.status != "DELETED"
                && s.permissions.iter().any(|p| p.arn == arn && version.is_none_or(|v| p.version == v))
        })
    }

    pub(crate) fn delete_permission_version(
        &self,
        ctx: &RequestContext,
        input: types::DeletePermissionVersionRequest,
    ) -> Result<types::DeletePermissionVersionResponse, ServiceError> {
        let arn = &input.permission_arn;
        self.authorize_permission(ctx, "DeletePermissionVersion", arn)?;
        let mut st = self.lock();
        self.owned_permission(&st, ctx, arn)?;
        let v = input.permission_version;
        if v <= 0 || !st.permissions[arn].versions.contains_key(&(v as u32)) {
            return Err(errors::invalid_parameter(format!("Version {v} of {arn} doesn't exist.")));
        }
        let v = v as u32;
        if st.permissions[arn].default_version == v {
            return Err(errors::operation_not_permitted(format!(
                "Version {v} is the default version of {arn}. Set another default version first."
            )));
        }
        if Self::in_use(&st, arn, Some(v)) {
            return Err(errors::operation_not_permitted(format!(
                "Version {v} of {arn} is associated with resource shares. Replace it first."
            )));
        }
        let p = st.permissions.get_mut(arn).expect("checked above");
        p.versions.remove(&v);
        Ok(types::DeletePermissionVersionResponse {
            return_value: Some(true),
            client_token: input.client_token,
            permission_status: Some("ATTACHABLE".into()),
        })
    }

    pub(crate) fn delete_permission(
        &self,
        ctx: &RequestContext,
        input: types::DeletePermissionRequest,
    ) -> Result<types::DeletePermissionResponse, ServiceError> {
        let arn = &input.permission_arn;
        if catalog::find(arn).is_some() {
            return Err(errors::operation_not_permitted("You can't delete an AWS managed permission."));
        }
        self.authorize_permission(ctx, "DeletePermission", arn)?;
        let mut st = self.lock();
        self.owned_permission(&st, ctx, arn)?;
        if Self::in_use(&st, arn, None) {
            return Err(errors::operation_not_permitted(format!(
                "The permission {arn} is associated with resource shares. Disassociate or replace it first."
            )));
        }
        let p = st.permissions.get_mut(arn).expect("checked above");
        p.status = "DELETED".into();
        p.updated = Some(ctx.received_at);
        Ok(types::DeletePermissionResponse {
            return_value: Some(true),
            client_token: input.client_token,
            permission_status: Some("DELETED".into()),
        })
    }

    pub(crate) fn associate_resource_share_permission(
        &self,
        ctx: &RequestContext,
        input: types::AssociateResourceSharePermissionRequest,
    ) -> Result<types::AssociateResourceSharePermissionResponse, ServiceError> {
        let arn = &input.resource_share_arn;
        let mut cond = ConditionContext::new();
        cond.insert("ram:PermissionArn".into(), vec![input.permission_arn.clone()]);
        ctx.authorize("ram:AssociateResourceSharePermission", arn, cond)?;
        let resources = {
            let mut st = self.lock();
            let share = self.owned_share(&st, ctx, arn)?;
            if share.status != "ACTIVE" {
                return Err(errors::invalid_state_transition(format!(
                    "The resource share {arn} is in the {} state.",
                    share.status
                )));
            }
            let (ty, version) =
                self.attachable_permission(&st, ctx, &input.permission_arn, input.permission_version)?;
            let replace = input.replace.unwrap_or(false);
            let share = st.shares.get_mut(arn).expect("checked above");
            match share.permissions.iter().position(|p| p.resource_type == ty) {
                Some(i) if share.permissions[i].arn == input.permission_arn => share.permissions[i].version = version,
                Some(i) if replace => {
                    share.permissions[i] = SharePermission {
                        arn: input.permission_arn.clone(),
                        version,
                        resource_type: ty,
                        updated: Some(ctx.received_at),
                    };
                }
                Some(_) => {
                    return Err(errors::invalid_parameter(format!(
                        "The resource share already has a permission for {ty}. Set replace to true to replace it."
                    )))
                }
                None => share.permissions.push(SharePermission {
                    arn: input.permission_arn.clone(),
                    version,
                    resource_type: ty,
                    updated: Some(ctx.received_at),
                }),
            }
            share.updated = Some(ctx.received_at);
            share.resources.iter().map(|r| r.entity.clone()).collect::<Vec<_>>()
        };
        self.push_policies(&ctx.partition, resources);
        Ok(types::AssociateResourceSharePermissionResponse {
            return_value: Some(true),
            client_token: input.client_token,
        })
    }

    pub(crate) fn disassociate_resource_share_permission(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateResourceSharePermissionRequest,
    ) -> Result<types::DisassociateResourceSharePermissionResponse, ServiceError> {
        let arn = &input.resource_share_arn;
        let mut cond = ConditionContext::new();
        cond.insert("ram:PermissionArn".into(), vec![input.permission_arn.clone()]);
        ctx.authorize("ram:DisassociateResourceSharePermission", arn, cond)?;
        let resources = {
            let mut st = self.lock();
            let share = self.owned_share(&st, ctx, arn)?;
            let Some(perm) = share.permissions.iter().find(|p| p.arn == input.permission_arn) else {
                return Err(errors::unknown_resource(format!(
                    "The permission {} isn't associated with the resource share {arn}.",
                    input.permission_arn
                )));
            };
            if share
                .resources
                .iter()
                .any(|r| r.status == "ASSOCIATED" && r.resource_type.as_deref() == Some(perm.resource_type.as_str()))
            {
                return Err(errors::operation_not_permitted(format!(
                    "The resource share still has {} resources, which need a permission. Replace the permission instead.",
                    perm.resource_type
                )));
            }
            let share = st.shares.get_mut(arn).expect("checked above");
            share.permissions.retain(|p| p.arn != input.permission_arn);
            share.updated = Some(ctx.received_at);
            share.resources.iter().map(|r| r.entity.clone()).collect::<Vec<_>>()
        };
        self.push_policies(&ctx.partition, resources);
        Ok(types::DisassociateResourceSharePermissionResponse {
            return_value: Some(true),
            client_token: input.client_token,
        })
    }

    fn permission_meta(
        &self,
        st: &State,
        partition: &str,
        arn: &str,
        version: u32,
    ) -> Option<types::ResourceSharePermissionSummary> {
        if let Some(m) = catalog::find(arn) {
            return Some(summary_of(managed_detail(&m, partition)));
        }
        st.permissions.get(arn).map(|p| summary_of(p.detail(version)))
    }

    pub(crate) fn list_resource_share_permissions(
        &self,
        ctx: &RequestContext,
        input: types::ListResourceSharePermissionsRequest,
    ) -> Result<types::ListResourceSharePermissionsResponse, ServiceError> {
        let arn = &input.resource_share_arn;
        ctx.authorize("ram:ListResourceSharePermissions", arn, ConditionContext::new())?;
        let st = self.lock();
        util::check_arn(arn)?;
        let share = st
            .shares
            .get(arn)
            .filter(|s| {
                s.region == ctx.region
                    && (s.owner == ctx.caller.account_id || self.shared_with(s, &ctx.caller.account_id))
            })
            .ok_or_else(|| crate::shares::not_found(arn))?;
        let out: Vec<_> = share
            .permissions
            .iter()
            .filter_map(|p| {
                let mut s = self.permission_meta(&st, &ctx.partition, &p.arn, p.version)?;
                s.status = Some("ASSOCIATED".into());
                if p.updated.is_some() {
                    s.last_updated_time = p.updated;
                }
                Some(s)
            })
            .collect();
        let (page, next) = paginate(out, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListResourceSharePermissionsResponse { permissions: Some(page), next_token: next })
    }

    pub(crate) fn list_permission_associations(
        &self,
        ctx: &RequestContext,
        input: types::ListPermissionAssociationsRequest,
    ) -> Result<types::ListPermissionAssociationsResponse, ServiceError> {
        ctx.authorize("ram:ListPermissionAssociations", "*", ConditionContext::new())?;
        let st = self.lock();
        let mut out = Vec::new();
        for share in st.shares.values().filter(|s| s.owner == ctx.caller.account_id && s.region == ctx.region) {
            let status = if share.status == "DELETED" { "DISASSOCIATED" } else { "ASSOCIATED" };
            for p in &share.permissions {
                let default_version = catalog::find(&p.arn).is_some()
                    || st.permissions.get(&p.arn).is_some_and(|x| x.default_version == p.version);
                let feature_set =
                    st.permissions.get(&p.arn).map(|x| x.feature_set.clone()).unwrap_or_else(|| "STANDARD".into());
                if input.permission_arn.as_ref().is_some_and(|a| a != &p.arn)
                    || input.permission_version.is_some_and(|v| v as u32 != p.version)
                    || input.association_status.as_ref().is_some_and(|s| s != status)
                    || input.resource_type.as_ref().is_some_and(|t| !t.eq_ignore_ascii_case(&p.resource_type))
                    || input.feature_set.as_ref().is_some_and(|f| f != &feature_set)
                    || input.default_version.is_some_and(|d| d != default_version)
                {
                    continue;
                }
                out.push(types::AssociatedPermission {
                    arn: Some(p.arn.clone()),
                    permission_version: Some(p.version.to_string()),
                    default_version: Some(default_version),
                    resource_type: Some(p.resource_type.clone()),
                    status: Some(status.into()),
                    feature_set: Some(feature_set),
                    last_updated_time: p.updated.or(share.updated),
                    resource_share_arn: Some(share.arn.clone()),
                });
            }
        }
        let (page, next) = paginate(out, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListPermissionAssociationsResponse { permissions: Some(page), next_token: next })
    }

    pub(crate) fn replace_permission_associations(
        &self,
        ctx: &RequestContext,
        input: types::ReplacePermissionAssociationsRequest,
    ) -> Result<types::ReplacePermissionAssociationsResponse, ServiceError> {
        let mut cond = ConditionContext::new();
        cond.insert("ram:PermissionArn".into(), vec![input.from_permission_arn.clone()]);
        ctx.authorize("ram:ReplacePermissionAssociations", "*", cond)?;
        let now = ctx.received_at;
        let (work, resources) = {
            let mut st = self.lock();
            let from_type = if let Some(m) = catalog::find(&input.from_permission_arn) {
                m.resource_type.to_string()
            } else {
                st.permissions
                    .get(&input.from_permission_arn)
                    .filter(|p| p.owner == ctx.caller.account_id)
                    .map(|p| p.resource_type.clone())
                    .ok_or_else(|| not_found(&input.from_permission_arn))?
            };
            let (to_type, to_version) = self.attachable_permission(&st, ctx, &input.to_permission_arn, None)?;
            if from_type != to_type {
                return Err(errors::invalid_parameter(format!(
                    "Both permissions must be for the same resource type, not {from_type} and {to_type}."
                )));
            }
            let mut resources = Vec::new();
            for share in st.shares.values_mut().filter(|s| s.owner == ctx.caller.account_id && s.status == "ACTIVE") {
                let mut touched = false;
                for p in share.permissions.iter_mut() {
                    if p.arn == input.from_permission_arn
                        && input.from_permission_version.is_none_or(|v| v as u32 == p.version)
                    {
                        *p = SharePermission {
                            arn: input.to_permission_arn.clone(),
                            version: to_version,
                            resource_type: to_type.clone(),
                            updated: Some(now),
                        };
                        touched = true;
                    }
                }
                if touched {
                    share.updated = Some(now);
                    resources.extend(share.resources.iter().map(|r| r.entity.clone()));
                }
            }
            let id = uuid::Uuid::new_v4().to_string();
            let work = ReplaceWork {
                id: id.clone(),
                owner: ctx.caller.account_id.clone(),
                from_arn: input.from_permission_arn.clone(),
                from_version: input.from_permission_version.map(|v| v as u32),
                to_arn: input.to_permission_arn.clone(),
                to_version,
                status: "COMPLETED".into(),
                status_message: None,
                created: Some(now),
                updated: Some(now),
            };
            st.replace_work.insert(id, work.clone());
            (work, resources)
        };
        self.push_policies(&ctx.partition, resources);
        Ok(types::ReplacePermissionAssociationsResponse {
            replace_permission_associations_work: Some(wire_work(&work)),
            client_token: input.client_token,
        })
    }

    pub(crate) fn list_replace_permission_associations_work(
        &self,
        ctx: &RequestContext,
        input: types::ListReplacePermissionAssociationsWorkRequest,
    ) -> Result<types::ListReplacePermissionAssociationsWorkResponse, ServiceError> {
        ctx.authorize("ram:ListReplacePermissionAssociationsWork", "*", ConditionContext::new())?;
        let st = self.lock();
        let out: Vec<_> = st
            .replace_work
            .values()
            .filter(|w| w.owner == ctx.caller.account_id)
            .filter(|w| input.work_ids.as_ref().is_none_or(|ids| ids.contains(&w.id)))
            .filter(|w| input.status.as_ref().is_none_or(|s| s == &w.status))
            .map(wire_work)
            .collect();
        let (page, next) = paginate(out, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListReplacePermissionAssociationsWorkResponse {
            replace_permission_associations_works: Some(page),
            next_token: next,
        })
    }

    pub(crate) fn promote_permission_created_from_policy(
        &self,
        ctx: &RequestContext,
        input: types::PromotePermissionCreatedFromPolicyRequest,
    ) -> Result<types::PromotePermissionCreatedFromPolicyResponse, ServiceError> {
        let arn = &input.permission_arn;
        self.authorize_permission(ctx, "PromotePermissionCreatedFromPolicy", arn)?;
        let mut st = self.lock();
        let p = self.owned_permission(&st, ctx, arn)?.clone();
        if p.feature_set != "CREATED_FROM_POLICY" {
            return Err(errors::operation_not_permitted(format!(
                "The permission {arn} wasn't created from a resource policy."
            )));
        }
        let new_arn = util::ram_arn(ctx, "permission", &input.name);
        if st.permissions.get(&new_arn).is_some_and(|x| x.status != "DELETED") {
            return Err(errors::permission_already_exists(format!(
                "A permission named {} already exists.",
                input.name
            )));
        }
        let now = ctx.received_at;
        let template = p.versions.get(&p.default_version).map(|v| v.template.clone()).unwrap_or_default();
        let promoted = Permission {
            arn: new_arn.clone(),
            name: input.name,
            owner: p.owner.clone(),
            region: p.region.clone(),
            resource_type: p.resource_type.clone(),
            feature_set: "STANDARD".into(),
            status: "ATTACHABLE".into(),
            default_version: 1,
            versions: [(1, version(template, now))].into_iter().collect(),
            created: Some(now),
            updated: Some(now),
            ..Default::default()
        };
        let summary = summary_of(promoted.detail(1));
        st.permissions.insert(new_arn, promoted);
        Ok(types::PromotePermissionCreatedFromPolicyResponse {
            permission: Some(summary),
            client_token: input.client_token,
        })
    }
}

fn version(template: String, now: DateTime<Utc>) -> PermissionVersion {
    PermissionVersion { template, created: Some(now), updated: Some(now), status: "ATTACHABLE".into() }
}

fn wire_work(w: &ReplaceWork) -> types::ReplacePermissionAssociationsWork {
    types::ReplacePermissionAssociationsWork {
        id: Some(w.id.clone()),
        from_permission_arn: Some(w.from_arn.clone()),
        from_permission_version: w.from_version.map(|v| v.to_string()),
        to_permission_arn: Some(w.to_arn.clone()),
        to_permission_version: Some(w.to_version.to_string()),
        status: Some(w.status.clone()),
        status_message: w.status_message.clone(),
        creation_time: w.created,
        last_updated_time: w.updated,
    }
}

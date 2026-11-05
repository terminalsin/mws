//! Resource shares and their associations.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::principals::{PrincipalKind, RAM_SERVICE_PRINCIPAL};
use crate::state::{Association, Invitation, Share, SharePermission, State};
use crate::util::{self, paginate, wire_tags};
use crate::{catalog, Ram};

pub fn not_found(arn: &str) -> ServiceError {
    errors::unknown_resource(format!("ResourceShare {arn} could not be found."))
}

impl Share {
    pub fn wire(&self) -> types::ResourceShare {
        types::ResourceShare {
            resource_share_arn: Some(self.arn.clone()),
            name: Some(self.name.clone()),
            owning_account_id: Some(self.owner.clone()),
            allow_external_principals: Some(self.allow_external),
            status: Some(self.status.clone()),
            status_message: None,
            tags: wire_tags(&self.tags),
            creation_time: self.created,
            last_updated_time: self.updated,
            feature_set: Some(self.feature_set.clone()),
            resource_share_configuration: self
                .retain_on_leave
                .map(|r| types::ResourceShareConfiguration { retain_sharing_on_account_leave_organization: Some(r) }),
        }
    }

    pub fn wire_association(&self, a: &Association, ty: &str) -> types::ResourceShareAssociation {
        types::ResourceShareAssociation {
            resource_share_arn: Some(self.arn.clone()),
            resource_share_name: Some(self.name.clone()),
            associated_entity: Some(a.entity.clone()),
            association_type: Some(ty.into()),
            status: Some(a.status.clone()),
            status_message: a.status_message.clone(),
            creation_time: Some(a.created),
            last_updated_time: Some(a.updated),
            external: (ty == "PRINCIPAL").then_some(a.external),
        }
    }
}

/// What an association request asks for, checked before taking the lock.
struct Checked {
    resources: Vec<(String, String)>,
    principals: Vec<(String, PrincipalKind)>,
    sources: Vec<(String, &'static str)>,
}

impl Ram {
    /// The caller's share at `arn` in this region.
    pub(crate) fn owned_share<'s>(
        &self,
        st: &'s State,
        ctx: &RequestContext,
        arn: &str,
    ) -> Result<&'s Share, ServiceError> {
        util::check_arn(arn)?;
        st.shares
            .get(arn)
            .filter(|s| s.owner == ctx.caller.account_id && s.region == ctx.region)
            .ok_or_else(|| not_found(arn))
    }

    fn authorize_share(
        &self,
        ctx: &RequestContext,
        action: &str,
        arn: &str,
        extra: ConditionContext,
    ) -> Result<(), ServiceError> {
        let tags = self.lock().shares.get(arn).map(|s| s.tags.clone()).unwrap_or_default();
        let mut cond = util::resource_tag_context(&tags);
        cond.extend(extra);
        ctx.authorize(&format!("ram:{action}"), arn, cond)
    }

    /// Validate the resources, principals and sources of a create or
    /// associate call. Talks to the owning services, so no lock is held.
    fn check_entities(
        &self,
        ctx: &RequestContext,
        resources: &[String],
        principals: &[String],
        sources: &[String],
    ) -> Result<Checked, ServiceError> {
        let owner = ctx.caller.account_id.as_str();
        let mut checked = Checked { resources: Vec::new(), principals: Vec::new(), sources: Vec::new() };
        for arn in resources {
            util::check_arn(arn)?;
            let ty = self.type_for_arn(arn).ok_or_else(|| {
                errors::invalid_resource_type(format!("The resource type of {arn} can't be shared with AWS RAM."))
            })?;
            let loc = ty
                .locate(arn)
                .filter(|l| l.region == ctx.region)
                .ok_or_else(|| errors::unknown_resource(format!("The resource {arn} could not be found.")))?;
            if loc.owner_account != owner {
                return Err(errors::operation_not_permitted(format!(
                    "You can share only resources that you own. Your account doesn't own {arn}."
                )));
            }
            ctx.authorize(ty.share_action(), arn, ConditionContext::new())?;
            checked.resources.push((arn.clone(), ty.resource_type().to_string()));
        }
        for p in principals {
            let kind = PrincipalKind::parse(p)?;
            match &kind {
                PrincipalKind::Account(a) if a == owner => {
                    return Err(errors::invalid_parameter(
                        "The resource share owner can't be a principal of its own resource share.",
                    ))
                }
                PrincipalKind::Organization { org_id } | PrincipalKind::OrganizationalUnit { org_id, .. } => {
                    let org = self.org_sharing_enabled(owner).ok_or_else(|| {
                        errors::operation_not_permitted(
                            "Unable to share with an organization or organizational unit because sharing with AWS Organizations is not enabled. Call EnableSharingWithAwsOrganization first.",
                        )
                    })?;
                    if &org.organization_id != org_id {
                        return Err(errors::operation_not_permitted(format!(
                            "You can share only with your own organization, not {p}."
                        )));
                    }
                }
                _ => {}
            }
            checked.principals.push((p.clone(), kind));
        }
        for s in sources {
            let ty = if s.len() == 12 && s.bytes().all(|b| b.is_ascii_digit()) {
                "ACCOUNT"
            } else if s.starts_with("arn:") {
                "ARN"
            } else {
                return Err(errors::invalid_parameter(format!("The source {s} must be an AWS account ID or an ARN.")));
            };
            checked.sources.push((s.clone(), ty));
        }
        Ok(checked)
    }

    /// Add `checked` to the share; returns the new associations. Takes the
    /// lock.
    fn apply_associations(
        &self,
        ctx: &RequestContext,
        share_arn: &str,
        checked: Checked,
    ) -> Result<Vec<types::ResourceShareAssociation>, ServiceError> {
        let now = ctx.received_at;
        let owner = ctx.caller.account_id.clone();
        // Who needs an invitation: accounts outside the organization (or
        // when sharing with it is off).
        let mut externals = BTreeMap::new();
        for (p, kind) in &checked.principals {
            if let Some(account) = kind.account() {
                externals.insert(p.clone(), !self.internal(&owner, account));
            }
        }
        let mut st = self.lock();
        let share = st.shares.get(share_arn).ok_or_else(|| not_found(share_arn))?;
        if share.status != "ACTIVE" {
            return Err(errors::invalid_state_transition(format!(
                "The resource share {share_arn} is in the {} state.",
                share.status
            )));
        }
        let allow_external = share.allow_external;
        for (p, kind) in &checked.principals {
            let external = externals.get(p).copied().unwrap_or(false);
            if external && !allow_external {
                return Err(errors::operation_not_permitted(format!(
                    "The resource share {share_arn} doesn't allow sharing with principals outside your organization, such as {p}."
                )));
            }
            if external && matches!(kind, PrincipalKind::Iam { .. }) {
                return Err(errors::operation_not_permitted(format!(
                    "You can share with IAM roles and users only inside your organization, not {p}."
                )));
            }
        }
        let mut out = Vec::new();
        let mut invitations = Vec::new();
        let share = st.shares.get_mut(share_arn).expect("checked above");
        share.updated = Some(now);
        for (arn, ty) in checked.resources {
            let a = upsert(&mut share.resources, &arn, now, |a| {
                a.status = "ASSOCIATED".into();
                a.resource_type = Some(ty.clone());
            });
            out.push(share.wire_association(&a, "RESOURCE"));
            if !share.permissions.iter().any(|p| p.resource_type == ty) {
                if let Some(m) = catalog::all().into_iter().find(|m| m.resource_type == ty && m.is_default) {
                    share.permissions.push(SharePermission {
                        arn: m.arn(&ctx.partition),
                        version: 1,
                        resource_type: ty.clone(),
                        updated: Some(now),
                    });
                }
            }
        }
        for (p, kind) in checked.principals {
            let external = externals.get(&p).copied().unwrap_or(false);
            let already = share
                .principals
                .iter()
                .any(|a| a.entity == p && matches!(a.status.as_str(), "ASSOCIATED" | "ASSOCIATING"));
            let a = upsert(&mut share.principals, &p, now, |a| {
                if !already {
                    a.status = if external { "ASSOCIATING" } else { "ASSOCIATED" }.into();
                    a.status_message = None;
                }
                a.external = external;
            });
            if external && !already {
                let receiver = kind.account().unwrap_or_default().to_string();
                invitations.push((receiver, matches!(kind, PrincipalKind::Iam { .. }).then(|| p.clone())));
            }
            out.push(share.wire_association(&a, "PRINCIPAL"));
        }
        for (s, ty) in checked.sources {
            let a = upsert(&mut share.sources, &s, now, |a| {
                a.status = "ASSOCIATED".into();
                a.source_type = Some(ty.into());
            });
            out.push(share.wire_association(&a, "SOURCE"));
        }
        let (name, arn) = (share.name.clone(), share.arn.clone());
        for (receiver, receiver_arn) in invitations {
            let id = uuid::Uuid::new_v4().to_string();
            let inv_arn = util::ram_arn(ctx, "resource-share-invitation", &id);
            st.invitations.insert(
                inv_arn.clone(),
                Invitation {
                    arn: inv_arn,
                    share_arn: arn.clone(),
                    share_name: name.clone(),
                    sender: owner.clone(),
                    receiver,
                    receiver_arn,
                    status: "PENDING".into(),
                    created: Some(now),
                },
            );
        }
        Ok(out)
    }

    /// Resolve the permissions a create call names, plus defaults.
    fn resolve_permissions(
        &self,
        st: &State,
        ctx: &RequestContext,
        arns: &[String],
    ) -> Result<Vec<SharePermission>, ServiceError> {
        let mut out: Vec<SharePermission> = Vec::new();
        for arn in arns {
            let (ty, version) = self.attachable_permission(st, ctx, arn, None)?;
            if out.iter().any(|p| p.resource_type == ty) {
                return Err(errors::invalid_parameter(format!(
                    "You can associate only one permission with each resource type, but you specified more than one for {ty}."
                )));
            }
            out.push(SharePermission { arn: arn.clone(), version, resource_type: ty, updated: Some(ctx.received_at) });
        }
        Ok(out)
    }

    pub(crate) fn create_resource_share(
        &self,
        ctx: &RequestContext,
        input: types::CreateResourceShareRequest,
    ) -> Result<types::CreateResourceShareResponse, ServiceError> {
        let resources = input.resource_arns.clone().unwrap_or_default();
        let principals = input.principals.clone().unwrap_or_default();
        let tags = input.tags.clone().unwrap_or_default();
        let allow_external = input.allow_external_principals.unwrap_or(true);
        let mut cond = util::request_tag_context(&tags);
        cond.insert("ram:RequestedAllowsExternalPrincipals".into(), vec![allow_external.to_string()]);
        if !resources.is_empty() {
            cond.insert("ram:ResourceArn".into(), resources.clone());
            let types: Vec<String> =
                resources.iter().filter_map(|r| self.type_for_arn(r)).map(|t| t.resource_type().to_string()).collect();
            cond.insert("ram:RequestedResourceType".into(), types);
        }
        if !principals.is_empty() {
            cond.insert("ram:Principal".into(), principals.clone());
        }
        ctx.authorize("ram:CreateResourceShare", "*", cond)?;
        if let Some(arn) = util::idempotent(&self.lock(), ctx, input.client_token.as_deref()) {
            let st = self.lock();
            let share = st.shares.get(&arn).ok_or_else(|| not_found(&arn))?;
            if share.name != input.name {
                return Err(errors::idempotent_parameter_mismatch(
                    "The client token was already used with different parameters.",
                ));
            }
            return Ok(types::CreateResourceShareResponse {
                resource_share: Some(share.wire()),
                client_token: input.client_token,
            });
        }
        if input.name.is_empty() {
            return Err(errors::invalid_parameter("The name of a resource share can't be empty."));
        }
        let checked =
            self.check_entities(ctx, &resources, &principals, input.sources.as_deref().unwrap_or_default())?;
        let now = ctx.received_at;
        let id = uuid::Uuid::new_v4().to_string();
        let arn = util::ram_arn(ctx, "resource-share", &id);
        let mut share = Share {
            arn: arn.clone(),
            name: input.name.clone(),
            owner: ctx.caller.account_id.clone(),
            region: ctx.region.clone(),
            allow_external,
            status: "ACTIVE".into(),
            feature_set: "STANDARD".into(),
            retain_on_leave: input
                .resource_share_configuration
                .as_ref()
                .and_then(|c| c.retain_sharing_on_account_leave_organization),
            created: Some(now),
            updated: Some(now),
            ..Default::default()
        };
        util::merge_tags(&mut share.tags, &tags)?;
        {
            let mut st = self.lock();
            share.permissions =
                self.resolve_permissions(&st, ctx, input.permission_arns.as_deref().unwrap_or_default())?;
            st.shares.insert(arn.clone(), share);
            util::remember_token(&mut st, ctx, input.client_token.as_deref(), &arn);
        }
        if let Err(e) = self.apply_associations(ctx, &arn, checked) {
            self.lock().shares.remove(&arn);
            return Err(e);
        }
        self.push_policies(&ctx.partition, self.share_resources(&arn));
        let st = self.lock();
        Ok(types::CreateResourceShareResponse {
            resource_share: st.shares.get(&arn).map(Share::wire),
            client_token: input.client_token,
        })
    }

    pub(crate) fn update_resource_share(
        &self,
        ctx: &RequestContext,
        input: types::UpdateResourceShareRequest,
    ) -> Result<types::UpdateResourceShareResponse, ServiceError> {
        let arn = &input.resource_share_arn;
        let mut cond = ConditionContext::new();
        if let Some(a) = input.allow_external_principals {
            cond.insert("ram:RequestedAllowsExternalPrincipals".into(), vec![a.to_string()]);
        }
        self.authorize_share(ctx, "UpdateResourceShare", arn, cond)?;
        let mut st = self.lock();
        self.owned_share(&st, ctx, arn)?;
        let share = st.shares.get_mut(arn).expect("checked above");
        if share.status != "ACTIVE" {
            return Err(errors::invalid_state_transition(format!(
                "The resource share {arn} is in the {} state.",
                share.status
            )));
        }
        if let Some(name) = input.name {
            share.name = name;
        }
        if let Some(a) = input.allow_external_principals {
            if !a && share.principals.iter().any(|p| p.external && p.status != "DISASSOCIATED") {
                return Err(errors::operation_not_permitted(
                    "The resource share has principals outside your organization; remove them before disallowing external principals.",
                ));
            }
            share.allow_external = a;
        }
        share.updated = Some(ctx.received_at);
        Ok(types::UpdateResourceShareResponse { resource_share: Some(share.wire()), client_token: input.client_token })
    }

    pub(crate) fn delete_resource_share(
        &self,
        ctx: &RequestContext,
        input: types::DeleteResourceShareRequest,
    ) -> Result<types::DeleteResourceShareResponse, ServiceError> {
        let arn = &input.resource_share_arn;
        self.authorize_share(ctx, "DeleteResourceShare", arn, ConditionContext::new())?;
        let resources = {
            let mut st = self.lock();
            self.owned_share(&st, ctx, arn)?;
            let now = ctx.received_at;
            let share = st.shares.get_mut(arn).expect("checked above");
            if share.status == "DELETED" {
                return Err(errors::operation_not_permitted(format!("The resource share {arn} is already deleted.")));
            }
            share.status = "DELETED".into();
            share.updated = Some(now);
            for a in share.resources.iter_mut().chain(share.principals.iter_mut()).chain(share.sources.iter_mut()) {
                a.status = "DISASSOCIATED".into();
                a.updated = now;
            }
            let resources: Vec<String> = share.resources.iter().map(|r| r.entity.clone()).collect();
            for inv in st.invitations.values_mut().filter(|i| &i.share_arn == arn && i.status == "PENDING") {
                inv.status = "EXPIRED".into();
            }
            resources
        };
        self.push_policies(&ctx.partition, resources);
        Ok(types::DeleteResourceShareResponse { return_value: Some(true), client_token: input.client_token })
    }

    pub(crate) fn associate_resource_share(
        &self,
        ctx: &RequestContext,
        input: types::AssociateResourceShareRequest,
    ) -> Result<types::AssociateResourceShareResponse, ServiceError> {
        let arn = &input.resource_share_arn;
        let resources = input.resource_arns.unwrap_or_default();
        let principals = input.principals.unwrap_or_default();
        let sources = input.sources.unwrap_or_default();
        if resources.is_empty() && principals.is_empty() && sources.is_empty() {
            return Err(errors::missing_required_parameter(
                "You must specify at least one resource ARN, principal or source.",
            ));
        }
        let mut cond = ConditionContext::new();
        if !resources.is_empty() {
            cond.insert("ram:ResourceArn".into(), resources.clone());
        }
        if !principals.is_empty() {
            cond.insert("ram:Principal".into(), principals.clone());
        }
        self.authorize_share(ctx, "AssociateResourceShare", arn, cond)?;
        let feature_set = {
            let st = self.lock();
            self.owned_share(&st, ctx, arn)?.feature_set.clone()
        };
        if feature_set != "STANDARD" {
            return Err(errors::operation_not_permitted(format!(
                "The resource share {arn} was created from a resource policy. Promote it to a standard resource share first."
            )));
        }
        let checked = self.check_entities(ctx, &resources, &principals, &sources)?;
        let out = self.apply_associations(ctx, arn, checked)?;
        self.push_policies(&ctx.partition, self.share_resources(arn));
        Ok(types::AssociateResourceShareResponse {
            resource_share_associations: Some(out),
            client_token: input.client_token,
        })
    }

    pub(crate) fn disassociate_resource_share(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateResourceShareRequest,
    ) -> Result<types::DisassociateResourceShareResponse, ServiceError> {
        let arn = &input.resource_share_arn;
        let resources = input.resource_arns.unwrap_or_default();
        let principals = input.principals.unwrap_or_default();
        let sources = input.sources.unwrap_or_default();
        if resources.is_empty() && principals.is_empty() && sources.is_empty() {
            return Err(errors::missing_required_parameter(
                "You must specify at least one resource ARN, principal or source.",
            ));
        }
        let mut cond = ConditionContext::new();
        if !resources.is_empty() {
            cond.insert("ram:ResourceArn".into(), resources.clone());
        }
        if !principals.is_empty() {
            cond.insert("ram:Principal".into(), principals.clone());
        }
        self.authorize_share(ctx, "DisassociateResourceShare", arn, cond)?;
        let now = ctx.received_at;
        let mut out = Vec::new();
        let touched = {
            let mut st = self.lock();
            self.owned_share(&st, ctx, arn)?;
            let share = st.shares.get_mut(arn).expect("checked above");
            let mut pending = Vec::new();
            for (list, wanted, ty) in [
                (&mut share.resources, &resources, "RESOURCE"),
                (&mut share.principals, &principals, "PRINCIPAL"),
                (&mut share.sources, &sources, "SOURCE"),
            ] {
                for w in wanted {
                    let Some(a) = list.iter_mut().find(|a| &a.entity == w && a.status != "DISASSOCIATED") else {
                        return Err(errors::unknown_resource(format!(
                            "{w} is not associated with the resource share {arn}."
                        )));
                    };
                    a.status = "DISASSOCIATED".into();
                    a.updated = now;
                    pending.push((a.clone(), ty));
                }
            }
            share.updated = Some(now);
            for (a, ty) in &pending {
                out.push(share.wire_association(a, ty));
            }
            let touched: Vec<String> = share.resources.iter().map(|r| r.entity.clone()).collect();
            for inv in st.invitations.values_mut() {
                if &inv.share_arn == arn
                    && inv.status == "PENDING"
                    && principals.iter().any(|p| p == &inv.receiver || inv.receiver_arn.as_ref() == Some(p))
                {
                    inv.status = "EXPIRED".into();
                }
            }
            touched
        };
        self.push_policies(&ctx.partition, touched);
        Ok(types::DisassociateResourceShareResponse {
            resource_share_associations: Some(out),
            client_token: input.client_token,
        })
    }

    /// Whether `account` can see `share` as a recipient (it is an
    /// associated principal, or in an organization or OU that is).
    pub(crate) fn shared_with(&self, share: &Share, account: &str) -> bool {
        share.owner != account
            && share.status == "ACTIVE"
            && share
                .principals
                .iter()
                .any(|p| p.status == "ASSOCIATED" && self.covers(&p.entity, &share.owner, account))
    }

    /// Shares visible as `resource_owner` (`SELF` or `OTHER-ACCOUNTS`).
    fn visible_shares(
        &self,
        st: &State,
        ctx: &RequestContext,
        resource_owner: &str,
    ) -> Result<Vec<Share>, ServiceError> {
        let account = ctx.caller.account_id.as_str();
        Ok(match resource_owner {
            "SELF" => st.shares.values().filter(|s| s.owner == account && s.region == ctx.region).cloned().collect(),
            "OTHER-ACCOUNTS" => {
                st.shares.values().filter(|s| s.region == ctx.region && self.shared_with(s, account)).cloned().collect()
            }
            other => return Err(errors::invalid_parameter(format!("The resourceOwner {other} is not valid."))),
        })
    }

    pub(crate) fn get_resource_shares(
        &self,
        ctx: &RequestContext,
        input: types::GetResourceSharesRequest,
    ) -> Result<types::GetResourceSharesResponse, ServiceError> {
        ctx.authorize("ram:GetResourceShares", "*", ConditionContext::new())?;
        let st = self.lock();
        let mut shares = self.visible_shares(&st, ctx, &input.resource_owner)?;
        if let Some(arns) = &input.resource_share_arns {
            shares.retain(|s| arns.contains(&s.arn));
        }
        if let Some(status) = &input.resource_share_status {
            shares.retain(|s| &s.status == status);
        }
        if let Some(name) = &input.name {
            shares.retain(|s| &s.name == name);
        }
        for f in input.tag_filters.iter().flatten() {
            let key = f.tag_key.clone().unwrap_or_default();
            shares.retain(|s| match (s.tags.get(&key), &f.tag_values) {
                (Some(v), Some(values)) if !values.is_empty() => values.contains(v),
                (Some(_), _) => true,
                (None, _) => false,
            });
        }
        if let Some(p) = &input.permission_arn {
            shares.retain(|s| {
                s.permissions
                    .iter()
                    .any(|x| &x.arn == p && input.permission_version.is_none_or(|v| x.version as i32 == v))
            });
        }
        let (page, next) = paginate(shares, input.max_results, input.next_token.as_deref())?;
        Ok(types::GetResourceSharesResponse {
            resource_shares: Some(page.iter().map(Share::wire).collect()),
            next_token: next,
        })
    }

    pub(crate) fn get_resource_share_associations(
        &self,
        ctx: &RequestContext,
        input: types::GetResourceShareAssociationsRequest,
    ) -> Result<types::GetResourceShareAssociationsResponse, ServiceError> {
        ctx.authorize("ram:GetResourceShareAssociations", "*", ConditionContext::new())?;
        let ty = input.association_type.as_str();
        if ty == "PRINCIPAL" && input.resource_arn.is_some() {
            return Err(errors::invalid_parameter("You can't specify resourceArn with associationType PRINCIPAL."));
        }
        if ty == "RESOURCE" && input.principal.is_some() {
            return Err(errors::invalid_parameter("You can't specify principal with associationType RESOURCE."));
        }
        let st = self.lock();
        let account = ctx.caller.account_id.as_str();
        let mut out = Vec::new();
        for share in st.shares.values().filter(|s| s.region == ctx.region) {
            if input.resource_share_arns.as_ref().is_some_and(|a| !a.contains(&share.arn)) {
                continue;
            }
            let owned = share.owner == account;
            let list = match ty {
                "RESOURCE" => &share.resources,
                "PRINCIPAL" => &share.principals,
                _ => &share.sources,
            };
            for a in list {
                // Recipients see the associations that name them.
                if !owned && !(ty == "PRINCIPAL" && self.covers(&a.entity, &share.owner, account)) {
                    continue;
                }
                if input.resource_arn.as_ref().is_some_and(|r| r != &a.entity)
                    || input.principal.as_ref().is_some_and(|p| p != &a.entity)
                    || input.association_status.as_ref().is_some_and(|s| s != &a.status)
                {
                    continue;
                }
                out.push(share.wire_association(a, ty));
            }
        }
        let (page, next) = paginate(out, input.max_results, input.next_token.as_deref())?;
        Ok(types::GetResourceShareAssociationsResponse { resource_share_associations: Some(page), next_token: next })
    }

    pub(crate) fn list_resources(
        &self,
        ctx: &RequestContext,
        input: types::ListResourcesRequest,
    ) -> Result<types::ListResourcesResponse, ServiceError> {
        ctx.authorize("ram:ListResources", "*", ConditionContext::new())?;
        if let Some(t) = &input.resource_type {
            if self.type_named(t).is_none() {
                return Err(errors::invalid_resource_type(format!("The resource type {t} is not valid.")));
            }
        }
        let st = self.lock();
        let shares = self.visible_shares(&st, ctx, &input.resource_owner)?;
        let mut out = Vec::new();
        for share in &shares {
            if share.status != "ACTIVE" || input.resource_share_arns.as_ref().is_some_and(|a| !a.contains(&share.arn)) {
                continue;
            }
            if let Some(p) = &input.principal {
                if !share.principals.iter().any(|a| &a.entity == p && a.status == "ASSOCIATED") {
                    continue;
                }
            }
            for r in share.resources.iter().filter(|r| r.status == "ASSOCIATED") {
                if input.resource_arns.as_ref().is_some_and(|a| !a.contains(&r.entity))
                    || input
                        .resource_type
                        .as_ref()
                        .is_some_and(|t| !r.resource_type.as_deref().unwrap_or_default().eq_ignore_ascii_case(t))
                {
                    continue;
                }
                out.push(wire_resource(share, r));
            }
        }
        let (page, next) = paginate(out, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListResourcesResponse { resources: Some(page), next_token: next })
    }

    pub(crate) fn list_principals(
        &self,
        ctx: &RequestContext,
        input: types::ListPrincipalsRequest,
    ) -> Result<types::ListPrincipalsResponse, ServiceError> {
        ctx.authorize("ram:ListPrincipals", "*", ConditionContext::new())?;
        let st = self.lock();
        let shares = self.visible_shares(&st, ctx, &input.resource_owner)?;
        let other = input.resource_owner == "OTHER-ACCOUNTS";
        let mut out = Vec::new();
        for share in &shares {
            if share.status != "ACTIVE" || input.resource_share_arns.as_ref().is_some_and(|a| !a.contains(&share.arn)) {
                continue;
            }
            let resources: Vec<&Association> = share.resources.iter().filter(|r| r.status == "ASSOCIATED").collect();
            if let Some(r) = &input.resource_arn {
                if !resources.iter().any(|a| &a.entity == r) {
                    continue;
                }
            }
            if let Some(t) = &input.resource_type {
                if !resources.iter().any(|a| a.resource_type.as_deref().unwrap_or_default().eq_ignore_ascii_case(t)) {
                    continue;
                }
            }
            if other {
                // The accounts that share with the caller.
                out.push(types::Principal {
                    id: Some(share.owner.clone()),
                    resource_share_arn: Some(share.arn.clone()),
                    creation_time: share.created,
                    last_updated_time: share.updated,
                    external: Some(!self.internal(&share.owner, &ctx.caller.account_id)),
                });
                continue;
            }
            for p in share.principals.iter().filter(|p| p.status == "ASSOCIATED") {
                if input.principals.as_ref().is_some_and(|w| !w.contains(&p.entity)) {
                    continue;
                }
                out.push(types::Principal {
                    id: Some(p.entity.clone()),
                    resource_share_arn: Some(share.arn.clone()),
                    creation_time: Some(p.created),
                    last_updated_time: Some(p.updated),
                    external: Some(p.external),
                });
            }
        }
        let (page, next) = paginate(out, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListPrincipalsResponse { principals: Some(page), next_token: next })
    }

    pub(crate) fn list_source_associations(
        &self,
        ctx: &RequestContext,
        input: types::ListSourceAssociationsRequest,
    ) -> Result<types::ListSourceAssociationsResponse, ServiceError> {
        ctx.authorize("ram:ListSourceAssociations", "*", ConditionContext::new())?;
        let st = self.lock();
        let mut out = Vec::new();
        for share in st.shares.values().filter(|s| s.owner == ctx.caller.account_id && s.region == ctx.region) {
            if input.resource_share_arns.as_ref().is_some_and(|a| !a.contains(&share.arn)) {
                continue;
            }
            for s in &share.sources {
                if input.source_id.as_ref().is_some_and(|x| x != &s.entity)
                    || input.source_type.as_ref().is_some_and(|x| Some(x) != s.source_type.as_ref())
                    || input.association_status.as_ref().is_some_and(|x| x != &s.status)
                {
                    continue;
                }
                out.push(types::AssociatedSource {
                    resource_share_arn: Some(share.arn.clone()),
                    source_id: Some(s.entity.clone()),
                    source_type: s.source_type.clone(),
                    status: Some(s.status.clone()),
                    last_updated_time: Some(s.updated),
                    creation_time: Some(s.created),
                    status_message: s.status_message.clone(),
                });
            }
        }
        let (page, next) = paginate(out, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListSourceAssociationsResponse { source_associations: Some(page), next_token: next })
    }

    pub(crate) fn list_resource_types(
        &self,
        ctx: &RequestContext,
        input: types::ListResourceTypesRequest,
    ) -> Result<types::ListResourceTypesResponse, ServiceError> {
        ctx.authorize("ram:ListResourceTypes", "*", ConditionContext::new())?;
        let scope = input.resource_region_scope.as_deref().unwrap_or("ALL");
        let mut out: Vec<types::ServiceNameAndResourceType> = self
            .resource_types()
            .iter()
            .filter(|_| scope != "GLOBAL")
            .map(|t| types::ServiceNameAndResourceType {
                resource_type: Some(t.resource_type().to_string()),
                service_name: Some(t.service_name().to_string()),
                resource_region_scope: Some("REGIONAL".into()),
            })
            .collect();
        out.sort_by(|a, b| a.resource_type.cmp(&b.resource_type));
        let (page, next) = paginate(out, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListResourceTypesResponse { resource_types: Some(page), next_token: next })
    }

    pub(crate) fn get_resource_policies(
        &self,
        ctx: &RequestContext,
        input: types::GetResourcePoliciesRequest,
    ) -> Result<types::GetResourcePoliciesResponse, ServiceError> {
        ctx.authorize("ram:GetResourcePolicies", "*", ConditionContext::new())?;
        for arn in &input.resource_arns {
            util::check_arn(arn)?;
            let owned = self
                .type_for_arn(arn)
                .and_then(|t| t.locate(arn))
                .is_some_and(|l| l.owner_account == ctx.caller.account_id && l.region == ctx.region);
            if !owned {
                return Err(errors::resource_arn_not_found(format!("The resource ARN {arn} was not found.")));
            }
        }
        let st = self.lock();
        let mut out = Vec::new();
        for arn in &input.resource_arns {
            if let Some(p) = &input.principal {
                let shared = st.shares.values().any(|s| {
                    s.status == "ACTIVE"
                        && s.resources.iter().any(|r| &r.entity == arn && r.status == "ASSOCIATED")
                        && s.principals.iter().any(|x| &x.entity == p && x.status == "ASSOCIATED")
                });
                if !shared {
                    continue;
                }
            }
            if let Some(policy) = self.policy_for(&st, &ctx.partition, arn) {
                out.push(policy);
            }
        }
        let (page, next) = paginate(out, input.max_results, input.next_token.as_deref())?;
        Ok(types::GetResourcePoliciesResponse { policies: Some(page), next_token: next })
    }

    pub(crate) fn enable_sharing_with_aws_organization(
        &self,
        ctx: &RequestContext,
    ) -> Result<types::EnableSharingWithAwsOrganizationResponse, ServiceError> {
        ctx.authorize("ram:EnableSharingWithAwsOrganization", "*", ConditionContext::new())?;
        let account = ctx.caller.account_id.as_str();
        let org = self.org_of(account).ok_or_else(|| {
            errors::operation_not_permitted("Your account isn't a member of an organization in AWS Organizations.")
        })?;
        if !org.is_management(account) {
            return Err(errors::operation_not_permitted(
                "Only the management account of an organization can enable sharing with AWS Organizations.",
            ));
        }
        // As in AWS: RAM turns on its trusted access in Organizations (which
        // the caller must be allowed to do) and creates its service-linked
        // role.
        self.organizations.enable_service_access_for(ctx, RAM_SERVICE_PRINCIPAL)?;
        self.iam.ensure_service_linked_role(
            account,
            RAM_SERVICE_PRINCIPAL,
            "AWSResourceAccessManagerServiceRolePolicy",
        );
        Ok(types::EnableSharingWithAwsOrganizationResponse { return_value: Some(true) })
    }

    pub(crate) fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<(), ServiceError> {
        let arn = target_arn(input.resource_share_arn.as_deref(), input.resource_arn.as_deref())?;
        let mut cond = util::request_tag_context(&input.tags);
        cond.extend(self.target_tags(&arn).map(|t| util::resource_tag_context(&t)).unwrap_or_default());
        ctx.authorize("ram:TagResource", &arn, cond)?;
        let mut st = self.lock();
        let tags = self.owned_tags(&mut st, ctx, &arn)?;
        let mut merged = tags.clone();
        util::merge_tags(&mut merged, &input.tags)?;
        *tags = merged;
        Ok(())
    }

    pub(crate) fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<(), ServiceError> {
        let arn = target_arn(input.resource_share_arn.as_deref(), input.resource_arn.as_deref())?;
        let mut cond = ConditionContext::new();
        cond.insert("aws:TagKeys".into(), input.tag_keys.clone());
        cond.extend(self.target_tags(&arn).map(|t| util::resource_tag_context(&t)).unwrap_or_default());
        ctx.authorize("ram:UntagResource", &arn, cond)?;
        let mut st = self.lock();
        let tags = self.owned_tags(&mut st, ctx, &arn)?;
        for k in &input.tag_keys {
            tags.remove(k);
        }
        Ok(())
    }

    fn target_tags(&self, arn: &str) -> Option<BTreeMap<String, String>> {
        let st = self.lock();
        st.shares.get(arn).map(|s| s.tags.clone()).or_else(|| st.permissions.get(arn).map(|p| p.tags.clone()))
    }

    fn owned_tags<'s>(
        &self,
        st: &'s mut State,
        ctx: &RequestContext,
        arn: &str,
    ) -> Result<&'s mut BTreeMap<String, String>, ServiceError> {
        let account = ctx.caller.account_id.as_str();
        if st.shares.get(arn).is_some_and(|s| s.owner == account && s.region == ctx.region) {
            return Ok(&mut st.shares.get_mut(arn).expect("checked").tags);
        }
        if st.permissions.get(arn).is_some_and(|p| p.owner == account && p.status != "DELETED") {
            return Ok(&mut st.permissions.get_mut(arn).expect("checked").tags);
        }
        Err(errors::unknown_resource(format!("The resource {arn} could not be found.")))
    }

    pub(crate) fn promote_resource_share_created_from_policy(
        &self,
        ctx: &RequestContext,
        input: types::PromoteResourceShareCreatedFromPolicyRequest,
    ) -> Result<types::PromoteResourceShareCreatedFromPolicyResponse, ServiceError> {
        let arn = &input.resource_share_arn;
        self.authorize_share(ctx, "PromoteResourceShareCreatedFromPolicy", arn, ConditionContext::new())?;
        let resources = {
            let mut st = self.lock();
            let share = self.owned_share(&st, ctx, arn)?.clone();
            if share.feature_set != "CREATED_FROM_POLICY" {
                return Err(errors::operation_not_permitted(format!(
                    "The resource share {arn} wasn't created from a resource policy."
                )));
            }
            // Each permission made from the policy must have a promoted,
            // standard twin (same template) to take its place.
            let mut replaced = Vec::new();
            for perm in &share.permissions {
                let Some(p) = st.permissions.get(&perm.arn) else {
                    replaced.push(perm.clone());
                    continue;
                };
                if p.feature_set == "STANDARD" {
                    replaced.push(perm.clone());
                    continue;
                }
                let template = p.versions.get(&perm.version).map(|v| v.template.clone()).unwrap_or_default();
                let twin = st.permissions.values().find(|q| {
                    q.owner == share.owner
                        && q.feature_set == "STANDARD"
                        && q.status == "ATTACHABLE"
                        && q.resource_type == p.resource_type
                        && q.versions.get(&q.default_version).is_some_and(|v| same_template(&v.template, &template))
                });
                let Some(twin) = twin else {
                    return Err(errors::unmatched_policy_permission(format!(
                        "There isn't a standard managed permission with the same permissions as {}. Promote it with PromotePermissionCreatedFromPolicy first.",
                        perm.arn
                    )));
                };
                replaced.push(SharePermission {
                    arn: twin.arn.clone(),
                    version: twin.default_version,
                    resource_type: twin.resource_type.clone(),
                    updated: Some(ctx.received_at),
                });
            }
            let s = st.shares.get_mut(arn).expect("checked above");
            s.permissions = replaced;
            s.feature_set = "STANDARD".into();
            s.from_policy_of = None;
            s.updated = Some(ctx.received_at);
            s.resources.iter().map(|r| r.entity.clone()).collect::<Vec<_>>()
        };
        self.push_policies(&ctx.partition, resources);
        Ok(types::PromoteResourceShareCreatedFromPolicyResponse { return_value: Some(true) })
    }

    /// A resource's own policy changed (`PutPolicy` / `DeletePolicy`): keep
    /// the share created from it in step.
    pub fn resource_policy_changed(&self, resource_arn: &str, owner: &str, policy: Option<&str>, now: DateTime<Utc>) {
        let Some(ty) = self.type_for_arn(resource_arn) else { return };
        let partition = resource_arn.split(':').nth(1).unwrap_or("aws").to_string();
        let region = util::arn_region_account(resource_arn).map(|(r, _)| r.to_string()).unwrap_or_default();
        let mut st = self.lock();
        let existing = st
            .shares
            .values()
            .find(|s| s.from_policy_of.as_deref() == Some(resource_arn) && s.status == "ACTIVE")
            .map(|s| s.arn.clone());
        let Some(policy) = policy else {
            if let Some(arn) = existing {
                let share = st.shares.get_mut(&arn).expect("found above");
                share.status = "DELETED".into();
                share.updated = Some(now);
                for a in share.resources.iter_mut().chain(share.principals.iter_mut()) {
                    a.status = "DISASSOCIATED".into();
                    a.updated = now;
                }
                let perms: Vec<String> = share.permissions.iter().map(|p| p.arn.clone()).collect();
                for p in perms {
                    if let Some(p) = st.permissions.get_mut(&p).filter(|p| p.feature_set == "CREATED_FROM_POLICY") {
                        p.status = "DELETED".into();
                    }
                }
            }
            return;
        };
        let statements = crate::policies::template_statements(policy);
        let mut principals = Vec::new();
        let mut template = Vec::new();
        for s in &statements {
            for p in policy_principals(s, &partition) {
                if !principals.contains(&p) {
                    principals.push(p);
                }
            }
            let mut t = serde_json::Map::new();
            for k in ["Effect", "Action", "Condition"] {
                if let Some(v) = s.get(k) {
                    t.insert(k.into(), v.clone());
                }
            }
            template.push(serde_json::Value::Object(t));
        }
        let template = if template.len() == 1 {
            template.remove(0).to_string()
        } else {
            serde_json::json!({ "Statement": template }).to_string()
        };
        let id = resource_arn.rsplit('/').next().unwrap_or_default().to_string();
        let perm_arn = format!("arn:{partition}:ram:{region}:{owner}:permission/ResourcePolicy-{id}");
        let perm = st.permissions.entry(perm_arn.clone()).or_insert_with(|| crate::state::Permission {
            arn: perm_arn.clone(),
            name: format!("ResourcePolicy-{id}"),
            owner: owner.to_string(),
            region: region.clone(),
            resource_type: ty.resource_type().to_string(),
            feature_set: "CREATED_FROM_POLICY".into(),
            status: "ATTACHABLE".into(),
            default_version: 1,
            created: Some(now),
            ..Default::default()
        });
        perm.status = "ATTACHABLE".into();
        perm.feature_set = "CREATED_FROM_POLICY".into();
        perm.updated = Some(now);
        perm.versions.insert(
            1,
            crate::state::PermissionVersion {
                template,
                created: Some(now),
                updated: Some(now),
                status: "ATTACHABLE".into(),
            },
        );
        let share_arn = existing.unwrap_or_else(|| {
            let arn = format!("arn:{partition}:ram:{region}:{owner}:resource-share/{}", uuid::Uuid::new_v4());
            st.shares.insert(
                arn.clone(),
                Share {
                    arn: arn.clone(),
                    name: format!("LinkedResourceShare-{id}"),
                    owner: owner.to_string(),
                    region: region.clone(),
                    allow_external: true,
                    status: "ACTIVE".into(),
                    feature_set: "CREATED_FROM_POLICY".into(),
                    created: Some(now),
                    from_policy_of: Some(resource_arn.to_string()),
                    ..Default::default()
                },
            );
            arn
        });
        let share = st.shares.get_mut(&share_arn).expect("inserted above");
        share.updated = Some(now);
        share.resources = vec![Association {
            entity: resource_arn.to_string(),
            created: now,
            updated: now,
            resource_type: Some(ty.resource_type().to_string()),
            ..Default::default()
        }];
        share.principals = principals
            .into_iter()
            .map(|p| Association { entity: p, created: now, updated: now, ..Default::default() })
            .collect();
        share.permissions = vec![SharePermission {
            arn: perm_arn,
            version: 1,
            resource_type: ty.resource_type().to_string(),
            updated: Some(now),
        }];
    }
}

/// Principals a policy statement names, as RAM principal ids.
fn policy_principals(s: &serde_json::Value, partition: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(p) = s.get("Principal") else { return out };
    let values = |v: Option<&serde_json::Value>| -> Vec<String> {
        match v {
            Some(serde_json::Value::String(x)) => vec![x.clone()],
            Some(serde_json::Value::Array(a)) => a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect(),
            _ => Vec::new(),
        }
    };
    for a in values(p.get("AWS")) {
        let root = format!("arn:{partition}:iam::");
        match a.strip_prefix(&root).and_then(|r| r.strip_suffix(":root")) {
            Some(account) => out.push(account.to_string()),
            None => out.push(a),
        }
    }
    out.extend(values(p.get("Service")));
    out
}

fn same_template(a: &str, b: &str) -> bool {
    let norm = |t: &str| crate::policies::template_statements(t);
    norm(a) == norm(b)
}

fn target_arn(share: Option<&str>, resource: Option<&str>) -> Result<String, ServiceError> {
    match (share, resource) {
        (Some(s), None) => Ok(s.to_string()),
        (None, Some(r)) => Ok(r.to_string()),
        (Some(_), Some(_)) => {
            Err(errors::invalid_parameter("Specify either resourceShareArn or resourceArn, not both."))
        }
        (None, None) => Err(errors::missing_required_parameter("You must specify resourceShareArn or resourceArn.")),
    }
}

pub fn wire_resource(share: &Share, r: &Association) -> types::Resource {
    types::Resource {
        arn: Some(r.entity.clone()),
        r#type: r.resource_type.clone(),
        resource_share_arn: Some(share.arn.clone()),
        resource_group_arn: None,
        status: Some("AVAILABLE".into()),
        status_message: None,
        creation_time: Some(r.created),
        last_updated_time: Some(r.updated),
        resource_region_scope: Some("REGIONAL".into()),
    }
}

/// Find or add the association for `entity`, then let `f` update it.
fn upsert(
    list: &mut Vec<Association>,
    entity: &str,
    now: DateTime<Utc>,
    f: impl FnOnce(&mut Association),
) -> Association {
    let idx = match list.iter().position(|a| a.entity == entity) {
        Some(i) => i,
        None => {
            list.push(Association { entity: entity.to_string(), created: now, ..Default::default() });
            list.len() - 1
        }
    };
    let a = &mut list[idx];
    a.updated = now;
    f(a);
    a.clone()
}

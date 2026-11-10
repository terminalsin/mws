//! Instances, their Regions, attribute-based access control settings and
//! tags.

use chrono::{DateTime, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::common::*;
use crate::generated::{errors, types};
use crate::state::{Instance, InstanceKind, Tags};
use crate::SsoAdmin;

fn region_metadata(name: &str, added: DateTime<Utc>, primary: bool) -> types::RegionMetadata {
    types::RegionMetadata {
        region_name: Some(name.to_string()),
        status: Some("ACTIVE".into()),
        added_date: Some(added),
        is_primary_region: primary,
    }
}

fn regions_of(i: &Instance) -> Vec<types::RegionMetadata> {
    let mut out = vec![region_metadata(&i.primary_region, i.created, true)];
    out.extend(i.regions.iter().map(|(r, at)| region_metadata(r, *at, false)));
    out
}

fn metadata(i: &Instance) -> types::InstanceMetadata {
    types::InstanceMetadata {
        instance_arn: Some(i.arn.clone()),
        identity_store_id: Some(i.identity_store_id.clone()),
        identity_store_arn: None,
        owner_account_id: Some(i.owner.clone()),
        name: i.name.clone(),
        created_date: Some(i.created),
        status: Some("ACTIVE".into()),
        status_reason: None,
        primary_region: Some(i.primary_region.clone()),
        regions: Some(regions_of(i)),
    }
}

fn check_access_control(c: &types::InstanceAccessControlAttributeConfiguration) -> Result<(), ServiceError> {
    if c.access_control_attributes.len() > 50 {
        return Err(errors::validation("You can configure up to 50 attributes for access control."));
    }
    let mut seen = std::collections::BTreeSet::new();
    for a in &c.access_control_attributes {
        if !seen.insert(a.key.to_ascii_lowercase()) {
            return Err(errors::validation(format!("Duplicate attribute key {}.", a.key)));
        }
        if a.value.source.len() != 1 {
            return Err(errors::validation("Each attribute must have exactly one source."));
        }
    }
    Ok(())
}

impl SsoAdmin {
    pub(crate) fn create_instance(
        &self,
        ctx: &RequestContext,
        input: types::CreateInstanceRequest,
    ) -> Result<types::CreateInstanceResponse, ServiceError> {
        let tags = tags_from(input.tags)?;
        ctx.authorize("sso:CreateInstance", "*", request_tag_context(&tags))?;
        let account = ctx.caller.account_id.clone();
        let org = self.iam.organization_of(&account);
        // AWS enables the organization instance from the console in the
        // management account; MWS lets CreateInstance do it there, as there is
        // no API for it.
        let kind = match &org {
            Some(o) if o.is_management(&account) => InstanceKind::Organization,
            _ => InstanceKind::Account,
        };
        if self.lock().instances.values().any(|i| i.owner == account) {
            return Err(errors::conflict(
                "An IAM Identity Center instance already exists in this account. You can create only one instance per account.",
            ));
        }
        let identity_store_id = self.identity.create_store(&account, &ctx.region);
        let id = format!("ssoins-{}", hex(16));
        let arn = format!("arn:{}:sso:::instance/{id}", ctx.partition);
        if kind == InstanceKind::Organization {
            self.organizations.enable_trusted_access(&account, SERVICE_PRINCIPAL, ctx.received_at);
        }
        self.iam.ensure_service_linked_role(&account, SERVICE_PRINCIPAL, "AWSSSOServiceRolePolicy");
        let inst = Instance {
            arn: arn.clone(),
            id,
            kind,
            name: input.name,
            owner: account,
            identity_store_id,
            created: ctx.received_at,
            primary_region: ctx.region.clone(),
            tags,
            permission_sets_enabled: kind == InstanceKind::Organization,
            ..Default::default()
        };
        self.lock().instances.insert(arn.clone(), inst);
        Ok(types::CreateInstanceResponse { instance_arn: Some(arn) })
    }

    pub(crate) fn describe_instance(
        &self,
        ctx: &RequestContext,
        input: types::DescribeInstanceRequest,
    ) -> Result<types::DescribeInstanceResponse, ServiceError> {
        let r = self.instance(ctx, &input.instance_arn, "sso:DescribeInstance", None)?;
        let store_arn = self.identity.store(&r.identity_store_id).map(|s| s.arn);
        self.with_instance(&r.arn, |i| {
            let enc = i
                .encryption
                .clone()
                .unwrap_or(types::EncryptionConfiguration { key_type: "AWS_OWNED_KMS_KEY".into(), kms_key_arn: None });
            Ok(types::DescribeInstanceResponse {
                instance_arn: Some(i.arn.clone()),
                identity_store_id: Some(i.identity_store_id.clone()),
                identity_store_arn: store_arn,
                owner_account_id: Some(i.owner.clone()),
                name: i.name.clone(),
                created_date: Some(i.created),
                status: Some("ACTIVE".into()),
                status_reason: None,
                primary_region: Some(i.primary_region.clone()),
                regions: Some(regions_of(i)),
                encryption_configuration_details: Some(types::EncryptionConfigurationDetails {
                    key_type: Some(enc.key_type),
                    kms_key_arn: enc.kms_key_arn,
                    encryption_status: Some("ENABLED".into()),
                    encryption_status_reason: None,
                }),
                permission_sets_enabled: Some(i.permission_sets_enabled),
            })
        })
    }

    pub(crate) fn list_instances(
        &self,
        ctx: &RequestContext,
        input: types::ListInstancesRequest,
    ) -> Result<types::ListInstancesResponse, ServiceError> {
        ctx.authorize("sso:ListInstances", "*", ConditionContext::new())?;
        let all: Vec<Instance> = self.lock().instances.values().cloned().collect();
        let visible: Vec<types::InstanceMetadata> = all
            .iter()
            .filter(|i| self.manages(&ctx.caller.account_id, i).is_some())
            .map(|i| {
                let mut m = metadata(i);
                m.identity_store_arn = self.identity.store(&i.identity_store_id).map(|s| s.arn);
                m
            })
            .collect();
        let (page, next_token) = paginate(visible, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListInstancesResponse { instances: Some(page), next_token })
    }

    pub(crate) fn update_instance(
        &self,
        ctx: &RequestContext,
        input: types::UpdateInstanceRequest,
    ) -> Result<types::UpdateInstanceResponse, ServiceError> {
        let r = self.instance(ctx, &input.instance_arn, "sso:UpdateInstance", None)?;
        if input.encryption_configuration.is_some() && input.permission_sets_enabled.is_some() {
            return Err(errors::validation(
                "You can update either EncryptionConfiguration or PermissionSetsEnabled in a single request, not both.",
            ));
        }
        if let Some(e) = &input.encryption_configuration {
            match (e.key_type.as_str(), &e.kms_key_arn) {
                ("CUSTOMER_MANAGED_KEY", None) => {
                    return Err(errors::validation("KmsKeyArn is required when KeyType is CUSTOMER_MANAGED_KEY."))
                }
                ("AWS_OWNED_KMS_KEY", Some(_)) => {
                    return Err(errors::validation("KmsKeyArn must not be set when KeyType is AWS_OWNED_KMS_KEY."))
                }
                _ => {}
            }
        }
        if let Some(key) = input.encryption_configuration.as_ref().and_then(|e| e.kms_key_arn.as_deref()) {
            self.check_kms_key(&r, key)?;
        }
        self.with_instance(&r.arn, |i| {
            if let Some(n) = input.name {
                i.name = Some(n);
            }
            if let Some(e) = input.encryption_configuration {
                i.encryption = Some(e);
            }
            if let Some(p) = input.permission_sets_enabled {
                if !p && i.kind == InstanceKind::Organization {
                    return Err(errors::validation("Permission sets can't be disabled for an organization instance."));
                }
                i.permission_sets_enabled = p;
            }
            Ok(types::UpdateInstanceResponse {})
        })
    }

    pub(crate) fn delete_instance(
        &self,
        ctx: &RequestContext,
        input: types::DeleteInstanceRequest,
    ) -> Result<types::DeleteInstanceResponse, ServiceError> {
        let r = self.instance(ctx, &input.instance_arn, "sso:DeleteInstance", None)?;
        if r.delegated {
            return Err(errors::access_denied("Only the account that owns the instance can delete it."));
        }
        let Some(inst) = self.lock().instances.remove(&r.arn) else {
            return Err(instance_not_found(&r.arn));
        };
        for ((_, account), p) in &inst.provisioned {
            self.iam.delete_reserved_role(account, &p.role_name);
        }
        self.identity.delete_store(&inst.identity_store_id);
        Ok(types::DeleteInstanceResponse {})
    }

    pub(crate) fn add_region(
        &self,
        ctx: &RequestContext,
        input: types::AddRegionRequest,
    ) -> Result<types::AddRegionResponse, ServiceError> {
        let r = self.instance(ctx, &input.instance_arn, "sso:AddRegion", None)?;
        self.with_instance(&r.arn, |i| {
            if i.primary_region == input.region_name || i.regions.contains_key(&input.region_name) {
                return Err(errors::conflict(format!(
                    "The Region {} is already enabled for this instance.",
                    input.region_name
                )));
            }
            if i.regions.len() >= 16 {
                return Err(errors::service_quota_exceeded("The instance has reached the maximum number of Regions."));
            }
            i.regions.insert(input.region_name, ctx.received_at);
            // Replication finishes at once in MWS.
            Ok(types::AddRegionResponse { status: Some("ADDING".into()) })
        })
    }

    pub(crate) fn remove_region(
        &self,
        ctx: &RequestContext,
        input: types::RemoveRegionRequest,
    ) -> Result<types::RemoveRegionResponse, ServiceError> {
        let r = self.instance(ctx, &input.instance_arn, "sso:RemoveRegion", None)?;
        self.with_instance(&r.arn, |i| {
            if i.primary_region == input.region_name {
                return Err(errors::validation("You can't remove the primary Region of an instance."));
            }
            i.regions.remove(&input.region_name).ok_or_else(|| {
                not_found(format!("The Region {} is not enabled for this instance.", input.region_name))
            })?;
            Ok(types::RemoveRegionResponse { status: Some("REMOVING".into()) })
        })
    }

    pub(crate) fn describe_region(
        &self,
        ctx: &RequestContext,
        input: types::DescribeRegionRequest,
    ) -> Result<types::DescribeRegionResponse, ServiceError> {
        let r = self.instance(ctx, &input.instance_arn, "sso:DescribeRegion", None)?;
        self.with_instance(&r.arn, |i| {
            let m = regions_of(i)
                .into_iter()
                .find(|m| m.region_name.as_deref() == Some(input.region_name.as_str()))
                .ok_or_else(|| {
                    not_found(format!("The Region {} is not enabled for this instance.", input.region_name))
                })?;
            Ok(types::DescribeRegionResponse {
                region_name: m.region_name,
                status: m.status,
                added_date: m.added_date,
                is_primary_region: m.is_primary_region,
            })
        })
    }

    pub(crate) fn list_regions(
        &self,
        ctx: &RequestContext,
        input: types::ListRegionsRequest,
    ) -> Result<types::ListRegionsResponse, ServiceError> {
        let r = self.instance(ctx, &input.instance_arn, "sso:ListRegions", None)?;
        let all = self.with_instance(&r.arn, |i| Ok(regions_of(i)))?;
        let (page, next_token) = paginate(all, input.max_results, 100, input.next_token.as_deref())?;
        Ok(types::ListRegionsResponse { regions: Some(page), next_token })
    }

    pub(crate) fn create_instance_access_control_attribute_configuration(
        &self,
        ctx: &RequestContext,
        input: types::CreateInstanceAccessControlAttributeConfigurationRequest,
    ) -> Result<types::CreateInstanceAccessControlAttributeConfigurationResponse, ServiceError> {
        let r =
            self.instance(ctx, &input.instance_arn, "sso:CreateInstanceAccessControlAttributeConfiguration", None)?;
        check_access_control(&input.instance_access_control_attribute_configuration)?;
        self.with_instance(&r.arn, |i| {
            if i.access_control.is_some() {
                return Err(errors::conflict("An attribute configuration already exists for this instance."));
            }
            i.access_control = Some(input.instance_access_control_attribute_configuration);
            Ok(types::CreateInstanceAccessControlAttributeConfigurationResponse {})
        })
    }

    pub(crate) fn describe_instance_access_control_attribute_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DescribeInstanceAccessControlAttributeConfigurationRequest,
    ) -> Result<types::DescribeInstanceAccessControlAttributeConfigurationResponse, ServiceError> {
        let r =
            self.instance(ctx, &input.instance_arn, "sso:DescribeInstanceAccessControlAttributeConfiguration", None)?;
        self.with_instance(&r.arn, |i| {
            let c = i
                .access_control
                .clone()
                .ok_or_else(|| not_found("No attribute configuration exists for this instance."))?;
            Ok(types::DescribeInstanceAccessControlAttributeConfigurationResponse {
                status: Some("ENABLED".into()),
                status_reason: None,
                instance_access_control_attribute_configuration: Some(c),
            })
        })
    }

    pub(crate) fn update_instance_access_control_attribute_configuration(
        &self,
        ctx: &RequestContext,
        input: types::UpdateInstanceAccessControlAttributeConfigurationRequest,
    ) -> Result<types::UpdateInstanceAccessControlAttributeConfigurationResponse, ServiceError> {
        let r =
            self.instance(ctx, &input.instance_arn, "sso:UpdateInstanceAccessControlAttributeConfiguration", None)?;
        check_access_control(&input.instance_access_control_attribute_configuration)?;
        self.with_instance(&r.arn, |i| {
            if i.access_control.is_none() {
                return Err(not_found("No attribute configuration exists for this instance."));
            }
            i.access_control = Some(input.instance_access_control_attribute_configuration);
            Ok(types::UpdateInstanceAccessControlAttributeConfigurationResponse {})
        })
    }

    pub(crate) fn delete_instance_access_control_attribute_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DeleteInstanceAccessControlAttributeConfigurationRequest,
    ) -> Result<types::DeleteInstanceAccessControlAttributeConfigurationResponse, ServiceError> {
        let r =
            self.instance(ctx, &input.instance_arn, "sso:DeleteInstanceAccessControlAttributeConfiguration", None)?;
        self.with_instance(&r.arn, |i| {
            i.access_control.take().ok_or_else(|| not_found("No attribute configuration exists for this instance."))?;
            Ok(types::DeleteInstanceAccessControlAttributeConfigurationResponse {})
        })
    }

    /// The instance that owns a taggable resource, checked and authorized.
    fn taggable(
        &self,
        ctx: &RequestContext,
        resource_arn: &str,
        instance_arn: Option<&str>,
        action: &str,
        extra: ConditionContext,
    ) -> Result<String, ServiceError> {
        let owner = { self.instance_arn_for(&self.lock(), resource_arn) };
        let owner = owner.ok_or_else(|| not_found(format!("Resource {resource_arn} doesn't exist.")))?;
        if let Some(given) = instance_arn {
            if given != owner {
                return Err(errors::validation("The resource does not belong to the specified instance."));
            }
        }
        self.instance_on(ctx, &owner, action, &[resource_arn], extra)?;
        Ok(owner)
    }

    fn tags_mut<'a>(i: &'a mut Instance, arn: &str) -> Option<&'a mut Tags> {
        if i.arn == arn {
            return Some(&mut i.tags);
        }
        if let Some(p) = i.permission_sets.get_mut(arn) {
            return Some(&mut p.tags);
        }
        if let Some(a) = i.applications.get_mut(arn) {
            return Some(&mut a.tags);
        }
        i.token_issuers.get_mut(arn).map(|t| &mut t.tags)
    }

    pub(crate) fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<types::TagResourceResponse, ServiceError> {
        let new = tags_from(Some(input.tags))?;
        let owner = self.taggable(
            ctx,
            &input.resource_arn,
            input.instance_arn.as_deref(),
            "sso:TagResource",
            request_tag_context(&new),
        )?;
        self.with_instance(&owner, |i| {
            let tags = Self::tags_mut(i, &input.resource_arn)
                .ok_or_else(|| not_found(format!("Resource {} doesn't exist.", input.resource_arn)))?;
            let mut merged = tags.clone();
            merged.extend(new);
            if merged.len() > 50 {
                return Err(errors::service_quota_exceeded("Tags exceed the maximum number of 50 tags per resource."));
            }
            *tags = merged;
            Ok(types::TagResourceResponse {})
        })
    }

    pub(crate) fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<types::UntagResourceResponse, ServiceError> {
        let mut keys = ConditionContext::new();
        keys.insert("aws:TagKeys".into(), input.tag_keys.clone());
        let owner =
            self.taggable(ctx, &input.resource_arn, input.instance_arn.as_deref(), "sso:UntagResource", keys)?;
        self.with_instance(&owner, |i| {
            let tags = Self::tags_mut(i, &input.resource_arn)
                .ok_or_else(|| not_found(format!("Resource {} doesn't exist.", input.resource_arn)))?;
            for k in &input.tag_keys {
                tags.remove(k);
            }
            Ok(types::UntagResourceResponse {})
        })
    }

    pub(crate) fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        let owner = self.taggable(
            ctx,
            &input.resource_arn,
            input.instance_arn.as_deref(),
            "sso:ListTagsForResource",
            ConditionContext::new(),
        )?;
        let tags = self.with_instance(&owner, |i| {
            Self::tags_mut(i, &input.resource_arn)
                .map(|t| tags_to(t))
                .ok_or_else(|| not_found(format!("Resource {} doesn't exist.", input.resource_arn)))
        })?;
        let (page, next_token) = paginate(tags, None, 50, input.next_token.as_deref())?;
        Ok(types::ListTagsForResourceResponse { tags: Some(page), next_token })
    }
}

impl SsoAdmin {
    /// A customer managed key must be a usable symmetric encryption key
    /// whose key policy lets IAM Identity Center and Identity Store use it
    /// for this instance (AWS's baseline key policy).
    fn check_kms_key(&self, r: &InstanceRef, key: &str) -> Result<(), ServiceError> {
        let invalid = |why: String| errors::validation(format!("The KMS key {key} can't be used: {why}"));
        let store_arn = self.identity.store(&r.identity_store_id).map(|s| s.arn).unwrap_or_default();
        let checks = [
            (SERVICE_PRINCIPAL, "kms:EncryptionContext:aws:sso:instance-arn", r.arn.clone()),
            ("identitystore.amazonaws.com", "kms:EncryptionContext:aws:identitystore:identitystore-arn", store_arn),
        ];
        for (principal, context_key, value) in checks {
            let mut conditions = ConditionContext::new();
            conditions.insert(context_key.to_string(), vec![value]);
            conditions.insert("aws:SourceAccount".to_string(), vec![r.owner.clone()]);
            let k = self
                .kms
                .key_for_service(
                    key,
                    principal,
                    &["kms:DescribeKey", "kms:Decrypt", "kms:GenerateDataKeyWithoutPlaintext"],
                    &conditions,
                )
                .map_err(|e| invalid(e.message))?;
            if k.key_spec != "SYMMETRIC_DEFAULT" || k.key_usage != "ENCRYPT_DECRYPT" {
                return Err(invalid("it must be a symmetric encryption key.".into()));
            }
            if k.key_state != "Enabled" {
                return Err(invalid(format!("it is {}.", k.key_state)));
            }
        }
        Ok(())
    }
}

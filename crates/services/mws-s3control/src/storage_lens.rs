//! S3 Storage Lens dashboards (configurations, with their own tags) and
//! Storage Lens groups. Every account has the `default-account-dashboard`,
//! as on AWS.

use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde::{Deserialize, Serialize};

use crate::generated::types;
use crate::S3Control;

const DEFAULT_DASHBOARD: &str = "default-account-dashboard";

fn err(code: &'static str, status: u16, message: impl Into<String>) -> ServiceError {
    ServiceError::client(code, status, message)
}

fn no_config() -> ServiceError {
    err("NoSuchConfiguration", 404, "The specified configuration does not exist.")
}

fn no_group() -> ServiceError {
    err("NoSuchStorageLensGroup", 404, "The specified Storage Lens group does not exist.")
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Dashboard {
    pub account_id: String,
    pub region: String,
    pub config: types::StorageLensConfiguration,
    pub tags: Vec<types::StorageLensTag>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Group {
    pub account_id: String,
    pub region: String,
    pub group: types::StorageLensGroup,
}

impl S3Control {
    fn lens_arn(ctx: &RequestContext, account: &str, id: &str) -> String {
        format!("arn:{}:s3:{}:{account}:storage-lens/{id}", ctx.partition, ctx.region)
    }

    fn group_arn(ctx: &RequestContext, account: &str, name: &str) -> String {
        format!("arn:{}:s3:{}:{account}:storage-lens-group/{name}", ctx.partition, ctx.region)
    }

    fn default_dashboard(ctx: &RequestContext, account: &str) -> Dashboard {
        Dashboard {
            account_id: account.to_string(),
            region: ctx.region.clone(),
            config: types::StorageLensConfiguration {
                id: DEFAULT_DASHBOARD.into(),
                is_enabled: true,
                storage_lens_arn: Some(Self::lens_arn(ctx, account, DEFAULT_DASHBOARD)),
                ..Default::default()
            },
            tags: Vec::new(),
        }
    }

    fn dashboard(&self, ctx: &RequestContext, account: &str, id: &str) -> Result<Dashboard, ServiceError> {
        let st = self.read();
        match st.storage_lens.get(&format!("{account}/{id}")) {
            Some(d) => Ok(d.clone()),
            None if id == DEFAULT_DASHBOARD => Ok(Self::default_dashboard(ctx, account)),
            None => Err(no_config()),
        }
    }

    pub(crate) async fn put_storage_lens_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutStorageLensConfigurationRequest,
    ) -> Result<(), ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let arn = Self::lens_arn(ctx, &account, &input.config_id);
        ctx.authorize("s3:PutStorageLensConfiguration", &arn, ConditionContext::new())?;
        let mut config = input.storage_lens_configuration;
        if config.id != input.config_id {
            return Err(err("InvalidRequest", 400, "The configuration ID in the body does not match the ConfigId"));
        }
        if config.include.is_some() && config.exclude.is_some() {
            return Err(err("InvalidRequest", 400, "Include and Exclude cannot both be specified"));
        }
        if let Some(dest) = config.data_export.as_ref().and_then(|d| d.s3_bucket_destination.as_ref()) {
            let bucket = dest.arn.rsplit(":::").next().unwrap_or_default();
            if self.s3.as_ref().is_some_and(|s3| s3.bucket_owner(bucket).is_none()) {
                return Err(err("InvalidRequest", 400, "The export destination bucket does not exist"));
            }
        }
        config.storage_lens_arn = Some(arn);
        let mut st = self.write();
        let k = format!("{account}/{}", input.config_id);
        let tags = input.tags.unwrap_or_else(|| st.storage_lens.get(&k).map(|d| d.tags.clone()).unwrap_or_default());
        st.storage_lens.insert(k, Dashboard { account_id: account, region: ctx.region.clone(), config, tags });
        Ok(())
    }

    pub(crate) async fn get_storage_lens_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetStorageLensConfigurationRequest,
    ) -> Result<types::GetStorageLensConfigurationResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        ctx.authorize(
            "s3:GetStorageLensConfiguration",
            &Self::lens_arn(ctx, &account, &input.config_id),
            ConditionContext::new(),
        )?;
        let d = self.dashboard(ctx, &account, &input.config_id)?;
        Ok(types::GetStorageLensConfigurationResult { storage_lens_configuration: Some(d.config) })
    }

    pub(crate) async fn delete_storage_lens_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DeleteStorageLensConfigurationRequest,
    ) -> Result<(), ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        ctx.authorize(
            "s3:DeleteStorageLensConfiguration",
            &Self::lens_arn(ctx, &account, &input.config_id),
            ConditionContext::new(),
        )?;
        if input.config_id == DEFAULT_DASHBOARD {
            return Err(err("InvalidRequest", 400, "The default dashboard cannot be deleted"));
        }
        self.write().storage_lens.remove(&format!("{account}/{}", input.config_id)).ok_or_else(no_config)?;
        Ok(())
    }

    pub(crate) async fn list_storage_lens_configurations(
        &self,
        ctx: &RequestContext,
        input: types::ListStorageLensConfigurationsRequest,
    ) -> Result<types::ListStorageLensConfigurationsResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        ctx.authorize("s3:ListStorageLensConfigurations", "*", ConditionContext::new())?;
        let st = self.read();
        let mut list: Vec<types::ListStorageLensConfigurationEntry> = Vec::new();
        if !st.storage_lens.contains_key(&format!("{account}/{DEFAULT_DASHBOARD}")) {
            let d = Self::default_dashboard(ctx, &account);
            list.push(types::ListStorageLensConfigurationEntry {
                id: d.config.id,
                storage_lens_arn: d.config.storage_lens_arn.unwrap_or_default(),
                home_region: d.region,
                is_enabled: true,
            });
        }
        for d in st.storage_lens.values().filter(|d| d.account_id == account) {
            list.push(types::ListStorageLensConfigurationEntry {
                id: d.config.id.clone(),
                storage_lens_arn: d.config.storage_lens_arn.clone().unwrap_or_default(),
                home_region: d.region.clone(),
                is_enabled: d.config.is_enabled,
            });
        }
        let _ = input.next_token;
        Ok(types::ListStorageLensConfigurationsResult { next_token: None, storage_lens_configuration_list: Some(list) })
    }

    pub(crate) async fn put_storage_lens_configuration_tagging(
        &self,
        ctx: &RequestContext,
        input: types::PutStorageLensConfigurationTaggingRequest,
    ) -> Result<types::PutStorageLensConfigurationTaggingResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        ctx.authorize(
            "s3:PutStorageLensConfigurationTagging",
            &Self::lens_arn(ctx, &account, &input.config_id),
            ConditionContext::new(),
        )?;
        if input.tags.len() > 50 {
            return Err(err("InvalidRequest", 400, "A configuration can have at most 50 tags"));
        }
        let mut d = self.dashboard(ctx, &account, &input.config_id)?;
        d.tags = input.tags;
        self.write().storage_lens.insert(format!("{account}/{}", input.config_id), d);
        Ok(types::PutStorageLensConfigurationTaggingResult {})
    }

    pub(crate) async fn get_storage_lens_configuration_tagging(
        &self,
        ctx: &RequestContext,
        input: types::GetStorageLensConfigurationTaggingRequest,
    ) -> Result<types::GetStorageLensConfigurationTaggingResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        ctx.authorize(
            "s3:GetStorageLensConfigurationTagging",
            &Self::lens_arn(ctx, &account, &input.config_id),
            ConditionContext::new(),
        )?;
        let d = self.dashboard(ctx, &account, &input.config_id)?;
        Ok(types::GetStorageLensConfigurationTaggingResult { tags: Some(d.tags) })
    }

    pub(crate) async fn delete_storage_lens_configuration_tagging(
        &self,
        ctx: &RequestContext,
        input: types::DeleteStorageLensConfigurationTaggingRequest,
    ) -> Result<types::DeleteStorageLensConfigurationTaggingResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        ctx.authorize(
            "s3:DeleteStorageLensConfigurationTagging",
            &Self::lens_arn(ctx, &account, &input.config_id),
            ConditionContext::new(),
        )?;
        let mut st = self.write();
        let d = st.storage_lens.get_mut(&format!("{account}/{}", input.config_id)).ok_or_else(no_config)?;
        d.tags.clear();
        Ok(types::DeleteStorageLensConfigurationTaggingResult {})
    }

    pub(crate) async fn create_storage_lens_group(
        &self,
        ctx: &RequestContext,
        input: types::CreateStorageLensGroupRequest,
    ) -> Result<(), ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let mut group = input.storage_lens_group;
        let arn = Self::group_arn(ctx, &account, &group.name);
        ctx.authorize(
            "s3:CreateStorageLensGroup",
            &arn,
            crate::access_points::tags_context(input.tags.as_deref().unwrap_or_default()),
        )?;
        let k = format!("{account}/{}", group.name);
        {
            let mut st = self.write();
            if st.storage_lens_groups.contains_key(&k) {
                return Err(err("InvalidRequest", 409, "A Storage Lens group with this name already exists"));
            }
            if st.storage_lens_groups.values().filter(|g| g.account_id == account).count() >= 50 {
                return Err(err("TooManyRequests", 400, "An account can have at most 50 Storage Lens groups"));
            }
            group.storage_lens_group_arn = Some(arn.clone());
            st.storage_lens_groups.insert(k, Group { account_id: account, region: ctx.region.clone(), group });
        }
        self.store_tags(&arn, input.tags);
        Ok(())
    }

    pub(crate) async fn get_storage_lens_group(
        &self,
        ctx: &RequestContext,
        input: types::GetStorageLensGroupRequest,
    ) -> Result<types::GetStorageLensGroupResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        ctx.authorize("s3:GetStorageLensGroup", &Self::group_arn(ctx, &account, &input.name), ConditionContext::new())?;
        let st = self.read();
        let g = st.storage_lens_groups.get(&format!("{account}/{}", input.name)).ok_or_else(no_group)?;
        Ok(types::GetStorageLensGroupResult { storage_lens_group: Some(g.group.clone()) })
    }

    pub(crate) async fn update_storage_lens_group(
        &self,
        ctx: &RequestContext,
        input: types::UpdateStorageLensGroupRequest,
    ) -> Result<(), ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let arn = Self::group_arn(ctx, &account, &input.name);
        ctx.authorize("s3:UpdateStorageLensGroup", &arn, ConditionContext::new())?;
        if input.storage_lens_group.name != input.name {
            return Err(err("InvalidRequest", 400, "The group name in the body does not match the Name"));
        }
        let mut st = self.write();
        let g = st.storage_lens_groups.get_mut(&format!("{account}/{}", input.name)).ok_or_else(no_group)?;
        g.group = input.storage_lens_group;
        g.group.storage_lens_group_arn = Some(arn);
        Ok(())
    }

    pub(crate) async fn delete_storage_lens_group(
        &self,
        ctx: &RequestContext,
        input: types::DeleteStorageLensGroupRequest,
    ) -> Result<(), ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        let arn = Self::group_arn(ctx, &account, &input.name);
        ctx.authorize("s3:DeleteStorageLensGroup", &arn, ConditionContext::new())?;
        let mut st = self.write();
        st.storage_lens_groups.remove(&format!("{account}/{}", input.name)).ok_or_else(no_group)?;
        st.resource_tags.remove(&arn);
        Ok(())
    }

    pub(crate) async fn list_storage_lens_groups(
        &self,
        ctx: &RequestContext,
        input: types::ListStorageLensGroupsRequest,
    ) -> Result<types::ListStorageLensGroupsResult, ServiceError> {
        let account = crate::access_points::account(ctx, &input.account_id)?;
        ctx.authorize("s3:ListStorageLensGroups", "*", ConditionContext::new())?;
        let st = self.read();
        let list = st
            .storage_lens_groups
            .values()
            .filter(|g| g.account_id == account)
            .map(|g| types::ListStorageLensGroupEntry {
                name: g.group.name.clone(),
                storage_lens_group_arn: g.group.storage_lens_group_arn.clone().unwrap_or_default(),
                home_region: g.region.clone(),
            })
            .collect();
        let _ = input.next_token;
        Ok(types::ListStorageLensGroupsResult { next_token: None, storage_lens_group_list: Some(list) })
    }

    /// Whether `arn` is a Storage Lens group (which takes tags).
    pub(crate) fn storage_lens_group_exists(&self, arn: &str) -> bool {
        self.read().storage_lens_groups.values().any(|g| g.group.storage_lens_group_arn.as_deref() == Some(arn))
    }
}

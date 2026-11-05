//! Access points: an application-specific entry into a file system, with
//! its own root directory and POSIX identity.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::util::{
    account_of, ap_arn, ap_not_found, bad_request, err, name_tag, new_id, page, request_tag_context,
    resource_tag_context, validate_tags, with_member, wrong_state,
};
use crate::Efs;

/// An access point's id from an id or ARN.
pub fn ap_id(id_or_arn: &str) -> &str {
    id_or_arn.rsplit('/').next().unwrap_or(id_or_arn)
}

impl Efs {
    pub(crate) fn access_point(
        &self,
        ctx: &RequestContext,
        id: &str,
    ) -> Result<t::AccessPointDescription, ServiceError> {
        let account = account_of(ctx);
        let id = ap_id(id);
        let mut st = self.lock();
        st.region(&account, &ctx.region).access_points.get(id).cloned().ok_or_else(|| ap_not_found(id))
    }

    pub(crate) fn authorize_ap(
        &self,
        ctx: &RequestContext,
        action: &str,
        ap: &t::AccessPointDescription,
    ) -> Result<(), ServiceError> {
        let context = resource_tag_context(ap.tags.as_deref().unwrap_or_default());
        ctx.authorize(
            &format!("elasticfilesystem:{action}"),
            ap.access_point_arn.as_deref().unwrap_or_default(),
            context,
        )
    }

    pub(crate) async fn create_access_point(
        &self,
        ctx: &RequestContext,
        input: t::CreateAccessPointRequest,
    ) -> Result<t::AccessPointDescription, ServiceError> {
        let account = account_of(ctx);
        let fs = self.file_system(ctx, &input.file_system_id)?;
        let tags = input.tags.clone().unwrap_or_default();
        validate_tags(&tags)?;
        let mut context = request_tag_context(&tags);
        if !tags.is_empty() {
            context.insert("elasticfilesystem:CreateAction".into(), vec!["CreateAccessPoint".into()]);
        }
        self.authorize_fs(ctx, "CreateAccessPoint", &fs, context.clone())?;
        if !tags.is_empty() {
            ctx.authorize(
                "elasticfilesystem:TagResource",
                &ap_arn(&ctx.partition, &ctx.region, &account, "*"),
                context,
            )?;
        }
        if fs.description.life_cycle_state != "available" {
            return Err(wrong_state(fs.id(), &fs.description.life_cycle_state));
        }
        let mut root = input.root_directory.clone().unwrap_or_default();
        let path = root.path.get_or_insert_with(|| "/".into());
        if crate::storage::relative(path).is_none() {
            return Err(bad_request(format!("Invalid root directory path '{path}'.")));
        }
        if let Some(info) = &root.creation_info {
            if u32::from_str_radix(&info.permissions, 8).is_err() {
                return Err(bad_request(format!("Invalid permissions '{}'.", info.permissions)));
            }
        }
        if let Some(user) = &input.posix_user {
            if user.secondary_gids.as_ref().is_some_and(|g| g.len() > 16) {
                return Err(bad_request("A POSIX user can have at most 16 secondary group IDs."));
            }
        }
        let mut st = self.lock();
        let long = Self::long_ids(&st, &account, &ctx.region);
        let region = st.region(&account, &ctx.region);
        if let Some(existing) =
            region.access_points.values().find(|a| a.client_token.as_deref() == Some(input.client_token.as_str()))
        {
            let id = existing.access_point_id.clone().unwrap_or_default();
            return Err(with_member(
                err(
                    "AccessPointAlreadyExists",
                    409,
                    format!("Access point '{id}' already exists with client token '{}'.", input.client_token),
                ),
                "AccessPointId",
                &id,
            ));
        }
        let count = region.access_points.values().filter(|a| a.file_system_id.as_deref() == Some(fs.id())).count();
        if count >= 10_000 {
            return Err(err(
                "AccessPointLimitExceeded",
                403,
                format!("File system '{}' has reached the maximum number of access points.", fs.id()),
            ));
        }
        let id = new_id("fsap", long);
        let ap = t::AccessPointDescription {
            client_token: Some(input.client_token.clone()),
            name: name_tag(&tags),
            tags: Some(tags),
            access_point_id: Some(id.clone()),
            access_point_arn: Some(ap_arn(&ctx.partition, &ctx.region, &account, &id)),
            file_system_id: Some(fs.id().to_string()),
            posix_user: input.posix_user.clone(),
            root_directory: Some(root),
            owner_id: Some(account.clone()),
            life_cycle_state: Some("available".into()),
        };
        region.access_points.insert(id, ap.clone());
        let mut out = ap;
        out.life_cycle_state = Some("creating".into());
        Ok(out)
    }

    pub(crate) async fn describe_access_points(
        &self,
        ctx: &RequestContext,
        input: t::DescribeAccessPointsRequest,
    ) -> Result<t::DescribeAccessPointsResponse, ServiceError> {
        let account = account_of(ctx);
        if input.access_point_id.is_some() && input.file_system_id.is_some() {
            return Err(bad_request("Specify either an access point ID or a file system ID, not both."));
        }
        if let Some(id) = &input.access_point_id {
            let ap = self.access_point(ctx, id)?;
            self.authorize_ap(ctx, "DescribeAccessPoints", &ap)?;
            return Ok(t::DescribeAccessPointsResponse { access_points: Some(vec![ap]), next_token: None });
        }
        if let Some(id) = &input.file_system_id {
            let fs = self.file_system(ctx, id)?;
            self.authorize_fs(ctx, "DescribeAccessPoints", &fs, ConditionContext::new())?;
        } else {
            ctx.authorize(
                "elasticfilesystem:DescribeAccessPoints",
                &ap_arn(&ctx.partition, &ctx.region, &account, "*"),
                ConditionContext::new(),
            )?;
        }
        let fs_filter = input.file_system_id.as_deref().map(crate::file_systems::fs_id);
        let mut st = self.lock();
        let all: Vec<t::AccessPointDescription> = st
            .region(&account, &ctx.region)
            .access_points
            .values()
            .filter(|a| fs_filter.is_none_or(|f| a.file_system_id.as_deref() == Some(f)))
            .cloned()
            .collect();
        let (items, next) = page(
            all,
            |a| a.access_point_id.clone().unwrap_or_default(),
            input.next_token.as_deref(),
            input.max_results,
            100,
        )?;
        Ok(t::DescribeAccessPointsResponse { access_points: Some(items), next_token: next })
    }

    pub(crate) async fn delete_access_point(
        &self,
        ctx: &RequestContext,
        input: t::DeleteAccessPointRequest,
    ) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        let ap = self.access_point(ctx, &input.access_point_id)?;
        self.authorize_ap(ctx, "DeleteAccessPoint", &ap)?;
        let mut st = self.lock();
        st.region(&account, &ctx.region).access_points.remove(ap_id(&input.access_point_id));
        Ok(())
    }
}

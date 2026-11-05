//! Tags on file systems and access points: the legacy file-system-only
//! `CreateTags` / `DeleteTags` / `DescribeTags` and the newer
//! `TagResource` / `UntagResource` / `ListTagsForResource`.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::util::{
    account_of, ap_not_found, bad_request, fs_not_found, merge_tags, name_tag, page, request_tag_context, validate_tags,
};
use crate::Efs;

enum Resource {
    FileSystem(String),
    AccessPoint(String),
}

fn resource(id_or_arn: &str) -> Result<Resource, ServiceError> {
    let id = id_or_arn.rsplit('/').next().unwrap_or(id_or_arn);
    if id.starts_with("fsap-") {
        Ok(Resource::AccessPoint(id.into()))
    } else if id.starts_with("fs-") {
        Ok(Resource::FileSystem(id.into()))
    } else {
        Err(bad_request(format!("Invalid resource ID '{id_or_arn}'.")))
    }
}

impl Efs {
    fn tags_of(
        &self,
        ctx: &RequestContext,
        r: &Resource,
        action: &str,
        context: ConditionContext,
    ) -> Result<Vec<t::Tag>, ServiceError> {
        match r {
            Resource::FileSystem(id) => {
                let fs = self.file_system(ctx, id)?;
                self.authorize_fs(ctx, action, &fs, context)?;
                Ok(fs.description.tags)
            }
            Resource::AccessPoint(id) => {
                let ap = self.access_point(ctx, id)?;
                let mut c = crate::util::resource_tag_context(ap.tags.as_deref().unwrap_or_default());
                c.extend(context);
                ctx.authorize(
                    &format!("elasticfilesystem:{action}"),
                    ap.access_point_arn.as_deref().unwrap_or_default(),
                    c,
                )?;
                Ok(ap.tags.unwrap_or_default())
            }
        }
    }

    fn set_tags(
        &self,
        ctx: &RequestContext,
        r: &Resource,
        f: impl FnOnce(&mut Vec<t::Tag>),
    ) -> Result<(), ServiceError> {
        let account = account_of(ctx);
        let mut st = self.lock();
        let region = st.region(&account, &ctx.region);
        match r {
            Resource::FileSystem(id) => {
                let fs = region.file_systems.get_mut(id).ok_or_else(|| fs_not_found(id))?;
                f(&mut fs.description.tags);
                fs.description.name = name_tag(&fs.description.tags);
            }
            Resource::AccessPoint(id) => {
                let ap = region.access_points.get_mut(id).ok_or_else(|| ap_not_found(id))?;
                let tags = ap.tags.get_or_insert_with(Vec::new);
                f(tags);
                ap.name = name_tag(tags);
            }
        }
        Ok(())
    }

    fn add_tags(&self, ctx: &RequestContext, r: Resource, tags: Vec<t::Tag>, action: &str) -> Result<(), ServiceError> {
        validate_tags(&tags)?;
        let existing = self.tags_of(ctx, &r, action, request_tag_context(&tags))?;
        let mut merged = existing;
        merge_tags(&mut merged, &tags);
        if merged.len() > 50 {
            return Err(bad_request("Too many tags. A resource can have at most 50 tags."));
        }
        self.set_tags(ctx, &r, |t| merge_tags(t, &tags))
    }

    fn remove_tags(
        &self,
        ctx: &RequestContext,
        r: Resource,
        keys: Vec<String>,
        action: &str,
    ) -> Result<(), ServiceError> {
        let mut context = ConditionContext::new();
        context.insert("aws:TagKeys".into(), keys.clone());
        self.tags_of(ctx, &r, action, context)?;
        self.set_tags(ctx, &r, |t| t.retain(|tag| !keys.contains(&tag.key)))
    }

    pub(crate) async fn create_tags(
        &self,
        ctx: &RequestContext,
        input: t::CreateTagsRequest,
    ) -> Result<(), ServiceError> {
        self.add_tags(ctx, Resource::FileSystem(input.file_system_id), input.tags, "CreateTags")
    }

    pub(crate) async fn delete_tags(
        &self,
        ctx: &RequestContext,
        input: t::DeleteTagsRequest,
    ) -> Result<(), ServiceError> {
        self.remove_tags(ctx, Resource::FileSystem(input.file_system_id), input.tag_keys, "DeleteTags")
    }

    pub(crate) async fn describe_tags(
        &self,
        ctx: &RequestContext,
        input: t::DescribeTagsRequest,
    ) -> Result<t::DescribeTagsResponse, ServiceError> {
        let tags = self.tags_of(
            ctx,
            &Resource::FileSystem(input.file_system_id.clone()),
            "DescribeTags",
            ConditionContext::new(),
        )?;
        let (items, next) = page(tags, |t| t.key.clone(), input.marker.as_deref(), input.max_items, 100)?;
        Ok(t::DescribeTagsResponse { marker: input.marker, tags: items, next_marker: next })
    }

    pub(crate) async fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: t::TagResourceRequest,
    ) -> Result<(), ServiceError> {
        self.add_tags(ctx, resource(&input.resource_id)?, input.tags, "TagResource")
    }

    pub(crate) async fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: t::UntagResourceRequest,
    ) -> Result<(), ServiceError> {
        self.remove_tags(ctx, resource(&input.resource_id)?, input.tag_keys, "UntagResource")
    }

    pub(crate) async fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: t::ListTagsForResourceRequest,
    ) -> Result<t::ListTagsForResourceResponse, ServiceError> {
        let tags = self.tags_of(ctx, &resource(&input.resource_id)?, "ListTagsForResource", ConditionContext::new())?;
        let (items, next) = page(tags, |t| t.key.clone(), input.next_token.as_deref(), input.max_results, 100)?;
        Ok(t::ListTagsForResourceResponse { tags: Some(items), next_token: next })
    }
}

//! Images: builds of a recipe, and what they output.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::state::{ImageRecord, State};
use crate::util::{
    account_of, arn, arn_not_found, authorize, check_policy, dependency, filters_match, in_use, invalid_combination,
    invalid_parameter_value, latest_references, merge, not_found, now, paginate, request_tags, resource_tags, s, slug,
    Arn, Version, VersionPattern,
};
use crate::{managed, ImageBuilder};

pub const POLICY_ACTIONS: &[&str] = &["imagebuilder:GetImage", "imagebuilder:ListImages"];

/// Image states a build is still working in.
pub const ACTIVE_STATES: &[&str] = &["PENDING", "CREATING", "BUILDING", "TESTING", "DISTRIBUTING", "INTEGRATING"];

#[derive(Debug, Clone)]
pub struct FoundImage {
    pub owner: String,
    pub record: ImageRecord,
}

pub fn status_of(i: &t::Image) -> &str {
    i.state.as_ref().and_then(|s| s.status.as_deref()).unwrap_or("PENDING")
}

fn version_of(i: &t::Image) -> Version {
    i.version.as_deref().and_then(Version::parse).unwrap_or(Version(0, 0, 0))
}

fn build_of(i: &t::Image) -> u32 {
    i.arn.as_deref().and_then(Arn::parse).and_then(|a| a.build).unwrap_or(1)
}

/// What a build is asked to do.
#[derive(Debug, Clone, Default)]
pub struct BuildRequest {
    pub image_recipe_arn: Option<String>,
    pub container_recipe_arn: Option<String>,
    pub infrastructure_configuration_arn: String,
    pub distribution_configuration_arn: Option<String>,
    pub image_tests_configuration: Option<t::ImageTestsConfiguration>,
    pub enhanced_image_metadata_enabled: Option<bool>,
    pub tags: Option<BTreeMap<String, String>>,
    pub image_scanning_configuration: Option<t::ImageScanningConfiguration>,
    pub workflows: Option<Vec<t::WorkflowConfiguration>>,
    pub execution_role: Option<String>,
    pub log_group_name: Option<String>,
    pub pipeline: Option<(String, String)>,
    pub build_type: &'static str,
    pub client_token: Option<String>,
}

impl ImageBuilder {
    fn image_builds(&self, a: &Arn) -> Vec<FoundImage> {
        if a.account == "aws" {
            return managed::images(&a.partition, &a.region)
                .into_iter()
                .filter(|(i, _)| i.name.as_deref() == Some(a.name.as_str()))
                .map(|(i, _)| FoundImage {
                    owner: "aws".into(),
                    record: ImageRecord { image: i, ..Default::default() },
                })
                .collect();
        }
        let st = self.lock();
        let Some(r) = st.regions.get(&State::key(&a.account, &a.region)) else { return Vec::new() };
        r.images
            .values()
            .filter(|v| v.image.arn.as_deref().and_then(Arn::parse).is_some_and(|x| x.name == a.name))
            .map(|v| FoundImage { owner: a.account.clone(), record: v.clone() })
            .collect()
    }

    /// Resolve an image ARN: a build version, or a (wildcard) version's
    /// latest build.
    pub(crate) fn resolve_image(&self, arn_text: &str) -> Option<FoundImage> {
        let a = Arn::parse(arn_text).filter(|a| a.kind == "image")?;
        let pattern = VersionPattern::parse(a.version.as_deref()?)?;
        self.image_builds(&a)
            .into_iter()
            .filter(|f| pattern.matches(version_of(&f.record.image)))
            .filter(|f| a.build.is_none_or(|b| b == build_of(&f.record.image)))
            .filter(|f| a.build.is_some() || status_of(&f.record.image) != "DELETED")
            .max_by_key(|f| (version_of(&f.record.image), build_of(&f.record.image)))
    }

    fn image_for(&self, ctx: &RequestContext, action: &str, arn_text: &str) -> Result<FoundImage, ServiceError> {
        match self.resolve_image(arn_text) {
            Some(f) => {
                let resource = f.record.image.arn.clone().unwrap_or_default();
                if f.owner == "aws" {
                    authorize(ctx, action, &resource, ConditionContext::new())?;
                } else {
                    ctx.authorize_with_resource_policy(
                        &format!("imagebuilder:{action}"),
                        &resource,
                        f.record.policy.as_deref(),
                        resource_tags(&f.record.image.tags),
                    )?;
                }
                Ok(f)
            }
            None => {
                authorize(ctx, action, arn_text, ConditionContext::new())?;
                Err(arn_not_found(arn_text))
            }
        }
    }

    fn latest_image_references(&self, i: &t::Image) -> Option<t::LatestVersionReferences> {
        let a = Arn::parse(i.arn.as_deref()?)?;
        let builds: Vec<(Version, u32)> =
            self.image_builds(&a).iter().map(|f| (version_of(&f.record.image), build_of(&f.record.image))).collect();
        Some(latest_references(&a.base(), version_of(i), builds.into_iter()))
    }

    /// Check a build's workflow configurations.
    pub(crate) fn check_workflows(
        &self,
        workflows: &Option<Vec<t::WorkflowConfiguration>>,
    ) -> Result<(), ServiceError> {
        for w in workflows.iter().flatten() {
            let found = self
                .resolve_workflow(&w.workflow_arn)
                .ok_or_else(|| invalid_parameter_value(format!("The workflow '{}' does not exist.", w.workflow_arn)))?;
            crate::workflows::check_workflow_parameters(&found, w)?;
        }
        Ok(())
    }

    /// `iam:PassRole` for an execution role (name or ARN).
    pub(crate) fn pass_execution_role(&self, ctx: &RequestContext, role: &Option<String>) -> Result<(), ServiceError> {
        let Some(role) = role else { return Ok(()) };
        let role_arn = if role.starts_with("arn:") {
            role.clone()
        } else {
            format!("arn:{}:iam::{}:role/{role}", ctx.partition, account_of(ctx))
        };
        let mut c = ConditionContext::new();
        c.insert("iam:PassedToService".into(), vec!["imagebuilder.amazonaws.com".into()]);
        ctx.authorize("iam:PassRole", &role_arn, c)
    }

    /// Validate a build request and create its image, then start the build
    /// in the background. Returns the image build version ARN.
    pub(crate) async fn start_build(&self, ctx: &RequestContext, req: BuildRequest) -> Result<String, ServiceError> {
        let account = account_of(ctx);
        let (recipe_arn, image_recipe, container_recipe) = match (&req.image_recipe_arn, &req.container_recipe_arn) {
            (Some(a), None) => (a.clone(), Some(self.image_recipe_for(ctx, "GetImageRecipe", a)?.resource), None),
            (None, Some(a)) => {
                (a.clone(), None, Some(self.container_recipe_for(ctx, "GetContainerRecipe", a)?.resource))
            }
            _ => {
                return Err(invalid_combination(
                    "You must specify exactly one of 'imageRecipeArn' and 'containerRecipeArn'.",
                ))
            }
        };
        let infra = self
            .with_region(ctx, |r| r.infrastructure.get(&req.infrastructure_configuration_arn).cloned())
            .ok_or_else(|| {
                invalid_parameter_value(format!(
                    "The infrastructure configuration '{}' does not exist.",
                    req.infrastructure_configuration_arn
                ))
            })?;
        let dist = match &req.distribution_configuration_arn {
            Some(d) => Some(self.with_region(ctx, |r| r.distributions.get(d).cloned()).ok_or_else(|| {
                invalid_parameter_value(format!("The distribution configuration '{d}' does not exist."))
            })?),
            None => None,
        };
        self.check_workflows(&req.workflows)?;
        self.pass_execution_role(ctx, &req.execution_role)?;
        let recipe = Arn::parse(&recipe_arn).ok_or_else(|| arn_not_found(&recipe_arn))?;
        let name = image_recipe
            .as_ref()
            .and_then(|r| r.name.clone())
            .or_else(|| container_recipe.as_ref().and_then(|r| r.name.clone()))
            .unwrap_or_else(|| recipe.name.clone());
        let version = recipe.version.clone().unwrap_or_else(|| "1.0.0".into());
        let (platform, os_version) = match &image_recipe {
            Some(r) => {
                let parent = self.resolve_parent(ctx, r.parent_image.as_deref().unwrap_or_default(), false).await.ok();
                (
                    r.platform.clone().unwrap_or_else(|| "Linux".into()),
                    parent.map(|p| p.os_version).unwrap_or_else(|| "Linux".into()),
                )
            }
            None => (
                container_recipe.as_ref().and_then(|r| r.platform.clone()).unwrap_or_else(|| "Linux".into()),
                "Amazon Linux 2023".into(),
            ),
        };
        let slugged = slug(&name);
        let tests = req
            .image_tests_configuration
            .clone()
            .unwrap_or(t::ImageTestsConfiguration { image_tests_enabled: Some(true), timeout_minutes: Some(720) });
        let image_arn = self.with_region(ctx, |r| {
            let build = r
                .images
                .values()
                .filter_map(|i| i.image.arn.as_deref().and_then(Arn::parse))
                .filter(|a| a.name == slugged && a.version.as_deref() == Some(version.as_str()))
                .filter_map(|a| a.build)
                .max()
                .unwrap_or(0)
                + 1;
            let image_arn = arn(ctx, &account, &format!("image/{slugged}/{version}/{build}"));
            let image = t::Image {
                arn: Some(image_arn.clone()),
                r#type: Some(if container_recipe.is_some() { "DOCKER" } else { "AMI" }.into()),
                name: Some(name.clone()),
                version: Some(version.clone()),
                platform: Some(platform.clone()),
                enhanced_image_metadata_enabled: Some(req.enhanced_image_metadata_enabled.unwrap_or(true)),
                os_version: Some(os_version.clone()),
                state: Some(t::ImageState { status: Some("PENDING".into()), ..Default::default() }),
                image_recipe: image_recipe.clone(),
                container_recipe: container_recipe.clone(),
                source_pipeline_name: req.pipeline.as_ref().map(|p| p.1.clone()),
                source_pipeline_arn: req.pipeline.as_ref().map(|p| p.0.clone()),
                infrastructure_configuration: Some(infra.clone()),
                distribution_configuration: dist.clone(),
                image_tests_configuration: Some(tests.clone()),
                date_created: Some(now(ctx)),
                output_resources: None,
                tags: Some(req.tags.clone().unwrap_or_default()),
                build_type: Some(req.build_type.into()),
                image_source: Some("CUSTOM".into()),
                scan_state: None,
                image_scanning_configuration: req.image_scanning_configuration.clone(),
                deprecation_time: None,
                lifecycle_execution_id: None,
                execution_role: req.execution_role.clone(),
                workflows: req.workflows.clone(),
                logging_configuration: Some(t::ImageLoggingConfiguration {
                    log_group_name: Some(
                        req.log_group_name.clone().unwrap_or_else(|| format!("/aws/imagebuilder/{name}")),
                    ),
                }),
            };
            r.images.insert(
                image_arn.clone(),
                ImageRecord { image, client_token: req.client_token.clone(), ..Default::default() },
            );
            image_arn
        });
        self.spawn_build(ctx, &account, &ctx.region, &image_arn);
        Ok(image_arn)
    }

    pub(crate) async fn create_image_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateImageRequest,
    ) -> Result<t::CreateImageResponse, ServiceError> {
        let recipe = input.image_recipe_arn.clone().or_else(|| input.container_recipe_arn.clone()).unwrap_or_default();
        let target = Arn::parse(&recipe)
            .map(|a| arn(ctx, &account_of(ctx), &format!("image/{}/{}/*", a.name, a.version.unwrap_or_default())))
            .unwrap_or_else(|| arn(ctx, &account_of(ctx), "image/*"));
        authorize(ctx, "CreateImage", &target, request_tags(&input.tags))?;
        let token = input.client_token.clone();
        self.idempotent(ctx, "CreateImage", &token, &input.clone(), async {
            let image_arn = self
                .start_build(
                    ctx,
                    BuildRequest {
                        image_recipe_arn: input.image_recipe_arn.clone(),
                        container_recipe_arn: input.container_recipe_arn.clone(),
                        infrastructure_configuration_arn: input.infrastructure_configuration_arn.clone(),
                        distribution_configuration_arn: input.distribution_configuration_arn.clone(),
                        image_tests_configuration: input.image_tests_configuration.clone(),
                        enhanced_image_metadata_enabled: input.enhanced_image_metadata_enabled,
                        tags: input.tags.clone(),
                        image_scanning_configuration: input.image_scanning_configuration.clone(),
                        workflows: input.workflows.clone(),
                        execution_role: input.execution_role.clone(),
                        log_group_name: input.logging_configuration.as_ref().and_then(|l| l.log_group_name.clone()),
                        pipeline: None,
                        build_type: "USER_INITIATED",
                        client_token: Some(token.clone()),
                    },
                )
                .await?;
            let latest = self.resolve_image(&image_arn).and_then(|f| self.latest_image_references(&f.record.image));
            Ok(t::CreateImageResponse {
                request_id: Some(ctx.request_id.clone()),
                client_token: Some(token.clone()),
                image_build_version_arn: Some(image_arn),
                latest_version_references: latest,
            })
        })
        .await
    }

    pub(crate) fn get_image_op(
        &self,
        ctx: &RequestContext,
        input: t::GetImageRequest,
    ) -> Result<t::GetImageResponse, ServiceError> {
        let f = self.image_for(ctx, "GetImage", &input.image_build_version_arn)?;
        let latest = self.latest_image_references(&f.record.image);
        Ok(t::GetImageResponse {
            request_id: Some(ctx.request_id.clone()),
            image: Some(f.record.image),
            latest_version_references: latest,
        })
    }

    fn visible_images(&self, ctx: &RequestContext, owner: &str) -> Vec<t::Image> {
        match owner {
            "Amazon" => managed::images(&ctx.partition, &ctx.region).into_iter().map(|(i, _)| i).collect(),
            "Self" | "Shared" => self.shared_or_own(ctx, owner, "imagebuilder:ListImages", |r| {
                r.images.values().map(|v| (v.image.clone(), v.policy.clone())).collect()
            }),
            _ => Vec::new(),
        }
    }

    pub(crate) fn list_images_op(
        &self,
        ctx: &RequestContext,
        input: t::ListImagesRequest,
    ) -> Result<t::ListImagesResponse, ServiceError> {
        authorize(ctx, "ListImages", &arn(ctx, &account_of(ctx), "image/*"), ConditionContext::new())?;
        let owner = input.owner.clone().unwrap_or_else(|| "Self".into());
        let include_deprecated = input.include_deprecated.unwrap_or(false);
        let mut by_version: BTreeMap<String, t::Image> = BTreeMap::new();
        for i in self.visible_images(ctx, &owner) {
            let st = status_of(&i);
            if st == "DELETED" || (st == "DEPRECATED" && !include_deprecated) {
                continue;
            }
            let ok =
                filters_match(&input.filters, &["name", "osVersion", "platform", "type", "version"], |n| match n {
                    "name" => s(&i.name),
                    "osVersion" => s(&i.os_version),
                    "platform" => s(&i.platform),
                    "type" => s(&i.r#type),
                    _ => s(&i.version),
                })?;
            if !ok {
                continue;
            }
            let key = Arn::parse(i.arn.as_deref().unwrap_or_default()).map(|a| a.version_arn()).unwrap_or_default();
            if by_version.get(&key).is_none_or(|p| build_of(p) < build_of(&i)) {
                by_version.insert(key, i);
            }
        }
        let mut list: Vec<(String, t::Image)> = by_version.into_iter().collect();
        if input.by_name {
            let mut latest: BTreeMap<String, (String, t::Image)> = BTreeMap::new();
            for (k, i) in list {
                let base = Arn::parse(&k).map(|a| a.base()).unwrap_or_default();
                if latest.get(&base).is_none_or(|(_, p)| version_of(p) < version_of(&i)) {
                    latest.insert(base, (k, i));
                }
            }
            list = latest.into_values().collect();
        }
        list.sort_by(|a, b| a.0.cmp(&b.0));
        let versions = list
            .into_iter()
            .map(|(k, i)| t::ImageVersion {
                arn: Some(k),
                name: i.name,
                r#type: i.r#type,
                version: i.version,
                platform: i.platform,
                os_version: i.os_version,
                owner: Some(if owner == "Amazon" {
                    "Amazon".into()
                } else {
                    Arn::parse(i.arn.as_deref().unwrap_or_default()).map(|a| a.account).unwrap_or_default()
                }),
                date_created: i.date_created,
                build_type: i.build_type,
                image_source: i.image_source,
            })
            .collect();
        let (page, next_token) = paginate(versions, input.max_results, &input.next_token)?;
        Ok(t::ListImagesResponse {
            request_id: Some(ctx.request_id.clone()),
            image_version_list: Some(page),
            next_token,
        })
    }

    fn summary(i: t::Image) -> t::ImageSummary {
        let owner = Arn::parse(i.arn.as_deref().unwrap_or_default()).map(|a| {
            if a.account == "aws" {
                "Amazon".into()
            } else {
                a.account
            }
        });
        t::ImageSummary {
            arn: i.arn,
            name: i.name,
            r#type: i.r#type,
            version: i.version,
            platform: i.platform,
            os_version: i.os_version,
            state: i.state,
            owner,
            date_created: i.date_created,
            output_resources: i.output_resources,
            tags: i.tags,
            build_type: i.build_type,
            image_source: i.image_source,
            deprecation_time: i.deprecation_time,
            lifecycle_execution_id: i.lifecycle_execution_id,
            logging_configuration: i.logging_configuration,
        }
    }

    pub(crate) fn list_image_build_versions_op(
        &self,
        ctx: &RequestContext,
        input: t::ListImageBuildVersionsRequest,
    ) -> Result<t::ListImageBuildVersionsResponse, ServiceError> {
        let target = input
            .image_version_arn
            .clone()
            .ok_or_else(|| crate::util::invalid_request("The imageVersionArn parameter is required."))?;
        authorize(ctx, "ListImageBuildVersions", &target, ConditionContext::new())?;
        let a = Arn::parse(&target).ok_or_else(|| arn_not_found(&target))?;
        let mut builds: Vec<t::Image> =
            self.image_builds(&a).into_iter().map(|f| f.record.image).filter(|i| i.version == a.version).collect();
        builds.sort_by_key(build_of);
        let mut out = Vec::new();
        for i in builds {
            if filters_match(&input.filters, &["name", "osVersion", "platform", "type", "version"], |n| match n {
                "name" => s(&i.name),
                "osVersion" => s(&i.os_version),
                "platform" => s(&i.platform),
                "type" => s(&i.r#type),
                _ => s(&i.version),
            })? {
                out.push(Self::summary(i));
            }
        }
        let (page, next_token) = paginate(out, input.max_results, &input.next_token)?;
        Ok(t::ListImageBuildVersionsResponse {
            request_id: Some(ctx.request_id.clone()),
            image_summary_list: Some(page),
            next_token,
        })
    }

    pub(crate) fn list_image_pipeline_images_op(
        &self,
        ctx: &RequestContext,
        input: t::ListImagePipelineImagesRequest,
    ) -> Result<t::ListImagePipelineImagesResponse, ServiceError> {
        let target = input.image_pipeline_arn.clone();
        authorize(ctx, "ListImagePipelineImages", &target, ConditionContext::new())?;
        let images = self
            .with_region(ctx, |r| {
                r.pipelines.get(&target)?;
                Some(
                    r.images
                        .values()
                        .filter(|i| i.image.source_pipeline_arn.as_deref() == Some(target.as_str()))
                        .map(|i| i.image.clone())
                        .collect::<Vec<_>>(),
                )
            })
            .ok_or_else(|| not_found(format!("The image pipeline '{target}' does not exist.")))?;
        let mut out = Vec::new();
        for i in images {
            if filters_match(&input.filters, &["name", "version"], |n| {
                if n == "name" {
                    s(&i.name)
                } else {
                    s(&i.version)
                }
            })? {
                out.push(Self::summary(i));
            }
        }
        let (page, next_token) = paginate(out, input.max_results, &input.next_token)?;
        Ok(t::ListImagePipelineImagesResponse {
            request_id: Some(ctx.request_id.clone()),
            image_summary_list: Some(page),
            next_token,
        })
    }

    pub(crate) fn delete_image_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteImageRequest,
    ) -> Result<t::DeleteImageResponse, ServiceError> {
        let target = input.image_build_version_arn.clone();
        let found = self.with_region(ctx, |r| r.images.get(&target).cloned());
        authorize(ctx, "DeleteImage", &target, resource_tags(&found.as_ref().and_then(|f| f.image.tags.clone())))?;
        let found = found.ok_or_else(|| arn_not_found(&target))?;
        if ACTIVE_STATES.contains(&status_of(&found.image)) {
            return Err(dependency(format!(
                "Resource dependency error: The image '{target}' cannot be deleted while it is being built. Cancel the build first."
            )));
        }
        self.with_region(ctx, |r| r.images.remove(&target));
        Ok(t::DeleteImageResponse { request_id: Some(ctx.request_id.clone()), image_build_version_arn: Some(target) })
    }

    pub(crate) async fn cancel_image_creation_op(
        &self,
        ctx: &RequestContext,
        input: t::CancelImageCreationRequest,
    ) -> Result<t::CancelImageCreationResponse, ServiceError> {
        let target = input.image_build_version_arn.clone();
        authorize(ctx, "CancelImageCreation", &target, ConditionContext::new())?;
        let token = input.client_token.clone();
        self.idempotent(ctx, "CancelImageCreation", &token, &input.clone(), async {
            let previous = self.with_region(ctx, |r| {
                let rec = r.images.get_mut(&target).ok_or_else(|| arn_not_found(&target))?;
                let status = status_of(&rec.image).to_string();
                if !ACTIVE_STATES.contains(&status.as_str()) {
                    return Err(in_use(format!(
                        "The image '{target}' cannot be cancelled because its status is {status}."
                    )));
                }
                rec.cancel_requested = true;
                rec.image.state = Some(t::ImageState {
                    status: Some("CANCELLED".into()),
                    reason: Some("Image creation cancelled by the user.".into()),
                    failure_context: None,
                });
                Ok(status)
            })?;
            self.emit_state_change(ctx, &account_of(ctx), &ctx.region, &target, Some(previous), "CANCELLED", None);
            Ok(t::CancelImageCreationResponse {
                request_id: Some(ctx.request_id.clone()),
                client_token: Some(token.clone()),
                image_build_version_arn: Some(target.clone()),
            })
        })
        .await
    }

    pub(crate) async fn retry_image_op(
        &self,
        ctx: &RequestContext,
        input: t::RetryImageRequest,
    ) -> Result<t::RetryImageResponse, ServiceError> {
        let target = input.image_build_version_arn.clone();
        authorize(ctx, "RetryImage", &target, ConditionContext::new())?;
        let token = input.client_token.clone();
        self.idempotent(ctx, "RetryImage", &token, &input.clone(), async {
            self.with_region(ctx, |r| {
                let rec = r.images.get_mut(&target).ok_or_else(|| arn_not_found(&target))?;
                let status = status_of(&rec.image).to_string();
                if !matches!(status.as_str(), "FAILED" | "CANCELLED") {
                    return Err(in_use(format!(
                        "The image '{target}' cannot be retried because its status is {status}. Only failed or cancelled builds can be retried."
                    )));
                }
                rec.cancel_requested = false;
                rec.build_ami = None;
                rec.live_instances.clear();
                rec.image.output_resources = None;
                rec.image.state = Some(t::ImageState { status: Some("PENDING".into()), ..Default::default() });
                Ok(())
            })?;
            self.spawn_build(ctx, &account_of(ctx), &ctx.region, &target);
            Ok(t::RetryImageResponse { client_token: Some(token.clone()), image_build_version_arn: Some(target.clone()) })
        })
        .await
    }

    pub(crate) fn get_image_policy_op(
        &self,
        ctx: &RequestContext,
        input: t::GetImagePolicyRequest,
    ) -> Result<t::GetImagePolicyResponse, ServiceError> {
        let target = input.image_arn.clone();
        authorize(ctx, "GetImagePolicy", &target, ConditionContext::new())?;
        let rec = self.with_region(ctx, |r| r.images.get(&target).cloned()).ok_or_else(|| arn_not_found(&target))?;
        let policy =
            rec.policy.ok_or_else(|| not_found(format!("The resource policy for '{target}' does not exist.")))?;
        Ok(t::GetImagePolicyResponse { request_id: Some(ctx.request_id.clone()), policy: Some(policy) })
    }

    pub(crate) fn put_image_policy_op(
        &self,
        ctx: &RequestContext,
        input: t::PutImagePolicyRequest,
    ) -> Result<t::PutImagePolicyResponse, ServiceError> {
        let target = input.image_arn.clone();
        authorize(ctx, "PutImagePolicy", &target, ConditionContext::new())?;
        check_policy(&input.policy, POLICY_ACTIONS)?;
        self.with_region(ctx, |r| match r.images.get_mut(&target) {
            Some(rec) => {
                rec.policy = Some(input.policy.clone());
                Ok(())
            }
            None => Err(arn_not_found(&target)),
        })?;
        Ok(t::PutImagePolicyResponse { request_id: Some(ctx.request_id.clone()), image_arn: Some(target) })
    }

    pub(crate) fn list_image_packages_op(
        &self,
        ctx: &RequestContext,
        input: t::ListImagePackagesRequest,
    ) -> Result<t::ListImagePackagesResponse, ServiceError> {
        let target = input.image_build_version_arn.clone();
        authorize(ctx, "ListImagePackages", &target, ConditionContext::new())?;
        let rec = self
            .with_region(ctx, |r| r.images.get(&target).cloned())
            .ok_or_else(|| not_found(format!("The image '{target}' does not exist.")))?;
        let (page, next_token) = paginate(rec.packages, input.max_results, &input.next_token)?;
        Ok(t::ListImagePackagesResponse {
            request_id: Some(ctx.request_id.clone()),
            image_package_list: Some(page),
            next_token,
        })
    }

    pub(crate) fn list_image_scan_findings_op(
        &self,
        ctx: &RequestContext,
        input: t::ListImageScanFindingsRequest,
    ) -> Result<t::ListImageScanFindingsResponse, ServiceError> {
        authorize(ctx, "ListImageScanFindings", "*", ConditionContext::new())?;
        for f in input.filters.iter().flatten() {
            let name = f.name.as_deref().unwrap_or_default();
            if !matches!(name, "imageBuildVersionArn" | "imagePipelineArn" | "vulnerabilityId" | "severity") {
                return Err(crate::util::invalid_request(format!("The filter name '{name}' is not valid.")));
            }
        }
        // Nothing scans images in MWS (Amazon Inspector is not emulated).
        let (page, next_token) = paginate(Vec::<t::ImageScanFinding>::new(), input.max_results, &input.next_token)?;
        Ok(t::ListImageScanFindingsResponse {
            request_id: Some(ctx.request_id.clone()),
            findings: Some(page),
            next_token,
        })
    }

    pub(crate) fn list_image_scan_finding_aggregations_op(
        &self,
        ctx: &RequestContext,
        input: t::ListImageScanFindingAggregationsRequest,
    ) -> Result<t::ListImageScanFindingAggregationsResponse, ServiceError> {
        authorize(ctx, "ListImageScanFindingAggregations", "*", ConditionContext::new())?;
        let aggregation = match input.filter.as_ref().and_then(|f| f.name.as_deref()) {
            None => "accountId",
            Some("imageBuildVersionArn") => "imageBuildVersionArn",
            Some("imagePipelineArn") => "imagePipelineArn",
            Some("vulnerabilityId") => "vulnerabilityId",
            Some(other) => {
                return Err(crate::util::invalid_request(format!("The filter name '{other}' is not valid.")))
            }
        };
        let (page, next_token) = paginate(Vec::<t::ImageScanFindingAggregation>::new(), None, &input.next_token)?;
        Ok(t::ListImageScanFindingAggregationsResponse {
            request_id: Some(ctx.request_id.clone()),
            aggregation_type: Some(aggregation.into()),
            responses: Some(page),
            next_token,
        })
    }

    pub(crate) async fn import_vm_image_op(
        &self,
        ctx: &RequestContext,
        input: t::ImportVmImageRequest,
    ) -> Result<t::ImportVmImageResponse, ServiceError> {
        authorize(
            ctx,
            "ImportVmImage",
            &arn(ctx, &account_of(ctx), &format!("image/{}/*", slug(&input.name))),
            request_tags(&input.tags),
        )?;
        Version::for_create(&input.semantic_version)?;
        // VM Import/Export is not emulated, so no import task can exist.
        Err(invalid_parameter_value(format!(
            "The value supplied for parameter 'vmImportTaskId' is not valid. The import task '{}' does not exist.",
            input.vm_import_task_id
        )))
    }

    pub(crate) async fn import_disk_image_op(
        &self,
        ctx: &RequestContext,
        input: t::ImportDiskImageRequest,
    ) -> Result<t::ImportDiskImageResponse, ServiceError> {
        let account = account_of(ctx);
        authorize(
            ctx,
            "ImportDiskImage",
            &arn(ctx, &account, &format!("image/{}/*", slug(&input.name))),
            request_tags(&input.tags),
        )?;
        let token = input.client_token.clone();
        self.idempotent(ctx, "ImportDiskImage", &token, &input.clone(), async {
            let v = Version::for_create(&input.semantic_version)?;
            if !input.uri.starts_with("s3://") {
                return Err(invalid_parameter_value(format!(
                    "The value supplied for parameter 'uri' is not valid. '{}' is not an S3 URI.",
                    input.uri
                )));
            }
            let infra = self
                .with_region(ctx, |r| r.infrastructure.get(&input.infrastructure_configuration_arn).cloned())
                .ok_or_else(|| {
                    invalid_parameter_value(format!(
                        "The infrastructure configuration '{}' does not exist.",
                        input.infrastructure_configuration_arn
                    ))
                })?;
            self.pass_execution_role(ctx, &input.execution_role)?;
            let slugged = slug(&input.name);
            let image_arn = self.with_region(ctx, |r| {
                let build = r
                    .images
                    .keys()
                    .filter_map(|k| Arn::parse(k))
                    .filter(|a| a.name == slugged && a.version.as_deref() == Some(v.to_string().as_str()))
                    .filter_map(|a| a.build)
                    .max()
                    .unwrap_or(0)
                    + 1;
                let image_arn = arn(ctx, &account, &format!("image/{slugged}/{v}/{build}"));
                let image = t::Image {
                    arn: Some(image_arn.clone()),
                    r#type: Some("AMI".into()),
                    name: Some(input.name.clone()),
                    version: Some(v.to_string()),
                    platform: Some(input.platform.clone()),
                    os_version: Some(input.os_version.clone()),
                    state: Some(t::ImageState { status: Some("PENDING".into()), ..Default::default() }),
                    infrastructure_configuration: Some(infra),
                    date_created: Some(now(ctx)),
                    tags: Some(input.tags.clone().unwrap_or_default()),
                    build_type: Some("IMPORT_ISO".into()),
                    image_source: Some("IMPORTED".into()),
                    execution_role: input.execution_role.clone(),
                    logging_configuration: input.logging_configuration.clone(),
                    ..Default::default()
                };
                r.images.insert(
                    image_arn.clone(),
                    ImageRecord {
                        image,
                        client_token: Some(token.clone()),
                        resolved_inputs: vec![input.uri.clone()],
                        ..Default::default()
                    },
                );
                image_arn
            });
            self.spawn_build(ctx, &account, &ctx.region, &image_arn);
            Ok(t::ImportDiskImageResponse {
                client_token: Some(token.clone()),
                image_build_version_arn: Some(image_arn),
            })
        })
        .await
    }

    pub(crate) async fn distribute_image_op(
        &self,
        ctx: &RequestContext,
        input: t::DistributeImageRequest,
    ) -> Result<t::DistributeImageResponse, ServiceError> {
        let account = account_of(ctx);
        authorize(
            ctx,
            "DistributeImage",
            &input.source_image,
            merge(request_tags(&input.tags), ConditionContext::new()),
        )?;
        let token = input.client_token.clone();
        self.idempotent(ctx, "DistributeImage", &token, &input.clone(), async {
            self.pass_execution_role(ctx, &Some(input.execution_role.clone()))?;
            let dist = self
                .with_region(ctx, |r| r.distributions.get(&input.distribution_configuration_arn).cloned())
                .ok_or_else(|| {
                not_found(format!(
                    "The distribution configuration '{}' does not exist.",
                    input.distribution_configuration_arn
                ))
            })?;
            let source = self.image_for(ctx, "GetImage", &input.source_image).map_err(|e| {
                if e.code == "ResourceNotFoundException" {
                    not_found(format!("The source image '{}' does not exist.", input.source_image))
                } else {
                    e
                }
            })?;
            let src = source.record.image.clone();
            let source_ami = src
                .output_resources
                .as_ref()
                .and_then(|o| o.amis.as_ref())
                .and_then(|a| {
                    a.iter()
                        .find(|x| {
                            x.region.as_deref() == Some(ctx.region.as_str())
                                && x.account_id.as_deref() == Some(account.as_str())
                        })
                        .or_else(|| a.first())
                })
                .and_then(|x| x.image.clone())
                .ok_or_else(|| {
                    invalid_parameter_value(format!(
                        "The source image '{}' has no AMI to distribute.",
                        input.source_image
                    ))
                })?;
            let name = src.name.clone().unwrap_or_default();
            let version = src.version.clone().unwrap_or_else(|| "1.0.0".into());
            let slugged = slug(&name);
            let image_arn = self.with_region(ctx, |r| {
                let build = r
                    .images
                    .keys()
                    .filter_map(|k| Arn::parse(k))
                    .filter(|a| a.name == slugged && a.version.as_deref() == Some(version.as_str()))
                    .filter_map(|a| a.build)
                    .max()
                    .unwrap_or(0)
                    + 1;
                let image_arn = arn(ctx, &account, &format!("image/{slugged}/{version}/{build}"));
                let image = t::Image {
                    arn: Some(image_arn.clone()),
                    state: Some(t::ImageState { status: Some("PENDING".into()), ..Default::default() }),
                    distribution_configuration: Some(dist.clone()),
                    date_created: Some(now(ctx)),
                    tags: Some(input.tags.clone().unwrap_or_default()),
                    build_type: Some("USER_INITIATED".into()),
                    execution_role: Some(input.execution_role.clone()),
                    logging_configuration: input.logging_configuration.clone(),
                    output_resources: None,
                    lifecycle_execution_id: None,
                    workflows: None,
                    ..src.clone()
                };
                r.images.insert(
                    image_arn.clone(),
                    ImageRecord {
                        image,
                        build_ami: Some(source_ami.clone()),
                        resolved_inputs: vec![format!("distribute:{source_ami}")],
                        client_token: Some(token.clone()),
                        ..Default::default()
                    },
                );
                image_arn
            });
            self.spawn_build(ctx, &account, &ctx.region, &image_arn);
            Ok(t::DistributeImageResponse {
                client_token: Some(token.clone()),
                image_build_version_arn: Some(image_arn),
            })
        })
        .await
    }

    pub(crate) fn get_marketplace_resource_op(
        &self,
        ctx: &RequestContext,
        input: t::GetMarketplaceResourceRequest,
    ) -> Result<t::GetMarketplaceResourceResponse, ServiceError> {
        authorize(ctx, "GetMarketplaceResource", &input.resource_arn, ConditionContext::new())?;
        // No AWS Marketplace components exist in MWS.
        Err(arn_not_found(&input.resource_arn))
    }
}

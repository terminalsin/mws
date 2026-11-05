//! Image recipes and container recipes, and the parent images they name.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::components::check_component_parameters;
use crate::generated::types as t;
use crate::state::{State, Versioned};
use crate::util::{
    account_of, already_exists, arn, arn_not_found, authorize, check_policy, dependency, filters_match,
    invalid_combination, invalid_parameter_value, latest_references_unbuilt, not_found, now, paginate, request_tags,
    resource_tags, s, slug, Arn, Version, VersionPattern,
};
use crate::{ec2link, managed, ImageBuilder};

pub const IMAGE_RECIPE_POLICY_ACTIONS: &[&str] = &["imagebuilder:GetImageRecipe", "imagebuilder:ListImageRecipes"];
pub const CONTAINER_RECIPE_POLICY_ACTIONS: &[&str] =
    &["imagebuilder:GetContainerRecipe", "imagebuilder:ListContainerRecipes"];

/// A parent image, resolved.
#[derive(Debug, Clone, Default)]
pub struct Parent {
    /// The AMI to launch, when known (an `ssm:` parent is read at build time).
    pub ami: Option<String>,
    pub platform: String,
    pub os_version: String,
}

fn os_version_for_ami_name(name: &str) -> String {
    if let Some(m) = managed::IMAGES.iter().find(|m| m.ami_name == name) {
        return m.os_version.to_string();
    }
    let n = name.to_lowercase();
    if n.starts_with("al2023") {
        "Amazon Linux 2023".into()
    } else if n.starts_with("amzn2") {
        "Amazon Linux 2".into()
    } else if n.contains("ubuntu") {
        "Ubuntu".into()
    } else if n.contains("debian") {
        "Debian".into()
    } else if n.contains("windows") {
        "Microsoft Windows Server".into()
    } else {
        "Linux".into()
    }
}

impl ImageBuilder {
    /// Resolve a recipe's parent image: an AMI id, an Image Builder image
    /// ARN (AWS-managed, yours, or shared with you), or `ssm:<parameter>`.
    /// With `at_build`, `ssm:` parents are read from Parameter Store.
    pub(crate) async fn resolve_parent(
        &self,
        ctx: &RequestContext,
        parent: &str,
        at_build: bool,
    ) -> Result<Parent, ServiceError> {
        let bad = |why: &str| {
            invalid_parameter_value(format!("The value supplied for parameter 'parentImage' is not valid. {why}"))
        };
        let account = account_of(ctx);
        if let Some(param) = parent.strip_prefix("ssm:") {
            if param.is_empty() {
                return Err(bad("The SSM parameter name is empty."));
            }
            if !at_build {
                return Ok(Parent { ami: None, platform: "Linux".into(), os_version: "Linux".into() });
            }
            let Some(ssm) = self.ssm() else {
                return Err(bad(&format!("The SSM parameter '{param}' could not be read.")));
            };
            let sctx = self.service_ctx(ctx, &account, &ctx.region);
            let out = ssm
                .invoke(sctx, "GetParameter", serde_json::json!({ "Name": param }))
                .await
                .map_err(|e| bad(&format!("The SSM parameter '{param}' could not be read: {}", e.message)))?;
            let value = out["Parameter"]["Value"].as_str().unwrap_or_default().to_string();
            if !value.starts_with("ami-") {
                return Err(bad(&format!("The SSM parameter '{param}' does not contain an AMI ID.")));
            }
            return Box::pin(self.resolve_parent(ctx, &value, at_build)).await;
        }
        if parent.starts_with("ami-") {
            let Some(ec2) = self.ec2() else {
                return Ok(Parent { ami: Some(parent.into()), platform: "Linux".into(), os_version: "Linux".into() });
            };
            let sctx = self.service_ctx(ctx, &account, &ctx.region);
            let img = ec2link::describe_image(ec2, &sctx, parent).await.ok_or_else(|| {
                bad(&format!("The AMI ID '{parent}' does not exist or you do not have access to it."))
            })?;
            let windows = img.platform.as_deref() == Some("windows");
            return Ok(Parent {
                ami: Some(parent.into()),
                platform: if windows { "Windows" } else { "Linux" }.into(),
                os_version: os_version_for_ami_name(img.name.as_deref().unwrap_or_default()),
            });
        }
        let a = Arn::parse(parent)
            .filter(|a| a.kind == "image")
            .ok_or_else(|| bad("Specify an AMI ID, an Image Builder image ARN or an SSM parameter (ssm:<name>)."))?;
        if a.account == "aws" {
            let m = managed::IMAGES
                .iter()
                .find(|m| m.name == a.name)
                .ok_or_else(|| bad(&format!("The image '{parent}' does not exist.")))?;
            let pattern = a.version.as_deref().and_then(VersionPattern::parse);
            if pattern.is_some_and(|p| !p.matches(Version::parse(m.version).unwrap_or(Version(0, 0, 0)))) {
                return Err(bad(&format!("The image '{parent}' does not exist.")));
            }
            let ami = match self.ec2() {
                Some(ec2) => {
                    let sctx = self.service_ctx(ctx, &account, &ctx.region);
                    ec2link::public_image_by_name(ec2, &sctx, m.ami_name).await
                }
                None => None,
            };
            return Ok(Parent { ami, platform: "Linux".into(), os_version: m.os_version.into() });
        }
        // An image you built, or one shared with you.
        let rec = self.resolve_image(parent).ok_or_else(|| bad(&format!("The image '{parent}' does not exist.")))?;
        if rec.owner != account {
            ctx.authorize_with_resource_policy(
                "imagebuilder:GetImage",
                rec.record.image.arn.as_deref().unwrap_or(parent),
                rec.record.policy.as_deref(),
                ConditionContext::new(),
            )?;
        }
        let ami = rec
            .record
            .image
            .output_resources
            .as_ref()
            .and_then(|o| o.amis.as_ref())
            .and_then(|amis| amis.iter().find(|x| x.region.as_deref() == Some(ctx.region.as_str())))
            .and_then(|x| x.image.clone())
            .ok_or_else(|| bad(&format!("The image '{parent}' has no AMI in {}.", ctx.region)))?;
        Ok(Parent {
            ami: Some(ami),
            platform: rec.record.image.platform.clone().unwrap_or_else(|| "Linux".into()),
            os_version: rec.record.image.os_version.clone().unwrap_or_else(|| "Linux".into()),
        })
    }

    /// Check a recipe's components: each exists, is visible to the caller,
    /// matches the platform and gets only parameters it declares.
    pub(crate) fn check_components(
        &self,
        ctx: &RequestContext,
        components: &Option<Vec<t::ComponentConfiguration>>,
        platform: &str,
    ) -> Result<(), ServiceError> {
        for c in components.iter().flatten() {
            let a = Arn::parse(&c.component_arn).filter(|a| a.kind == "component").ok_or_else(|| {
                invalid_parameter_value(format!(
                    "The value supplied for parameter 'componentArn' is not valid: {}",
                    c.component_arn
                ))
            })?;
            if a.version.as_deref().and_then(VersionPattern::parse).is_none() {
                return Err(invalid_parameter_value(format!(
                    "The value supplied for parameter 'componentArn' is not valid: {}",
                    c.component_arn
                )));
            }
            let found = self.component_for(ctx, "GetComponent", &c.component_arn).map_err(|e| {
                if e.code == "ResourceNotFoundException" {
                    invalid_parameter_value(format!("The component '{}' does not exist.", c.component_arn))
                } else {
                    e
                }
            })?;
            let cp = found.component.platform.clone().unwrap_or_default();
            if !cp.eq_ignore_ascii_case(platform) {
                return Err(invalid_parameter_value(format!(
                    "The component '{}' is for platform {cp}, which does not match the parent image platform {platform}.",
                    c.component_arn
                )));
            }
            check_component_parameters(&found.component, c)?;
        }
        Ok(())
    }

    // ---- image recipes ----------------------------------------------------------

    pub(crate) async fn create_image_recipe_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateImageRecipeRequest,
    ) -> Result<t::CreateImageRecipeResponse, ServiceError> {
        let account = account_of(ctx);
        let target = arn(ctx, &account, &format!("image-recipe/{}/{}", slug(&input.name), input.semantic_version));
        authorize(ctx, "CreateImageRecipe", &target, request_tags(&input.tags))?;
        if input.dry_run {
            return Err(crate::util::dry_run_ok());
        }
        let token = input.client_token.clone();
        self.idempotent(ctx, "CreateImageRecipe", &token, &input.clone(), async {
            let v = Version::for_create(&input.semantic_version)?;
            let target = arn(ctx, &account, &format!("image-recipe/{}/{v}", slug(&input.name)));
            if self.with_region(ctx, |r| r.image_recipes.contains_key(&target)) {
                return Err(already_exists(&target));
            }
            let parent = self.resolve_parent(ctx, &input.parent_image, false).await?;
            self.check_components(ctx, &input.components, &parent.platform)?;
            let recipe = t::ImageRecipe {
                arn: Some(target.clone()),
                r#type: Some("AMI".into()),
                name: Some(input.name.clone()),
                description: input.description.clone(),
                platform: Some(parent.platform.clone()),
                owner: Some(account.clone()),
                version: Some(v.to_string()),
                components: input.components.clone(),
                parent_image: Some(input.parent_image.clone()),
                block_device_mappings: input.block_device_mappings.clone(),
                date_created: Some(now(ctx)),
                tags: Some(input.tags.clone().unwrap_or_default()),
                working_directory: Some(input.working_directory.clone().unwrap_or_else(|| "/tmp".into())),
                additional_instance_configuration: input.additional_instance_configuration.clone(),
                ami_tags: input.ami_tags.clone(),
                ami_watermarks: input.ami_watermarks.clone(),
            };
            self.with_region(ctx, |r| {
                if r.image_recipes.contains_key(&target) {
                    return Err(already_exists(&target));
                }
                r.image_recipes.insert(target.clone(), Versioned { resource: recipe.clone(), policy: None });
                Ok(())
            })?;
            Ok(t::CreateImageRecipeResponse {
                request_id: Some(ctx.request_id.clone()),
                client_token: Some(token.clone()),
                image_recipe_arn: Some(target.clone()),
                latest_version_references: self.recipe_references(&target, false),
            })
        })
        .await
    }

    fn recipe_references(&self, recipe_arn: &str, container: bool) -> Option<t::LatestVersionReferences> {
        let a = Arn::parse(recipe_arn)?;
        let current = Version::parse(a.version.as_deref()?)?;
        let st = self.lock();
        let r = st.regions.get(&State::key(&a.account, &a.region))?;
        let versions: Vec<Version> = if container {
            r.container_recipes
                .keys()
                .filter_map(|k| Arn::parse(k))
                .filter(|x| x.name == a.name)
                .filter_map(|x| x.version.as_deref().and_then(Version::parse))
                .collect()
        } else {
            r.image_recipes
                .keys()
                .filter_map(|k| Arn::parse(k))
                .filter(|x| x.name == a.name)
                .filter_map(|x| x.version.as_deref().and_then(Version::parse))
                .collect()
        };
        Some(latest_references_unbuilt(&a.base(), current, versions.into_iter()))
    }

    /// An image recipe, from any account (the caller is authorized with the
    /// recipe's policy).
    pub(crate) fn image_recipe_for(
        &self,
        ctx: &RequestContext,
        action: &str,
        recipe_arn: &str,
    ) -> Result<Versioned<t::ImageRecipe>, ServiceError> {
        let found = Arn::parse(recipe_arn).and_then(|a| {
            let st = self.lock();
            st.regions.get(&State::key(&a.account, &a.region))?.image_recipes.get(recipe_arn).cloned()
        });
        match found {
            Some(v) => {
                ctx.authorize_with_resource_policy(
                    &format!("imagebuilder:{action}"),
                    recipe_arn,
                    v.policy.as_deref(),
                    resource_tags(&v.resource.tags),
                )?;
                Ok(v)
            }
            None => {
                authorize(ctx, action, recipe_arn, ConditionContext::new())?;
                Err(arn_not_found(recipe_arn))
            }
        }
    }

    pub(crate) fn get_image_recipe_op(
        &self,
        ctx: &RequestContext,
        input: t::GetImageRecipeRequest,
    ) -> Result<t::GetImageRecipeResponse, ServiceError> {
        let v = self.image_recipe_for(ctx, "GetImageRecipe", &input.image_recipe_arn)?;
        Ok(t::GetImageRecipeResponse {
            request_id: Some(ctx.request_id.clone()),
            image_recipe: Some(v.resource),
            latest_version_references: self.recipe_references(&input.image_recipe_arn, false),
        })
    }

    pub(crate) fn list_image_recipes_op(
        &self,
        ctx: &RequestContext,
        input: t::ListImageRecipesRequest,
    ) -> Result<t::ListImageRecipesResponse, ServiceError> {
        authorize(ctx, "ListImageRecipes", &arn(ctx, &account_of(ctx), "image-recipe/*"), ConditionContext::new())?;
        let owner = input.owner.clone().unwrap_or_else(|| "Self".into());
        let recipes: Vec<t::ImageRecipe> = self.shared_or_own(ctx, &owner, "imagebuilder:ListImageRecipes", |r| {
            r.image_recipes.values().map(|v| (v.resource.clone(), v.policy.clone())).collect()
        });
        let mut out = Vec::new();
        for r in recipes {
            if filters_match(&input.filters, &["name", "parentImage", "platform"], |n| match n {
                "name" => s(&r.name),
                "parentImage" => s(&r.parent_image),
                _ => s(&r.platform),
            })? {
                out.push(t::ImageRecipeSummary {
                    arn: r.arn,
                    name: r.name,
                    platform: r.platform,
                    owner: r.owner,
                    parent_image: r.parent_image,
                    date_created: r.date_created,
                    tags: r.tags,
                });
            }
        }
        out.sort_by(|a, b| a.arn.cmp(&b.arn));
        let (page, next_token) = paginate(out, input.max_results, &input.next_token)?;
        Ok(t::ListImageRecipesResponse {
            request_id: Some(ctx.request_id.clone()),
            image_recipe_summary_list: Some(page),
            next_token,
        })
    }

    /// Resources of the caller (`Self`) or shared with it (`Shared`).
    pub(crate) fn shared_or_own<T>(
        &self,
        ctx: &RequestContext,
        owner: &str,
        action: &str,
        pick: impl Fn(&crate::state::Region) -> Vec<(T, Option<String>)>,
    ) -> Vec<T>
    where
        T: HasArn,
    {
        let account = account_of(ctx);
        let st = self.lock();
        let mut out = Vec::new();
        for (key, r) in &st.regions {
            let Some((acct, region)) = key.split_once('/') else { continue };
            if region != ctx.region {
                continue;
            }
            match owner {
                "Self" if acct == account => out.extend(pick(r).into_iter().map(|(t, _)| t)),
                "Shared" if acct != account => {
                    for (item, policy) in pick(r) {
                        let Some(policy) = policy else { continue };
                        let decision = ctx.check(
                            action,
                            item.arn(),
                            Some(&policy),
                            mws_core::ResourcePolicyMode::Required,
                            ConditionContext::new(),
                        );
                        if decision == mws_core::AuthzDecision::Allow {
                            out.push(item);
                        }
                    }
                }
                _ => {}
            }
        }
        out
    }

    pub(crate) fn delete_image_recipe_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteImageRecipeRequest,
    ) -> Result<t::DeleteImageRecipeResponse, ServiceError> {
        let target = input.image_recipe_arn.clone();
        let found = self.with_region(ctx, |r| r.image_recipes.get(&target).map(|v| v.resource.tags.clone()));
        authorize(ctx, "DeleteImageRecipe", &target, resource_tags(&found.clone().flatten()))?;
        if found.is_none() {
            return Err(arn_not_found(&target));
        }
        let users: Vec<String> = self.with_region(ctx, |r| {
            r.pipelines
                .iter()
                .filter(|(_, p)| p.pipeline.image_recipe_arn.as_deref() == Some(target.as_str()))
                .map(|(k, _)| k.clone())
                .collect()
        });
        if !users.is_empty() {
            return Err(dependency(format!(
                "Resource dependency error: The resource ARN '{target}' has the following dependencies: {}.",
                users.join(", ")
            )));
        }
        self.with_region(ctx, |r| r.image_recipes.remove(&target));
        Ok(t::DeleteImageRecipeResponse { request_id: Some(ctx.request_id.clone()), image_recipe_arn: Some(target) })
    }

    pub(crate) fn get_image_recipe_policy_op(
        &self,
        ctx: &RequestContext,
        input: t::GetImageRecipePolicyRequest,
    ) -> Result<t::GetImageRecipePolicyResponse, ServiceError> {
        let target = input.image_recipe_arn.clone();
        authorize(ctx, "GetImageRecipePolicy", &target, ConditionContext::new())?;
        let v =
            self.with_region(ctx, |r| r.image_recipes.get(&target).cloned()).ok_or_else(|| arn_not_found(&target))?;
        let policy =
            v.policy.ok_or_else(|| not_found(format!("The resource policy for '{target}' does not exist.")))?;
        Ok(t::GetImageRecipePolicyResponse { request_id: Some(ctx.request_id.clone()), policy: Some(policy) })
    }

    pub(crate) fn put_image_recipe_policy_op(
        &self,
        ctx: &RequestContext,
        input: t::PutImageRecipePolicyRequest,
    ) -> Result<t::PutImageRecipePolicyResponse, ServiceError> {
        let target = input.image_recipe_arn.clone();
        authorize(ctx, "PutImageRecipePolicy", &target, ConditionContext::new())?;
        check_policy(&input.policy, IMAGE_RECIPE_POLICY_ACTIONS)?;
        self.with_region(ctx, |r| match r.image_recipes.get_mut(&target) {
            Some(v) => {
                v.policy = Some(input.policy.clone());
                Ok(())
            }
            None => Err(arn_not_found(&target)),
        })?;
        Ok(t::PutImageRecipePolicyResponse { request_id: Some(ctx.request_id.clone()), image_recipe_arn: Some(target) })
    }

    // ---- container recipes -------------------------------------------------------

    pub(crate) async fn create_container_recipe_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateContainerRecipeRequest,
    ) -> Result<t::CreateContainerRecipeResponse, ServiceError> {
        let account = account_of(ctx);
        let target = arn(ctx, &account, &format!("container-recipe/{}/{}", slug(&input.name), input.semantic_version));
        authorize(ctx, "CreateContainerRecipe", &target, request_tags(&input.tags))?;
        if input.dry_run {
            return Err(crate::util::dry_run_ok());
        }
        let token = input.client_token.clone();
        self.idempotent(ctx, "CreateContainerRecipe", &token, &input.clone(), async {
            let v = Version::for_create(&input.semantic_version)?;
            let target = arn(ctx, &account, &format!("container-recipe/{}/{v}", slug(&input.name)));
            if self.with_region(ctx, |r| r.container_recipes.contains_key(&target)) {
                return Err(already_exists(&target));
            }
            let dockerfile =
                match (&input.dockerfile_template_data, &input.dockerfile_template_uri) {
                    (Some(d), None) => d.clone(),
                    (None, Some(u)) => self.document_from_uri(ctx, u).await?,
                    _ => return Err(invalid_combination(
                        "You must specify either 'dockerfileTemplateData' or 'dockerfileTemplateUri', but not both.",
                    )),
                };
            if input.target_repository.service != "ECR" {
                return Err(invalid_parameter_value(
                    "The value supplied for parameter 'targetRepository.service' is not valid.",
                ));
            }
            let platform = input.platform_override.clone().unwrap_or_else(|| "Linux".into());
            self.check_components(ctx, &input.components, &platform)?;
            if let Some(ami) = input.instance_configuration.as_ref().and_then(|i| i.image.clone()) {
                self.resolve_parent(ctx, &ami, false).await?;
            }
            let recipe = t::ContainerRecipe {
                arn: Some(target.clone()),
                container_type: Some(input.container_type.clone()),
                name: Some(input.name.clone()),
                description: input.description.clone(),
                platform: Some(platform),
                owner: Some(account.clone()),
                version: Some(v.to_string()),
                components: input.components.clone(),
                instance_configuration: input.instance_configuration.clone(),
                dockerfile_template_data: Some(dockerfile),
                kms_key_id: input.kms_key_id.clone(),
                encrypted: Some(true),
                parent_image: Some(input.parent_image.clone()),
                date_created: Some(now(ctx)),
                tags: Some(input.tags.clone().unwrap_or_default()),
                working_directory: Some(input.working_directory.clone().unwrap_or_else(|| "/tmp".into())),
                target_repository: Some(input.target_repository.clone()),
            };
            self.with_region(ctx, |r| {
                if r.container_recipes.contains_key(&target) {
                    return Err(already_exists(&target));
                }
                r.container_recipes.insert(target.clone(), Versioned { resource: recipe, policy: None });
                Ok(())
            })?;
            Ok(t::CreateContainerRecipeResponse {
                request_id: Some(ctx.request_id.clone()),
                client_token: Some(token.clone()),
                container_recipe_arn: Some(target.clone()),
                latest_version_references: self.recipe_references(&target, true),
            })
        })
        .await
    }

    pub(crate) fn container_recipe_for(
        &self,
        ctx: &RequestContext,
        action: &str,
        recipe_arn: &str,
    ) -> Result<Versioned<t::ContainerRecipe>, ServiceError> {
        let found = Arn::parse(recipe_arn).and_then(|a| {
            let st = self.lock();
            st.regions.get(&State::key(&a.account, &a.region))?.container_recipes.get(recipe_arn).cloned()
        });
        match found {
            Some(v) => {
                ctx.authorize_with_resource_policy(
                    &format!("imagebuilder:{action}"),
                    recipe_arn,
                    v.policy.as_deref(),
                    resource_tags(&v.resource.tags),
                )?;
                Ok(v)
            }
            None => {
                authorize(ctx, action, recipe_arn, ConditionContext::new())?;
                Err(arn_not_found(recipe_arn))
            }
        }
    }

    pub(crate) fn get_container_recipe_op(
        &self,
        ctx: &RequestContext,
        input: t::GetContainerRecipeRequest,
    ) -> Result<t::GetContainerRecipeResponse, ServiceError> {
        let v = self.container_recipe_for(ctx, "GetContainerRecipe", &input.container_recipe_arn)?;
        Ok(t::GetContainerRecipeResponse {
            request_id: Some(ctx.request_id.clone()),
            container_recipe: Some(v.resource),
            latest_version_references: self.recipe_references(&input.container_recipe_arn, true),
        })
    }

    pub(crate) fn list_container_recipes_op(
        &self,
        ctx: &RequestContext,
        input: t::ListContainerRecipesRequest,
    ) -> Result<t::ListContainerRecipesResponse, ServiceError> {
        authorize(
            ctx,
            "ListContainerRecipes",
            &arn(ctx, &account_of(ctx), "container-recipe/*"),
            ConditionContext::new(),
        )?;
        let owner = input.owner.clone().unwrap_or_else(|| "Self".into());
        let recipes: Vec<t::ContainerRecipe> =
            self.shared_or_own(ctx, &owner, "imagebuilder:ListContainerRecipes", |r| {
                r.container_recipes.values().map(|v| (v.resource.clone(), v.policy.clone())).collect()
            });
        let mut out = Vec::new();
        for r in recipes {
            if filters_match(&input.filters, &["containerType", "name", "parentImage", "platform"], |n| match n {
                "containerType" => s(&r.container_type),
                "name" => s(&r.name),
                "parentImage" => s(&r.parent_image),
                _ => s(&r.platform),
            })? {
                out.push(t::ContainerRecipeSummary {
                    arn: r.arn,
                    container_type: r.container_type,
                    name: r.name,
                    platform: r.platform,
                    owner: r.owner,
                    parent_image: r.parent_image,
                    date_created: r.date_created,
                    instance_image: r.instance_configuration.and_then(|i| i.image),
                    tags: r.tags,
                });
            }
        }
        out.sort_by(|a, b| a.arn.cmp(&b.arn));
        let (page, next_token) = paginate(out, input.max_results, &input.next_token)?;
        Ok(t::ListContainerRecipesResponse {
            request_id: Some(ctx.request_id.clone()),
            container_recipe_summary_list: Some(page),
            next_token,
        })
    }

    pub(crate) fn delete_container_recipe_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteContainerRecipeRequest,
    ) -> Result<t::DeleteContainerRecipeResponse, ServiceError> {
        let target = input.container_recipe_arn.clone();
        let found = self.with_region(ctx, |r| r.container_recipes.get(&target).map(|v| v.resource.tags.clone()));
        authorize(ctx, "DeleteContainerRecipe", &target, resource_tags(&found.clone().flatten()))?;
        if found.is_none() {
            return Err(arn_not_found(&target));
        }
        let users: Vec<String> = self.with_region(ctx, |r| {
            r.pipelines
                .iter()
                .filter(|(_, p)| p.pipeline.container_recipe_arn.as_deref() == Some(target.as_str()))
                .map(|(k, _)| k.clone())
                .collect()
        });
        if !users.is_empty() {
            return Err(dependency(format!(
                "Resource dependency error: The resource ARN '{target}' has the following dependencies: {}.",
                users.join(", ")
            )));
        }
        self.with_region(ctx, |r| r.container_recipes.remove(&target));
        Ok(t::DeleteContainerRecipeResponse {
            request_id: Some(ctx.request_id.clone()),
            container_recipe_arn: Some(target),
        })
    }

    pub(crate) fn get_container_recipe_policy_op(
        &self,
        ctx: &RequestContext,
        input: t::GetContainerRecipePolicyRequest,
    ) -> Result<t::GetContainerRecipePolicyResponse, ServiceError> {
        let target = input.container_recipe_arn.clone();
        authorize(ctx, "GetContainerRecipePolicy", &target, ConditionContext::new())?;
        let v = self
            .with_region(ctx, |r| r.container_recipes.get(&target).cloned())
            .ok_or_else(|| arn_not_found(&target))?;
        let policy =
            v.policy.ok_or_else(|| not_found(format!("The resource policy for '{target}' does not exist.")))?;
        Ok(t::GetContainerRecipePolicyResponse { request_id: Some(ctx.request_id.clone()), policy: Some(policy) })
    }

    pub(crate) fn put_container_recipe_policy_op(
        &self,
        ctx: &RequestContext,
        input: t::PutContainerRecipePolicyRequest,
    ) -> Result<t::PutContainerRecipePolicyResponse, ServiceError> {
        let target = input.container_recipe_arn.clone();
        authorize(ctx, "PutContainerRecipePolicy", &target, ConditionContext::new())?;
        check_policy(&input.policy, CONTAINER_RECIPE_POLICY_ACTIONS)?;
        self.with_region(ctx, |r| match r.container_recipes.get_mut(&target) {
            Some(v) => {
                v.policy = Some(input.policy.clone());
                Ok(())
            }
            None => Err(arn_not_found(&target)),
        })?;
        Ok(t::PutContainerRecipePolicyResponse {
            request_id: Some(ctx.request_id.clone()),
            container_recipe_arn: Some(target),
        })
    }
}

/// Resources with an ARN, for shared listings.
pub trait HasArn {
    fn arn(&self) -> &str;
}

impl HasArn for t::ImageRecipe {
    fn arn(&self) -> &str {
        self.arn.as_deref().unwrap_or_default()
    }
}

impl HasArn for t::ContainerRecipe {
    fn arn(&self) -> &str {
        self.arn.as_deref().unwrap_or_default()
    }
}

impl HasArn for t::Image {
    fn arn(&self) -> &str {
        self.arn.as_deref().unwrap_or_default()
    }
}

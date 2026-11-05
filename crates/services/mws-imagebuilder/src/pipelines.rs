//! Image pipelines: recipes built on demand or on a schedule.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::types as t;
use crate::images::BuildRequest;
use crate::state::Pipeline;
use crate::util::{
    account_of, already_exists, arn, arn_not_found, authorize, date, filters_match, invalid_combination,
    invalid_parameter_value, not_found, now, paginate, request_tags, resource_tags, s, slug,
};
use crate::ImageBuilder;

/// The fields create and update share.
struct PipelineFields<'a> {
    image_recipe_arn: &'a Option<String>,
    container_recipe_arn: &'a Option<String>,
    infrastructure_configuration_arn: &'a str,
    distribution_configuration_arn: &'a Option<String>,
    schedule: &'a Option<t::Schedule>,
    status: &'a Option<String>,
    workflows: &'a Option<Vec<t::WorkflowConfiguration>>,
    execution_role: &'a Option<String>,
}

fn parse_schedule(s: &t::Schedule) -> Result<Option<mws_schedule::Schedule>, ServiceError> {
    let Some(expr) = &s.schedule_expression else { return Ok(None) };
    if !expr.starts_with("cron(") {
        return Err(invalid_parameter_value(format!(
            "The value supplied for parameter 'scheduleExpression' is not valid. '{expr}' is not a cron expression."
        )));
    }
    let parsed = mws_schedule::Schedule::parse(expr).ok_or_else(|| {
        invalid_parameter_value(format!("The value supplied for parameter 'scheduleExpression' is not valid. '{expr}' is not a valid cron expression."))
    })?;
    if let Some(c) = &s.pipeline_execution_start_condition {
        if !matches!(c.as_str(), "EXPRESSION_MATCH_ONLY" | "EXPRESSION_MATCH_AND_DEPENDENCY_UPDATES_AVAILABLE") {
            return Err(invalid_parameter_value(format!(
                "The value '{c}' is not a valid pipelineExecutionStartCondition."
            )));
        }
    }
    Ok(Some(parsed))
}

/// The next time `schedule` fires after `after`.
fn next_run(
    schedule: &t::Schedule,
    anchor: chrono::DateTime<chrono::Utc>,
    after: chrono::DateTime<chrono::Utc>,
) -> Option<String> {
    let parsed = parse_schedule(schedule).ok().flatten()?;
    parsed.fires_between(anchor, after, after + chrono::Duration::days(800), 1).first().map(|t| date(*t))
}

impl ImageBuilder {
    async fn check_pipeline(&self, ctx: &RequestContext, f: &PipelineFields<'_>) -> Result<String, ServiceError> {
        let platform = match (f.image_recipe_arn, f.container_recipe_arn) {
            (Some(a), None) => self.image_recipe_for(ctx, "GetImageRecipe", a)?.resource.platform,
            (None, Some(a)) => self.container_recipe_for(ctx, "GetContainerRecipe", a)?.resource.platform,
            _ => {
                return Err(invalid_combination(
                    "You must specify exactly one of 'imageRecipeArn' and 'containerRecipeArn'.",
                ))
            }
        };
        if !self.with_region(ctx, |r| r.infrastructure.contains_key(f.infrastructure_configuration_arn)) {
            return Err(invalid_parameter_value(format!(
                "The infrastructure configuration '{}' does not exist.",
                f.infrastructure_configuration_arn
            )));
        }
        if let Some(d) = f.distribution_configuration_arn {
            if !self.with_region(ctx, |r| r.distributions.contains_key(d)) {
                return Err(invalid_parameter_value(format!("The distribution configuration '{d}' does not exist.")));
            }
        }
        if let Some(s) = f.schedule {
            parse_schedule(s)?;
        }
        if let Some(st) = f.status {
            if !matches!(st.as_str(), "ENABLED" | "DISABLED") {
                return Err(invalid_parameter_value(format!("The value '{st}' is not a valid pipeline status.")));
            }
        }
        self.check_workflows(f.workflows)?;
        self.pass_execution_role(ctx, f.execution_role)?;
        Ok(platform.unwrap_or_else(|| "Linux".into()))
    }

    pub(crate) async fn create_image_pipeline_op(
        &self,
        ctx: &RequestContext,
        input: t::CreateImagePipelineRequest,
    ) -> Result<t::CreateImagePipelineResponse, ServiceError> {
        let account = account_of(ctx);
        let target = arn(ctx, &account, &format!("image-pipeline/{}", slug(&input.name)));
        authorize(ctx, "CreateImagePipeline", &target, request_tags(&input.tags))?;
        if input.dry_run {
            return Err(crate::util::dry_run_ok());
        }
        let token = input.client_token.clone();
        self.idempotent(ctx, "CreateImagePipeline", &token, &input.clone(), async {
            if self.with_region(ctx, |r| r.pipelines.contains_key(&target)) {
                return Err(already_exists(&target));
            }
            let platform = self
                .check_pipeline(
                    ctx,
                    &PipelineFields {
                        image_recipe_arn: &input.image_recipe_arn,
                        container_recipe_arn: &input.container_recipe_arn,
                        infrastructure_configuration_arn: &input.infrastructure_configuration_arn,
                        distribution_configuration_arn: &input.distribution_configuration_arn,
                        schedule: &input.schedule,
                        status: &input.status,
                        workflows: &input.workflows,
                        execution_role: &input.execution_role,
                    },
                )
                .await?;
            let schedule = input.schedule.clone().map(|mut s| {
                if s.schedule_expression.is_some() && s.pipeline_execution_start_condition.is_none() {
                    s.pipeline_execution_start_condition =
                        Some("EXPRESSION_MATCH_AND_DEPENDENCY_UPDATES_AVAILABLE".into());
                }
                s
            });
            let status = input.status.clone().unwrap_or_else(|| "ENABLED".into());
            let pipeline = t::ImagePipeline {
                arn: Some(target.clone()),
                name: Some(input.name.clone()),
                description: input.description.clone(),
                platform: Some(platform),
                enhanced_image_metadata_enabled: Some(input.enhanced_image_metadata_enabled.unwrap_or(true)),
                image_recipe_arn: input.image_recipe_arn.clone(),
                container_recipe_arn: input.container_recipe_arn.clone(),
                infrastructure_configuration_arn: Some(input.infrastructure_configuration_arn.clone()),
                distribution_configuration_arn: input.distribution_configuration_arn.clone(),
                image_tests_configuration: Some(input.image_tests_configuration.clone().unwrap_or(
                    t::ImageTestsConfiguration { image_tests_enabled: Some(true), timeout_minutes: Some(720) },
                )),
                date_next_run: schedule
                    .as_ref()
                    .filter(|_| status == "ENABLED")
                    .and_then(|s| next_run(s, ctx.received_at, ctx.received_at)),
                schedule,
                status: Some(status),
                date_created: Some(now(ctx)),
                date_updated: None,
                date_last_run: None,
                last_run_status: None,
                tags: Some(input.tags.clone().unwrap_or_default()),
                image_scanning_configuration: input.image_scanning_configuration.clone(),
                image_tags: input.image_tags.clone(),
                execution_role: input.execution_role.clone(),
                workflows: input.workflows.clone(),
                logging_configuration: input.logging_configuration.clone(),
                consecutive_failures: Some(0),
            };
            self.with_region(ctx, |r| {
                if r.pipelines.contains_key(&target) {
                    return Err(already_exists(&target));
                }
                r.pipelines.insert(target.clone(), Pipeline { pipeline, schedule_checked: Some(ctx.received_at) });
                Ok(())
            })?;
            Ok(t::CreateImagePipelineResponse {
                request_id: Some(ctx.request_id.clone()),
                client_token: Some(token.clone()),
                image_pipeline_arn: Some(target.clone()),
            })
        })
        .await
    }

    pub(crate) async fn update_image_pipeline_op(
        &self,
        ctx: &RequestContext,
        input: t::UpdateImagePipelineRequest,
    ) -> Result<t::UpdateImagePipelineResponse, ServiceError> {
        let target = input.image_pipeline_arn.clone();
        let existing = self.with_region(ctx, |r| r.pipelines.get(&target).cloned());
        authorize(
            ctx,
            "UpdateImagePipeline",
            &target,
            resource_tags(&existing.as_ref().and_then(|p| p.pipeline.tags.clone())),
        )?;
        let token = input.client_token.clone();
        self.idempotent(ctx, "UpdateImagePipeline", &token, &input.clone(), async {
            let existing = existing.clone().ok_or_else(|| arn_not_found(&target))?;
            let platform = self
                .check_pipeline(
                    ctx,
                    &PipelineFields {
                        image_recipe_arn: &input.image_recipe_arn,
                        container_recipe_arn: &input.container_recipe_arn,
                        infrastructure_configuration_arn: &input.infrastructure_configuration_arn,
                        distribution_configuration_arn: &input.distribution_configuration_arn,
                        schedule: &input.schedule,
                        status: &input.status,
                        workflows: &input.workflows,
                        execution_role: &input.execution_role,
                    },
                )
                .await?;
            let schedule = input.schedule.clone().map(|mut s| {
                if s.schedule_expression.is_some() && s.pipeline_execution_start_condition.is_none() {
                    s.pipeline_execution_start_condition =
                        Some("EXPRESSION_MATCH_AND_DEPENDENCY_UPDATES_AVAILABLE".into());
                }
                s
            });
            let status = input.status.clone().unwrap_or_else(|| "ENABLED".into());
            let p = existing.pipeline;
            let updated = t::ImagePipeline {
                description: input.description.clone(),
                platform: Some(platform),
                enhanced_image_metadata_enabled: Some(input.enhanced_image_metadata_enabled.unwrap_or(true)),
                image_recipe_arn: input.image_recipe_arn.clone(),
                container_recipe_arn: input.container_recipe_arn.clone(),
                infrastructure_configuration_arn: Some(input.infrastructure_configuration_arn.clone()),
                distribution_configuration_arn: input.distribution_configuration_arn.clone(),
                image_tests_configuration: Some(input.image_tests_configuration.clone().unwrap_or(
                    t::ImageTestsConfiguration { image_tests_enabled: Some(true), timeout_minutes: Some(720) },
                )),
                date_next_run: schedule
                    .as_ref()
                    .filter(|_| status == "ENABLED")
                    .and_then(|s| next_run(s, ctx.received_at, ctx.received_at)),
                schedule,
                status: Some(status),
                date_updated: Some(now(ctx)),
                image_scanning_configuration: input.image_scanning_configuration.clone(),
                image_tags: input.image_tags.clone(),
                execution_role: input.execution_role.clone(),
                workflows: input.workflows.clone(),
                logging_configuration: input.logging_configuration.clone(),
                ..p
            };
            self.with_region(ctx, |r| {
                r.pipelines
                    .insert(target.clone(), Pipeline { pipeline: updated, schedule_checked: Some(ctx.received_at) })
            });
            Ok(t::UpdateImagePipelineResponse {
                request_id: Some(ctx.request_id.clone()),
                client_token: Some(token.clone()),
                image_pipeline_arn: Some(target.clone()),
            })
        })
        .await
    }

    pub(crate) fn get_image_pipeline_op(
        &self,
        ctx: &RequestContext,
        input: t::GetImagePipelineRequest,
    ) -> Result<t::GetImagePipelineResponse, ServiceError> {
        let target = input.image_pipeline_arn.clone();
        let found = self.with_region(ctx, |r| r.pipelines.get(&target).cloned());
        authorize(
            ctx,
            "GetImagePipeline",
            &target,
            resource_tags(&found.as_ref().and_then(|p| p.pipeline.tags.clone())),
        )?;
        let p = found.ok_or_else(|| arn_not_found(&target))?;
        Ok(t::GetImagePipelineResponse { request_id: Some(ctx.request_id.clone()), image_pipeline: Some(p.pipeline) })
    }

    pub(crate) fn list_image_pipelines_op(
        &self,
        ctx: &RequestContext,
        input: t::ListImagePipelinesRequest,
    ) -> Result<t::ListImagePipelinesResponse, ServiceError> {
        authorize(ctx, "ListImagePipelines", &arn(ctx, &account_of(ctx), "image-pipeline/*"), ConditionContext::new())?;
        let all: Vec<t::ImagePipeline> =
            self.with_region(ctx, |r| r.pipelines.values().map(|p| p.pipeline.clone()).collect());
        let mut out = Vec::new();
        for p in all {
            let ok = filters_match(
                &input.filters,
                &[
                    "description",
                    "distributionConfigurationArn",
                    "imageRecipeArn",
                    "infrastructureConfigurationArn",
                    "name",
                    "status",
                ],
                |n| match n {
                    "description" => s(&p.description),
                    "distributionConfigurationArn" => s(&p.distribution_configuration_arn),
                    "imageRecipeArn" => s(&p.image_recipe_arn),
                    "infrastructureConfigurationArn" => s(&p.infrastructure_configuration_arn),
                    "name" => s(&p.name),
                    _ => s(&p.status),
                },
            )?;
            if ok {
                out.push(p);
            }
        }
        let (page, next_token) = paginate(out, input.max_results, &input.next_token)?;
        Ok(t::ListImagePipelinesResponse {
            request_id: Some(ctx.request_id.clone()),
            image_pipeline_list: Some(page),
            next_token,
        })
    }

    pub(crate) fn delete_image_pipeline_op(
        &self,
        ctx: &RequestContext,
        input: t::DeleteImagePipelineRequest,
    ) -> Result<t::DeleteImagePipelineResponse, ServiceError> {
        let target = input.image_pipeline_arn.clone();
        let found = self.with_region(ctx, |r| r.pipelines.get(&target).map(|p| p.pipeline.tags.clone()));
        authorize(ctx, "DeleteImagePipeline", &target, resource_tags(&found.clone().flatten()))?;
        if found.is_none() {
            return Err(arn_not_found(&target));
        }
        self.with_region(ctx, |r| r.pipelines.remove(&target));
        Ok(t::DeleteImagePipelineResponse {
            request_id: Some(ctx.request_id.clone()),
            image_pipeline_arn: Some(target),
        })
    }

    fn pipeline_build_request(
        p: &t::ImagePipeline,
        build_type: &'static str,
        extra_tags: Option<std::collections::BTreeMap<String, String>>,
        token: Option<String>,
    ) -> BuildRequest {
        let mut tags = p.image_tags.clone().unwrap_or_default();
        tags.extend(extra_tags.unwrap_or_default());
        BuildRequest {
            image_recipe_arn: p.image_recipe_arn.clone(),
            container_recipe_arn: p.container_recipe_arn.clone(),
            infrastructure_configuration_arn: p.infrastructure_configuration_arn.clone().unwrap_or_default(),
            distribution_configuration_arn: p.distribution_configuration_arn.clone(),
            image_tests_configuration: p.image_tests_configuration.clone(),
            enhanced_image_metadata_enabled: p.enhanced_image_metadata_enabled,
            tags: Some(tags),
            image_scanning_configuration: p.image_scanning_configuration.clone(),
            workflows: p.workflows.clone(),
            execution_role: p.execution_role.clone(),
            log_group_name: p.logging_configuration.as_ref().and_then(|l| l.image_log_group_name.clone()),
            pipeline: Some((p.arn.clone().unwrap_or_default(), p.name.clone().unwrap_or_default())),
            build_type,
            client_token: token,
        }
    }

    pub(crate) async fn start_image_pipeline_execution_op(
        &self,
        ctx: &RequestContext,
        input: t::StartImagePipelineExecutionRequest,
    ) -> Result<t::StartImagePipelineExecutionResponse, ServiceError> {
        let target = input.image_pipeline_arn.clone();
        let found = self.with_region(ctx, |r| r.pipelines.get(&target).cloned());
        authorize(
            ctx,
            "StartImagePipelineExecution",
            &target,
            crate::util::merge(
                resource_tags(&found.as_ref().and_then(|p| p.pipeline.tags.clone())),
                request_tags(&input.tags),
            ),
        )?;
        let token = input.client_token.clone();
        self.idempotent(ctx, "StartImagePipelineExecution", &token, &input.clone(), async {
            let p = found
                .clone()
                .ok_or_else(|| not_found(format!("The image pipeline '{target}' does not exist.")))?
                .pipeline;
            let image_arn = self
                .start_build(
                    ctx,
                    Self::pipeline_build_request(&p, "USER_INITIATED", input.tags.clone(), Some(token.clone())),
                )
                .await?;
            self.with_region(ctx, |r| {
                if let Some(p) = r.pipelines.get_mut(&target) {
                    p.pipeline.date_last_run = Some(now(ctx));
                    p.pipeline.last_run_status = Some("PENDING".into());
                }
            });
            Ok(t::StartImagePipelineExecutionResponse {
                request_id: Some(ctx.request_id.clone()),
                client_token: Some(token.clone()),
                image_build_version_arn: Some(image_arn),
            })
        })
        .await
    }

    /// Record a pipeline build's outcome: last run status, consecutive
    /// failures, and auto-disable.
    pub(crate) fn pipeline_build_finished(&self, account: &str, region: &str, image: &t::Image, status: &str) {
        let Some(arn) = image.source_pipeline_arn.clone() else { return };
        self.with_region_of(account, region, |r| {
            let Some(p) = r.pipelines.get_mut(&arn) else { return };
            p.pipeline.last_run_status = Some(status.to_string());
            let failures = p.pipeline.consecutive_failures.unwrap_or(0);
            match status {
                "AVAILABLE" => p.pipeline.consecutive_failures = Some(0),
                "FAILED" => {
                    let n = failures + 1;
                    p.pipeline.consecutive_failures = Some(n);
                    let limit = p
                        .pipeline
                        .schedule
                        .as_ref()
                        .and_then(|s| s.auto_disable_policy.as_ref())
                        .map(|a| a.failure_count);
                    if limit.is_some_and(|l| n >= l) {
                        p.pipeline.status = Some("DISABLED".into());
                        p.pipeline.date_next_run = None;
                    }
                }
                _ => {}
            }
        });
    }

    /// Start the builds whose schedule came due on the emulated clock.
    pub(crate) async fn fire_pipeline_schedules(&self, template: &RequestContext) {
        let now = self.now();
        let mut due: Vec<(String, String, t::ImagePipeline)> = Vec::new();
        {
            let mut st = self.lock();
            for (key, r) in st.regions.iter_mut() {
                let Some((account, region)) = key.split_once('/') else { continue };
                for p in r.pipelines.values_mut() {
                    let checked = p.schedule_checked.unwrap_or(now);
                    p.schedule_checked = Some(now);
                    if p.pipeline.status.as_deref() != Some("ENABLED") {
                        continue;
                    }
                    let Some(schedule) = p.pipeline.schedule.clone() else { continue };
                    let Ok(Some(parsed)) = parse_schedule(&schedule) else { continue };
                    if parsed.fires_between(checked, checked, now, 1).is_empty() {
                        continue;
                    }
                    p.pipeline.date_next_run = next_run(&schedule, now, now);
                    due.push((account.to_string(), region.to_string(), p.pipeline.clone()));
                }
            }
        }
        for (account, region, p) in due {
            let ctx = self.service_ctx(template, &account, &region);
            let condition =
                p.schedule.as_ref().and_then(|s| s.pipeline_execution_start_condition.clone()).unwrap_or_default();
            if condition == "EXPRESSION_MATCH_AND_DEPENDENCY_UPDATES_AVAILABLE"
                && !self.dependencies_changed(&ctx, &p).await
            {
                continue;
            }
            let req = Self::pipeline_build_request(&p, "SCHEDULED", None, None);
            match self.start_build(&ctx, req).await {
                Ok(_) => self.with_region_of(&account, &region, |r| {
                    if let Some(x) = r.pipelines.get_mut(p.arn.as_deref().unwrap_or_default()) {
                        x.pipeline.date_last_run = Some(date(now));
                        x.pipeline.last_run_status = Some("PENDING".into());
                    }
                }),
                Err(e) => {
                    tracing::warn!(pipeline = ?p.arn, error = %e.message, "scheduled Image Builder build did not start")
                }
            }
        }
    }

    /// Whether the pipeline's recipe now resolves to a different parent
    /// image or component versions than its last successful build.
    async fn dependencies_changed(&self, ctx: &RequestContext, p: &t::ImagePipeline) -> bool {
        let arn = p.arn.clone().unwrap_or_default();
        let last = self.with_region(ctx, |r| {
            r.images
                .values()
                .filter(|i| i.image.source_pipeline_arn.as_deref() == Some(arn.as_str()))
                .filter(|i| crate::images::status_of(&i.image) == "AVAILABLE")
                .max_by(|a, b| a.image.date_created.cmp(&b.image.date_created))
                .map(|i| i.resolved_inputs.clone())
        });
        let Some(last) = last else { return true };
        let Some(recipe_arn) = &p.image_recipe_arn else { return true };
        let Some(recipe) = self.with_region(ctx, |r| r.image_recipes.get(recipe_arn).cloned()) else { return true };
        let parent =
            match self.resolve_parent(ctx, recipe.resource.parent_image.as_deref().unwrap_or_default(), true).await {
                Ok(p) => p.ami.unwrap_or_default(),
                Err(_) => return true,
            };
        let mut now = vec![parent];
        for c in recipe.resource.components.iter().flatten() {
            match self.resolve_component(&c.component_arn) {
                Some(f) => now.push(f.component.arn.unwrap_or_default()),
                None => return true,
            }
        }
        now != last
    }
}

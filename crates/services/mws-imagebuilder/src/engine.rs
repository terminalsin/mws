//! The build engine: runs an image's workflows step by step against EC2,
//! then distributes the output.

use std::collections::BTreeMap;
use std::time::Duration;

use base64::Engine;
use mws_core::RequestContext;
use serde_json::{json, Value};

use crate::components::component_parameters;
use crate::generated::types as t;
use crate::images::{status_of, ACTIVE_STATES};
use crate::state::{StepExecution, WorkflowExecution};
use crate::toe::Document;
use crate::util::{date, Arn};
use crate::workflows::{StepDef, WorkflowDocument};
use crate::{distribution, ec2link, managed, ImageBuilder, ImageStateChange};

/// Why a build stopped.
#[derive(Debug, Clone)]
struct Failure {
    status: &'static str,
    reason: String,
    context: Option<Box<t::ImageFailureContext>>,
}

impl Failure {
    fn failed(reason: impl Into<String>) -> Failure {
        Failure { status: "FAILED", reason: reason.into(), context: None }
    }

    fn cancelled() -> Failure {
        Failure { status: "CANCELLED", reason: "Image creation cancelled by the user.".into(), context: None }
    }
}

/// A component as a build runs it.
struct Component {
    arn: String,
    doc: Document,
    params: BTreeMap<String, String>,
}

/// What one build knows while it runs.
struct Build {
    /// The caller's context (or the pipeline owner's, for scheduled runs).
    caller: RequestContext,
    /// Image Builder's service-linked role in the image's account.
    svc: RequestContext,
    account: String,
    region: String,
    arn: String,
    image: t::Image,
    parent_ami: Option<String>,
    components: Vec<Component>,
    log: Vec<(chrono::DateTime<chrono::Utc>, String)>,
}

impl Build {
    fn note(&mut self, msg: impl Into<String>) {
        self.log.push((chrono::Utc::now(), msg.into()));
    }

    fn infra(&self) -> t::InfrastructureConfiguration {
        self.image.infrastructure_configuration.clone().unwrap_or_default()
    }

    fn build_date(&self) -> String {
        let at = self
            .image
            .date_created
            .as_deref()
            .and_then(|d| chrono::DateTime::parse_from_rfc3339(d).ok())
            .map(|d| d.with_timezone(&chrono::Utc))
            .unwrap_or_else(chrono::Utc::now);
        at.format("%Y-%m-%dT%H-%M-%S%.3fZ").to_string()
    }

    fn build_number(&self) -> u32 {
        Arn::parse(&self.arn).and_then(|a| a.build).unwrap_or(1)
    }

    fn working_directory(&self) -> String {
        self.image
            .image_recipe
            .as_ref()
            .and_then(|r| r.working_directory.clone())
            .or_else(|| self.image.container_recipe.as_ref().and_then(|r| r.working_directory.clone()))
            .unwrap_or_else(|| "/tmp".into())
    }

    /// The distribution entry for `region`, if any.
    fn distribution_for(&self, region: &str) -> Option<t::Distribution> {
        self.image
            .distribution_configuration
            .as_ref()
            .and_then(|d| d.distributions.as_ref())
            .and_then(|d| d.iter().find(|x| x.region == region).cloned())
    }

    /// The output AMI's name in `region`.
    fn ami_name(&self, region: &str) -> String {
        match self.distribution_for(region).and_then(|d| d.ami_distribution_configuration).and_then(|a| a.name) {
            Some(n) => distribution::render_ami_name(&n, &self.build_date(), self.build_number()),
            None => format!("{} {}", self.image.name.clone().unwrap_or_default(), self.build_date()),
        }
    }

    fn ami_description(&self, region: &str) -> Option<String> {
        self.distribution_for(region)
            .and_then(|d| d.ami_distribution_configuration)
            .and_then(|a| a.description)
            .or_else(|| self.image.image_recipe.as_ref().and_then(|r| r.description.clone()))
    }

    /// Tags Image Builder puts on what it creates.
    fn standard_tags(&self) -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert("Ec2ImageBuilderArn".to_string(), self.arn.clone());
        m.insert("CreatedBy".to_string(), "EC2 Image Builder".to_string());
        m
    }
}

impl ImageBuilder {
    /// Start an image's build in the background.
    pub(crate) fn spawn_build(&self, ctx: &RequestContext, account: &str, region: &str, arn: &str) {
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let me = self.clone();
        let (ctx, account, region, arn) = (ctx.clone(), account.to_string(), region.to_string(), arn.to_string());
        tokio::spawn(async move { me.run_build(ctx, account, region, arn).await });
    }

    fn image_record(&self, account: &str, region: &str, arn: &str) -> Option<crate::state::ImageRecord> {
        self.with_region_of(account, region, |r| r.images.get(arn).cloned())
    }

    fn cancelled(&self, b: &Build) -> bool {
        self.image_record(&b.account, &b.region, &b.arn).is_none_or(|r| r.cancel_requested)
    }

    /// Move the image to `status` (unless it was cancelled meanwhile).
    fn set_status(&self, b: &Build, status: &str) -> Result<(), Failure> {
        let previous = self.with_region_of(&b.account, &b.region, |r| {
            let rec = r.images.get_mut(&b.arn)?;
            if rec.cancel_requested {
                return None;
            }
            let prev = status_of(&rec.image).to_string();
            rec.image.state = Some(t::ImageState { status: Some(status.into()), ..Default::default() });
            Some(prev)
        });
        match previous {
            Some(prev) => {
                self.emit_state_change(&b.svc, &b.account, &b.region, &b.arn, Some(prev), status, None);
                Ok(())
            }
            None => Err(Failure::cancelled()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn emit_state_change(
        &self,
        ctx: &RequestContext,
        account: &str,
        region: &str,
        arn: &str,
        previous: Option<String>,
        status: &str,
        reason: Option<String>,
    ) {
        if let Some(events) = self.events() {
            events.image_state_changed(
                ctx,
                &ImageStateChange {
                    partition: ctx.partition.clone(),
                    account: account.to_string(),
                    region: region.to_string(),
                    image_build_version_arn: arn.to_string(),
                    previous_status: previous,
                    status: status.to_string(),
                    reason,
                    time: self.now(),
                },
            );
        }
    }

    async fn run_build(&self, ctx: RequestContext, account: String, region: String, arn: String) {
        let Some(rec) = self.image_record(&account, &region, &arn) else { return };
        let svc = self.service_ctx(&ctx, &account, &region);
        let mut b = Build {
            caller: ctx,
            svc,
            account,
            region,
            arn,
            image: rec.image.clone(),
            parent_ami: None,
            components: Vec::new(),
            log: Vec::new(),
        };
        b.note(format!("Build of {} started", b.arn));
        let result = self.run_stages(&mut b).await;
        // Clean up what is still running.
        let rec = self.image_record(&b.account, &b.region, &b.arn).unwrap_or_default();
        let keep_on_failure = b.infra().terminate_instance_on_failure == Some(false);
        if result.is_ok() || !keep_on_failure {
            if let Some(ec2) = self.ec2() {
                for i in &rec.live_instances {
                    let _ = ec2link::terminate(ec2, &b.svc, i).await;
                }
            }
            self.with_region_of(&b.account, &b.region, |r| {
                if let Some(rec) = r.images.get_mut(&b.arn) {
                    rec.live_instances.clear();
                }
            });
        }
        let (status, reason) = match &result {
            Ok(()) => ("AVAILABLE", None),
            Err(f) => (f.status, Some(f.reason.clone())),
        };
        b.note(format!("Build finished: {status}{}", reason.as_ref().map(|r| format!(" ({r})")).unwrap_or_default()));
        let previous = self.with_region_of(&b.account, &b.region, |r| {
            let rec = r.images.get_mut(&b.arn)?;
            let prev = status_of(&rec.image).to_string();
            if rec.cancel_requested && status != "CANCELLED" {
                // CancelImageCreation already recorded the outcome.
                return None;
            }
            rec.image.state = Some(t::ImageState {
                status: Some(status.into()),
                reason: reason.clone(),
                failure_context: result.as_ref().err().and_then(|f| f.context.clone().map(|c| *c)),
            });
            Some(prev)
        });
        if let Some(prev) = previous {
            if prev != status {
                self.emit_state_change(&b.svc, &b.account, &b.region, &b.arn, Some(prev), status, reason.clone());
            }
        }
        let final_status = self
            .image_record(&b.account, &b.region, &b.arn)
            .map(|r| status_of(&r.image).to_string())
            .unwrap_or_else(|| status.to_string());
        self.pipeline_build_finished(&b.account, &b.region, &b.image, &final_status);
        self.notify_sns(&b, &final_status).await;
        self.write_logs(&b).await;
    }

    async fn run_stages(&self, b: &mut Build) -> Result<(), Failure> {
        let rec = self.image_record(&b.account, &b.region, &b.arn).ok_or_else(Failure::cancelled)?;
        // Distribution-only builds (DistributeImage).
        if rec.resolved_inputs.first().is_some_and(|i| i.starts_with("distribute:")) {
            self.set_status(b, "DISTRIBUTING")?;
            let ami = rec.build_ami.clone().ok_or_else(|| Failure::failed("The source image has no AMI."))?;
            let out = self.distribute(b, &ami).await?;
            self.set_outputs(b, out, None);
            self.set_status(b, "INTEGRATING")?;
            return Ok(());
        }
        if b.image.build_type.as_deref() == Some("IMPORT_ISO") {
            return self.import_iso(b).await;
        }
        self.set_status(b, "CREATING")?;
        let ec2 = self.ec2().ok_or_else(|| Failure::failed("EC2 is not available to run builds."))?.clone();
        let container = b.image.container_recipe.is_some();
        // Resolve the parent image and components now, as AWS does.
        if let Some(recipe) = b.image.image_recipe.clone() {
            let caller = b.caller.clone();
            let parent = self
                .resolve_parent(&caller, recipe.parent_image.as_deref().unwrap_or_default(), true)
                .await
                .map_err(|e| Failure::failed(e.message))?;
            b.parent_ami =
                Some(parent.ami.ok_or_else(|| Failure::failed("The parent image could not be resolved to an AMI."))?);
        } else if let Some(cr) = &b.image.container_recipe {
            // Container builds run on the instance image the recipe names,
            // else on the ECS-optimized Amazon Linux 2023 AMI.
            let ami = match cr.instance_configuration.as_ref().and_then(|i| i.image.clone()) {
                Some(i) => {
                    let caller = b.caller.clone();
                    self.resolve_parent(&caller, &i, true).await.map_err(|e| Failure::failed(e.message))?.ami
                }
                None => {
                    ec2link::public_image_by_name(&ec2, &b.svc, "al2023-ami-ecs-hvm-2023.0.20250101-kernel-6.1-x86_64")
                        .await
                }
            };
            b.parent_ami =
                Some(ami.ok_or_else(|| Failure::failed("The instance image could not be resolved to an AMI."))?);
        }
        let configs = b
            .image
            .image_recipe
            .as_ref()
            .and_then(|r| r.components.clone())
            .or_else(|| b.image.container_recipe.as_ref().and_then(|r| r.components.clone()))
            .unwrap_or_default();
        let mut resolved = vec![b.parent_ami.clone().unwrap_or_default()];
        for c in &configs {
            let found = self
                .resolve_component(&c.component_arn)
                .ok_or_else(|| Failure::failed(format!("The component '{}' does not exist.", c.component_arn)))?;
            let arn = found.component.arn.clone().unwrap_or_default();
            let doc = Document::parse(found.component.data.as_deref().unwrap_or_default())
                .map_err(|e| Failure::failed(format!("The component '{arn}' is not valid: {e}")))?;
            resolved.push(arn.clone());
            b.components.push(Component { arn, doc, params: component_parameters(c) });
        }
        self.with_region_of(&b.account, &b.region, |r| {
            if let Some(rec) = r.images.get_mut(&b.arn) {
                rec.resolved_inputs = resolved.clone();
            }
        });

        // Build.
        self.set_status(b, "BUILDING")?;
        for (wf, cfg) in self.workflows_of(b, "BUILD", container) {
            self.run_workflow(b, &ec2, &wf, &cfg).await?;
        }
        let ami = self.image_record(&b.account, &b.region, &b.arn).and_then(|r| r.build_ami).filter(|_| !container);
        if !container && ami.is_none() {
            return Err(Failure::failed("The build workflow did not create an image."));
        }

        // Test.
        let tests_enabled =
            b.image.image_tests_configuration.as_ref().and_then(|t| t.image_tests_enabled).unwrap_or(true);
        if tests_enabled {
            self.set_status(b, "TESTING")?;
            for (wf, cfg) in self.workflows_of(b, "TEST", container) {
                self.run_workflow(b, &ec2, &wf, &cfg).await?;
            }
        }

        // Distribute.
        self.set_status(b, "DISTRIBUTING")?;
        if container {
            let containers = self.container_outputs(b);
            self.set_outputs(b, Vec::new(), Some(containers));
        } else {
            let distribution_workflows = self.workflows_of(b, "DISTRIBUTION", container);
            if distribution_workflows.is_empty() {
                let out = self.distribute(b, ami.as_deref().unwrap_or_default()).await?;
                self.set_outputs(b, out, None);
            } else {
                for (wf, cfg) in distribution_workflows {
                    self.run_workflow(b, &ec2, &wf, &cfg).await?;
                }
            }
        }
        self.set_status(b, "INTEGRATING")?;
        Ok(())
    }

    /// The workflows of `kind` a build runs: the ones it names, else the
    /// AWS-managed default (none for distribution).
    fn workflows_of(&self, b: &Build, kind: &str, container: bool) -> Vec<(t::Workflow, t::WorkflowConfiguration)> {
        let named: Vec<(t::Workflow, t::WorkflowConfiguration)> = b
            .image
            .workflows
            .iter()
            .flatten()
            .filter_map(|c| self.resolve_workflow(&c.workflow_arn).map(|w| (w, c.clone())))
            .filter(|(w, _)| w.r#type.as_deref() == Some(kind))
            .collect();
        if !named.is_empty() || kind == "DISTRIBUTION" {
            return named;
        }
        let w = managed::default_workflow(&b.svc.partition, &b.region, &kind.to_lowercase(), container);
        let cfg = t::WorkflowConfiguration { workflow_arn: w.arn.clone().unwrap_or_default(), ..Default::default() };
        vec![(w, cfg)]
    }

    fn set_outputs(&self, b: &Build, amis: Vec<t::Ami>, containers: Option<Vec<t::Container>>) {
        self.with_region_of(&b.account, &b.region, |r| {
            if let Some(rec) = r.images.get_mut(&b.arn) {
                rec.image.output_resources = Some(t::OutputResources {
                    amis: (!amis.is_empty()).then_some(amis.clone()),
                    containers: containers.clone(),
                });
            }
        });
    }

    async fn run_workflow(
        &self,
        b: &mut Build,
        ec2: &ec2link::Ec2,
        wf: &t::Workflow,
        cfg: &t::WorkflowConfiguration,
    ) -> Result<(), Failure> {
        let wf_arn = wf.arn.clone().unwrap_or_default();
        let kind = wf.r#type.clone().unwrap_or_else(|| "BUILD".into());
        let doc = WorkflowDocument::parse(wf.data.as_deref().unwrap_or_default())
            .map_err(|e| Failure::failed(format!("The workflow '{wf_arn}' is not valid: {e}")))?;
        let mut params: BTreeMap<String, Value> = BTreeMap::new();
        for p in &doc.parameters {
            if let Some(d) = &p.default_value {
                params.insert(p.name.clone(), param_value(&p.r#type, d));
            }
        }
        for p in cfg.parameters.iter().flatten() {
            let ty = doc.parameters.iter().find(|d| d.name == p.name).map(|d| d.r#type.clone()).unwrap_or_default();
            params.insert(p.name.clone(), param_value(&ty, &p.value));
        }
        let exec_id = format!("wf-{}", uuid::Uuid::new_v4());
        let retried = self
            .image_record(&b.account, &b.region, &b.arn)
            .is_some_and(|r| !r.workflow_executions.is_empty() && r.image.state.is_some());
        let mut step_ids = Vec::new();
        self.with_region_of(&b.account, &b.region, |r| {
            for s in &doc.steps {
                let id = format!("step-{}", uuid::Uuid::new_v4());
                r.step_executions.insert(
                    id.clone(),
                    StepExecution {
                        metadata: t::WorkflowStepMetadata {
                            step_execution_id: Some(id.clone()),
                            name: Some(s.name.clone()),
                            description: s.description.clone(),
                            action: Some(s.action.clone()),
                            status: Some("PENDING".into()),
                            rollback_status: None,
                            attempt_number: Some(0),
                            max_attempts: Some(1),
                            ..Default::default()
                        },
                        workflow_execution_id: exec_id.clone(),
                        workflow_build_version_arn: wf_arn.clone(),
                        image_build_version_arn: b.arn.clone(),
                        on_failure: Some(s.on_failure.clone()),
                        timeout_seconds: s.timeout_seconds,
                        ..Default::default()
                    },
                );
                step_ids.push(id);
            }
            r.workflow_executions.insert(
                exec_id.clone(),
                WorkflowExecution {
                    metadata: t::WorkflowExecutionMetadata {
                        workflow_build_version_arn: Some(wf_arn.clone()),
                        workflow_execution_id: Some(exec_id.clone()),
                        r#type: Some(kind.clone()),
                        status: Some("RUNNING".into()),
                        message: None,
                        total_step_count: doc.steps.len() as i32,
                        start_time: Some(date(self.now())),
                        parallel_group: cfg.parallel_group.clone(),
                        retried: Some(retried),
                        ..Default::default()
                    },
                    image_build_version_arn: b.arn.clone(),
                    steps: step_ids.clone(),
                },
            );
            if let Some(rec) = r.images.get_mut(&b.arn) {
                rec.workflow_executions.push(exec_id.clone());
            }
        });
        b.note(format!("Workflow {wf_arn} ({kind}) started: {exec_id}"));

        let mut outputs: BTreeMap<String, Value> = BTreeMap::new();
        let mut failure: Option<Failure> = None;
        let (mut ok, mut failed, mut skipped) = (0, 0, 0);
        for (step, id) in doc.steps.iter().zip(&step_ids) {
            if self.cancelled(b) {
                failure = Some(Failure::cancelled());
                break;
            }
            let root = json!({
                "stepOutputs": outputs,
                "parameters": params,
                "imageBuildVersionArn": b.arn,
            });
            let inputs = resolve_inputs(&step.inputs, &root);
            if let Some(cond) = &step.condition {
                if !condition_holds(cond, &root) {
                    skipped += 1;
                    self.update_step(b, id, |m| {
                        m.status = Some("SKIPPED".into());
                    });
                    continue;
                }
            }
            let started = date(self.now());
            self.update_step(b, id, |m| {
                m.status = Some("RUNNING".into());
                m.start_time = Some(started.clone());
                m.inputs = Some(inputs.to_string());
                m.attempt_number = Some(1);
            });
            let result = self.run_step(b, ec2, &kind, step, id, &inputs).await;
            let ended = date(self.now());
            match result {
                Ok(out) => {
                    ok += 1;
                    self.update_step(b, id, |m| {
                        m.status = Some("COMPLETED".into());
                        m.end_time = Some(ended.clone());
                        m.outputs = Some(out.to_string());
                        m.message = Some("Step completed successfully.".into());
                    });
                    outputs.insert(step.name.clone(), out);
                }
                Err(mut f) => {
                    failed += 1;
                    let cancelled = f.status == "CANCELLED";
                    self.update_step(b, id, |m| {
                        m.status = Some(if cancelled { "CANCELLED" } else { "FAILED" }.into());
                        m.end_time = Some(ended.clone());
                        m.message = Some(f.reason.clone());
                    });
                    b.note(format!("Step {} failed: {}", step.name, f.reason));
                    if step.on_failure == "Abort" || cancelled {
                        let ctx = f.context.get_or_insert_with(Default::default);
                        ctx.image_status = Some(status_of(&b.image).to_string());
                        ctx.workflow_execution_id = Some(exec_id.clone());
                        ctx.workflow_arn = Some(wf_arn.clone());
                        ctx.step_execution_id = Some(id.clone());
                        ctx.failed_step = Some(step.name.clone());
                        if !cancelled {
                            f.reason = format!(
                                "Workflow Execution ID: '{exec_id}' failed with reason: Step '{}' failed: {}",
                                step.name, f.reason
                            );
                        }
                        failure = Some(f);
                        break;
                    }
                }
            }
        }
        // Steps never reached.
        let status = match &failure {
            None => "COMPLETED",
            Some(f) if f.status == "CANCELLED" => "CANCELLED",
            Some(_) => "FAILED",
        };
        let end = date(self.now());
        let message = failure.as_ref().map(|f| f.reason.clone());
        self.with_region_of(&b.account, &b.region, |r| {
            for id in &step_ids {
                if let Some(s) = r.step_executions.get_mut(id) {
                    if s.metadata.status.as_deref() == Some("PENDING") {
                        s.metadata.status = Some(if status == "CANCELLED" { "CANCELLED" } else { "SKIPPED" }.into());
                        skipped += 1;
                    }
                }
            }
            if let Some(e) = r.workflow_executions.get_mut(&exec_id) {
                e.metadata.status = Some(status.into());
                e.metadata.end_time = Some(end.clone());
                e.metadata.message = message.clone();
                e.metadata.total_steps_succeeded = ok;
                e.metadata.total_steps_failed = failed;
                e.metadata.total_steps_skipped = skipped;
            }
        });
        b.note(format!("Workflow {exec_id} {status}"));
        match failure {
            Some(f) if f.status == "CANCELLED" => Err(f),
            Some(f) if cfg.on_failure.as_deref() != Some("CONTINUE") => Err(f),
            _ => Ok(()),
        }
    }

    fn update_step(&self, b: &Build, id: &str, f: impl FnOnce(&mut t::WorkflowStepMetadata)) {
        self.with_region_of(&b.account, &b.region, |r| {
            if let Some(s) = r.step_executions.get_mut(id) {
                f(&mut s.metadata);
            }
        });
    }

    async fn run_step(
        &self,
        b: &mut Build,
        ec2: &ec2link::Ec2,
        kind: &str,
        step: &StepDef,
        step_id: &str,
        inputs: &Value,
    ) -> Result<Value, Failure> {
        let instance_input = || {
            inputs
                .get("instanceId")
                .and_then(Value::as_str)
                .map(String::from)
                .ok_or_else(|| Failure::failed("The step input 'instanceId' is required."))
        };
        match step.action.as_str() {
            "LaunchInstance" => {
                let image = match inputs.get("imageIdOverride").and_then(Value::as_str) {
                    Some(i) => i.to_string(),
                    None if kind == "TEST" => self
                        .image_record(&b.account, &b.region, &b.arn)
                        .and_then(|r| r.build_ami)
                        .or_else(|| b.parent_ami.clone())
                        .ok_or_else(|| Failure::failed("There is no image to test."))?,
                    None => b.parent_ami.clone().ok_or_else(|| Failure::failed("The parent image is not resolved."))?,
                };
                let id = self.launch(b, ec2, kind, &image, inputs).await?;
                Ok(json!({ "instanceId": id }))
            }
            "ExecuteComponents" => {
                let instance = instance_input()?;
                let phases: &[&str] = if kind == "TEST" { &["test"] } else { &["build", "validate"] };
                self.execute_components(b, &instance, phases).await?;
                Ok(json!({ "runCommandId": format!("{:x}", uuid::Uuid::new_v4().as_u128()) }))
            }
            "CollectImageMetadata" => {
                let instance = instance_input()?;
                if b.image.enhanced_image_metadata_enabled != Some(false) {
                    self.collect_packages(b, &instance).await;
                }
                Ok(json!({}))
            }
            "CreateImage" => {
                let instance = instance_input()?;
                let name = b.ami_name(&b.region.clone());
                let mut tags = b.standard_tags();
                if let Some(r) = &b.image.image_recipe {
                    tags.extend(r.ami_tags.clone().unwrap_or_default());
                }
                if let Some(a) = b.distribution_for(&b.region.clone()).and_then(|d| d.ami_distribution_configuration) {
                    tags.extend(a.ami_tags.unwrap_or_default());
                }
                let desc = b.ami_description(&b.region.clone());
                let ami = ec2link::create_image(ec2, &b.svc, &instance, &name, desc, &tags)
                    .await
                    .map_err(|e| Failure::failed(format!("CreateImage failed: {}", e.message)))?;
                ec2link::wait_available(ec2, &b.svc, &ami).await.map_err(Failure::failed)?;
                self.with_region_of(&b.account, &b.region, |r| {
                    if let Some(rec) = r.images.get_mut(&b.arn) {
                        rec.build_ami = Some(ami.clone());
                    }
                });
                b.note(format!("Created AMI {ami} ({name})"));
                Ok(json!({ "imageId": ami }))
            }
            "TerminateInstance" => {
                let instance = instance_input()?;
                if b.infra().terminate_instance_on_completion != Some(false) {
                    ec2link::terminate(ec2, &b.svc, &instance)
                        .await
                        .map_err(|e| Failure::failed(format!("TerminateInstances failed: {}", e.message)))?;
                    self.with_region_of(&b.account, &b.region, |r| {
                        if let Some(rec) = r.images.get_mut(&b.arn) {
                            rec.live_instances.retain(|i| i != &instance);
                        }
                    });
                }
                Ok(json!({}))
            }
            "RunCommand" => {
                let instance = instance_input()?;
                let document = inputs.get("documentName").and_then(Value::as_str).unwrap_or("AWS-RunShellScript");
                if document != "AWS-RunShellScript" {
                    return Err(Failure::failed(format!("The SSM document '{document}' is not supported by MWS.")));
                }
                let commands: Vec<String> = inputs["parameters"]["commands"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(crate::yaml::text)
                    .collect();
                let out = self.exec(b, &instance, &commands.join("\n")).await?;
                Ok(json!({ "runCommandId": format!("{:x}", uuid::Uuid::new_v4().as_u128()), "output": out }))
            }
            "WaitForAction" => self.wait_for_action(b, step_id).await,
            "DistributeImage" => {
                let ami = self
                    .image_record(&b.account, &b.region, &b.arn)
                    .and_then(|r| r.build_ami)
                    .ok_or_else(|| Failure::failed("There is no image to distribute."))?;
                let out = self.distribute(b, &ami).await?;
                self.set_outputs(b, out, None);
                Ok(json!({}))
            }
            // Steps with nothing to emulate beyond succeeding.
            _ => Ok(json!({})),
        }
    }

    async fn launch(
        &self,
        b: &mut Build,
        ec2: &ec2link::Ec2,
        kind: &str,
        image: &str,
        inputs: &Value,
    ) -> Result<String, Failure> {
        let infra = b.infra();
        let arch = ec2link::describe_image(ec2, &b.svc, image).await.and_then(|i| i.architecture).unwrap_or_default();
        let instance_type = inputs
            .get("instanceTypesOverride")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(Value::as_str)
            .map(String::from)
            .or_else(|| infra.instance_types.as_ref().and_then(|t| t.first().cloned()))
            .unwrap_or_else(|| if arch == "arm64" { "m6g.large" } else { "m5.large" }.into());
        let mut tags = infra.resource_tags.clone().unwrap_or_default();
        tags.extend(b.standard_tags());
        let what = if kind == "TEST" { "Test" } else { "Build" };
        tags.insert(
            "Name".into(),
            format!(
                "{what} instance for {} {}",
                b.image.name.clone().unwrap_or_default(),
                b.image.version.clone().unwrap_or_default()
            ),
        );
        let user_data = b
            .image
            .image_recipe
            .as_ref()
            .and_then(|r| r.additional_instance_configuration.as_ref())
            .and_then(|a| a.user_data_override.clone());
        let profile = infra.instance_profile_name.clone().unwrap_or_default();
        let id = ec2link::run_instance(
            ec2,
            &b.svc,
            ec2link::Launch {
                image_id: image,
                instance_type: &instance_type,
                subnet_id: infra.subnet_id.clone(),
                security_group_ids: infra.security_group_ids.clone(),
                key_name: infra.key_pair.clone(),
                instance_profile: &profile,
                user_data,
                tags,
                http_tokens: infra.instance_metadata_options.as_ref().and_then(|m| m.http_tokens.clone()),
                hop_limit: infra.instance_metadata_options.as_ref().and_then(|m| m.http_put_response_hop_limit),
                availability_zone: infra.placement.as_ref().and_then(|p| p.availability_zone.clone()),
                tenancy: infra.placement.as_ref().and_then(|p| p.tenancy.clone()),
            },
        )
        .await
        .map_err(|e| Failure::failed(format!("RunInstances failed: {}: {}", e.code, e.message)))?;
        self.with_region_of(&b.account, &b.region, |r| {
            if let Some(rec) = r.images.get_mut(&b.arn) {
                rec.live_instances.push(id.clone());
            }
        });
        b.note(format!("Launched {what} instance {id} from {image} ({instance_type})"));
        ec2link::wait_running(ec2, &b.svc, &id).await.map_err(Failure::failed)?;
        Ok(id)
    }

    /// Run a script on an instance as the SSM agent would. Metadata-only
    /// EC2 runs nothing, so every script succeeds there.
    async fn exec(&self, b: &mut Build, instance: &str, script: &str) -> Result<String, Failure> {
        let ec2 = self.ec2().ok_or_else(|| Failure::failed("EC2 is not available."))?;
        let wd = b.working_directory();
        let full =
            format!("mkdir -p {wd} 2>/dev/null; cd {wd} 2>/dev/null || true\n{script}", wd = crate::toe::sh_quote(&wd));
        match ec2.run_command_on_instance(&b.account, &b.region, instance, &full).await {
            Ok(None) => Ok(String::new()),
            Ok(Some(out)) => {
                let text = format!("{}{}", out.stdout, out.stderr);
                for line in text.lines().take(500) {
                    b.note(line.to_string());
                }
                if out.exit_code == 0 {
                    Ok(out.stdout)
                } else {
                    let tail: String = out
                        .stderr
                        .lines()
                        .rev()
                        .take(5)
                        .collect::<Vec<_>>()
                        .into_iter()
                        .rev()
                        .collect::<Vec<_>>()
                        .join("\n");
                    Err(Failure::failed(format!("exit status {}: {}", out.exit_code, tail.trim())))
                }
            }
            Err(e) => Err(Failure::failed(e)),
        }
    }

    async fn execute_components(&self, b: &mut Build, instance: &str, phases: &[&str]) -> Result<(), Failure> {
        let comps: Vec<(String, Document, BTreeMap<String, String>)> =
            b.components.iter().map(|c| (c.arn.clone(), c.doc.clone(), c.params.clone())).collect();
        for (arn, doc, params) in comps {
            for phase in phases {
                let steps = doc.plan(phase, &params).map_err(|e| Failure {
                    status: "FAILED",
                    reason: format!("Component '{arn}': {e}"),
                    context: Some(Box::new(t::ImageFailureContext {
                        component_failure: Some(t::ComponentFailureContext {
                            component_arn: Some(arn.clone()),
                            phase_name: Some(phase.to_string()),
                            error_message: Some(e.clone()),
                            ..Default::default()
                        }),
                        ..Default::default()
                    })),
                })?;
                for step in steps {
                    if self.cancelled(b) {
                        return Err(Failure::cancelled());
                    }
                    b.note(format!("[{arn}] phase {phase}, step {} ({})", step.name, step.action));
                    let mut last = Ok(String::new());
                    for _ in 0..step.max_attempts {
                        last = self.exec(b, instance, &step.script).await;
                        if last.is_ok() {
                            break;
                        }
                    }
                    if let Err(f) = last {
                        if step.on_failure == "Abort" {
                            return Err(Failure {
                                status: "FAILED",
                                reason: format!(
                                    "Component '{arn}' failed in phase '{phase}', step '{}': {}",
                                    step.name, f.reason
                                ),
                                context: Some(Box::new(t::ImageFailureContext {
                                    component_failure: Some(t::ComponentFailureContext {
                                        component_arn: Some(arn.clone()),
                                        phase_name: Some(phase.to_string()),
                                        step_name: Some(step.name.clone()),
                                        action: Some(step.action.clone()),
                                        error_message: Some(f.reason.clone()),
                                    }),
                                    ..Default::default()
                                })),
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn collect_packages(&self, b: &mut Build, instance: &str) {
        let script = "if command -v rpm >/dev/null 2>&1; then rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\\n'; \
                      elif command -v dpkg-query >/dev/null 2>&1; then dpkg-query -W -f='${Package} ${Version}\\n'; \
                      elif command -v apk >/dev/null 2>&1; then apk info -v 2>/dev/null | sed 's/-\\([0-9][^-]*-r[0-9]*\\)$/ \\1/'; fi";
        let Some(ec2) = self.ec2() else { return };
        let Ok(Some(out)) = ec2.run_command_on_instance(&b.account, &b.region, instance, script).await else { return };
        let mut packages: Vec<t::ImagePackage> = out
            .stdout
            .lines()
            .filter_map(|l| l.split_once(' '))
            .map(|(n, v)| t::ImagePackage {
                package_name: Some(n.to_string()),
                package_version: Some(v.trim().to_string()),
            })
            .collect();
        packages.sort_by(|a, b| a.package_name.cmp(&b.package_name));
        self.with_region_of(&b.account, &b.region, |r| {
            if let Some(rec) = r.images.get_mut(&b.arn) {
                rec.packages = packages;
            }
        });
    }

    async fn wait_for_action(&self, b: &mut Build, step_id: &str) -> Result<Value, Failure> {
        b.note(format!("Step {step_id} is waiting for an action"));
        loop {
            if self.cancelled(b) {
                return Err(Failure::cancelled());
            }
            let got = self.with_region_of(&b.account, &b.region, |r| {
                r.step_executions
                    .get(step_id)
                    .and_then(|s| s.action_received.clone().map(|a| (a, s.action_reason.clone())))
            });
            match got {
                Some((a, _)) if a == "RESUME" => return Ok(json!({ "action": "RESUME" })),
                Some((_, reason)) => {
                    return Err(Failure::failed(format!(
                        "The step was stopped{}.",
                        reason.map(|r| format!(": {r}")).unwrap_or_default()
                    )))
                }
                None => tokio::time::sleep(Duration::from_millis(200)).await,
            }
        }
    }

    /// Copy, share and tag the output AMI as the distribution configuration
    /// says; returns the AMIs.
    async fn distribute(&self, b: &mut Build, ami: &str) -> Result<Vec<t::Ami>, Failure> {
        let ec2 = self.ec2().ok_or_else(|| Failure::failed("EC2 is not available."))?.clone();
        let fail = |region: &str, msg: String| Failure {
            status: "FAILED",
            reason: format!("Distribution failed: {msg}"),
            context: Some(Box::new(t::ImageFailureContext {
                distribution_failure: Some(t::DistributionFailureContext {
                    error_message: Some(msg.clone()),
                    region_failures: Some(vec![t::RegionFailure {
                        region: Some(region.to_string()),
                        error_message: Some(msg),
                        ..Default::default()
                    }]),
                }),
                ..Default::default()
            })),
        };
        let available = || Some(t::ImageState { status: Some("AVAILABLE".into()), ..Default::default() });
        let build_region = b.region.clone();
        let distributions = b
            .image
            .distribution_configuration
            .as_ref()
            .and_then(|d| d.distributions.clone())
            .unwrap_or_else(|| vec![t::Distribution { region: build_region.clone(), ..Default::default() }]);
        let mut out = Vec::new();
        for d in distributions {
            let region = d.region.clone();
            let ctx = self.service_ctx(&b.svc, &b.account, &region);
            let cfg = d.ami_distribution_configuration.clone().unwrap_or_default();
            let name = b.ami_name(&region);
            let description = b.ami_description(&region);
            let region_ami = if region == build_region {
                ami.to_string()
            } else {
                let copied = ec2link::copy_image(
                    &ec2,
                    &ctx,
                    &build_region,
                    ami,
                    &name,
                    description.clone(),
                    cfg.kms_key_id.clone(),
                )
                .await
                .map_err(|e| fail(&region, format!("CopyImage to {region} failed: {}", e.message)))?;
                ec2link::wait_available(&ec2, &ctx, &copied).await.map_err(|e| fail(&region, e))?;
                let mut tags = b.standard_tags();
                if let Some(r) = &b.image.image_recipe {
                    tags.extend(r.ami_tags.clone().unwrap_or_default());
                }
                tags.extend(cfg.ami_tags.clone().unwrap_or_default());
                ec2link::create_tags(&ec2, &ctx, &copied, &tags).await.map_err(|e| fail(&region, e.message))?;
                b.note(format!("Copied {ami} to {region} as {copied}"));
                copied
            };
            if let Some(lp) = &cfg.launch_permission {
                ec2link::add_launch_permissions(
                    &ec2,
                    &ctx,
                    &region_ami,
                    lp.user_ids.as_deref().unwrap_or_default(),
                    lp.user_groups.as_deref().unwrap_or_default(),
                    lp.organization_arns.as_deref().unwrap_or_default(),
                    lp.organizational_unit_arns.as_deref().unwrap_or_default(),
                )
                .await
                .map_err(|e| fail(&region, format!("Sharing {region_ami} failed: {}", e.message)))?;
            }
            out.push(t::Ami {
                region: Some(region.clone()),
                image: Some(region_ami.clone()),
                name: Some(name.clone()),
                description: description.clone(),
                state: available(),
                account_id: Some(b.account.clone()),
            });
            let mut by_account: BTreeMap<String, String> = BTreeMap::new();
            by_account.insert(b.account.clone(), region_ami.clone());
            for target in cfg.target_account_ids.iter().flatten() {
                if target == &b.account {
                    continue;
                }
                ec2link::add_launch_permissions(&ec2, &ctx, &region_ami, std::slice::from_ref(target), &[], &[], &[])
                    .await
                    .map_err(|e| fail(&region, e.message))?;
                let tctx = self.service_ctx(&b.svc, target, &region);
                let copied = ec2link::copy_image(&ec2, &tctx, &region, &region_ami, &name, description.clone(), None)
                    .await
                    .map_err(|e| {
                        fail(&region, format!("Copying {region_ami} to account {target} failed: {}", e.message))
                    })?;
                ec2link::wait_available(&ec2, &tctx, &copied).await.map_err(|e| fail(&region, e))?;
                let mut tags = b.standard_tags();
                tags.extend(cfg.ami_tags.clone().unwrap_or_default());
                let _ = ec2link::create_tags(&ec2, &tctx, &copied, &tags).await;
                b.note(format!("Copied {region_ami} to account {target} as {copied}"));
                by_account.insert(target.clone(), copied.clone());
                out.push(t::Ami {
                    region: Some(region.clone()),
                    image: Some(copied),
                    name: Some(name.clone()),
                    description: description.clone(),
                    state: available(),
                    account_id: Some(target.clone()),
                });
            }
            for p in d.ssm_parameter_configurations.iter().flatten() {
                let acct = p.ami_account_id.clone().unwrap_or_else(|| b.account.clone());
                let Some(value) = by_account.get(&acct).cloned() else {
                    return Err(fail(
                        &region,
                        format!("No AMI was distributed to account {acct} for parameter {}.", p.parameter_name),
                    ));
                };
                let Some(ssm) = self.ssm() else {
                    return Err(fail(&region, "Systems Manager is not available.".into()));
                };
                let pctx = self.service_ctx(&b.svc, &acct, &region);
                ssm.invoke(
                    pctx,
                    "PutParameter",
                    json!({
                        "Name": p.parameter_name,
                        "Value": value,
                        "Type": "String",
                        "DataType": p.data_type.clone().unwrap_or_else(|| "aws:ec2:image".into()),
                        "Overwrite": true,
                    }),
                )
                .await
                .map_err(|e| fail(&region, format!("Writing parameter {} failed: {}", p.parameter_name, e.message)))?;
                b.note(format!("Wrote {value} to SSM parameter {}", p.parameter_name));
            }
            for lt in d.launch_template_configurations.iter().flatten() {
                let acct = lt.account_id.clone().unwrap_or_else(|| b.account.clone());
                let Some(value) = by_account.get(&acct).cloned() else {
                    return Err(fail(
                        &region,
                        format!(
                            "No AMI was distributed to account {acct} for launch template {}.",
                            lt.launch_template_id
                        ),
                    ));
                };
                let lctx = self.service_ctx(&b.svc, &acct, &region);
                let version = ec2link::update_launch_template(
                    &ec2,
                    &lctx,
                    &lt.launch_template_id,
                    &value,
                    &format!("Image Builder: {}", b.image.arn.clone().unwrap_or_default()),
                    lt.set_default_version,
                )
                .await
                .map_err(|e| {
                    fail(&region, format!("Updating launch template {} failed: {}", lt.launch_template_id, e.message))
                })?;
                b.note(format!("Launch template {} version {version} uses {value}", lt.launch_template_id));
            }
        }
        Ok(out)
    }

    fn container_outputs(&self, b: &Build) -> Vec<t::Container> {
        let Some(cr) = &b.image.container_recipe else { return Vec::new() };
        let tag = format!("{}-{}", b.image.version.clone().unwrap_or_default(), b.build_number());
        let mut out = Vec::new();
        let repo = cr.target_repository.clone().map(|r| r.repository_name).unwrap_or_default();
        out.push(t::Container {
            region: Some(b.region.clone()),
            image_uris: Some(vec![format!("{}.dkr.ecr.{}.amazonaws.com/{repo}:{tag}", b.account, b.region)]),
        });
        for d in b.image.distribution_configuration.as_ref().and_then(|d| d.distributions.clone()).unwrap_or_default() {
            if let Some(c) = d.container_distribution_configuration {
                let tags = c.container_tags.clone().unwrap_or_else(|| vec![tag.clone()]);
                out.push(t::Container {
                    region: Some(d.region.clone()),
                    image_uris: Some(
                        tags.iter()
                            .map(|t| {
                                format!(
                                    "{}.dkr.ecr.{}.amazonaws.com/{}:{t}",
                                    b.account, d.region, c.target_repository.repository_name
                                )
                            })
                            .collect(),
                    ),
                });
            }
        }
        out
    }

    async fn import_iso(&self, b: &mut Build) -> Result<(), Failure> {
        self.set_status(b, "CREATING")?;
        let ec2 = self.ec2().ok_or_else(|| Failure::failed("EC2 is not available."))?.clone();
        self.set_status(b, "BUILDING")?;
        // The ISO's installed system becomes an AMI; MWS registers it as
        // an EBS-backed image (it cannot run Windows installers).
        let name = b.ami_name(&b.region.clone());
        let out = mws_ec2::generated::Handler::register_image(
            &ec2,
            &b.svc,
            mws_ec2::generated::types::RegisterImageRequest {
                name: name.clone(),
                description: b.image.name.clone(),
                architecture: Some("x86_64".into()),
                root_device_name: Some("/dev/sda1".into()),
                block_device_mappings: Some(vec![mws_ec2::generated::types::BlockDeviceMapping {
                    device_name: Some("/dev/sda1".into()),
                    ebs: Some(mws_ec2::generated::types::EbsBlockDevice {
                        volume_size: Some(30),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                ..Default::default()
            },
        )
        .await
        .map_err(|e| Failure::failed(format!("RegisterImage failed: {}", e.message)))?;
        let ami = out.image_id.unwrap_or_default();
        let _ = ec2link::create_tags(&ec2, &b.svc, &ami, &b.standard_tags()).await;
        self.with_region_of(&b.account, &b.region, |r| {
            if let Some(rec) = r.images.get_mut(&b.arn) {
                rec.build_ami = Some(ami.clone());
            }
        });
        self.set_status(b, "DISTRIBUTING")?;
        self.set_outputs(
            b,
            vec![t::Ami {
                region: Some(b.region.clone()),
                image: Some(ami),
                name: Some(name),
                description: None,
                state: Some(t::ImageState { status: Some("AVAILABLE".into()), ..Default::default() }),
                account_id: Some(b.account.clone()),
            }],
            None,
        );
        self.set_status(b, "INTEGRATING")?;
        Ok(())
    }

    /// Publish the image to the infrastructure configuration's SNS topic
    /// when the build ends, as Image Builder does.
    async fn notify_sns(&self, b: &Build, status: &str) {
        let Some(topic) = b.infra().sns_topic_arn else { return };
        if ACTIVE_STATES.contains(&status) {
            return;
        }
        let Some(sns) = self.sns() else { return };
        let image = crate::generated::invoke(self, &b.svc, "GetImage", json!({ "imageBuildVersionArn": b.arn }))
            .await
            .map(|v| v["image"].clone())
            .unwrap_or(Value::Null);
        let region = topic.split(':').nth(3).unwrap_or(&b.region).to_string();
        let ctx = self.service_ctx(&b.svc, &b.account, &region);
        if let Err(e) = sns.invoke(ctx, "Publish", json!({ "TopicArn": topic, "Message": image.to_string() })).await {
            tracing::warn!(topic, error = %e.message, "Image Builder could not publish the build notification");
        }
    }

    /// Write the build log to CloudWatch Logs and, if configured, S3.
    async fn write_logs(&self, b: &Build) {
        let text: String = b.log.iter().map(|(at, m)| format!("{} {m}\n", date(*at))).collect();
        if let (Some(logs), Some(group)) =
            (self.logs(), b.image.logging_configuration.as_ref().and_then(|l| l.log_group_name.clone()))
        {
            let stream = format!("{}/{}", b.image.version.clone().unwrap_or_default(), b.build_number());
            let ctx = b.svc.clone();
            let _ = logs.invoke(ctx.clone(), "CreateLogGroup", json!({ "logGroupName": group })).await;
            let _ = logs
                .invoke(ctx.clone(), "CreateLogStream", json!({ "logGroupName": group, "logStreamName": stream }))
                .await;
            let events: Vec<Value> =
                b.log.iter().map(|(at, m)| json!({ "timestamp": at.timestamp_millis(), "message": m })).collect();
            for chunk in events.chunks(1000) {
                let _ = logs
                    .invoke(
                        ctx.clone(),
                        "PutLogEvents",
                        json!({ "logGroupName": group, "logStreamName": stream, "logEvents": chunk }),
                    )
                    .await;
            }
        }
        if let (Some(s3), Some(s3logs)) = (self.s3(), b.infra().logging.and_then(|l| l.s3_logs)) {
            if let Some(bucket) = s3logs.s3_bucket_name {
                let prefix = s3logs.s3_key_prefix.map(|p| format!("{}/", p.trim_end_matches('/'))).unwrap_or_default();
                let key = format!(
                    "{prefix}{}/{}/{}/console.log",
                    b.image.name.clone().unwrap_or_default(),
                    b.image.version.clone().unwrap_or_default(),
                    b.build_number()
                );
                let body = base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
                if let Err(e) =
                    s3.invoke(b.svc.clone(), "PutObject", json!({ "Bucket": bucket, "Key": key, "Body": body })).await
                {
                    tracing::warn!(bucket, error = %e.message, "Image Builder could not write the build log to S3");
                }
            }
        }
    }
}

fn param_value(ty: &str, values: &[String]) -> Value {
    match ty {
        "boolean" => Value::Bool(values.first().is_some_and(|v| v == "true")),
        "integer" => values.first().and_then(|v| v.parse::<i64>().ok()).map(Value::from).unwrap_or(Value::Null),
        "stringList" => Value::Array(values.iter().cloned().map(Value::String).collect()),
        _ => values.first().cloned().map(Value::String).unwrap_or(Value::Null),
    }
}

/// Resolve `$.a.b` paths against `root`.
fn json_path(path: &str, root: &Value) -> Value {
    let Some(rest) = path.strip_prefix("$.") else { return Value::String(path.to_string()) };
    let mut cur = root;
    for part in rest.split('.') {
        match cur.get(part) {
            Some(v) => cur = v,
            None => return Value::Null,
        }
    }
    cur.clone()
}

/// Step inputs with `key.$` references resolved.
fn resolve_inputs(inputs: &Value, root: &Value) -> Value {
    match inputs {
        Value::Object(o) => {
            let mut out = serde_json::Map::new();
            for (k, v) in o {
                match (k.strip_suffix(".$"), v) {
                    (Some(key), Value::String(path)) => {
                        out.insert(key.to_string(), json_path(path, root));
                    }
                    _ => {
                        out.insert(k.clone(), resolve_inputs(v, root));
                    }
                }
            }
            Value::Object(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(|x| resolve_inputs(x, root)).collect()),
        other => other.clone(),
    }
}

/// A step's `if` condition: `and`, `or`, `not`, `booleanEquals`,
/// `stringEquals` and `numberEquals` over `value` (or `value.$`).
fn condition_holds(cond: &Value, root: &Value) -> bool {
    let value = || match (cond.get("value.$"), cond.get("value")) {
        (Some(Value::String(p)), _) => json_path(p, root),
        (_, Some(v)) => v.clone(),
        _ => Value::Null,
    };
    if let Some(all) = cond.get("and").and_then(Value::as_array) {
        return all.iter().all(|c| condition_holds(c, root));
    }
    if let Some(any) = cond.get("or").and_then(Value::as_array) {
        return any.iter().any(|c| condition_holds(c, root));
    }
    if let Some(inner) = cond.get("not") {
        return !condition_holds(inner, root);
    }
    if let Some(b) = cond.get("booleanEquals") {
        let v = value();
        let as_bool = |x: &Value| x.as_bool().or_else(|| x.as_str().map(|s| s == "true"));
        return as_bool(b) == as_bool(&v);
    }
    if let Some(s) = cond.get("stringEquals") {
        return crate::yaml::text(s) == crate::yaml::text(&value());
    }
    if let Some(n) = cond.get("numberEquals") {
        return n.as_f64() == value().as_f64();
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inputs_and_conditions() {
        let root = json!({ "stepOutputs": { "Launch": { "instanceId": "i-1" } }, "parameters": { "wait": true } });
        let r = resolve_inputs(&json!({ "instanceId.$": "$.stepOutputs.Launch.instanceId", "x": 1 }), &root);
        assert_eq!(r, json!({ "instanceId": "i-1", "x": 1 }));
        assert!(condition_holds(&json!({ "booleanEquals": true, "value.$": "$.parameters.wait" }), &root));
        assert!(!condition_holds(&json!({ "not": { "booleanEquals": true, "value.$": "$.parameters.wait" } }), &root));
    }
}

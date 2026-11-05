//! Model customization (and the custom models it makes), custom model
//! deployments, model import and copy, batch inference, evaluation and
//! prompt optimization jobs. Jobs run on the emulated clock: they report
//! `InProgress` (batch inference: `Submitted`) and finish a moment later,
//! creating what they produce.

use chrono::{DateTime, Duration, Utc};
use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::{json, Map, Value};

use crate::catalog;
use crate::generated::types;
use crate::resolve::foundation_from_arn;
use crate::state::{kind, Record, Scope};
use crate::util::{
    arn, conflict, from_doc, not_found, page, random_id, request_tag_context, resource_tag_context, set, sort_records,
    tag_map, to_doc, ts, validation, MAX_TAGS,
};
use crate::Bedrock;

/// How long a job runs before it completes, on the emulated clock.
pub const JOB_SECS: i64 = 2;

fn record(
    id: &str,
    arn: &str,
    name: &str,
    now: DateTime<Utc>,
    status: &str,
    done: Option<&str>,
    doc: Map<String, Value>,
) -> Record {
    Record {
        id: id.into(),
        arn: arn.into(),
        name: name.into(),
        created: now,
        updated: now,
        status: status.into(),
        transition: done.map(|d| (d.to_string(), now + Duration::seconds(JOB_SECS))),
        doc,
    }
}

fn check_tags(tags: &[types::Tag], name: &str) -> Result<(), ServiceError> {
    if tags.len() > MAX_TAGS {
        return Err(crate::util::too_many_tags(name));
    }
    Ok(())
}

/// Every string under `key` anywhere in a document.
fn collect_strings(v: &Value, key: &str, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            for (k, v) in m {
                if k == key {
                    if let Some(s) = v.as_str() {
                        if !out.iter().any(|o| o == s) {
                            out.push(s.to_string());
                        }
                    }
                }
                collect_strings(v, key, out);
            }
        }
        Value::Array(a) => a.iter().for_each(|v| collect_strings(v, key, out)),
        _ => {}
    }
}

fn base_model(
    ctx: &RequestContext,
    ident: &str,
    customization: &str,
) -> Result<&'static catalog::ModelSpec, ServiceError> {
    let id = ident.rsplit("foundation-model/").next().unwrap_or(ident);
    let m = catalog::model(id).ok_or_else(|| validation(format!("The base model {ident} is invalid.")))?;
    if !m.customizations_supported.iter().any(|c| c == customization) {
        return Err(validation(format!(
            "The base model {} does not support customization type {customization}.",
            m.arn(&ctx.partition, &ctx.region)
        )));
    }
    Ok(m)
}

impl Bedrock {
    /// Find a record, authorize `action` on it, and return a copy.
    fn record_for(
        &self,
        ctx: &RequestContext,
        kind: &str,
        ident: &str,
        action: &str,
        what: &str,
    ) -> Result<Record, ServiceError> {
        let (r, tags) = self.scope(ctx, |s| {
            let r = s.find(kind, ident).cloned().ok_or_else(|| not_found(format!("{what} {ident} was not found.")))?;
            let tags = s.tags.get(&r.arn).cloned();
            Ok::<_, ServiceError>((r, tags))
        })?;
        ctx.authorize(action, &r.arn, resource_tag_context(tags.as_ref()))?;
        Ok(r)
    }

    fn insert_tagged(&self, ctx: &RequestContext, kind: &str, r: Record, tags: &[types::Tag]) {
        self.scope(ctx, |s| {
            if !tags.is_empty() {
                s.tags.insert(r.arn.clone(), tag_map(tags));
            }
            s.insert(kind, r);
        })
    }

    // Model customization -------------------------------------------------

    pub fn create_model_customization_job(
        &self,
        ctx: &RequestContext,
        input: types::CreateModelCustomizationJobRequest,
    ) -> Result<types::CreateModelCustomizationJobResponse, ServiceError> {
        let job_tags = input.job_tags.clone().unwrap_or_default();
        let model_tags = input.custom_model_tags.clone().unwrap_or_default();
        check_tags(&job_tags, &input.job_name)?;
        let customization = input.customization_type.clone().unwrap_or_else(|| "FINE_TUNING".into());
        let base = base_model(ctx, &input.base_model_identifier, &customization)?;
        let id = random_id(12);
        let job_arn = arn(ctx, &format!("model-customization-job/{}/{id}", base.model_id));
        ctx.authorize("bedrock:CreateModelCustomizationJob", &job_arn, request_tag_context(&job_tags))?;
        let model_id = random_id(12);
        let model_arn = arn(ctx, &format!("custom-model/{}/{model_id}", base.model_id));
        let now = ctx.received_at;
        let base_arn = base.arn(&ctx.partition, &ctx.region);
        self.scope(ctx, |s| {
            if s.kind(kind::CUSTOMIZATION_JOB).any(|r| r.name == input.job_name) {
                return Err(conflict(format!("A model customization job named {} already exists.", input.job_name)));
            }
            if s.kind(kind::CUSTOM_MODEL).any(|r| r.name == input.custom_model_name) {
                return Err(conflict(format!("A custom model named {} already exists.", input.custom_model_name)));
            }
            Ok(())
        })?;
        let mut doc = to_doc(&input);
        for k in ["job_tags", "custom_model_tags", "base_model_identifier", "custom_model_kms_key_id"] {
            doc.remove(k);
        }
        set(&mut doc, "job_arn", job_arn.clone());
        set(&mut doc, "output_model_name", input.custom_model_name.clone());
        set(&mut doc, "output_model_arn", model_arn.clone());
        set(&mut doc, "base_model_arn", base_arn.clone());
        set(&mut doc, "customization_type", customization.clone());
        if let Some(k) = &input.custom_model_kms_key_id {
            set(&mut doc, "output_model_kms_key_arn", k.clone());
        }
        let mut model_doc = doc.clone();
        crate::util::rename(&mut model_doc, "output_model_kms_key_arn", "model_kms_key_arn");
        for k in ["output_model_name", "output_model_arn", "client_request_token", "role_arn", "vpc_config"] {
            model_doc.remove(k);
        }
        set(&mut model_doc, "job_name", input.job_name.clone());
        set(&mut model_doc, "base_model_name", base.model_name.clone());
        self.insert_tagged(
            ctx,
            kind::CUSTOMIZATION_JOB,
            record(&id, &job_arn, &input.job_name, now, "InProgress", Some("Completed"), doc),
            &job_tags,
        );
        self.insert_tagged(
            ctx,
            kind::CUSTOM_MODEL,
            record(&model_id, &model_arn, &input.custom_model_name, now, "Creating", Some("Active"), model_doc),
            &model_tags,
        );
        Ok(types::CreateModelCustomizationJobResponse { job_arn })
    }

    pub fn get_model_customization_job(
        &self,
        ctx: &RequestContext,
        input: types::GetModelCustomizationJobRequest,
    ) -> Result<types::GetModelCustomizationJobResponse, ServiceError> {
        let r = self.record_for(
            ctx,
            kind::CUSTOMIZATION_JOB,
            &input.job_identifier,
            "bedrock:GetModelCustomizationJob",
            "Model customization job",
        )?;
        Ok(from_doc(&job_doc(&r, "status", "creation_time")))
    }

    pub fn list_model_customization_jobs(
        &self,
        ctx: &RequestContext,
        input: types::ListModelCustomizationJobsRequest,
    ) -> Result<types::ListModelCustomizationJobsResponse, ServiceError> {
        ctx.authorize("bedrock:ListModelCustomizationJobs", "*", ConditionContext::new())?;
        let items = self.list(
            ctx,
            kind::CUSTOMIZATION_JOB,
            Filter {
                status: input.status_equals.as_deref(),
                name: input.name_contains.as_deref(),
                after: input.creation_time_after,
                before: input.creation_time_before,
                sort_by: input.sort_by.as_deref(),
                sort_order: input.sort_order.as_deref(),
            },
            |r| {
                let mut d = job_doc(r, "status", "creation_time");
                crate::util::rename(&mut d, "output_model_arn", "custom_model_arn");
                crate::util::rename(&mut d, "output_model_name", "custom_model_name");
                from_doc::<types::ModelCustomizationJobSummary>(&d)
            },
        );
        let (items, next_token) = page(items, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListModelCustomizationJobsResponse { next_token, model_customization_job_summaries: Some(items) })
    }

    pub fn stop_model_customization_job(
        &self,
        ctx: &RequestContext,
        input: types::StopModelCustomizationJobRequest,
    ) -> Result<types::StopModelCustomizationJobResponse, ServiceError> {
        let r = self.record_for(
            ctx,
            kind::CUSTOMIZATION_JOB,
            &input.job_identifier,
            "bedrock:StopModelCustomizationJob",
            "Model customization job",
        )?;
        self.stop(ctx, kind::CUSTOMIZATION_JOB, &r, "InProgress", "Stopped")?;
        self.scope(ctx, |s| {
            if let Some(m) = r.str("output_model_arn").and_then(|a| s.find_id(kind::CUSTOM_MODEL, a)) {
                s.remove(kind::CUSTOM_MODEL, &m);
            }
        });
        Ok(types::StopModelCustomizationJobResponse {})
    }

    /// Stop a running job: `running` -> `stopped`.
    fn stop(
        &self,
        ctx: &RequestContext,
        kind: &str,
        r: &Record,
        running: &str,
        stopped: &str,
    ) -> Result<(), ServiceError> {
        let now = ctx.received_at;
        self.scope(ctx, |s| {
            let rec = s.get_mut(kind, &r.id).expect("record exists");
            if rec.status != running && !(running == "InProgress" && rec.status == "Submitted") {
                return Err(validation(format!("The job can't be stopped because its status is {}.", rec.status)));
            }
            rec.status = stopped.into();
            rec.transition = None;
            rec.updated = now;
            set(&mut rec.doc, "end_time", ts(now));
            Ok(())
        })
    }

    // Custom models -----------------------------------------------------------

    pub fn create_custom_model(
        &self,
        ctx: &RequestContext,
        input: types::CreateCustomModelRequest,
    ) -> Result<types::CreateCustomModelResponse, ServiceError> {
        let tags = input.model_tags.clone().unwrap_or_default();
        check_tags(&tags, &input.model_name)?;
        let base = catalog::model("amazon.nova-lite-v1:0").expect("built-in model");
        let id = random_id(12);
        let model_arn = arn(ctx, &format!("custom-model/imported/{id}"));
        ctx.authorize("bedrock:CreateCustomModel", &model_arn, request_tag_context(&tags))?;
        if input.model_source_config.is_none() && input.custom_model_data_source.is_none() {
            return Err(validation("Specify modelSourceConfig or customModelDataSource."));
        }
        if self.scope(ctx, |s| s.kind(kind::CUSTOM_MODEL).any(|r| r.name == input.model_name)) {
            return Err(conflict(format!("A custom model named {} already exists.", input.model_name)));
        }
        let mut doc = Map::new();
        set(&mut doc, "base_model_arn", base.arn(&ctx.partition, &ctx.region));
        set(&mut doc, "base_model_name", base.model_name.clone());
        set(&mut doc, "customization_type", "IMPORTED");
        if let Some(k) = &input.model_kms_key_arn {
            set(&mut doc, "model_kms_key_arn", k.clone());
        }
        let now = ctx.received_at;
        self.insert_tagged(
            ctx,
            kind::CUSTOM_MODEL,
            record(&id, &model_arn, &input.model_name, now, "Creating", Some("Active"), doc),
            &tags,
        );
        Ok(types::CreateCustomModelResponse { model_arn })
    }

    pub fn get_custom_model(
        &self,
        ctx: &RequestContext,
        input: types::GetCustomModelRequest,
    ) -> Result<types::GetCustomModelResponse, ServiceError> {
        let r = self.record_for(
            ctx,
            kind::CUSTOM_MODEL,
            &input.model_identifier,
            "bedrock:GetCustomModel",
            "Custom model",
        )?;
        Ok(from_doc(&model_doc(&r)))
    }

    pub fn list_custom_models(
        &self,
        ctx: &RequestContext,
        input: types::ListCustomModelsRequest,
    ) -> Result<types::ListCustomModelsResponse, ServiceError> {
        ctx.authorize("bedrock:ListCustomModels", "*", ConditionContext::new())?;
        let account = ctx.caller.account_id.clone();
        let items: Vec<types::CustomModelSummary> = self.scope(ctx, |s| {
            let mut v: Vec<&Record> = s
                .kind(kind::CUSTOM_MODEL)
                .filter(|r| input.model_status.as_ref().is_none_or(|st| &r.status == st))
                .filter(|r| input.name_contains.as_ref().is_none_or(|n| r.name.contains(n.as_str())))
                .filter(|r| {
                    input.base_model_arn_equals.as_ref().is_none_or(|b| r.str("base_model_arn") == Some(b.as_str()))
                })
                .filter(|r| {
                    input
                        .foundation_model_arn_equals
                        .as_ref()
                        .is_none_or(|b| r.str("base_model_arn") == Some(b.as_str()))
                })
                .filter(|r| input.creation_time_after.is_none_or(|t| r.created > t))
                .filter(|r| input.creation_time_before.is_none_or(|t| r.created < t))
                .collect();
            sort_records(&mut v, input.sort_by.as_deref(), input.sort_order.as_deref());
            v.into_iter()
                .map(|r| {
                    let mut d = model_doc(r);
                    set(&mut d, "owner_account_id", account.clone());
                    from_doc(&d)
                })
                .collect()
        });
        let (items, next_token) = page(items, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListCustomModelsResponse { next_token, model_summaries: Some(items) })
    }

    pub fn delete_custom_model(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCustomModelRequest,
    ) -> Result<types::DeleteCustomModelResponse, ServiceError> {
        let r = self.record_for(
            ctx,
            kind::CUSTOM_MODEL,
            &input.model_identifier,
            "bedrock:DeleteCustomModel",
            "Custom model",
        )?;
        self.scope(ctx, |s| {
            let used = s.kind(kind::PROVISIONED).any(|p| p.str("model_arn") == Some(r.arn.as_str()))
                || s.kind(kind::DEPLOYMENT).any(|d| d.str("model_arn") == Some(r.arn.as_str()));
            if used {
                return Err(conflict(format!(
                    "The custom model {} is in use by a Provisioned Throughput or custom model deployment.",
                    r.name
                )));
            }
            s.remove(kind::CUSTOM_MODEL, &r.id);
            Ok(types::DeleteCustomModelResponse {})
        })
    }

    // Custom model deployments --------------------------------------------------

    pub fn create_custom_model_deployment(
        &self,
        ctx: &RequestContext,
        input: types::CreateCustomModelDeploymentRequest,
    ) -> Result<types::CreateCustomModelDeploymentResponse, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        check_tags(&tags, &input.model_deployment_name)?;
        let id = random_id(12);
        let d_arn = arn(ctx, &format!("custom-model-deployment/{id}"));
        ctx.authorize("bedrock:CreateCustomModelDeployment", &d_arn, request_tag_context(&tags))?;
        let model_arn = self.active_custom_model(ctx, &input.model_arn)?;
        let now = ctx.received_at;
        if self.scope(ctx, |s| s.kind(kind::DEPLOYMENT).any(|r| r.name == input.model_deployment_name)) {
            return Err(conflict(format!("A deployment named {} already exists.", input.model_deployment_name)));
        }
        let mut doc = Map::new();
        set(&mut doc, "model_arn", model_arn);
        if let Some(d) = &input.description {
            set(&mut doc, "description", d.clone());
        }
        self.insert_tagged(
            ctx,
            kind::DEPLOYMENT,
            Record {
                transition: Some(("Active".into(), now + Duration::seconds(1))),
                ..record(&id, &d_arn, &input.model_deployment_name, now, "Creating", None, doc)
            },
            &tags,
        );
        Ok(types::CreateCustomModelDeploymentResponse { custom_model_deployment_arn: d_arn })
    }

    fn active_custom_model(&self, ctx: &RequestContext, ident: &str) -> Result<String, ServiceError> {
        self.scope(ctx, |s| {
            let m = s
                .find(kind::CUSTOM_MODEL, ident)
                .ok_or_else(|| not_found(format!("Custom model {ident} was not found.")))?;
            if m.status != "Active" {
                return Err(validation(format!("The custom model {ident} is not active.")));
            }
            Ok(m.arn.clone())
        })
    }

    pub fn get_custom_model_deployment(
        &self,
        ctx: &RequestContext,
        input: types::GetCustomModelDeploymentRequest,
    ) -> Result<types::GetCustomModelDeploymentResponse, ServiceError> {
        let r = self.record_for(
            ctx,
            kind::DEPLOYMENT,
            &input.custom_model_deployment_identifier,
            "bedrock:GetCustomModelDeployment",
            "Custom model deployment",
        )?;
        Ok(from_doc(&deployment_doc(&r)))
    }

    pub fn update_custom_model_deployment(
        &self,
        ctx: &RequestContext,
        input: types::UpdateCustomModelDeploymentRequest,
    ) -> Result<types::UpdateCustomModelDeploymentResponse, ServiceError> {
        let r = self.record_for(
            ctx,
            kind::DEPLOYMENT,
            &input.custom_model_deployment_identifier,
            "bedrock:UpdateCustomModelDeployment",
            "Custom model deployment",
        )?;
        let model_arn = self.active_custom_model(ctx, &input.model_arn)?;
        let now = ctx.received_at;
        self.scope(ctx, |s| {
            let rec = s.get_mut(kind::DEPLOYMENT, &r.id).expect("record exists");
            set(&mut rec.doc, "update_details", json!({"model_arn": model_arn, "update_status": "Updating"}));
            set(&mut rec.doc, "model_arn", model_arn);
            rec.updated = now;
        });
        Ok(types::UpdateCustomModelDeploymentResponse { custom_model_deployment_arn: r.arn })
    }

    pub fn list_custom_model_deployments(
        &self,
        ctx: &RequestContext,
        input: types::ListCustomModelDeploymentsRequest,
    ) -> Result<types::ListCustomModelDeploymentsResponse, ServiceError> {
        ctx.authorize("bedrock:ListCustomModelDeployments", "*", ConditionContext::new())?;
        let model = input.model_arn_equals.clone();
        let items = self.list(
            ctx,
            kind::DEPLOYMENT,
            Filter {
                status: input.status_equals.as_deref(),
                name: input.name_contains.as_deref(),
                after: input.created_after,
                before: input.created_before,
                sort_by: input.sort_by.as_deref(),
                sort_order: input.sort_order.as_deref(),
            },
            |r| {
                let mut d = deployment_doc(r);
                set(&mut d, "custom_model_deployment_name", r.name.clone());
                (r.str("model_arn").map(str::to_string), from_doc::<types::CustomModelDeploymentSummary>(&d))
            },
        );
        let items: Vec<_> = items.into_iter().filter(|(m, _)| model.is_none() || m == &model).map(|(_, s)| s).collect();
        let (items, next_token) = page(items, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListCustomModelDeploymentsResponse { next_token, model_deployment_summaries: Some(items) })
    }

    pub fn delete_custom_model_deployment(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCustomModelDeploymentRequest,
    ) -> Result<types::DeleteCustomModelDeploymentResponse, ServiceError> {
        let r = self.record_for(
            ctx,
            kind::DEPLOYMENT,
            &input.custom_model_deployment_identifier,
            "bedrock:DeleteCustomModelDeployment",
            "Custom model deployment",
        )?;
        self.scope(ctx, |s| s.remove(kind::DEPLOYMENT, &r.id));
        Ok(types::DeleteCustomModelDeploymentResponse {})
    }

    // Model import ------------------------------------------------------------

    pub fn create_model_import_job(
        &self,
        ctx: &RequestContext,
        input: types::CreateModelImportJobRequest,
    ) -> Result<types::CreateModelImportJobResponse, ServiceError> {
        let job_tags = input.job_tags.clone().unwrap_or_default();
        let model_tags = input.imported_model_tags.clone().unwrap_or_default();
        check_tags(&job_tags, &input.job_name)?;
        let id = random_id(12);
        let job_arn = arn(ctx, &format!("model-import-job/{id}"));
        ctx.authorize("bedrock:CreateModelImportJob", &job_arn, request_tag_context(&job_tags))?;
        let model_id = random_id(12);
        let model_arn = arn(ctx, &format!("imported-model/{model_id}"));
        self.scope(ctx, |s| {
            if s.kind(kind::IMPORT_JOB).any(|r| r.name == input.job_name) {
                return Err(conflict(format!("A model import job named {} already exists.", input.job_name)));
            }
            if s.kind(kind::IMPORTED_MODEL).any(|r| r.name == input.imported_model_name) {
                return Err(conflict(format!("An imported model named {} already exists.", input.imported_model_name)));
            }
            Ok(())
        })?;
        let now = ctx.received_at;
        let mut doc = to_doc(&input);
        for k in ["job_tags", "imported_model_tags", "imported_model_kms_key_id"] {
            doc.remove(k);
        }
        set(&mut doc, "job_arn", job_arn.clone());
        set(&mut doc, "imported_model_arn", model_arn.clone());
        let mut mdoc = Map::new();
        set(&mut mdoc, "job_name", input.job_name.clone());
        set(&mut mdoc, "job_arn", job_arn.clone());
        if let Some(v) = doc.get("model_data_source") {
            mdoc.insert("model_data_source".into(), v.clone());
        }
        set(&mut mdoc, "model_architecture", "llama3");
        set(&mut mdoc, "instruct_supported", true);
        set(
            &mut mdoc,
            "custom_model_units",
            json!({"custom_model_units_per_model_copy": 1, "custom_model_units_version": "1.0"}),
        );
        self.insert_tagged(
            ctx,
            kind::IMPORT_JOB,
            record(&id, &job_arn, &input.job_name, now, "InProgress", Some("Completed"), doc),
            &job_tags,
        );
        self.insert_tagged(
            ctx,
            kind::IMPORTED_MODEL,
            record(&model_id, &model_arn, &input.imported_model_name, now, "Creating", Some("Active"), mdoc),
            &model_tags,
        );
        Ok(types::CreateModelImportJobResponse { job_arn })
    }

    pub fn get_model_import_job(
        &self,
        ctx: &RequestContext,
        input: types::GetModelImportJobRequest,
    ) -> Result<types::GetModelImportJobResponse, ServiceError> {
        let r = self.record_for(
            ctx,
            kind::IMPORT_JOB,
            &input.job_identifier,
            "bedrock:GetModelImportJob",
            "Model import job",
        )?;
        Ok(from_doc(&job_doc(&r, "status", "creation_time")))
    }

    pub fn list_model_import_jobs(
        &self,
        ctx: &RequestContext,
        input: types::ListModelImportJobsRequest,
    ) -> Result<types::ListModelImportJobsResponse, ServiceError> {
        ctx.authorize("bedrock:ListModelImportJobs", "*", ConditionContext::new())?;
        let items = self.list(
            ctx,
            kind::IMPORT_JOB,
            Filter {
                status: input.status_equals.as_deref(),
                name: input.name_contains.as_deref(),
                after: input.creation_time_after,
                before: input.creation_time_before,
                sort_by: input.sort_by.as_deref(),
                sort_order: input.sort_order.as_deref(),
            },
            |r| from_doc::<types::ModelImportJobSummary>(&job_doc(r, "status", "creation_time")),
        );
        let (items, next_token) = page(items, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListModelImportJobsResponse { next_token, model_import_job_summaries: Some(items) })
    }

    fn imported(&self, ctx: &RequestContext, ident: &str, action: &str) -> Result<Record, ServiceError> {
        let r = self.record_for(ctx, kind::IMPORTED_MODEL, ident, action, "Imported model")?;
        if r.status != "Active" {
            return Err(not_found(format!("Imported model {ident} was not found.")));
        }
        Ok(r)
    }

    pub fn get_imported_model(
        &self,
        ctx: &RequestContext,
        input: types::GetImportedModelRequest,
    ) -> Result<types::GetImportedModelResponse, ServiceError> {
        let r = self.imported(ctx, &input.model_identifier, "bedrock:GetImportedModel")?;
        Ok(from_doc(&model_doc(&r)))
    }

    pub fn list_imported_models(
        &self,
        ctx: &RequestContext,
        input: types::ListImportedModelsRequest,
    ) -> Result<types::ListImportedModelsResponse, ServiceError> {
        ctx.authorize("bedrock:ListImportedModels", "*", ConditionContext::new())?;
        let items = self.list(
            ctx,
            kind::IMPORTED_MODEL,
            Filter {
                status: Some("Active"),
                name: input.name_contains.as_deref(),
                after: input.creation_time_after,
                before: input.creation_time_before,
                sort_by: input.sort_by.as_deref(),
                sort_order: input.sort_order.as_deref(),
            },
            |r| from_doc::<types::ImportedModelSummary>(&model_doc(r)),
        );
        let (items, next_token) = page(items, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListImportedModelsResponse { next_token, model_summaries: Some(items) })
    }

    pub fn delete_imported_model(
        &self,
        ctx: &RequestContext,
        input: types::DeleteImportedModelRequest,
    ) -> Result<types::DeleteImportedModelResponse, ServiceError> {
        let r = self.imported(ctx, &input.model_identifier, "bedrock:DeleteImportedModel")?;
        self.scope(ctx, |s| s.remove(kind::IMPORTED_MODEL, &r.id));
        Ok(types::DeleteImportedModelResponse {})
    }

    // Model copy --------------------------------------------------------------

    pub fn create_model_copy_job(
        &self,
        ctx: &RequestContext,
        input: types::CreateModelCopyJobRequest,
    ) -> Result<types::CreateModelCopyJobResponse, ServiceError> {
        let tags = input.target_model_tags.clone().unwrap_or_default();
        check_tags(&tags, &input.target_model_name)?;
        let id = random_id(12);
        let job_arn = arn(ctx, &format!("model-copy-job/{id}"));
        ctx.authorize("bedrock:CreateModelCopyJob", &job_arn, request_tag_context(&tags))?;
        // The source is a custom model in another Region of this account.
        let source = input.source_model_arn.clone();
        let mut parts = source.splitn(6, ':');
        let (Some("arn"), _, Some("bedrock"), Some(src_region), Some(src_account), Some(resource)) =
            (parts.next(), parts.next(), parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(validation(format!("The source model {source} is invalid.")));
        };
        let src = self
            .scope_in(src_account, src_region, ctx.received_at, |s| s.find(kind::CUSTOM_MODEL, &source).cloned())
            .filter(|_| resource.starts_with("custom-model/"))
            .ok_or_else(|| not_found(format!("The source model {source} was not found.")))?;
        let base = src.str("base_model_id_hint").map(str::to_string).unwrap_or_else(|| {
            resource
                .trim_start_matches("custom-model/")
                .rsplit_once('/')
                .map(|(b, _)| b.to_string())
                .unwrap_or_default()
        });
        let model_id = random_id(12);
        let target_arn = arn(ctx, &format!("custom-model/{base}/{model_id}"));
        if self.scope(ctx, |s| s.kind(kind::CUSTOM_MODEL).any(|r| r.name == input.target_model_name)) {
            return Err(conflict(format!("A custom model named {} already exists.", input.target_model_name)));
        }
        let now = ctx.received_at;
        let mut doc = to_doc(&input);
        doc.remove("client_request_token");
        doc.remove("model_kms_key_id");
        set(&mut doc, "job_arn", job_arn.clone());
        set(&mut doc, "target_model_arn", target_arn.clone());
        set(&mut doc, "source_account_id", src_account.to_string());
        set(&mut doc, "source_model_name", src.name.clone());
        if let Some(k) = &input.model_kms_key_id {
            set(&mut doc, "target_model_kms_key_arn", k.clone());
        }
        let mut model_doc = src.doc.clone();
        if let Some(b) = src.str("base_model_arn").and_then(foundation_from_arn) {
            set(&mut model_doc, "base_model_arn", b.arn(&ctx.partition, &ctx.region));
        }
        self.insert_tagged(
            ctx,
            kind::COPY_JOB,
            record(&id, &job_arn, &id, now, "InProgress", Some("Completed"), doc),
            &[],
        );
        self.insert_tagged(
            ctx,
            kind::CUSTOM_MODEL,
            record(&model_id, &target_arn, &input.target_model_name, now, "Creating", Some("Active"), model_doc),
            &tags,
        );
        Ok(types::CreateModelCopyJobResponse { job_arn })
    }

    pub fn get_model_copy_job(
        &self,
        ctx: &RequestContext,
        input: types::GetModelCopyJobRequest,
    ) -> Result<types::GetModelCopyJobResponse, ServiceError> {
        let r = self.record_for(ctx, kind::COPY_JOB, &input.job_arn, "bedrock:GetModelCopyJob", "Model copy job")?;
        Ok(from_doc(&job_doc(&r, "status", "creation_time")))
    }

    pub fn list_model_copy_jobs(
        &self,
        ctx: &RequestContext,
        input: types::ListModelCopyJobsRequest,
    ) -> Result<types::ListModelCopyJobsResponse, ServiceError> {
        ctx.authorize("bedrock:ListModelCopyJobs", "*", ConditionContext::new())?;
        let items = self.list(
            ctx,
            kind::COPY_JOB,
            Filter {
                status: input.status_equals.as_deref(),
                name: None,
                after: input.creation_time_after,
                before: input.creation_time_before,
                sort_by: input.sort_by.as_deref(),
                sort_order: input.sort_order.as_deref(),
            },
            |r| from_doc::<types::ModelCopyJobSummary>(&job_doc(r, "status", "creation_time")),
        );
        let items: Vec<_> = items
            .into_iter()
            .filter(|j| input.source_account_equals.as_ref().is_none_or(|a| &j.source_account_id == a))
            .filter(|j| input.source_model_arn_equals.as_ref().is_none_or(|a| &j.source_model_arn == a))
            .filter(|j| {
                input
                    .target_model_name_contains
                    .as_ref()
                    .is_none_or(|n| j.target_model_name.as_deref().is_some_and(|t| t.contains(n.as_str())))
            })
            .collect();
        let (items, next_token) = page(items, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListModelCopyJobsResponse { next_token, model_copy_job_summaries: Some(items) })
    }

    // Batch inference -----------------------------------------------------------

    pub fn create_model_invocation_job(
        &self,
        ctx: &RequestContext,
        input: types::CreateModelInvocationJobRequest,
    ) -> Result<types::CreateModelInvocationJobResponse, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        check_tags(&tags, &input.job_name)?;
        let id = random_id(12);
        let job_arn = arn(ctx, &format!("model-invocation-job/{id}"));
        ctx.authorize("bedrock:CreateModelInvocationJob", &job_arn, request_tag_context(&tags))?;
        let mut passed = ConditionContext::new();
        passed.insert("iam:PassedToService".into(), vec!["bedrock.amazonaws.com".into()]);
        ctx.authorize("iam:PassRole", &input.role_arn, passed)?;
        let target = self
            .resolve_invocation(ctx, &input.model_id)
            .map_err(|_| validation(format!("The provided model identifier {} is invalid.", input.model_id)))?;
        let now = ctx.received_at;
        if self.scope(ctx, |s| s.kind(kind::INVOCATION_JOB).any(|r| r.name == input.job_name)) {
            return Err(conflict(format!("A batch inference job named {} already exists.", input.job_name)));
        }
        let mut doc = to_doc(&input);
        doc.remove("tags");
        set(&mut doc, "job_arn", job_arn.clone());
        let hours = input.timeout_duration_in_hours.unwrap_or(24) as i64;
        set(&mut doc, "job_expiration_time", ts(now + Duration::hours(hours)));
        let runner = self.runner.get().cloned();
        let s3 = |cfg: &Value| {
            cfg.as_object()
                .and_then(|c| c.values().next())
                .and_then(|v| v.get("s3_uri"))
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string()
        };
        let job = BatchJob {
            context: ctx.clone(),
            account: ctx.caller.account_id.clone(),
            region: ctx.region.clone(),
            job_arn: job_arn.clone(),
            job_id: id.clone(),
            model_id: target.model.model_id.clone(),
            role_arn: input.role_arn.clone(),
            family: target.model.family,
            submitted: now,
            input_uri: doc.get("input_data_config").map(s3).unwrap_or_default(),
            output_uri: doc.get("output_data_config").map(s3).unwrap_or_default(),
        };
        let done = if runner.is_some() { None } else { Some("Completed") };
        self.insert_tagged(
            ctx,
            kind::INVOCATION_JOB,
            record(&id, &job_arn, &input.job_name, now, "Submitted", done, doc),
            &tags,
        );
        if let Some(run) = runner {
            run(job);
        }
        Ok(types::CreateModelInvocationJobResponse { job_arn })
    }

    pub fn get_model_invocation_job(
        &self,
        ctx: &RequestContext,
        input: types::GetModelInvocationJobRequest,
    ) -> Result<types::GetModelInvocationJobResponse, ServiceError> {
        let r = self.record_for(
            ctx,
            kind::INVOCATION_JOB,
            &input.job_identifier,
            "bedrock:GetModelInvocationJob",
            "Batch inference job",
        )?;
        Ok(from_doc(&invocation_doc(&r)))
    }

    pub fn list_model_invocation_jobs(
        &self,
        ctx: &RequestContext,
        input: types::ListModelInvocationJobsRequest,
    ) -> Result<types::ListModelInvocationJobsResponse, ServiceError> {
        ctx.authorize("bedrock:ListModelInvocationJobs", "*", ConditionContext::new())?;
        let items = self.list(
            ctx,
            kind::INVOCATION_JOB,
            Filter {
                status: input.status_equals.as_deref(),
                name: input.name_contains.as_deref(),
                after: input.submit_time_after,
                before: input.submit_time_before,
                sort_by: input.sort_by.as_deref(),
                sort_order: input.sort_order.as_deref(),
            },
            |r| from_doc::<types::ModelInvocationJobSummary>(&invocation_doc(r)),
        );
        let (items, next_token) = page(items, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListModelInvocationJobsResponse { next_token, invocation_job_summaries: Some(items) })
    }

    pub fn stop_model_invocation_job(
        &self,
        ctx: &RequestContext,
        input: types::StopModelInvocationJobRequest,
    ) -> Result<types::StopModelInvocationJobResponse, ServiceError> {
        let r = self.record_for(
            ctx,
            kind::INVOCATION_JOB,
            &input.job_identifier,
            "bedrock:StopModelInvocationJob",
            "Batch inference job",
        )?;
        self.stop(ctx, kind::INVOCATION_JOB, &r, "InProgress", "Stopped")?;
        Ok(types::StopModelInvocationJobResponse {})
    }

    /// Mark a batch inference job as running; false when it was stopped.
    pub fn start_invocation_job(&self, account: &str, region: &str, job_arn: &str, now: DateTime<Utc>) -> bool {
        self.scope_in(account, region, now, |s| {
            let Some(id) = s.find_id(kind::INVOCATION_JOB, job_arn) else { return false };
            let r = s.get_mut(kind::INVOCATION_JOB, &id).expect("record exists");
            if r.status != "Submitted" {
                return false;
            }
            r.status = "InProgress".into();
            r.updated = now;
            true
        })
    }

    /// Record a batch inference job's results (bedrock-runtime runs the
    /// records and reports here).
    pub fn finish_invocation_job(
        &self,
        account: &str,
        region: &str,
        job_arn: &str,
        now: DateTime<Utc>,
        counts: (i64, i64, i64),
        message: Option<String>,
    ) {
        self.scope_in(account, region, now, |s| {
            let Some(id) = s.find_id(kind::INVOCATION_JOB, job_arn) else { return };
            let r = s.get_mut(kind::INVOCATION_JOB, &id).expect("record exists");
            if r.status == "Stopped" {
                return;
            }
            let (total, ok, errors) = counts;
            r.status = if errors > 0 && ok > 0 {
                "PartiallyCompleted".into()
            } else if errors > 0 || message.is_some() {
                "Failed".into()
            } else {
                "Completed".into()
            };
            r.transition = None;
            r.updated = now;
            set(&mut r.doc, "end_time", ts(now));
            set(&mut r.doc, "total_record_count", total);
            set(&mut r.doc, "processed_record_count", total);
            set(&mut r.doc, "success_record_count", ok);
            set(&mut r.doc, "error_record_count", errors);
            if let Some(m) = message {
                set(&mut r.doc, "message", m);
            }
        })
    }

    // Evaluation jobs -------------------------------------------------------------

    pub fn create_evaluation_job(
        &self,
        ctx: &RequestContext,
        input: types::CreateEvaluationJobRequest,
    ) -> Result<types::CreateEvaluationJobResponse, ServiceError> {
        let tags = input.job_tags.clone().unwrap_or_default();
        check_tags(&tags, &input.job_name)?;
        let id = random_id(12);
        let job_arn = arn(ctx, &format!("evaluation-job/{id}"));
        ctx.authorize("bedrock:CreateEvaluationJob", &job_arn, request_tag_context(&tags))?;
        if self.scope(ctx, |s| s.kind(kind::EVALUATION_JOB).any(|r| r.name == input.job_name)) {
            return Err(conflict(format!("An evaluation job named {} already exists.", input.job_name)));
        }
        let now = ctx.received_at;
        let mut doc = to_doc(&input);
        doc.remove("job_tags");
        set(&mut doc, "job_arn", job_arn.clone());
        let job_type = match input.evaluation_config {
            types::EvaluationConfig::Human(_) => "Human",
            types::EvaluationConfig::Automated(_) => "Automated",
        };
        set(&mut doc, "job_type", job_type);
        self.insert_tagged(
            ctx,
            kind::EVALUATION_JOB,
            record(&id, &job_arn, &input.job_name, now, "InProgress", Some("Completed"), doc),
            &tags,
        );
        Ok(types::CreateEvaluationJobResponse { job_arn })
    }

    pub fn get_evaluation_job(
        &self,
        ctx: &RequestContext,
        input: types::GetEvaluationJobRequest,
    ) -> Result<types::GetEvaluationJobResponse, ServiceError> {
        let r = self.record_for(
            ctx,
            kind::EVALUATION_JOB,
            &input.job_identifier,
            "bedrock:GetEvaluationJob",
            "Evaluation job",
        )?;
        Ok(from_doc(&job_doc(&r, "status", "creation_time")))
    }

    pub fn list_evaluation_jobs(
        &self,
        ctx: &RequestContext,
        input: types::ListEvaluationJobsRequest,
    ) -> Result<types::ListEvaluationJobsResponse, ServiceError> {
        ctx.authorize("bedrock:ListEvaluationJobs", "*", ConditionContext::new())?;
        let app = input.application_type_equals.clone();
        let items = self.list(
            ctx,
            kind::EVALUATION_JOB,
            Filter {
                status: input.status_equals.as_deref(),
                name: input.name_contains.as_deref(),
                after: input.creation_time_after,
                before: input.creation_time_before,
                sort_by: input.sort_by.as_deref(),
                sort_order: input.sort_order.as_deref(),
            },
            |r| {
                let mut d = job_doc(r, "status", "creation_time");
                let full = Value::Object(r.doc.clone());
                let mut tasks = Vec::new();
                collect_strings(&full, "task_type", &mut tasks);
                let mut models = Vec::new();
                collect_strings(&full, "model_identifier", &mut models);
                collect_strings(&full, "inference_source_identifier", &mut models);
                set(&mut d, "evaluation_task_types", json!(tasks));
                set(&mut d, "model_identifiers", json!(models));
                (r.str("application_type").map(str::to_string), from_doc::<types::EvaluationSummary>(&d))
            },
        );
        let items: Vec<_> = items.into_iter().filter(|(a, _)| app.is_none() || a == &app).map(|(_, s)| s).collect();
        let (items, next_token) = page(items, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListEvaluationJobsResponse { next_token, job_summaries: Some(items) })
    }

    pub fn stop_evaluation_job(
        &self,
        ctx: &RequestContext,
        input: types::StopEvaluationJobRequest,
    ) -> Result<types::StopEvaluationJobResponse, ServiceError> {
        let r = self.record_for(
            ctx,
            kind::EVALUATION_JOB,
            &input.job_identifier,
            "bedrock:StopEvaluationJob",
            "Evaluation job",
        )?;
        self.stop(ctx, kind::EVALUATION_JOB, &r, "InProgress", "Stopped")?;
        Ok(types::StopEvaluationJobResponse {})
    }

    pub fn batch_delete_evaluation_job(
        &self,
        ctx: &RequestContext,
        input: types::BatchDeleteEvaluationJobRequest,
    ) -> Result<types::BatchDeleteEvaluationJobResponse, ServiceError> {
        let mut errors = Vec::new();
        let mut deleted = Vec::new();
        for ident in &input.job_identifiers {
            match self.batch_delete_one(ctx, kind::EVALUATION_JOB, ident, "bedrock:BatchDeleteEvaluationJob") {
                Ok(()) => deleted.push(types::BatchDeleteEvaluationJobItem {
                    job_identifier: ident.clone(),
                    job_status: "Deleting".into(),
                }),
                Err(e) => errors.push(types::BatchDeleteEvaluationJobError {
                    job_identifier: ident.clone(),
                    code: e.code.to_string(),
                    message: Some(e.message),
                }),
            }
        }
        Ok(types::BatchDeleteEvaluationJobResponse { errors, evaluation_jobs: deleted })
    }

    fn batch_delete_one(
        &self,
        ctx: &RequestContext,
        kind: &str,
        ident: &str,
        action: &str,
    ) -> Result<(), ServiceError> {
        let r = self.record_for(ctx, kind, ident, action, "Job")?;
        if r.status == "InProgress" {
            return Err(conflict(format!("The job {ident} is in progress. Stop it before deleting it.")));
        }
        self.scope(ctx, |s| s.remove(kind, &r.id));
        Ok(())
    }

    // Advanced prompt optimization ------------------------------------------------

    pub fn create_advanced_prompt_optimization_job(
        &self,
        ctx: &RequestContext,
        input: types::CreateAdvancedPromptOptimizationJobRequest,
    ) -> Result<types::CreateAdvancedPromptOptimizationJobResponse, ServiceError> {
        let tags = input.tags.clone().unwrap_or_default();
        check_tags(&tags, &input.job_name)?;
        let id = random_id(12);
        let job_arn = arn(ctx, &format!("advanced-prompt-optimization-job/{id}"));
        ctx.authorize("bedrock:CreateAdvancedPromptOptimizationJob", &job_arn, request_tag_context(&tags))?;
        if self.scope(ctx, |s| s.kind(kind::PROMPT_OPTIMIZATION_JOB).any(|r| r.name == input.job_name)) {
            return Err(conflict(format!("A prompt optimization job named {} already exists.", input.job_name)));
        }
        let now = ctx.received_at;
        let mut doc = to_doc(&input);
        doc.remove("tags");
        doc.remove("client_token");
        set(&mut doc, "job_arn", job_arn.clone());
        self.insert_tagged(
            ctx,
            kind::PROMPT_OPTIMIZATION_JOB,
            record(&id, &job_arn, &input.job_name, now, "InProgress", Some("Completed"), doc),
            &tags,
        );
        Ok(types::CreateAdvancedPromptOptimizationJobResponse { job_arn })
    }

    pub fn get_advanced_prompt_optimization_job(
        &self,
        ctx: &RequestContext,
        input: types::GetAdvancedPromptOptimizationJobRequest,
    ) -> Result<types::GetAdvancedPromptOptimizationJobResponse, ServiceError> {
        let r = self.record_for(
            ctx,
            kind::PROMPT_OPTIMIZATION_JOB,
            &input.job_identifier,
            "bedrock:GetAdvancedPromptOptimizationJob",
            "Prompt optimization job",
        )?;
        Ok(from_doc(&job_doc(&r, "job_status", "creation_time")))
    }

    pub fn list_advanced_prompt_optimization_jobs(
        &self,
        ctx: &RequestContext,
        input: types::ListAdvancedPromptOptimizationJobsRequest,
    ) -> Result<types::ListAdvancedPromptOptimizationJobsResponse, ServiceError> {
        ctx.authorize("bedrock:ListAdvancedPromptOptimizationJobs", "*", ConditionContext::new())?;
        let items = self.list(
            ctx,
            kind::PROMPT_OPTIMIZATION_JOB,
            Filter {
                status: None,
                name: None,
                after: None,
                before: None,
                sort_by: input.sort_by.as_deref(),
                sort_order: input.sort_order.as_deref(),
            },
            |r| from_doc::<types::AdvancedPromptOptimizationJobSummary>(&job_doc(r, "job_status", "creation_time")),
        );
        let (items, next_token) = page(items, input.max_results, input.next_token.as_deref())?;
        Ok(types::ListAdvancedPromptOptimizationJobsResponse { job_summaries: Some(items), next_token })
    }

    pub fn stop_advanced_prompt_optimization_job(
        &self,
        ctx: &RequestContext,
        input: types::StopAdvancedPromptOptimizationJobRequest,
    ) -> Result<types::StopAdvancedPromptOptimizationJobResponse, ServiceError> {
        let r = self.record_for(
            ctx,
            kind::PROMPT_OPTIMIZATION_JOB,
            &input.job_identifier,
            "bedrock:StopAdvancedPromptOptimizationJob",
            "Prompt optimization job",
        )?;
        self.stop(ctx, kind::PROMPT_OPTIMIZATION_JOB, &r, "InProgress", "Stopped")?;
        Ok(types::StopAdvancedPromptOptimizationJobResponse {})
    }

    pub fn batch_delete_advanced_prompt_optimization_job(
        &self,
        ctx: &RequestContext,
        input: types::BatchDeleteAdvancedPromptOptimizationJobRequest,
    ) -> Result<types::BatchDeleteAdvancedPromptOptimizationJobResponse, ServiceError> {
        let mut errors = Vec::new();
        let mut deleted = Vec::new();
        for ident in &input.job_identifiers {
            match self.batch_delete_one(
                ctx,
                kind::PROMPT_OPTIMIZATION_JOB,
                ident,
                "bedrock:BatchDeleteAdvancedPromptOptimizationJob",
            ) {
                Ok(()) => deleted.push(types::BatchDeleteAdvancedPromptOptimizationJobItem {
                    job_identifier: ident.clone(),
                    job_status: "Deleting".into(),
                }),
                Err(e) => errors.push(types::BatchDeleteAdvancedPromptOptimizationJobError {
                    job_identifier: ident.clone(),
                    code: e.code.to_string(),
                    message: Some(e.message),
                }),
            }
        }
        Ok(types::BatchDeleteAdvancedPromptOptimizationJobResponse {
            errors,
            advanced_prompt_optimization_jobs: deleted,
        })
    }

    // Shared listing ----------------------------------------------------------------

    fn list<T>(&self, ctx: &RequestContext, kind: &str, f: Filter<'_>, view: impl Fn(&Record) -> T) -> Vec<T> {
        self.scope(ctx, |s: &mut Scope| {
            let mut v: Vec<&Record> = s
                .kind(kind)
                .filter(|r| f.status.is_none_or(|st| r.status == st))
                .filter(|r| f.name.is_none_or(|n| r.name.contains(n)))
                .filter(|r| f.after.is_none_or(|t| r.created > t))
                .filter(|r| f.before.is_none_or(|t| r.created < t))
                .collect();
            sort_records(&mut v, f.sort_by, f.sort_order);
            v.into_iter().map(&view).collect()
        })
    }
}

/// A batch inference job for bedrock-runtime to run.
#[derive(Clone)]
pub struct BatchJob {
    /// The `CreateModelInvocationJob` request, for assuming the job role.
    pub context: RequestContext,
    pub account: String,
    pub region: String,
    pub job_arn: String,
    pub job_id: String,
    /// The foundation model that answers the records.
    pub model_id: String,
    /// Its request format.
    pub family: crate::catalog::Family,
    pub role_arn: String,
    /// When the job was created (emulated clock).
    pub submitted: DateTime<Utc>,
    pub input_uri: String,
    pub output_uri: String,
}

struct Filter<'a> {
    status: Option<&'a str>,
    name: Option<&'a str>,
    after: Option<DateTime<Utc>>,
    before: Option<DateTime<Utc>>,
    sort_by: Option<&'a str>,
    sort_order: Option<&'a str>,
}

fn job_doc(r: &Record, status_key: &str, created_key: &str) -> Map<String, Value> {
    let mut d = r.doc.clone();
    set(&mut d, "job_name", r.name.clone());
    set(&mut d, "job_arn", r.arn.clone());
    set(&mut d, status_key, r.status.clone());
    set(&mut d, created_key, ts(r.created));
    set(&mut d, "last_modified_time", ts(r.updated));
    if matches!(r.status.as_str(), "Completed" | "Failed" | "Stopped") && !d.contains_key("end_time") {
        set(&mut d, "end_time", ts(r.updated));
    }
    d
}

fn model_doc(r: &Record) -> Map<String, Value> {
    let mut d = r.doc.clone();
    set(&mut d, "model_arn", r.arn.clone());
    set(&mut d, "model_name", r.name.clone());
    set(&mut d, "creation_time", ts(r.created));
    set(&mut d, "model_status", r.status.clone());
    d
}

fn deployment_doc(r: &Record) -> Map<String, Value> {
    let mut d = r.doc.clone();
    set(&mut d, "custom_model_deployment_arn", r.arn.clone());
    set(&mut d, "model_deployment_name", r.name.clone());
    set(&mut d, "created_at", ts(r.created));
    set(&mut d, "last_updated_at", ts(r.updated));
    set(&mut d, "status", r.status.clone());
    d
}

fn invocation_doc(r: &Record) -> Map<String, Value> {
    let mut d = job_doc(r, "status", "submit_time");
    d.remove("creation_time");
    d
}

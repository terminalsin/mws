//! Tags, OpenTelemetry enrichment of vended metrics, resource metrics
//! configurations and the metrics dataset's KMS key.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::names::{self, request_tag_conditions, resource_tag_conditions};
use crate::state::{OTelEnrichment, State};
use crate::CloudWatch;

const DEFAULT_DATASET: &str = "default";

/// The state key and resource kind an ARN names, when it is one of the
/// caller's CloudWatch resources.
fn locate<'a>(ctx: &RequestContext, arn: &'a str) -> Result<(String, &'a str, &'a str), ServiceError> {
    let invalid =
        || errors::invalid_parameter_value(format!("The value {arn} for parameter ResourceARN is not valid."));
    let parts: Vec<&str> = arn.splitn(6, ':').collect();
    if parts.len() != 6 || parts[0] != "arn" || parts[2] != "cloudwatch" {
        return Err(invalid());
    }
    let (region, account, resource) = (parts[3], parts[4], parts[5]);
    if account != ctx.caller.account_id {
        return Err(not_found());
    }
    let (kind, name) = if let Some(n) = resource.strip_prefix("alarm:") {
        ("alarm", n)
    } else if let Some(n) = resource.strip_prefix("alarm-mute-rule:") {
        ("mute", n)
    } else if let Some(n) = resource.strip_prefix("dashboard/") {
        ("dashboard", n)
    } else if let Some(n) = resource.strip_prefix("insight-rule/") {
        ("insight", n)
    } else if let Some(n) = resource.strip_prefix("metric-stream/") {
        ("stream", n)
    } else {
        return Err(invalid());
    };
    let region = if kind == "dashboard" { crate::dashboards::global() } else { region };
    Ok((region.to_string(), kind, name))
}

fn not_found() -> ServiceError {
    errors::resource_not_found_exception("The specified resource does not exist.")
}

fn exists(st: &State, account: &str, region: &str, kind: &str, name: &str) -> bool {
    let Some(r) = st.region_ref(account, region) else { return false };
    match kind {
        "alarm" => r.alarms.contains_key(name),
        "mute" => r.mute_rules.contains_key(name),
        "dashboard" => r.dashboards.contains_key(name),
        "insight" => r.insight_rules.contains_key(name),
        "stream" => r.metric_streams.contains_key(name),
        _ => false,
    }
}

fn otel_out(
    o: &OTelEnrichment,
) -> (Option<Vec<types::OTelEnrichmentMetricSelector>>, Option<Vec<types::OTelEnrichmentMetricSelector>>) {
    (o.include_filters.clone(), o.exclude_filters.clone())
}

fn validate_selectors(
    include: Option<&[types::OTelEnrichmentMetricSelector]>,
    exclude: Option<&[types::OTelEnrichmentMetricSelector]>,
) -> Result<(), ServiceError> {
    for (field, list) in [("IncludeFilters", include), ("ExcludeFilters", exclude)] {
        for (i, s) in list.unwrap_or_default().iter().enumerate() {
            if !s.namespace.starts_with("AWS/") {
                return Err(errors::validation(format!(
                    "{field}.member.{}.Namespace must be the namespace of an AWS vended metric (AWS/...).",
                    i + 1
                )));
            }
        }
    }
    Ok(())
}

fn valid_resource_arn(arn: &str) -> bool {
    let p: Vec<&str> = arn.splitn(6, ':').collect();
    p.len() == 6 && p[0] == "arn" && !p[1].is_empty() && !p[2].is_empty() && !p[5].is_empty()
}

impl CloudWatch {
    fn tags_of(&self, ctx: &RequestContext, region: &str, arn: &str) -> Option<BTreeMap<String, String>> {
        self.lock().region_ref(&ctx.caller.account_id, region).and_then(|r| r.tags.get(arn).cloned())
    }

    pub(crate) fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceInput,
    ) -> Result<types::TagResourceOutput, ServiceError> {
        let (region, kind, name) = locate(ctx, &input.resource_arn)?;
        let mut conds = request_tag_conditions(&input.tags);
        conds.extend(resource_tag_conditions(self.tags_of(ctx, &region, &input.resource_arn).as_ref()));
        ctx.authorize("cloudwatch:TagResource", &input.resource_arn, conds)?;
        if let Some(t) = input.tags.iter().find(|t| t.key.starts_with("aws:")) {
            return Err(errors::invalid_parameter_value(format!(
                "Tag keys beginning with aws: are reserved for AWS use: {}",
                t.key
            )));
        }
        let mut st = self.lock();
        if !exists(&st, &ctx.caller.account_id, &region, kind, name) {
            return Err(not_found());
        }
        let tags = st.region(&ctx.caller.account_id, &region).tags.entry(input.resource_arn.clone()).or_default();
        let mut merged = tags.clone();
        for t in input.tags {
            merged.insert(t.key, t.value);
        }
        if merged.len() > 50 {
            return Err(errors::invalid_parameter_value("The number of tags on a resource must not exceed 50."));
        }
        *tags = merged;
        Ok(types::TagResourceOutput {})
    }

    pub(crate) fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceInput,
    ) -> Result<types::UntagResourceOutput, ServiceError> {
        let (region, kind, name) = locate(ctx, &input.resource_arn)?;
        let mut conds = resource_tag_conditions(self.tags_of(ctx, &region, &input.resource_arn).as_ref());
        conds.insert("aws:TagKeys".into(), input.tag_keys.clone());
        ctx.authorize("cloudwatch:UntagResource", &input.resource_arn, conds)?;
        let mut st = self.lock();
        if !exists(&st, &ctx.caller.account_id, &region, kind, name) {
            return Err(not_found());
        }
        let r = st.region(&ctx.caller.account_id, &region);
        if let Some(tags) = r.tags.get_mut(&input.resource_arn) {
            for k in &input.tag_keys {
                tags.remove(k);
            }
            if tags.is_empty() {
                r.tags.remove(&input.resource_arn);
            }
        }
        Ok(types::UntagResourceOutput {})
    }

    pub(crate) fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceInput,
    ) -> Result<types::ListTagsForResourceOutput, ServiceError> {
        let (region, kind, name) = locate(ctx, &input.resource_arn)?;
        let tags = self.tags_of(ctx, &region, &input.resource_arn);
        ctx.authorize("cloudwatch:ListTagsForResource", &input.resource_arn, resource_tag_conditions(tags.as_ref()))?;
        if !exists(&self.lock(), &ctx.caller.account_id, &region, kind, name) {
            return Err(not_found());
        }
        let tags = tags.unwrap_or_default().into_iter().map(|(key, value)| types::Tag { key, value }).collect();
        Ok(types::ListTagsForResourceOutput { tags: Some(tags) })
    }

    pub(crate) fn start_o_tel_enrichment(
        &self,
        ctx: &RequestContext,
        input: types::StartOTelEnrichmentInput,
    ) -> Result<types::StartOTelEnrichmentOutput, ServiceError> {
        ctx.authorize("cloudwatch:StartOTelEnrichment", &names::any(ctx), ConditionContext::new())?;
        validate_selectors(input.include_filters.as_deref(), input.exclude_filters.as_deref())?;
        let now = names::now(ctx);
        let mut st = self.lock();
        let r = st.region(&ctx.caller.account_id, &ctx.region);
        let created = r.otel.as_ref().map(|o| o.created).unwrap_or(now);
        let o = OTelEnrichment {
            running: true,
            include_filters: input.include_filters,
            exclude_filters: input.exclude_filters,
            created,
            updated: now,
        };
        let (include_filters, exclude_filters) = otel_out(&o);
        r.otel = Some(o);
        Ok(types::StartOTelEnrichmentOutput {
            include_filters,
            exclude_filters,
            created_at: Some(created),
            updated_at: Some(now),
        })
    }

    pub(crate) fn update_o_tel_enrichment(
        &self,
        ctx: &RequestContext,
        input: types::UpdateOTelEnrichmentInput,
    ) -> Result<types::UpdateOTelEnrichmentOutput, ServiceError> {
        ctx.authorize("cloudwatch:UpdateOTelEnrichment", &names::any(ctx), ConditionContext::new())?;
        validate_selectors(input.include_filters.as_deref(), input.exclude_filters.as_deref())?;
        let now = names::now(ctx);
        let mut st = self.lock();
        let r = st.region(&ctx.caller.account_id, &ctx.region);
        let o = r.otel.as_mut().filter(|o| o.running).ok_or_else(|| {
            errors::validation("OTel enrichment is not enabled for this account. Call StartOTelEnrichment first.")
        })?;
        o.include_filters = input.include_filters;
        o.exclude_filters = input.exclude_filters;
        o.updated = now;
        let (include_filters, exclude_filters) = otel_out(o);
        Ok(types::UpdateOTelEnrichmentOutput {
            include_filters,
            exclude_filters,
            created_at: Some(o.created),
            updated_at: Some(now),
        })
    }

    pub(crate) fn get_o_tel_enrichment(
        &self,
        ctx: &RequestContext,
        _input: types::GetOTelEnrichmentInput,
    ) -> Result<types::GetOTelEnrichmentOutput, ServiceError> {
        ctx.authorize("cloudwatch:GetOTelEnrichment", &names::any(ctx), ConditionContext::new())?;
        let st = self.lock();
        let o = st.region_ref(&ctx.caller.account_id, &ctx.region).and_then(|r| r.otel.as_ref());
        Ok(match o {
            Some(o) if o.running => types::GetOTelEnrichmentOutput {
                status: "Running".into(),
                include_filters: o.include_filters.clone(),
                exclude_filters: o.exclude_filters.clone(),
                created_at: Some(o.created),
                updated_at: Some(o.updated),
            },
            _ => types::GetOTelEnrichmentOutput { status: "Stopped".into(), ..Default::default() },
        })
    }

    pub(crate) fn stop_o_tel_enrichment(
        &self,
        ctx: &RequestContext,
        _input: types::StopOTelEnrichmentInput,
    ) -> Result<types::StopOTelEnrichmentOutput, ServiceError> {
        ctx.authorize("cloudwatch:StopOTelEnrichment", &names::any(ctx), ConditionContext::new())?;
        let mut st = self.lock();
        let r = st.region(&ctx.caller.account_id, &ctx.region);
        if let Some(o) = r.otel.as_mut() {
            o.running = false;
            o.updated = names::now(ctx);
        }
        Ok(types::StopOTelEnrichmentOutput {})
    }

    fn resource_metrics_arn(ctx: &RequestContext, action: &str, arn: &str) -> Result<(), ServiceError> {
        ctx.authorize(&format!("cloudwatch:{action}"), arn, ConditionContext::new())?;
        if !valid_resource_arn(arn) {
            return Err(errors::validation(format!("The value {arn} for parameter ResourceArn is not a valid ARN.")));
        }
        Ok(())
    }

    fn validate_selections(selections: Option<&[types::ResourceMetricSelection]>) -> Result<(), ServiceError> {
        for (i, s) in selections.unwrap_or_default().iter().enumerate() {
            if s.include_metrics.is_empty() {
                return Err(errors::validation(format!(
                    "MetricSelections.member.{}.IncludeMetrics must name at least one metric.",
                    i + 1
                )));
            }
        }
        Ok(())
    }

    pub(crate) fn create_resource_metrics_configuration(
        &self,
        ctx: &RequestContext,
        input: types::CreateResourceMetricsConfigurationInput,
    ) -> Result<types::CreateResourceMetricsConfigurationOutput, ServiceError> {
        Self::resource_metrics_arn(ctx, "CreateResourceMetricsConfiguration", &input.resource_arn)?;
        Self::validate_selections(input.metric_selections.as_deref())?;
        let now = names::now(ctx);
        let mut st = self.lock();
        let r = st.region(&ctx.caller.account_id, &ctx.region);
        if r.resource_metrics.contains_key(&input.resource_arn) {
            return Err(errors::conflict(format!(
                "A resource metrics configuration already exists for resource {}.",
                input.resource_arn
            )));
        }
        let c = types::ResourceMetricsConfiguration {
            resource_arn: input.resource_arn.clone(),
            created_at: now,
            updated_at: now,
            metric_selections: input.metric_selections,
        };
        r.resource_metrics.insert(input.resource_arn, c.clone());
        Ok(types::CreateResourceMetricsConfigurationOutput { resource_metrics_configuration: c })
    }

    fn resource_metrics_missing(arn: &str) -> ServiceError {
        errors::resource_not_found_exception(format!("No resource metrics configuration exists for resource {arn}."))
    }

    pub(crate) fn get_resource_metrics_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetResourceMetricsConfigurationInput,
    ) -> Result<types::GetResourceMetricsConfigurationOutput, ServiceError> {
        Self::resource_metrics_arn(ctx, "GetResourceMetricsConfiguration", &input.resource_arn)?;
        let st = self.lock();
        let c = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .and_then(|r| r.resource_metrics.get(&input.resource_arn))
            .ok_or_else(|| Self::resource_metrics_missing(&input.resource_arn))?;
        Ok(types::GetResourceMetricsConfigurationOutput { resource_metrics_configuration: c.clone() })
    }

    pub(crate) fn update_resource_metrics_configuration(
        &self,
        ctx: &RequestContext,
        input: types::UpdateResourceMetricsConfigurationInput,
    ) -> Result<types::UpdateResourceMetricsConfigurationOutput, ServiceError> {
        Self::resource_metrics_arn(ctx, "UpdateResourceMetricsConfiguration", &input.resource_arn)?;
        Self::validate_selections(input.metric_selections.as_deref())?;
        let mut st = self.lock();
        let c = st
            .region(&ctx.caller.account_id, &ctx.region)
            .resource_metrics
            .get_mut(&input.resource_arn)
            .ok_or_else(|| Self::resource_metrics_missing(&input.resource_arn))?;
        c.metric_selections = input.metric_selections;
        c.updated_at = names::now(ctx);
        Ok(types::UpdateResourceMetricsConfigurationOutput { resource_metrics_configuration: c.clone() })
    }

    pub(crate) fn delete_resource_metrics_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DeleteResourceMetricsConfigurationInput,
    ) -> Result<types::DeleteResourceMetricsConfigurationOutput, ServiceError> {
        Self::resource_metrics_arn(ctx, "DeleteResourceMetricsConfiguration", &input.resource_arn)?;
        let mut st = self.lock();
        st.region(&ctx.caller.account_id, &ctx.region)
            .resource_metrics
            .remove(&input.resource_arn)
            .ok_or_else(|| Self::resource_metrics_missing(&input.resource_arn))?;
        Ok(types::DeleteResourceMetricsConfigurationOutput {})
    }

    /// The dataset id an identifier names (`default` or its ARN).
    fn dataset_id(ctx: &RequestContext, action: &str, identifier: &str) -> Result<String, ServiceError> {
        let arn = names::dataset_arn(ctx, DEFAULT_DATASET);
        ctx.authorize(&format!("cloudwatch:{action}"), &arn, ConditionContext::new())?;
        if identifier == DEFAULT_DATASET || identifier == arn {
            Ok(DEFAULT_DATASET.into())
        } else {
            Err(errors::resource_not_found_exception(format!("Dataset {identifier} does not exist.")))
        }
    }

    pub(crate) fn get_dataset(
        &self,
        ctx: &RequestContext,
        input: types::GetDatasetInput,
    ) -> Result<types::GetDatasetOutput, ServiceError> {
        let id = Self::dataset_id(ctx, "GetDataset", &input.dataset_identifier)?;
        let st = self.lock();
        let key =
            st.region_ref(&ctx.caller.account_id, &ctx.region).and_then(|r| r.datasets.get(&id).cloned().flatten());
        Ok(types::GetDatasetOutput { arn: names::dataset_arn(ctx, &id), dataset_id: id, kms_key_arn: key })
    }

    /// Check that CloudWatch may use `key` for the caller, as AWS does by
    /// encrypting and decrypting with it through `monitoring`.
    fn check_key(&self, ctx: &RequestContext, key: &str) -> Result<String, ServiceError> {
        let Some(kms) = self.inner.kms.get() else {
            return Err(errors::kms_key_not_found(format!("The KMS key {key} does not exist.")));
        };
        let context =
            BTreeMap::from([("aws:cloudwatch:dataset".to_string(), names::dataset_arn(ctx, DEFAULT_DATASET))]);
        let map = |e: ServiceError| match e.code.as_ref() {
            "NotFoundException" | "InvalidArnException" => errors::kms_key_not_found(e.message),
            "DisabledException" | "KMSInvalidStateException" => errors::kms_key_disabled(e.message),
            "AccessDeniedException" => errors::kms_access_denied(e.message),
            _ => errors::kms_access_denied(e.message),
        };
        let (arn, ciphertext) =
            kms.encrypt_via(ctx, "monitoring", key, b"cloudwatch-dataset-check", &context).map_err(map)?;
        kms.decrypt_via(ctx, "monitoring", &ciphertext, &context).map_err(map)?;
        Ok(arn)
    }

    pub(crate) fn associate_dataset_kms_key(
        &self,
        ctx: &RequestContext,
        input: types::AssociateDatasetKmsKeyInput,
    ) -> Result<types::AssociateDatasetKmsKeyOutput, ServiceError> {
        let id = Self::dataset_id(ctx, "AssociateDatasetKmsKey", &input.dataset_identifier)?;
        if !input.kms_key_arn.starts_with("arn:") {
            return Err(errors::validation("The KMS key must be specified by its key ARN."));
        }
        let arn = self.check_key(ctx, &input.kms_key_arn)?;
        let current = self
            .lock()
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .and_then(|r| r.datasets.get(&id).cloned().flatten());
        // Replacing a key needs kms:Decrypt on the current one too, unless
        // that key is no longer usable.
        if let Some(cur) = current.filter(|c| *c != arn) {
            if let Err(e) = self.check_key(ctx, &cur) {
                if e.code == "KmsAccessDeniedException" {
                    return Err(e);
                }
            }
        }
        self.lock().region(&ctx.caller.account_id, &ctx.region).datasets.insert(id, Some(arn));
        Ok(types::AssociateDatasetKmsKeyOutput {})
    }

    pub(crate) fn disassociate_dataset_kms_key(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateDatasetKmsKeyInput,
    ) -> Result<types::DisassociateDatasetKmsKeyOutput, ServiceError> {
        let id = Self::dataset_id(ctx, "DisassociateDatasetKmsKey", &input.dataset_identifier)?;
        self.lock().region(&ctx.caller.account_id, &ctx.region).datasets.remove(&id);
        Ok(types::DisassociateDatasetKmsKeyOutput {})
    }
}

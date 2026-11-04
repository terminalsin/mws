//! Transformers, anomaly detectors, OpenSearch and S3 Tables
//! integrations, lookup tables, scheduled queries, the storage tier and
//! syslog configurations.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::names::{arn, check_tags, now_ms, page, random_alnum, request_tag_conditions, uuid, GroupRef};
use crate::state::{AnomalyDetector, Integration, LookupTable, ScheduledQuery, Transformer};
use crate::transform;
use crate::Logs;

/// A lookup table body: CSV with a header row.
fn csv_shape(body: &str) -> (Vec<String>, i64) {
    let mut lines = body.lines().filter(|l| !l.trim().is_empty());
    let header = lines.next().map(|h| h.split(',').map(|c| c.trim().to_string()).collect()).unwrap_or_default();
    (header, lines.count() as i64)
}

fn check_schedule(expr: &str) -> Result<(), ServiceError> {
    let ok = (expr.starts_with("cron(") || expr.starts_with("rate(")) && expr.ends_with(')');
    if !ok {
        return Err(errors::validation(format!("Invalid schedule expression: {expr}. Use cron(...) or rate(...).")));
    }
    if mws_schedule::Schedule::parse(expr).is_none() {
        let what = if expr.starts_with("rate(") { "rate" } else { "cron" };
        return Err(errors::validation(format!("Invalid {what} expression: {expr}")));
    }
    Ok(())
}

impl Logs {
    // ---- transformers --------------------------------------------------------

    pub(crate) fn put_transformer(
        &self,
        ctx: &RequestContext,
        input: types::PutTransformerRequest,
    ) -> Result<(), ServiceError> {
        let g = GroupRef::parse(ctx, &input.log_group_identifier)?;
        self.authorize_group(ctx, "PutTransformer", &g, None, ConditionContext::new())?;
        transform::validate(&input.transformer_config).map_err(errors::invalid_parameter)?;
        let now = now_ms(ctx);
        let mut st = self.lock();
        let group = st.group_mut(&g)?;
        if group.class == "INFREQUENT_ACCESS" {
            return Err(errors::invalid_operation(
                "Transformers are not supported for log groups of the INFREQUENT_ACCESS class.",
            ));
        }
        let created = group.transformer.as_ref().map_or(now, |t| t.creation_time);
        group.transformer =
            Some(Transformer { processors: input.transformer_config, creation_time: created, last_modified_time: now });
        Ok(())
    }

    pub(crate) fn get_transformer(
        &self,
        ctx: &RequestContext,
        input: types::GetTransformerRequest,
    ) -> Result<types::GetTransformerResponse, ServiceError> {
        let g = GroupRef::parse(ctx, &input.log_group_identifier)?;
        self.authorize_group(ctx, "GetTransformer", &g, None, ConditionContext::new())?;
        let st = self.lock();
        let t = st.group(&g)?.transformer.clone();
        Ok(types::GetTransformerResponse {
            log_group_identifier: Some(input.log_group_identifier),
            creation_time: t.as_ref().map(|t| t.creation_time),
            last_modified_time: t.as_ref().map(|t| t.last_modified_time),
            transformer_config: t.map(|t| t.processors),
        })
    }

    pub(crate) fn delete_transformer(
        &self,
        ctx: &RequestContext,
        input: types::DeleteTransformerRequest,
    ) -> Result<(), ServiceError> {
        let g = GroupRef::parse(ctx, &input.log_group_identifier)?;
        self.authorize_group(ctx, "DeleteTransformer", &g, None, ConditionContext::new())?;
        let mut st = self.lock();
        st.group_mut(&g)?
            .transformer
            .take()
            .ok_or_else(|| errors::resource_not_found("No transformer found for the log group."))?;
        Ok(())
    }

    pub(crate) fn test_transformer(
        &self,
        ctx: &RequestContext,
        input: types::TestTransformerRequest,
    ) -> Result<types::TestTransformerResponse, ServiceError> {
        self.authorize(ctx, "TestTransformer", "*", ConditionContext::new())?;
        transform::validate(&input.transformer_config).map_err(errors::invalid_parameter)?;
        let mut out = Vec::new();
        for (i, m) in input.log_event_messages.iter().enumerate() {
            let t = transform::run(&input.transformer_config, m).map_err(errors::invalid_operation)?;
            out.push(types::TransformedLogRecord {
                event_number: i as i64 + 1,
                event_message: Some(m.clone()),
                transformed_event_message: Some(t),
            });
        }
        Ok(types::TestTransformerResponse { transformed_logs: Some(out) })
    }

    // ---- anomaly detectors ------------------------------------------------------

    pub(crate) fn create_log_anomaly_detector(
        &self,
        ctx: &RequestContext,
        input: types::CreateLogAnomalyDetectorRequest,
    ) -> Result<types::CreateLogAnomalyDetectorResponse, ServiceError> {
        let a = arn(ctx, &format!("anomaly-detector:{}", uuid()));
        let tags = input.tags.clone().unwrap_or_default();
        self.authorize(ctx, "CreateLogAnomalyDetector", &a, request_tag_conditions(&tags))?;
        check_tags(0, &tags)?;
        for g in &input.log_group_arn_list {
            let g = GroupRef::parse(ctx, g)?;
            self.lock().group(&g)?;
        }
        if let Some(t) = input.anomaly_visibility_time {
            if !(7..=90).contains(&t) {
                return Err(errors::invalid_parameter("anomalyVisibilityTime must be between 7 and 90 days."));
            }
        }
        if let Some(p) = &input.filter_pattern {
            crate::events::parse_pattern(Some(p))?;
        }
        let now = now_ms(ctx);
        let record = types::AnomalyDetector {
            anomaly_detector_arn: Some(a.clone()),
            detector_name: input.detector_name,
            log_group_arn_list: Some(input.log_group_arn_list),
            evaluation_frequency: input.evaluation_frequency,
            filter_pattern: input.filter_pattern,
            anomaly_detector_status: Some("INITIALIZING".into()),
            kms_key_id: input.kms_key_id,
            creation_time_stamp: now,
            last_modified_time_stamp: now,
            anomaly_visibility_time: Some(input.anomaly_visibility_time.unwrap_or(21)),
        };
        self.lock()
            .region(&ctx.caller.account_id, &ctx.region)
            .anomaly_detectors
            .insert(a.clone(), AnomalyDetector { record, tags, anomalies: Vec::new() });
        Ok(types::CreateLogAnomalyDetectorResponse { anomaly_detector_arn: Some(a) })
    }

    fn with_detector<R>(
        &self,
        ctx: &RequestContext,
        action: &str,
        detector_arn: &str,
        f: impl FnOnce(&mut AnomalyDetector) -> Result<R, ServiceError>,
    ) -> Result<R, ServiceError> {
        self.authorize(ctx, action, detector_arn, ConditionContext::new())?;
        let mut st = self.lock();
        let d = st
            .region(&ctx.caller.account_id, &ctx.region)
            .anomaly_detectors
            .get_mut(detector_arn)
            .ok_or_else(|| errors::resource_not_found("The specified anomaly detector does not exist."))?;
        f(d)
    }

    pub(crate) fn get_log_anomaly_detector(
        &self,
        ctx: &RequestContext,
        input: types::GetLogAnomalyDetectorRequest,
    ) -> Result<types::GetLogAnomalyDetectorResponse, ServiceError> {
        self.with_detector(ctx, "GetLogAnomalyDetector", &input.anomaly_detector_arn, |d| {
            let r = d.record.clone();
            Ok(types::GetLogAnomalyDetectorResponse {
                detector_name: r.detector_name,
                log_group_arn_list: r.log_group_arn_list,
                evaluation_frequency: r.evaluation_frequency,
                filter_pattern: r.filter_pattern,
                anomaly_detector_status: r.anomaly_detector_status,
                kms_key_id: r.kms_key_id,
                creation_time_stamp: r.creation_time_stamp,
                last_modified_time_stamp: r.last_modified_time_stamp,
                anomaly_visibility_time: r.anomaly_visibility_time,
            })
        })
    }

    pub(crate) fn update_log_anomaly_detector(
        &self,
        ctx: &RequestContext,
        input: types::UpdateLogAnomalyDetectorRequest,
    ) -> Result<(), ServiceError> {
        let now = now_ms(ctx);
        if let Some(p) = &input.filter_pattern {
            crate::events::parse_pattern(Some(p))?;
        }
        self.with_detector(ctx, "UpdateLogAnomalyDetector", &input.anomaly_detector_arn, |d| {
            let r = &mut d.record;
            if let Some(f) = input.evaluation_frequency {
                r.evaluation_frequency = Some(f);
            }
            if let Some(p) = input.filter_pattern {
                r.filter_pattern = Some(p);
            }
            if let Some(t) = input.anomaly_visibility_time {
                r.anomaly_visibility_time = Some(t);
            }
            r.anomaly_detector_status = Some(if input.enabled { "ANALYZING" } else { "PAUSED" }.into());
            r.last_modified_time_stamp = now;
            Ok(())
        })
    }

    pub(crate) fn delete_log_anomaly_detector(
        &self,
        ctx: &RequestContext,
        input: types::DeleteLogAnomalyDetectorRequest,
    ) -> Result<(), ServiceError> {
        self.with_detector(ctx, "DeleteLogAnomalyDetector", &input.anomaly_detector_arn, |_| Ok(()))?;
        self.lock().region(&ctx.caller.account_id, &ctx.region).anomaly_detectors.remove(&input.anomaly_detector_arn);
        Ok(())
    }

    pub(crate) fn list_log_anomaly_detectors(
        &self,
        ctx: &RequestContext,
        input: types::ListLogAnomalyDetectorsRequest,
    ) -> Result<types::ListLogAnomalyDetectorsResponse, ServiceError> {
        self.authorize(ctx, "ListLogAnomalyDetectors", &arn(ctx, "anomaly-detector:*"), ConditionContext::new())?;
        let want = input.filter_log_group_arn.as_ref().map(|a| a.trim_end_matches(":*").to_string());
        let st = self.lock();
        let out: Vec<_> = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .map(|r| {
                r.anomaly_detectors
                    .values()
                    .filter(|d| {
                        want.as_ref().is_none_or(|w| {
                            d.record.log_group_arn_list.iter().flatten().any(|a| a.trim_end_matches(":*") == w)
                        })
                    })
                    .map(|d| d.record.clone())
                    .collect()
            })
            .unwrap_or_default();
        let (out, next_token) =
            page(out, input.next_token.as_deref(), input.limit.unwrap_or(50).clamp(1, 50) as usize)?;
        Ok(types::ListLogAnomalyDetectorsResponse { anomaly_detectors: Some(out), next_token })
    }

    pub(crate) fn list_anomalies(
        &self,
        ctx: &RequestContext,
        input: types::ListAnomaliesRequest,
    ) -> Result<types::ListAnomaliesResponse, ServiceError> {
        let mut out = Vec::new();
        match &input.anomaly_detector_arn {
            Some(a) => {
                let anomalies = self.with_detector(ctx, "ListAnomalies", a, |d| Ok(d.anomalies.clone()))?;
                out.extend(anomalies);
            }
            None => {
                self.authorize(ctx, "ListAnomalies", &arn(ctx, "anomaly-detector:*"), ConditionContext::new())?;
                let st = self.lock();
                if let Some(r) = st.region_ref(&ctx.caller.account_id, &ctx.region) {
                    out.extend(r.anomaly_detectors.values().flat_map(|d| d.anomalies.iter().cloned()));
                }
            }
        }
        out.retain(|a| match input.suppression_state.as_deref() {
            Some("SUPPRESSED") => a.suppressed == Some(true),
            Some("UNSUPPRESSED") => a.suppressed != Some(true),
            _ => true,
        });
        let (out, next_token) =
            page(out, input.next_token.as_deref(), input.limit.unwrap_or(50).clamp(1, 50) as usize)?;
        Ok(types::ListAnomaliesResponse { anomalies: Some(out), next_token })
    }

    pub(crate) fn update_anomaly(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAnomalyRequest,
    ) -> Result<(), ServiceError> {
        if input.anomaly_id.is_none() && input.pattern_id.is_none() {
            return Err(errors::invalid_parameter("Either anomalyId or patternId must be specified."));
        }
        if input.suppression_type.as_deref() == Some("LIMITED") && input.suppression_period.is_none() {
            return Err(errors::invalid_parameter("suppressionPeriod is required when suppressionType is LIMITED."));
        }
        let now = now_ms(ctx);
        self.with_detector(ctx, "UpdateAnomaly", &input.anomaly_detector_arn, |d| {
            let hits: Vec<&mut types::Anomaly> = d
                .anomalies
                .iter_mut()
                .filter(|a| {
                    input.anomaly_id.as_ref().is_some_and(|id| &a.anomaly_id == id)
                        || input.pattern_id.as_ref().is_some_and(|p| &a.pattern_id == p)
                })
                .collect();
            if hits.is_empty() {
                return Err(errors::resource_not_found("The specified anomaly does not exist."));
            }
            for a in hits {
                if let Some(b) = input.baseline {
                    a.state = if b { "Baseline" } else { "Active" }.into();
                }
                if let Some(t) = &input.suppression_type {
                    a.suppressed = Some(true);
                    a.suppressed_date = now;
                    a.state = "Suppressed".into();
                    a.is_pattern_level_suppression = Some(input.pattern_id.is_some());
                    a.suppressed_until = match (t.as_str(), &input.suppression_period) {
                        ("LIMITED", Some(p)) => {
                            let unit = match p.suppression_unit.as_deref() {
                                Some("SECONDS") => 1000,
                                Some("MINUTES") => 60_000,
                                _ => 3_600_000,
                            };
                            now + i64::from(p.value) * unit
                        }
                        _ => 0,
                    };
                }
            }
            Ok(())
        })
    }

    // ---- integrations -----------------------------------------------------------

    pub(crate) fn put_integration(
        &self,
        ctx: &RequestContext,
        input: types::PutIntegrationRequest,
    ) -> Result<types::PutIntegrationResponse, ServiceError> {
        self.authorize(
            ctx,
            "PutIntegration",
            &arn(ctx, &format!("integration:{}", input.integration_name)),
            ConditionContext::new(),
        )?;
        let types::ResourceConfig::OpenSearchResourceConfig(cfg) = &input.resource_config;
        if !cfg.data_source_role_arn.starts_with("arn:") {
            return Err(errors::validation("dataSourceRoleArn must be an IAM role ARN."));
        }
        let active = || Some(types::OpenSearchResourceStatus { status: Some("ACTIVE".into()), status_message: None });
        let base = input.integration_name.replace(['_', ' '], "-").to_lowercase();
        let account = &ctx.caller.account_id;
        let region = &ctx.region;
        let collection_id = random_alnum(20).to_lowercase();
        let details = types::OpenSearchIntegrationDetails {
            data_source: Some(types::OpenSearchDataSource {
                data_source_name: Some(base.replace('-', "_")),
                status: active(),
            }),
            application: Some(types::OpenSearchApplication {
                application_endpoint: Some(format!("https://application-{base}.{region}.opensearch.amazonaws.com")),
                application_arn: Some(cfg.application_arn.clone().unwrap_or_else(|| {
                    format!(
                        "arn:{}:opensearch:{region}:{account}:application/{}",
                        ctx.partition,
                        random_alnum(12).to_lowercase()
                    )
                })),
                application_id: Some(random_alnum(12).to_lowercase()),
                status: active(),
            }),
            collection: Some(types::OpenSearchCollection {
                collection_endpoint: Some(format!("https://{collection_id}.{region}.aoss.amazonaws.com")),
                collection_arn: Some(format!(
                    "arn:{}:aoss:{region}:{account}:collection/{collection_id}",
                    ctx.partition
                )),
                status: active(),
            }),
            workspace: Some(types::OpenSearchWorkspace {
                workspace_id: Some(random_alnum(12).to_lowercase()),
                status: active(),
            }),
            encryption_policy: Some(types::OpenSearchEncryptionPolicy {
                policy_name: Some(format!("{base}-ep")),
                status: active(),
            }),
            network_policy: Some(types::OpenSearchNetworkPolicy {
                policy_name: Some(format!("{base}-np")),
                status: active(),
            }),
            access_policy: Some(types::OpenSearchDataAccessPolicy {
                policy_name: Some(format!("{base}-ap")),
                status: active(),
            }),
            lifecycle_policy: Some(types::OpenSearchLifecyclePolicy {
                policy_name: Some(format!("{base}-lp")),
                status: active(),
            }),
        };
        let mut st = self.lock();
        let r = st.region(account, region);
        if r.integrations.contains_key(&input.integration_name) {
            return Err(errors::validation(format!("An integration named {} already exists.", input.integration_name)));
        }
        r.integrations.insert(
            input.integration_name.clone(),
            Integration {
                name: input.integration_name.clone(),
                integration_type: input.integration_type,
                status: "ACTIVE".into(),
                details: Some(types::IntegrationDetails::OpenSearchIntegrationDetails(details)),
                config: Some(input.resource_config),
            },
        );
        Ok(types::PutIntegrationResponse {
            integration_name: Some(input.integration_name),
            integration_status: Some("ACTIVE".into()),
        })
    }

    pub(crate) fn get_integration(
        &self,
        ctx: &RequestContext,
        input: types::GetIntegrationRequest,
    ) -> Result<types::GetIntegrationResponse, ServiceError> {
        self.authorize(
            ctx,
            "GetIntegration",
            &arn(ctx, &format!("integration:{}", input.integration_name)),
            ConditionContext::new(),
        )?;
        let st = self.lock();
        let i = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .and_then(|r| r.integrations.get(&input.integration_name))
            .ok_or_else(|| errors::resource_not_found("The specified integration does not exist."))?;
        Ok(types::GetIntegrationResponse {
            integration_name: Some(i.name.clone()),
            integration_type: Some(i.integration_type.clone()),
            integration_status: Some(i.status.clone()),
            integration_details: i.details.clone(),
        })
    }

    pub(crate) fn list_integrations(
        &self,
        ctx: &RequestContext,
        input: types::ListIntegrationsRequest,
    ) -> Result<types::ListIntegrationsResponse, ServiceError> {
        self.authorize(ctx, "ListIntegrations", "*", ConditionContext::new())?;
        let st = self.lock();
        let out = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .map(|r| {
                r.integrations
                    .values()
                    .filter(|i| input.integration_name_prefix.as_ref().is_none_or(|p| i.name.starts_with(p.as_str())))
                    .filter(|i| input.integration_type.as_ref().is_none_or(|t| &i.integration_type == t))
                    .filter(|i| input.integration_status.as_ref().is_none_or(|s| &i.status == s))
                    .map(|i| types::IntegrationSummary {
                        integration_name: Some(i.name.clone()),
                        integration_type: Some(i.integration_type.clone()),
                        integration_status: Some(i.status.clone()),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(types::ListIntegrationsResponse { integration_summaries: Some(out) })
    }

    pub(crate) fn delete_integration(
        &self,
        ctx: &RequestContext,
        input: types::DeleteIntegrationRequest,
    ) -> Result<types::DeleteIntegrationResponse, ServiceError> {
        self.authorize(
            ctx,
            "DeleteIntegration",
            &arn(ctx, &format!("integration:{}", input.integration_name)),
            ConditionContext::new(),
        )?;
        let mut st = self.lock();
        let r = st.region(&ctx.caller.account_id, &ctx.region);
        if !r.integrations.contains_key(&input.integration_name) {
            return Err(errors::resource_not_found("The specified integration does not exist."));
        }
        let _ = input.force;
        r.integrations.remove(&input.integration_name);
        Ok(types::DeleteIntegrationResponse {})
    }

    // ---- S3 Tables integrations --------------------------------------------------

    pub(crate) fn associate_source_to_s3_table_integration(
        &self,
        ctx: &RequestContext,
        input: types::AssociateSourceToS3TableIntegrationRequest,
    ) -> Result<types::AssociateSourceToS3TableIntegrationResponse, ServiceError> {
        self.authorize(ctx, "AssociateSourceToS3TableIntegration", &input.integration_arn, ConditionContext::new())?;
        if !input.integration_arn.starts_with("arn:") {
            return Err(errors::validation(format!("Invalid integrationArn: {}", input.integration_arn)));
        }
        let id = random_alnum(16).to_lowercase();
        let source = types::S3TableIntegrationSource {
            identifier: Some(id.clone()),
            data_source: Some(input.data_source),
            status: Some("ACTIVE".into()),
            status_reason: None,
            created_time_stamp: Some(now_ms(ctx)),
            parent_source_identifier: None,
        };
        let mut st = self.lock();
        let sources =
            st.region(&ctx.caller.account_id, &ctx.region).s3_table_sources.entry(input.integration_arn).or_default();
        if sources.iter().any(|s| s.data_source == source.data_source) {
            return Err(errors::validation("This data source is already associated with the integration."));
        }
        sources.push(source);
        Ok(types::AssociateSourceToS3TableIntegrationResponse { identifier: Some(id) })
    }

    pub(crate) fn disassociate_source_from_s3_table_integration(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateSourceFromS3TableIntegrationRequest,
    ) -> Result<types::DisassociateSourceFromS3TableIntegrationResponse, ServiceError> {
        self.authorize(ctx, "DisassociateSourceFromS3TableIntegration", "*", ConditionContext::new())?;
        let mut st = self.lock();
        let region = st.region(&ctx.caller.account_id, &ctx.region);
        let mut found = false;
        for sources in region.s3_table_sources.values_mut() {
            let before = sources.len();
            sources.retain(|s| s.identifier.as_ref() != Some(&input.identifier));
            found |= sources.len() != before;
        }
        if !found {
            return Err(errors::resource_not_found("The specified source does not exist."));
        }
        Ok(types::DisassociateSourceFromS3TableIntegrationResponse { identifier: Some(input.identifier) })
    }

    pub(crate) fn list_sources_for_s3_table_integration(
        &self,
        ctx: &RequestContext,
        input: types::ListSourcesForS3TableIntegrationRequest,
    ) -> Result<types::ListSourcesForS3TableIntegrationResponse, ServiceError> {
        self.authorize(ctx, "ListSourcesForS3TableIntegration", &input.integration_arn, ConditionContext::new())?;
        let st = self.lock();
        let out = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .and_then(|r| r.s3_table_sources.get(&input.integration_arn))
            .cloned()
            .unwrap_or_default();
        let (out, next_token) =
            page(out, input.next_token.as_deref(), input.max_results.unwrap_or(100).clamp(1, 100) as usize)?;
        Ok(types::ListSourcesForS3TableIntegrationResponse { sources: Some(out), next_token })
    }

    // ---- lookup tables -------------------------------------------------------------

    fn table_from_query(&self, ctx: &RequestContext, query_id: &str) -> Result<String, ServiceError> {
        let st = self.lock();
        let q = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .and_then(|r| r.queries.get(query_id))
            .ok_or_else(|| errors::resource_not_found(format!("Query does not exist: {query_id}")))?;
        let mut columns: Vec<String> = Vec::new();
        for row in &q.results {
            for f in row.iter().filter_map(|f| f.field.clone()) {
                if f != "@ptr" && !columns.contains(&f) {
                    columns.push(f);
                }
            }
        }
        let mut body = columns.join(",");
        for row in &q.results {
            body.push('\n');
            let cells: Vec<String> = columns
                .iter()
                .map(|c| {
                    row.iter().find(|f| f.field.as_ref() == Some(c)).and_then(|f| f.value.clone()).unwrap_or_default()
                })
                .collect();
            body.push_str(&cells.join(","));
        }
        Ok(body)
    }

    pub(crate) fn create_lookup_table(
        &self,
        ctx: &RequestContext,
        input: types::CreateLookupTableRequest,
    ) -> Result<types::CreateLookupTableResponse, ServiceError> {
        let a = arn(ctx, &format!("lookup-table:{}", input.lookup_table_name));
        let tags = input.tags.clone().unwrap_or_default();
        self.authorize(ctx, "CreateLookupTable", &a, request_tag_conditions(&tags))?;
        check_tags(0, &tags)?;
        let body = match (input.table_body, input.query_id) {
            (Some(b), None) => b,
            (None, Some(q)) => self.table_from_query(ctx, &q)?,
            _ => return Err(errors::validation("Exactly one of tableBody and queryId must be specified.")),
        };
        if csv_shape(&body).0.is_empty() {
            return Err(errors::validation("The table body must be CSV with a header row."));
        }
        if let Some(k) = &input.kms_key_id {
            self.check_kms_key(k, &a, &ctx.region)?;
        }
        let now = now_ms(ctx);
        let mut st = self.lock();
        let r = st.region(&ctx.caller.account_id, &ctx.region);
        if r.lookup_tables.contains_key(&input.lookup_table_name) {
            return Err(errors::resource_already_exists("The specified lookup table already exists."));
        }
        r.lookup_tables.insert(
            input.lookup_table_name.clone(),
            LookupTable {
                arn: a.clone(),
                name: input.lookup_table_name,
                description: input.description,
                body,
                kms_key_id: input.kms_key_id,
                last_updated_time: now,
                tags,
            },
        );
        Ok(types::CreateLookupTableResponse { lookup_table_arn: Some(a), created_at: Some(now) })
    }

    fn table_name(arn: &str) -> Result<String, ServiceError> {
        arn.rsplit_once(":lookup-table:")
            .map(|(_, n)| n.to_string())
            .ok_or_else(|| errors::invalid_parameter(format!("Invalid lookup table ARN: {arn}")))
    }

    pub(crate) fn get_lookup_table(
        &self,
        ctx: &RequestContext,
        input: types::GetLookupTableRequest,
    ) -> Result<types::GetLookupTableResponse, ServiceError> {
        self.authorize(ctx, "GetLookupTable", &input.lookup_table_arn, ConditionContext::new())?;
        let name = Self::table_name(&input.lookup_table_arn)?;
        let st = self.lock();
        let t = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .and_then(|r| r.lookup_tables.get(&name))
            .ok_or_else(|| errors::resource_not_found("The specified lookup table does not exist."))?;
        Ok(types::GetLookupTableResponse {
            lookup_table_arn: Some(t.arn.clone()),
            lookup_table_name: Some(t.name.clone()),
            description: t.description.clone(),
            table_body: Some(t.body.clone()),
            size_bytes: Some(t.body.len() as i64),
            last_updated_time: Some(t.last_updated_time),
            kms_key_id: t.kms_key_id.clone(),
        })
    }

    pub(crate) fn update_lookup_table(
        &self,
        ctx: &RequestContext,
        input: types::UpdateLookupTableRequest,
    ) -> Result<types::UpdateLookupTableResponse, ServiceError> {
        self.authorize(ctx, "UpdateLookupTable", &input.lookup_table_arn, ConditionContext::new())?;
        let name = Self::table_name(&input.lookup_table_arn)?;
        let body = match (input.table_body, input.query_id) {
            (Some(b), None) => Some(b),
            (None, Some(q)) => Some(self.table_from_query(ctx, &q)?),
            (None, None) => None,
            _ => return Err(errors::validation("Specify at most one of tableBody and queryId.")),
        };
        if let Some(k) = &input.kms_key_id {
            self.check_kms_key(k, &input.lookup_table_arn, &ctx.region)?;
        }
        let now = now_ms(ctx);
        let mut st = self.lock();
        let t = st
            .region(&ctx.caller.account_id, &ctx.region)
            .lookup_tables
            .get_mut(&name)
            .ok_or_else(|| errors::resource_not_found("The specified lookup table does not exist."))?;
        if let Some(b) = body {
            t.body = b;
        }
        if let Some(d) = input.description {
            t.description = Some(d);
        }
        if let Some(k) = input.kms_key_id {
            t.kms_key_id = Some(k);
        }
        t.last_updated_time = now;
        Ok(types::UpdateLookupTableResponse { lookup_table_arn: Some(t.arn.clone()), last_updated_time: Some(now) })
    }

    pub(crate) fn delete_lookup_table(
        &self,
        ctx: &RequestContext,
        input: types::DeleteLookupTableRequest,
    ) -> Result<(), ServiceError> {
        self.authorize(ctx, "DeleteLookupTable", &input.lookup_table_arn, ConditionContext::new())?;
        let name = Self::table_name(&input.lookup_table_arn)?;
        let mut st = self.lock();
        st.region(&ctx.caller.account_id, &ctx.region)
            .lookup_tables
            .remove(&name)
            .ok_or_else(|| errors::resource_not_found("The specified lookup table does not exist."))?;
        Ok(())
    }

    pub(crate) fn describe_lookup_tables(
        &self,
        ctx: &RequestContext,
        input: types::DescribeLookupTablesRequest,
    ) -> Result<types::DescribeLookupTablesResponse, ServiceError> {
        self.authorize(ctx, "DescribeLookupTables", &arn(ctx, "lookup-table:*"), ConditionContext::new())?;
        let st = self.lock();
        let out: Vec<types::LookupTable> = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .map(|r| {
                r.lookup_tables
                    .values()
                    .filter(|t| input.lookup_table_name_prefix.as_ref().is_none_or(|p| t.name.starts_with(p.as_str())))
                    .map(|t| {
                        let (fields, records) = csv_shape(&t.body);
                        types::LookupTable {
                            lookup_table_arn: Some(t.arn.clone()),
                            lookup_table_name: Some(t.name.clone()),
                            description: t.description.clone(),
                            table_fields: Some(fields),
                            records_count: Some(records),
                            size_bytes: Some(t.body.len() as i64),
                            last_updated_time: Some(t.last_updated_time),
                            kms_key_id: t.kms_key_id.clone(),
                        }
                    })
                    .collect()
            })
            .unwrap_or_default();
        let limit = if input.max_results > 0 { input.max_results as usize } else { 50 };
        let (out, next_token) = page(out, input.next_token.as_deref(), limit)?;
        Ok(types::DescribeLookupTablesResponse { lookup_tables: Some(out), next_token })
    }

    // ---- scheduled queries ----------------------------------------------------------

    fn scheduled_arn(&self, ctx: &RequestContext, identifier: &str) -> Result<String, ServiceError> {
        let st = self.lock();
        let r = st.region_ref(&ctx.caller.account_id, &ctx.region);
        let found = r.and_then(|r| {
            r.scheduled_queries
                .iter()
                .find(|(a, q)| *a == identifier || q.record.name.as_deref() == Some(identifier))
                .map(|(a, _)| a.clone())
        });
        found.ok_or_else(|| errors::resource_not_found(format!("Scheduled query {identifier} does not exist.")))
    }

    pub(crate) fn create_scheduled_query(
        &self,
        ctx: &RequestContext,
        input: types::CreateScheduledQueryRequest,
    ) -> Result<types::CreateScheduledQueryResponse, ServiceError> {
        let a = arn(ctx, &format!("scheduled-query:{}", uuid()));
        let tags = input.tags.clone().unwrap_or_default();
        self.authorize(ctx, "CreateScheduledQuery", &a, request_tag_conditions(&tags))?;
        check_tags(0, &tags)?;
        check_schedule(&input.schedule_expression)?;
        crate::sqlppl::compile(&input.query_language, &input.query_string)
            .map_err(|e| errors::validation(format!("Invalid query: {e}")))?;
        if !input.execution_role_arn.starts_with("arn:") {
            return Err(errors::validation("executionRoleArn must be an IAM role ARN."));
        }
        let now = now_ms(ctx);
        let state = input.state.unwrap_or_else(|| "ENABLED".into());
        let mut st = self.lock();
        let r = st.region(&ctx.caller.account_id, &ctx.region);
        if r.scheduled_queries.values().any(|q| q.record.name.as_deref() == Some(&input.name)) {
            return Err(errors::conflict(format!("A scheduled query named {} already exists.", input.name)));
        }
        let record = types::GetScheduledQueryResponse {
            scheduled_query_arn: Some(a.clone()),
            name: Some(input.name),
            description: input.description,
            query_language: Some(input.query_language),
            query_string: Some(input.query_string),
            log_group_identifiers: input.log_group_identifiers,
            schedule_expression: Some(input.schedule_expression),
            timezone: Some(input.timezone.unwrap_or_else(|| "UTC".into())),
            start_time_offset: input.start_time_offset,
            end_time_offset: input.end_time_offset,
            destination_configuration: input.destination_configuration,
            state: Some(state.clone()),
            schedule_type: Some("CUSTOMER_MANAGED".into()),
            last_triggered_time: None,
            last_execution_status: None,
            schedule_start_time: input.schedule_start_time,
            schedule_end_time: input.schedule_end_time,
            execution_role_arn: Some(input.execution_role_arn),
            creation_time: Some(now),
            last_updated_time: Some(now),
        };
        r.scheduled_queries
            .insert(a.clone(), ScheduledQuery { record, tags, history: Vec::new(), evaluated_until: Some(now) });
        Ok(types::CreateScheduledQueryResponse { scheduled_query_arn: Some(a), state: Some(state) })
    }

    pub(crate) fn get_scheduled_query(
        &self,
        ctx: &RequestContext,
        input: types::GetScheduledQueryRequest,
    ) -> Result<types::GetScheduledQueryResponse, ServiceError> {
        let a = self.scheduled_arn(ctx, &input.identifier)?;
        self.authorize(ctx, "GetScheduledQuery", &a, ConditionContext::new())?;
        let st = self.lock();
        Ok(st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .and_then(|r| r.scheduled_queries.get(&a))
            .map(|q| q.record.clone())
            .unwrap_or_default())
    }

    pub(crate) fn update_scheduled_query(
        &self,
        ctx: &RequestContext,
        input: types::UpdateScheduledQueryRequest,
    ) -> Result<types::UpdateScheduledQueryResponse, ServiceError> {
        let a = self.scheduled_arn(ctx, &input.identifier)?;
        self.authorize(ctx, "UpdateScheduledQuery", &a, ConditionContext::new())?;
        check_schedule(&input.schedule_expression)?;
        crate::sqlppl::compile(&input.query_language, &input.query_string)
            .map_err(|e| errors::validation(format!("Invalid query: {e}")))?;
        let now = now_ms(ctx);
        let mut st = self.lock();
        let q = st.region(&ctx.caller.account_id, &ctx.region).scheduled_queries.get_mut(&a).ok_or_else(|| {
            errors::resource_not_found(format!("Scheduled query {} does not exist.", input.identifier))
        })?;
        let r = &mut q.record;
        r.description = input.description.or(r.description.take());
        r.query_language = Some(input.query_language);
        r.query_string = Some(input.query_string);
        r.log_group_identifiers = input.log_group_identifiers.or(r.log_group_identifiers.take());
        r.schedule_expression = Some(input.schedule_expression);
        r.timezone = input.timezone.or(r.timezone.take());
        r.start_time_offset = input.start_time_offset.or(r.start_time_offset);
        r.end_time_offset = input.end_time_offset.or(r.end_time_offset);
        r.destination_configuration = input.destination_configuration.or(r.destination_configuration.take());
        r.schedule_start_time = input.schedule_start_time.or(r.schedule_start_time);
        r.schedule_end_time = input.schedule_end_time.or(r.schedule_end_time);
        r.execution_role_arn = Some(input.execution_role_arn);
        r.state = input.state.or(r.state.take());
        r.last_updated_time = Some(now);
        let r = r.clone();
        Ok(types::UpdateScheduledQueryResponse {
            scheduled_query_arn: r.scheduled_query_arn,
            name: r.name,
            description: r.description,
            query_language: r.query_language,
            query_string: r.query_string,
            log_group_identifiers: r.log_group_identifiers,
            schedule_expression: r.schedule_expression,
            timezone: r.timezone,
            start_time_offset: r.start_time_offset,
            end_time_offset: r.end_time_offset,
            destination_configuration: r.destination_configuration,
            state: r.state,
            schedule_type: r.schedule_type,
            last_triggered_time: r.last_triggered_time,
            last_execution_status: r.last_execution_status,
            schedule_start_time: r.schedule_start_time,
            schedule_end_time: r.schedule_end_time,
            execution_role_arn: r.execution_role_arn,
            creation_time: r.creation_time,
            last_updated_time: r.last_updated_time,
        })
    }

    pub(crate) fn delete_scheduled_query(
        &self,
        ctx: &RequestContext,
        input: types::DeleteScheduledQueryRequest,
    ) -> Result<types::DeleteScheduledQueryResponse, ServiceError> {
        let a = self.scheduled_arn(ctx, &input.identifier)?;
        self.authorize(ctx, "DeleteScheduledQuery", &a, ConditionContext::new())?;
        self.lock().region(&ctx.caller.account_id, &ctx.region).scheduled_queries.remove(&a);
        Ok(types::DeleteScheduledQueryResponse {})
    }

    pub(crate) fn list_scheduled_queries(
        &self,
        ctx: &RequestContext,
        input: types::ListScheduledQueriesRequest,
    ) -> Result<types::ListScheduledQueriesResponse, ServiceError> {
        self.authorize(ctx, "ListScheduledQueries", &arn(ctx, "scheduled-query:*"), ConditionContext::new())?;
        let st = self.lock();
        let out: Vec<types::ScheduledQuerySummary> = st
            .region_ref(&ctx.caller.account_id, &ctx.region)
            .map(|r| {
                r.scheduled_queries
                    .values()
                    .map(|q| &q.record)
                    .filter(|q| input.state.as_ref().is_none_or(|s| q.state.as_ref() == Some(s)))
                    .filter(|q| input.schedule_type.as_ref().is_none_or(|s| q.schedule_type.as_ref() == Some(s)))
                    .map(|q| types::ScheduledQuerySummary {
                        scheduled_query_arn: q.scheduled_query_arn.clone(),
                        name: q.name.clone(),
                        state: q.state.clone(),
                        schedule_type: q.schedule_type.clone(),
                        last_triggered_time: q.last_triggered_time,
                        last_execution_status: q.last_execution_status.clone(),
                        schedule_expression: q.schedule_expression.clone(),
                        timezone: q.timezone.clone(),
                        destination_configuration: q.destination_configuration.clone(),
                        creation_time: q.creation_time,
                        last_updated_time: q.last_updated_time,
                    })
                    .collect()
            })
            .unwrap_or_default();
        let (out, next_token) =
            page(out, input.next_token.as_deref(), input.max_results.unwrap_or(50).clamp(1, 1000) as usize)?;
        Ok(types::ListScheduledQueriesResponse { next_token, scheduled_queries: Some(out) })
    }

    pub(crate) fn get_scheduled_query_history(
        &self,
        ctx: &RequestContext,
        input: types::GetScheduledQueryHistoryRequest,
    ) -> Result<types::GetScheduledQueryHistoryResponse, ServiceError> {
        let a = self.scheduled_arn(ctx, &input.identifier)?;
        self.authorize(ctx, "GetScheduledQueryHistory", &a, ConditionContext::new())?;
        if input.end_time < input.start_time {
            return Err(errors::validation("endTime must not be before startTime."));
        }
        let st = self.lock();
        let q =
            st.region_ref(&ctx.caller.account_id, &ctx.region).and_then(|r| r.scheduled_queries.get(&a)).ok_or_else(
                || errors::resource_not_found(format!("Scheduled query {} does not exist.", input.identifier)),
            )?;
        let out: Vec<_> = q
            .history
            .iter()
            .filter(|h| h.triggered_timestamp.is_some_and(|t| t >= input.start_time && t <= input.end_time))
            .filter(|h| {
                input
                    .execution_statuses
                    .as_ref()
                    .is_none_or(|s| h.execution_status.as_ref().is_some_and(|x| s.contains(x)))
            })
            .cloned()
            .collect();
        let (out, next_token) =
            page(out, input.next_token.as_deref(), input.max_results.unwrap_or(50).clamp(1, 1000) as usize)?;
        Ok(types::GetScheduledQueryHistoryResponse {
            name: q.record.name.clone(),
            scheduled_query_arn: Some(a),
            trigger_history: Some(out),
            next_token,
        })
    }

    // ---- storage tier ----------------------------------------------------------------

    pub(crate) fn put_storage_tier_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutStorageTierPolicyRequest,
    ) -> Result<types::PutStorageTierPolicyResponse, ServiceError> {
        self.authorize(ctx, "PutStorageTierPolicy", "*", ConditionContext::new())?;
        let now = now_ms(ctx);
        self.lock().region(&ctx.caller.account_id, &ctx.region).storage_tier = Some((input.storage_tier.clone(), now));
        Ok(types::PutStorageTierPolicyResponse { storage_tier: Some(input.storage_tier), last_updated_time: Some(now) })
    }

    pub(crate) fn get_storage_tier_policy(
        &self,
        ctx: &RequestContext,
        _input: types::GetStorageTierPolicyRequest,
    ) -> Result<types::GetStorageTierPolicyResponse, ServiceError> {
        self.authorize(ctx, "GetStorageTierPolicy", "*", ConditionContext::new())?;
        let st = self.lock();
        let tier = st.region_ref(&ctx.caller.account_id, &ctx.region).and_then(|r| r.storage_tier.clone());
        Ok(match tier {
            Some((t, at)) => types::GetStorageTierPolicyResponse { storage_tier: Some(t), last_updated_time: Some(at) },
            None => {
                types::GetStorageTierPolicyResponse { storage_tier: Some("STANDARD".into()), last_updated_time: None }
            }
        })
    }

    // ---- syslog ------------------------------------------------------------------------

    pub(crate) fn put_syslog_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutSyslogConfigurationRequest,
    ) -> Result<(), ServiceError> {
        let g = GroupRef::parse(ctx, &input.log_group_identifier)?;
        self.authorize_group(ctx, "PutSyslogConfiguration", &g, None, ConditionContext::new())?;
        if let Some(v) = &input.vpc_endpoint_id {
            if !v.starts_with("vpce-") {
                return Err(errors::invalid_parameter(format!("Invalid VPC endpoint ID: {v}")));
            }
        }
        let now = now_ms(ctx);
        let mut st = self.lock();
        let group = st.group_mut(&g)?;
        group.syslog.retain(|c| c.vpc_endpoint_id != input.vpc_endpoint_id);
        group.syslog.push(types::SyslogConfiguration {
            log_group_arn: Some(g.arn()),
            source_type: Some("VPCE".into()),
            vpc_endpoint_id: input.vpc_endpoint_id,
            created_at: Some(now),
        });
        Ok(())
    }

    pub(crate) fn delete_syslog_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DeleteSyslogConfigurationRequest,
    ) -> Result<(), ServiceError> {
        let g = GroupRef::parse(ctx, &input.log_group_identifier)?;
        self.authorize_group(ctx, "DeleteSyslogConfiguration", &g, None, ConditionContext::new())?;
        let mut st = self.lock();
        let group = st.group_mut(&g)?;
        let before = group.syslog.len();
        group.syslog.retain(|c| input.vpc_endpoint_id.is_some() && c.vpc_endpoint_id != input.vpc_endpoint_id);
        if group.syslog.len() == before {
            return Err(errors::resource_not_found("The specified syslog configuration does not exist."));
        }
        Ok(())
    }

    pub(crate) fn list_syslog_configurations(
        &self,
        ctx: &RequestContext,
        input: types::ListSyslogConfigurationsRequest,
    ) -> Result<types::ListSyslogConfigurationsResponse, ServiceError> {
        let mut out = Vec::new();
        match &input.log_group_identifier {
            Some(id) => {
                let g = GroupRef::parse(ctx, id)?;
                self.authorize_group(ctx, "ListSyslogConfigurations", &g, None, ConditionContext::new())?;
                out.extend(self.lock().group(&g)?.syslog.iter().cloned());
            }
            None => {
                self.authorize(ctx, "ListSyslogConfigurations", &arn(ctx, "log-group:*"), ConditionContext::new())?;
                let st = self.lock();
                if let Some(r) = st.region_ref(&ctx.caller.account_id, &ctx.region) {
                    out.extend(r.log_groups.values().flat_map(|g| g.syslog.iter().cloned()));
                }
            }
        }
        out.retain(|c| input.vpc_endpoint_id.as_ref().is_none_or(|v| c.vpc_endpoint_id.as_ref() == Some(v)));
        let limit = if input.max_results > 0 { input.max_results as usize } else { 50 };
        let (out, next_token) = page(out, input.next_token.as_deref(), limit)?;
        Ok(types::ListSyslogConfigurationsResponse { syslog_configurations: Some(out), next_token })
    }
}

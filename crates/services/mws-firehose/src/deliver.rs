//! Delivery: a background round each second reads Kinesis sources and
//! flushes every destination whose buffer is due by its buffering hints
//! (size or interval, on the emulated clock), with the destination role's
//! permissions.

use std::collections::BTreeMap;
use std::time::Duration;

use base64::Engine;
use mws_core::RequestContext;
use serde_json::{json, Value};

use crate::config;
use crate::generated::types;
use crate::monitor::{delivery_metric, destination_label, point, ErrorLog};
use crate::output::{self, PrefixInputs};
use crate::processing::{Failed, Out};
use crate::state::{Buffered, Destination};
use crate::{http, Firehose, SERVICE_PRINCIPAL};

const TICK: Duration = Duration::from_secs(1);
/// S3 deliveries are retried for up to a day.
const S3_RETRY_MS: i64 = 86_400_000;

/// One flush: a destination's buffer, taken out of the state.
struct Job {
    stream_arn: String,
    stream_name: String,
    account: String,
    version: u64,
    destination: Destination,
    records: Vec<Buffered>,
}

fn hints(kind: &str, config: &Value) -> (usize, i64) {
    let effective = config::effective(kind, config);
    let size = effective.pointer("/buffering_hints/size_in_m_bs").and_then(Value::as_i64).unwrap_or(5);
    let interval = effective.pointer("/buffering_hints/interval_in_seconds").and_then(Value::as_i64).unwrap_or(300);
    (size.max(1) as usize * 1024 * 1024, interval.max(0) * 1000)
}

/// What a successful delivery delivered.
#[derive(Debug, Default, Clone, Copy)]
struct Delivered {
    records: usize,
    bytes: usize,
}

impl Delivered {
    fn of(records: &[Out]) -> Self {
        Self { records: records.len(), bytes: records.iter().map(|r| r.data.len()).sum() }
    }
}

/// Why a delivery failed, and whether to try again later.
struct DeliveryError {
    code: String,
    message: String,
    /// The destination the error log names, when not the configured one
    /// (an S3 backup bucket).
    destination: Option<String>,
    /// The records are handled (backed up to S3): do not retry.
    give_up: bool,
}

impl DeliveryError {
    fn new(code: &str, message: impl Into<String>) -> Self {
        Self { code: code.into(), message: message.into(), destination: None, give_up: false }
    }
}

impl Firehose {
    /// Remember a request's context and start the delivery rounds.
    pub(crate) fn observe(&self, ctx: &RequestContext) {
        let offset = ctx.received_at - chrono::Utc::now();
        *self.inner.template.lock().expect("Firehose template lock poisoned") = Some((ctx.clone(), offset));
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        self.inner.started.get_or_init(|| {
            let weak = std::sync::Arc::downgrade(&self.inner);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(TICK).await;
                    let Some(inner) = weak.upgrade() else { return };
                    Firehose { inner }.deliver_round(false).await;
                }
            });
        });
    }

    /// A context for background work in `region`, at the emulated time
    /// now.
    pub(crate) fn background_context(&self, region: &str) -> Option<RequestContext> {
        let (mut ctx, offset) = self.inner.template.lock().expect("Firehose template lock poisoned").clone()?;
        ctx.request_id = uuid::Uuid::new_v4().to_string();
        ctx.region = region.to_string();
        ctx.received_at = chrono::Utc::now() + offset;
        ctx.source_ip = None;
        Some(ctx)
    }

    /// The role's identity, as Firehose gets it by assuming the role.
    pub(crate) fn role_context(
        &self,
        ctx: &RequestContext,
        role: &str,
        stream_arn: &str,
        account: &str,
    ) -> Result<RequestContext, String> {
        let Some(sts) = self.inner.sts.get() else { return Err("STS is not available.".into()) };
        let cannot = || format!("Firehose is unable to assume role {role}. Please check the role provided.");
        let creds = sts
            .assume_role_as_service(&mws_sts::ServiceAssume {
                role_arn: role,
                service_principal: SERVICE_PRINCIPAL,
                session_name: "Firehose",
                duration_seconds: 3600,
                source_account: Some(account),
                source_arn: Some(stream_arn),
                now: ctx.received_at,
            })
            .map_err(|_| cannot())?;
        let resolved = sts
            .credential_store()
            .resolve(&creds.access_key_id, Some(&creds.session_token), ctx.received_at)
            .ok()
            .flatten()
            .ok_or_else(cannot)?;
        Ok(RequestContext { caller: resolved.caller, source_ip: None, ..ctx.clone() })
    }

    /// One delivery round. `force` flushes every non-empty buffer.
    pub(crate) async fn deliver_round(&self, force: bool) {
        let _guard = self.inner.delivering.lock().await;
        self.poll_sources().await;
        let mut jobs = Vec::new();
        {
            let template = self.inner.template.lock().expect("Firehose template lock poisoned").clone();
            let Some((_, offset)) = template else { return };
            let now = (chrono::Utc::now() + offset).timestamp_millis();
            let mut st = self.lock();
            st.settle(now);
            for s in st.streams.values_mut().filter(|s| s.active()) {
                for d in &mut s.destinations {
                    let Some(first) = d.buffer.first().map(|r| r.arrival) else { continue };
                    let (size, interval) = hints(&d.kind, &d.config);
                    let bytes: usize = d.buffer.iter().map(|r| r.data.len()).sum();
                    if force || bytes >= size || now - first >= interval {
                        let records = std::mem::take(&mut d.buffer);
                        jobs.push(Job {
                            stream_arn: s.arn.clone(),
                            stream_name: s.name.clone(),
                            account: s.account.clone(),
                            version: s.version,
                            destination: d.clone(),
                            records,
                        });
                    }
                }
            }
        }
        for job in jobs {
            let region = job.stream_arn.split(':').nth(3).unwrap_or("us-east-1").to_string();
            let Some(ctx) = self.background_context(&region) else { continue };
            let now = ctx.received_at.timestamp_millis();
            let result = self.deliver(&ctx, &job).await;
            self.report(&ctx, &job, &result).await;
            let mut st = self.lock();
            let Some(s) = st.streams.get_mut(&job.stream_arn) else { continue };
            let Some(d) = s.destinations.iter_mut().find(|d| d.id == job.destination.id) else { continue };
            match result {
                Ok(_) => d.failing_since = None,
                Err(e) if e.give_up => d.failing_since = None,
                Err(e) => {
                    let since = *d.failing_since.get_or_insert(now);
                    if now - since < S3_RETRY_MS {
                        tracing::info!(stream = %job.stream_arn, code = %e.code, "Firehose delivery failed, will retry: {}", e.message);
                        let mut back = job.records;
                        back.append(&mut d.buffer);
                        d.buffer = back;
                    } else {
                        tracing::warn!(stream = %job.stream_arn, code = %e.code, "Firehose dropped records after retrying for 24 hours: {}", e.message);
                        d.failing_since = None;
                    }
                }
            }
        }
    }

    /// Metrics and the error log for one delivery attempt.
    async fn report(&self, ctx: &RequestContext, job: &Job, result: &Result<Delivered, DeliveryError>) {
        let d = &job.destination;
        let metric = delivery_metric(&d.kind);
        let mut points = Vec::new();
        match result {
            Ok(done) => {
                let oldest = job.records.iter().map(|r| r.arrival).min().unwrap_or(ctx.received_at.timestamp_millis());
                let freshness = (ctx.received_at.timestamp_millis() - oldest).max(0) as f64 / 1000.0;
                points.push(point(format!("{metric}.Records"), "Count", done.records as f64));
                points.push(point(format!("{metric}.Bytes"), "Bytes", done.bytes as f64));
                points.push(point(format!("{metric}.Success"), "None", 1.0));
                points.push(point(format!("{metric}.DataFreshness"), "Seconds", freshness));
            }
            Err(e) => {
                points.push(point(format!("{metric}.Success"), "None", 0.0));
                let effective = config::effective(&d.kind, &d.config);
                self.log_error(
                    ctx,
                    &effective,
                    ErrorLog {
                        stream_arn: &job.stream_arn,
                        account: &job.account,
                        version: job.version,
                        destination: e.destination.clone().unwrap_or_else(|| destination_label(&d.kind, &effective)),
                        code: &e.code,
                        message: &e.message,
                        processor: None,
                    },
                )
                .await;
            }
        }
        self.metrics(ctx, &job.account, &job.stream_name, points);
    }

    /// Log the records processing could not handle (one entry per error)
    /// and publish the processing metrics.
    async fn report_processing(
        &self,
        ctx: &RequestContext,
        job: &Job,
        effective: &Value,
        processing: Option<&types::ProcessingConfiguration>,
        processed: &crate::processing::Processed,
    ) {
        let lambda = processing
            .filter(|p| p.enabled.unwrap_or(false))
            .is_some_and(|p| p.processors.iter().flatten().any(|p| p.r#type == "Lambda"));
        if lambda {
            let processing_failed = processed.failed.iter().any(|f| f.output_type == "processing-failed");
            let ok = Delivered::of(&processed.ok);
            self.metrics(
                ctx,
                &job.account,
                &job.stream_name,
                vec![
                    point("ExecuteProcessing.Success", "None", if processing_failed { 0.0 } else { 1.0 }),
                    point("SucceedProcessing.Records", "Count", ok.records as f64),
                    point("SucceedProcessing.Bytes", "Bytes", ok.bytes as f64),
                ],
            );
        }
        let mut seen = std::collections::BTreeSet::new();
        for f in &processed.failed {
            if !seen.insert((f.error_code.clone(), f.lambda_arn.clone())) {
                continue;
            }
            self.log_error(
                ctx,
                effective,
                ErrorLog {
                    stream_arn: &job.stream_arn,
                    account: &job.account,
                    version: job.version,
                    destination: destination_label(&job.destination.kind, effective),
                    code: &f.error_code,
                    message: &f.error_message,
                    processor: f.lambda_arn.as_deref(),
                },
            )
            .await;
        }
    }

    async fn deliver(&self, ctx: &RequestContext, job: &Job) -> Result<Delivered, DeliveryError> {
        let d = &job.destination;
        let effective = config::effective(&d.kind, &d.config);
        let role = effective.get("role_arn").and_then(Value::as_str).map(str::to_string);
        let processing: Option<types::ProcessingConfiguration> =
            effective.get("processing_configuration").and_then(|v| serde_json::from_value(v.clone()).ok());
        let dynamic = config::dynamic_partitioning(&effective);
        match d.kind.as_str() {
            "extended_s3" => {
                let s3: types::ExtendedS3DestinationConfiguration = config::typed(&d.kind, &d.config);
                // The source backup gets the records as they came in.
                if s3.s3_backup_mode.as_deref() == Some("Enabled") {
                    if let Some(backup) = &s3.s3_backup_configuration {
                        let plain = plain_out(&job.records);
                        let backed_up = self.write_s3(ctx, job, &backup_target(backup), &plain, false).await;
                        let mut points =
                            vec![point("BackupToS3.Success", "None", if backed_up.is_ok() { 1.0 } else { 0.0 })];
                        if backed_up.is_ok() {
                            let n = Delivered::of(&plain);
                            points.push(point("BackupToS3.Records", "Count", n.records as f64));
                            points.push(point("BackupToS3.Bytes", "Bytes", n.bytes as f64));
                        }
                        self.metrics(ctx, &job.account, &job.stream_name, points);
                        backed_up?;
                    }
                }
                let mut processed = self
                    .process(
                        ctx,
                        &job.stream_arn,
                        &job.account,
                        role.as_deref(),
                        processing.as_ref(),
                        dynamic,
                        job.records.clone(),
                    )
                    .await;
                if config::format_conversion(&effective) {
                    // Conversion reads the schema from the AWS Glue Data
                    // Catalog, which MWS does not have: the table is never
                    // found.
                    tracing::info!(stream = %job.stream_arn, "Firehose cannot convert record formats: MWS has no AWS Glue Data Catalog");
                    let ok = std::mem::take(&mut processed.ok);
                    processed.failed.extend(ok.into_iter().map(|r| Failed {
                        source: r.source,
                        data: r.data,
                        output_type: "format-conversion-failed",
                        error_code: "DataFormatConversion.EntityNotFound".into(),
                        error_message: "The specified table/database could not be found. Ensure that the table/database exists and that the values provided in the schema configuration are correct, especially with regards to casing.".into(),
                        lambda_arn: None,
                    }));
                }
                self.report_processing(ctx, job, &effective, processing.as_ref(), &processed).await;
                let target = S3Target {
                    role: s3.role_arn.clone(),
                    bucket_arn: s3.bucket_arn.clone(),
                    prefix: s3.prefix.clone().unwrap_or_default(),
                    error_prefix: s3.error_output_prefix.clone(),
                    compression: s3.compression_format.clone().unwrap_or_else(|| "UNCOMPRESSED".into()),
                    kms_key: s3
                        .encryption_configuration
                        .as_ref()
                        .and_then(|e| e.kms_encryption_config.as_ref())
                        .map(|k| k.awskms_key_arn.clone()),
                    file_extension: s3.file_extension.clone(),
                };
                self.write_s3(ctx, job, &target, &processed.ok, dynamic).await?;
                self.write_errors(ctx, job, &target, &processed.failed).await?;
                Ok(Delivered::of(&processed.ok))
            }
            "redshift" => {
                // Firehose stages Redshift data in S3, then runs COPY; MWS
                // has no Redshift, so the staged objects are the result.
                let r: types::RedshiftDestinationConfiguration = config::typed(&d.kind, &d.config);
                let target = backup_target(&r.s3_configuration);
                let processed = self
                    .process(
                        ctx,
                        &job.stream_arn,
                        &job.account,
                        role.as_deref(),
                        processing.as_ref(),
                        false,
                        job.records.clone(),
                    )
                    .await;
                self.report_processing(ctx, job, &effective, processing.as_ref(), &processed).await;
                self.write_s3(ctx, job, &target, &processed.ok, false).await?;
                self.write_errors(ctx, job, &target, &processed.failed).await?;
                let staged = Delivered::of(&processed.ok);
                self.metrics(
                    ctx,
                    &job.account,
                    &job.stream_name,
                    vec![
                        point("DeliveryToS3.Records", "Count", staged.records as f64),
                        point("DeliveryToS3.Bytes", "Bytes", staged.bytes as f64),
                        point("DeliveryToS3.Success", "None", 1.0),
                    ],
                );
                Ok(staged)
            }
            _ => self.deliver_http_like(ctx, job, &effective, role.as_deref(), processing.as_ref()).await,
        }
    }

    /// Destinations reached over HTTP (HTTP endpoints, Splunk, OpenSearch)
    /// and those MWS cannot reach (Snowflake, Iceberg): failures go to the
    /// S3 backup once the retry duration has passed.
    async fn deliver_http_like(
        &self,
        ctx: &RequestContext,
        job: &Job,
        effective: &Value,
        role: Option<&str>,
        processing: Option<&types::ProcessingConfiguration>,
    ) -> Result<Delivered, DeliveryError> {
        let d = &job.destination;
        let backup: types::S3DestinationConfiguration =
            effective.get("s3_configuration").and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default();
        let backup = backup_target(&backup);
        let mode = effective.get("s3_backup_mode").and_then(Value::as_str).unwrap_or_default().to_string();
        let processed =
            self.process(ctx, &job.stream_arn, &job.account, role, processing, false, job.records.clone()).await;
        self.report_processing(ctx, job, effective, processing, &processed).await;
        self.write_errors(ctx, job, &backup, &processed.failed).await?;
        if matches!(mode.as_str(), "AllData" | "AllEvents" | "AllDocuments") {
            self.write_s3(ctx, job, &backup, &processed.ok, false).await?;
        }
        if processed.ok.is_empty() {
            return Ok(Delivered::default());
        }
        let (failed_type, result) = match d.kind.as_str() {
            "http_endpoint" => {
                ("http-endpoint-failed", self.send_http_endpoint(ctx, job, effective, role, &processed.ok).await)
            }
            "splunk" => ("splunk-failed", self.send_splunk(ctx, job, effective, role, &processed.ok).await),
            "elasticsearch" => {
                ("elasticsearch-failed", send_bulk(effective, "cluster_endpoint", ctx, &processed.ok).await)
            }
            "amazonopensearchservice" => {
                ("AmazonOpenSearchService-failed", send_bulk(effective, "cluster_endpoint", ctx, &processed.ok).await)
            }
            "amazon_open_search_serverless" => (
                "AmazonOpenSearchServerless-failed",
                send_bulk(effective, "collection_endpoint", ctx, &processed.ok).await,
            ),
            "snowflake" => (
                "snowflake-failed",
                Err(DeliveryError::new("Snowflake.Unreachable", "MWS does not emulate Snowflake.")),
            ),
            _ => (
                "iceberg-failed",
                Err(DeliveryError::new("Iceberg.Unreachable", "MWS does not emulate Iceberg tables.")),
            ),
        };
        let Err(e) = result else { return Ok(Delivered::of(&processed.ok)) };
        let retry_ms =
            effective.pointer("/retry_options/duration_in_seconds").and_then(Value::as_i64).unwrap_or(300) * 1000;
        let now = ctx.received_at.timestamp_millis();
        let since = d.failing_since.unwrap_or(now);
        if now - since < retry_ms {
            return Err(e);
        }
        let failed: Vec<Failed> = processed
            .ok
            .into_iter()
            .map(|r| Failed {
                source: r.source,
                data: r.data,
                output_type: failed_type,
                error_code: e.code.clone(),
                error_message: e.message.clone(),
                lambda_arn: None,
            })
            .collect();
        self.write_errors(ctx, job, &S3Target { error_prefix: backup.error_prefix.clone(), ..backup.clone() }, &failed)
            .await?;
        // The records are in the S3 backup now; the attempt still failed.
        Err(DeliveryError { give_up: true, ..e })
    }

    /// Write records to S3 as one object per partition (one object without
    /// dynamic partitioning).
    async fn write_s3(
        &self,
        ctx: &RequestContext,
        job: &Job,
        target: &S3Target,
        records: &[Out],
        dynamic: bool,
    ) -> Result<(), DeliveryError> {
        if records.is_empty() {
            return Ok(());
        }
        let mut groups: BTreeMap<(Keys, Keys), Vec<&Out>> = BTreeMap::new();
        for r in records {
            let key = if dynamic {
                (
                    r.query_keys.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                    r.lambda_keys.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                )
            } else {
                (Vec::new(), Vec::new())
            };
            groups.entry(key).or_default().push(r);
        }
        for ((q, l), group) in groups {
            let at = chrono::DateTime::from_timestamp_millis(group[0].source.arrival).unwrap_or(ctx.received_at);
            let query_keys: BTreeMap<String, String> = q.into_iter().collect();
            let lambda_keys: BTreeMap<String, String> = l.into_iter().collect();
            let inputs =
                PrefixInputs { at, error_output_type: None, query_keys: &query_keys, lambda_keys: &lambda_keys };
            let prefix = output::evaluate_prefix(&target.prefix, &inputs, dynamic)
                .map_err(|m| DeliveryError::new("S3.InvalidPrefix", m))?;
            let data: Vec<u8> = group.iter().flat_map(|r| r.data.iter().copied()).collect();
            let ext = output::extension(target.file_extension.as_deref(), &target.compression);
            let name = output::object_name(&job.stream_name, job.version, ctx.received_at, &ext);
            let body = output::compress(&target.compression, &data, name.trim_end_matches(&ext));
            self.put_object(ctx, job, target, &format!("{prefix}{name}"), body).await?;
        }
        Ok(())
    }

    async fn write_errors(
        &self,
        ctx: &RequestContext,
        job: &Job,
        target: &S3Target,
        failed: &[Failed],
    ) -> Result<(), DeliveryError> {
        let mut by_type: BTreeMap<&str, Vec<Failed>> = BTreeMap::new();
        for f in failed {
            by_type.entry(f.output_type).or_default().push(f.clone());
        }
        for (kind, failed) in by_type {
            let prefix = output::error_prefix(target.error_prefix.as_deref(), kind, ctx.received_at);
            let name = output::object_name(&job.stream_name, job.version, ctx.received_at, "");
            let body = output::error_lines(&failed, ctx.received_at.timestamp_millis());
            self.put_object(ctx, job, target, &format!("{prefix}{name}"), body).await?;
        }
        Ok(())
    }

    async fn put_object(
        &self,
        ctx: &RequestContext,
        job: &Job,
        target: &S3Target,
        key: &str,
        body: Vec<u8>,
    ) -> Result<(), DeliveryError> {
        let Some(s3) = self.inner.s3.get() else {
            return Err(DeliveryError::new("S3.ServiceUnavailable", "S3 is not available."));
        };
        let Some(bucket) = target.bucket_arn.rsplit(":::").next().filter(|b| !b.is_empty()) else {
            return Err(DeliveryError::new("S3.InvalidBucket", format!("Invalid bucket ARN {}", target.bucket_arn)));
        };
        let rctx = self
            .role_context(ctx, &target.role, &job.stream_arn, &job.account)
            .map_err(|m| DeliveryError::new("Role.AssumeRoleFailed", m))?;
        let mut request = json!({
            "Bucket": bucket,
            "Key": key,
            "Body": base64::engine::general_purpose::STANDARD.encode(&body),
        });
        if let Some(k) = &target.kms_key {
            request["ServerSideEncryption"] = json!("aws:kms");
            request["SSEKMSKeyId"] = json!(k);
        }
        mws_core::Service::invoke(s3, rctx, "PutObject", request).await.map(|_| ()).map_err(|e| {
            let c: &str = &e.code;
            // Firehose names S3's error codes `S3.<code>`.
            let code = match c {
                "KMS.DisabledException" => "S3.KMS.KeyDisabled".to_string(),
                c if c.contains("AccessDenied") && !c.starts_with("KMS.") => "S3.AccessDenied".to_string(),
                c => format!("S3.{c}"),
            };
            DeliveryError { destination: Some(target.bucket_arn.clone()), ..DeliveryError::new(&code, e.message) }
        })
    }
}

/// Partition key values, in key order.
type Keys = Vec<(String, String)>;

/// Where and how S3 output is written.
#[derive(Debug, Clone, Default)]
struct S3Target {
    role: String,
    bucket_arn: String,
    prefix: String,
    error_prefix: Option<String>,
    compression: String,
    kms_key: Option<String>,
    file_extension: Option<String>,
}

fn backup_target(c: &types::S3DestinationConfiguration) -> S3Target {
    S3Target {
        role: c.role_arn.clone(),
        bucket_arn: c.bucket_arn.clone(),
        prefix: c.prefix.clone().unwrap_or_default(),
        error_prefix: c.error_output_prefix.clone(),
        compression: c.compression_format.clone().unwrap_or_else(|| "UNCOMPRESSED".into()),
        kms_key: c
            .encryption_configuration
            .as_ref()
            .and_then(|e| e.kms_encryption_config.as_ref())
            .map(|k| k.awskms_key_arn.clone()),
        file_extension: None,
    }
}

fn plain_out(records: &[Buffered]) -> Vec<Out> {
    records
        .iter()
        .map(|r| Out {
            data: r.data.clone(),
            source: r.clone(),
            query_keys: BTreeMap::new(),
            lambda_keys: BTreeMap::new(),
        })
        .collect()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    output::compress("GZIP", data, "")
}

impl Firehose {
    /// Firehose's HTTP endpoint delivery request. The endpoint must answer
    /// 200 with a JSON body echoing the request id.
    async fn send_http_endpoint(
        &self,
        ctx: &RequestContext,
        job: &Job,
        c: &Value,
        role: Option<&str>,
        records: &[Out],
    ) -> Result<(), DeliveryError> {
        let h: types::HttpEndpointDestinationConfiguration = serde_json::from_value(c.clone()).unwrap_or_default();
        let secret = match c.get("secrets_manager_configuration") {
            Some(sm) => self
                .secret_value(ctx, &job.stream_arn, &job.account, sm, role, "api_key")
                .await
                .map_err(|m| DeliveryError::new("HttpEndpoint.SecretsManagerAccessDenied", m))?,
            None => None,
        };
        let request_id = uuid::Uuid::new_v4().to_string();
        let body = json!({
            "requestId": request_id,
            "timestamp": ctx.received_at.timestamp_millis(),
            "records": records
                .iter()
                .map(|r| json!({"data": base64::engine::general_purpose::STANDARD.encode(&r.data)}))
                .collect::<Vec<_>>(),
        });
        let mut headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Amz-Firehose-Protocol-Version".to_string(), "1.0".to_string()),
            ("X-Amz-Firehose-Request-Id".to_string(), request_id.clone()),
            ("X-Amz-Firehose-Source-Arn".to_string(), job.stream_arn.clone()),
            ("User-Agent".to_string(), "Amazon Kinesis Data Firehose Agent/1.0".to_string()),
        ];
        if let Some(key) = secret.as_ref().or(h.endpoint_configuration.access_key.as_ref()) {
            headers.push(("X-Amz-Firehose-Access-Key".to_string(), key.clone()));
        }
        let request = h.request_configuration.clone().unwrap_or_default();
        if let Some(attrs) = &request.common_attributes {
            let map: serde_json::Map<String, Value> =
                attrs.iter().map(|a| (a.attribute_name.clone(), json!(a.attribute_value))).collect();
            headers
                .push(("X-Amz-Firehose-Common-Attributes".to_string(), json!({"commonAttributes": map}).to_string()));
        }
        let mut payload = body.to_string().into_bytes();
        if request.content_encoding.as_deref() == Some("GZIP") {
            headers.push(("Content-Encoding".to_string(), "gzip".to_string()));
            payload = gzip(&payload);
        }
        let resp = http::send(http::Request {
            method: "POST",
            url: &h.endpoint_configuration.url,
            headers,
            body: Some(payload),
        })
        .await
        .map_err(|m| {
            DeliveryError::new(
                "HttpEndpoint.ConnectionFailed",
                format!("Unable to connect to the destination endpoint. {m}"),
            )
        })?;
        if resp.status != 200 {
            return Err(DeliveryError::new(
                "HttpEndpoint.DestinationException",
                format!(
                    "The following response was received from the endpoint destination. {}: {}",
                    resp.status,
                    String::from_utf8_lossy(&resp.body)
                ),
            ));
        }
        let echoed = serde_json::from_slice::<Value>(&resp.body)
            .ok()
            .and_then(|v| v.get("requestId").and_then(Value::as_str).map(str::to_string));
        if echoed.as_deref() != Some(request_id.as_str()) {
            return Err(DeliveryError::new(
                "HttpEndpoint.InvalidResponseFromDestination",
                format!(
                    "The response received from the specified endpoint is invalid. Contact the owner of the endpoint to resolve the issue. Response for request {request_id} is not recognized as valid JSON or has unexpected fields. Raw response received: {} {}",
                    resp.status,
                    String::from_utf8_lossy(&resp.body)
                ),
            ));
        }
        Ok(())
    }

    /// Splunk HTTP Event Collector delivery.
    async fn send_splunk(
        &self,
        ctx: &RequestContext,
        job: &Job,
        c: &Value,
        role: Option<&str>,
        records: &[Out],
    ) -> Result<(), DeliveryError> {
        let s: types::SplunkDestinationConfiguration = serde_json::from_value(c.clone()).unwrap_or_default();
        let secret = match c.get("secrets_manager_configuration") {
            Some(sm) => self
                .secret_value(ctx, &job.stream_arn, &job.account, sm, role, "hec_token")
                .await
                .map_err(|m| DeliveryError::new("Splunk.SecretsManagerAccessDenied", m))?,
            None => None,
        };
        let path = if s.hec_endpoint_type == "Raw" { "/services/collector/raw" } else { "/services/collector/event" };
        let url = format!("{}{path}", s.hec_endpoint.trim_end_matches('/'));
        let body: Vec<u8> = records.iter().flat_map(|r| r.data.iter().copied()).collect();
        let token = secret.or(s.hec_token).unwrap_or_default();
        let headers = vec![
            ("Authorization".to_string(), format!("Splunk {token}")),
            ("Content-Type".to_string(), "application/json".to_string()),
            ("X-Splunk-Request-Channel".to_string(), uuid::Uuid::new_v4().to_string()),
        ];
        let resp = http::send(http::Request { method: "POST", url: &url, headers, body: Some(body) }).await.map_err(|m| {
            DeliveryError::new(
                "Splunk.ConnectionTimeout",
                format!("The connection to Splunk timed out. This might be a transient error and the request will be retried. {m}"),
            )
        })?;
        if resp.status != 200 {
            let text = String::from_utf8_lossy(&resp.body);
            let (code, message) = match resp.status {
                401 | 403 => {
                    ("Splunk.InvalidToken", "The HEC token is invalid. Update Firehose with a valid HEC token.")
                }
                404 => ("Splunk.URLNotFound", "The requested URL was not found on the Splunk server."),
                400 => ("Splunk.InvalidDataFormat", "The data is not formatted correctly."),
                _ => ("Splunk.ServerError", "Data delivery to Splunk failed due to a server error from a Splunk node."),
            };
            return Err(DeliveryError::new(
                code,
                format!("{message} The HEC endpoint answered {}: {text}", resp.status),
            ));
        }
        Ok(())
    }
}

/// The index name with its rotation suffix.
fn rotated_index(index: &str, rotation: &str, at: chrono::DateTime<chrono::Utc>) -> String {
    match rotation {
        "OneHour" => format!("{index}-{}", at.format("%Y-%m-%d-%H")),
        "OneDay" => format!("{index}-{}", at.format("%Y-%m-%d")),
        "OneWeek" => format!("{index}-{}", at.format("%Y-w%V")),
        "OneMonth" => format!("{index}-{}", at.format("%Y-%m")),
        _ => index.to_string(),
    }
}

/// An OpenSearch / Elasticsearch `_bulk` request to the configured
/// endpoint. Domains named only by ARN cannot be reached.
async fn send_bulk(c: &Value, endpoint_key: &str, ctx: &RequestContext, records: &[Out]) -> Result<(), DeliveryError> {
    let Some(endpoint) = c.get(endpoint_key).and_then(Value::as_str) else {
        return Err(DeliveryError::new(
            "OS.ConnectionFailed",
            "MWS does not emulate OpenSearch domains; configure a ClusterEndpoint to deliver to.",
        ));
    };
    let index = c.get("index_name").and_then(Value::as_str).unwrap_or_default();
    let rotation = c.get("index_rotation_period").and_then(Value::as_str).unwrap_or("NoRotation");
    let index = rotated_index(index, rotation, ctx.received_at);
    let mut body = Vec::new();
    for r in records {
        body.extend_from_slice(json!({"index": {"_index": index}}).to_string().as_bytes());
        body.push(b'\n');
        body.extend_from_slice(String::from_utf8_lossy(&r.data).trim_end().as_bytes());
        body.push(b'\n');
    }
    let url = format!("{}/_bulk", endpoint.trim_end_matches('/'));
    let headers = vec![("Content-Type".to_string(), "application/x-ndjson".to_string())];
    let resp = http::send(http::Request { method: "POST", url: &url, headers, body: Some(body) })
        .await
        .map_err(|m| DeliveryError::new("OS.ConnectionFailed", m))?;
    if !(200..300).contains(&resp.status) {
        return Err(DeliveryError::new(
            "OS.InvalidResponse",
            format!("The endpoint answered {}: {}", resp.status, String::from_utf8_lossy(&resp.body)),
        ));
    }
    Ok(())
}

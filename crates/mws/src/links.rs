//! Glue between services whose crates cannot depend on each other (the
//! dependency would run in a cycle), wired where AWS couples them.

use mws_core::RequestContext;
use mws_s3::{NotificationDestination, NotificationSource};
use mws_sns::{QueueDelivery, QueueMessage};
use mws_sqs::{ServiceMessage, ServiceMessageAttribute, ServiceSendError, Sqs};

/// SNS delivering to `sqs` subscriptions and dead-letter queues.
pub(crate) struct SnsToSqs(pub Sqs);

impl QueueDelivery for SnsToSqs {
    fn send(&self, m: QueueMessage) -> Result<String, String> {
        let attributes = m
            .message_attributes
            .into_iter()
            .map(|(k, v)| {
                (
                    k,
                    ServiceMessageAttribute {
                        data_type: v.data_type,
                        string_value: v.string_value,
                        binary_value: v.binary_value,
                    },
                )
            })
            .collect();
        self.0
            .send_message_as_service(ServiceMessage {
                queue_arn: &m.queue_arn,
                service_principal: &m.service_principal,
                source_arn: &m.source_arn,
                source_account: &m.source_account,
                body: m.body,
                message_attributes: attributes,
                message_group_id: m.message_group_id,
                message_deduplication_id: m.message_deduplication_id,
                now: m.now,
            })
            .map_err(|e| e.to_string())
    }
}

/// S3 event notifications sent to queues as `s3.amazonaws.com`.
pub(crate) struct S3ToSqs(pub Sqs);

const S3_PRINCIPAL: &str = "s3.amazonaws.com";

impl NotificationDestination for S3ToSqs {
    fn service(&self) -> &'static str {
        "sqs"
    }

    fn check(&self, _ctx: &RequestContext, arn: &str, source: &NotificationSource<'_>) -> Result<(), String> {
        if arn.ends_with(".fifo") {
            return Err("FIFO SQS queues are not supported as notification destinations".to_string());
        }
        self.0.check_service_access(arn, S3_PRINCIPAL, source.bucket_arn, source.bucket_owner).map_err(|e| match e {
            ServiceSendError::NoSuchQueue => "The destination queue does not exist".to_string(),
            _ => "Permissions on the destination queue do not allow S3 to publish notifications from this bucket"
                .to_string(),
        })
    }

    fn deliver(&self, ctx: &RequestContext, arn: &str, source: &NotificationSource<'_>, message: String) {
        let sent = self.0.send_message_as_service(ServiceMessage {
            queue_arn: arn,
            service_principal: S3_PRINCIPAL,
            source_arn: source.bucket_arn,
            source_account: source.bucket_owner,
            body: message,
            message_attributes: Default::default(),
            message_group_id: None,
            message_deduplication_id: None,
            now: ctx.received_at,
        });
        if let Err(e) = sent {
            tracing::warn!(queue = arn, "S3 could not send a notification: {e}");
        }
    }
}

/// Lambda's event source pollers reading SQS queues as the function's
/// execution role, through SQS's own operations.
pub(crate) struct LambdaFromSqs(pub Sqs);

fn queue_url(ctx: &RequestContext, arn: &str) -> Result<String, mws_core::ServiceError> {
    Sqs::queue_url_for(ctx, arn).ok_or_else(|| {
        mws_core::ServiceError::client(
            "AWS.SimpleQueueService.NonExistentQueue",
            400,
            "The specified queue does not exist.",
        )
    })
}

#[async_trait::async_trait]
impl mws_lambda::QueueSource for LambdaFromSqs {
    fn facts(&self, ctx: &RequestContext, queue_arn: &str) -> Result<mws_lambda::QueueFacts, mws_core::ServiceError> {
        let out = self.0.get_queue_attributes(
            ctx,
            mws_sqs::generated::types::GetQueueAttributesRequest {
                queue_url: queue_url(ctx, queue_arn)?,
                attribute_names: Some(vec!["VisibilityTimeout".into(), "FifoQueue".into()]),
            },
        )?;
        let attrs = out.attributes.unwrap_or_default();
        Ok(mws_lambda::QueueFacts {
            visibility_timeout: attrs.get("VisibilityTimeout").and_then(|v| v.parse().ok()).unwrap_or(30),
            fifo: attrs.get("FifoQueue").is_some_and(|v| v == "true"),
        })
    }

    fn authorize(&self, ctx: &RequestContext, queue_arn: &str, action: &str) -> Result<(), mws_core::ServiceError> {
        self.0.authorize_caller(ctx, queue_arn, action)
    }

    async fn receive(
        &self,
        ctx: &RequestContext,
        queue_arn: &str,
        max: i32,
    ) -> Result<Vec<mws_lambda::QueueMessage>, mws_core::ServiceError> {
        let out = self
            .0
            .receive_message(
                ctx,
                mws_sqs::generated::types::ReceiveMessageRequest {
                    queue_url: queue_url(ctx, queue_arn)?,
                    max_number_of_messages: Some(max.clamp(1, 10)),
                    wait_time_seconds: Some(0),
                    message_system_attribute_names: Some(vec!["All".into()]),
                    message_attribute_names: Some(vec!["All".into()]),
                    ..Default::default()
                },
            )
            .await?;
        Ok(out
            .messages
            .unwrap_or_default()
            .into_iter()
            .map(|m| mws_lambda::QueueMessage {
                message_id: m.message_id.unwrap_or_default(),
                receipt_handle: m.receipt_handle.unwrap_or_default(),
                body: m.body.unwrap_or_default(),
                md5_of_body: m.md5_of_body.unwrap_or_default(),
                md5_of_message_attributes: m.md5_of_message_attributes,
                attributes: m.attributes.unwrap_or_default(),
                message_attributes: m
                    .message_attributes
                    .unwrap_or_default()
                    .into_iter()
                    .map(|(k, v)| {
                        (
                            k,
                            mws_lambda::QueueMessageAttribute {
                                data_type: v.data_type,
                                string_value: v.string_value,
                                binary_value: v.binary_value,
                            },
                        )
                    })
                    .collect(),
            })
            .collect())
    }

    fn delete(
        &self,
        ctx: &RequestContext,
        queue_arn: &str,
        receipt_handles: &[String],
    ) -> Result<(), mws_core::ServiceError> {
        let url = queue_url(ctx, queue_arn)?;
        for chunk in receipt_handles.chunks(10) {
            self.0.delete_message_batch(
                ctx,
                mws_sqs::generated::types::DeleteMessageBatchRequest {
                    queue_url: url.clone(),
                    entries: chunk
                        .iter()
                        .enumerate()
                        .map(|(i, h)| mws_sqs::generated::types::DeleteMessageBatchRequestEntry {
                            id: i.to_string(),
                            receipt_handle: h.clone(),
                        })
                        .collect(),
                },
            )?;
        }
        Ok(())
    }
}

/// CloudWatch Logs subscription filters invoking Lambda functions, as
/// `logs.amazonaws.com` (or its Regional form), asynchronously.
pub(crate) struct LogsToLambda(pub mws_lambda::Lambda);

const LOGS_PERMISSION: &str =
    "Could not execute the lambda function. Make sure you have given CloudWatch Logs permission to execute your function.";

impl LogsToLambda {
    fn principals(region: &str) -> [String; 2] {
        ["logs.amazonaws.com".to_string(), format!("logs.{region}.amazonaws.com")]
    }
}

impl mws_logs::SubscriptionTarget for LogsToLambda {
    fn service(&self) -> &'static str {
        "lambda"
    }

    fn check(&self, ctx: &RequestContext, arn: &str, source: &mws_logs::SubscriptionSource<'_>) -> Result<(), String> {
        let allowed = Self::principals(&ctx.region).iter().any(|p| {
            let inv = mws_lambda::ServiceInvocation {
                function: arn,
                service_principal: p,
                source_account: Some(source.account),
                source_arn: Some(source.log_group_arn),
                payload: Vec::new(),
            };
            self.0.check_service_invoke(ctx, &inv).is_ok()
        });
        if allowed {
            Ok(())
        } else {
            Err(LOGS_PERMISSION.to_string())
        }
    }

    fn deliver(&self, ctx: &RequestContext, arn: &str, source: &mws_logs::SubscriptionSource<'_>, gzipped: Vec<u8>) {
        let payload = mws_logs::lambda_event(&gzipped);
        for p in Self::principals(&ctx.region) {
            let inv = mws_lambda::ServiceInvocation {
                function: arn,
                service_principal: &p,
                source_account: Some(source.account),
                source_arn: Some(source.log_group_arn),
                payload: payload.clone(),
            };
            match self.0.invoke_event_as_service(ctx, inv) {
                Ok(()) => return,
                Err(mws_lambda::ServiceInvokeError::AccessDenied) => continue,
                Err(e) => {
                    tracing::debug!(function = arn, "subscription delivery failed: {e:?}");
                    return;
                }
            }
        }
    }
}

/// CloudWatch Logs assuming a subscription's role, as `logs.amazonaws.com`
/// or the regional principal, whichever the trust policy names.
fn logs_role_context(
    sts: &mws_sts::Sts,
    ctx: &RequestContext,
    source: &mws_logs::SubscriptionSource<'_>,
) -> Result<RequestContext, String> {
    let cannot = || "Make sure you have given CloudWatch Logs permission to assume the provided role.".to_string();
    let role = source.role_arn.ok_or_else(cannot)?;
    for principal in LogsToLambda::principals(&ctx.region) {
        let Ok(creds) = sts.assume_role_as_service(&mws_sts::ServiceAssume {
            role_arn: role,
            service_principal: &principal,
            session_name: "CWLtoKinesisSession",
            duration_seconds: 3600,
            source_account: Some(source.account),
            source_arn: Some(source.log_group_arn),
            now: ctx.received_at,
        }) else {
            continue;
        };
        if let Ok(Some(r)) =
            sts.credential_store().resolve(&creds.access_key_id, Some(&creds.session_token), ctx.received_at)
        {
            return Ok(RequestContext { caller: r.caller, source_ip: None, ..ctx.clone() });
        }
    }
    Err(cannot())
}

/// The Kinesis partition key CloudWatch Logs uses: the log stream for
/// `ByLogStream`, random for `Random`.
fn logs_partition_key(source: &mws_logs::SubscriptionSource<'_>) -> String {
    if source.distribution == "Random" || source.log_stream.is_empty() {
        uuid::Uuid::new_v4().simple().to_string()
    } else {
        source.log_stream.to_string()
    }
}

/// Subscription filters delivering to Kinesis data streams, as the
/// filter's role.
pub(crate) struct LogsToKinesis {
    pub kinesis: mws_kinesis::Kinesis,
    pub sts: mws_sts::Sts,
}

impl LogsToKinesis {
    fn put(&self, ctx: &RequestContext, arn: &str, partition_key: String, data: Vec<u8>) -> Result<(), String> {
        self.kinesis
            .put_record(
                ctx,
                mws_kinesis::generated::types::PutRecordInput {
                    stream_arn: Some(arn.to_string()),
                    partition_key: Some(partition_key),
                    data,
                    ..Default::default()
                },
            )
            .map(|_| ())
            .map_err(|e| e.message)
    }
}

impl mws_logs::SubscriptionTarget for LogsToKinesis {
    fn service(&self) -> &'static str {
        "kinesis"
    }

    fn check(&self, ctx: &RequestContext, arn: &str, source: &mws_logs::SubscriptionSource<'_>) -> Result<(), String> {
        let rctx = logs_role_context(&self.sts, ctx, source)
            .map_err(|m| format!("Could not deliver test message to specified Kinesis stream. {m}"))?;
        let test = mws_logs::control_message(ctx.received_at.timestamp_millis(), "Kinesis stream");
        self.put(&rctx, arn, uuid::Uuid::new_v4().simple().to_string(), test).map_err(|_| {
            "Could not deliver test message to specified Kinesis stream. Check if the given kinesis stream is in ACTIVE state."
                .to_string()
        })
    }

    fn deliver(&self, ctx: &RequestContext, arn: &str, source: &mws_logs::SubscriptionSource<'_>, gzipped: Vec<u8>) {
        let sent = logs_role_context(&self.sts, ctx, source)
            .and_then(|rctx| self.put(&rctx, arn, logs_partition_key(source), gzipped));
        if let Err(e) = sent {
            tracing::info!(stream = arn, "CloudWatch Logs could not deliver to Kinesis: {e}");
        }
    }
}

/// Subscription filters delivering to Firehose streams, as the filter's
/// role.
pub(crate) struct LogsToFirehose {
    pub firehose: mws_firehose::Firehose,
    pub sts: mws_sts::Sts,
}

impl LogsToFirehose {
    fn put(&self, ctx: &RequestContext, arn: &str, data: Vec<u8>) -> Result<(), String> {
        let name = arn.rsplit_once("deliverystream/").map(|(_, n)| n).unwrap_or(arn);
        self.firehose
            .put_record(
                ctx,
                mws_firehose::generated::types::PutRecordInput {
                    delivery_stream_name: name.to_string(),
                    record: mws_firehose::generated::types::Record { data },
                },
            )
            .map(|_| ())
            .map_err(|e| e.message)
    }
}

impl mws_logs::SubscriptionTarget for LogsToFirehose {
    fn service(&self) -> &'static str {
        "firehose"
    }

    fn check(&self, ctx: &RequestContext, arn: &str, source: &mws_logs::SubscriptionSource<'_>) -> Result<(), String> {
        let rctx = logs_role_context(&self.sts, ctx, source)
            .map_err(|m| format!("Could not deliver test message to specified Firehose stream. {m}"))?;
        let test = mws_logs::control_message(ctx.received_at.timestamp_millis(), "Firehose");
        self.put(&rctx, arn, test).map_err(|_| {
            "Could not deliver test message to specified Firehose stream. Check if the given Firehose stream is in ACTIVE state."
                .to_string()
        })
    }

    fn deliver(&self, ctx: &RequestContext, arn: &str, source: &mws_logs::SubscriptionSource<'_>, gzipped: Vec<u8>) {
        let sent = logs_role_context(&self.sts, ctx, source).and_then(|rctx| self.put(&rctx, arn, gzipped));
        if let Err(e) = sent {
            tracing::info!(stream = arn, "CloudWatch Logs could not deliver to Firehose: {e}");
        }
    }
}

/// Lambda's event source pollers reading Kinesis data streams as the
/// function's execution role, through Kinesis's own operations.
pub(crate) struct LambdaFromKinesis(pub mws_kinesis::Kinesis);

impl mws_lambda::StreamSource for LambdaFromKinesis {
    fn authorize(&self, ctx: &RequestContext, stream_arn: &str, action: &str) -> Result<(), mws_core::ServiceError> {
        self.0.authorize_caller(ctx, stream_arn, action)
    }

    fn shards(
        &self,
        ctx: &RequestContext,
        stream_arn: &str,
    ) -> Result<Vec<mws_lambda::StreamShard>, mws_core::ServiceError> {
        let mut out = Vec::new();
        let mut token = None;
        loop {
            let page = self.0.list_shards(
                ctx,
                mws_kinesis::generated::types::ListShardsInput {
                    stream_arn: token.is_none().then(|| stream_arn.to_string()),
                    next_token: token.clone(),
                    ..Default::default()
                },
            )?;
            out.extend(page.shards.unwrap_or_default().into_iter().map(|s| mws_lambda::StreamShard {
                shard_id: s.shard_id,
                parent_shard_id: s.parent_shard_id,
                adjacent_parent_shard_id: s.adjacent_parent_shard_id,
            }));
            match page.next_token {
                Some(t) => token = Some(t),
                None => return Ok(out),
            }
        }
    }

    fn iterator(
        &self,
        ctx: &RequestContext,
        stream_arn: &str,
        shard_id: &str,
        position: mws_lambda::StreamPosition,
    ) -> Result<String, mws_core::ServiceError> {
        let mut input = mws_kinesis::generated::types::GetShardIteratorInput {
            stream_arn: Some(stream_arn.to_string()),
            shard_id: shard_id.to_string(),
            ..Default::default()
        };
        input.shard_iterator_type = match position {
            mws_lambda::StreamPosition::TrimHorizon => "TRIM_HORIZON".into(),
            mws_lambda::StreamPosition::Latest => "LATEST".into(),
            mws_lambda::StreamPosition::AtTimestamp(t) => {
                input.timestamp = Some(t);
                "AT_TIMESTAMP".into()
            }
            mws_lambda::StreamPosition::AfterSequenceNumber(seq) => {
                input.starting_sequence_number = Some(seq);
                "AFTER_SEQUENCE_NUMBER".into()
            }
        };
        Ok(self.0.get_shard_iterator(ctx, input)?.shard_iterator.unwrap_or_default())
    }

    fn read(
        &self,
        ctx: &RequestContext,
        iterator: &str,
        limit: i32,
    ) -> Result<mws_lambda::StreamRead, mws_core::ServiceError> {
        let out = self.0.get_records(
            ctx,
            mws_kinesis::generated::types::GetRecordsInput {
                shard_iterator: iterator.to_string(),
                limit: Some(limit),
                ..Default::default()
            },
        )?;
        Ok(mws_lambda::StreamRead {
            records: out
                .records
                .into_iter()
                .map(|r| mws_lambda::StreamRecord {
                    sequence_number: r.sequence_number,
                    partition_key: r.partition_key.unwrap_or_default(),
                    data: r.data,
                    approximate_arrival: r.approximate_arrival_timestamp.unwrap_or(ctx.received_at),
                    encryption_type: r.encryption_type,
                })
                .collect(),
            next_iterator: out.next_shard_iterator,
        })
    }
}

/// CloudWatch Logs metric filters publish their metrics into CloudWatch.
pub struct LogsToCloudWatch(pub mws_cloudwatch::CloudWatch);

impl mws_logs::MetricPublisher for LogsToCloudWatch {
    fn publish(&self, metrics: Vec<mws_logs::FilterMetric>) {
        for m in metrics {
            let Some(timestamp) = chrono::DateTime::from_timestamp_millis(m.timestamp) else { continue };
            self.0.put_metric_as_service(mws_cloudwatch::ServiceMetric {
                account: m.account,
                region: m.region,
                namespace: m.namespace,
                metric_name: m.metric_name,
                dimensions: m.dimensions,
                unit: m.unit,
                timestamp,
                values: vec![(m.value, 1.0)],
            });
        }
    }
}

/// Kinesis publishes its `AWS/Kinesis` metrics into CloudWatch.
pub struct KinesisToCloudWatch(pub mws_cloudwatch::CloudWatch);

impl mws_kinesis::MetricPublisher for KinesisToCloudWatch {
    fn publish(&self, metrics: Vec<mws_kinesis::KinesisMetric>) {
        for m in metrics {
            let Some(timestamp) = chrono::DateTime::from_timestamp_millis(m.timestamp) else { continue };
            self.0.put_metric_as_service(mws_cloudwatch::ServiceMetric {
                account: m.account,
                region: m.region,
                namespace: m.namespace,
                metric_name: m.metric_name,
                dimensions: m.dimensions,
                unit: Some(m.unit),
                timestamp,
                values: vec![(m.value, 1.0)],
            });
        }
    }
}

/// CloudWatch metric streams putting their records into Firehose, as the
/// stream's role assumed by `streams.metrics.cloudwatch.amazonaws.com`.
pub(crate) struct MetricStreamsToFirehose {
    pub firehose: mws_firehose::Firehose,
    pub sts: mws_sts::Sts,
}

impl mws_cloudwatch::MetricStreamDelivery for MetricStreamsToFirehose {
    fn deliver(
        &self,
        ctx: &RequestContext,
        stream_arn: &str,
        firehose_arn: &str,
        role_arn: &str,
        records: Vec<Vec<u8>>,
    ) -> Result<(), String> {
        let creds = self
            .sts
            .assume_role_as_service(&mws_sts::ServiceAssume {
                role_arn,
                service_principal: "streams.metrics.cloudwatch.amazonaws.com",
                session_name: "MetricStreams",
                duration_seconds: 3600,
                source_account: Some(&ctx.caller.account_id),
                source_arn: Some(stream_arn),
                now: ctx.received_at,
            })
            .map_err(|e| format!("CloudWatch could not assume {role_arn}: {e:?}"))?;
        let resolved = self
            .sts
            .credential_store()
            .resolve(&creds.access_key_id, Some(&creds.session_token), ctx.received_at)
            .map_err(|e| format!("{e:?}"))?
            .ok_or_else(|| "the role session could not be resolved".to_string())?;
        let rctx = RequestContext { caller: resolved.caller, source_ip: None, ..ctx.clone() };
        let name = firehose_arn.rsplit_once("deliverystream/").map(|(_, n)| n).unwrap_or(firehose_arn);
        // Firehose takes up to 1,000 KiB per record: pack the lines.
        let mut chunk: Vec<u8> = Vec::new();
        let mut chunks = Vec::new();
        for r in records {
            if !chunk.is_empty() && chunk.len() + r.len() > 1_000_000 {
                chunks.push(std::mem::take(&mut chunk));
            }
            chunk.extend(r);
        }
        if !chunk.is_empty() {
            chunks.push(chunk);
        }
        for data in chunks {
            self.firehose
                .put_record(
                    &rctx,
                    mws_firehose::generated::types::PutRecordInput {
                        delivery_stream_name: name.to_string(),
                        record: mws_firehose::generated::types::Record { data },
                    },
                )
                .map_err(|e| e.message)?;
        }
        Ok(())
    }
}

//! Glue between services whose crates cannot depend on each other (the
//! dependency would run in a cycle), wired where AWS couples them.

use mws_core::{RequestContext, ServiceClient};
use mws_s3::{NotificationDestination, NotificationSource};
use mws_sns::{QueueDelivery, QueueMessage};
use mws_sqs::{ServiceSendError, Sqs};

/// SNS delivering to `sqs` subscriptions and dead-letter queues: SNS calls
/// SQS's own `SendMessage` as `sns.amazonaws.com`, which the queue policy
/// (and the queue's KMS key policy) must allow for the topic.
pub(crate) struct SnsToSqs(pub ServiceClient);

#[async_trait::async_trait]
impl QueueDelivery for SnsToSqs {
    async fn send(&self, ctx: &RequestContext, m: QueueMessage) -> Result<String, String> {
        let mut ctx = ctx.as_service(&m.service_principal, &m.source_account, Some(&m.source_arn));
        ctx.received_at = m.now;
        let attributes =
            m.message_attributes.into_iter().map(|(k, v)| (k, (v.data_type, v.string_value, v.binary_value)));
        let message = OutgoingMessage {
            body: m.body,
            attributes: attributes.collect(),
            group_id: m.message_group_id,
            dedup_id: m.message_deduplication_id,
        };
        send_message(&self.0, ctx, &m.queue_arn, message).await.map_err(|e| e.message.to_string())
    }
}

/// A message attribute: `(data type, string value, binary value)`.
pub(crate) type Attribute = (String, Option<String>, Option<Vec<u8>>);

/// A message one service sends to a queue.
pub(crate) struct OutgoingMessage {
    pub body: String,
    pub attributes: std::collections::BTreeMap<String, Attribute>,
    pub group_id: Option<String>,
    pub dedup_id: Option<String>,
}

/// Call SQS's `SendMessage` on `queue_arn` as `ctx`'s caller (normally a
/// service principal). Returns the message id.
pub(crate) async fn send_message(
    client: &ServiceClient,
    mut ctx: RequestContext,
    queue_arn: &str,
    m: OutgoingMessage,
) -> Result<String, mws_core::ServiceError> {
    use base64::Engine;
    if let Some(region) = queue_arn.split(':').nth(3) {
        ctx.region = region.to_string();
    }
    let queue_url = Sqs::queue_url_for(&ctx, queue_arn).ok_or_else(|| {
        mws_core::ServiceError::client("QueueDoesNotExist", 400, "The specified queue does not exist.")
    })?;
    let mut input = serde_json::json!({ "QueueUrl": queue_url, "MessageBody": m.body });
    if !m.attributes.is_empty() {
        let attributes: serde_json::Map<String, serde_json::Value> = m
            .attributes
            .into_iter()
            .map(|(k, (data_type, string, binary))| {
                let mut a = serde_json::json!({ "DataType": data_type });
                if let Some(s) = string {
                    a["StringValue"] = s.into();
                }
                if let Some(b) = binary {
                    a["BinaryValue"] = base64::engine::general_purpose::STANDARD.encode(b).into();
                }
                (k, a)
            })
            .collect();
        input["MessageAttributes"] = attributes.into();
    }
    if let Some(g) = m.group_id {
        input["MessageGroupId"] = g.into();
    }
    if let Some(d) = m.dedup_id {
        input["MessageDeduplicationId"] = d.into();
    }
    let out = client.call(&ctx, "sqs", "SendMessage", input).await?;
    Ok(out.get("MessageId").and_then(serde_json::Value::as_str).unwrap_or_default().to_string())
}

/// S3 event notifications sent to queues as `s3.amazonaws.com`: S3 calls
/// SQS's own `SendMessage`, which the queue policy (and the queue's KMS key
/// policy) must allow for the bucket.
pub(crate) struct S3ToSqs {
    pub sqs: Sqs,
    pub client: ServiceClient,
}

const S3_PRINCIPAL: &str = "s3.amazonaws.com";

impl NotificationDestination for S3ToSqs {
    fn service(&self) -> &'static str {
        "sqs"
    }

    fn check(&self, _ctx: &RequestContext, arn: &str, source: &NotificationSource<'_>) -> Result<(), String> {
        if arn.ends_with(".fifo") {
            return Err("FIFO SQS queues are not supported as notification destinations".to_string());
        }
        self.sqs.check_service_access(arn, S3_PRINCIPAL, source.bucket_arn, source.bucket_owner).map_err(|e| match e {
            ServiceSendError::NoSuchQueue => "The destination queue does not exist".to_string(),
            _ => "Permissions on the destination queue do not allow S3 to publish notifications from this bucket"
                .to_string(),
        })
    }

    fn deliver(&self, ctx: &RequestContext, arn: &str, source: &NotificationSource<'_>, message: String) {
        let ctx = ctx.as_service(S3_PRINCIPAL, source.bucket_owner, Some(source.bucket_arn));
        let (client, queue) = (self.client.clone(), arn.to_string());
        mws_core::deferred::defer(async move {
            let message =
                OutgoingMessage { body: message, attributes: Default::default(), group_id: None, dedup_id: None };
            if let Err(e) = send_message(&client, ctx, &queue, message).await {
                tracing::warn!(queue, "S3 could not send a notification: {}", e.message);
            }
        });
    }
}

/// S3 event notifications that invoke functions: S3 calls Lambda's own
/// `Invoke` (`Event`) as `s3.amazonaws.com`, which the function policy must
/// allow for the bucket.
pub(crate) struct S3ToLambda {
    pub lambda: mws_lambda::Lambda,
    pub client: ServiceClient,
}

impl NotificationDestination for S3ToLambda {
    fn service(&self) -> &'static str {
        "lambda"
    }

    fn check(&self, ctx: &RequestContext, arn: &str, source: &NotificationSource<'_>) -> Result<(), String> {
        self.lambda.check(ctx, arn, source)
    }

    fn deliver(&self, ctx: &RequestContext, arn: &str, source: &NotificationSource<'_>, message: String) {
        let ctx = ctx.as_service(S3_PRINCIPAL, source.bucket_owner, Some(source.bucket_arn));
        let (client, function) = (self.client.clone(), arn.to_string());
        mws_core::deferred::defer(async move {
            if let Err(e) = invoke_event(&client, ctx, &function, message.into_bytes()).await {
                tracing::warn!(function, "S3 could not invoke a notification function: {}", e.message);
            }
        });
    }
}

/// S3 event notifications published to topics: S3 calls SNS's own
/// `Publish` as `s3.amazonaws.com`, which the topic policy must allow.
pub(crate) struct S3ToSns {
    pub sns: mws_sns::Sns,
    pub client: ServiceClient,
}

impl NotificationDestination for S3ToSns {
    fn service(&self) -> &'static str {
        "sns"
    }

    fn check(&self, ctx: &RequestContext, arn: &str, source: &NotificationSource<'_>) -> Result<(), String> {
        self.sns.check(ctx, arn, source)
    }

    fn deliver(&self, ctx: &RequestContext, arn: &str, source: &NotificationSource<'_>, message: String) {
        let mut ctx = ctx.as_service(S3_PRINCIPAL, source.bucket_owner, Some(source.bucket_arn));
        if let Some(region) = arn.split(':').nth(3) {
            ctx.region = region.to_string();
        }
        let (client, topic) = (self.client.clone(), arn.to_string());
        mws_core::deferred::defer(async move {
            let input = serde_json::json!({
                "TopicArn": topic,
                "Message": message,
                "Subject": "Amazon S3 Notification",
            });
            if let Err(e) = client.call(&ctx, "sns", "Publish", input).await {
                tracing::warn!(topic, "S3 could not publish a notification: {}", e.message);
            }
        });
    }
}

/// Call Lambda's `Invoke` with `InvocationType=Event` on `function` as
/// `ctx`'s caller (normally a service principal).
pub(crate) async fn invoke_event(
    client: &ServiceClient,
    mut ctx: RequestContext,
    function: &str,
    payload: Vec<u8>,
) -> Result<(), mws_core::ServiceError> {
    use base64::Engine;
    if let Some(region) = function.strip_prefix("arn:").and_then(|a| a.split(':').nth(2)) {
        ctx.region = region.to_string();
    }
    let input = serde_json::json!({
        "FunctionName": function,
        "InvocationType": "Event",
        "Payload": base64::engine::general_purpose::STANDARD.encode(payload),
    });
    client.call(&ctx, "lambda", "Invoke", input).await.map(|_| ())
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

/// Firehose publishing its `AWS/Firehose` metrics into CloudWatch.
pub struct FirehoseToCloudWatch(pub mws_cloudwatch::CloudWatch);

impl mws_firehose::MetricPublisher for FirehoseToCloudWatch {
    fn publish(&self, metrics: Vec<mws_firehose::FirehoseMetric>) {
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

/// SQS publishing its `AWS/SQS` queue metrics into CloudWatch.
pub struct SqsToCloudWatch(pub mws_cloudwatch::CloudWatch);

impl mws_sqs::MetricPublisher for SqsToCloudWatch {
    fn publish(&self, metrics: Vec<mws_sqs::QueueMetric>) {
        for m in metrics {
            let Some(timestamp) = chrono::DateTime::from_timestamp_millis(m.timestamp) else { continue };
            self.0.put_metric_as_service(mws_cloudwatch::ServiceMetric {
                account: m.account,
                region: m.region,
                namespace: "AWS/SQS".into(),
                metric_name: m.metric_name.into(),
                dimensions: vec![("QueueName".into(), m.queue_name)],
                unit: Some(m.unit.into()),
                timestamp,
                values: m.values,
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

/// Lambda destination records (asynchronous invocation destinations,
/// dead-letter queues, stream mapping failures) for SQS, SNS and
/// EventBridge, sent through each service's own operation as the
/// function's execution role.
pub(crate) enum LambdaDestination {
    Sqs(Sqs),
    Sns(mws_sns::Sns),
    Events(mws_events::Events),
}

fn message_attributes(m: &mws_lambda::DestinationMessage) -> serde_json::Map<String, serde_json::Value> {
    let strings = m.string_attributes.iter().map(|(k, v)| (k, "String", v));
    let numbers = m.number_attributes.iter().map(|(k, v)| (k, "Number", v));
    strings
        .chain(numbers)
        .map(|(k, t, v)| (k.clone(), serde_json::json!({ "DataType": t, "StringValue": v })))
        .collect()
}

#[async_trait::async_trait]
impl mws_lambda::DestinationSink for LambdaDestination {
    fn service(&self) -> &'static str {
        match self {
            LambdaDestination::Sqs(_) => "sqs",
            LambdaDestination::Sns(_) => "sns",
            LambdaDestination::Events(_) => "events",
        }
    }

    async fn send(
        &self,
        ctx: &RequestContext,
        arn: &str,
        m: &mws_lambda::DestinationMessage,
    ) -> Result<(), mws_core::ServiceError> {
        use mws_core::Service;
        let attributes = message_attributes(m);
        match self {
            LambdaDestination::Sqs(sqs) => {
                let mut request = serde_json::json!({ "QueueUrl": queue_url(ctx, arn)?, "MessageBody": m.body });
                if !attributes.is_empty() {
                    request["MessageAttributes"] = serde_json::Value::Object(attributes);
                }
                sqs.invoke(ctx.clone(), "SendMessage", request).await.map(|_| ())
            }
            LambdaDestination::Sns(sns) => {
                let mut request = serde_json::json!({ "TopicArn": arn, "Message": m.body });
                if !attributes.is_empty() {
                    request["MessageAttributes"] = serde_json::Value::Object(attributes);
                }
                sns.invoke(ctx.clone(), "Publish", request).await.map(|_| ())
            }
            LambdaDestination::Events(events) => {
                let request = serde_json::json!({ "Entries": [{
                    "Source": "lambda",
                    "DetailType": m.detail_type,
                    "Detail": m.body,
                    "EventBusName": arn,
                    "Resources": [arn, m.function_arn],
                }]});
                let out = events.invoke(ctx.clone(), "PutEvents", request).await?;
                match out.get("FailedEntryCount").and_then(serde_json::Value::as_i64) {
                    Some(n) if n > 0 => {
                        let entry = &out["Entries"][0];
                        Err(mws_core::ServiceError::client(
                            entry["ErrorCode"].as_str().unwrap_or("InternalFailure").to_string(),
                            400,
                            entry["ErrorMessage"].as_str().unwrap_or("PutEvents failed").to_string(),
                        ))
                    }
                    _ => Ok(()),
                }
            }
        }
    }
}

/// Instance profiles for EC2: IAM resolves them, and instance metadata
/// hands out the role's credentials, assumed by `ec2.amazonaws.com` with the
/// instance id as the session name, as in AWS.
pub(crate) struct Ec2InstanceRoles {
    pub iam: mws_iam::Iam,
    pub sts: mws_sts::Sts,
}

impl mws_ec2::InstanceRoleCredentials for Ec2InstanceRoles {
    fn instance_profile(&self, account: &str, name_or_arn: &str) -> Option<mws_ec2::InstanceProfile> {
        let p = self.iam.instance_profile(account, name_or_arn)?;
        Some(mws_ec2::InstanceProfile { arn: p.arn, id: p.id, role_arn: p.role_arn })
    }

    fn credentials(
        &self,
        role_arn: &str,
        instance_arn: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<mws_ec2::RoleCredentials> {
        let instance_id = instance_arn.rsplit('/').next().unwrap_or(instance_arn);
        let account = instance_arn.split(':').nth(4);
        let c = self
            .sts
            .assume_role_as_service(&mws_sts::ServiceAssume {
                role_arn,
                service_principal: "ec2.amazonaws.com",
                session_name: instance_id,
                duration_seconds: 6 * 3600,
                source_account: account,
                source_arn: Some(instance_arn),
                now,
            })
            .ok()?;
        Some(mws_ec2::RoleCredentials {
            access_key_id: c.access_key_id,
            secret_access_key: c.secret_access_key,
            session_token: c.session_token,
            expiration: c.expiration,
        })
    }
}

/// CloudFormation service roles: the stack's `RoleARN`, assumed as
/// `cloudformation.amazonaws.com`.
pub struct CloudFormationRoles(pub mws_sts::Sts, pub mws_iam::Iam);

impl mws_cloudformation::RoleAssumer for CloudFormationRoles {
    fn assume(
        &self,
        role_arn: &str,
        session_name: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<mws_core::Caller, String> {
        let creds = self
            .0
            .assume_role_as_service(&mws_sts::ServiceAssume {
                role_arn,
                service_principal: "cloudformation.amazonaws.com",
                session_name,
                duration_seconds: 3600,
                source_account: role_arn.split(':').nth(4),
                source_arn: None,
                now,
            })
            .map_err(|_| format!("Role {role_arn} is invalid or cannot be assumed"))?;
        self.0
            .credential_store()
            .resolve(&creds.access_key_id, Some(&creds.session_token), now)
            .map_err(|e| format!("{e:?}"))?
            .map(|r| r.caller)
            .ok_or_else(|| format!("Role {role_arn} is invalid or cannot be assumed"))
    }

    fn resolve(
        &self,
        access_key_id: &str,
        session_token: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<mws_core::Caller> {
        self.0.credential_store().resolve(access_key_id, session_token, now).ok().flatten().map(|r| r.caller)
    }

    fn credentials(
        &self,
        role_arn: &str,
        service_principal: &str,
        session_name: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(String, String, String), String> {
        let creds = self
            .0
            .assume_role_as_service(&mws_sts::ServiceAssume {
                role_arn,
                service_principal,
                session_name,
                duration_seconds: 3600,
                source_account: role_arn.split(':').nth(4),
                source_arn: None,
                now,
            })
            .map_err(|_| format!("Role {role_arn} is invalid or cannot be assumed"))?;
        Ok((creds.access_key_id, creds.secret_access_key, creds.session_token))
    }

    fn registry_identity(
        &self,
        account: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(mws_core::Caller, String), String> {
        let role_arn = self.1.ensure_cloudformation_registry_role(account);
        let (key, _, token) =
            self.credentials(&role_arn, "resources.cloudformation.amazonaws.com", "CloudFormationRegistry", now)?;
        let caller = self
            .resolve(&key, Some(&token), now)
            .ok_or_else(|| format!("Registry handlers cannot run in account {account}"))?;
        Ok((caller, role_arn))
    }

    fn org_member(
        &self,
        member_account: &str,
        management_account: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<mws_core::Caller, String> {
        let role_arn = self.1.ensure_stacksets_execution_role(member_account, management_account);
        let creds = self
            .0
            .assume_role_as_service(&mws_sts::ServiceAssume {
                role_arn: &role_arn,
                service_principal: "member.org.stacksets.cloudformation.amazonaws.com",
                session_name: "AWSCloudFormation-StackSets",
                duration_seconds: 3600,
                source_account: Some(management_account),
                source_arn: None,
                now,
            })
            .map_err(|_| format!("Account {member_account} cannot be deployed to"))?;
        self.resolve(&creds.access_key_id, Some(&creds.session_token), now)
            .ok_or_else(|| format!("Account {member_account} cannot be deployed to"))
    }
}

/// Global Accelerator endpoints that live in EC2: instances, Elastic IP
/// addresses and (for custom routing) VPC subnets.
pub(crate) struct GlobalAcceleratorEc2(pub mws_ec2::Ec2);

impl GlobalAcceleratorEc2 {
    fn instance_health(&self, account: &str, region: &str, id: &str) -> mws_globalaccelerator::EndpointHealth {
        use mws_globalaccelerator::EndpointHealth;
        match self.0.instance_summary(account, region, id) {
            Some(i) if i.state == "running" => EndpointHealth::healthy(),
            Some(i) => EndpointHealth::unhealthy(format!("Instance {id} is {}.", i.state)),
            None => EndpointHealth::unhealthy(format!("Instance {id} no longer exists.")),
        }
    }
}

impl mws_globalaccelerator::EndpointDirectory for GlobalAcceleratorEc2 {
    fn endpoint(
        &self,
        account: &str,
        region: &str,
        id: &str,
    ) -> mws_globalaccelerator::Lookup<mws_globalaccelerator::EndpointHealth> {
        use mws_globalaccelerator::{EndpointHealth, Lookup};
        if id.starts_with("i-") {
            return match self.0.instance_summary(account, region, id) {
                None => Lookup::Missing,
                Some(i) if i.state == "terminated" => Lookup::Missing,
                Some(_) => Lookup::Found(self.instance_health(account, region, id)),
            };
        }
        if id.starts_with("eipalloc-") {
            return match self.0.address_summary(account, region, id) {
                None => Lookup::Missing,
                Some(a) => Lookup::Found(match (&a.instance_id, &a.network_interface_id) {
                    (Some(instance), _) => self.instance_health(account, region, instance),
                    (None, Some(_)) => EndpointHealth::healthy(),
                    (None, None) => EndpointHealth::unhealthy(format!(
                        "Elastic IP address {id} isn't associated with an instance or network interface."
                    )),
                }),
            };
        }
        Lookup::NotMine
    }

    fn subnet(&self, account: &str, region: &str, id: &str) -> mws_globalaccelerator::Lookup<String> {
        use mws_globalaccelerator::Lookup;
        match self.0.subnet_summary(account, region, id) {
            Some(s) => s.cidr_block.map(Lookup::Found).unwrap_or(Lookup::Missing),
            None => Lookup::Missing,
        }
    }
}

/// Private CA certificate authorities, shareable through AWS RAM: RAM's
/// policy for a shared CA becomes part of the CA's resource policy.
pub(crate) struct RamCertificateAuthorities(pub mws_acmpca::PrivateCa);

impl mws_ram::ShareableResourceType for RamCertificateAuthorities {
    fn resource_type(&self) -> &'static str {
        "acm-pca:CertificateAuthority"
    }

    fn service_name(&self) -> &'static str {
        "acm-pca"
    }

    fn matches(&self, arn: &str) -> bool {
        arn.split(':').nth(2) == Some("acm-pca") && arn.contains(":certificate-authority/")
    }

    fn locate(&self, arn: &str) -> Option<mws_ram::ResourceLocation> {
        let ca = self.0.ca_info(arn)?;
        Some(mws_ram::ResourceLocation { owner_account: ca.owner, region: arn.split(':').nth(3)?.to_string() })
    }

    fn set_shared_policy(&self, arn: &str, policy: Option<String>) {
        self.0.set_shared_policy(arn, policy);
    }

    fn shareable_actions(&self) -> &'static [&'static str] {
        &[
            "acm-pca:DescribeCertificateAuthority",
            "acm-pca:GetCertificate",
            "acm-pca:GetCertificateAuthorityCertificate",
            "acm-pca:IssueCertificate",
            "acm-pca:ListPermissions",
            "acm-pca:ListTags",
            "acm-pca:RevokeCertificate",
        ]
    }

    fn share_action(&self) -> &'static str {
        "acm-pca:PutPolicy"
    }
}

/// `PutPolicy` / `DeletePolicy` on a CA, mirrored as a RAM share created
/// from the policy.
pub(crate) struct CaPoliciesToRam(pub mws_ram::Ram);

impl mws_acmpca::CaPolicyListener for CaPoliciesToRam {
    fn policy_changed(
        &self,
        ca_arn: &str,
        owner_account: &str,
        policy: Option<&str>,
        now: chrono::DateTime<chrono::Utc>,
    ) {
        self.0.resource_policy_changed(ca_arn, owner_account, policy, now);
    }
}

/// Security Hub's view of AWS Organizations: the caller's organization and
/// the delegated administrator `EnableOrganizationAdminAccount` registers.
pub struct SecurityHubOrganizations(pub mws_organizations::Organizations);

const SECURITY_HUB_PRINCIPAL: &str = "securityhub.amazonaws.com";

impl mws_securityhub::OrganizationLink for SecurityHubOrganizations {
    fn organization(&self, account: &str) -> Option<mws_securityhub::OrgInfo> {
        let org = self.0.organization_of(account)?;
        Some(mws_securityhub::OrgInfo {
            id: org.id,
            management_account: org.management_account,
            accounts: org
                .accounts
                .into_iter()
                .map(|a| mws_securityhub::OrgAccount {
                    active: a.status == "ACTIVE",
                    id: a.id,
                    email: a.email,
                    path: a.path,
                })
                .collect(),
        })
    }

    fn register_delegated_administrator(&self, management: &str, admin: &str) -> Result<(), String> {
        use mws_organizations::DelegationError;
        self.0
            .register_delegated_administrator_for_service(management, admin, SECURITY_HUB_PRINCIPAL, chrono::Utc::now())
            .map_err(|e| match e {
                DelegationError::NotManagementAccount => {
                    "The request must be made by the management account of an organization.".to_string()
                }
                DelegationError::AccountNotInOrganization => {
                    format!("Account {admin} is not a member of the organization.")
                }
                DelegationError::ManagementAccount => {
                    "The management account cannot be the delegated administrator for Security Hub.".to_string()
                }
                DelegationError::NotAllFeatures => "The organization must have all features enabled.".to_string(),
            })
    }

    fn deregister_delegated_administrator(&self, management: &str, admin: &str) {
        let _ = self.0.deregister_delegated_administrator_for_service(management, admin, SECURITY_HUB_PRINCIPAL);
    }
}

/// Security Hub finding events, sent to the account's default event bus
/// with source `aws.securityhub`.
pub struct SecurityHubToEvents(pub mws_events::Events);

impl mws_securityhub::FindingEventSink for SecurityHubToEvents {
    fn finding_event(&self, ctx: &RequestContext, e: mws_securityhub::FindingEvent) {
        self.0.put_service_event(
            ctx,
            mws_events::ServiceEvent {
                partition: e.partition,
                account: e.account,
                region: e.region,
                source: "aws.securityhub".into(),
                detail_type: e.detail_type,
                resources: e.resources,
                detail: e.detail,
                time: e.time,
            },
        );
    }
}

/// RDS placing subnet groups and security groups in EC2's VPCs.
pub(crate) struct RdsNetwork(pub mws_ec2::Ec2);

impl RdsNetwork {
    fn subnet(s: mws_ec2::SubnetInfo) -> mws_rds::Subnet {
        mws_rds::Subnet { subnet_id: s.subnet_id, vpc_id: s.vpc_id, availability_zone: s.availability_zone }
    }
}

impl mws_rds::Network for RdsNetwork {
    fn subnets(&self, ctx: &RequestContext, ids: &[String]) -> Vec<mws_rds::Subnet> {
        let account = &ctx.caller.account_id;
        ids.iter().filter_map(|id| self.0.subnet_info(ctx, account, id)).map(Self::subnet).collect()
    }

    fn default_subnets(&self, ctx: &RequestContext) -> Vec<mws_rds::Subnet> {
        self.0.subnets_of_vpc(ctx, &ctx.caller.account_id, None).into_iter().map(Self::subnet).collect()
    }

    fn security_group_vpc(&self, ctx: &RequestContext, group_id: &str) -> Option<String> {
        self.0.security_group_info(ctx, &ctx.caller.account_id, group_id).map(|g| g.vpc_id)
    }

    fn default_security_group(&self, ctx: &RequestContext, vpc_id: &str) -> Option<String> {
        self.0.vpc_info(ctx, &ctx.caller.account_id, Some(vpc_id)).and_then(|v| v.default_security_group)
    }
}

/// RDS events on the default event bus, and event subscriptions'
/// notifications published to SNS as `events.rds.amazonaws.com` (the topic
/// policy must allow it, with the event's source as `aws:SourceArn`).
pub(crate) struct RdsEvents {
    pub events: mws_events::Events,
    pub sns: mws_sns::Sns,
}

impl RdsEvents {
    fn publish<'a>(
        topic_arn: &'a str,
        source_arn: &'a str,
        account: &'a str,
        subject: &str,
        message: &str,
    ) -> mws_sns::ServicePublish<'a> {
        mws_sns::ServicePublish {
            topic_arn,
            service_principal: "events.rds.amazonaws.com",
            source_arn,
            source_account: account,
            message: message.to_string(),
            subject: Some(subject.to_string()),
            attributes: Default::default(),
            message_group_id: None,
            message_deduplication_id: None,
        }
    }

    fn source_arn(ctx: &RequestContext, account: &str) -> String {
        format!("arn:{}:rds:{}:{account}:es:*", ctx.partition, ctx.region)
    }
}

impl mws_rds::EventSink for RdsEvents {
    fn check_topic(&self, ctx: &RequestContext, topic_arn: &str) -> Result<(), String> {
        let account = ctx.caller.account_id.clone();
        let source = Self::source_arn(ctx, &account);
        // The policy is checked per event (its conditions usually name the
        // event's source), so only the topic's existence is checked here.
        match self.sns.check_service_publish(&Self::publish(topic_arn, &source, &account, "", "")) {
            Ok(()) | Err(mws_sns::ServicePublishError::AccessDenied) => Ok(()),
            Err(mws_sns::ServicePublishError::NoSuchTopic) => Err("SNSTopicArnNotFound".into()),
            Err(_) => Err("SNSInvalidTopic".into()),
        }
    }

    fn notify_topic(&self, ctx: &RequestContext, topic_arn: &str, source_arn: &str, subject: &str, message: &str) {
        let account = source_arn.split(':').nth(4).unwrap_or_default().to_string();
        if let Err(e) =
            self.sns.publish_as_service(ctx, &Self::publish(topic_arn, source_arn, &account, subject, message))
        {
            tracing::debug!(topic = topic_arn, "RDS event notification not delivered: {e:?}");
        }
    }

    fn put_event(&self, ctx: &RequestContext, e: &mws_rds::RdsEvent) {
        let (detail_type, source_type) = match e.source_type.as_str() {
            "db-cluster" => ("RDS DB Cluster Event", "CLUSTER"),
            "db-snapshot" => ("RDS DB Snapshot Event", "SNAPSHOT"),
            "db-cluster-snapshot" => ("RDS DB Cluster Snapshot Event", "CLUSTER_SNAPSHOT"),
            "db-parameter-group" => ("RDS DB Parameter Group Event", "DB_PARAM"),
            "db-security-group" => ("RDS DB Security Group Event", "SECURITY_GROUP"),
            _ => ("RDS DB Instance Event", "DB_INSTANCE"),
        };
        let detail = serde_json::json!({
            "EventCategories": e.categories,
            "SourceType": source_type,
            "SourceArn": e.source_arn,
            "Date": e.time.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "Message": e.message,
            "SourceIdentifier": e.source_identifier,
            "EventID": e.event_id,
        });
        self.events.put_service_event(
            ctx,
            mws_events::ServiceEvent {
                partition: ctx.partition.clone(),
                account: e.account.clone(),
                region: e.region.clone(),
                source: "aws.rds".into(),
                detail_type: detail_type.into(),
                resources: vec![e.source_arn.clone()],
                detail,
                time: e.time,
            },
        );
    }
}

/// Security Hub V2 export jobs, written to S3 as
/// `securityhub.amazonaws.com` (encrypted with the job's KMS key).
pub struct SecurityHubExports(pub mws_s3::S3);

impl mws_securityhub::ExportSink for SecurityHubExports {
    fn put_object(
        &self,
        ctx: &RequestContext,
        bucket: &str,
        key: &str,
        body: Vec<u8>,
        kms_key_arn: Option<&str>,
    ) -> Result<(), String> {
        let account = &ctx.caller.account_id;
        let source_arn = format!("arn:{}:securityhub:{}:{account}:hubv2/default", ctx.partition, ctx.region);
        let put = mws_s3::ServicePutObject {
            bucket,
            key,
            body,
            content_type: "application/json",
            service_principal: SECURITY_HUB_PRINCIPAL,
            source_account: account,
            source_arn: &source_arn,
            acl: Some("bucket-owner-full-control"),
            partition: &ctx.partition,
        };
        match kms_key_arn.filter(|k| !k.is_empty()) {
            Some(k) => self.0.put_object_as_service_kms(put, k).map(|_| ()),
            None => self.0.put_object_as_service(put).map(|_| ()).map_err(|e| e.to_string()),
        }
    }
}

/// GuardDuty's view of AWS Organizations: accounts, and delegated
/// administration registered with the caller's permissions.
pub(crate) struct GuardDutyOrganizations(pub mws_organizations::Organizations);

impl mws_guardduty::OrganizationLink for GuardDutyOrganizations {
    fn organization(&self, account: &str) -> Option<mws_guardduty::OrgInfo> {
        let o = self.0.organization_of(account)?;
        Some(mws_guardduty::OrgInfo {
            id: o.id,
            management_account: o.management_account,
            accounts: o
                .accounts
                .into_iter()
                .map(|a| mws_guardduty::OrgAccount { id: a.id, email: a.email, joined: a.joined, status: a.status })
                .collect(),
        })
    }

    fn register_admin(&self, ctx: &RequestContext, admin: &str) -> Result<(), mws_core::ServiceError> {
        // AWS makes these Organizations calls with the caller's credentials.
        for action in ["organizations:EnableAWSServiceAccess", "organizations:RegisterDelegatedAdministrator"] {
            ctx.authorize(action, "*", mws_core::ConditionContext::new())?;
        }
        self.0
            .register_delegated_administrator_for_service(
                &ctx.caller.account_id,
                admin,
                mws_guardduty::SERVICE_PRINCIPAL,
                chrono::Utc::now(),
            )
            .map_err(guardduty_delegation_error)
    }

    fn deregister_admin(&self, ctx: &RequestContext, admin: &str) -> Result<(), mws_core::ServiceError> {
        ctx.authorize("organizations:DeregisterDelegatedAdministrator", "*", mws_core::ConditionContext::new())?;
        self.0
            .deregister_delegated_administrator_for_service(
                &ctx.caller.account_id,
                admin,
                mws_guardduty::SERVICE_PRINCIPAL,
            )
            .map_err(guardduty_delegation_error)
    }
}

fn guardduty_delegation_error(e: mws_organizations::DelegationError) -> mws_core::ServiceError {
    use mws_organizations::DelegationError;
    let message = match e {
        DelegationError::NotManagementAccount => "the caller is not the management account of an organization",
        DelegationError::AccountNotInOrganization => "the account is not a member of the organization",
        DelegationError::ManagementAccount => "the management account cannot be a delegated administrator",
        DelegationError::NotAllFeatures => "the organization does not have all features enabled",
    };
    mws_core::ServiceError::client("BadRequestException", 400, message)
}

/// GuardDuty publishing destinations: findings exported into S3 as
/// `guardduty.amazonaws.com`, SSE-KMS under the destination's key.
pub(crate) struct GuardDutyToS3(pub mws_s3::S3);

impl mws_guardduty::FindingExporter for GuardDutyToS3 {
    fn export(&self, _ctx: &RequestContext, e: mws_guardduty::FindingExport) -> Result<(), String> {
        let path = e.destination_arn.rsplit(":::").next().unwrap_or_default();
        let (bucket, prefix) = path.split_once('/').unwrap_or((path, ""));
        let key = match prefix.trim_end_matches('/') {
            "" => e.key.clone(),
            p => format!("{p}/{}", e.key),
        };
        let put = mws_s3::ServicePutObject {
            bucket,
            key: &key,
            body: e.body,
            content_type: "application/octet-stream",
            service_principal: mws_guardduty::SERVICE_PRINCIPAL,
            source_account: &e.account,
            source_arn: &e.detector_arn,
            acl: None,
            partition: &e.partition,
        };
        self.0.put_object_as_service_kms(put, &e.kms_key_arn).map(|_| ()).map_err(|err| err.to_string())
    }
}

/// GuardDuty findings imported into Security Hub as product `aws/guardduty`.
pub(crate) struct GuardDutyToSecurityHub(pub mws_securityhub::SecurityHub);

impl mws_guardduty::SecurityHubSink for GuardDutyToSecurityHub {
    fn import_findings(&self, ctx: &RequestContext, account: &str, region: &str, findings: Vec<serde_json::Value>) {
        let r = self.0.import_findings_as_service(
            ctx,
            account,
            region,
            "aws/guardduty",
            mws_guardduty::SERVICE_PRINCIPAL,
            findings,
        );
        for (id, code, message) in r.failed {
            tracing::debug!(%id, %code, %message, "Security Hub rejected a GuardDuty finding");
        }
    }
}

/// Route 53 alias records that target an accelerator's DNS name answer with
/// its static IP addresses.
pub(crate) struct Route53ToGlobalAccelerator(pub mws_globalaccelerator::GlobalAccelerator);

/// The hosted zone of every accelerator's DNS names.
const GLOBAL_ACCELERATOR_ZONE: &str = "Z2BJ6XQ5FK7U4H";

impl mws_route53::AliasTargetResolver for Route53ToGlobalAccelerator {
    fn resolve(&self, hosted_zone_id: &str, dns_name: &str, record_type: &str) -> Option<Vec<String>> {
        if hosted_zone_id != GLOBAL_ACCELERATOR_ZONE {
            return None;
        }
        let a = self.0.addresses_for_dns_name(dns_name)?;
        match record_type {
            "A" => Some(a.ipv4),
            "AAAA" => Some(a.ipv6),
            _ => Some(Vec::new()),
        }
    }
}

/// ELB's `AWS/ApplicationELB`, `AWS/NetworkELB`, `AWS/GatewayELB` and
/// `AWS/ELB` metrics.
pub struct ElbToCloudWatch(pub mws_cloudwatch::CloudWatch);

impl mws_elb::MetricSink for ElbToCloudWatch {
    fn publish(&self, metrics: Vec<mws_elb::ElbMetric>) {
        for m in metrics {
            self.0.put_metric_as_service(mws_cloudwatch::ServiceMetric {
                account: m.account,
                region: m.region,
                namespace: m.namespace.into(),
                metric_name: m.metric_name.into(),
                dimensions: m.dimensions,
                unit: Some(m.unit.into()),
                timestamp: m.timestamp,
                values: vec![(m.value, 1.0)],
            });
        }
    }
}

/// Global Accelerator endpoints that are Application or Network Load
/// Balancers: they must exist, and they are healthy while active with at
/// least one healthy target, as Global Accelerator judges them.
pub(crate) struct GlobalAcceleratorElb(pub mws_elb::Elb);

impl mws_globalaccelerator::EndpointDirectory for GlobalAcceleratorElb {
    fn endpoint(
        &self,
        account: &str,
        region: &str,
        id: &str,
    ) -> mws_globalaccelerator::Lookup<mws_globalaccelerator::EndpointHealth> {
        use mws_globalaccelerator::{EndpointHealth, Lookup};
        if !id.contains(":elasticloadbalancing:") {
            return Lookup::NotMine;
        }
        let Some(lb) = self.0.load_balancer(account, region, id) else { return Lookup::Missing };
        Lookup::Found(if !lb.state.starts_with("active") {
            EndpointHealth::unhealthy(format!("Load balancer {} is {}.", lb.name, lb.state))
        } else if lb.healthy_targets == 0 {
            EndpointHealth::unhealthy(format!("Load balancer {} has no healthy targets.", lb.name))
        } else {
            EndpointHealth::healthy()
        })
    }
}

/// RDS snapshot exports, written to S3 as the export's role (assumed as
/// `export.rds.amazonaws.com`) with SSE-KMS.
pub(crate) struct RdsExports {
    pub sts: mws_sts::Sts,
    pub s3: mws_s3::S3,
}

/// Roles RDS assumes itself (Enhanced Monitoring), checked against
/// their trust policies.
pub(crate) struct RdsRoles(pub mws_sts::Sts);

impl mws_rds::ServiceRoles for RdsRoles {
    fn can_assume(&self, ctx: &RequestContext, role_arn: &str, service_principal: &str, source_arn: &str) -> bool {
        self.0
            .service_can_assume(&mws_sts::ServiceAssume {
                role_arn,
                service_principal,
                session_name: "rds",
                duration_seconds: 3600,
                source_account: Some(&ctx.caller.account_id),
                source_arn: Some(source_arn),
                now: ctx.received_at,
            })
            .is_ok()
    }
}

#[async_trait::async_trait]
impl mws_rds::ExportStore for RdsExports {
    fn assume(&self, ctx: &RequestContext, role_arn: &str, source_arn: &str) -> Result<RequestContext, String> {
        let creds = self
            .sts
            .assume_role_as_service(&mws_sts::ServiceAssume {
                role_arn,
                service_principal: "export.rds.amazonaws.com",
                session_name: "rds-export",
                duration_seconds: 3600,
                source_account: Some(&ctx.caller.account_id),
                source_arn: Some(source_arn),
                now: ctx.received_at,
            })
            .map_err(|e| format!("{e:?}"))?;
        let resolved = self
            .sts
            .credential_store()
            .resolve(&creds.access_key_id, Some(&creds.session_token), ctx.received_at)
            .map_err(|e| format!("{e:?}"))?
            .ok_or_else(|| "the role session could not be resolved".to_string())?;
        Ok(RequestContext { caller: resolved.caller, source_ip: None, ..ctx.clone() })
    }

    async fn put_object(
        &self,
        role: &RequestContext,
        bucket: &str,
        key: &str,
        body: Vec<u8>,
        kms_key: &str,
    ) -> Result<(), String> {
        use base64::Engine as _;
        let request = serde_json::json!({
            "Bucket": bucket,
            "Key": key,
            "Body": base64::engine::general_purpose::STANDARD.encode(&body),
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": kms_key,
        });
        mws_core::Service::invoke(&self.s3, role.clone(), "PutObject", request)
            .await
            .map(|_| ())
            .map_err(|e| format!("{}: {}", e.code, e.message))
    }
}

/// Lambda container images come from ECR. Resolving one at
/// `CreateFunction`/`UpdateFunctionCode` is a pull by the caller; starting
/// an execution environment fetches the resolved digest as Lambda.
pub struct LambdaImages(pub mws_ecr::Ecr);

impl LambdaImages {
    fn convert(&self, image: mws_ecr::PulledImage) -> mws_lambda::ContainerImage {
        let blob = |d: &mws_oci::Descriptor, data: bytes::Bytes| mws_lambda::ImageBlob {
            digest: d.digest.clone(),
            media_type: d.media_type.clone(),
            data,
        };
        mws_lambda::ContainerImage {
            resolved_uri: self.0.image_uri(&image.location, &image.resolved_digest),
            resolved_digest: image.resolved_digest,
            digest: image.digest,
            manifest: bytes::Bytes::from(image.manifest.into_bytes()),
            manifest_media_type: image.media_type,
            config: blob(&image.config, image.config_data),
            layers: image.layers.into_iter().map(|(d, data)| blob(&d, data)).collect(),
        }
    }
}

impl mws_lambda::ImageSource for LambdaImages {
    fn resolve(
        &self,
        ctx: &RequestContext,
        uri: &str,
        architecture: &str,
    ) -> Result<mws_lambda::ContainerImage, mws_lambda::ImageError> {
        let location =
            self.0.locate_image(uri, &ctx.caller.account_id, &ctx.region).ok_or(mws_lambda::ImageError::Invalid)?;
        match self.0.pull_image(Some(ctx), &location, architecture) {
            Ok(image) => Ok(self.convert(image)),
            Err(mws_ecr::PullError::NotFound) => Err(mws_lambda::ImageError::NotFound),
            Err(mws_ecr::PullError::AccessDenied) => Err(mws_lambda::ImageError::AccessDenied),
            Err(mws_ecr::PullError::Unsupported) => Err(mws_lambda::ImageError::Unsupported),
        }
    }

    fn fetch(
        &self,
        account: &str,
        region: &str,
        resolved_uri: &str,
        architecture: &str,
    ) -> Option<mws_lambda::ContainerImage> {
        let location = self.0.locate_image(resolved_uri, account, region)?;
        self.0.pull_image(None, &location, architecture).ok().map(|i| self.convert(i))
    }
}

/// Usage of the quotas other services enforce, for Service Quotas.
pub struct QuotaUsage {
    pub ec2: mws_ec2::Ec2,
    pub s3: mws_s3::S3,
    pub iam: mws_iam::Iam,
}

impl mws_servicequotas::UsageSource for QuotaUsage {
    fn usage(&self, account: &str, region: &str, service: &str, code: &str) -> Option<f64> {
        match (service, code) {
            ("s3", "L-DC2B2D3D") => Some(self.s3.bucket_count(account) as f64),
            ("iam", "L-FE177D64") => Some(self.iam.role_count(account) as f64),
            ("ec2" | "vpc", _) => self.ec2.quota_usage(account, region, service, code),
            _ => None,
        }
    }
}

/// Service Quotas publishing `AWS/Usage` metrics into CloudWatch.
pub struct UsageToCloudWatch(pub mws_cloudwatch::CloudWatch);

impl mws_servicequotas::MetricPublisher for UsageToCloudWatch {
    fn publish(&self, data: Vec<mws_servicequotas::UsageDatum>) {
        for d in data {
            self.0.put_metric_as_service(mws_cloudwatch::ServiceMetric {
                account: d.account,
                region: d.region,
                namespace: d.namespace,
                metric_name: d.metric_name,
                dimensions: d.dimensions,
                unit: Some(d.unit),
                timestamp: d.timestamp,
                values: vec![(d.value, 1.0)],
            });
        }
    }
}

/// Organizations as Service Quotas sees it (quota request templates).
pub struct QuotaOrganizations(pub mws_organizations::Organizations);

impl mws_servicequotas::OrganizationDirectory for QuotaOrganizations {
    fn account(&self, account_id: &str) -> Option<mws_servicequotas::OrgAccount> {
        let m = self.0.member_account(account_id)?;
        Some(mws_servicequotas::OrgAccount {
            management_account_id: m.management_account_id,
            all_features: m.all_features,
            joined_method: m.joined_method,
            joined: m.joined,
        })
    }
}

/// Consolidated billing and account names for Cost Explorer.
pub struct CostAccounts(pub mws_organizations::Organizations);

impl mws_ce::AccountDirectory for CostAccounts {
    fn payer(&self, account: &str) -> Option<String> {
        self.0.member_account(account).map(|m| m.management_account_id)
    }

    fn name(&self, account: &str) -> Option<String> {
        self.0.member_account(account).map(|m| m.name).filter(|n| !n.is_empty())
    }
}

/// Cost anomaly alerts, published by `costalerts.amazonaws.com`.
pub struct AnomalyAlerts(pub mws_sns::Sns);

impl mws_ce::AnomalyNotifier for AnomalyAlerts {
    fn notify(&self, ctx: &RequestContext, alert: mws_ce::AnomalyAlert) -> Result<(), String> {
        self.0
            .publish_as_service(
                ctx,
                &mws_sns::ServicePublish {
                    topic_arn: &alert.topic_arn,
                    service_principal: "costalerts.amazonaws.com",
                    source_arn: &alert.subscription_arn,
                    source_account: &alert.account,
                    message: alert.message,
                    subject: Some(alert.subject),
                    attributes: Default::default(),
                    message_group_id: None,
                    message_deduplication_id: None,
                },
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

/// ElastiCache subnet groups and security groups, read from EC2.
pub(crate) struct ElastiCacheNetwork {
    pub ec2: mws_ec2::Ec2,
    pub partition: String,
}

fn subnet_info(s: mws_ec2::network::SubnetView) -> mws_elasticache::SubnetInfo {
    mws_elasticache::SubnetInfo {
        subnet_id: s.subnet_id,
        vpc_id: s.vpc_id,
        availability_zone: s.availability_zone,
        ipv6: s.ipv6,
    }
}

impl mws_elasticache::NetworkView for ElastiCacheNetwork {
    fn subnet(&self, account: &str, region: &str, subnet_id: &str) -> Option<mws_elasticache::SubnetInfo> {
        self.ec2.subnet_view(account, region, &self.partition, subnet_id).map(subnet_info)
    }
    fn default_subnets(&self, account: &str, region: &str) -> Vec<mws_elasticache::SubnetInfo> {
        self.ec2.default_subnet_views(account, region, &self.partition).into_iter().map(subnet_info).collect()
    }
    fn security_group_vpc(&self, account: &str, region: &str, group_id: &str) -> Option<String> {
        self.ec2.security_group_vpc(account, region, &self.partition, group_id)
    }
    fn default_security_group(&self, account: &str, region: &str, vpc_id: &str) -> Option<String> {
        self.ec2.default_security_group(account, region, &self.partition, vpc_id)
    }
    fn docker_network(&self, vpc_id: &str) -> Option<String> {
        Some(mws_ec2::network::docker_network_name(vpc_id))
    }
}

/// ElastiCache snapshot exports to, and seeds from, S3, as
/// `elasticache.amazonaws.com`.
pub(crate) struct ElastiCacheSnapshots(pub mws_s3::S3);

impl mws_elasticache::SnapshotBucket for ElastiCacheSnapshots {
    fn export(
        &self,
        ctx: &RequestContext,
        bucket: &str,
        key: &str,
        body: Vec<u8>,
        source_arn: &str,
    ) -> Result<(), mws_core::ServiceError> {
        let account = source_arn.split(':').nth(4).unwrap_or_default();
        let put = mws_s3::ServicePutObject {
            bucket,
            key,
            body,
            content_type: "application/octet-stream",
            service_principal: "elasticache.amazonaws.com",
            source_account: account,
            source_arn,
            acl: None,
            partition: &ctx.partition,
        };
        let invalid =
            |m: String| mws_core::ServiceError::new("InvalidParameterValue", 400, mws_core::ErrorFault::Client, m);
        match self.0.put_object_as_service(put) {
            Ok(_) => Ok(()),
            Err(mws_s3::ServicePutError::NoSuchBucket) => Err(invalid(format!("The S3 bucket {bucket} does not exist."))),
            Err(mws_s3::ServicePutError::AccessDenied { .. }) => Err(invalid(format!(
                "No permission to access S3 bucket {bucket}: grant elasticache.amazonaws.com s3:PutObject in the bucket policy."
            ))),
            Err(e) => Err(invalid(format!("Could not write to S3 bucket {bucket}: {e}"))),
        }
    }

    fn read(&self, s3_arn: &str) -> Option<Vec<u8>> {
        let path = s3_arn.split(":::").nth(1)?;
        let (bucket, key) = path.split_once('/')?;
        self.0.object_bytes(bucket, key)
    }
}

/// ElastiCache event notifications, published to SNS as
/// `elasticache.amazonaws.com`.
pub(crate) struct ElastiCacheNotifications(pub mws_sns::Sns);

impl mws_elasticache::EventNotifier for ElastiCacheNotifications {
    fn notify(&self, ctx: &RequestContext, topic_arn: &str, source_arn: &str, message: &str) {
        let id = source_arn.rsplit(':').next().unwrap_or_default();
        let account = source_arn.split(':').nth(4).unwrap_or_default();
        let body = serde_json::json!({ message: id }).to_string();
        let p = mws_sns::ServicePublish {
            topic_arn,
            service_principal: "elasticache.amazonaws.com",
            source_arn,
            source_account: account,
            message: body,
            subject: Some(message.to_string()),
            attributes: Default::default(),
            message_group_id: None,
            message_deduplication_id: None,
        };
        if let Err(e) = self.0.publish_as_service(ctx, &p) {
            tracing::debug!("ElastiCache notification to {topic_arn}: {e}");
        }
    }
}

/// ElastiCache publishes its `AWS/ElastiCache` metrics into CloudWatch.
pub struct ElastiCacheToCloudWatch(pub mws_cloudwatch::CloudWatch);

impl mws_elasticache::MetricPublisher for ElastiCacheToCloudWatch {
    fn publish(&self, metrics: Vec<mws_elasticache::CacheMetric>) {
        for m in metrics {
            let Some(timestamp) = chrono::DateTime::from_timestamp_millis(m.timestamp) else { continue };
            self.0.put_metric_as_service(mws_cloudwatch::ServiceMetric {
                account: m.account,
                region: m.region,
                namespace: "AWS/ElastiCache".into(),
                metric_name: m.metric_name.into(),
                dimensions: m.dimensions,
                unit: Some(m.unit.into()),
                timestamp,
                values: vec![(m.value, 1.0)],
            });
        }
    }
}

/// What ECS tasks get from other services: EC2 network interfaces for
/// `awsvpc` tasks, task and execution role sessions from STS, container
/// secrets from Secrets Manager and Parameter Store, and `awslogs` output in
/// CloudWatch Logs.
pub(crate) struct EcsPlatform {
    pub ec2: mws_ec2::Ec2,
    pub sts: mws_sts::Sts,
    pub secretsmanager: mws_secretsmanager::SecretsManager,
    pub ssm: mws_ssm::Ssm,
    pub logs: mws_logs::Logs,
    pub elb: mws_elb::Elb,
    pub autoscaling: mws_autoscaling::AutoScaling,
    pub ecr: mws_ecr::Ecr,
}

impl EcsPlatform {
    /// ECS acting through its service-linked role: no caller policy applies.
    fn service_linked(ctx: &RequestContext) -> RequestContext {
        RequestContext { authorizer: std::sync::Arc::new(mws_core::AllowAll), ..ctx.clone() }
    }
}

#[async_trait::async_trait]
impl mws_ecs::TaskPlatform for EcsPlatform {
    fn create_interface(
        &self,
        ctx: &RequestContext,
        account: &str,
        subnets: &[String],
        security_groups: &[String],
        assign_public_ip: bool,
        description: &str,
    ) -> Result<mws_ecs::platform::TaskInterface, mws_core::ServiceError> {
        let subnet = subnets.first().cloned().unwrap_or_default();
        let i = self.ec2.create_task_interface(
            ctx,
            account,
            &subnet,
            security_groups,
            assign_public_ip,
            description,
            "ecs.amazonaws.com",
        )?;
        Ok(mws_ecs::platform::TaskInterface {
            eni_id: i.eni_id,
            private_ip: i.private_ip,
            mac_address: i.mac_address,
            private_dns_name: i.private_dns_name,
            subnet_id: i.subnet_id,
            vpc_id: i.vpc_id,
            vpc_cidr: i.vpc_cidr,
            availability_zone: i.availability_zone,
        })
    }

    fn delete_interface(&self, ctx: &RequestContext, account: &str, eni_id: &str) {
        self.ec2.delete_task_interface(ctx, account, eni_id);
    }

    fn assume_task_role(
        &self,
        role_arn: &str,
        task_arn: &str,
        account: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<mws_ecs::platform::RoleCredentials, String> {
        let task_id = task_arn.rsplit('/').next().unwrap_or(task_arn);
        let c = self
            .sts
            .assume_role_as_service(&mws_sts::ServiceAssume {
                role_arn,
                service_principal: "ecs-tasks.amazonaws.com",
                session_name: task_id,
                duration_seconds: 6 * 3600,
                source_account: Some(account),
                source_arn: Some(task_arn),
                now,
            })
            .map_err(|e| match e {
                mws_sts::ServiceAssumeError::NoSuchRole => format!("role {role_arn} does not exist"),
                mws_sts::ServiceAssumeError::NotTrusted => {
                    format!("ECS was unable to assume the role '{role_arn}' that was provided for this task.")
                }
            })?;
        Ok(mws_ecs::platform::RoleCredentials {
            access_key_id: c.access_key_id,
            secret_access_key: c.secret_access_key,
            session_token: c.session_token,
            expiration: c.expiration,
        })
    }

    fn role_context(
        &self,
        base: &RequestContext,
        credentials: &mws_ecs::platform::RoleCredentials,
    ) -> Option<RequestContext> {
        let resolved = self
            .sts
            .credential_store()
            .resolve(&credentials.access_key_id, Some(&credentials.session_token), base.received_at)
            .ok()
            .flatten()?;
        Some(RequestContext { caller: resolved.caller, source_ip: None, ..base.clone() })
    }

    async fn read_secret(&self, ctx: &RequestContext, value_from: &str) -> Result<String, mws_core::ServiceError> {
        if value_from.contains(":secretsmanager:") {
            // arn:aws:secretsmanager:region:account:secret:name[:json-key[:version-stage[:version-id]]]
            let parts: Vec<&str> = value_from.split(':').collect();
            let arn = parts.iter().take(7).copied().collect::<Vec<_>>().join(":");
            let key = parts.get(7).filter(|k| !k.is_empty());
            let stage = parts.get(8).filter(|k| !k.is_empty());
            let version = parts.get(9).filter(|k| !k.is_empty());
            let s = self.secretsmanager.read_for_reference(ctx, &arn, version.or(stage).copied())?;
            return match key {
                None => Ok(s.secret_string),
                Some(k) => {
                    let v: serde_json::Value = serde_json::from_str(&s.secret_string).map_err(|_| {
                        mws_core::ServiceError::new(
                            "InvalidParameterException",
                            400,
                            mws_core::ErrorFault::Client,
                            "The secret value is not valid JSON.",
                        )
                    })?;
                    match v.get(*k) {
                        Some(serde_json::Value::String(s)) => Ok(s.clone()),
                        Some(other) => Ok(other.to_string()),
                        None => Err(mws_core::ServiceError::new(
                            "ResourceNotFoundException",
                            400,
                            mws_core::ErrorFault::Client,
                            format!("The JSON key {k} was not found in the secret."),
                        )),
                    }
                }
            };
        }
        // A parameter name, or arn:aws:ssm:region:account:parameter/name.
        let name = match value_from.split_once(":parameter") {
            Some((_, rest)) if value_from.starts_with("arn:") => rest.to_string(),
            _ => value_from.to_string(),
        };
        let out = mws_core::Service::invoke(
            &self.ssm,
            ctx.clone(),
            "GetParameter",
            serde_json::json!({ "Name": name, "WithDecryption": true }),
        )
        .await?;
        Ok(out["Parameter"]["Value"].as_str().unwrap_or_default().to_string())
    }

    fn write_logs(
        &self,
        ctx: &RequestContext,
        log_group: &str,
        log_stream: &str,
        create_group: bool,
        events: Vec<mws_ecs::platform::LogEvent>,
    ) -> Result<(), mws_core::ServiceError> {
        let events = events
            .into_iter()
            .map(|e| mws_logs::ServiceLogEvent { timestamp: e.timestamp_ms, message: e.message })
            .collect();
        if create_group {
            return self.logs.put_log_events_as_caller(ctx, log_group, log_stream, events);
        }
        // Without awslogs-create-group, a missing group fails the write.
        self.logs.put_log_events_as_caller_existing_group(ctx, log_group, log_stream, events)
    }

    fn default_subnets(&self, ctx: &RequestContext, account: &str) -> Vec<String> {
        self.ec2.default_subnets(ctx, account)
    }

    async fn update_targets(
        &self,
        ctx: &RequestContext,
        target_group_arn: &str,
        targets: &[(String, i32)],
        register: bool,
    ) -> Result<(), mws_core::ServiceError> {
        let op = if register { "RegisterTargets" } else { "DeregisterTargets" };
        let request = serde_json::json!({
            "TargetGroupArn": target_group_arn,
            "Targets": targets.iter().map(|(id, port)| serde_json::json!({"Id": id, "Port": port})).collect::<Vec<_>>(),
        });
        mws_core::Service::invoke(&self.elb, Self::service_linked(ctx), op, request).await.map(|_| ())
    }

    async fn target_group(
        &self,
        ctx: &RequestContext,
        target_group_arn: &str,
    ) -> Option<mws_ecs::platform::TargetGroupInfo> {
        let out = mws_core::Service::invoke(
            &self.elb,
            Self::service_linked(ctx),
            "DescribeTargetGroups",
            serde_json::json!({ "TargetGroupArns": [target_group_arn] }),
        )
        .await
        .ok()?;
        let g = out.pointer("/TargetGroups/0")?;
        Some(mws_ecs::platform::TargetGroupInfo {
            target_group_arn: target_group_arn.to_string(),
            target_type: g["TargetType"].as_str().unwrap_or("instance").to_string(),
            load_balancer_arns: g["LoadBalancerArns"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str().map(String::from))
                .collect(),
        })
    }

    fn is_registry_image(&self, image: &str, account: &str, region: &str) -> bool {
        self.ecr.locate_image(image, account, region).is_some()
    }

    fn pull_registry_image(
        &self,
        ctx: Option<&RequestContext>,
        image: &str,
        account: &str,
        region: &str,
        architecture: &str,
    ) -> Result<mws_ecs::platform::RegistryImage, mws_ecs::platform::RegistryPullError> {
        use mws_ecs::platform::RegistryPullError as E;
        let location = self.ecr.locate_image(image, account, region).ok_or(E::NotFound)?;
        if let Some(ctx) = ctx {
            self.ecr.authorize_registry_login(ctx).map_err(E::Auth)?;
        }
        let pulled = self.ecr.pull_image(ctx, &location, architecture).map_err(|e| match e {
            mws_ecr::PullError::NotFound => E::NotFound,
            mws_ecr::PullError::AccessDenied => E::Denied,
            mws_ecr::PullError::Unsupported => E::Unsupported,
        })?;
        Ok(mws_ecs::platform::RegistryImage {
            resolved_digest: pulled.resolved_digest,
            digest: pulled.digest,
            manifest: bytes::Bytes::from(pulled.manifest.into_bytes()),
            manifest_media_type: pulled.media_type,
            config_digest: pulled.config.digest.clone(),
            config: pulled.config_data,
            layers: pulled.layers.into_iter().map(|(d, data)| (d.digest, data)).collect(),
        })
    }

    async fn target_health(&self, ctx: &RequestContext, target_group_arn: &str, id: &str, port: i32) -> Option<String> {
        let request = serde_json::json!({
            "TargetGroupArn": target_group_arn,
            "Targets": [{"Id": id, "Port": port}],
        });
        let out = mws_core::Service::invoke(&self.elb, Self::service_linked(ctx), "DescribeTargetHealth", request)
            .await
            .ok()?;
        out["TargetHealthDescriptions"][0]["TargetHealth"]["State"].as_str().map(String::from)
    }

    async fn scaling_group(&self, ctx: &RequestContext, name: &str) -> Option<mws_ecs::platform::ScalingGroup> {
        let out = mws_core::Service::invoke(
            &self.autoscaling,
            Self::service_linked(ctx),
            "DescribeAutoScalingGroups",
            serde_json::json!({"AutoScalingGroupNames": [name]}),
        )
        .await
        .ok()?;
        let g = out.pointer("/AutoScalingGroups/0")?;
        let int = |k: &str| g.get(k).and_then(serde_json::Value::as_i64).unwrap_or_default() as i32;
        let text = |v: &serde_json::Value, k: &str| {
            v.get(k).and_then(serde_json::Value::as_str).unwrap_or_default().to_string()
        };
        Some(mws_ecs::platform::ScalingGroup {
            desired_capacity: int("DesiredCapacity"),
            min_size: int("MinSize"),
            max_size: int("MaxSize"),
            instances: g
                .get("Instances")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .map(|i| mws_ecs::platform::ScalingGroupInstance {
                    instance_id: text(i, "InstanceId"),
                    lifecycle_state: text(i, "LifecycleState"),
                    instance_type: text(i, "InstanceType"),
                    availability_zone: text(i, "AvailabilityZone"),
                })
                .collect(),
        })
    }

    async fn set_desired_capacity(
        &self,
        ctx: &RequestContext,
        name: &str,
        desired: i32,
    ) -> Result<(), mws_core::ServiceError> {
        mws_core::Service::invoke(
            &self.autoscaling,
            Self::service_linked(ctx),
            "SetDesiredCapacity",
            serde_json::json!({"AutoScalingGroupName": name, "DesiredCapacity": desired, "HonorCooldown": false}),
        )
        .await?;
        self.autoscaling.tick().await;
        Ok(())
    }

    async fn instance_type_resources(&self, ctx: &RequestContext, instance_type: &str) -> Option<(i32, i32)> {
        let out = mws_core::Service::invoke(
            &self.ec2,
            Self::service_linked(ctx),
            "DescribeInstanceTypes",
            serde_json::json!({"InstanceTypes": [instance_type]}),
        )
        .await
        .ok()?;
        let t = out.pointer("/InstanceTypes/0")?;
        let vcpus = t.pointer("/VCpuInfo/DefaultVCpus")?.as_i64()? as i32;
        let mem = t.pointer("/MemoryInfo/SizeInMiB")?.as_i64()? as i32;
        Some((vcpus, mem))
    }

    async fn create_express_ingress(
        &self,
        ctx: &RequestContext,
        name: &str,
        subnets: &[String],
        security_groups: &[String],
        port: i32,
        health_check_path: &str,
    ) -> Result<Option<mws_ecs::platform::ExpressIngress>, mws_core::ServiceError> {
        use mws_core::Service;
        let account = ctx.caller.account_id.clone();
        let behalf = Self::service_linked(ctx);
        let Some(first) = subnets.first().and_then(|s| self.ec2.subnet_info(ctx, &account, s)) else {
            return Ok(None);
        };
        // An Application Load Balancer needs subnets in two zones.
        let mut lb_subnets: Vec<String> = subnets.to_vec();
        let mut zones: Vec<String> = subnets
            .iter()
            .filter_map(|s| self.ec2.subnet_info(ctx, &account, s))
            .map(|s| s.availability_zone)
            .collect();
        for s in self.ec2.subnets_of_vpc(ctx, &account, Some(&first.vpc_id)) {
            if zones.len() >= 2 {
                break;
            }
            if !zones.contains(&s.availability_zone) {
                zones.push(s.availability_zone.clone());
                lb_subnets.push(s.subnet_id);
            }
        }
        let base: String = format!("ecs-express-{name}").chars().take(32).collect();
        let base = base.trim_end_matches('-').to_string();
        let lb = self
            .elb
            .invoke(
                behalf.clone(),
                "CreateLoadBalancer",
                serde_json::json!({
                    "Name": base,
                    "Subnets": lb_subnets,
                    "SecurityGroups": security_groups,
                    "Scheme": "internet-facing",
                    "Type": "application",
                }),
            )
            .await?;
        let lb_arn =
            lb.pointer("/LoadBalancers/0/LoadBalancerArn").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        let dns = lb.pointer("/LoadBalancers/0/DNSName").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        let lb_groups: Vec<String> = lb
            .pointer("/LoadBalancers/0/SecurityGroups")
            .and_then(|v| v.as_array())
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(String::from))
            .collect();
        let tg = self
            .elb
            .invoke(
                behalf.clone(),
                "CreateTargetGroup",
                serde_json::json!({
                    "Name": base,
                    "Protocol": "HTTP",
                    "Port": port,
                    "VpcId": first.vpc_id,
                    "TargetType": "ip",
                    "HealthCheckPath": health_check_path,
                }),
            )
            .await?;
        let tg_arn =
            tg.pointer("/TargetGroups/0/TargetGroupArn").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        let listener = self
            .elb
            .invoke(
                behalf,
                "CreateListener",
                serde_json::json!({
                    "LoadBalancerArn": lb_arn,
                    "Protocol": "HTTP",
                    "Port": 80,
                    "DefaultActions": [{"Type": "forward", "TargetGroupArn": tg_arn}],
                }),
            )
            .await?;
        let listener_arn =
            listener.pointer("/Listeners/0/ListenerArn").and_then(|v| v.as_str()).unwrap_or_default().to_string();
        Ok(Some(mws_ecs::platform::ExpressIngress {
            load_balancer_arn: lb_arn,
            listener_arn,
            target_group_arn: tg_arn,
            dns_name: dns,
            subnets: lb_subnets,
            security_groups: lb_groups,
        }))
    }

    async fn delete_express_ingress(&self, ctx: &RequestContext, ingress: &mws_ecs::platform::ExpressIngress) {
        use mws_core::Service;
        let behalf = Self::service_linked(ctx);
        let calls = [
            ("DeleteListener", serde_json::json!({"ListenerArn": ingress.listener_arn})),
            ("DeleteLoadBalancer", serde_json::json!({"LoadBalancerArn": ingress.load_balancer_arn})),
            ("DeleteTargetGroup", serde_json::json!({"TargetGroupArn": ingress.target_group_arn})),
        ];
        for (op, input) in calls {
            if let Err(e) = self.elb.invoke(behalf.clone(), op, input).await {
                tracing::warn!("ECS Express clean-up {op} failed: {} {}", e.code, e.message);
            }
        }
    }
}

/// ElastiCache slow and engine logs, delivered the way vended logs are:
/// to CloudWatch Logs as `delivery.logs.amazonaws.com` (adding that
/// principal to the account's `AWSLogDeliveryWrite20150319` resource
/// policy, as AWS does), and to Firehose streams tagged
/// `LogDeliveryEnabled=true` through the log delivery service-linked role.
pub(crate) struct ElastiCacheLogs {
    pub logs: mws_logs::Logs,
    pub firehose: mws_firehose::Firehose,
}

const LOG_DELIVERY_POLICY: &str = "AWSLogDeliveryWrite20150319";

fn log_delivery_ctx(b: &mws_elasticache::LogBatch) -> RequestContext {
    let role = "AWSServiceRoleForLogDelivery";
    RequestContext {
        request_id: uuid::Uuid::new_v4().to_string(),
        region: b.region.clone(),
        partition: b.partition.clone(),
        received_at: chrono::Utc::now(),
        caller: mws_core::Caller {
            account_id: b.account.clone(),
            arn: format!("arn:{}:sts::{}:assumed-role/{role}/LogDelivery", b.partition, b.account),
            user_id: format!("AROA{}:LogDelivery", uuid::Uuid::new_v4().simple().to_string()[..17].to_uppercase()),
            access_key_id: String::new(),
            kind: mws_core::CallerKind::AssumedRole { role_name: role.into(), session_name: "LogDelivery".into() },
            session: None,
        },
        source_ip: None,
        secure_transport: true,
        authorizer: std::sync::Arc::new(mws_core::AllowAll),
        endpoint: None,
    }
}

impl ElastiCacheLogs {
    /// Let `delivery.logs.amazonaws.com` write to `log_group`.
    async fn allow_delivery(&self, b: &mws_elasticache::LogBatch) -> Result<(), String> {
        use mws_core::Service;
        let ctx = log_delivery_ctx(b);
        let resource = format!("arn:{}:logs:{}:{}:log-group:{}:*", b.partition, b.region, b.account, b.destination);
        let existing = self
            .logs
            .invoke(ctx.clone(), "DescribeResourcePolicies", serde_json::json!({}))
            .await
            .map_err(|e| e.message)?;
        let mut doc = existing["resourcePolicies"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|p| p["policyName"] == LOG_DELIVERY_POLICY)
            .and_then(|p| p["policyDocument"].as_str())
            .and_then(|d| serde_json::from_str::<serde_json::Value>(d).ok())
            .unwrap_or_else(|| {
                serde_json::json!({
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Sid": "AWSLogDeliveryWrite",
                        "Effect": "Allow",
                        "Principal": {"Service": "delivery.logs.amazonaws.com"},
                        "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                        "Resource": [],
                        "Condition": {"StringEquals": {"aws:SourceAccount": b.account}},
                    }],
                })
            });
        let resources = &mut doc["Statement"][0]["Resource"];
        if let Some(one) = resources.as_str().map(str::to_string) {
            *resources = serde_json::json!([one]);
        }
        if let Some(list) = resources.as_array_mut() {
            if !list.iter().any(|r| r == &serde_json::Value::String(resource.clone())) {
                list.push(resource.into());
            }
        }
        self.logs
            .invoke(
                ctx,
                "PutResourcePolicy",
                serde_json::json!({"policyName": LOG_DELIVERY_POLICY, "policyDocument": doc.to_string()}),
            )
            .await
            .map(|_| ())
            .map_err(|e| e.message)
    }
}

#[async_trait::async_trait]
impl mws_elasticache::LogDelivery for ElastiCacheLogs {
    async fn deliver(&self, b: mws_elasticache::LogBatch) -> Result<(), String> {
        let now = chrono::Utc::now().timestamp_millis();
        match b.destination_type.as_str() {
            "cloudwatch-logs" => {
                let writer = mws_logs::ServiceLogWriter {
                    partition: &b.partition,
                    account: &b.account,
                    region: &b.region,
                    log_group: &b.destination,
                    service_principal: "delivery.logs.amazonaws.com",
                    source_account: &b.account,
                    source_arn: &b.source_arn,
                };
                let events = || {
                    b.events
                        .iter()
                        .map(|(t, m)| mws_logs::ServiceLogEvent { timestamp: *t, message: m.clone() })
                        .collect::<Vec<_>>()
                };
                match self.logs.put_log_events_as_service(&writer, &b.log_stream, events(), now) {
                    Err(mws_logs::ServiceLogError::AccessDenied { .. }) => {
                        self.allow_delivery(&b).await?;
                        self.logs.put_log_events_as_service(&writer, &b.log_stream, events(), now)
                    }
                    other => other,
                }
                .map_err(|e| e.to_string())
            }
            "kinesis-firehose" => {
                use mws_core::Service;
                let ctx = log_delivery_ctx(&b);
                let tags = self
                    .firehose
                    .invoke(
                        ctx.clone(),
                        "ListTagsForDeliveryStream",
                        serde_json::json!({"DeliveryStreamName": b.destination}),
                    )
                    .await
                    .map_err(|e| e.message)?;
                let enabled = tags["Tags"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .any(|t| t["Key"] == "LogDeliveryEnabled" && t["Value"] == "true");
                if !enabled {
                    return Err(format!(
                        "Delivery stream {} must have the tag LogDeliveryEnabled with the value true.",
                        b.destination
                    ));
                }
                for (_, message) in &b.events {
                    let mut data = message.clone().into_bytes();
                    data.push(b'\n');
                    self.firehose
                        .put_record(
                            &ctx,
                            mws_firehose::generated::types::PutRecordInput {
                                delivery_stream_name: b.destination.clone(),
                                record: mws_firehose::generated::types::Record { data },
                            },
                        )
                        .map_err(|e| e.message)?;
                }
                Ok(())
            }
            other => Err(format!("Unsupported destination type {other}")),
        }
    }
}

/// ECR pull-through cache credentials: the rule's Secrets Manager secret
/// (`{"username": ..., "accessToken": ...}`), read as the registry's
/// account (AWS reads it with ECR's service-linked role).
pub struct EcrUpstreamCredentials(pub mws_secretsmanager::SecretsManager);

#[async_trait::async_trait]
impl mws_ecr::UpstreamCredentials for EcrUpstreamCredentials {
    async fn credentials(
        &self,
        ctx: &mws_core::RequestContext,
        account: &str,
        secret_arn: &str,
    ) -> Result<(String, String), String> {
        let caller = mws_core::Caller {
            account_id: account.to_string(),
            arn: format!("arn:{}:iam::{account}:root", ctx.partition),
            user_id: account.to_string(),
            access_key_id: String::new(),
            kind: mws_core::CallerKind::Root,
            session: None,
        };
        let rctx = mws_core::RequestContext { caller, ..ctx.clone() };
        let s = self
            .0
            .read_for_reference(&rctx, secret_arn, None)
            .map_err(|e| format!("The credentials in {secret_arn} can't be read: {}", e.message))?;
        let text = s.secret_string;
        let doc: serde_json::Value =
            serde_json::from_str(&text).map_err(|_| format!("The secret {secret_arn} is not a JSON object."))?;
        let field = |k: &str| doc.get(k).and_then(|v| v.as_str()).map(str::to_string);
        match (field("username"), field("accessToken")) {
            (Some(u), Some(t)) => Ok((u, t)),
            _ => Err(format!("The secret {secret_arn} must have username and accessToken.")),
        }
    }
}

/// S3 object events of buckets with EventBridge enabled: to EventBridge,
/// and new objects to GuardDuty Malware Protection, which scans those its
/// plans protect.
pub(crate) struct S3ObjectEvents {
    pub events: crate::sinks::S3ToEvents,
    pub guardduty: mws_guardduty::GuardDuty,
}

impl mws_s3::EventBridgeSink for S3ObjectEvents {
    fn object_event(&self, ctx: &RequestContext, e: &mws_s3::ObjectEvent) {
        self.events.object_event(ctx, e);
        if !e.event_name.starts_with("ObjectCreated:") {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else { return };
        let (gd, ctx, e) = (self.guardduty.clone(), ctx.clone(), e.clone());
        runtime.spawn(async move {
            gd.object_created(&ctx, &e.bucket_owner, &e.bucket, &e.key, e.version_id.as_deref()).await;
        });
    }
}

/// Malware Protection for S3 working in S3 as a protection plan's role.
pub(crate) struct GuardDutyMalwareObjects {
    pub sts: mws_sts::Sts,
    pub s3: mws_s3::S3,
}

impl GuardDutyMalwareObjects {
    async fn call(
        &self,
        role: &RequestContext,
        op: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        mws_core::Service::invoke(&self.s3, role.clone(), op, input).await.map_err(|e| e.code.to_string())
    }
}

fn object_target(bucket: &str, key: &str, version_id: Option<&str>) -> serde_json::Value {
    let mut v = serde_json::json!({ "Bucket": bucket, "Key": key });
    if let Some(id) = version_id.filter(|v| !v.is_empty() && *v != "null") {
        v["VersionId"] = serde_json::Value::String(id.to_string());
    }
    v
}

#[async_trait::async_trait]
impl mws_guardduty::MalwareObjectStore for GuardDutyMalwareObjects {
    fn assume(&self, ctx: &RequestContext, role_arn: &str, plan_arn: &str) -> Result<RequestContext, String> {
        let account = plan_arn.split(':').nth(4).unwrap_or(&ctx.caller.account_id);
        let creds = self
            .sts
            .assume_role_as_service(&mws_sts::ServiceAssume {
                role_arn,
                service_principal: "malware-protection-plan.guardduty.amazonaws.com",
                session_name: "GuardDutyMalwareProtection",
                duration_seconds: 3600,
                source_account: Some(account),
                source_arn: Some(plan_arn),
                now: ctx.received_at,
            })
            .map_err(|e| format!("{e:?}"))?;
        let resolved = self
            .sts
            .credential_store()
            .resolve(&creds.access_key_id, Some(&creds.session_token), ctx.received_at)
            .map_err(|e| format!("{e:?}"))?
            .ok_or_else(|| "the role session could not be resolved".to_string())?;
        Ok(RequestContext { caller: resolved.caller, source_ip: None, ..ctx.clone() })
    }

    async fn enable_eventbridge(&self, role: &RequestContext, bucket: &str) -> Result<(), String> {
        let mut config =
            self.call(role, "GetBucketNotificationConfiguration", serde_json::json!({ "Bucket": bucket })).await?;
        if config.get("EventBridgeConfiguration").is_some_and(|v| !v.is_null()) {
            return Ok(());
        }
        config["EventBridgeConfiguration"] = serde_json::json!({});
        let input = serde_json::json!({ "Bucket": bucket, "NotificationConfiguration": config });
        self.call(role, "PutBucketNotificationConfiguration", input).await.map(|_| ())
    }

    async fn get_object(
        &self,
        role: &RequestContext,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<mws_guardduty::ScannedObject, String> {
        use base64::Engine as _;
        let out = self.call(role, "GetObject", object_target(bucket, key, version_id)).await?;
        let body = out.get("Body").and_then(serde_json::Value::as_str).unwrap_or("");
        let text = |k: &str| out.get(k).and_then(serde_json::Value::as_str).map(str::to_string);
        Ok(mws_guardduty::ScannedObject {
            body: base64::engine::general_purpose::STANDARD.decode(body).unwrap_or_default(),
            etag: text("ETag"),
            version_id: text("VersionId"),
        })
    }

    async fn tag_object(
        &self,
        role: &RequestContext,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        tag_key: &str,
        value: &str,
    ) -> Result<(), String> {
        let target = object_target(bucket, key, version_id);
        let current = self.call(role, "GetObjectTagging", target.clone()).await?;
        let mut tags: Vec<serde_json::Value> = current
            .get("TagSet")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|t| t.get("Key").and_then(serde_json::Value::as_str) != Some(tag_key))
            .collect();
        tags.push(serde_json::json!({ "Key": tag_key, "Value": value }));
        let mut input = target;
        input["Tagging"] = serde_json::json!({ "TagSet": tags });
        self.call(role, "PutObjectTagging", input).await.map(|_| ())
    }
}

/// EC2 endpoint services check the Network and Gateway Load Balancers they
/// are offered behind, and take their Availability Zones.
pub(crate) struct Ec2LoadBalancers(pub mws_elb::Elb);

impl mws_ec2::LoadBalancers for Ec2LoadBalancers {
    fn load_balancer(&self, account: &str, region: &str, arn: &str) -> Option<(String, Vec<String>)> {
        self.0.load_balancer(account, region, arn).map(|lb| (lb.lb_type, lb.availability_zones))
    }
}

/// Lambda `FileSystemConfigs` mount EFS access points.
pub(crate) struct LambdaFileSystems(pub mws_efs::Efs);

impl mws_lambda::FileSystems for LambdaFileSystems {
    fn mount(
        &self,
        req: &mws_lambda::FileSystemMountRequest,
    ) -> Result<mws_lambda::MountedFileSystem, mws_lambda::FileSystemMountError> {
        let m = mws_efs::service_mount::ServiceMount {
            account: req.account.clone(),
            region: req.region.clone(),
            access_point_arn: req.access_point_arn.clone(),
            subnet_ids: req.subnet_ids.clone(),
            security_group_ids: req.security_group_ids.clone(),
            role_arn: req.role_arn.clone(),
            session_name: req.session_name.clone(),
        };
        match self.0.mount_for_service(&m) {
            Ok(m) => Ok(mws_lambda::MountedFileSystem { dir: m.dir, read_only: m.read_only, owner: m.owner }),
            Err(mws_efs::service_mount::ServiceMountError::Connectivity(e)) => {
                Err(mws_lambda::FileSystemMountError::Connectivity(e))
            }
            Err(mws_efs::service_mount::ServiceMountError::Failure(e)) => {
                Err(mws_lambda::FileSystemMountError::Failure(e))
            }
        }
    }
}

/// Image Builder build instances acting as their instance profile's role
/// (assumed by `ec2.amazonaws.com` with the instance id as the session
/// name, as instance metadata hands it out) when they push container
/// images and upload build logs.
pub(crate) struct ImageBuilderInstanceRoles {
    pub iam: mws_iam::Iam,
    pub sts: mws_sts::Sts,
}

impl mws_imagebuilder::InstanceRoles for ImageBuilderInstanceRoles {
    fn instance_context(
        &self,
        base: &RequestContext,
        account: &str,
        instance_profile: &str,
        instance_id: &str,
    ) -> Result<RequestContext, String> {
        let none = |why: String| format!("the build instance {instance_id} has no credentials: {why}");
        let profile = self
            .iam
            .instance_profile(account, instance_profile)
            .ok_or_else(|| none(format!("instance profile {instance_profile} does not exist")))?;
        let role = profile.role_arn.ok_or_else(|| none(format!("instance profile {instance_profile} has no role")))?;
        let instance_arn = format!("arn:{}:ec2:{}:{account}:instance/{instance_id}", base.partition, base.region);
        let creds = self
            .sts
            .assume_role_as_service(&mws_sts::ServiceAssume {
                role_arn: &role,
                service_principal: "ec2.amazonaws.com",
                session_name: instance_id,
                duration_seconds: 6 * 3600,
                source_account: Some(account),
                source_arn: Some(&instance_arn),
                now: base.received_at,
            })
            .map_err(|_| none(format!("EC2 cannot assume the role {role}")))?;
        let resolved = self
            .sts
            .credential_store()
            .resolve(&creds.access_key_id, Some(&creds.session_token), base.received_at)
            .ok()
            .flatten()
            .ok_or_else(|| none(format!("EC2 cannot assume the role {role}")))?;
        Ok(RequestContext { caller: resolved.caller, ..base.clone() })
    }
}

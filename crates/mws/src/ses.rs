//! What SES reaches in other services: Route 53 for domain verification,
//! S3 for receipt rules and import/export jobs, SNS, Lambda, EventBridge,
//! Firehose and CloudWatch for notifications and event destinations.

use async_trait::async_trait;
use mws_core::{RequestContext, Service};
use mws_ses::{BusEvent, Metric, S3Put, SERVICE_PRINCIPAL};

pub(crate) struct SesLinks {
    pub route53: mws_route53::Route53,
    pub s3: mws_s3::S3,
    pub sns: mws_sns::Sns,
    pub lambda: mws_lambda::Lambda,
    pub events: mws_events::Events,
    pub firehose: mws_firehose::Firehose,
    pub cloudwatch: mws_cloudwatch::CloudWatch,
    pub sts: mws_sts::Sts,
    pub partition: String,
}

impl SesLinks {
    /// `ctx` as a session of `role_arn`, assumed by SES.
    fn role_context(
        &self,
        ctx: &RequestContext,
        role_arn: &str,
        source_account: &str,
        source_arn: &str,
    ) -> Result<RequestContext, String> {
        let creds = self
            .sts
            .assume_role_as_service(&mws_sts::ServiceAssume {
                role_arn,
                service_principal: SERVICE_PRINCIPAL,
                session_name: "SES",
                duration_seconds: 3600,
                source_account: Some(source_account),
                source_arn: Some(source_arn),
                now: ctx.received_at,
            })
            .map_err(|e| format!("SES could not assume {role_arn}: {e:?}"))?;
        let resolved = self
            .sts
            .credential_store()
            .resolve(&creds.access_key_id, Some(&creds.session_token), ctx.received_at)
            .map_err(|e| format!("{e:?}"))?
            .ok_or_else(|| "the role session could not be resolved".to_string())?;
        Ok(RequestContext { caller: resolved.caller, source_ip: None, ..ctx.clone() })
    }

    fn service_put<'a>(
        &'a self,
        bucket: &'a str,
        key: &'a str,
        body: Vec<u8>,
        source_account: &'a str,
        source_arn: &'a str,
    ) -> mws_s3::ServicePutObject<'a> {
        mws_s3::ServicePutObject {
            bucket,
            key,
            body,
            content_type: "application/octet-stream",
            service_principal: SERVICE_PRINCIPAL,
            source_account,
            source_arn,
            acl: None,
            partition: &self.partition,
        }
    }

    fn sns_publish<'a>(
        &self,
        topic_arn: &'a str,
        source_account: &'a str,
        source_arn: &'a str,
        message: String,
        subject: Option<&str>,
    ) -> mws_sns::ServicePublish<'a> {
        mws_sns::ServicePublish {
            topic_arn,
            service_principal: SERVICE_PRINCIPAL,
            source_arn,
            source_account,
            message,
            subject: subject.map(str::to_string),
            attributes: Default::default(),
            message_group_id: None,
            message_deduplication_id: None,
        }
    }
}

#[async_trait]
impl mws_ses::Links for SesLinks {
    fn dns(&self, name: &str, ty: &str) -> Vec<String> {
        self.route53.public_record_values(name, ty)
    }

    fn check_s3(
        &self,
        _ctx: &RequestContext,
        bucket: &str,
        source_account: &str,
        source_arn: &str,
    ) -> Result<(), String> {
        let put = self.service_put(bucket, "ses-permission-check", Vec::new(), source_account, source_arn);
        self.s3.check_service_access(&put, &["s3:PutObject"]).map_err(|e| e.to_string())
    }

    async fn put_s3(&self, ctx: &RequestContext, put: S3Put<'_>) -> Result<(), String> {
        if put.role_arn.is_none() && put.kms_key_arn.is_none() {
            let p = self.service_put(put.bucket, put.key, put.body, put.source_account, put.source_arn);
            return self.s3.put_object_as_service(p).map(|_| ()).map_err(|e| e.to_string());
        }
        // Writes as a role, or encrypted with a KMS key, go through S3's own
        // PutObject so that IAM and the key policy judge them.
        let rctx = match put.role_arn {
            Some(role) => self.role_context(ctx, role, put.source_account, put.source_arn)?,
            None => ctx.clone(),
        };
        let mut input = serde_json::json!({
            "Bucket": put.bucket,
            "Key": put.key,
            "Body": mws_ses_b64(&put.body),
        });
        if let Some(key) = put.kms_key_arn {
            input["ServerSideEncryption"] = "aws:kms".into();
            input["SSEKMSKeyId"] = key.into();
        }
        self.s3.invoke(rctx, "PutObject", input).await.map(|_| ()).map_err(|e| format!("{}: {}", e.code, e.message))
    }

    fn get_s3(&self, _ctx: &RequestContext, bucket: &str, key: &str) -> Result<Vec<u8>, String> {
        let owner = self.s3.bucket_owner(bucket).ok_or_else(|| "NoSuchBucket".to_string())?;
        let source_arn = String::new();
        let get = self.service_put(bucket, key, Vec::new(), &owner, &source_arn);
        self.s3.check_service_access(&get, &["s3:GetObject"]).map_err(|e| e.to_string())?;
        self.s3.object_bytes(bucket, key).ok_or_else(|| "NoSuchKey".to_string())
    }

    fn check_sns(
        &self,
        _ctx: &RequestContext,
        topic_arn: &str,
        source_account: &str,
        source_arn: &str,
    ) -> Result<(), String> {
        let p = self.sns_publish(topic_arn, source_account, source_arn, String::new(), None);
        self.sns.check_service_publish(&p).map_err(|e| e.to_string())
    }

    fn publish_sns(
        &self,
        ctx: &RequestContext,
        topic_arn: &str,
        subject: Option<&str>,
        message: String,
        source_account: &str,
        source_arn: &str,
    ) -> Result<(), String> {
        let p = self.sns_publish(topic_arn, source_account, source_arn, message, subject);
        self.sns.publish_as_service(ctx, &p).map(|_| ()).map_err(|e| e.to_string())
    }

    fn check_lambda(
        &self,
        ctx: &RequestContext,
        function_arn: &str,
        source_account: &str,
        source_arn: &str,
    ) -> Result<(), String> {
        let inv = mws_lambda::ServiceInvocation {
            function: function_arn,
            service_principal: SERVICE_PRINCIPAL,
            source_account: Some(source_account),
            source_arn: Some(source_arn),
            payload: Vec::new(),
        };
        self.lambda.check_service_invoke(ctx, &inv).map(|_| ()).map_err(|e| e.to_string())
    }

    async fn invoke_lambda(
        &self,
        ctx: &RequestContext,
        function_arn: &str,
        payload: Vec<u8>,
        sync: bool,
        source_account: &str,
        source_arn: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        let inv = mws_lambda::ServiceInvocation {
            function: function_arn,
            service_principal: SERVICE_PRINCIPAL,
            source_account: Some(source_account),
            source_arn: Some(source_arn),
            payload,
        };
        if !sync {
            return self.lambda.invoke_event_as_service(ctx, inv).map(|()| None).map_err(|e| e.to_string());
        }
        let out = self.lambda.invoke_as_service(ctx, inv).await.map_err(|e| e.to_string())?;
        match out.function_error {
            Some(e) => Err(format!("the function failed ({e})")),
            None => Ok(Some(out.payload)),
        }
    }

    fn put_event(&self, ctx: &RequestContext, e: BusEvent) {
        self.events.put_service_event(
            ctx,
            mws_events::ServiceEvent {
                partition: self.partition.clone(),
                account: e.account,
                region: e.region,
                source: "aws.ses".into(),
                detail_type: e.detail_type,
                resources: e.resources,
                detail: e.detail,
                time: e.time,
            },
        );
    }

    fn put_firehose(
        &self,
        ctx: &RequestContext,
        role_arn: &str,
        stream_arn: &str,
        data: Vec<u8>,
        source_account: &str,
        source_arn: &str,
    ) -> Result<(), String> {
        let rctx = self.role_context(ctx, role_arn, source_account, source_arn)?;
        let name = stream_arn.rsplit_once("deliverystream/").map(|(_, n)| n).unwrap_or(stream_arn);
        self.firehose
            .put_record(
                &rctx,
                mws_firehose::generated::types::PutRecordInput {
                    delivery_stream_name: name.to_string(),
                    record: mws_firehose::generated::types::Record { data },
                },
            )
            .map(|_| ())
            .map_err(|e| e.message)
    }

    fn check_firehose(
        &self,
        ctx: &RequestContext,
        role_arn: &str,
        _stream_arn: &str,
        source_account: &str,
        source_arn: &str,
    ) -> Result<(), String> {
        self.role_context(ctx, role_arn, source_account, source_arn).map(|_| ())
    }

    fn put_metric(&self, m: Metric) {
        self.cloudwatch.put_metric_as_service(mws_cloudwatch::ServiceMetric {
            account: m.account,
            region: m.region,
            namespace: m.namespace,
            metric_name: m.name,
            dimensions: m.dimensions,
            unit: Some(m.unit),
            timestamp: m.time,
            values: vec![(m.value, 1.0)],
        });
    }
}

fn mws_ses_b64(b: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(b)
}

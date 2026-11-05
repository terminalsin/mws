//! The other services SES reaches into, where AWS couples them. The
//! composition root implements [`Links`] over the real services; every
//! call is made as the SES service principal (`ses.amazonaws.com`) and is
//! judged by the resource's own policy, or as a role SES assumes.

use chrono::{DateTime, Utc};
use mws_core::RequestContext;

pub const SERVICE_PRINCIPAL: &str = "ses.amazonaws.com";

/// Where SES delivers, publishes and looks things up.
#[async_trait::async_trait]
pub trait Links: Send + Sync {
    /// The values of `name`'s `ty` records in public DNS (Route 53 public
    /// hosted zones).
    fn dns(&self, _name: &str, _ty: &str) -> Vec<String> {
        Vec::new()
    }

    /// Whether SES may write objects to `bucket` (receipt rule S3 actions).
    fn check_s3(
        &self,
        _ctx: &RequestContext,
        _bucket: &str,
        _source_account: &str,
        _source_arn: &str,
    ) -> Result<(), String> {
        Err("S3 is not available".into())
    }

    /// Write an object as SES.
    async fn put_s3(&self, _ctx: &RequestContext, _put: S3Put<'_>) -> Result<(), String> {
        Err("S3 is not available".into())
    }

    /// Read an object as SES (import jobs).
    fn get_s3(&self, _ctx: &RequestContext, _bucket: &str, _key: &str) -> Result<Vec<u8>, String> {
        Err("S3 is not available".into())
    }

    /// Whether SES may publish to `topic_arn`.
    fn check_sns(
        &self,
        _ctx: &RequestContext,
        _topic_arn: &str,
        _source_account: &str,
        _source_arn: &str,
    ) -> Result<(), String> {
        Err("SNS is not available".into())
    }

    /// Publish to a topic as SES.
    fn publish_sns(
        &self,
        _ctx: &RequestContext,
        _topic_arn: &str,
        _subject: Option<&str>,
        _message: String,
        _source_account: &str,
        _source_arn: &str,
    ) -> Result<(), String> {
        Err("SNS is not available".into())
    }

    /// Whether SES may invoke `function_arn`.
    fn check_lambda(
        &self,
        _ctx: &RequestContext,
        _function_arn: &str,
        _source_account: &str,
        _source_arn: &str,
    ) -> Result<(), String> {
        Err("Lambda is not available".into())
    }

    /// Invoke a function as SES: `sync` waits for its result.
    async fn invoke_lambda(
        &self,
        _ctx: &RequestContext,
        _function_arn: &str,
        _payload: Vec<u8>,
        _sync: bool,
        _source_account: &str,
        _source_arn: &str,
    ) -> Result<Option<Vec<u8>>, String> {
        Err("Lambda is not available".into())
    }

    /// Put an event on `account`'s default bus in `region`.
    fn put_event(&self, _ctx: &RequestContext, _event: BusEvent) {}

    /// Put a record into a Firehose stream as the role SES assumes.
    fn put_firehose(
        &self,
        _ctx: &RequestContext,
        _role_arn: &str,
        _stream_arn: &str,
        _data: Vec<u8>,
        _source_account: &str,
        _source_arn: &str,
    ) -> Result<(), String> {
        Err("Firehose is not available".into())
    }

    /// Whether SES can assume `role_arn` and the stream exists.
    fn check_firehose(
        &self,
        _ctx: &RequestContext,
        _role_arn: &str,
        _stream_arn: &str,
        _source_account: &str,
        _source_arn: &str,
    ) -> Result<(), String> {
        Ok(())
    }

    /// Publish a CloudWatch metric in `account`/`region`.
    fn put_metric(&self, _metric: Metric) {}
}

/// An object SES writes to S3.
#[derive(Debug, Clone)]
pub struct S3Put<'a> {
    pub bucket: &'a str,
    pub key: &'a str,
    pub body: Vec<u8>,
    pub source_account: &'a str,
    pub source_arn: &'a str,
    /// A KMS key to encrypt the object with.
    pub kms_key_arn: Option<&'a str>,
    /// A role to write as, instead of the SES service principal.
    pub role_arn: Option<&'a str>,
}

/// An event SES puts on an EventBridge bus.
#[derive(Debug, Clone)]
pub struct BusEvent {
    pub account: String,
    pub region: String,
    pub detail_type: String,
    pub resources: Vec<String>,
    pub detail: serde_json::Value,
    pub time: DateTime<Utc>,
}

/// A CloudWatch metric data point SES publishes.
#[derive(Debug, Clone)]
pub struct Metric {
    pub account: String,
    pub region: String,
    pub namespace: String,
    pub name: String,
    pub dimensions: Vec<(String, String)>,
    pub value: f64,
    pub unit: String,
    pub time: DateTime<Utc>,
}

/// No other services: everything SES would reach fails.
pub struct NoLinks;

impl Links for NoLinks {}

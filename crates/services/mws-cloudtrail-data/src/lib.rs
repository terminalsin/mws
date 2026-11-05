//! AWS CloudTrail Data for MWS: `PutAuditEvents` sends events from outside
//! AWS through a CloudTrail Lake channel into its event data stores (see
//! [`mws_cloudtrail::CloudTrail::put_audit_events`]).

#[allow(clippy::all, dead_code, unused_imports, non_snake_case, non_camel_case_types)]
pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/cloudtrail_data_generated.rs"));
}

use mws_cloudtrail::{AuditError, AuditEvent, CloudTrail};
use mws_core::{HttpRequest, HttpResponse, RequestContext, Service, ServiceError};

use generated::{errors, types};

/// The CloudTrail Data service, in front of CloudTrail's channels.
#[derive(Clone)]
pub struct CloudTrailData {
    cloudtrail: CloudTrail,
}

impl CloudTrailData {
    pub fn new(cloudtrail: CloudTrail) -> Self {
        Self { cloudtrail }
    }
}

#[async_trait::async_trait]
impl generated::Handler for CloudTrailData {
    async fn put_audit_events(
        &self,
        ctx: &RequestContext,
        input: types::PutAuditEventsRequest,
    ) -> Result<types::PutAuditEventsResponse, ServiceError> {
        let events = input
            .audit_events
            .into_iter()
            .map(|e| AuditEvent { id: e.id, event_data: e.event_data, event_data_checksum: e.event_data_checksum })
            .collect();
        let result = self
            .cloudtrail
            .put_audit_events(ctx, &input.channel_arn, input.external_id.as_deref(), events)
            .map_err(|e| match e {
                AuditError::InvalidChannelArn(m) => errors::invalid_channel_arn(m),
                AuditError::ChannelNotFound(m) => errors::channel_not_found(m),
                AuditError::InsufficientPermission(m) => errors::channel_insufficient_permission(m),
                AuditError::DuplicatedId(m) => errors::duplicated_audit_event_id(m),
                AuditError::Denied(e) => e,
            })?;
        Ok(types::PutAuditEventsResponse {
            successful: result
                .successful
                .into_iter()
                .map(|(id, event_id)| types::AuditEventResultEntry { id, event_id })
                .collect(),
            failed: result
                .failed
                .into_iter()
                .map(|(id, error_code, error_message)| types::ResultErrorEntry { id, error_code, error_message })
                .collect(),
        })
    }
}

#[async_trait::async_trait]
impl Service for CloudTrailData {
    fn signing_name(&self) -> &'static str {
        "cloudtrail-data"
    }

    async fn handle(&self, ctx: RequestContext, request: HttpRequest) -> HttpResponse {
        generated::dispatch(self, &ctx, &request).await
    }

    fn render_error(&self, request_id: &str, error: &ServiceError) -> HttpResponse {
        mws_proto_restjson::error_response(&generated::SERVICE_INFO, request_id, error)
    }

    async fn invoke(
        &self,
        ctx: RequestContext,
        operation: &str,
        input: serde_json::Value,
    ) -> Result<serde_json::Value, ServiceError> {
        generated::invoke(self, &ctx, operation, input).await
    }
}

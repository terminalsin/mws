//! awsQuery for SQS. The model moved SQS to awsJson, but SQS still answers
//! the form-encoded awsQuery requests older SDKs send (AWS SDK for Java 1.x,
//! boto3 before 1.34, ...). Requests decode with the awsQuery codec
//! generated from the same model, run through the awsJson handlers (the
//! generated types are identical), and answer in XML with the awsQuery
//! error codes.

use mws_core::{HttpRequest, HttpResponse, RequestContext, ServiceError};

use crate::generated as j;
use crate::names::wire_code;
use crate::query_generated as q;
use crate::Sqs;

/// Whether a request uses awsQuery rather than awsJson.
pub fn is_query(request: &HttpRequest) -> bool {
    !request.headers().contains_key("x-amz-target")
}

pub async fn handle(sqs: &Sqs, ctx: &RequestContext, request: &HttpRequest) -> HttpResponse {
    let mut params = mws_proto_query::read_params(request);
    // Legacy clients post to the queue URL and may leave `QueueUrl` out.
    if params.get("QueueUrl").is_none() {
        let path = request.uri().path();
        if path.trim_matches('/').split('/').count() == 2 {
            let base = ctx.endpoint.clone().unwrap_or_else(|| format!("https://sqs.{}.amazonaws.com", ctx.region));
            params.insert("QueueUrl", format!("{}{path}", base.trim_end_matches('/')));
        }
    }
    // As over awsJson, unknown attribute names are `InvalidAttributeName`
    // rather than a validation error.
    if params.get("Action") == Some("GetQueueAttributes") {
        let unknown = params
            .indexes("AttributeName")
            .into_iter()
            .filter_map(|i| params.get(&format!("AttributeName.{i}")))
            .find(|n| !crate::attributes::known(n));
        if let Some(name) = unknown {
            let e = to_query(crate::attributes::unknown_attribute(name));
            return mws_proto_query::error_response(&q::SERVICE_INFO, &ctx.request_id, &e);
        }
    }
    q::dispatch(&Bridge(sqs), ctx, &params).await
}

/// The awsQuery form of an error: modeled errors take their awsQuery code.
fn to_query(mut e: ServiceError) -> ServiceError {
    e.code = wire_code(&e).into();
    e
}

fn convert<A: serde::Serialize, B: serde::de::DeserializeOwned>(a: A) -> Result<B, ServiceError> {
    serde_json::from_value(serde_json::to_value(a).map_err(|e| ServiceError::internal(e.to_string()))?)
        .map_err(|e| ServiceError::internal(e.to_string()))
}

struct Bridge<'a>(&'a Sqs);

macro_rules! bridge {
    ($($name:ident($input:ident) -> $output:ty;)*) => {
        #[async_trait::async_trait]
        impl q::Handler for Bridge<'_> {
            $(
                async fn $name(&self, ctx: &RequestContext, input: q::types::$input) -> Result<$output, ServiceError> {
                    let input: j::types::$input = convert(input)?;
                    let out = <Sqs as j::Handler>::$name(self.0, ctx, input).await.map_err(to_query)?;
                    convert(out)
                }
            )*
        }
    };
}

bridge! {
        add_permission(AddPermissionRequest) -> ();
        cancel_message_move_task(CancelMessageMoveTaskRequest) -> q::types::CancelMessageMoveTaskResult;
        change_message_visibility(ChangeMessageVisibilityRequest) -> ();
        change_message_visibility_batch(ChangeMessageVisibilityBatchRequest) -> q::types::ChangeMessageVisibilityBatchResult;
        create_queue(CreateQueueRequest) -> q::types::CreateQueueResult;
        delete_message(DeleteMessageRequest) -> ();
        delete_message_batch(DeleteMessageBatchRequest) -> q::types::DeleteMessageBatchResult;
        delete_queue(DeleteQueueRequest) -> ();
        get_queue_attributes(GetQueueAttributesRequest) -> q::types::GetQueueAttributesResult;
        get_queue_url(GetQueueUrlRequest) -> q::types::GetQueueUrlResult;
        list_dead_letter_source_queues(ListDeadLetterSourceQueuesRequest) -> q::types::ListDeadLetterSourceQueuesResult;
        list_message_move_tasks(ListMessageMoveTasksRequest) -> q::types::ListMessageMoveTasksResult;
        list_queue_tags(ListQueueTagsRequest) -> q::types::ListQueueTagsResult;
        list_queues(ListQueuesRequest) -> q::types::ListQueuesResult;
        purge_queue(PurgeQueueRequest) -> ();
        receive_message(ReceiveMessageRequest) -> q::types::ReceiveMessageResult;
        remove_permission(RemovePermissionRequest) -> ();
        send_message(SendMessageRequest) -> q::types::SendMessageResult;
        send_message_batch(SendMessageBatchRequest) -> q::types::SendMessageBatchResult;
        set_queue_attributes(SetQueueAttributesRequest) -> ();
        start_message_move_task(StartMessageMoveTaskRequest) -> q::types::StartMessageMoveTaskResult;
        tag_queue(TagQueueRequest) -> ();
        untag_queue(UntagQueueRequest) -> ();
}

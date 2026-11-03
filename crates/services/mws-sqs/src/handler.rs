//! Wires the generated `Handler` trait to the operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::Sqs;

#[async_trait::async_trait]
impl Handler for Sqs {
    async fn add_permission(
        &self,
        ctx: &RequestContext,
        input: types::AddPermissionRequest,
    ) -> Result<(), ServiceError> {
        Sqs::add_permission(self, ctx, input)
    }

    async fn cancel_message_move_task(
        &self,
        ctx: &RequestContext,
        input: types::CancelMessageMoveTaskRequest,
    ) -> Result<types::CancelMessageMoveTaskResult, ServiceError> {
        Sqs::cancel_message_move_task(self, ctx, input)
    }

    async fn change_message_visibility(
        &self,
        ctx: &RequestContext,
        input: types::ChangeMessageVisibilityRequest,
    ) -> Result<(), ServiceError> {
        Sqs::change_message_visibility(self, ctx, input)
    }

    async fn change_message_visibility_batch(
        &self,
        ctx: &RequestContext,
        input: types::ChangeMessageVisibilityBatchRequest,
    ) -> Result<types::ChangeMessageVisibilityBatchResult, ServiceError> {
        Sqs::change_message_visibility_batch(self, ctx, input)
    }

    async fn create_queue(
        &self,
        ctx: &RequestContext,
        input: types::CreateQueueRequest,
    ) -> Result<types::CreateQueueResult, ServiceError> {
        Sqs::create_queue(self, ctx, input)
    }

    async fn delete_message(
        &self,
        ctx: &RequestContext,
        input: types::DeleteMessageRequest,
    ) -> Result<(), ServiceError> {
        Sqs::delete_message(self, ctx, input)
    }

    async fn delete_message_batch(
        &self,
        ctx: &RequestContext,
        input: types::DeleteMessageBatchRequest,
    ) -> Result<types::DeleteMessageBatchResult, ServiceError> {
        Sqs::delete_message_batch(self, ctx, input)
    }

    async fn delete_queue(&self, ctx: &RequestContext, input: types::DeleteQueueRequest) -> Result<(), ServiceError> {
        Sqs::delete_queue(self, ctx, input)
    }

    async fn get_queue_attributes(
        &self,
        ctx: &RequestContext,
        input: types::GetQueueAttributesRequest,
    ) -> Result<types::GetQueueAttributesResult, ServiceError> {
        Sqs::get_queue_attributes(self, ctx, input)
    }

    async fn get_queue_url(
        &self,
        ctx: &RequestContext,
        input: types::GetQueueUrlRequest,
    ) -> Result<types::GetQueueUrlResult, ServiceError> {
        Sqs::get_queue_url(self, ctx, input)
    }

    async fn list_dead_letter_source_queues(
        &self,
        ctx: &RequestContext,
        input: types::ListDeadLetterSourceQueuesRequest,
    ) -> Result<types::ListDeadLetterSourceQueuesResult, ServiceError> {
        Sqs::list_dead_letter_source_queues(self, ctx, input)
    }

    async fn list_message_move_tasks(
        &self,
        ctx: &RequestContext,
        input: types::ListMessageMoveTasksRequest,
    ) -> Result<types::ListMessageMoveTasksResult, ServiceError> {
        Sqs::list_message_move_tasks(self, ctx, input)
    }

    async fn list_queue_tags(
        &self,
        ctx: &RequestContext,
        input: types::ListQueueTagsRequest,
    ) -> Result<types::ListQueueTagsResult, ServiceError> {
        Sqs::list_queue_tags(self, ctx, input)
    }

    async fn list_queues(
        &self,
        ctx: &RequestContext,
        input: types::ListQueuesRequest,
    ) -> Result<types::ListQueuesResult, ServiceError> {
        Sqs::list_queues(self, ctx, input)
    }

    async fn purge_queue(&self, ctx: &RequestContext, input: types::PurgeQueueRequest) -> Result<(), ServiceError> {
        Sqs::purge_queue(self, ctx, input)
    }

    async fn receive_message(
        &self,
        ctx: &RequestContext,
        input: types::ReceiveMessageRequest,
    ) -> Result<types::ReceiveMessageResult, ServiceError> {
        Sqs::receive_message(self, ctx, input).await
    }

    async fn remove_permission(
        &self,
        ctx: &RequestContext,
        input: types::RemovePermissionRequest,
    ) -> Result<(), ServiceError> {
        Sqs::remove_permission(self, ctx, input)
    }

    async fn send_message(
        &self,
        ctx: &RequestContext,
        input: types::SendMessageRequest,
    ) -> Result<types::SendMessageResult, ServiceError> {
        Sqs::send_message(self, ctx, input)
    }

    async fn send_message_batch(
        &self,
        ctx: &RequestContext,
        input: types::SendMessageBatchRequest,
    ) -> Result<types::SendMessageBatchResult, ServiceError> {
        Sqs::send_message_batch(self, ctx, input)
    }

    async fn set_queue_attributes(
        &self,
        ctx: &RequestContext,
        input: types::SetQueueAttributesRequest,
    ) -> Result<(), ServiceError> {
        Sqs::set_queue_attributes(self, ctx, input)
    }

    async fn start_message_move_task(
        &self,
        ctx: &RequestContext,
        input: types::StartMessageMoveTaskRequest,
    ) -> Result<types::StartMessageMoveTaskResult, ServiceError> {
        Sqs::start_message_move_task(self, ctx, input)
    }

    async fn tag_queue(&self, ctx: &RequestContext, input: types::TagQueueRequest) -> Result<(), ServiceError> {
        Sqs::tag_queue(self, ctx, input)
    }

    async fn untag_queue(&self, ctx: &RequestContext, input: types::UntagQueueRequest) -> Result<(), ServiceError> {
        Sqs::untag_queue(self, ctx, input)
    }
}

//! The generated `Handler`, forwarding to the operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::BedrockRuntime;

#[async_trait::async_trait]
impl Handler for BedrockRuntime {
    async fn apply_guardrail(
        &self,
        ctx: &RequestContext,
        input: types::ApplyGuardrailRequest,
    ) -> Result<types::ApplyGuardrailResponse, ServiceError> {
        BedrockRuntime::apply_guardrail(self, ctx, input).await
    }

    async fn converse(
        &self,
        ctx: &RequestContext,
        input: types::ConverseRequest,
    ) -> Result<types::ConverseResponse, ServiceError> {
        BedrockRuntime::converse(self, ctx, input).await
    }

    async fn converse_stream(
        &self,
        ctx: &RequestContext,
        input: types::ConverseStreamRequest,
    ) -> Result<types::ConverseStreamResponse, ServiceError> {
        BedrockRuntime::converse_stream(self, ctx, input).await
    }

    async fn count_tokens(
        &self,
        ctx: &RequestContext,
        input: types::CountTokensRequest,
    ) -> Result<types::CountTokensResponse, ServiceError> {
        BedrockRuntime::count_tokens(self, ctx, input).await
    }

    async fn get_async_invoke(
        &self,
        ctx: &RequestContext,
        input: types::GetAsyncInvokeRequest,
    ) -> Result<types::GetAsyncInvokeResponse, ServiceError> {
        BedrockRuntime::get_async_invoke(self, ctx, input).await
    }

    async fn invoke_model(
        &self,
        ctx: &RequestContext,
        input: types::InvokeModelRequest,
    ) -> Result<types::InvokeModelResponse, ServiceError> {
        BedrockRuntime::invoke_model(self, ctx, input).await
    }

    async fn invoke_model_with_response_stream(
        &self,
        ctx: &RequestContext,
        input: types::InvokeModelWithResponseStreamRequest,
    ) -> Result<types::InvokeModelWithResponseStreamResponse, ServiceError> {
        BedrockRuntime::invoke_model_with_response_stream(self, ctx, input).await
    }

    async fn list_async_invokes(
        &self,
        ctx: &RequestContext,
        input: types::ListAsyncInvokesRequest,
    ) -> Result<types::ListAsyncInvokesResponse, ServiceError> {
        BedrockRuntime::list_async_invokes(self, ctx, input).await
    }

    async fn start_async_invoke(
        &self,
        ctx: &RequestContext,
        input: types::StartAsyncInvokeRequest,
    ) -> Result<types::StartAsyncInvokeResponse, ServiceError> {
        BedrockRuntime::start_async_invoke(self, ctx, input).await
    }
}

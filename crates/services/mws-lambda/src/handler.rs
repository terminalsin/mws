//! Wires the generated `Handler` trait to the operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::Lambda;

#[async_trait::async_trait]
impl Handler for Lambda {
    async fn add_layer_version_permission(
        &self,
        ctx: &RequestContext,
        input: types::AddLayerVersionPermissionRequest,
    ) -> Result<types::AddLayerVersionPermissionResponse, ServiceError> {
        Lambda::add_layer_version_permission(self, ctx, input).await
    }
    async fn add_permission(
        &self,
        ctx: &RequestContext,
        input: types::AddPermissionRequest,
    ) -> Result<types::AddPermissionResponse, ServiceError> {
        Lambda::add_permission(self, ctx, input).await
    }
    async fn create_alias(
        &self,
        ctx: &RequestContext,
        input: types::CreateAliasRequest,
    ) -> Result<types::AliasConfiguration, ServiceError> {
        Lambda::create_alias(self, ctx, input).await
    }
    async fn create_code_signing_config(
        &self,
        ctx: &RequestContext,
        input: types::CreateCodeSigningConfigRequest,
    ) -> Result<types::CreateCodeSigningConfigResponse, ServiceError> {
        Lambda::create_code_signing_config(self, ctx, input).await
    }
    async fn create_event_source_mapping(
        &self,
        ctx: &RequestContext,
        input: types::CreateEventSourceMappingRequest,
    ) -> Result<types::EventSourceMappingConfiguration, ServiceError> {
        Lambda::create_event_source_mapping(self, ctx, input).await
    }
    async fn create_function(
        &self,
        ctx: &RequestContext,
        input: types::CreateFunctionRequest,
    ) -> Result<types::FunctionConfiguration, ServiceError> {
        Lambda::create_function(self, ctx, input).await
    }
    async fn create_function_url_config(
        &self,
        ctx: &RequestContext,
        input: types::CreateFunctionUrlConfigRequest,
    ) -> Result<types::CreateFunctionUrlConfigResponse, ServiceError> {
        Lambda::create_function_url_config(self, ctx, input).await
    }
    async fn delete_alias(&self, ctx: &RequestContext, input: types::DeleteAliasRequest) -> Result<(), ServiceError> {
        Lambda::delete_alias(self, ctx, input).await
    }
    async fn delete_code_signing_config(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCodeSigningConfigRequest,
    ) -> Result<types::DeleteCodeSigningConfigResponse, ServiceError> {
        Lambda::delete_code_signing_config(self, ctx, input).await
    }
    async fn delete_event_source_mapping(
        &self,
        ctx: &RequestContext,
        input: types::DeleteEventSourceMappingRequest,
    ) -> Result<types::EventSourceMappingConfiguration, ServiceError> {
        Lambda::delete_event_source_mapping(self, ctx, input).await
    }
    async fn delete_function(
        &self,
        ctx: &RequestContext,
        input: types::DeleteFunctionRequest,
    ) -> Result<types::DeleteFunctionResponse, ServiceError> {
        Lambda::delete_function(self, ctx, input).await
    }
    async fn delete_function_code_signing_config(
        &self,
        ctx: &RequestContext,
        input: types::DeleteFunctionCodeSigningConfigRequest,
    ) -> Result<(), ServiceError> {
        Lambda::delete_function_code_signing_config(self, ctx, input).await
    }
    async fn delete_function_concurrency(
        &self,
        ctx: &RequestContext,
        input: types::DeleteFunctionConcurrencyRequest,
    ) -> Result<(), ServiceError> {
        Lambda::delete_function_concurrency(self, ctx, input).await
    }
    async fn delete_function_event_invoke_config(
        &self,
        ctx: &RequestContext,
        input: types::DeleteFunctionEventInvokeConfigRequest,
    ) -> Result<(), ServiceError> {
        Lambda::delete_function_event_invoke_config(self, ctx, input).await
    }
    async fn delete_function_url_config(
        &self,
        ctx: &RequestContext,
        input: types::DeleteFunctionUrlConfigRequest,
    ) -> Result<(), ServiceError> {
        Lambda::delete_function_url_config(self, ctx, input).await
    }
    async fn delete_layer_version(
        &self,
        ctx: &RequestContext,
        input: types::DeleteLayerVersionRequest,
    ) -> Result<(), ServiceError> {
        Lambda::delete_layer_version(self, ctx, input).await
    }
    async fn delete_provisioned_concurrency_config(
        &self,
        ctx: &RequestContext,
        input: types::DeleteProvisionedConcurrencyConfigRequest,
    ) -> Result<(), ServiceError> {
        Lambda::delete_provisioned_concurrency_config(self, ctx, input).await
    }
    async fn get_account_settings(
        &self,
        ctx: &RequestContext,
        input: types::GetAccountSettingsRequest,
    ) -> Result<types::GetAccountSettingsResponse, ServiceError> {
        Lambda::get_account_settings(self, ctx, input).await
    }
    async fn get_alias(
        &self,
        ctx: &RequestContext,
        input: types::GetAliasRequest,
    ) -> Result<types::AliasConfiguration, ServiceError> {
        Lambda::get_alias(self, ctx, input).await
    }
    async fn get_code_signing_config(
        &self,
        ctx: &RequestContext,
        input: types::GetCodeSigningConfigRequest,
    ) -> Result<types::GetCodeSigningConfigResponse, ServiceError> {
        Lambda::get_code_signing_config(self, ctx, input).await
    }
    async fn get_event_source_mapping(
        &self,
        ctx: &RequestContext,
        input: types::GetEventSourceMappingRequest,
    ) -> Result<types::EventSourceMappingConfiguration, ServiceError> {
        Lambda::get_event_source_mapping(self, ctx, input).await
    }
    async fn get_function(
        &self,
        ctx: &RequestContext,
        input: types::GetFunctionRequest,
    ) -> Result<types::GetFunctionResponse, ServiceError> {
        Lambda::get_function(self, ctx, input).await
    }
    async fn get_function_code_signing_config(
        &self,
        ctx: &RequestContext,
        input: types::GetFunctionCodeSigningConfigRequest,
    ) -> Result<types::GetFunctionCodeSigningConfigResponse, ServiceError> {
        Lambda::get_function_code_signing_config(self, ctx, input).await
    }
    async fn get_function_concurrency(
        &self,
        ctx: &RequestContext,
        input: types::GetFunctionConcurrencyRequest,
    ) -> Result<types::GetFunctionConcurrencyResponse, ServiceError> {
        Lambda::get_function_concurrency(self, ctx, input).await
    }
    async fn get_function_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetFunctionConfigurationRequest,
    ) -> Result<types::FunctionConfiguration, ServiceError> {
        Lambda::get_function_configuration(self, ctx, input).await
    }
    async fn get_function_event_invoke_config(
        &self,
        ctx: &RequestContext,
        input: types::GetFunctionEventInvokeConfigRequest,
    ) -> Result<types::FunctionEventInvokeConfig, ServiceError> {
        Lambda::get_function_event_invoke_config(self, ctx, input).await
    }
    async fn get_function_recursion_config(
        &self,
        ctx: &RequestContext,
        input: types::GetFunctionRecursionConfigRequest,
    ) -> Result<types::GetFunctionRecursionConfigResponse, ServiceError> {
        Lambda::get_function_recursion_config(self, ctx, input).await
    }
    async fn get_function_url_config(
        &self,
        ctx: &RequestContext,
        input: types::GetFunctionUrlConfigRequest,
    ) -> Result<types::GetFunctionUrlConfigResponse, ServiceError> {
        Lambda::get_function_url_config(self, ctx, input).await
    }
    async fn get_layer_version(
        &self,
        ctx: &RequestContext,
        input: types::GetLayerVersionRequest,
    ) -> Result<types::GetLayerVersionResponse, ServiceError> {
        Lambda::get_layer_version(self, ctx, input).await
    }
    async fn get_layer_version_by_arn(
        &self,
        ctx: &RequestContext,
        input: types::GetLayerVersionByArnRequest,
    ) -> Result<types::GetLayerVersionResponse, ServiceError> {
        Lambda::get_layer_version_by_arn(self, ctx, input).await
    }
    async fn get_layer_version_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetLayerVersionPolicyRequest,
    ) -> Result<types::GetLayerVersionPolicyResponse, ServiceError> {
        Lambda::get_layer_version_policy(self, ctx, input).await
    }
    async fn get_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetPolicyRequest,
    ) -> Result<types::GetPolicyResponse, ServiceError> {
        Lambda::get_policy(self, ctx, input).await
    }
    async fn get_provisioned_concurrency_config(
        &self,
        ctx: &RequestContext,
        input: types::GetProvisionedConcurrencyConfigRequest,
    ) -> Result<types::GetProvisionedConcurrencyConfigResponse, ServiceError> {
        Lambda::get_provisioned_concurrency_config(self, ctx, input).await
    }
    async fn get_runtime_management_config(
        &self,
        ctx: &RequestContext,
        input: types::GetRuntimeManagementConfigRequest,
    ) -> Result<types::GetRuntimeManagementConfigResponse, ServiceError> {
        Lambda::get_runtime_management_config(self, ctx, input).await
    }
    async fn invoke(
        &self,
        ctx: &RequestContext,
        input: types::InvocationRequest,
    ) -> Result<types::InvocationResponse, ServiceError> {
        Lambda::invoke(self, ctx, input).await
    }
    async fn invoke_async(
        &self,
        ctx: &RequestContext,
        input: types::InvokeAsyncRequest,
    ) -> Result<types::InvokeAsyncResponse, ServiceError> {
        Lambda::invoke_async(self, ctx, input).await
    }
    async fn invoke_with_response_stream(
        &self,
        ctx: &RequestContext,
        input: types::InvokeWithResponseStreamRequest,
    ) -> Result<types::InvokeWithResponseStreamResponse, ServiceError> {
        Lambda::invoke_with_response_stream(self, ctx, input).await
    }
    async fn list_aliases(
        &self,
        ctx: &RequestContext,
        input: types::ListAliasesRequest,
    ) -> Result<types::ListAliasesResponse, ServiceError> {
        Lambda::list_aliases(self, ctx, input).await
    }
    async fn list_code_signing_configs(
        &self,
        ctx: &RequestContext,
        input: types::ListCodeSigningConfigsRequest,
    ) -> Result<types::ListCodeSigningConfigsResponse, ServiceError> {
        Lambda::list_code_signing_configs(self, ctx, input).await
    }
    async fn list_event_source_mappings(
        &self,
        ctx: &RequestContext,
        input: types::ListEventSourceMappingsRequest,
    ) -> Result<types::ListEventSourceMappingsResponse, ServiceError> {
        Lambda::list_event_source_mappings(self, ctx, input).await
    }
    async fn list_function_event_invoke_configs(
        &self,
        ctx: &RequestContext,
        input: types::ListFunctionEventInvokeConfigsRequest,
    ) -> Result<types::ListFunctionEventInvokeConfigsResponse, ServiceError> {
        Lambda::list_function_event_invoke_configs(self, ctx, input).await
    }
    async fn list_function_url_configs(
        &self,
        ctx: &RequestContext,
        input: types::ListFunctionUrlConfigsRequest,
    ) -> Result<types::ListFunctionUrlConfigsResponse, ServiceError> {
        Lambda::list_function_url_configs(self, ctx, input).await
    }
    async fn list_functions(
        &self,
        ctx: &RequestContext,
        input: types::ListFunctionsRequest,
    ) -> Result<types::ListFunctionsResponse, ServiceError> {
        Lambda::list_functions(self, ctx, input).await
    }
    async fn list_functions_by_code_signing_config(
        &self,
        ctx: &RequestContext,
        input: types::ListFunctionsByCodeSigningConfigRequest,
    ) -> Result<types::ListFunctionsByCodeSigningConfigResponse, ServiceError> {
        Lambda::list_functions_by_code_signing_config(self, ctx, input).await
    }
    async fn list_layer_versions(
        &self,
        ctx: &RequestContext,
        input: types::ListLayerVersionsRequest,
    ) -> Result<types::ListLayerVersionsResponse, ServiceError> {
        Lambda::list_layer_versions(self, ctx, input).await
    }
    async fn list_layers(
        &self,
        ctx: &RequestContext,
        input: types::ListLayersRequest,
    ) -> Result<types::ListLayersResponse, ServiceError> {
        Lambda::list_layers(self, ctx, input).await
    }
    async fn list_provisioned_concurrency_configs(
        &self,
        ctx: &RequestContext,
        input: types::ListProvisionedConcurrencyConfigsRequest,
    ) -> Result<types::ListProvisionedConcurrencyConfigsResponse, ServiceError> {
        Lambda::list_provisioned_concurrency_configs(self, ctx, input).await
    }
    async fn list_tags(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsRequest,
    ) -> Result<types::ListTagsResponse, ServiceError> {
        Lambda::list_tags(self, ctx, input).await
    }
    async fn list_versions_by_function(
        &self,
        ctx: &RequestContext,
        input: types::ListVersionsByFunctionRequest,
    ) -> Result<types::ListVersionsByFunctionResponse, ServiceError> {
        Lambda::list_versions_by_function(self, ctx, input).await
    }
    async fn publish_layer_version(
        &self,
        ctx: &RequestContext,
        input: types::PublishLayerVersionRequest,
    ) -> Result<types::PublishLayerVersionResponse, ServiceError> {
        Lambda::publish_layer_version(self, ctx, input).await
    }
    async fn publish_version(
        &self,
        ctx: &RequestContext,
        input: types::PublishVersionRequest,
    ) -> Result<types::FunctionConfiguration, ServiceError> {
        Lambda::publish_version(self, ctx, input).await
    }
    async fn put_function_code_signing_config(
        &self,
        ctx: &RequestContext,
        input: types::PutFunctionCodeSigningConfigRequest,
    ) -> Result<types::PutFunctionCodeSigningConfigResponse, ServiceError> {
        Lambda::put_function_code_signing_config(self, ctx, input).await
    }
    async fn put_function_concurrency(
        &self,
        ctx: &RequestContext,
        input: types::PutFunctionConcurrencyRequest,
    ) -> Result<types::Concurrency, ServiceError> {
        Lambda::put_function_concurrency(self, ctx, input).await
    }
    async fn put_function_event_invoke_config(
        &self,
        ctx: &RequestContext,
        input: types::PutFunctionEventInvokeConfigRequest,
    ) -> Result<types::FunctionEventInvokeConfig, ServiceError> {
        Lambda::put_function_event_invoke_config(self, ctx, input).await
    }
    async fn put_function_recursion_config(
        &self,
        ctx: &RequestContext,
        input: types::PutFunctionRecursionConfigRequest,
    ) -> Result<types::PutFunctionRecursionConfigResponse, ServiceError> {
        Lambda::put_function_recursion_config(self, ctx, input).await
    }
    async fn put_provisioned_concurrency_config(
        &self,
        ctx: &RequestContext,
        input: types::PutProvisionedConcurrencyConfigRequest,
    ) -> Result<types::PutProvisionedConcurrencyConfigResponse, ServiceError> {
        Lambda::put_provisioned_concurrency_config(self, ctx, input).await
    }
    async fn put_runtime_management_config(
        &self,
        ctx: &RequestContext,
        input: types::PutRuntimeManagementConfigRequest,
    ) -> Result<types::PutRuntimeManagementConfigResponse, ServiceError> {
        Lambda::put_runtime_management_config(self, ctx, input).await
    }
    async fn remove_layer_version_permission(
        &self,
        ctx: &RequestContext,
        input: types::RemoveLayerVersionPermissionRequest,
    ) -> Result<(), ServiceError> {
        Lambda::remove_layer_version_permission(self, ctx, input).await
    }
    async fn remove_permission(
        &self,
        ctx: &RequestContext,
        input: types::RemovePermissionRequest,
    ) -> Result<(), ServiceError> {
        Lambda::remove_permission(self, ctx, input).await
    }
    async fn tag_resource(&self, ctx: &RequestContext, input: types::TagResourceRequest) -> Result<(), ServiceError> {
        Lambda::tag_resource(self, ctx, input).await
    }
    async fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<(), ServiceError> {
        Lambda::untag_resource(self, ctx, input).await
    }
    async fn update_alias(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAliasRequest,
    ) -> Result<types::AliasConfiguration, ServiceError> {
        Lambda::update_alias(self, ctx, input).await
    }
    async fn update_code_signing_config(
        &self,
        ctx: &RequestContext,
        input: types::UpdateCodeSigningConfigRequest,
    ) -> Result<types::UpdateCodeSigningConfigResponse, ServiceError> {
        Lambda::update_code_signing_config(self, ctx, input).await
    }
    async fn update_event_source_mapping(
        &self,
        ctx: &RequestContext,
        input: types::UpdateEventSourceMappingRequest,
    ) -> Result<types::EventSourceMappingConfiguration, ServiceError> {
        Lambda::update_event_source_mapping(self, ctx, input).await
    }
    async fn update_function_code(
        &self,
        ctx: &RequestContext,
        input: types::UpdateFunctionCodeRequest,
    ) -> Result<types::FunctionConfiguration, ServiceError> {
        Lambda::update_function_code(self, ctx, input).await
    }
    async fn update_function_configuration(
        &self,
        ctx: &RequestContext,
        input: types::UpdateFunctionConfigurationRequest,
    ) -> Result<types::FunctionConfiguration, ServiceError> {
        Lambda::update_function_configuration(self, ctx, input).await
    }
    async fn update_function_event_invoke_config(
        &self,
        ctx: &RequestContext,
        input: types::UpdateFunctionEventInvokeConfigRequest,
    ) -> Result<types::FunctionEventInvokeConfig, ServiceError> {
        Lambda::update_function_event_invoke_config(self, ctx, input).await
    }
    async fn update_function_url_config(
        &self,
        ctx: &RequestContext,
        input: types::UpdateFunctionUrlConfigRequest,
    ) -> Result<types::UpdateFunctionUrlConfigResponse, ServiceError> {
        Lambda::update_function_url_config(self, ctx, input).await
    }
    async fn checkpoint_durable_execution(
        &self,
        ctx: &RequestContext,
        input: types::CheckpointDurableExecutionRequest,
    ) -> Result<types::CheckpointDurableExecutionResponse, ServiceError> {
        Lambda::checkpoint_durable_execution(self, ctx, input).await
    }
    async fn create_capacity_provider(
        &self,
        ctx: &RequestContext,
        input: types::CreateCapacityProviderRequest,
    ) -> Result<types::CreateCapacityProviderResponse, ServiceError> {
        Lambda::create_capacity_provider(self, ctx, input).await
    }
    async fn delete_capacity_provider(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCapacityProviderRequest,
    ) -> Result<types::DeleteCapacityProviderResponse, ServiceError> {
        Lambda::delete_capacity_provider(self, ctx, input).await
    }
    async fn delete_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteResourcePolicyRequest,
    ) -> Result<(), ServiceError> {
        Lambda::delete_resource_policy(self, ctx, input).await
    }
    async fn get_capacity_provider(
        &self,
        ctx: &RequestContext,
        input: types::GetCapacityProviderRequest,
    ) -> Result<types::GetCapacityProviderResponse, ServiceError> {
        Lambda::get_capacity_provider(self, ctx, input).await
    }
    async fn get_durable_execution(
        &self,
        ctx: &RequestContext,
        input: types::GetDurableExecutionRequest,
    ) -> Result<types::GetDurableExecutionResponse, ServiceError> {
        Lambda::get_durable_execution(self, ctx, input).await
    }
    async fn get_durable_execution_history(
        &self,
        ctx: &RequestContext,
        input: types::GetDurableExecutionHistoryRequest,
    ) -> Result<types::GetDurableExecutionHistoryResponse, ServiceError> {
        Lambda::get_durable_execution_history(self, ctx, input).await
    }
    async fn get_durable_execution_state(
        &self,
        ctx: &RequestContext,
        input: types::GetDurableExecutionStateRequest,
    ) -> Result<types::GetDurableExecutionStateResponse, ServiceError> {
        Lambda::get_durable_execution_state(self, ctx, input).await
    }
    async fn get_function_scaling_config(
        &self,
        ctx: &RequestContext,
        input: types::GetFunctionScalingConfigRequest,
    ) -> Result<types::GetFunctionScalingConfigResponse, ServiceError> {
        Lambda::get_function_scaling_config(self, ctx, input).await
    }
    async fn get_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetResourcePolicyRequest,
    ) -> Result<types::GetResourcePolicyResponse, ServiceError> {
        Lambda::get_resource_policy(self, ctx, input).await
    }
    async fn list_capacity_providers(
        &self,
        ctx: &RequestContext,
        input: types::ListCapacityProvidersRequest,
    ) -> Result<types::ListCapacityProvidersResponse, ServiceError> {
        Lambda::list_capacity_providers(self, ctx, input).await
    }
    async fn list_durable_executions_by_function(
        &self,
        ctx: &RequestContext,
        input: types::ListDurableExecutionsByFunctionRequest,
    ) -> Result<types::ListDurableExecutionsByFunctionResponse, ServiceError> {
        Lambda::list_durable_executions_by_function(self, ctx, input).await
    }
    async fn list_function_versions_by_capacity_provider(
        &self,
        ctx: &RequestContext,
        input: types::ListFunctionVersionsByCapacityProviderRequest,
    ) -> Result<types::ListFunctionVersionsByCapacityProviderResponse, ServiceError> {
        Lambda::list_function_versions_by_capacity_provider(self, ctx, input).await
    }
    async fn put_function_scaling_config(
        &self,
        ctx: &RequestContext,
        input: types::PutFunctionScalingConfigRequest,
    ) -> Result<types::PutFunctionScalingConfigResponse, ServiceError> {
        Lambda::put_function_scaling_config(self, ctx, input).await
    }
    async fn put_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutResourcePolicyRequest,
    ) -> Result<types::PutResourcePolicyResponse, ServiceError> {
        Lambda::put_resource_policy(self, ctx, input).await
    }
    async fn send_durable_execution_callback_failure(
        &self,
        ctx: &RequestContext,
        input: types::SendDurableExecutionCallbackFailureRequest,
    ) -> Result<types::SendDurableExecutionCallbackFailureResponse, ServiceError> {
        Lambda::send_durable_execution_callback_failure(self, ctx, input).await
    }
    async fn send_durable_execution_callback_heartbeat(
        &self,
        ctx: &RequestContext,
        input: types::SendDurableExecutionCallbackHeartbeatRequest,
    ) -> Result<types::SendDurableExecutionCallbackHeartbeatResponse, ServiceError> {
        Lambda::send_durable_execution_callback_heartbeat(self, ctx, input).await
    }
    async fn send_durable_execution_callback_success(
        &self,
        ctx: &RequestContext,
        input: types::SendDurableExecutionCallbackSuccessRequest,
    ) -> Result<types::SendDurableExecutionCallbackSuccessResponse, ServiceError> {
        Lambda::send_durable_execution_callback_success(self, ctx, input).await
    }
    async fn stop_durable_execution(
        &self,
        ctx: &RequestContext,
        input: types::StopDurableExecutionRequest,
    ) -> Result<types::StopDurableExecutionResponse, ServiceError> {
        Lambda::stop_durable_execution(self, ctx, input).await
    }
    async fn update_capacity_provider(
        &self,
        ctx: &RequestContext,
        input: types::UpdateCapacityProviderRequest,
    ) -> Result<types::UpdateCapacityProviderResponse, ServiceError> {
        Lambda::update_capacity_provider(self, ctx, input).await
    }
}

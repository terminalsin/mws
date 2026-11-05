//! Wires the generated `Handler` trait to the operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::Bedrock;

#[async_trait::async_trait]
impl Handler for Bedrock {
    async fn batch_delete_advanced_prompt_optimization_job(
        &self,
        ctx: &RequestContext,
        input: types::BatchDeleteAdvancedPromptOptimizationJobRequest,
    ) -> Result<types::BatchDeleteAdvancedPromptOptimizationJobResponse, ServiceError> {
        Bedrock::batch_delete_advanced_prompt_optimization_job(self, ctx, input)
    }
    async fn batch_delete_evaluation_job(
        &self,
        ctx: &RequestContext,
        input: types::BatchDeleteEvaluationJobRequest,
    ) -> Result<types::BatchDeleteEvaluationJobResponse, ServiceError> {
        Bedrock::batch_delete_evaluation_job(self, ctx, input)
    }
    async fn cancel_automated_reasoning_policy_build_workflow(
        &self,
        ctx: &RequestContext,
        input: types::CancelAutomatedReasoningPolicyBuildWorkflowRequest,
    ) -> Result<types::CancelAutomatedReasoningPolicyBuildWorkflowResponse, ServiceError> {
        Bedrock::cancel_automated_reasoning_policy_build_workflow(self, ctx, input)
    }
    async fn create_advanced_prompt_optimization_job(
        &self,
        ctx: &RequestContext,
        input: types::CreateAdvancedPromptOptimizationJobRequest,
    ) -> Result<types::CreateAdvancedPromptOptimizationJobResponse, ServiceError> {
        Bedrock::create_advanced_prompt_optimization_job(self, ctx, input)
    }
    async fn create_automated_reasoning_policy(
        &self,
        ctx: &RequestContext,
        input: types::CreateAutomatedReasoningPolicyRequest,
    ) -> Result<types::CreateAutomatedReasoningPolicyResponse, ServiceError> {
        Bedrock::create_automated_reasoning_policy(self, ctx, input)
    }
    async fn create_automated_reasoning_policy_test_case(
        &self,
        ctx: &RequestContext,
        input: types::CreateAutomatedReasoningPolicyTestCaseRequest,
    ) -> Result<types::CreateAutomatedReasoningPolicyTestCaseResponse, ServiceError> {
        Bedrock::create_automated_reasoning_policy_test_case(self, ctx, input)
    }
    async fn create_automated_reasoning_policy_version(
        &self,
        ctx: &RequestContext,
        input: types::CreateAutomatedReasoningPolicyVersionRequest,
    ) -> Result<types::CreateAutomatedReasoningPolicyVersionResponse, ServiceError> {
        Bedrock::create_automated_reasoning_policy_version(self, ctx, input)
    }
    async fn create_custom_model(
        &self,
        ctx: &RequestContext,
        input: types::CreateCustomModelRequest,
    ) -> Result<types::CreateCustomModelResponse, ServiceError> {
        Bedrock::create_custom_model(self, ctx, input)
    }
    async fn create_custom_model_deployment(
        &self,
        ctx: &RequestContext,
        input: types::CreateCustomModelDeploymentRequest,
    ) -> Result<types::CreateCustomModelDeploymentResponse, ServiceError> {
        Bedrock::create_custom_model_deployment(self, ctx, input)
    }
    async fn create_evaluation_job(
        &self,
        ctx: &RequestContext,
        input: types::CreateEvaluationJobRequest,
    ) -> Result<types::CreateEvaluationJobResponse, ServiceError> {
        Bedrock::create_evaluation_job(self, ctx, input)
    }
    async fn create_foundation_model_agreement(
        &self,
        ctx: &RequestContext,
        input: types::CreateFoundationModelAgreementRequest,
    ) -> Result<types::CreateFoundationModelAgreementResponse, ServiceError> {
        Bedrock::create_foundation_model_agreement(self, ctx, input)
    }
    async fn create_guardrail(
        &self,
        ctx: &RequestContext,
        input: types::CreateGuardrailRequest,
    ) -> Result<types::CreateGuardrailResponse, ServiceError> {
        Bedrock::create_guardrail(self, ctx, input)
    }
    async fn create_guardrail_version(
        &self,
        ctx: &RequestContext,
        input: types::CreateGuardrailVersionRequest,
    ) -> Result<types::CreateGuardrailVersionResponse, ServiceError> {
        Bedrock::create_guardrail_version(self, ctx, input)
    }
    async fn create_inference_profile(
        &self,
        ctx: &RequestContext,
        input: types::CreateInferenceProfileRequest,
    ) -> Result<types::CreateInferenceProfileResponse, ServiceError> {
        Bedrock::create_inference_profile(self, ctx, input)
    }
    async fn create_marketplace_model_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::CreateMarketplaceModelEndpointRequest,
    ) -> Result<types::CreateMarketplaceModelEndpointResponse, ServiceError> {
        Bedrock::create_marketplace_model_endpoint(self, ctx, input)
    }
    async fn create_model_copy_job(
        &self,
        ctx: &RequestContext,
        input: types::CreateModelCopyJobRequest,
    ) -> Result<types::CreateModelCopyJobResponse, ServiceError> {
        Bedrock::create_model_copy_job(self, ctx, input)
    }
    async fn create_model_customization_job(
        &self,
        ctx: &RequestContext,
        input: types::CreateModelCustomizationJobRequest,
    ) -> Result<types::CreateModelCustomizationJobResponse, ServiceError> {
        Bedrock::create_model_customization_job(self, ctx, input)
    }
    async fn create_model_import_job(
        &self,
        ctx: &RequestContext,
        input: types::CreateModelImportJobRequest,
    ) -> Result<types::CreateModelImportJobResponse, ServiceError> {
        Bedrock::create_model_import_job(self, ctx, input)
    }
    async fn create_model_invocation_job(
        &self,
        ctx: &RequestContext,
        input: types::CreateModelInvocationJobRequest,
    ) -> Result<types::CreateModelInvocationJobResponse, ServiceError> {
        Bedrock::create_model_invocation_job(self, ctx, input)
    }
    async fn create_prompt_router(
        &self,
        ctx: &RequestContext,
        input: types::CreatePromptRouterRequest,
    ) -> Result<types::CreatePromptRouterResponse, ServiceError> {
        Bedrock::create_prompt_router(self, ctx, input)
    }
    async fn create_provisioned_model_throughput(
        &self,
        ctx: &RequestContext,
        input: types::CreateProvisionedModelThroughputRequest,
    ) -> Result<types::CreateProvisionedModelThroughputResponse, ServiceError> {
        Bedrock::create_provisioned_model_throughput(self, ctx, input)
    }
    async fn delete_automated_reasoning_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAutomatedReasoningPolicyRequest,
    ) -> Result<types::DeleteAutomatedReasoningPolicyResponse, ServiceError> {
        Bedrock::delete_automated_reasoning_policy(self, ctx, input)
    }
    async fn delete_automated_reasoning_policy_build_workflow(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAutomatedReasoningPolicyBuildWorkflowRequest,
    ) -> Result<types::DeleteAutomatedReasoningPolicyBuildWorkflowResponse, ServiceError> {
        Bedrock::delete_automated_reasoning_policy_build_workflow(self, ctx, input)
    }
    async fn delete_automated_reasoning_policy_test_case(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAutomatedReasoningPolicyTestCaseRequest,
    ) -> Result<types::DeleteAutomatedReasoningPolicyTestCaseResponse, ServiceError> {
        Bedrock::delete_automated_reasoning_policy_test_case(self, ctx, input)
    }
    async fn delete_custom_model(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCustomModelRequest,
    ) -> Result<types::DeleteCustomModelResponse, ServiceError> {
        Bedrock::delete_custom_model(self, ctx, input)
    }
    async fn delete_custom_model_deployment(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCustomModelDeploymentRequest,
    ) -> Result<types::DeleteCustomModelDeploymentResponse, ServiceError> {
        Bedrock::delete_custom_model_deployment(self, ctx, input)
    }
    async fn delete_enforced_guardrail_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DeleteEnforcedGuardrailConfigurationRequest,
    ) -> Result<types::DeleteEnforcedGuardrailConfigurationResponse, ServiceError> {
        Bedrock::delete_enforced_guardrail_configuration(self, ctx, input)
    }
    async fn delete_foundation_model_agreement(
        &self,
        ctx: &RequestContext,
        input: types::DeleteFoundationModelAgreementRequest,
    ) -> Result<types::DeleteFoundationModelAgreementResponse, ServiceError> {
        Bedrock::delete_foundation_model_agreement(self, ctx, input)
    }
    async fn delete_guardrail(
        &self,
        ctx: &RequestContext,
        input: types::DeleteGuardrailRequest,
    ) -> Result<types::DeleteGuardrailResponse, ServiceError> {
        Bedrock::delete_guardrail(self, ctx, input)
    }
    async fn delete_imported_model(
        &self,
        ctx: &RequestContext,
        input: types::DeleteImportedModelRequest,
    ) -> Result<types::DeleteImportedModelResponse, ServiceError> {
        Bedrock::delete_imported_model(self, ctx, input)
    }
    async fn delete_inference_profile(
        &self,
        ctx: &RequestContext,
        input: types::DeleteInferenceProfileRequest,
    ) -> Result<types::DeleteInferenceProfileResponse, ServiceError> {
        Bedrock::delete_inference_profile(self, ctx, input)
    }
    async fn delete_marketplace_model_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::DeleteMarketplaceModelEndpointRequest,
    ) -> Result<types::DeleteMarketplaceModelEndpointResponse, ServiceError> {
        Bedrock::delete_marketplace_model_endpoint(self, ctx, input)
    }
    async fn delete_model_invocation_logging_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DeleteModelInvocationLoggingConfigurationRequest,
    ) -> Result<types::DeleteModelInvocationLoggingConfigurationResponse, ServiceError> {
        Bedrock::delete_model_invocation_logging_configuration(self, ctx, input)
    }
    async fn delete_prompt_router(
        &self,
        ctx: &RequestContext,
        input: types::DeletePromptRouterRequest,
    ) -> Result<types::DeletePromptRouterResponse, ServiceError> {
        Bedrock::delete_prompt_router(self, ctx, input)
    }
    async fn delete_provisioned_model_throughput(
        &self,
        ctx: &RequestContext,
        input: types::DeleteProvisionedModelThroughputRequest,
    ) -> Result<types::DeleteProvisionedModelThroughputResponse, ServiceError> {
        Bedrock::delete_provisioned_model_throughput(self, ctx, input)
    }
    async fn delete_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteResourcePolicyRequest,
    ) -> Result<types::DeleteResourcePolicyResponse, ServiceError> {
        Bedrock::delete_resource_policy(self, ctx, input)
    }
    async fn deregister_marketplace_model_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::DeregisterMarketplaceModelEndpointRequest,
    ) -> Result<types::DeregisterMarketplaceModelEndpointResponse, ServiceError> {
        Bedrock::deregister_marketplace_model_endpoint(self, ctx, input)
    }
    async fn export_automated_reasoning_policy_version(
        &self,
        ctx: &RequestContext,
        input: types::ExportAutomatedReasoningPolicyVersionRequest,
    ) -> Result<types::ExportAutomatedReasoningPolicyVersionResponse, ServiceError> {
        Bedrock::export_automated_reasoning_policy_version(self, ctx, input)
    }
    async fn get_account_data_retention(
        &self,
        ctx: &RequestContext,
        input: types::GetAccountDataRetentionRequest,
    ) -> Result<types::GetAccountDataRetentionResponse, ServiceError> {
        Bedrock::get_account_data_retention(self, ctx, input)
    }
    async fn get_advanced_prompt_optimization_job(
        &self,
        ctx: &RequestContext,
        input: types::GetAdvancedPromptOptimizationJobRequest,
    ) -> Result<types::GetAdvancedPromptOptimizationJobResponse, ServiceError> {
        Bedrock::get_advanced_prompt_optimization_job(self, ctx, input)
    }
    async fn get_automated_reasoning_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetAutomatedReasoningPolicyRequest,
    ) -> Result<types::GetAutomatedReasoningPolicyResponse, ServiceError> {
        Bedrock::get_automated_reasoning_policy(self, ctx, input)
    }
    async fn get_automated_reasoning_policy_annotations(
        &self,
        ctx: &RequestContext,
        input: types::GetAutomatedReasoningPolicyAnnotationsRequest,
    ) -> Result<types::GetAutomatedReasoningPolicyAnnotationsResponse, ServiceError> {
        Bedrock::get_automated_reasoning_policy_annotations(self, ctx, input)
    }
    async fn get_automated_reasoning_policy_build_workflow(
        &self,
        ctx: &RequestContext,
        input: types::GetAutomatedReasoningPolicyBuildWorkflowRequest,
    ) -> Result<types::GetAutomatedReasoningPolicyBuildWorkflowResponse, ServiceError> {
        Bedrock::get_automated_reasoning_policy_build_workflow(self, ctx, input)
    }
    async fn get_automated_reasoning_policy_build_workflow_result_assets(
        &self,
        ctx: &RequestContext,
        input: types::GetAutomatedReasoningPolicyBuildWorkflowResultAssetsRequest,
    ) -> Result<types::GetAutomatedReasoningPolicyBuildWorkflowResultAssetsResponse, ServiceError> {
        Bedrock::get_automated_reasoning_policy_build_workflow_result_assets(self, ctx, input)
    }
    async fn get_automated_reasoning_policy_next_scenario(
        &self,
        ctx: &RequestContext,
        input: types::GetAutomatedReasoningPolicyNextScenarioRequest,
    ) -> Result<types::GetAutomatedReasoningPolicyNextScenarioResponse, ServiceError> {
        Bedrock::get_automated_reasoning_policy_next_scenario(self, ctx, input)
    }
    async fn get_automated_reasoning_policy_test_case(
        &self,
        ctx: &RequestContext,
        input: types::GetAutomatedReasoningPolicyTestCaseRequest,
    ) -> Result<types::GetAutomatedReasoningPolicyTestCaseResponse, ServiceError> {
        Bedrock::get_automated_reasoning_policy_test_case(self, ctx, input)
    }
    async fn get_automated_reasoning_policy_test_result(
        &self,
        ctx: &RequestContext,
        input: types::GetAutomatedReasoningPolicyTestResultRequest,
    ) -> Result<types::GetAutomatedReasoningPolicyTestResultResponse, ServiceError> {
        Bedrock::get_automated_reasoning_policy_test_result(self, ctx, input)
    }
    async fn get_custom_model(
        &self,
        ctx: &RequestContext,
        input: types::GetCustomModelRequest,
    ) -> Result<types::GetCustomModelResponse, ServiceError> {
        Bedrock::get_custom_model(self, ctx, input)
    }
    async fn get_custom_model_deployment(
        &self,
        ctx: &RequestContext,
        input: types::GetCustomModelDeploymentRequest,
    ) -> Result<types::GetCustomModelDeploymentResponse, ServiceError> {
        Bedrock::get_custom_model_deployment(self, ctx, input)
    }
    async fn get_evaluation_job(
        &self,
        ctx: &RequestContext,
        input: types::GetEvaluationJobRequest,
    ) -> Result<types::GetEvaluationJobResponse, ServiceError> {
        Bedrock::get_evaluation_job(self, ctx, input)
    }
    async fn get_foundation_model(
        &self,
        ctx: &RequestContext,
        input: types::GetFoundationModelRequest,
    ) -> Result<types::GetFoundationModelResponse, ServiceError> {
        Bedrock::get_foundation_model(self, ctx, input)
    }
    async fn get_foundation_model_availability(
        &self,
        ctx: &RequestContext,
        input: types::GetFoundationModelAvailabilityRequest,
    ) -> Result<types::GetFoundationModelAvailabilityResponse, ServiceError> {
        Bedrock::get_foundation_model_availability(self, ctx, input)
    }
    async fn get_guardrail(
        &self,
        ctx: &RequestContext,
        input: types::GetGuardrailRequest,
    ) -> Result<types::GetGuardrailResponse, ServiceError> {
        Bedrock::get_guardrail(self, ctx, input)
    }
    async fn get_imported_model(
        &self,
        ctx: &RequestContext,
        input: types::GetImportedModelRequest,
    ) -> Result<types::GetImportedModelResponse, ServiceError> {
        Bedrock::get_imported_model(self, ctx, input)
    }
    async fn get_inference_profile(
        &self,
        ctx: &RequestContext,
        input: types::GetInferenceProfileRequest,
    ) -> Result<types::GetInferenceProfileResponse, ServiceError> {
        Bedrock::get_inference_profile(self, ctx, input)
    }
    async fn get_marketplace_model_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::GetMarketplaceModelEndpointRequest,
    ) -> Result<types::GetMarketplaceModelEndpointResponse, ServiceError> {
        Bedrock::get_marketplace_model_endpoint(self, ctx, input)
    }
    async fn get_model_copy_job(
        &self,
        ctx: &RequestContext,
        input: types::GetModelCopyJobRequest,
    ) -> Result<types::GetModelCopyJobResponse, ServiceError> {
        Bedrock::get_model_copy_job(self, ctx, input)
    }
    async fn get_model_customization_job(
        &self,
        ctx: &RequestContext,
        input: types::GetModelCustomizationJobRequest,
    ) -> Result<types::GetModelCustomizationJobResponse, ServiceError> {
        Bedrock::get_model_customization_job(self, ctx, input)
    }
    async fn get_model_import_job(
        &self,
        ctx: &RequestContext,
        input: types::GetModelImportJobRequest,
    ) -> Result<types::GetModelImportJobResponse, ServiceError> {
        Bedrock::get_model_import_job(self, ctx, input)
    }
    async fn get_model_invocation_job(
        &self,
        ctx: &RequestContext,
        input: types::GetModelInvocationJobRequest,
    ) -> Result<types::GetModelInvocationJobResponse, ServiceError> {
        Bedrock::get_model_invocation_job(self, ctx, input)
    }
    async fn get_model_invocation_logging_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetModelInvocationLoggingConfigurationRequest,
    ) -> Result<types::GetModelInvocationLoggingConfigurationResponse, ServiceError> {
        Bedrock::get_model_invocation_logging_configuration(self, ctx, input)
    }
    async fn get_prompt_router(
        &self,
        ctx: &RequestContext,
        input: types::GetPromptRouterRequest,
    ) -> Result<types::GetPromptRouterResponse, ServiceError> {
        Bedrock::get_prompt_router(self, ctx, input)
    }
    async fn get_provisioned_model_throughput(
        &self,
        ctx: &RequestContext,
        input: types::GetProvisionedModelThroughputRequest,
    ) -> Result<types::GetProvisionedModelThroughputResponse, ServiceError> {
        Bedrock::get_provisioned_model_throughput(self, ctx, input)
    }
    async fn get_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetResourcePolicyRequest,
    ) -> Result<types::GetResourcePolicyResponse, ServiceError> {
        Bedrock::get_resource_policy(self, ctx, input)
    }
    async fn get_use_case_for_model_access(
        &self,
        ctx: &RequestContext,
        input: types::GetUseCaseForModelAccessRequest,
    ) -> Result<types::GetUseCaseForModelAccessResponse, ServiceError> {
        Bedrock::get_use_case_for_model_access(self, ctx, input)
    }
    async fn list_advanced_prompt_optimization_jobs(
        &self,
        ctx: &RequestContext,
        input: types::ListAdvancedPromptOptimizationJobsRequest,
    ) -> Result<types::ListAdvancedPromptOptimizationJobsResponse, ServiceError> {
        Bedrock::list_advanced_prompt_optimization_jobs(self, ctx, input)
    }
    async fn list_automated_reasoning_policies(
        &self,
        ctx: &RequestContext,
        input: types::ListAutomatedReasoningPoliciesRequest,
    ) -> Result<types::ListAutomatedReasoningPoliciesResponse, ServiceError> {
        Bedrock::list_automated_reasoning_policies(self, ctx, input)
    }
    async fn list_automated_reasoning_policy_build_workflows(
        &self,
        ctx: &RequestContext,
        input: types::ListAutomatedReasoningPolicyBuildWorkflowsRequest,
    ) -> Result<types::ListAutomatedReasoningPolicyBuildWorkflowsResponse, ServiceError> {
        Bedrock::list_automated_reasoning_policy_build_workflows(self, ctx, input)
    }
    async fn list_automated_reasoning_policy_test_cases(
        &self,
        ctx: &RequestContext,
        input: types::ListAutomatedReasoningPolicyTestCasesRequest,
    ) -> Result<types::ListAutomatedReasoningPolicyTestCasesResponse, ServiceError> {
        Bedrock::list_automated_reasoning_policy_test_cases(self, ctx, input)
    }
    async fn list_automated_reasoning_policy_test_results(
        &self,
        ctx: &RequestContext,
        input: types::ListAutomatedReasoningPolicyTestResultsRequest,
    ) -> Result<types::ListAutomatedReasoningPolicyTestResultsResponse, ServiceError> {
        Bedrock::list_automated_reasoning_policy_test_results(self, ctx, input)
    }
    async fn list_custom_model_deployments(
        &self,
        ctx: &RequestContext,
        input: types::ListCustomModelDeploymentsRequest,
    ) -> Result<types::ListCustomModelDeploymentsResponse, ServiceError> {
        Bedrock::list_custom_model_deployments(self, ctx, input)
    }
    async fn list_custom_models(
        &self,
        ctx: &RequestContext,
        input: types::ListCustomModelsRequest,
    ) -> Result<types::ListCustomModelsResponse, ServiceError> {
        Bedrock::list_custom_models(self, ctx, input)
    }
    async fn list_enforced_guardrails_configuration(
        &self,
        ctx: &RequestContext,
        input: types::ListEnforcedGuardrailsConfigurationRequest,
    ) -> Result<types::ListEnforcedGuardrailsConfigurationResponse, ServiceError> {
        Bedrock::list_enforced_guardrails_configuration(self, ctx, input)
    }
    async fn list_evaluation_jobs(
        &self,
        ctx: &RequestContext,
        input: types::ListEvaluationJobsRequest,
    ) -> Result<types::ListEvaluationJobsResponse, ServiceError> {
        Bedrock::list_evaluation_jobs(self, ctx, input)
    }
    async fn list_foundation_model_agreement_offers(
        &self,
        ctx: &RequestContext,
        input: types::ListFoundationModelAgreementOffersRequest,
    ) -> Result<types::ListFoundationModelAgreementOffersResponse, ServiceError> {
        Bedrock::list_foundation_model_agreement_offers(self, ctx, input)
    }
    async fn list_foundation_models(
        &self,
        ctx: &RequestContext,
        input: types::ListFoundationModelsRequest,
    ) -> Result<types::ListFoundationModelsResponse, ServiceError> {
        Bedrock::list_foundation_models(self, ctx, input)
    }
    async fn list_guardrails(
        &self,
        ctx: &RequestContext,
        input: types::ListGuardrailsRequest,
    ) -> Result<types::ListGuardrailsResponse, ServiceError> {
        Bedrock::list_guardrails(self, ctx, input)
    }
    async fn list_imported_models(
        &self,
        ctx: &RequestContext,
        input: types::ListImportedModelsRequest,
    ) -> Result<types::ListImportedModelsResponse, ServiceError> {
        Bedrock::list_imported_models(self, ctx, input)
    }
    async fn list_inference_profiles(
        &self,
        ctx: &RequestContext,
        input: types::ListInferenceProfilesRequest,
    ) -> Result<types::ListInferenceProfilesResponse, ServiceError> {
        Bedrock::list_inference_profiles(self, ctx, input)
    }
    async fn list_marketplace_model_endpoints(
        &self,
        ctx: &RequestContext,
        input: types::ListMarketplaceModelEndpointsRequest,
    ) -> Result<types::ListMarketplaceModelEndpointsResponse, ServiceError> {
        Bedrock::list_marketplace_model_endpoints(self, ctx, input)
    }
    async fn list_model_copy_jobs(
        &self,
        ctx: &RequestContext,
        input: types::ListModelCopyJobsRequest,
    ) -> Result<types::ListModelCopyJobsResponse, ServiceError> {
        Bedrock::list_model_copy_jobs(self, ctx, input)
    }
    async fn list_model_customization_jobs(
        &self,
        ctx: &RequestContext,
        input: types::ListModelCustomizationJobsRequest,
    ) -> Result<types::ListModelCustomizationJobsResponse, ServiceError> {
        Bedrock::list_model_customization_jobs(self, ctx, input)
    }
    async fn list_model_import_jobs(
        &self,
        ctx: &RequestContext,
        input: types::ListModelImportJobsRequest,
    ) -> Result<types::ListModelImportJobsResponse, ServiceError> {
        Bedrock::list_model_import_jobs(self, ctx, input)
    }
    async fn list_model_invocation_jobs(
        &self,
        ctx: &RequestContext,
        input: types::ListModelInvocationJobsRequest,
    ) -> Result<types::ListModelInvocationJobsResponse, ServiceError> {
        Bedrock::list_model_invocation_jobs(self, ctx, input)
    }
    async fn list_prompt_routers(
        &self,
        ctx: &RequestContext,
        input: types::ListPromptRoutersRequest,
    ) -> Result<types::ListPromptRoutersResponse, ServiceError> {
        Bedrock::list_prompt_routers(self, ctx, input)
    }
    async fn list_provisioned_model_throughputs(
        &self,
        ctx: &RequestContext,
        input: types::ListProvisionedModelThroughputsRequest,
    ) -> Result<types::ListProvisionedModelThroughputsResponse, ServiceError> {
        Bedrock::list_provisioned_model_throughputs(self, ctx, input)
    }
    async fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        Bedrock::list_tags_for_resource(self, ctx, input)
    }
    async fn put_account_data_retention(
        &self,
        ctx: &RequestContext,
        input: types::PutAccountDataRetentionRequest,
    ) -> Result<types::PutAccountDataRetentionResponse, ServiceError> {
        Bedrock::put_account_data_retention(self, ctx, input)
    }
    async fn put_enforced_guardrail_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutEnforcedGuardrailConfigurationRequest,
    ) -> Result<types::PutEnforcedGuardrailConfigurationResponse, ServiceError> {
        Bedrock::put_enforced_guardrail_configuration(self, ctx, input)
    }
    async fn put_model_invocation_logging_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutModelInvocationLoggingConfigurationRequest,
    ) -> Result<types::PutModelInvocationLoggingConfigurationResponse, ServiceError> {
        Bedrock::put_model_invocation_logging_configuration(self, ctx, input)
    }
    async fn put_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutResourcePolicyRequest,
    ) -> Result<types::PutResourcePolicyResponse, ServiceError> {
        Bedrock::put_resource_policy(self, ctx, input)
    }
    async fn put_use_case_for_model_access(
        &self,
        ctx: &RequestContext,
        input: types::PutUseCaseForModelAccessRequest,
    ) -> Result<types::PutUseCaseForModelAccessResponse, ServiceError> {
        Bedrock::put_use_case_for_model_access(self, ctx, input)
    }
    async fn register_marketplace_model_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::RegisterMarketplaceModelEndpointRequest,
    ) -> Result<types::RegisterMarketplaceModelEndpointResponse, ServiceError> {
        Bedrock::register_marketplace_model_endpoint(self, ctx, input)
    }
    async fn start_automated_reasoning_policy_build_workflow(
        &self,
        ctx: &RequestContext,
        input: types::StartAutomatedReasoningPolicyBuildWorkflowRequest,
    ) -> Result<types::StartAutomatedReasoningPolicyBuildWorkflowResponse, ServiceError> {
        Bedrock::start_automated_reasoning_policy_build_workflow(self, ctx, input)
    }
    async fn start_automated_reasoning_policy_test_workflow(
        &self,
        ctx: &RequestContext,
        input: types::StartAutomatedReasoningPolicyTestWorkflowRequest,
    ) -> Result<types::StartAutomatedReasoningPolicyTestWorkflowResponse, ServiceError> {
        Bedrock::start_automated_reasoning_policy_test_workflow(self, ctx, input)
    }
    async fn stop_advanced_prompt_optimization_job(
        &self,
        ctx: &RequestContext,
        input: types::StopAdvancedPromptOptimizationJobRequest,
    ) -> Result<types::StopAdvancedPromptOptimizationJobResponse, ServiceError> {
        Bedrock::stop_advanced_prompt_optimization_job(self, ctx, input)
    }
    async fn stop_evaluation_job(
        &self,
        ctx: &RequestContext,
        input: types::StopEvaluationJobRequest,
    ) -> Result<types::StopEvaluationJobResponse, ServiceError> {
        Bedrock::stop_evaluation_job(self, ctx, input)
    }
    async fn stop_model_customization_job(
        &self,
        ctx: &RequestContext,
        input: types::StopModelCustomizationJobRequest,
    ) -> Result<types::StopModelCustomizationJobResponse, ServiceError> {
        Bedrock::stop_model_customization_job(self, ctx, input)
    }
    async fn stop_model_invocation_job(
        &self,
        ctx: &RequestContext,
        input: types::StopModelInvocationJobRequest,
    ) -> Result<types::StopModelInvocationJobResponse, ServiceError> {
        Bedrock::stop_model_invocation_job(self, ctx, input)
    }
    async fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<types::TagResourceResponse, ServiceError> {
        Bedrock::tag_resource(self, ctx, input)
    }
    async fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<types::UntagResourceResponse, ServiceError> {
        Bedrock::untag_resource(self, ctx, input)
    }
    async fn update_automated_reasoning_policy(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAutomatedReasoningPolicyRequest,
    ) -> Result<types::UpdateAutomatedReasoningPolicyResponse, ServiceError> {
        Bedrock::update_automated_reasoning_policy(self, ctx, input)
    }
    async fn update_automated_reasoning_policy_annotations(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAutomatedReasoningPolicyAnnotationsRequest,
    ) -> Result<types::UpdateAutomatedReasoningPolicyAnnotationsResponse, ServiceError> {
        Bedrock::update_automated_reasoning_policy_annotations(self, ctx, input)
    }
    async fn update_automated_reasoning_policy_test_case(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAutomatedReasoningPolicyTestCaseRequest,
    ) -> Result<types::UpdateAutomatedReasoningPolicyTestCaseResponse, ServiceError> {
        Bedrock::update_automated_reasoning_policy_test_case(self, ctx, input)
    }
    async fn update_custom_model_deployment(
        &self,
        ctx: &RequestContext,
        input: types::UpdateCustomModelDeploymentRequest,
    ) -> Result<types::UpdateCustomModelDeploymentResponse, ServiceError> {
        Bedrock::update_custom_model_deployment(self, ctx, input)
    }
    async fn update_guardrail(
        &self,
        ctx: &RequestContext,
        input: types::UpdateGuardrailRequest,
    ) -> Result<types::UpdateGuardrailResponse, ServiceError> {
        Bedrock::update_guardrail(self, ctx, input)
    }
    async fn update_marketplace_model_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::UpdateMarketplaceModelEndpointRequest,
    ) -> Result<types::UpdateMarketplaceModelEndpointResponse, ServiceError> {
        Bedrock::update_marketplace_model_endpoint(self, ctx, input)
    }
    async fn update_provisioned_model_throughput(
        &self,
        ctx: &RequestContext,
        input: types::UpdateProvisionedModelThroughputRequest,
    ) -> Result<types::UpdateProvisionedModelThroughputResponse, ServiceError> {
        Bedrock::update_provisioned_model_throughput(self, ctx, input)
    }
}

//! Wires the generated `Handler` trait to the operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::ImageBuilder;

#[async_trait::async_trait]
impl Handler for ImageBuilder {
    async fn cancel_image_creation(
        &self,
        ctx: &RequestContext,
        input: types::CancelImageCreationRequest,
    ) -> Result<types::CancelImageCreationResponse, ServiceError> {
        self.cancel_image_creation_op(ctx, input).await
    }
    async fn cancel_lifecycle_execution(
        &self,
        ctx: &RequestContext,
        input: types::CancelLifecycleExecutionRequest,
    ) -> Result<types::CancelLifecycleExecutionResponse, ServiceError> {
        self.cancel_lifecycle_execution_op(ctx, input).await
    }
    async fn create_component(
        &self,
        ctx: &RequestContext,
        input: types::CreateComponentRequest,
    ) -> Result<types::CreateComponentResponse, ServiceError> {
        self.create_component_op(ctx, input).await
    }
    async fn create_container_recipe(
        &self,
        ctx: &RequestContext,
        input: types::CreateContainerRecipeRequest,
    ) -> Result<types::CreateContainerRecipeResponse, ServiceError> {
        self.create_container_recipe_op(ctx, input).await
    }
    async fn create_distribution_configuration(
        &self,
        ctx: &RequestContext,
        input: types::CreateDistributionConfigurationRequest,
    ) -> Result<types::CreateDistributionConfigurationResponse, ServiceError> {
        self.create_distribution_configuration_op(ctx, input).await
    }
    async fn create_image(
        &self,
        ctx: &RequestContext,
        input: types::CreateImageRequest,
    ) -> Result<types::CreateImageResponse, ServiceError> {
        self.create_image_op(ctx, input).await
    }
    async fn create_image_pipeline(
        &self,
        ctx: &RequestContext,
        input: types::CreateImagePipelineRequest,
    ) -> Result<types::CreateImagePipelineResponse, ServiceError> {
        self.create_image_pipeline_op(ctx, input).await
    }
    async fn create_image_recipe(
        &self,
        ctx: &RequestContext,
        input: types::CreateImageRecipeRequest,
    ) -> Result<types::CreateImageRecipeResponse, ServiceError> {
        self.create_image_recipe_op(ctx, input).await
    }
    async fn create_infrastructure_configuration(
        &self,
        ctx: &RequestContext,
        input: types::CreateInfrastructureConfigurationRequest,
    ) -> Result<types::CreateInfrastructureConfigurationResponse, ServiceError> {
        self.create_infrastructure_configuration_op(ctx, input).await
    }
    async fn create_lifecycle_policy(
        &self,
        ctx: &RequestContext,
        input: types::CreateLifecyclePolicyRequest,
    ) -> Result<types::CreateLifecyclePolicyResponse, ServiceError> {
        self.create_lifecycle_policy_op(ctx, input).await
    }
    async fn create_workflow(
        &self,
        ctx: &RequestContext,
        input: types::CreateWorkflowRequest,
    ) -> Result<types::CreateWorkflowResponse, ServiceError> {
        self.create_workflow_op(ctx, input).await
    }
    async fn delete_component(
        &self,
        ctx: &RequestContext,
        input: types::DeleteComponentRequest,
    ) -> Result<types::DeleteComponentResponse, ServiceError> {
        self.delete_component_op(ctx, input)
    }
    async fn delete_container_recipe(
        &self,
        ctx: &RequestContext,
        input: types::DeleteContainerRecipeRequest,
    ) -> Result<types::DeleteContainerRecipeResponse, ServiceError> {
        self.delete_container_recipe_op(ctx, input)
    }
    async fn delete_distribution_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DeleteDistributionConfigurationRequest,
    ) -> Result<types::DeleteDistributionConfigurationResponse, ServiceError> {
        self.delete_distribution_configuration_op(ctx, input)
    }
    async fn delete_image(
        &self,
        ctx: &RequestContext,
        input: types::DeleteImageRequest,
    ) -> Result<types::DeleteImageResponse, ServiceError> {
        self.delete_image_op(ctx, input)
    }
    async fn delete_image_pipeline(
        &self,
        ctx: &RequestContext,
        input: types::DeleteImagePipelineRequest,
    ) -> Result<types::DeleteImagePipelineResponse, ServiceError> {
        self.delete_image_pipeline_op(ctx, input)
    }
    async fn delete_image_recipe(
        &self,
        ctx: &RequestContext,
        input: types::DeleteImageRecipeRequest,
    ) -> Result<types::DeleteImageRecipeResponse, ServiceError> {
        self.delete_image_recipe_op(ctx, input)
    }
    async fn delete_infrastructure_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DeleteInfrastructureConfigurationRequest,
    ) -> Result<types::DeleteInfrastructureConfigurationResponse, ServiceError> {
        self.delete_infrastructure_configuration_op(ctx, input)
    }
    async fn delete_lifecycle_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteLifecyclePolicyRequest,
    ) -> Result<types::DeleteLifecyclePolicyResponse, ServiceError> {
        self.delete_lifecycle_policy_op(ctx, input)
    }
    async fn delete_workflow(
        &self,
        ctx: &RequestContext,
        input: types::DeleteWorkflowRequest,
    ) -> Result<types::DeleteWorkflowResponse, ServiceError> {
        self.delete_workflow_op(ctx, input)
    }
    async fn distribute_image(
        &self,
        ctx: &RequestContext,
        input: types::DistributeImageRequest,
    ) -> Result<types::DistributeImageResponse, ServiceError> {
        self.distribute_image_op(ctx, input).await
    }
    async fn get_component(
        &self,
        ctx: &RequestContext,
        input: types::GetComponentRequest,
    ) -> Result<types::GetComponentResponse, ServiceError> {
        self.get_component_op(ctx, input)
    }
    async fn get_component_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetComponentPolicyRequest,
    ) -> Result<types::GetComponentPolicyResponse, ServiceError> {
        self.get_component_policy_op(ctx, input)
    }
    async fn get_container_recipe(
        &self,
        ctx: &RequestContext,
        input: types::GetContainerRecipeRequest,
    ) -> Result<types::GetContainerRecipeResponse, ServiceError> {
        self.get_container_recipe_op(ctx, input)
    }
    async fn get_container_recipe_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetContainerRecipePolicyRequest,
    ) -> Result<types::GetContainerRecipePolicyResponse, ServiceError> {
        self.get_container_recipe_policy_op(ctx, input)
    }
    async fn get_distribution_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetDistributionConfigurationRequest,
    ) -> Result<types::GetDistributionConfigurationResponse, ServiceError> {
        self.get_distribution_configuration_op(ctx, input)
    }
    async fn get_image(
        &self,
        ctx: &RequestContext,
        input: types::GetImageRequest,
    ) -> Result<types::GetImageResponse, ServiceError> {
        self.get_image_op(ctx, input)
    }
    async fn get_image_pipeline(
        &self,
        ctx: &RequestContext,
        input: types::GetImagePipelineRequest,
    ) -> Result<types::GetImagePipelineResponse, ServiceError> {
        self.get_image_pipeline_op(ctx, input)
    }
    async fn get_image_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetImagePolicyRequest,
    ) -> Result<types::GetImagePolicyResponse, ServiceError> {
        self.get_image_policy_op(ctx, input)
    }
    async fn get_image_recipe(
        &self,
        ctx: &RequestContext,
        input: types::GetImageRecipeRequest,
    ) -> Result<types::GetImageRecipeResponse, ServiceError> {
        self.get_image_recipe_op(ctx, input)
    }
    async fn get_image_recipe_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetImageRecipePolicyRequest,
    ) -> Result<types::GetImageRecipePolicyResponse, ServiceError> {
        self.get_image_recipe_policy_op(ctx, input)
    }
    async fn get_infrastructure_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetInfrastructureConfigurationRequest,
    ) -> Result<types::GetInfrastructureConfigurationResponse, ServiceError> {
        self.get_infrastructure_configuration_op(ctx, input)
    }
    async fn get_lifecycle_execution(
        &self,
        ctx: &RequestContext,
        input: types::GetLifecycleExecutionRequest,
    ) -> Result<types::GetLifecycleExecutionResponse, ServiceError> {
        self.get_lifecycle_execution_op(ctx, input)
    }
    async fn get_lifecycle_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetLifecyclePolicyRequest,
    ) -> Result<types::GetLifecyclePolicyResponse, ServiceError> {
        self.get_lifecycle_policy_op(ctx, input)
    }
    async fn get_marketplace_resource(
        &self,
        ctx: &RequestContext,
        input: types::GetMarketplaceResourceRequest,
    ) -> Result<types::GetMarketplaceResourceResponse, ServiceError> {
        self.get_marketplace_resource_op(ctx, input)
    }
    async fn get_workflow(
        &self,
        ctx: &RequestContext,
        input: types::GetWorkflowRequest,
    ) -> Result<types::GetWorkflowResponse, ServiceError> {
        self.get_workflow_op(ctx, input)
    }
    async fn get_workflow_execution(
        &self,
        ctx: &RequestContext,
        input: types::GetWorkflowExecutionRequest,
    ) -> Result<types::GetWorkflowExecutionResponse, ServiceError> {
        self.get_workflow_execution_op(ctx, input)
    }
    async fn get_workflow_step_execution(
        &self,
        ctx: &RequestContext,
        input: types::GetWorkflowStepExecutionRequest,
    ) -> Result<types::GetWorkflowStepExecutionResponse, ServiceError> {
        self.get_workflow_step_execution_op(ctx, input)
    }
    async fn import_component(
        &self,
        ctx: &RequestContext,
        input: types::ImportComponentRequest,
    ) -> Result<types::ImportComponentResponse, ServiceError> {
        self.import_component_op(ctx, input).await
    }
    async fn import_disk_image(
        &self,
        ctx: &RequestContext,
        input: types::ImportDiskImageRequest,
    ) -> Result<types::ImportDiskImageResponse, ServiceError> {
        self.import_disk_image_op(ctx, input).await
    }
    async fn import_vm_image(
        &self,
        ctx: &RequestContext,
        input: types::ImportVmImageRequest,
    ) -> Result<types::ImportVmImageResponse, ServiceError> {
        self.import_vm_image_op(ctx, input).await
    }
    async fn list_component_build_versions(
        &self,
        ctx: &RequestContext,
        input: types::ListComponentBuildVersionsRequest,
    ) -> Result<types::ListComponentBuildVersionsResponse, ServiceError> {
        self.list_component_build_versions_op(ctx, input)
    }
    async fn list_components(
        &self,
        ctx: &RequestContext,
        input: types::ListComponentsRequest,
    ) -> Result<types::ListComponentsResponse, ServiceError> {
        self.list_components_op(ctx, input)
    }
    async fn list_container_recipes(
        &self,
        ctx: &RequestContext,
        input: types::ListContainerRecipesRequest,
    ) -> Result<types::ListContainerRecipesResponse, ServiceError> {
        self.list_container_recipes_op(ctx, input)
    }
    async fn list_distribution_configurations(
        &self,
        ctx: &RequestContext,
        input: types::ListDistributionConfigurationsRequest,
    ) -> Result<types::ListDistributionConfigurationsResponse, ServiceError> {
        self.list_distribution_configurations_op(ctx, input)
    }
    async fn list_image_build_versions(
        &self,
        ctx: &RequestContext,
        input: types::ListImageBuildVersionsRequest,
    ) -> Result<types::ListImageBuildVersionsResponse, ServiceError> {
        self.list_image_build_versions_op(ctx, input)
    }
    async fn list_image_packages(
        &self,
        ctx: &RequestContext,
        input: types::ListImagePackagesRequest,
    ) -> Result<types::ListImagePackagesResponse, ServiceError> {
        self.list_image_packages_op(ctx, input)
    }
    async fn list_image_pipeline_images(
        &self,
        ctx: &RequestContext,
        input: types::ListImagePipelineImagesRequest,
    ) -> Result<types::ListImagePipelineImagesResponse, ServiceError> {
        self.list_image_pipeline_images_op(ctx, input)
    }
    async fn list_image_pipelines(
        &self,
        ctx: &RequestContext,
        input: types::ListImagePipelinesRequest,
    ) -> Result<types::ListImagePipelinesResponse, ServiceError> {
        self.list_image_pipelines_op(ctx, input)
    }
    async fn list_image_recipes(
        &self,
        ctx: &RequestContext,
        input: types::ListImageRecipesRequest,
    ) -> Result<types::ListImageRecipesResponse, ServiceError> {
        self.list_image_recipes_op(ctx, input)
    }
    async fn list_image_scan_finding_aggregations(
        &self,
        ctx: &RequestContext,
        input: types::ListImageScanFindingAggregationsRequest,
    ) -> Result<types::ListImageScanFindingAggregationsResponse, ServiceError> {
        self.list_image_scan_finding_aggregations_op(ctx, input)
    }
    async fn list_image_scan_findings(
        &self,
        ctx: &RequestContext,
        input: types::ListImageScanFindingsRequest,
    ) -> Result<types::ListImageScanFindingsResponse, ServiceError> {
        self.list_image_scan_findings_op(ctx, input)
    }
    async fn list_images(
        &self,
        ctx: &RequestContext,
        input: types::ListImagesRequest,
    ) -> Result<types::ListImagesResponse, ServiceError> {
        self.list_images_op(ctx, input)
    }
    async fn list_infrastructure_configurations(
        &self,
        ctx: &RequestContext,
        input: types::ListInfrastructureConfigurationsRequest,
    ) -> Result<types::ListInfrastructureConfigurationsResponse, ServiceError> {
        self.list_infrastructure_configurations_op(ctx, input)
    }
    async fn list_lifecycle_execution_resources(
        &self,
        ctx: &RequestContext,
        input: types::ListLifecycleExecutionResourcesRequest,
    ) -> Result<types::ListLifecycleExecutionResourcesResponse, ServiceError> {
        self.list_lifecycle_execution_resources_op(ctx, input)
    }
    async fn list_lifecycle_executions(
        &self,
        ctx: &RequestContext,
        input: types::ListLifecycleExecutionsRequest,
    ) -> Result<types::ListLifecycleExecutionsResponse, ServiceError> {
        self.list_lifecycle_executions_op(ctx, input)
    }
    async fn list_lifecycle_policies(
        &self,
        ctx: &RequestContext,
        input: types::ListLifecyclePoliciesRequest,
    ) -> Result<types::ListLifecyclePoliciesResponse, ServiceError> {
        self.list_lifecycle_policies_op(ctx, input)
    }
    async fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        self.list_tags_for_resource_op(ctx, input)
    }
    async fn list_waiting_workflow_steps(
        &self,
        ctx: &RequestContext,
        input: types::ListWaitingWorkflowStepsRequest,
    ) -> Result<types::ListWaitingWorkflowStepsResponse, ServiceError> {
        self.list_waiting_workflow_steps_op(ctx, input)
    }
    async fn list_workflow_build_versions(
        &self,
        ctx: &RequestContext,
        input: types::ListWorkflowBuildVersionsRequest,
    ) -> Result<types::ListWorkflowBuildVersionsResponse, ServiceError> {
        self.list_workflow_build_versions_op(ctx, input)
    }
    async fn list_workflow_executions(
        &self,
        ctx: &RequestContext,
        input: types::ListWorkflowExecutionsRequest,
    ) -> Result<types::ListWorkflowExecutionsResponse, ServiceError> {
        self.list_workflow_executions_op(ctx, input)
    }
    async fn list_workflow_step_executions(
        &self,
        ctx: &RequestContext,
        input: types::ListWorkflowStepExecutionsRequest,
    ) -> Result<types::ListWorkflowStepExecutionsResponse, ServiceError> {
        self.list_workflow_step_executions_op(ctx, input)
    }
    async fn list_workflows(
        &self,
        ctx: &RequestContext,
        input: types::ListWorkflowsRequest,
    ) -> Result<types::ListWorkflowsResponse, ServiceError> {
        self.list_workflows_op(ctx, input)
    }
    async fn put_component_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutComponentPolicyRequest,
    ) -> Result<types::PutComponentPolicyResponse, ServiceError> {
        self.put_component_policy_op(ctx, input)
    }
    async fn put_container_recipe_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutContainerRecipePolicyRequest,
    ) -> Result<types::PutContainerRecipePolicyResponse, ServiceError> {
        self.put_container_recipe_policy_op(ctx, input)
    }
    async fn put_image_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutImagePolicyRequest,
    ) -> Result<types::PutImagePolicyResponse, ServiceError> {
        self.put_image_policy_op(ctx, input)
    }
    async fn put_image_recipe_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutImageRecipePolicyRequest,
    ) -> Result<types::PutImageRecipePolicyResponse, ServiceError> {
        self.put_image_recipe_policy_op(ctx, input)
    }
    async fn retry_image(
        &self,
        ctx: &RequestContext,
        input: types::RetryImageRequest,
    ) -> Result<types::RetryImageResponse, ServiceError> {
        self.retry_image_op(ctx, input).await
    }
    async fn send_workflow_step_action(
        &self,
        ctx: &RequestContext,
        input: types::SendWorkflowStepActionRequest,
    ) -> Result<types::SendWorkflowStepActionResponse, ServiceError> {
        self.send_workflow_step_action_op(ctx, input).await
    }
    async fn start_image_pipeline_execution(
        &self,
        ctx: &RequestContext,
        input: types::StartImagePipelineExecutionRequest,
    ) -> Result<types::StartImagePipelineExecutionResponse, ServiceError> {
        self.start_image_pipeline_execution_op(ctx, input).await
    }
    async fn start_resource_state_update(
        &self,
        ctx: &RequestContext,
        input: types::StartResourceStateUpdateRequest,
    ) -> Result<types::StartResourceStateUpdateResponse, ServiceError> {
        self.start_resource_state_update_op(ctx, input).await
    }
    async fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<types::TagResourceResponse, ServiceError> {
        self.tag_resource_op(ctx, input)
    }
    async fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<types::UntagResourceResponse, ServiceError> {
        self.untag_resource_op(ctx, input)
    }
    async fn update_distribution_configuration(
        &self,
        ctx: &RequestContext,
        input: types::UpdateDistributionConfigurationRequest,
    ) -> Result<types::UpdateDistributionConfigurationResponse, ServiceError> {
        self.update_distribution_configuration_op(ctx, input).await
    }
    async fn update_image_pipeline(
        &self,
        ctx: &RequestContext,
        input: types::UpdateImagePipelineRequest,
    ) -> Result<types::UpdateImagePipelineResponse, ServiceError> {
        self.update_image_pipeline_op(ctx, input).await
    }
    async fn update_infrastructure_configuration(
        &self,
        ctx: &RequestContext,
        input: types::UpdateInfrastructureConfigurationRequest,
    ) -> Result<types::UpdateInfrastructureConfigurationResponse, ServiceError> {
        self.update_infrastructure_configuration_op(ctx, input).await
    }
    async fn update_lifecycle_policy(
        &self,
        ctx: &RequestContext,
        input: types::UpdateLifecyclePolicyRequest,
    ) -> Result<types::UpdateLifecyclePolicyResponse, ServiceError> {
        self.update_lifecycle_policy_op(ctx, input).await
    }
}

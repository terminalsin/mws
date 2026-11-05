//! The generated `Handler`, forwarding each operation to its implementation.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::Ecs;

#[async_trait::async_trait]
impl Handler for Ecs {
    async fn associate_gateway_with_cluster(
        &self,
        ctx: &RequestContext,
        input: types::AssociateGatewayWithClusterRequest,
    ) -> Result<types::AssociateGatewayWithClusterResponse, ServiceError> {
        self.associate_gateway_with_cluster_op(ctx, input)
    }
    async fn continue_service_deployment(
        &self,
        ctx: &RequestContext,
        input: types::ContinueServiceDeploymentRequest,
    ) -> Result<types::ContinueServiceDeploymentResponse, ServiceError> {
        self.continue_service_deployment_op(ctx, input)
    }
    async fn create_capacity_provider(
        &self,
        ctx: &RequestContext,
        input: types::CreateCapacityProviderRequest,
    ) -> Result<types::CreateCapacityProviderResponse, ServiceError> {
        self.create_capacity_provider_op(ctx, input)
    }
    async fn create_cluster(
        &self,
        ctx: &RequestContext,
        input: types::CreateClusterRequest,
    ) -> Result<types::CreateClusterResponse, ServiceError> {
        self.create_cluster_op(ctx, input)
    }
    async fn create_daemon(
        &self,
        ctx: &RequestContext,
        input: types::CreateDaemonRequest,
    ) -> Result<types::CreateDaemonResponse, ServiceError> {
        self.create_daemon_op(ctx, input)
    }
    async fn create_express_gateway_service(
        &self,
        ctx: &RequestContext,
        input: types::CreateExpressGatewayServiceRequest,
    ) -> Result<types::CreateExpressGatewayServiceResponse, ServiceError> {
        self.create_express_gateway_service_op(ctx, input).await
    }
    async fn create_gateway(
        &self,
        ctx: &RequestContext,
        input: types::CreateGatewayRequest,
    ) -> Result<types::CreateGatewayResponse, ServiceError> {
        self.create_gateway_op(ctx, input)
    }
    async fn create_service(
        &self,
        ctx: &RequestContext,
        input: types::CreateServiceRequest,
    ) -> Result<types::CreateServiceResponse, ServiceError> {
        self.create_service_op(ctx, input)
    }
    async fn create_task_set(
        &self,
        ctx: &RequestContext,
        input: types::CreateTaskSetRequest,
    ) -> Result<types::CreateTaskSetResponse, ServiceError> {
        self.create_task_set_op(ctx, input)
    }
    async fn delete_account_setting(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccountSettingRequest,
    ) -> Result<types::DeleteAccountSettingResponse, ServiceError> {
        self.delete_account_setting_op(ctx, input)
    }
    async fn delete_attributes(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAttributesRequest,
    ) -> Result<types::DeleteAttributesResponse, ServiceError> {
        self.delete_attributes_op(ctx, input)
    }
    async fn delete_capacity_provider(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCapacityProviderRequest,
    ) -> Result<types::DeleteCapacityProviderResponse, ServiceError> {
        self.delete_capacity_provider_op(ctx, input)
    }
    async fn delete_cluster(
        &self,
        ctx: &RequestContext,
        input: types::DeleteClusterRequest,
    ) -> Result<types::DeleteClusterResponse, ServiceError> {
        self.delete_cluster_op(ctx, input)
    }
    async fn delete_daemon(
        &self,
        ctx: &RequestContext,
        input: types::DeleteDaemonRequest,
    ) -> Result<types::DeleteDaemonResponse, ServiceError> {
        self.delete_daemon_op(ctx, input)
    }
    async fn delete_daemon_task_definition(
        &self,
        ctx: &RequestContext,
        input: types::DeleteDaemonTaskDefinitionRequest,
    ) -> Result<types::DeleteDaemonTaskDefinitionResponse, ServiceError> {
        self.delete_daemon_task_definition_op(ctx, input)
    }
    async fn delete_express_gateway_service(
        &self,
        ctx: &RequestContext,
        input: types::DeleteExpressGatewayServiceRequest,
    ) -> Result<types::DeleteExpressGatewayServiceResponse, ServiceError> {
        self.delete_express_gateway_service_op(ctx, input).await
    }
    async fn delete_gateway(
        &self,
        ctx: &RequestContext,
        input: types::DeleteGatewayRequest,
    ) -> Result<types::DeleteGatewayResponse, ServiceError> {
        self.delete_gateway_op(ctx, input)
    }
    async fn delete_service(
        &self,
        ctx: &RequestContext,
        input: types::DeleteServiceRequest,
    ) -> Result<types::DeleteServiceResponse, ServiceError> {
        self.delete_service_op(ctx, input)
    }
    async fn delete_task_definitions(
        &self,
        ctx: &RequestContext,
        input: types::DeleteTaskDefinitionsRequest,
    ) -> Result<types::DeleteTaskDefinitionsResponse, ServiceError> {
        self.delete_task_definitions_op(ctx, input)
    }
    async fn delete_task_set(
        &self,
        ctx: &RequestContext,
        input: types::DeleteTaskSetRequest,
    ) -> Result<types::DeleteTaskSetResponse, ServiceError> {
        self.delete_task_set_op(ctx, input)
    }
    async fn deregister_container_instance(
        &self,
        ctx: &RequestContext,
        input: types::DeregisterContainerInstanceRequest,
    ) -> Result<types::DeregisterContainerInstanceResponse, ServiceError> {
        self.deregister_container_instance_op(ctx, input)
    }
    async fn deregister_task_definition(
        &self,
        ctx: &RequestContext,
        input: types::DeregisterTaskDefinitionRequest,
    ) -> Result<types::DeregisterTaskDefinitionResponse, ServiceError> {
        self.deregister_task_definition_op(ctx, input)
    }
    async fn describe_capacity_providers(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCapacityProvidersRequest,
    ) -> Result<types::DescribeCapacityProvidersResponse, ServiceError> {
        self.describe_capacity_providers_op(ctx, input)
    }
    async fn describe_clusters(
        &self,
        ctx: &RequestContext,
        input: types::DescribeClustersRequest,
    ) -> Result<types::DescribeClustersResponse, ServiceError> {
        self.describe_clusters_op(ctx, input)
    }
    async fn describe_container_instances(
        &self,
        ctx: &RequestContext,
        input: types::DescribeContainerInstancesRequest,
    ) -> Result<types::DescribeContainerInstancesResponse, ServiceError> {
        self.describe_container_instances_op(ctx, input)
    }
    async fn describe_daemon(
        &self,
        ctx: &RequestContext,
        input: types::DescribeDaemonRequest,
    ) -> Result<types::DescribeDaemonResponse, ServiceError> {
        self.describe_daemon_op(ctx, input)
    }
    async fn describe_daemon_deployments(
        &self,
        ctx: &RequestContext,
        input: types::DescribeDaemonDeploymentsRequest,
    ) -> Result<types::DescribeDaemonDeploymentsResponse, ServiceError> {
        self.describe_daemon_deployments_op(ctx, input)
    }
    async fn describe_daemon_revisions(
        &self,
        ctx: &RequestContext,
        input: types::DescribeDaemonRevisionsRequest,
    ) -> Result<types::DescribeDaemonRevisionsResponse, ServiceError> {
        self.describe_daemon_revisions_op(ctx, input)
    }
    async fn describe_daemon_task_definition(
        &self,
        ctx: &RequestContext,
        input: types::DescribeDaemonTaskDefinitionRequest,
    ) -> Result<types::DescribeDaemonTaskDefinitionResponse, ServiceError> {
        self.describe_daemon_task_definition_op(ctx, input)
    }
    async fn describe_express_gateway_service(
        &self,
        ctx: &RequestContext,
        input: types::DescribeExpressGatewayServiceRequest,
    ) -> Result<types::DescribeExpressGatewayServiceResponse, ServiceError> {
        self.describe_express_gateway_service_op(ctx, input)
    }
    async fn describe_gateway(
        &self,
        ctx: &RequestContext,
        input: types::DescribeGatewayRequest,
    ) -> Result<types::DescribeGatewayResponse, ServiceError> {
        self.describe_gateway_op(ctx, input)
    }
    async fn describe_gateway_resources(
        &self,
        ctx: &RequestContext,
        input: types::DescribeGatewayResourcesRequest,
    ) -> Result<types::DescribeGatewayResourcesResponse, ServiceError> {
        self.describe_gateway_resources_op(ctx, input)
    }
    async fn describe_gateway_route(
        &self,
        ctx: &RequestContext,
        input: types::DescribeGatewayRouteRequest,
    ) -> Result<types::DescribeGatewayRouteResponse, ServiceError> {
        self.describe_gateway_route_op(ctx, input)
    }
    async fn describe_service_deployments(
        &self,
        ctx: &RequestContext,
        input: types::DescribeServiceDeploymentsRequest,
    ) -> Result<types::DescribeServiceDeploymentsResponse, ServiceError> {
        self.describe_service_deployments_op(ctx, input)
    }
    async fn describe_service_revisions(
        &self,
        ctx: &RequestContext,
        input: types::DescribeServiceRevisionsRequest,
    ) -> Result<types::DescribeServiceRevisionsResponse, ServiceError> {
        self.describe_service_revisions_op(ctx, input)
    }
    async fn describe_services(
        &self,
        ctx: &RequestContext,
        input: types::DescribeServicesRequest,
    ) -> Result<types::DescribeServicesResponse, ServiceError> {
        self.describe_services_op(ctx, input)
    }
    async fn describe_task_definition(
        &self,
        ctx: &RequestContext,
        input: types::DescribeTaskDefinitionRequest,
    ) -> Result<types::DescribeTaskDefinitionResponse, ServiceError> {
        self.describe_task_definition_op(ctx, input)
    }
    async fn describe_task_sets(
        &self,
        ctx: &RequestContext,
        input: types::DescribeTaskSetsRequest,
    ) -> Result<types::DescribeTaskSetsResponse, ServiceError> {
        self.describe_task_sets_op(ctx, input)
    }
    async fn describe_tasks(
        &self,
        ctx: &RequestContext,
        input: types::DescribeTasksRequest,
    ) -> Result<types::DescribeTasksResponse, ServiceError> {
        self.describe_tasks_op(ctx, input)
    }
    async fn disassociate_gateway_from_cluster(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateGatewayFromClusterRequest,
    ) -> Result<types::DisassociateGatewayFromClusterResponse, ServiceError> {
        self.disassociate_gateway_from_cluster_op(ctx, input)
    }
    async fn discover_poll_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::DiscoverPollEndpointRequest,
    ) -> Result<types::DiscoverPollEndpointResponse, ServiceError> {
        self.discover_poll_endpoint_op(ctx, input)
    }
    async fn execute_command(
        &self,
        ctx: &RequestContext,
        input: types::ExecuteCommandRequest,
    ) -> Result<types::ExecuteCommandResponse, ServiceError> {
        self.execute_command_op(ctx, input).await
    }
    async fn get_task_protection(
        &self,
        ctx: &RequestContext,
        input: types::GetTaskProtectionRequest,
    ) -> Result<types::GetTaskProtectionResponse, ServiceError> {
        self.get_task_protection_op(ctx, input)
    }
    async fn list_account_settings(
        &self,
        ctx: &RequestContext,
        input: types::ListAccountSettingsRequest,
    ) -> Result<types::ListAccountSettingsResponse, ServiceError> {
        self.list_account_settings_op(ctx, input)
    }
    async fn list_attributes(
        &self,
        ctx: &RequestContext,
        input: types::ListAttributesRequest,
    ) -> Result<types::ListAttributesResponse, ServiceError> {
        self.list_attributes_op(ctx, input)
    }
    async fn list_clusters(
        &self,
        ctx: &RequestContext,
        input: types::ListClustersRequest,
    ) -> Result<types::ListClustersResponse, ServiceError> {
        self.list_clusters_op(ctx, input)
    }
    async fn list_container_instances(
        &self,
        ctx: &RequestContext,
        input: types::ListContainerInstancesRequest,
    ) -> Result<types::ListContainerInstancesResponse, ServiceError> {
        self.list_container_instances_op(ctx, input)
    }
    async fn list_daemon_deployments(
        &self,
        ctx: &RequestContext,
        input: types::ListDaemonDeploymentsRequest,
    ) -> Result<types::ListDaemonDeploymentsResponse, ServiceError> {
        self.list_daemon_deployments_op(ctx, input)
    }
    async fn list_daemon_task_definitions(
        &self,
        ctx: &RequestContext,
        input: types::ListDaemonTaskDefinitionsRequest,
    ) -> Result<types::ListDaemonTaskDefinitionsResponse, ServiceError> {
        self.list_daemon_task_definitions_op(ctx, input)
    }
    async fn list_daemons(
        &self,
        ctx: &RequestContext,
        input: types::ListDaemonsRequest,
    ) -> Result<types::ListDaemonsResponse, ServiceError> {
        self.list_daemons_op(ctx, input)
    }
    async fn list_gateway_cluster_associations(
        &self,
        ctx: &RequestContext,
        input: types::ListGatewayClusterAssociationsRequest,
    ) -> Result<types::ListGatewayClusterAssociationsResponse, ServiceError> {
        self.list_gateway_cluster_associations_op(ctx, input)
    }
    async fn list_gateway_routes(
        &self,
        ctx: &RequestContext,
        input: types::ListGatewayRoutesRequest,
    ) -> Result<types::ListGatewayRoutesResponse, ServiceError> {
        self.list_gateway_routes_op(ctx, input)
    }
    async fn list_gateways(
        &self,
        ctx: &RequestContext,
        input: types::ListGatewaysRequest,
    ) -> Result<types::ListGatewaysResponse, ServiceError> {
        self.list_gateways_op(ctx, input)
    }
    async fn list_service_deployments(
        &self,
        ctx: &RequestContext,
        input: types::ListServiceDeploymentsRequest,
    ) -> Result<types::ListServiceDeploymentsResponse, ServiceError> {
        self.list_service_deployments_op(ctx, input)
    }
    async fn list_services(
        &self,
        ctx: &RequestContext,
        input: types::ListServicesRequest,
    ) -> Result<types::ListServicesResponse, ServiceError> {
        self.list_services_op(ctx, input)
    }
    async fn list_services_by_namespace(
        &self,
        ctx: &RequestContext,
        input: types::ListServicesByNamespaceRequest,
    ) -> Result<types::ListServicesByNamespaceResponse, ServiceError> {
        self.list_services_by_namespace_op(ctx, input)
    }
    async fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        self.list_tags_for_resource_op(ctx, input)
    }
    async fn list_task_definition_families(
        &self,
        ctx: &RequestContext,
        input: types::ListTaskDefinitionFamiliesRequest,
    ) -> Result<types::ListTaskDefinitionFamiliesResponse, ServiceError> {
        self.list_task_definition_families_op(ctx, input)
    }
    async fn list_task_definitions(
        &self,
        ctx: &RequestContext,
        input: types::ListTaskDefinitionsRequest,
    ) -> Result<types::ListTaskDefinitionsResponse, ServiceError> {
        self.list_task_definitions_op(ctx, input)
    }
    async fn list_tasks(
        &self,
        ctx: &RequestContext,
        input: types::ListTasksRequest,
    ) -> Result<types::ListTasksResponse, ServiceError> {
        self.list_tasks_op(ctx, input)
    }
    async fn put_account_setting(
        &self,
        ctx: &RequestContext,
        input: types::PutAccountSettingRequest,
    ) -> Result<types::PutAccountSettingResponse, ServiceError> {
        self.put_account_setting_op(ctx, input)
    }
    async fn put_account_setting_default(
        &self,
        ctx: &RequestContext,
        input: types::PutAccountSettingDefaultRequest,
    ) -> Result<types::PutAccountSettingDefaultResponse, ServiceError> {
        self.put_account_setting_default_op(ctx, input)
    }
    async fn put_attributes(
        &self,
        ctx: &RequestContext,
        input: types::PutAttributesRequest,
    ) -> Result<types::PutAttributesResponse, ServiceError> {
        self.put_attributes_op(ctx, input)
    }
    async fn put_cluster_capacity_providers(
        &self,
        ctx: &RequestContext,
        input: types::PutClusterCapacityProvidersRequest,
    ) -> Result<types::PutClusterCapacityProvidersResponse, ServiceError> {
        self.put_cluster_capacity_providers_op(ctx, input)
    }
    async fn register_container_instance(
        &self,
        ctx: &RequestContext,
        input: types::RegisterContainerInstanceRequest,
    ) -> Result<types::RegisterContainerInstanceResponse, ServiceError> {
        self.register_container_instance_op(ctx, input)
    }
    async fn register_daemon_task_definition(
        &self,
        ctx: &RequestContext,
        input: types::RegisterDaemonTaskDefinitionRequest,
    ) -> Result<types::RegisterDaemonTaskDefinitionResponse, ServiceError> {
        self.register_daemon_task_definition_op(ctx, input)
    }
    async fn register_task_definition(
        &self,
        ctx: &RequestContext,
        input: types::RegisterTaskDefinitionRequest,
    ) -> Result<types::RegisterTaskDefinitionResponse, ServiceError> {
        self.register_task_definition_op(ctx, input)
    }
    async fn run_task(
        &self,
        ctx: &RequestContext,
        input: types::RunTaskRequest,
    ) -> Result<types::RunTaskResponse, ServiceError> {
        self.run_task_op(ctx, input)
    }
    async fn start_task(
        &self,
        ctx: &RequestContext,
        input: types::StartTaskRequest,
    ) -> Result<types::StartTaskResponse, ServiceError> {
        self.start_task_op(ctx, input)
    }
    async fn stop_service_deployment(
        &self,
        ctx: &RequestContext,
        input: types::StopServiceDeploymentRequest,
    ) -> Result<types::StopServiceDeploymentResponse, ServiceError> {
        self.stop_service_deployment_op(ctx, input)
    }
    async fn stop_task(
        &self,
        ctx: &RequestContext,
        input: types::StopTaskRequest,
    ) -> Result<types::StopTaskResponse, ServiceError> {
        self.stop_task_op(ctx, input)
    }
    async fn submit_attachment_state_changes(
        &self,
        ctx: &RequestContext,
        input: types::SubmitAttachmentStateChangesRequest,
    ) -> Result<types::SubmitAttachmentStateChangesResponse, ServiceError> {
        self.submit_attachment_state_changes_op(ctx, input)
    }
    async fn submit_container_state_change(
        &self,
        ctx: &RequestContext,
        input: types::SubmitContainerStateChangeRequest,
    ) -> Result<types::SubmitContainerStateChangeResponse, ServiceError> {
        self.submit_container_state_change_op(ctx, input)
    }
    async fn submit_task_state_change(
        &self,
        ctx: &RequestContext,
        input: types::SubmitTaskStateChangeRequest,
    ) -> Result<types::SubmitTaskStateChangeResponse, ServiceError> {
        self.submit_task_state_change_op(ctx, input)
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
    async fn update_capacity_provider(
        &self,
        ctx: &RequestContext,
        input: types::UpdateCapacityProviderRequest,
    ) -> Result<types::UpdateCapacityProviderResponse, ServiceError> {
        self.update_capacity_provider_op(ctx, input)
    }
    async fn update_cluster(
        &self,
        ctx: &RequestContext,
        input: types::UpdateClusterRequest,
    ) -> Result<types::UpdateClusterResponse, ServiceError> {
        self.update_cluster_op(ctx, input)
    }
    async fn update_cluster_settings(
        &self,
        ctx: &RequestContext,
        input: types::UpdateClusterSettingsRequest,
    ) -> Result<types::UpdateClusterSettingsResponse, ServiceError> {
        self.update_cluster_settings_op(ctx, input)
    }
    async fn update_container_agent(
        &self,
        ctx: &RequestContext,
        input: types::UpdateContainerAgentRequest,
    ) -> Result<types::UpdateContainerAgentResponse, ServiceError> {
        self.update_container_agent_op(ctx, input)
    }
    async fn update_container_instances_state(
        &self,
        ctx: &RequestContext,
        input: types::UpdateContainerInstancesStateRequest,
    ) -> Result<types::UpdateContainerInstancesStateResponse, ServiceError> {
        self.update_container_instances_state_op(ctx, input)
    }
    async fn update_daemon(
        &self,
        ctx: &RequestContext,
        input: types::UpdateDaemonRequest,
    ) -> Result<types::UpdateDaemonResponse, ServiceError> {
        self.update_daemon_op(ctx, input)
    }
    async fn update_express_gateway_service(
        &self,
        ctx: &RequestContext,
        input: types::UpdateExpressGatewayServiceRequest,
    ) -> Result<types::UpdateExpressGatewayServiceResponse, ServiceError> {
        self.update_express_gateway_service_op(ctx, input)
    }
    async fn update_gateway(
        &self,
        ctx: &RequestContext,
        input: types::UpdateGatewayRequest,
    ) -> Result<types::UpdateGatewayResponse, ServiceError> {
        self.update_gateway_op(ctx, input)
    }
    async fn update_service(
        &self,
        ctx: &RequestContext,
        input: types::UpdateServiceRequest,
    ) -> Result<types::UpdateServiceResponse, ServiceError> {
        self.update_service_op(ctx, input)
    }
    async fn update_service_primary_task_set(
        &self,
        ctx: &RequestContext,
        input: types::UpdateServicePrimaryTaskSetRequest,
    ) -> Result<types::UpdateServicePrimaryTaskSetResponse, ServiceError> {
        self.update_service_primary_task_set_op(ctx, input)
    }
    async fn update_task_protection(
        &self,
        ctx: &RequestContext,
        input: types::UpdateTaskProtectionRequest,
    ) -> Result<types::UpdateTaskProtectionResponse, ServiceError> {
        self.update_task_protection_op(ctx, input)
    }
    async fn update_task_set(
        &self,
        ctx: &RequestContext,
        input: types::UpdateTaskSetRequest,
    ) -> Result<types::UpdateTaskSetResponse, ServiceError> {
        self.update_task_set_op(ctx, input)
    }
}

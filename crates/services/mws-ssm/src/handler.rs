//! Wires the generated `Handler` trait to the synchronous operations. The
//! operations not listed answer `NotImplemented`.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::Ssm;

macro_rules! delegate {
    ($($name:ident($input:ty) -> $output:ty;)*) => {
        $(
            fn $name<'life0, 'life1, 'async_trait>(
                &'life0 self,
                ctx: &'life1 RequestContext,
                input: $input,
            ) -> ::std::pin::Pin<Box<dyn ::std::future::Future<Output = Result<$output, ServiceError>> + Send + 'async_trait>>
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                Self: 'async_trait,
            {
                let result = Ssm::$name(self, ctx, input);
                Box::pin(async move { result })
            }
        )*
    };
}

macro_rules! delegate_async {
    ($($name:ident($input:ty) -> $output:ty;)*) => {
        $(
            fn $name<'life0, 'life1, 'async_trait>(
                &'life0 self,
                ctx: &'life1 RequestContext,
                input: $input,
            ) -> ::std::pin::Pin<Box<dyn ::std::future::Future<Output = Result<$output, ServiceError>> + Send + 'async_trait>>
            where
                'life0: 'async_trait,
                'life1: 'async_trait,
                Self: 'async_trait,
            {
                Box::pin(async move { Ssm::$name(self, ctx, input).await })
            }
        )*
    };
}

impl Handler for Ssm {
    delegate_async! {
        start_session(types::StartSessionRequest) -> types::StartSessionResponse;
        resume_session(types::ResumeSessionRequest) -> types::ResumeSessionResponse;
        get_access_token(types::GetAccessTokenRequest) -> types::GetAccessTokenResponse;
    }
    delegate! {
        describe_sessions(types::DescribeSessionsRequest) -> types::DescribeSessionsResponse;
        terminate_session(types::TerminateSessionRequest) -> types::TerminateSessionResponse;
        get_connection_status(types::GetConnectionStatusRequest) -> types::GetConnectionStatusResponse;
        start_access_request(types::StartAccessRequestRequest) -> types::StartAccessRequestResponse;
        create_cloud_connector(types::CreateCloudConnectorRequest) -> types::CreateCloudConnectorResult;
        get_cloud_connector(types::GetCloudConnectorRequest) -> types::GetCloudConnectorResult;
        list_cloud_connectors(types::ListCloudConnectorsRequest) -> types::ListCloudConnectorsResult;
        update_cloud_connector(types::UpdateCloudConnectorRequest) -> types::UpdateCloudConnectorResult;
        delete_cloud_connector(types::DeleteCloudConnectorRequest) -> types::DeleteCloudConnectorResult;
        validate_cloud_connector(types::ValidateCloudConnectorRequest) -> types::ValidateCloudConnectorResult;
        start_automation_execution(types::StartAutomationExecutionRequest) -> types::StartAutomationExecutionResult;
        start_change_request_execution(types::StartChangeRequestExecutionRequest) -> types::StartChangeRequestExecutionResult;
        get_automation_execution(types::GetAutomationExecutionRequest) -> types::GetAutomationExecutionResult;
        describe_automation_executions(types::DescribeAutomationExecutionsRequest) -> types::DescribeAutomationExecutionsResult;
        describe_automation_step_executions(types::DescribeAutomationStepExecutionsRequest) -> types::DescribeAutomationStepExecutionsResult;
        stop_automation_execution(types::StopAutomationExecutionRequest) -> types::StopAutomationExecutionResult;
        send_automation_signal(types::SendAutomationSignalRequest) -> types::SendAutomationSignalResult;
        start_execution_preview(types::StartExecutionPreviewRequest) -> types::StartExecutionPreviewResponse;
        get_execution_preview(types::GetExecutionPreviewRequest) -> types::GetExecutionPreviewResponse;
        create_ops_item(types::CreateOpsItemRequest) -> types::CreateOpsItemResponse;
        get_ops_item(types::GetOpsItemRequest) -> types::GetOpsItemResponse;
        update_ops_item(types::UpdateOpsItemRequest) -> types::UpdateOpsItemResponse;
        delete_ops_item(types::DeleteOpsItemRequest) -> types::DeleteOpsItemResponse;
        describe_ops_items(types::DescribeOpsItemsRequest) -> types::DescribeOpsItemsResponse;
        associate_ops_item_related_item(types::AssociateOpsItemRelatedItemRequest) -> types::AssociateOpsItemRelatedItemResponse;
        disassociate_ops_item_related_item(types::DisassociateOpsItemRelatedItemRequest) -> types::DisassociateOpsItemRelatedItemResponse;
        list_ops_item_related_items(types::ListOpsItemRelatedItemsRequest) -> types::ListOpsItemRelatedItemsResponse;
        list_ops_item_events(types::ListOpsItemEventsRequest) -> types::ListOpsItemEventsResponse;
        get_ops_summary(types::GetOpsSummaryRequest) -> types::GetOpsSummaryResult;
        create_ops_metadata(types::CreateOpsMetadataRequest) -> types::CreateOpsMetadataResult;
        get_ops_metadata(types::GetOpsMetadataRequest) -> types::GetOpsMetadataResult;
        update_ops_metadata(types::UpdateOpsMetadataRequest) -> types::UpdateOpsMetadataResult;
        delete_ops_metadata(types::DeleteOpsMetadataRequest) -> types::DeleteOpsMetadataResult;
        list_ops_metadata(types::ListOpsMetadataRequest) -> types::ListOpsMetadataResult;
        list_nodes(types::ListNodesRequest) -> types::ListNodesResult;
        list_nodes_summary(types::ListNodesSummaryRequest) -> types::ListNodesSummaryResult;
        describe_instance_properties(types::DescribeInstancePropertiesRequest) -> types::DescribeInstancePropertiesResult;
        get_calendar_state(types::GetCalendarStateRequest) -> types::GetCalendarStateResponse;
        update_document_metadata(types::UpdateDocumentMetadataRequest) -> types::UpdateDocumentMetadataResponse;
        list_document_metadata_history(types::ListDocumentMetadataHistoryRequest) -> types::ListDocumentMetadataHistoryResponse;
        update_managed_instance_role(types::UpdateManagedInstanceRoleRequest) -> types::UpdateManagedInstanceRoleResult;
        create_resource_data_sync(types::CreateResourceDataSyncRequest) -> types::CreateResourceDataSyncResult;
        delete_resource_data_sync(types::DeleteResourceDataSyncRequest) -> types::DeleteResourceDataSyncResult;
        list_resource_data_sync(types::ListResourceDataSyncRequest) -> types::ListResourceDataSyncResult;
        update_resource_data_sync(types::UpdateResourceDataSyncRequest) -> types::UpdateResourceDataSyncResult;
        put_inventory(types::PutInventoryRequest) -> types::PutInventoryResult;
        get_inventory(types::GetInventoryRequest) -> types::GetInventoryResult;
        get_inventory_schema(types::GetInventorySchemaRequest) -> types::GetInventorySchemaResult;
        list_inventory_entries(types::ListInventoryEntriesRequest) -> types::ListInventoryEntriesResult;
        delete_inventory(types::DeleteInventoryRequest) -> types::DeleteInventoryResult;
        describe_inventory_deletions(types::DescribeInventoryDeletionsRequest) -> types::DescribeInventoryDeletionsResult;
        put_compliance_items(types::PutComplianceItemsRequest) -> types::PutComplianceItemsResult;
        list_compliance_items(types::ListComplianceItemsRequest) -> types::ListComplianceItemsResult;
        list_compliance_summaries(types::ListComplianceSummariesRequest) -> types::ListComplianceSummariesResult;
        list_resource_compliance_summaries(types::ListResourceComplianceSummariesRequest) -> types::ListResourceComplianceSummariesResult;
        describe_instance_patch_states(types::DescribeInstancePatchStatesRequest) -> types::DescribeInstancePatchStatesResult;
        describe_instance_patch_states_for_patch_group(types::DescribeInstancePatchStatesForPatchGroupRequest) -> types::DescribeInstancePatchStatesForPatchGroupResult;
        describe_instance_patches(types::DescribeInstancePatchesRequest) -> types::DescribeInstancePatchesResult;
        get_deployable_patch_snapshot_for_instance(types::GetDeployablePatchSnapshotForInstanceRequest) -> types::GetDeployablePatchSnapshotForInstanceResult;
        describe_patch_properties(types::DescribePatchPropertiesRequest) -> types::DescribePatchPropertiesResult;
        create_association(types::CreateAssociationRequest) -> types::CreateAssociationResult;
        create_association_batch(types::CreateAssociationBatchRequest) -> types::CreateAssociationBatchResult;
        delete_association(types::DeleteAssociationRequest) -> types::DeleteAssociationResult;
        describe_association(types::DescribeAssociationRequest) -> types::DescribeAssociationResult;
        describe_association_execution_targets(types::DescribeAssociationExecutionTargetsRequest) -> types::DescribeAssociationExecutionTargetsResult;
        describe_association_executions(types::DescribeAssociationExecutionsRequest) -> types::DescribeAssociationExecutionsResult;
        describe_effective_instance_associations(types::DescribeEffectiveInstanceAssociationsRequest) -> types::DescribeEffectiveInstanceAssociationsResult;
        describe_instance_associations_status(types::DescribeInstanceAssociationsStatusRequest) -> types::DescribeInstanceAssociationsStatusResult;
        list_association_versions(types::ListAssociationVersionsRequest) -> types::ListAssociationVersionsResult;
        list_associations(types::ListAssociationsRequest) -> types::ListAssociationsResult;
        start_associations_once(types::StartAssociationsOnceRequest) -> types::StartAssociationsOnceResult;
        update_association(types::UpdateAssociationRequest) -> types::UpdateAssociationResult;
        update_association_status(types::UpdateAssociationStatusRequest) -> types::UpdateAssociationStatusResult;
        create_activation(types::CreateActivationRequest) -> types::CreateActivationResult;
        delete_activation(types::DeleteActivationRequest) -> types::DeleteActivationResult;
        describe_activations(types::DescribeActivationsRequest) -> types::DescribeActivationsResult;
        deregister_managed_instance(types::DeregisterManagedInstanceRequest) -> types::DeregisterManagedInstanceResult;
        create_patch_baseline(types::CreatePatchBaselineRequest) -> types::CreatePatchBaselineResult;
        delete_patch_baseline(types::DeletePatchBaselineRequest) -> types::DeletePatchBaselineResult;
        deregister_patch_baseline_for_patch_group(types::DeregisterPatchBaselineForPatchGroupRequest) -> types::DeregisterPatchBaselineForPatchGroupResult;
        describe_available_patches(types::DescribeAvailablePatchesRequest) -> types::DescribeAvailablePatchesResult;
        describe_effective_patches_for_patch_baseline(types::DescribeEffectivePatchesForPatchBaselineRequest) -> types::DescribeEffectivePatchesForPatchBaselineResult;
        describe_patch_baselines(types::DescribePatchBaselinesRequest) -> types::DescribePatchBaselinesResult;
        describe_patch_group_state(types::DescribePatchGroupStateRequest) -> types::DescribePatchGroupStateResult;
        describe_patch_groups(types::DescribePatchGroupsRequest) -> types::DescribePatchGroupsResult;
        get_default_patch_baseline(types::GetDefaultPatchBaselineRequest) -> types::GetDefaultPatchBaselineResult;
        get_patch_baseline(types::GetPatchBaselineRequest) -> types::GetPatchBaselineResult;
        get_patch_baseline_for_patch_group(types::GetPatchBaselineForPatchGroupRequest) -> types::GetPatchBaselineForPatchGroupResult;
        register_default_patch_baseline(types::RegisterDefaultPatchBaselineRequest) -> types::RegisterDefaultPatchBaselineResult;
        register_patch_baseline_for_patch_group(types::RegisterPatchBaselineForPatchGroupRequest) -> types::RegisterPatchBaselineForPatchGroupResult;
        update_patch_baseline(types::UpdatePatchBaselineRequest) -> types::UpdatePatchBaselineResult;
        cancel_maintenance_window_execution(types::CancelMaintenanceWindowExecutionRequest) -> types::CancelMaintenanceWindowExecutionResult;
        create_maintenance_window(types::CreateMaintenanceWindowRequest) -> types::CreateMaintenanceWindowResult;
        delete_maintenance_window(types::DeleteMaintenanceWindowRequest) -> types::DeleteMaintenanceWindowResult;
        deregister_target_from_maintenance_window(types::DeregisterTargetFromMaintenanceWindowRequest) -> types::DeregisterTargetFromMaintenanceWindowResult;
        deregister_task_from_maintenance_window(types::DeregisterTaskFromMaintenanceWindowRequest) -> types::DeregisterTaskFromMaintenanceWindowResult;
        describe_maintenance_window_execution_task_invocations(types::DescribeMaintenanceWindowExecutionTaskInvocationsRequest) -> types::DescribeMaintenanceWindowExecutionTaskInvocationsResult;
        describe_maintenance_window_execution_tasks(types::DescribeMaintenanceWindowExecutionTasksRequest) -> types::DescribeMaintenanceWindowExecutionTasksResult;
        describe_maintenance_window_executions(types::DescribeMaintenanceWindowExecutionsRequest) -> types::DescribeMaintenanceWindowExecutionsResult;
        describe_maintenance_window_schedule(types::DescribeMaintenanceWindowScheduleRequest) -> types::DescribeMaintenanceWindowScheduleResult;
        describe_maintenance_window_targets(types::DescribeMaintenanceWindowTargetsRequest) -> types::DescribeMaintenanceWindowTargetsResult;
        describe_maintenance_window_tasks(types::DescribeMaintenanceWindowTasksRequest) -> types::DescribeMaintenanceWindowTasksResult;
        describe_maintenance_windows(types::DescribeMaintenanceWindowsRequest) -> types::DescribeMaintenanceWindowsResult;
        describe_maintenance_windows_for_target(types::DescribeMaintenanceWindowsForTargetRequest) -> types::DescribeMaintenanceWindowsForTargetResult;
        get_maintenance_window(types::GetMaintenanceWindowRequest) -> types::GetMaintenanceWindowResult;
        get_maintenance_window_execution(types::GetMaintenanceWindowExecutionRequest) -> types::GetMaintenanceWindowExecutionResult;
        get_maintenance_window_execution_task(types::GetMaintenanceWindowExecutionTaskRequest) -> types::GetMaintenanceWindowExecutionTaskResult;
        get_maintenance_window_execution_task_invocation(types::GetMaintenanceWindowExecutionTaskInvocationRequest) -> types::GetMaintenanceWindowExecutionTaskInvocationResult;
        get_maintenance_window_task(types::GetMaintenanceWindowTaskRequest) -> types::GetMaintenanceWindowTaskResult;
        register_target_with_maintenance_window(types::RegisterTargetWithMaintenanceWindowRequest) -> types::RegisterTargetWithMaintenanceWindowResult;
        register_task_with_maintenance_window(types::RegisterTaskWithMaintenanceWindowRequest) -> types::RegisterTaskWithMaintenanceWindowResult;
        update_maintenance_window(types::UpdateMaintenanceWindowRequest) -> types::UpdateMaintenanceWindowResult;
        update_maintenance_window_target(types::UpdateMaintenanceWindowTargetRequest) -> types::UpdateMaintenanceWindowTargetResult;
        update_maintenance_window_task(types::UpdateMaintenanceWindowTaskRequest) -> types::UpdateMaintenanceWindowTaskResult;
        cancel_command(types::CancelCommandRequest) -> types::CancelCommandResult;
        create_document(types::CreateDocumentRequest) -> types::CreateDocumentResult;
        delete_document(types::DeleteDocumentRequest) -> types::DeleteDocumentResult;
        describe_document(types::DescribeDocumentRequest) -> types::DescribeDocumentResult;
        describe_document_permission(types::DescribeDocumentPermissionRequest) -> types::DescribeDocumentPermissionResponse;
        describe_instance_information(types::DescribeInstanceInformationRequest) -> types::DescribeInstanceInformationResult;
        get_command_invocation(types::GetCommandInvocationRequest) -> types::GetCommandInvocationResult;
        get_document(types::GetDocumentRequest) -> types::GetDocumentResult;
        list_command_invocations(types::ListCommandInvocationsRequest) -> types::ListCommandInvocationsResult;
        list_commands(types::ListCommandsRequest) -> types::ListCommandsResult;
        list_document_versions(types::ListDocumentVersionsRequest) -> types::ListDocumentVersionsResult;
        list_documents(types::ListDocumentsRequest) -> types::ListDocumentsResult;
        modify_document_permission(types::ModifyDocumentPermissionRequest) -> types::ModifyDocumentPermissionResponse;
        send_command(types::SendCommandRequest) -> types::SendCommandResult;
        update_document(types::UpdateDocumentRequest) -> types::UpdateDocumentResult;
        update_document_default_version(types::UpdateDocumentDefaultVersionRequest) -> types::UpdateDocumentDefaultVersionResult;
        add_tags_to_resource(types::AddTagsToResourceRequest) -> types::AddTagsToResourceResult;
        delete_parameter(types::DeleteParameterRequest) -> types::DeleteParameterResult;
        delete_parameters(types::DeleteParametersRequest) -> types::DeleteParametersResult;
        delete_resource_policy(types::DeleteResourcePolicyRequest) -> types::DeleteResourcePolicyResponse;
        describe_parameters(types::DescribeParametersRequest) -> types::DescribeParametersResult;
        get_parameter(types::GetParameterRequest) -> types::GetParameterResult;
        get_parameter_history(types::GetParameterHistoryRequest) -> types::GetParameterHistoryResult;
        get_parameters(types::GetParametersRequest) -> types::GetParametersResult;
        get_parameters_by_path(types::GetParametersByPathRequest) -> types::GetParametersByPathResult;
        get_resource_policies(types::GetResourcePoliciesRequest) -> types::GetResourcePoliciesResponse;
        get_service_setting(types::GetServiceSettingRequest) -> types::GetServiceSettingResult;
        label_parameter_version(types::LabelParameterVersionRequest) -> types::LabelParameterVersionResult;
        list_tags_for_resource(types::ListTagsForResourceRequest) -> types::ListTagsForResourceResult;
        put_parameter(types::PutParameterRequest) -> types::PutParameterResult;
        put_resource_policy(types::PutResourcePolicyRequest) -> types::PutResourcePolicyResponse;
        remove_tags_from_resource(types::RemoveTagsFromResourceRequest) -> types::RemoveTagsFromResourceResult;
        reset_service_setting(types::ResetServiceSettingRequest) -> types::ResetServiceSettingResult;
        unlabel_parameter_version(types::UnlabelParameterVersionRequest) -> types::UnlabelParameterVersionResult;
        update_service_setting(types::UpdateServiceSettingRequest) -> types::UpdateServiceSettingResult;
    }
}

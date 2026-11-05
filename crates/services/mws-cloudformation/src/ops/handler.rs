//! The generated `Handler`, forwarding to the operation modules.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::CloudFormation;

#[async_trait::async_trait]
impl Handler for CloudFormation {
    async fn create_stack(
        &self,
        ctx: &RequestContext,
        input: types::CreateStackInput,
    ) -> Result<types::CreateStackOutput, ServiceError> {
        self.create_stack_op(ctx, input).await
    }

    async fn update_stack(
        &self,
        ctx: &RequestContext,
        input: types::UpdateStackInput,
    ) -> Result<types::UpdateStackOutput, ServiceError> {
        self.update_stack_op(ctx, input).await
    }

    async fn delete_stack(&self, ctx: &RequestContext, input: types::DeleteStackInput) -> Result<(), ServiceError> {
        self.delete_stack_op(ctx, input).await
    }

    async fn describe_stacks(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStacksInput,
    ) -> Result<types::DescribeStacksOutput, ServiceError> {
        self.describe_stacks_op(ctx, input)
    }

    async fn list_stacks(
        &self,
        ctx: &RequestContext,
        input: types::ListStacksInput,
    ) -> Result<types::ListStacksOutput, ServiceError> {
        self.list_stacks_op(ctx, input)
    }

    async fn describe_stack_events(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStackEventsInput,
    ) -> Result<types::DescribeStackEventsOutput, ServiceError> {
        self.describe_stack_events_op(ctx, input)
    }

    async fn describe_stack_resources(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStackResourcesInput,
    ) -> Result<types::DescribeStackResourcesOutput, ServiceError> {
        self.describe_stack_resources_op(ctx, input)
    }

    async fn describe_stack_resource(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStackResourceInput,
    ) -> Result<types::DescribeStackResourceOutput, ServiceError> {
        self.describe_stack_resource_op(ctx, input)
    }

    async fn list_stack_resources(
        &self,
        ctx: &RequestContext,
        input: types::ListStackResourcesInput,
    ) -> Result<types::ListStackResourcesOutput, ServiceError> {
        self.list_stack_resources_op(ctx, input)
    }

    async fn get_template(
        &self,
        ctx: &RequestContext,
        input: types::GetTemplateInput,
    ) -> Result<types::GetTemplateOutput, ServiceError> {
        self.get_template_op(ctx, input)
    }

    async fn update_termination_protection(
        &self,
        ctx: &RequestContext,
        input: types::UpdateTerminationProtectionInput,
    ) -> Result<types::UpdateTerminationProtectionOutput, ServiceError> {
        self.update_termination_protection_op(ctx, input)
    }

    async fn set_stack_policy(
        &self,
        ctx: &RequestContext,
        input: types::SetStackPolicyInput,
    ) -> Result<(), ServiceError> {
        self.set_stack_policy_op(ctx, input).await
    }

    async fn get_stack_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetStackPolicyInput,
    ) -> Result<types::GetStackPolicyOutput, ServiceError> {
        self.get_stack_policy_op(ctx, input)
    }

    async fn signal_resource(
        &self,
        ctx: &RequestContext,
        input: types::SignalResourceInput,
    ) -> Result<(), ServiceError> {
        self.signal_resource_op(ctx, input)
    }

    async fn list_exports(
        &self,
        ctx: &RequestContext,
        input: types::ListExportsInput,
    ) -> Result<types::ListExportsOutput, ServiceError> {
        self.list_exports_op(ctx, input)
    }

    async fn list_imports(
        &self,
        ctx: &RequestContext,
        input: types::ListImportsInput,
    ) -> Result<types::ListImportsOutput, ServiceError> {
        self.list_imports_op(ctx, input)
    }

    async fn cancel_update_stack(
        &self,
        ctx: &RequestContext,
        input: types::CancelUpdateStackInput,
    ) -> Result<(), ServiceError> {
        self.cancel_update_stack_op(ctx, input)
    }

    async fn continue_update_rollback(
        &self,
        ctx: &RequestContext,
        input: types::ContinueUpdateRollbackInput,
    ) -> Result<types::ContinueUpdateRollbackOutput, ServiceError> {
        self.continue_update_rollback_op(ctx, input).await
    }

    async fn rollback_stack(
        &self,
        ctx: &RequestContext,
        input: types::RollbackStackInput,
    ) -> Result<types::RollbackStackOutput, ServiceError> {
        self.rollback_stack_op(ctx, input).await
    }

    async fn create_change_set(
        &self,
        ctx: &RequestContext,
        input: types::CreateChangeSetInput,
    ) -> Result<types::CreateChangeSetOutput, ServiceError> {
        self.create_change_set_op(ctx, input).await
    }

    async fn describe_change_set(
        &self,
        ctx: &RequestContext,
        input: types::DescribeChangeSetInput,
    ) -> Result<types::DescribeChangeSetOutput, ServiceError> {
        self.describe_change_set_op(ctx, input)
    }

    async fn list_change_sets(
        &self,
        ctx: &RequestContext,
        input: types::ListChangeSetsInput,
    ) -> Result<types::ListChangeSetsOutput, ServiceError> {
        self.list_change_sets_op(ctx, input)
    }

    async fn delete_change_set(
        &self,
        ctx: &RequestContext,
        input: types::DeleteChangeSetInput,
    ) -> Result<types::DeleteChangeSetOutput, ServiceError> {
        self.delete_change_set_op(ctx, input)
    }

    async fn execute_change_set(
        &self,
        ctx: &RequestContext,
        input: types::ExecuteChangeSetInput,
    ) -> Result<types::ExecuteChangeSetOutput, ServiceError> {
        self.execute_change_set_op(ctx, input).await
    }

    async fn describe_change_set_hooks(
        &self,
        ctx: &RequestContext,
        input: types::DescribeChangeSetHooksInput,
    ) -> Result<types::DescribeChangeSetHooksOutput, ServiceError> {
        self.describe_change_set_hooks_op(ctx, input)
    }

    async fn detect_stack_drift(
        &self,
        ctx: &RequestContext,
        input: types::DetectStackDriftInput,
    ) -> Result<types::DetectStackDriftOutput, ServiceError> {
        self.detect_stack_drift_op(ctx, input).await
    }

    async fn describe_stack_drift_detection_status(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStackDriftDetectionStatusInput,
    ) -> Result<types::DescribeStackDriftDetectionStatusOutput, ServiceError> {
        self.describe_stack_drift_detection_status_op(ctx, input)
    }

    async fn describe_stack_resource_drifts(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStackResourceDriftsInput,
    ) -> Result<types::DescribeStackResourceDriftsOutput, ServiceError> {
        self.describe_stack_resource_drifts_op(ctx, input)
    }

    async fn detect_stack_resource_drift(
        &self,
        ctx: &RequestContext,
        input: types::DetectStackResourceDriftInput,
    ) -> Result<types::DetectStackResourceDriftOutput, ServiceError> {
        self.detect_stack_resource_drift_op(ctx, input).await
    }

    async fn validate_template(
        &self,
        ctx: &RequestContext,
        input: types::ValidateTemplateInput,
    ) -> Result<types::ValidateTemplateOutput, ServiceError> {
        self.validate_template_op(ctx, input).await
    }

    async fn get_template_summary(
        &self,
        ctx: &RequestContext,
        input: types::GetTemplateSummaryInput,
    ) -> Result<types::GetTemplateSummaryOutput, ServiceError> {
        self.get_template_summary_op(ctx, input).await
    }

    async fn estimate_template_cost(
        &self,
        ctx: &RequestContext,
        input: types::EstimateTemplateCostInput,
    ) -> Result<types::EstimateTemplateCostOutput, ServiceError> {
        self.estimate_template_cost_op(ctx, input).await
    }

    async fn describe_account_limits(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAccountLimitsInput,
    ) -> Result<types::DescribeAccountLimitsOutput, ServiceError> {
        self.describe_account_limits_op(ctx, input)
    }

    async fn list_types(
        &self,
        ctx: &RequestContext,
        input: types::ListTypesInput,
    ) -> Result<types::ListTypesOutput, ServiceError> {
        self.list_types_op(ctx, input)
    }

    async fn describe_type(
        &self,
        ctx: &RequestContext,
        input: types::DescribeTypeInput,
    ) -> Result<types::DescribeTypeOutput, ServiceError> {
        self.describe_type_op(ctx, input)
    }

    async fn activate_organizations_access(
        &self,
        ctx: &RequestContext,
        input: types::ActivateOrganizationsAccessInput,
    ) -> Result<types::ActivateOrganizationsAccessOutput, ServiceError> {
        let _ = input;
        self.activate_organizations_access_op(ctx).await?;
        Ok(Default::default())
    }

    async fn deactivate_organizations_access(
        &self,
        ctx: &RequestContext,
        input: types::DeactivateOrganizationsAccessInput,
    ) -> Result<types::DeactivateOrganizationsAccessOutput, ServiceError> {
        let _ = input;
        self.deactivate_organizations_access_op(ctx).await?;
        Ok(Default::default())
    }

    async fn describe_organizations_access(
        &self,
        ctx: &RequestContext,
        input: types::DescribeOrganizationsAccessInput,
    ) -> Result<types::DescribeOrganizationsAccessOutput, ServiceError> {
        self.describe_organizations_access_op(ctx, input).await
    }

    async fn create_stack_set(
        &self,
        ctx: &RequestContext,
        input: types::CreateStackSetInput,
    ) -> Result<types::CreateStackSetOutput, ServiceError> {
        self.create_stack_set_op(ctx, input).await
    }

    async fn update_stack_set(
        &self,
        ctx: &RequestContext,
        input: types::UpdateStackSetInput,
    ) -> Result<types::UpdateStackSetOutput, ServiceError> {
        self.update_stack_set_op(ctx, input).await
    }

    async fn delete_stack_set(
        &self,
        ctx: &RequestContext,
        input: types::DeleteStackSetInput,
    ) -> Result<types::DeleteStackSetOutput, ServiceError> {
        self.delete_stack_set_op(ctx, input).await?;
        Ok(Default::default())
    }

    async fn list_stack_sets(
        &self,
        ctx: &RequestContext,
        input: types::ListStackSetsInput,
    ) -> Result<types::ListStackSetsOutput, ServiceError> {
        self.list_stack_sets_op(ctx, input).await
    }

    async fn describe_stack_set(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStackSetInput,
    ) -> Result<types::DescribeStackSetOutput, ServiceError> {
        self.describe_stack_set_op(ctx, input).await
    }

    async fn create_stack_instances(
        &self,
        ctx: &RequestContext,
        input: types::CreateStackInstancesInput,
    ) -> Result<types::CreateStackInstancesOutput, ServiceError> {
        self.create_stack_instances_op(ctx, input).await
    }

    async fn update_stack_instances(
        &self,
        ctx: &RequestContext,
        input: types::UpdateStackInstancesInput,
    ) -> Result<types::UpdateStackInstancesOutput, ServiceError> {
        self.update_stack_instances_op(ctx, input).await
    }

    async fn delete_stack_instances(
        &self,
        ctx: &RequestContext,
        input: types::DeleteStackInstancesInput,
    ) -> Result<types::DeleteStackInstancesOutput, ServiceError> {
        self.delete_stack_instances_op(ctx, input).await
    }

    async fn describe_stack_instance(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStackInstanceInput,
    ) -> Result<types::DescribeStackInstanceOutput, ServiceError> {
        self.describe_stack_instance_op(ctx, input).await
    }

    async fn list_stack_instances(
        &self,
        ctx: &RequestContext,
        input: types::ListStackInstancesInput,
    ) -> Result<types::ListStackInstancesOutput, ServiceError> {
        self.list_stack_instances_op(ctx, input).await
    }

    async fn describe_stack_set_operation(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStackSetOperationInput,
    ) -> Result<types::DescribeStackSetOperationOutput, ServiceError> {
        self.describe_stack_set_operation_op(ctx, input).await
    }

    async fn list_stack_set_operations(
        &self,
        ctx: &RequestContext,
        input: types::ListStackSetOperationsInput,
    ) -> Result<types::ListStackSetOperationsOutput, ServiceError> {
        self.list_stack_set_operations_op(ctx, input).await
    }

    async fn list_stack_set_operation_results(
        &self,
        ctx: &RequestContext,
        input: types::ListStackSetOperationResultsInput,
    ) -> Result<types::ListStackSetOperationResultsOutput, ServiceError> {
        self.list_stack_set_operation_results_op(ctx, input).await
    }

    async fn stop_stack_set_operation(
        &self,
        ctx: &RequestContext,
        input: types::StopStackSetOperationInput,
    ) -> Result<types::StopStackSetOperationOutput, ServiceError> {
        self.stop_stack_set_operation_op(ctx, input).await?;
        Ok(Default::default())
    }

    async fn detect_stack_set_drift(
        &self,
        ctx: &RequestContext,
        input: types::DetectStackSetDriftInput,
    ) -> Result<types::DetectStackSetDriftOutput, ServiceError> {
        self.detect_stack_set_drift_op(ctx, input).await
    }

    async fn list_stack_instance_resource_drifts(
        &self,
        ctx: &RequestContext,
        input: types::ListStackInstanceResourceDriftsInput,
    ) -> Result<types::ListStackInstanceResourceDriftsOutput, ServiceError> {
        self.list_stack_instance_resource_drifts_op(ctx, input).await
    }

    async fn list_stack_set_auto_deployment_targets(
        &self,
        ctx: &RequestContext,
        input: types::ListStackSetAutoDeploymentTargetsInput,
    ) -> Result<types::ListStackSetAutoDeploymentTargetsOutput, ServiceError> {
        self.list_stack_set_auto_deployment_targets_op(ctx, input).await
    }

    async fn import_stacks_to_stack_set(
        &self,
        ctx: &RequestContext,
        input: types::ImportStacksToStackSetInput,
    ) -> Result<types::ImportStacksToStackSetOutput, ServiceError> {
        self.import_stacks_to_stack_set_op(ctx, input).await
    }

    async fn register_type(
        &self,
        ctx: &RequestContext,
        input: types::RegisterTypeInput,
    ) -> Result<types::RegisterTypeOutput, ServiceError> {
        self.register_type_op(ctx, input).await
    }

    async fn describe_type_registration(
        &self,
        ctx: &RequestContext,
        input: types::DescribeTypeRegistrationInput,
    ) -> Result<types::DescribeTypeRegistrationOutput, ServiceError> {
        self.describe_type_registration_op(ctx, input)
    }

    async fn list_type_registrations(
        &self,
        ctx: &RequestContext,
        input: types::ListTypeRegistrationsInput,
    ) -> Result<types::ListTypeRegistrationsOutput, ServiceError> {
        self.list_type_registrations_op(ctx, input)
    }

    async fn deregister_type(
        &self,
        ctx: &RequestContext,
        input: types::DeregisterTypeInput,
    ) -> Result<types::DeregisterTypeOutput, ServiceError> {
        self.deregister_type_op(ctx, input)?;
        Ok(Default::default())
    }

    async fn list_type_versions(
        &self,
        ctx: &RequestContext,
        input: types::ListTypeVersionsInput,
    ) -> Result<types::ListTypeVersionsOutput, ServiceError> {
        self.list_type_versions_op(ctx, input)
    }

    async fn set_type_default_version(
        &self,
        ctx: &RequestContext,
        input: types::SetTypeDefaultVersionInput,
    ) -> Result<types::SetTypeDefaultVersionOutput, ServiceError> {
        self.set_type_default_version_op(ctx, input)?;
        Ok(Default::default())
    }

    async fn set_type_configuration(
        &self,
        ctx: &RequestContext,
        input: types::SetTypeConfigurationInput,
    ) -> Result<types::SetTypeConfigurationOutput, ServiceError> {
        self.set_type_configuration_op(ctx, input)
    }

    async fn batch_describe_type_configurations(
        &self,
        ctx: &RequestContext,
        input: types::BatchDescribeTypeConfigurationsInput,
    ) -> Result<types::BatchDescribeTypeConfigurationsOutput, ServiceError> {
        self.batch_describe_type_configurations_op(ctx, input)
    }

    async fn register_publisher(
        &self,
        ctx: &RequestContext,
        input: types::RegisterPublisherInput,
    ) -> Result<types::RegisterPublisherOutput, ServiceError> {
        self.register_publisher_op(ctx, input)
    }

    async fn describe_publisher(
        &self,
        ctx: &RequestContext,
        input: types::DescribePublisherInput,
    ) -> Result<types::DescribePublisherOutput, ServiceError> {
        self.describe_publisher_op(ctx, input)
    }

    async fn test_type(
        &self,
        ctx: &RequestContext,
        input: types::TestTypeInput,
    ) -> Result<types::TestTypeOutput, ServiceError> {
        self.test_type_op(ctx, input).await
    }

    async fn publish_type(
        &self,
        ctx: &RequestContext,
        input: types::PublishTypeInput,
    ) -> Result<types::PublishTypeOutput, ServiceError> {
        self.publish_type_op(ctx, input)
    }

    async fn activate_type(
        &self,
        ctx: &RequestContext,
        input: types::ActivateTypeInput,
    ) -> Result<types::ActivateTypeOutput, ServiceError> {
        self.activate_type_op(ctx, input)
    }

    async fn deactivate_type(
        &self,
        ctx: &RequestContext,
        input: types::DeactivateTypeInput,
    ) -> Result<types::DeactivateTypeOutput, ServiceError> {
        self.deactivate_type_op(ctx, input)?;
        Ok(Default::default())
    }

    async fn record_handler_progress(
        &self,
        ctx: &RequestContext,
        input: types::RecordHandlerProgressInput,
    ) -> Result<types::RecordHandlerProgressOutput, ServiceError> {
        self.record_handler_progress_op(ctx, input)?;
        Ok(Default::default())
    }

    async fn get_hook_result(
        &self,
        ctx: &RequestContext,
        input: types::GetHookResultInput,
    ) -> Result<types::GetHookResultOutput, ServiceError> {
        self.get_hook_result_op(ctx, input)
    }

    async fn list_hook_results(
        &self,
        ctx: &RequestContext,
        input: types::ListHookResultsInput,
    ) -> Result<types::ListHookResultsOutput, ServiceError> {
        self.list_hook_results_op(ctx, input)
    }
}

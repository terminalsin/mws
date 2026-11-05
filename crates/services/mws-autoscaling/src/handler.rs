//! Forwards the generated handler to the operations in `ops`.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::AutoScaling;

#[async_trait::async_trait]
impl Handler for AutoScaling {
    async fn attach_instances(
        &self,
        ctx: &RequestContext,
        input: types::AttachInstancesQuery,
    ) -> Result<(), ServiceError> {
        self.attach_instances_op(ctx, input).await
    }
    async fn attach_load_balancer_target_groups(
        &self,
        ctx: &RequestContext,
        input: types::AttachLoadBalancerTargetGroupsType,
    ) -> Result<types::AttachLoadBalancerTargetGroupsResultType, ServiceError> {
        self.attach_load_balancer_target_groups_op(ctx, input)
    }
    async fn attach_load_balancers(
        &self,
        ctx: &RequestContext,
        input: types::AttachLoadBalancersType,
    ) -> Result<types::AttachLoadBalancersResultType, ServiceError> {
        self.attach_load_balancers_op(ctx, input)
    }
    async fn attach_traffic_sources(
        &self,
        ctx: &RequestContext,
        input: types::AttachTrafficSourcesType,
    ) -> Result<types::AttachTrafficSourcesResultType, ServiceError> {
        self.attach_traffic_sources_op(ctx, input)
    }
    async fn batch_delete_scheduled_action(
        &self,
        ctx: &RequestContext,
        input: types::BatchDeleteScheduledActionType,
    ) -> Result<types::BatchDeleteScheduledActionAnswer, ServiceError> {
        self.batch_delete_scheduled_action_op(ctx, input)
    }
    async fn batch_put_scheduled_update_group_action(
        &self,
        ctx: &RequestContext,
        input: types::BatchPutScheduledUpdateGroupActionType,
    ) -> Result<types::BatchPutScheduledUpdateGroupActionAnswer, ServiceError> {
        self.batch_put_scheduled_update_group_action_op(ctx, input)
    }
    async fn cancel_instance_refresh(
        &self,
        ctx: &RequestContext,
        input: types::CancelInstanceRefreshType,
    ) -> Result<types::CancelInstanceRefreshAnswer, ServiceError> {
        self.cancel_instance_refresh_op(ctx, input)
    }
    async fn complete_lifecycle_action(
        &self,
        ctx: &RequestContext,
        input: types::CompleteLifecycleActionType,
    ) -> Result<types::CompleteLifecycleActionAnswer, ServiceError> {
        self.complete_lifecycle_action_op(ctx, input)
    }
    async fn create_auto_scaling_group(
        &self,
        ctx: &RequestContext,
        input: types::CreateAutoScalingGroupType,
    ) -> Result<(), ServiceError> {
        self.create_auto_scaling_group_op(ctx, input).await
    }
    async fn create_launch_configuration(
        &self,
        ctx: &RequestContext,
        input: types::CreateLaunchConfigurationType,
    ) -> Result<(), ServiceError> {
        self.create_launch_configuration_op(ctx, input).await
    }
    async fn create_or_update_tags(
        &self,
        ctx: &RequestContext,
        input: types::CreateOrUpdateTagsType,
    ) -> Result<(), ServiceError> {
        self.create_or_update_tags_op(ctx, input)
    }
    async fn delete_auto_scaling_group(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAutoScalingGroupType,
    ) -> Result<(), ServiceError> {
        self.delete_auto_scaling_group_op(ctx, input).await
    }
    async fn delete_launch_configuration(
        &self,
        ctx: &RequestContext,
        input: types::LaunchConfigurationNameType,
    ) -> Result<(), ServiceError> {
        self.delete_launch_configuration_op(ctx, input)
    }
    async fn delete_lifecycle_hook(
        &self,
        ctx: &RequestContext,
        input: types::DeleteLifecycleHookType,
    ) -> Result<types::DeleteLifecycleHookAnswer, ServiceError> {
        self.delete_lifecycle_hook_op(ctx, input)
    }
    async fn delete_notification_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DeleteNotificationConfigurationType,
    ) -> Result<(), ServiceError> {
        self.delete_notification_configuration_op(ctx, input)
    }
    async fn delete_policy(&self, ctx: &RequestContext, input: types::DeletePolicyType) -> Result<(), ServiceError> {
        self.delete_policy_op(ctx, input)
    }
    async fn delete_scheduled_action(
        &self,
        ctx: &RequestContext,
        input: types::DeleteScheduledActionType,
    ) -> Result<(), ServiceError> {
        self.delete_scheduled_action_op(ctx, input)
    }
    async fn delete_tags(&self, ctx: &RequestContext, input: types::DeleteTagsType) -> Result<(), ServiceError> {
        self.delete_tags_op(ctx, input)
    }
    async fn delete_warm_pool(
        &self,
        ctx: &RequestContext,
        input: types::DeleteWarmPoolType,
    ) -> Result<types::DeleteWarmPoolAnswer, ServiceError> {
        self.delete_warm_pool_op(ctx, input).await
    }
    async fn describe_account_settings(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAccountSettingsType,
    ) -> Result<types::DescribeAccountSettingsAnswer, ServiceError> {
        self.describe_account_settings_op(ctx, input)
    }
    async fn describe_auto_scaling_groups(
        &self,
        ctx: &RequestContext,
        input: types::AutoScalingGroupNamesType,
    ) -> Result<types::AutoScalingGroupsType, ServiceError> {
        self.describe_auto_scaling_groups_op(ctx, input).await
    }
    async fn describe_auto_scaling_instances(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAutoScalingInstancesType,
    ) -> Result<types::AutoScalingInstancesType, ServiceError> {
        self.describe_auto_scaling_instances_op(ctx, input)
    }
    async fn describe_instance_refreshes(
        &self,
        ctx: &RequestContext,
        input: types::DescribeInstanceRefreshesType,
    ) -> Result<types::DescribeInstanceRefreshesAnswer, ServiceError> {
        self.describe_instance_refreshes_op(ctx, input)
    }
    async fn describe_launch_configurations(
        &self,
        ctx: &RequestContext,
        input: types::LaunchConfigurationNamesType,
    ) -> Result<types::LaunchConfigurationsType, ServiceError> {
        self.describe_launch_configurations_op(ctx, input)
    }
    async fn describe_lifecycle_hooks(
        &self,
        ctx: &RequestContext,
        input: types::DescribeLifecycleHooksType,
    ) -> Result<types::DescribeLifecycleHooksAnswer, ServiceError> {
        self.describe_lifecycle_hooks_op(ctx, input)
    }
    async fn describe_load_balancer_target_groups(
        &self,
        ctx: &RequestContext,
        input: types::DescribeLoadBalancerTargetGroupsRequest,
    ) -> Result<types::DescribeLoadBalancerTargetGroupsResponse, ServiceError> {
        self.describe_load_balancer_target_groups_op(ctx, input)
    }
    async fn describe_load_balancers(
        &self,
        ctx: &RequestContext,
        input: types::DescribeLoadBalancersRequest,
    ) -> Result<types::DescribeLoadBalancersResponse, ServiceError> {
        self.describe_load_balancers_op(ctx, input)
    }
    async fn describe_notification_configurations(
        &self,
        ctx: &RequestContext,
        input: types::DescribeNotificationConfigurationsType,
    ) -> Result<types::DescribeNotificationConfigurationsAnswer, ServiceError> {
        self.describe_notification_configurations_op(ctx, input)
    }
    async fn describe_policies(
        &self,
        ctx: &RequestContext,
        input: types::DescribePoliciesType,
    ) -> Result<types::PoliciesType, ServiceError> {
        self.describe_policies_op(ctx, input)
    }
    async fn describe_scaling_activities(
        &self,
        ctx: &RequestContext,
        input: types::DescribeScalingActivitiesType,
    ) -> Result<types::ActivitiesType, ServiceError> {
        self.describe_scaling_activities_op(ctx, input)
    }
    async fn describe_scheduled_actions(
        &self,
        ctx: &RequestContext,
        input: types::DescribeScheduledActionsType,
    ) -> Result<types::ScheduledActionsType, ServiceError> {
        self.describe_scheduled_actions_op(ctx, input)
    }
    async fn describe_tags(
        &self,
        ctx: &RequestContext,
        input: types::DescribeTagsType,
    ) -> Result<types::TagsType, ServiceError> {
        self.describe_tags_op(ctx, input)
    }
    async fn describe_traffic_sources(
        &self,
        ctx: &RequestContext,
        input: types::DescribeTrafficSourcesRequest,
    ) -> Result<types::DescribeTrafficSourcesResponse, ServiceError> {
        self.describe_traffic_sources_op(ctx, input)
    }
    async fn describe_warm_pool(
        &self,
        ctx: &RequestContext,
        input: types::DescribeWarmPoolType,
    ) -> Result<types::DescribeWarmPoolAnswer, ServiceError> {
        self.describe_warm_pool_op(ctx, input)
    }
    async fn detach_instances(
        &self,
        ctx: &RequestContext,
        input: types::DetachInstancesQuery,
    ) -> Result<types::DetachInstancesAnswer, ServiceError> {
        self.detach_instances_op(ctx, input)
    }
    async fn detach_load_balancer_target_groups(
        &self,
        ctx: &RequestContext,
        input: types::DetachLoadBalancerTargetGroupsType,
    ) -> Result<types::DetachLoadBalancerTargetGroupsResultType, ServiceError> {
        self.detach_load_balancer_target_groups_op(ctx, input)
    }
    async fn detach_load_balancers(
        &self,
        ctx: &RequestContext,
        input: types::DetachLoadBalancersType,
    ) -> Result<types::DetachLoadBalancersResultType, ServiceError> {
        self.detach_load_balancers_op(ctx, input)
    }
    async fn detach_traffic_sources(
        &self,
        ctx: &RequestContext,
        input: types::DetachTrafficSourcesType,
    ) -> Result<types::DetachTrafficSourcesResultType, ServiceError> {
        self.detach_traffic_sources_op(ctx, input)
    }
    async fn disable_metrics_collection(
        &self,
        ctx: &RequestContext,
        input: types::DisableMetricsCollectionQuery,
    ) -> Result<(), ServiceError> {
        self.disable_metrics_collection_op(ctx, input)
    }
    async fn enable_metrics_collection(
        &self,
        ctx: &RequestContext,
        input: types::EnableMetricsCollectionQuery,
    ) -> Result<(), ServiceError> {
        self.enable_metrics_collection_op(ctx, input)
    }
    async fn enter_standby(
        &self,
        ctx: &RequestContext,
        input: types::EnterStandbyQuery,
    ) -> Result<types::EnterStandbyAnswer, ServiceError> {
        self.enter_standby_op(ctx, input)
    }
    async fn execute_policy(&self, ctx: &RequestContext, input: types::ExecutePolicyType) -> Result<(), ServiceError> {
        self.execute_policy_op(ctx, input)
    }
    async fn exit_standby(
        &self,
        ctx: &RequestContext,
        input: types::ExitStandbyQuery,
    ) -> Result<types::ExitStandbyAnswer, ServiceError> {
        self.exit_standby_op(ctx, input)
    }
    async fn get_predictive_scaling_forecast(
        &self,
        ctx: &RequestContext,
        input: types::GetPredictiveScalingForecastType,
    ) -> Result<types::GetPredictiveScalingForecastAnswer, ServiceError> {
        self.get_predictive_scaling_forecast_op(ctx, input)
    }
    async fn launch_instances(
        &self,
        ctx: &RequestContext,
        input: types::LaunchInstancesRequest,
    ) -> Result<types::LaunchInstancesResult, ServiceError> {
        self.launch_instances_op(ctx, input).await
    }
    async fn put_account_setting(
        &self,
        ctx: &RequestContext,
        input: types::PutAccountSettingType,
    ) -> Result<types::PutAccountSettingAnswer, ServiceError> {
        self.put_account_setting_op(ctx, input)
    }
    async fn put_lifecycle_hook(
        &self,
        ctx: &RequestContext,
        input: types::PutLifecycleHookType,
    ) -> Result<types::PutLifecycleHookAnswer, ServiceError> {
        self.put_lifecycle_hook_op(ctx, input)
    }
    async fn put_notification_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutNotificationConfigurationType,
    ) -> Result<(), ServiceError> {
        self.put_notification_configuration_op(ctx, input)
    }
    async fn put_scaling_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutScalingPolicyType,
    ) -> Result<types::PolicyARNType, ServiceError> {
        self.put_scaling_policy_op(ctx, input)
    }
    async fn put_scheduled_update_group_action(
        &self,
        ctx: &RequestContext,
        input: types::PutScheduledUpdateGroupActionType,
    ) -> Result<(), ServiceError> {
        self.put_scheduled_update_group_action_op(ctx, input)
    }
    async fn put_warm_pool(
        &self,
        ctx: &RequestContext,
        input: types::PutWarmPoolType,
    ) -> Result<types::PutWarmPoolAnswer, ServiceError> {
        self.put_warm_pool_op(ctx, input)
    }
    async fn record_lifecycle_action_heartbeat(
        &self,
        ctx: &RequestContext,
        input: types::RecordLifecycleActionHeartbeatType,
    ) -> Result<types::RecordLifecycleActionHeartbeatAnswer, ServiceError> {
        self.record_lifecycle_action_heartbeat_op(ctx, input)
    }
    async fn resume_processes(
        &self,
        ctx: &RequestContext,
        input: types::ScalingProcessQuery,
    ) -> Result<(), ServiceError> {
        self.resume_processes_op(ctx, input)
    }
    async fn rollback_instance_refresh(
        &self,
        ctx: &RequestContext,
        input: types::RollbackInstanceRefreshType,
    ) -> Result<types::RollbackInstanceRefreshAnswer, ServiceError> {
        self.rollback_instance_refresh_op(ctx, input)
    }
    async fn set_desired_capacity(
        &self,
        ctx: &RequestContext,
        input: types::SetDesiredCapacityType,
    ) -> Result<(), ServiceError> {
        self.set_desired_capacity_op(ctx, input)
    }
    async fn set_instance_health(
        &self,
        ctx: &RequestContext,
        input: types::SetInstanceHealthQuery,
    ) -> Result<(), ServiceError> {
        self.set_instance_health_op(ctx, input)
    }
    async fn set_instance_protection(
        &self,
        ctx: &RequestContext,
        input: types::SetInstanceProtectionQuery,
    ) -> Result<types::SetInstanceProtectionAnswer, ServiceError> {
        self.set_instance_protection_op(ctx, input)
    }
    async fn start_instance_refresh(
        &self,
        ctx: &RequestContext,
        input: types::StartInstanceRefreshType,
    ) -> Result<types::StartInstanceRefreshAnswer, ServiceError> {
        self.start_instance_refresh_op(ctx, input)
    }
    async fn suspend_processes(
        &self,
        ctx: &RequestContext,
        input: types::ScalingProcessQuery,
    ) -> Result<(), ServiceError> {
        self.suspend_processes_op(ctx, input)
    }
    async fn terminate_instance_in_auto_scaling_group(
        &self,
        ctx: &RequestContext,
        input: types::TerminateInstanceInAutoScalingGroupType,
    ) -> Result<types::ActivityType, ServiceError> {
        self.terminate_instance_in_auto_scaling_group_op(ctx, input)
    }
    async fn update_auto_scaling_group(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAutoScalingGroupType,
    ) -> Result<(), ServiceError> {
        self.update_auto_scaling_group_op(ctx, input).await
    }
    async fn describe_account_limits(
        &self,
        ctx: &RequestContext,
        _input: (),
    ) -> Result<types::DescribeAccountLimitsAnswer, ServiceError> {
        self.describe_account_limits_op(ctx)
    }
    async fn describe_adjustment_types(
        &self,
        ctx: &RequestContext,
        _input: (),
    ) -> Result<types::DescribeAdjustmentTypesAnswer, ServiceError> {
        self.describe_adjustment_types_op(ctx)
    }
    async fn describe_auto_scaling_notification_types(
        &self,
        ctx: &RequestContext,
        _input: (),
    ) -> Result<types::DescribeAutoScalingNotificationTypesAnswer, ServiceError> {
        self.describe_auto_scaling_notification_types_op(ctx)
    }
    async fn describe_lifecycle_hook_types(
        &self,
        ctx: &RequestContext,
        _input: (),
    ) -> Result<types::DescribeLifecycleHookTypesAnswer, ServiceError> {
        self.describe_lifecycle_hook_types_op(ctx)
    }
    async fn describe_metric_collection_types(
        &self,
        ctx: &RequestContext,
        _input: (),
    ) -> Result<types::DescribeMetricCollectionTypesAnswer, ServiceError> {
        self.describe_metric_collection_types_op(ctx)
    }
    async fn describe_scaling_process_types(
        &self,
        ctx: &RequestContext,
        _input: (),
    ) -> Result<types::ProcessesType, ServiceError> {
        self.describe_scaling_process_types_op(ctx)
    }
    async fn describe_termination_policy_types(
        &self,
        ctx: &RequestContext,
        _input: (),
    ) -> Result<types::DescribeTerminationPolicyTypesAnswer, ServiceError> {
        self.describe_termination_policy_types_op(ctx)
    }
}

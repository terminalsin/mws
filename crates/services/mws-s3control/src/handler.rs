//! Wires the generated `Handler` trait to the operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::S3Control;

#[async_trait::async_trait]
impl Handler for S3Control {
    async fn create_job(
        &self,
        ctx: &RequestContext,
        input: types::CreateJobRequest,
    ) -> Result<types::CreateJobResult, ServiceError> {
        S3Control::create_job(self, ctx, input).await
    }
    async fn describe_job(
        &self,
        ctx: &RequestContext,
        input: types::DescribeJobRequest,
    ) -> Result<types::DescribeJobResult, ServiceError> {
        S3Control::describe_job(self, ctx, input).await
    }
    async fn list_jobs(
        &self,
        ctx: &RequestContext,
        input: types::ListJobsRequest,
    ) -> Result<types::ListJobsResult, ServiceError> {
        S3Control::list_jobs(self, ctx, input).await
    }
    async fn update_job_priority(
        &self,
        ctx: &RequestContext,
        input: types::UpdateJobPriorityRequest,
    ) -> Result<types::UpdateJobPriorityResult, ServiceError> {
        S3Control::update_job_priority(self, ctx, input).await
    }
    async fn update_job_status(
        &self,
        ctx: &RequestContext,
        input: types::UpdateJobStatusRequest,
    ) -> Result<types::UpdateJobStatusResult, ServiceError> {
        S3Control::update_job_status(self, ctx, input).await
    }
    async fn get_job_tagging(
        &self,
        ctx: &RequestContext,
        input: types::GetJobTaggingRequest,
    ) -> Result<types::GetJobTaggingResult, ServiceError> {
        S3Control::get_job_tagging(self, ctx, input).await
    }
    async fn put_job_tagging(
        &self,
        ctx: &RequestContext,
        input: types::PutJobTaggingRequest,
    ) -> Result<types::PutJobTaggingResult, ServiceError> {
        S3Control::put_job_tagging(self, ctx, input).await
    }
    async fn delete_job_tagging(
        &self,
        ctx: &RequestContext,
        input: types::DeleteJobTaggingRequest,
    ) -> Result<types::DeleteJobTaggingResult, ServiceError> {
        S3Control::delete_job_tagging(self, ctx, input).await
    }
    async fn create_access_point(
        &self,
        ctx: &RequestContext,
        input: types::CreateAccessPointRequest,
    ) -> Result<types::CreateAccessPointResult, ServiceError> {
        S3Control::create_access_point(self, ctx, input)
    }
    async fn create_access_point_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::CreateAccessPointForObjectLambdaRequest,
    ) -> Result<types::CreateAccessPointForObjectLambdaResult, ServiceError> {
        S3Control::create_access_point_for_object_lambda(self, ctx, input)
    }
    async fn delete_access_point(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessPointRequest,
    ) -> Result<(), ServiceError> {
        S3Control::delete_access_point(self, ctx, input)
    }
    async fn delete_access_point_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessPointForObjectLambdaRequest,
    ) -> Result<(), ServiceError> {
        S3Control::delete_access_point_for_object_lambda(self, ctx, input)
    }
    async fn delete_access_point_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessPointPolicyRequest,
    ) -> Result<(), ServiceError> {
        S3Control::delete_access_point_policy(self, ctx, input)
    }
    async fn delete_access_point_policy_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessPointPolicyForObjectLambdaRequest,
    ) -> Result<(), ServiceError> {
        S3Control::delete_access_point_policy_for_object_lambda(self, ctx, input)
    }
    async fn delete_public_access_block(
        &self,
        ctx: &RequestContext,
        input: types::DeletePublicAccessBlockRequest,
    ) -> Result<(), ServiceError> {
        S3Control::delete_public_access_block(self, ctx, input)
    }
    async fn get_access_point(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessPointRequest,
    ) -> Result<types::GetAccessPointResult, ServiceError> {
        S3Control::get_access_point(self, ctx, input)
    }
    async fn get_access_point_configuration_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessPointConfigurationForObjectLambdaRequest,
    ) -> Result<types::GetAccessPointConfigurationForObjectLambdaResult, ServiceError> {
        S3Control::get_access_point_configuration_for_object_lambda(self, ctx, input)
    }
    async fn get_access_point_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessPointForObjectLambdaRequest,
    ) -> Result<types::GetAccessPointForObjectLambdaResult, ServiceError> {
        S3Control::get_access_point_for_object_lambda(self, ctx, input)
    }
    async fn get_access_point_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessPointPolicyRequest,
    ) -> Result<types::GetAccessPointPolicyResult, ServiceError> {
        S3Control::get_access_point_policy(self, ctx, input)
    }
    async fn get_access_point_policy_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessPointPolicyForObjectLambdaRequest,
    ) -> Result<types::GetAccessPointPolicyForObjectLambdaResult, ServiceError> {
        S3Control::get_access_point_policy_for_object_lambda(self, ctx, input)
    }
    async fn get_access_point_policy_status(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessPointPolicyStatusRequest,
    ) -> Result<types::GetAccessPointPolicyStatusResult, ServiceError> {
        S3Control::get_access_point_policy_status(self, ctx, input)
    }
    async fn get_access_point_policy_status_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessPointPolicyStatusForObjectLambdaRequest,
    ) -> Result<types::GetAccessPointPolicyStatusForObjectLambdaResult, ServiceError> {
        S3Control::get_access_point_policy_status_for_object_lambda(self, ctx, input)
    }
    async fn get_public_access_block(
        &self,
        ctx: &RequestContext,
        input: types::GetPublicAccessBlockRequest,
    ) -> Result<types::GetPublicAccessBlockOutput, ServiceError> {
        S3Control::get_public_access_block(self, ctx, input)
    }
    async fn list_access_points(
        &self,
        ctx: &RequestContext,
        input: types::ListAccessPointsRequest,
    ) -> Result<types::ListAccessPointsResult, ServiceError> {
        S3Control::list_access_points(self, ctx, input)
    }
    async fn list_access_points_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::ListAccessPointsForObjectLambdaRequest,
    ) -> Result<types::ListAccessPointsForObjectLambdaResult, ServiceError> {
        S3Control::list_access_points_for_object_lambda(self, ctx, input)
    }
    async fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResult, ServiceError> {
        S3Control::list_tags_for_resource(self, ctx, input)
    }
    async fn put_access_point_configuration_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::PutAccessPointConfigurationForObjectLambdaRequest,
    ) -> Result<(), ServiceError> {
        S3Control::put_access_point_configuration_for_object_lambda(self, ctx, input)
    }
    async fn put_access_point_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutAccessPointPolicyRequest,
    ) -> Result<(), ServiceError> {
        S3Control::put_access_point_policy(self, ctx, input)
    }
    async fn put_access_point_policy_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::PutAccessPointPolicyForObjectLambdaRequest,
    ) -> Result<(), ServiceError> {
        S3Control::put_access_point_policy_for_object_lambda(self, ctx, input)
    }
    async fn put_public_access_block(
        &self,
        ctx: &RequestContext,
        input: types::PutPublicAccessBlockRequest,
    ) -> Result<(), ServiceError> {
        S3Control::put_public_access_block(self, ctx, input)
    }
    async fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<types::TagResourceResult, ServiceError> {
        S3Control::tag_resource(self, ctx, input)
    }
    async fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<types::UntagResourceResult, ServiceError> {
        S3Control::untag_resource(self, ctx, input)
    }
    async fn associate_access_grants_identity_center(
        &self,
        ctx: &RequestContext,
        input: types::AssociateAccessGrantsIdentityCenterRequest,
    ) -> Result<(), ServiceError> {
        S3Control::associate_access_grants_identity_center(self, ctx, input).await
    }
    async fn create_access_grant(
        &self,
        ctx: &RequestContext,
        input: types::CreateAccessGrantRequest,
    ) -> Result<types::CreateAccessGrantResult, ServiceError> {
        S3Control::create_access_grant(self, ctx, input).await
    }
    async fn create_access_grants_instance(
        &self,
        ctx: &RequestContext,
        input: types::CreateAccessGrantsInstanceRequest,
    ) -> Result<types::CreateAccessGrantsInstanceResult, ServiceError> {
        S3Control::create_access_grants_instance(self, ctx, input).await
    }
    async fn create_access_grants_location(
        &self,
        ctx: &RequestContext,
        input: types::CreateAccessGrantsLocationRequest,
    ) -> Result<types::CreateAccessGrantsLocationResult, ServiceError> {
        S3Control::create_access_grants_location(self, ctx, input).await
    }
    async fn create_multi_region_access_point(
        &self,
        ctx: &RequestContext,
        input: types::CreateMultiRegionAccessPointRequest,
    ) -> Result<types::CreateMultiRegionAccessPointResult, ServiceError> {
        S3Control::create_multi_region_access_point(self, ctx, input).await
    }
    async fn create_storage_lens_group(
        &self,
        ctx: &RequestContext,
        input: types::CreateStorageLensGroupRequest,
    ) -> Result<(), ServiceError> {
        S3Control::create_storage_lens_group(self, ctx, input).await
    }
    async fn delete_access_grant(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessGrantRequest,
    ) -> Result<(), ServiceError> {
        S3Control::delete_access_grant(self, ctx, input).await
    }
    async fn delete_access_grants_instance(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessGrantsInstanceRequest,
    ) -> Result<(), ServiceError> {
        S3Control::delete_access_grants_instance(self, ctx, input).await
    }
    async fn delete_access_grants_instance_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessGrantsInstanceResourcePolicyRequest,
    ) -> Result<(), ServiceError> {
        S3Control::delete_access_grants_instance_resource_policy(self, ctx, input).await
    }
    async fn delete_access_grants_location(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessGrantsLocationRequest,
    ) -> Result<(), ServiceError> {
        S3Control::delete_access_grants_location(self, ctx, input).await
    }
    async fn delete_access_point_scope(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessPointScopeRequest,
    ) -> Result<(), ServiceError> {
        S3Control::delete_access_point_scope(self, ctx, input)
    }
    async fn delete_multi_region_access_point(
        &self,
        ctx: &RequestContext,
        input: types::DeleteMultiRegionAccessPointRequest,
    ) -> Result<types::DeleteMultiRegionAccessPointResult, ServiceError> {
        S3Control::delete_multi_region_access_point(self, ctx, input).await
    }
    async fn delete_storage_lens_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DeleteStorageLensConfigurationRequest,
    ) -> Result<(), ServiceError> {
        S3Control::delete_storage_lens_configuration(self, ctx, input).await
    }
    async fn delete_storage_lens_configuration_tagging(
        &self,
        ctx: &RequestContext,
        input: types::DeleteStorageLensConfigurationTaggingRequest,
    ) -> Result<types::DeleteStorageLensConfigurationTaggingResult, ServiceError> {
        S3Control::delete_storage_lens_configuration_tagging(self, ctx, input).await
    }
    async fn delete_storage_lens_group(
        &self,
        ctx: &RequestContext,
        input: types::DeleteStorageLensGroupRequest,
    ) -> Result<(), ServiceError> {
        S3Control::delete_storage_lens_group(self, ctx, input).await
    }
    async fn describe_multi_region_access_point_operation(
        &self,
        ctx: &RequestContext,
        input: types::DescribeMultiRegionAccessPointOperationRequest,
    ) -> Result<types::DescribeMultiRegionAccessPointOperationResult, ServiceError> {
        S3Control::describe_multi_region_access_point_operation(self, ctx, input).await
    }
    async fn dissociate_access_grants_identity_center(
        &self,
        ctx: &RequestContext,
        input: types::DissociateAccessGrantsIdentityCenterRequest,
    ) -> Result<(), ServiceError> {
        S3Control::dissociate_access_grants_identity_center(self, ctx, input).await
    }
    async fn get_access_grant(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessGrantRequest,
    ) -> Result<types::GetAccessGrantResult, ServiceError> {
        S3Control::get_access_grant(self, ctx, input).await
    }
    async fn get_access_grants_instance(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessGrantsInstanceRequest,
    ) -> Result<types::GetAccessGrantsInstanceResult, ServiceError> {
        S3Control::get_access_grants_instance(self, ctx, input).await
    }
    async fn get_access_grants_instance_for_prefix(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessGrantsInstanceForPrefixRequest,
    ) -> Result<types::GetAccessGrantsInstanceForPrefixResult, ServiceError> {
        S3Control::get_access_grants_instance_for_prefix(self, ctx, input).await
    }
    async fn get_access_grants_instance_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessGrantsInstanceResourcePolicyRequest,
    ) -> Result<types::GetAccessGrantsInstanceResourcePolicyResult, ServiceError> {
        S3Control::get_access_grants_instance_resource_policy(self, ctx, input).await
    }
    async fn get_access_grants_location(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessGrantsLocationRequest,
    ) -> Result<types::GetAccessGrantsLocationResult, ServiceError> {
        S3Control::get_access_grants_location(self, ctx, input).await
    }
    async fn get_access_point_scope(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessPointScopeRequest,
    ) -> Result<types::GetAccessPointScopeResult, ServiceError> {
        S3Control::get_access_point_scope(self, ctx, input)
    }
    async fn get_data_access(
        &self,
        ctx: &RequestContext,
        input: types::GetDataAccessRequest,
    ) -> Result<types::GetDataAccessResult, ServiceError> {
        S3Control::get_data_access(self, ctx, input).await
    }
    async fn get_multi_region_access_point(
        &self,
        ctx: &RequestContext,
        input: types::GetMultiRegionAccessPointRequest,
    ) -> Result<types::GetMultiRegionAccessPointResult, ServiceError> {
        S3Control::get_multi_region_access_point(self, ctx, input).await
    }
    async fn get_multi_region_access_point_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetMultiRegionAccessPointPolicyRequest,
    ) -> Result<types::GetMultiRegionAccessPointPolicyResult, ServiceError> {
        S3Control::get_multi_region_access_point_policy(self, ctx, input).await
    }
    async fn get_multi_region_access_point_policy_status(
        &self,
        ctx: &RequestContext,
        input: types::GetMultiRegionAccessPointPolicyStatusRequest,
    ) -> Result<types::GetMultiRegionAccessPointPolicyStatusResult, ServiceError> {
        S3Control::get_multi_region_access_point_policy_status(self, ctx, input).await
    }
    async fn get_multi_region_access_point_routes(
        &self,
        ctx: &RequestContext,
        input: types::GetMultiRegionAccessPointRoutesRequest,
    ) -> Result<types::GetMultiRegionAccessPointRoutesResult, ServiceError> {
        S3Control::get_multi_region_access_point_routes(self, ctx, input).await
    }
    async fn get_storage_lens_configuration(
        &self,
        ctx: &RequestContext,
        input: types::GetStorageLensConfigurationRequest,
    ) -> Result<types::GetStorageLensConfigurationResult, ServiceError> {
        S3Control::get_storage_lens_configuration(self, ctx, input).await
    }
    async fn get_storage_lens_configuration_tagging(
        &self,
        ctx: &RequestContext,
        input: types::GetStorageLensConfigurationTaggingRequest,
    ) -> Result<types::GetStorageLensConfigurationTaggingResult, ServiceError> {
        S3Control::get_storage_lens_configuration_tagging(self, ctx, input).await
    }
    async fn get_storage_lens_group(
        &self,
        ctx: &RequestContext,
        input: types::GetStorageLensGroupRequest,
    ) -> Result<types::GetStorageLensGroupResult, ServiceError> {
        S3Control::get_storage_lens_group(self, ctx, input).await
    }
    async fn list_access_grants(
        &self,
        ctx: &RequestContext,
        input: types::ListAccessGrantsRequest,
    ) -> Result<types::ListAccessGrantsResult, ServiceError> {
        S3Control::list_access_grants(self, ctx, input).await
    }
    async fn list_access_grants_instances(
        &self,
        ctx: &RequestContext,
        input: types::ListAccessGrantsInstancesRequest,
    ) -> Result<types::ListAccessGrantsInstancesResult, ServiceError> {
        S3Control::list_access_grants_instances(self, ctx, input).await
    }
    async fn list_access_grants_locations(
        &self,
        ctx: &RequestContext,
        input: types::ListAccessGrantsLocationsRequest,
    ) -> Result<types::ListAccessGrantsLocationsResult, ServiceError> {
        S3Control::list_access_grants_locations(self, ctx, input).await
    }
    async fn list_access_points_for_directory_buckets(
        &self,
        ctx: &RequestContext,
        input: types::ListAccessPointsForDirectoryBucketsRequest,
    ) -> Result<types::ListAccessPointsForDirectoryBucketsResult, ServiceError> {
        S3Control::list_access_points_for_directory_buckets(self, ctx, input)
    }
    async fn list_caller_access_grants(
        &self,
        ctx: &RequestContext,
        input: types::ListCallerAccessGrantsRequest,
    ) -> Result<types::ListCallerAccessGrantsResult, ServiceError> {
        S3Control::list_caller_access_grants(self, ctx, input).await
    }
    async fn list_multi_region_access_points(
        &self,
        ctx: &RequestContext,
        input: types::ListMultiRegionAccessPointsRequest,
    ) -> Result<types::ListMultiRegionAccessPointsResult, ServiceError> {
        S3Control::list_multi_region_access_points(self, ctx, input).await
    }
    async fn list_storage_lens_configurations(
        &self,
        ctx: &RequestContext,
        input: types::ListStorageLensConfigurationsRequest,
    ) -> Result<types::ListStorageLensConfigurationsResult, ServiceError> {
        S3Control::list_storage_lens_configurations(self, ctx, input).await
    }
    async fn list_storage_lens_groups(
        &self,
        ctx: &RequestContext,
        input: types::ListStorageLensGroupsRequest,
    ) -> Result<types::ListStorageLensGroupsResult, ServiceError> {
        S3Control::list_storage_lens_groups(self, ctx, input).await
    }
    async fn put_access_grants_instance_resource_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutAccessGrantsInstanceResourcePolicyRequest,
    ) -> Result<types::PutAccessGrantsInstanceResourcePolicyResult, ServiceError> {
        S3Control::put_access_grants_instance_resource_policy(self, ctx, input).await
    }
    async fn put_access_point_scope(
        &self,
        ctx: &RequestContext,
        input: types::PutAccessPointScopeRequest,
    ) -> Result<(), ServiceError> {
        S3Control::put_access_point_scope(self, ctx, input)
    }
    async fn put_multi_region_access_point_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutMultiRegionAccessPointPolicyRequest,
    ) -> Result<types::PutMultiRegionAccessPointPolicyResult, ServiceError> {
        S3Control::put_multi_region_access_point_policy(self, ctx, input).await
    }
    async fn put_storage_lens_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutStorageLensConfigurationRequest,
    ) -> Result<(), ServiceError> {
        S3Control::put_storage_lens_configuration(self, ctx, input).await
    }
    async fn put_storage_lens_configuration_tagging(
        &self,
        ctx: &RequestContext,
        input: types::PutStorageLensConfigurationTaggingRequest,
    ) -> Result<types::PutStorageLensConfigurationTaggingResult, ServiceError> {
        S3Control::put_storage_lens_configuration_tagging(self, ctx, input).await
    }
    async fn submit_multi_region_access_point_routes(
        &self,
        ctx: &RequestContext,
        input: types::SubmitMultiRegionAccessPointRoutesRequest,
    ) -> Result<types::SubmitMultiRegionAccessPointRoutesResult, ServiceError> {
        S3Control::submit_multi_region_access_point_routes(self, ctx, input).await
    }
    async fn update_access_grants_location(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAccessGrantsLocationRequest,
    ) -> Result<types::UpdateAccessGrantsLocationResult, ServiceError> {
        S3Control::update_access_grants_location(self, ctx, input).await
    }
    async fn update_storage_lens_group(
        &self,
        ctx: &RequestContext,
        input: types::UpdateStorageLensGroupRequest,
    ) -> Result<(), ServiceError> {
        S3Control::update_storage_lens_group(self, ctx, input).await
    }
}

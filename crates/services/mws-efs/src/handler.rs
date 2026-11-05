//! Wires the generated `Handler` trait to the operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::Efs;

#[async_trait::async_trait]
impl Handler for Efs {
    async fn create_access_point(
        &self,
        ctx: &RequestContext,
        input: types::CreateAccessPointRequest,
    ) -> Result<types::AccessPointDescription, ServiceError> {
        Efs::create_access_point(self, ctx, input).await
    }
    async fn create_file_system(
        &self,
        ctx: &RequestContext,
        input: types::CreateFileSystemRequest,
    ) -> Result<types::FileSystemDescription, ServiceError> {
        Efs::create_file_system(self, ctx, input).await
    }
    async fn create_mount_target(
        &self,
        ctx: &RequestContext,
        input: types::CreateMountTargetRequest,
    ) -> Result<types::MountTargetDescription, ServiceError> {
        Efs::create_mount_target(self, ctx, input).await
    }
    async fn create_replication_configuration(
        &self,
        ctx: &RequestContext,
        input: types::CreateReplicationConfigurationRequest,
    ) -> Result<types::ReplicationConfigurationDescription, ServiceError> {
        Efs::create_replication_configuration(self, ctx, input).await
    }
    async fn create_tags(&self, ctx: &RequestContext, input: types::CreateTagsRequest) -> Result<(), ServiceError> {
        Efs::create_tags(self, ctx, input).await
    }
    async fn delete_access_point(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessPointRequest,
    ) -> Result<(), ServiceError> {
        Efs::delete_access_point(self, ctx, input).await
    }
    async fn delete_file_system(
        &self,
        ctx: &RequestContext,
        input: types::DeleteFileSystemRequest,
    ) -> Result<(), ServiceError> {
        Efs::delete_file_system(self, ctx, input).await
    }
    async fn delete_file_system_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteFileSystemPolicyRequest,
    ) -> Result<(), ServiceError> {
        Efs::delete_file_system_policy(self, ctx, input).await
    }
    async fn delete_mount_target(
        &self,
        ctx: &RequestContext,
        input: types::DeleteMountTargetRequest,
    ) -> Result<(), ServiceError> {
        Efs::delete_mount_target(self, ctx, input).await
    }
    async fn delete_replication_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DeleteReplicationConfigurationRequest,
    ) -> Result<(), ServiceError> {
        Efs::delete_replication_configuration(self, ctx, input).await
    }
    async fn delete_tags(&self, ctx: &RequestContext, input: types::DeleteTagsRequest) -> Result<(), ServiceError> {
        Efs::delete_tags(self, ctx, input).await
    }
    async fn describe_access_points(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAccessPointsRequest,
    ) -> Result<types::DescribeAccessPointsResponse, ServiceError> {
        Efs::describe_access_points(self, ctx, input).await
    }
    async fn describe_account_preferences(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAccountPreferencesRequest,
    ) -> Result<types::DescribeAccountPreferencesResponse, ServiceError> {
        Efs::describe_account_preferences(self, ctx, input).await
    }
    async fn describe_backup_policy(
        &self,
        ctx: &RequestContext,
        input: types::DescribeBackupPolicyRequest,
    ) -> Result<types::BackupPolicyDescription, ServiceError> {
        Efs::describe_backup_policy(self, ctx, input).await
    }
    async fn describe_file_system_policy(
        &self,
        ctx: &RequestContext,
        input: types::DescribeFileSystemPolicyRequest,
    ) -> Result<types::FileSystemPolicyDescription, ServiceError> {
        Efs::describe_file_system_policy(self, ctx, input).await
    }
    async fn describe_file_systems(
        &self,
        ctx: &RequestContext,
        input: types::DescribeFileSystemsRequest,
    ) -> Result<types::DescribeFileSystemsResponse, ServiceError> {
        Efs::describe_file_systems(self, ctx, input).await
    }
    async fn describe_lifecycle_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DescribeLifecycleConfigurationRequest,
    ) -> Result<types::LifecycleConfigurationDescription, ServiceError> {
        Efs::describe_lifecycle_configuration(self, ctx, input).await
    }
    async fn describe_mount_target_security_groups(
        &self,
        ctx: &RequestContext,
        input: types::DescribeMountTargetSecurityGroupsRequest,
    ) -> Result<types::DescribeMountTargetSecurityGroupsResponse, ServiceError> {
        Efs::describe_mount_target_security_groups(self, ctx, input).await
    }
    async fn describe_mount_targets(
        &self,
        ctx: &RequestContext,
        input: types::DescribeMountTargetsRequest,
    ) -> Result<types::DescribeMountTargetsResponse, ServiceError> {
        Efs::describe_mount_targets(self, ctx, input).await
    }
    async fn describe_replication_configurations(
        &self,
        ctx: &RequestContext,
        input: types::DescribeReplicationConfigurationsRequest,
    ) -> Result<types::DescribeReplicationConfigurationsResponse, ServiceError> {
        Efs::describe_replication_configurations(self, ctx, input).await
    }
    async fn describe_tags(
        &self,
        ctx: &RequestContext,
        input: types::DescribeTagsRequest,
    ) -> Result<types::DescribeTagsResponse, ServiceError> {
        Efs::describe_tags(self, ctx, input).await
    }
    async fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        Efs::list_tags_for_resource(self, ctx, input).await
    }
    async fn modify_mount_target_security_groups(
        &self,
        ctx: &RequestContext,
        input: types::ModifyMountTargetSecurityGroupsRequest,
    ) -> Result<(), ServiceError> {
        Efs::modify_mount_target_security_groups(self, ctx, input).await
    }
    async fn put_account_preferences(
        &self,
        ctx: &RequestContext,
        input: types::PutAccountPreferencesRequest,
    ) -> Result<types::PutAccountPreferencesResponse, ServiceError> {
        Efs::put_account_preferences(self, ctx, input).await
    }
    async fn put_backup_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutBackupPolicyRequest,
    ) -> Result<types::BackupPolicyDescription, ServiceError> {
        Efs::put_backup_policy(self, ctx, input).await
    }
    async fn put_file_system_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutFileSystemPolicyRequest,
    ) -> Result<types::FileSystemPolicyDescription, ServiceError> {
        Efs::put_file_system_policy(self, ctx, input).await
    }
    async fn put_lifecycle_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutLifecycleConfigurationRequest,
    ) -> Result<types::LifecycleConfigurationDescription, ServiceError> {
        Efs::put_lifecycle_configuration(self, ctx, input).await
    }
    async fn tag_resource(&self, ctx: &RequestContext, input: types::TagResourceRequest) -> Result<(), ServiceError> {
        Efs::tag_resource(self, ctx, input).await
    }
    async fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<(), ServiceError> {
        Efs::untag_resource(self, ctx, input).await
    }
    async fn update_file_system(
        &self,
        ctx: &RequestContext,
        input: types::UpdateFileSystemRequest,
    ) -> Result<types::FileSystemDescription, ServiceError> {
        Efs::update_file_system(self, ctx, input).await
    }
    async fn update_file_system_protection(
        &self,
        ctx: &RequestContext,
        input: types::UpdateFileSystemProtectionRequest,
    ) -> Result<types::FileSystemProtectionDescription, ServiceError> {
        Efs::update_file_system_protection(self, ctx, input).await
    }
}

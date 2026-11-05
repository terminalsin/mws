//! `generated::Handler`: every operation forwards to `ops`.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::ops::*;
use crate::ElastiCache;

#[async_trait::async_trait]
impl Handler for ElastiCache {
    async fn add_tags_to_resource(
        &self,
        ctx: &RequestContext,
        input: types::AddTagsToResourceMessage,
    ) -> Result<types::TagListMessage, ServiceError> {
        misc::add_tags(self, ctx, input).await
    }
    async fn authorize_cache_security_group_ingress(
        &self,
        ctx: &RequestContext,
        input: types::AuthorizeCacheSecurityGroupIngressMessage,
    ) -> Result<types::AuthorizeCacheSecurityGroupIngressResult, ServiceError> {
        subnets::authorize_ingress(self, ctx, input).await
    }
    async fn batch_apply_update_action(
        &self,
        ctx: &RequestContext,
        input: types::BatchApplyUpdateActionMessage,
    ) -> Result<types::UpdateActionResultsMessage, ServiceError> {
        misc::batch_apply(self, ctx, input).await
    }
    async fn batch_stop_update_action(
        &self,
        ctx: &RequestContext,
        input: types::BatchStopUpdateActionMessage,
    ) -> Result<types::UpdateActionResultsMessage, ServiceError> {
        misc::batch_stop(self, ctx, input).await
    }
    async fn complete_migration(
        &self,
        ctx: &RequestContext,
        input: types::CompleteMigrationMessage,
    ) -> Result<types::CompleteMigrationResponse, ServiceError> {
        replication::complete_migration(self, ctx, input).await
    }
    async fn copy_serverless_cache_snapshot(
        &self,
        ctx: &RequestContext,
        input: types::CopyServerlessCacheSnapshotRequest,
    ) -> Result<types::CopyServerlessCacheSnapshotResponse, ServiceError> {
        serverless::copy_snapshot(self, ctx, input).await
    }
    async fn copy_snapshot(
        &self,
        ctx: &RequestContext,
        input: types::CopySnapshotMessage,
    ) -> Result<types::CopySnapshotResult, ServiceError> {
        snapshots::copy(self, ctx, input).await
    }
    async fn create_cache_cluster(
        &self,
        ctx: &RequestContext,
        input: types::CreateCacheClusterMessage,
    ) -> Result<types::CreateCacheClusterResult, ServiceError> {
        clusters::create(self, ctx, input).await
    }
    async fn create_cache_parameter_group(
        &self,
        ctx: &RequestContext,
        input: types::CreateCacheParameterGroupMessage,
    ) -> Result<types::CreateCacheParameterGroupResult, ServiceError> {
        params::create(self, ctx, input).await
    }
    async fn create_cache_security_group(
        &self,
        ctx: &RequestContext,
        input: types::CreateCacheSecurityGroupMessage,
    ) -> Result<types::CreateCacheSecurityGroupResult, ServiceError> {
        subnets::create_security_group(self, ctx, input).await
    }
    async fn create_cache_subnet_group(
        &self,
        ctx: &RequestContext,
        input: types::CreateCacheSubnetGroupMessage,
    ) -> Result<types::CreateCacheSubnetGroupResult, ServiceError> {
        subnets::create(self, ctx, input).await
    }
    async fn create_global_replication_group(
        &self,
        ctx: &RequestContext,
        input: types::CreateGlobalReplicationGroupMessage,
    ) -> Result<types::CreateGlobalReplicationGroupResult, ServiceError> {
        global::create(self, ctx, input).await
    }
    async fn create_replication_group(
        &self,
        ctx: &RequestContext,
        input: types::CreateReplicationGroupMessage,
    ) -> Result<types::CreateReplicationGroupResult, ServiceError> {
        replication::create(self, ctx, input).await
    }
    async fn create_serverless_cache(
        &self,
        ctx: &RequestContext,
        input: types::CreateServerlessCacheRequest,
    ) -> Result<types::CreateServerlessCacheResponse, ServiceError> {
        serverless::create(self, ctx, input).await
    }
    async fn create_serverless_cache_snapshot(
        &self,
        ctx: &RequestContext,
        input: types::CreateServerlessCacheSnapshotRequest,
    ) -> Result<types::CreateServerlessCacheSnapshotResponse, ServiceError> {
        serverless::create_snapshot(self, ctx, input).await
    }
    async fn create_snapshot(
        &self,
        ctx: &RequestContext,
        input: types::CreateSnapshotMessage,
    ) -> Result<types::CreateSnapshotResult, ServiceError> {
        snapshots::create(self, ctx, input).await
    }
    async fn create_user(
        &self,
        ctx: &RequestContext,
        input: types::CreateUserMessage,
    ) -> Result<types::User, ServiceError> {
        users::create(self, ctx, input).await
    }
    async fn create_user_group(
        &self,
        ctx: &RequestContext,
        input: types::CreateUserGroupMessage,
    ) -> Result<types::UserGroup, ServiceError> {
        users::create_group(self, ctx, input).await
    }
    async fn decrease_node_groups_in_global_replication_group(
        &self,
        ctx: &RequestContext,
        input: types::DecreaseNodeGroupsInGlobalReplicationGroupMessage,
    ) -> Result<types::DecreaseNodeGroupsInGlobalReplicationGroupResult, ServiceError> {
        global::decrease_node_groups(self, ctx, input).await
    }
    async fn decrease_replica_count(
        &self,
        ctx: &RequestContext,
        input: types::DecreaseReplicaCountMessage,
    ) -> Result<types::DecreaseReplicaCountResult, ServiceError> {
        replication::decrease_replicas(self, ctx, input).await
    }
    async fn delete_cache_cluster(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCacheClusterMessage,
    ) -> Result<types::DeleteCacheClusterResult, ServiceError> {
        clusters::delete(self, ctx, input).await
    }
    async fn delete_global_replication_group(
        &self,
        ctx: &RequestContext,
        input: types::DeleteGlobalReplicationGroupMessage,
    ) -> Result<types::DeleteGlobalReplicationGroupResult, ServiceError> {
        global::delete(self, ctx, input).await
    }
    async fn delete_replication_group(
        &self,
        ctx: &RequestContext,
        input: types::DeleteReplicationGroupMessage,
    ) -> Result<types::DeleteReplicationGroupResult, ServiceError> {
        replication::delete(self, ctx, input).await
    }
    async fn delete_serverless_cache(
        &self,
        ctx: &RequestContext,
        input: types::DeleteServerlessCacheRequest,
    ) -> Result<types::DeleteServerlessCacheResponse, ServiceError> {
        serverless::delete(self, ctx, input).await
    }
    async fn delete_serverless_cache_snapshot(
        &self,
        ctx: &RequestContext,
        input: types::DeleteServerlessCacheSnapshotRequest,
    ) -> Result<types::DeleteServerlessCacheSnapshotResponse, ServiceError> {
        serverless::delete_snapshot(self, ctx, input).await
    }
    async fn delete_snapshot(
        &self,
        ctx: &RequestContext,
        input: types::DeleteSnapshotMessage,
    ) -> Result<types::DeleteSnapshotResult, ServiceError> {
        snapshots::delete(self, ctx, input).await
    }
    async fn delete_user(
        &self,
        ctx: &RequestContext,
        input: types::DeleteUserMessage,
    ) -> Result<types::User, ServiceError> {
        users::delete(self, ctx, input).await
    }
    async fn delete_user_group(
        &self,
        ctx: &RequestContext,
        input: types::DeleteUserGroupMessage,
    ) -> Result<types::UserGroup, ServiceError> {
        users::delete_group(self, ctx, input).await
    }
    async fn describe_cache_clusters(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCacheClustersMessage,
    ) -> Result<types::CacheClusterMessage, ServiceError> {
        clusters::describe(self, ctx, input).await
    }
    async fn describe_cache_engine_versions(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCacheEngineVersionsMessage,
    ) -> Result<types::CacheEngineVersionMessage, ServiceError> {
        misc::describe_engine_versions(self, ctx, input).await
    }
    async fn describe_cache_parameter_groups(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCacheParameterGroupsMessage,
    ) -> Result<types::CacheParameterGroupsMessage, ServiceError> {
        params::describe_groups(self, ctx, input).await
    }
    async fn describe_cache_parameters(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCacheParametersMessage,
    ) -> Result<types::CacheParameterGroupDetails, ServiceError> {
        params::describe_parameters(self, ctx, input).await
    }
    async fn describe_cache_security_groups(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCacheSecurityGroupsMessage,
    ) -> Result<types::CacheSecurityGroupMessage, ServiceError> {
        subnets::describe_security_groups(self, ctx, input).await
    }
    async fn describe_cache_subnet_groups(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCacheSubnetGroupsMessage,
    ) -> Result<types::CacheSubnetGroupMessage, ServiceError> {
        subnets::describe(self, ctx, input).await
    }
    async fn describe_engine_default_parameters(
        &self,
        ctx: &RequestContext,
        input: types::DescribeEngineDefaultParametersMessage,
    ) -> Result<types::DescribeEngineDefaultParametersResult, ServiceError> {
        params::describe_defaults(self, ctx, input).await
    }
    async fn describe_events(
        &self,
        ctx: &RequestContext,
        input: types::DescribeEventsMessage,
    ) -> Result<types::EventsMessage, ServiceError> {
        misc::describe_events(self, ctx, input).await
    }
    async fn describe_global_replication_groups(
        &self,
        ctx: &RequestContext,
        input: types::DescribeGlobalReplicationGroupsMessage,
    ) -> Result<types::DescribeGlobalReplicationGroupsResult, ServiceError> {
        global::describe(self, ctx, input).await
    }
    async fn describe_replication_groups(
        &self,
        ctx: &RequestContext,
        input: types::DescribeReplicationGroupsMessage,
    ) -> Result<types::ReplicationGroupMessage, ServiceError> {
        replication::describe(self, ctx, input).await
    }
    async fn describe_reserved_cache_nodes(
        &self,
        ctx: &RequestContext,
        input: types::DescribeReservedCacheNodesMessage,
    ) -> Result<types::ReservedCacheNodeMessage, ServiceError> {
        misc::describe_reserved(self, ctx, input).await
    }
    async fn describe_reserved_cache_nodes_offerings(
        &self,
        ctx: &RequestContext,
        input: types::DescribeReservedCacheNodesOfferingsMessage,
    ) -> Result<types::ReservedCacheNodesOfferingMessage, ServiceError> {
        misc::describe_offerings(self, ctx, input).await
    }
    async fn describe_serverless_cache_snapshots(
        &self,
        ctx: &RequestContext,
        input: types::DescribeServerlessCacheSnapshotsRequest,
    ) -> Result<types::DescribeServerlessCacheSnapshotsResponse, ServiceError> {
        serverless::describe_snapshots(self, ctx, input).await
    }
    async fn describe_serverless_caches(
        &self,
        ctx: &RequestContext,
        input: types::DescribeServerlessCachesRequest,
    ) -> Result<types::DescribeServerlessCachesResponse, ServiceError> {
        serverless::describe(self, ctx, input).await
    }
    async fn describe_service_updates(
        &self,
        ctx: &RequestContext,
        input: types::DescribeServiceUpdatesMessage,
    ) -> Result<types::ServiceUpdatesMessage, ServiceError> {
        misc::describe_service_updates(self, ctx, input).await
    }
    async fn describe_snapshots(
        &self,
        ctx: &RequestContext,
        input: types::DescribeSnapshotsMessage,
    ) -> Result<types::DescribeSnapshotsListMessage, ServiceError> {
        snapshots::describe(self, ctx, input).await
    }
    async fn describe_update_actions(
        &self,
        ctx: &RequestContext,
        input: types::DescribeUpdateActionsMessage,
    ) -> Result<types::UpdateActionsMessage, ServiceError> {
        misc::describe_update_actions(self, ctx, input).await
    }
    async fn describe_user_groups(
        &self,
        ctx: &RequestContext,
        input: types::DescribeUserGroupsMessage,
    ) -> Result<types::DescribeUserGroupsResult, ServiceError> {
        users::describe_groups(self, ctx, input).await
    }
    async fn describe_users(
        &self,
        ctx: &RequestContext,
        input: types::DescribeUsersMessage,
    ) -> Result<types::DescribeUsersResult, ServiceError> {
        users::describe(self, ctx, input).await
    }
    async fn disassociate_global_replication_group(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateGlobalReplicationGroupMessage,
    ) -> Result<types::DisassociateGlobalReplicationGroupResult, ServiceError> {
        global::disassociate(self, ctx, input).await
    }
    async fn export_serverless_cache_snapshot(
        &self,
        ctx: &RequestContext,
        input: types::ExportServerlessCacheSnapshotRequest,
    ) -> Result<types::ExportServerlessCacheSnapshotResponse, ServiceError> {
        serverless::export_snapshot(self, ctx, input).await
    }
    async fn failover_global_replication_group(
        &self,
        ctx: &RequestContext,
        input: types::FailoverGlobalReplicationGroupMessage,
    ) -> Result<types::FailoverGlobalReplicationGroupResult, ServiceError> {
        global::failover(self, ctx, input).await
    }
    async fn increase_node_groups_in_global_replication_group(
        &self,
        ctx: &RequestContext,
        input: types::IncreaseNodeGroupsInGlobalReplicationGroupMessage,
    ) -> Result<types::IncreaseNodeGroupsInGlobalReplicationGroupResult, ServiceError> {
        global::increase_node_groups(self, ctx, input).await
    }
    async fn increase_replica_count(
        &self,
        ctx: &RequestContext,
        input: types::IncreaseReplicaCountMessage,
    ) -> Result<types::IncreaseReplicaCountResult, ServiceError> {
        replication::increase_replicas(self, ctx, input).await
    }
    async fn list_allowed_node_type_modifications(
        &self,
        ctx: &RequestContext,
        input: types::ListAllowedNodeTypeModificationsMessage,
    ) -> Result<types::AllowedNodeTypeModificationsMessage, ServiceError> {
        clusters::allowed_node_types(self, ctx, input).await
    }
    async fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceMessage,
    ) -> Result<types::TagListMessage, ServiceError> {
        misc::list_tags(self, ctx, input).await
    }
    async fn modify_cache_cluster(
        &self,
        ctx: &RequestContext,
        input: types::ModifyCacheClusterMessage,
    ) -> Result<types::ModifyCacheClusterResult, ServiceError> {
        clusters::modify(self, ctx, input).await
    }
    async fn modify_cache_parameter_group(
        &self,
        ctx: &RequestContext,
        input: types::ModifyCacheParameterGroupMessage,
    ) -> Result<types::CacheParameterGroupNameMessage, ServiceError> {
        params::modify(self, ctx, input).await
    }
    async fn modify_cache_subnet_group(
        &self,
        ctx: &RequestContext,
        input: types::ModifyCacheSubnetGroupMessage,
    ) -> Result<types::ModifyCacheSubnetGroupResult, ServiceError> {
        subnets::modify(self, ctx, input).await
    }
    async fn modify_global_replication_group(
        &self,
        ctx: &RequestContext,
        input: types::ModifyGlobalReplicationGroupMessage,
    ) -> Result<types::ModifyGlobalReplicationGroupResult, ServiceError> {
        global::modify(self, ctx, input).await
    }
    async fn modify_replication_group(
        &self,
        ctx: &RequestContext,
        input: types::ModifyReplicationGroupMessage,
    ) -> Result<types::ModifyReplicationGroupResult, ServiceError> {
        replication::modify(self, ctx, input).await
    }
    async fn modify_replication_group_shard_configuration(
        &self,
        ctx: &RequestContext,
        input: types::ModifyReplicationGroupShardConfigurationMessage,
    ) -> Result<types::ModifyReplicationGroupShardConfigurationResult, ServiceError> {
        replication::modify_shards(self, ctx, input).await
    }
    async fn modify_serverless_cache(
        &self,
        ctx: &RequestContext,
        input: types::ModifyServerlessCacheRequest,
    ) -> Result<types::ModifyServerlessCacheResponse, ServiceError> {
        serverless::modify(self, ctx, input).await
    }
    async fn modify_user(
        &self,
        ctx: &RequestContext,
        input: types::ModifyUserMessage,
    ) -> Result<types::User, ServiceError> {
        users::modify(self, ctx, input).await
    }
    async fn modify_user_group(
        &self,
        ctx: &RequestContext,
        input: types::ModifyUserGroupMessage,
    ) -> Result<types::UserGroup, ServiceError> {
        users::modify_group(self, ctx, input).await
    }
    async fn prepare_migration(
        &self,
        ctx: &RequestContext,
        input: types::PrepareMigrationRequest,
    ) -> Result<types::PrepareMigrationResponse, ServiceError> {
        serverless::prepare_migration(self, ctx, input).await
    }
    async fn purchase_reserved_cache_nodes_offering(
        &self,
        ctx: &RequestContext,
        input: types::PurchaseReservedCacheNodesOfferingMessage,
    ) -> Result<types::PurchaseReservedCacheNodesOfferingResult, ServiceError> {
        misc::purchase_offering(self, ctx, input).await
    }
    async fn rebalance_slots_in_global_replication_group(
        &self,
        ctx: &RequestContext,
        input: types::RebalanceSlotsInGlobalReplicationGroupMessage,
    ) -> Result<types::RebalanceSlotsInGlobalReplicationGroupResult, ServiceError> {
        global::rebalance(self, ctx, input).await
    }
    async fn reboot_cache_cluster(
        &self,
        ctx: &RequestContext,
        input: types::RebootCacheClusterMessage,
    ) -> Result<types::RebootCacheClusterResult, ServiceError> {
        clusters::reboot(self, ctx, input).await
    }
    async fn remove_tags_from_resource(
        &self,
        ctx: &RequestContext,
        input: types::RemoveTagsFromResourceMessage,
    ) -> Result<types::TagListMessage, ServiceError> {
        misc::remove_tags(self, ctx, input).await
    }
    async fn reset_cache_parameter_group(
        &self,
        ctx: &RequestContext,
        input: types::ResetCacheParameterGroupMessage,
    ) -> Result<types::CacheParameterGroupNameMessage, ServiceError> {
        params::reset(self, ctx, input).await
    }
    async fn revoke_cache_security_group_ingress(
        &self,
        ctx: &RequestContext,
        input: types::RevokeCacheSecurityGroupIngressMessage,
    ) -> Result<types::RevokeCacheSecurityGroupIngressResult, ServiceError> {
        subnets::revoke_ingress(self, ctx, input).await
    }
    async fn start_migration(
        &self,
        ctx: &RequestContext,
        input: types::StartMigrationMessage,
    ) -> Result<types::StartMigrationResponse, ServiceError> {
        replication::start_migration(self, ctx, input).await
    }
    async fn stop_migration(
        &self,
        ctx: &RequestContext,
        input: types::StopMigrationRequest,
    ) -> Result<types::StopMigrationResponse, ServiceError> {
        serverless::stop_migration(self, ctx, input).await
    }
    async fn test_failover(
        &self,
        ctx: &RequestContext,
        input: types::TestFailoverMessage,
    ) -> Result<types::TestFailoverResult, ServiceError> {
        replication::test_failover(self, ctx, input).await
    }
    async fn test_migration(
        &self,
        ctx: &RequestContext,
        input: types::TestMigrationMessage,
    ) -> Result<types::TestMigrationResponse, ServiceError> {
        replication::test_migration(self, ctx, input).await
    }
    async fn delete_cache_parameter_group(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCacheParameterGroupMessage,
    ) -> Result<(), ServiceError> {
        params::delete(self, ctx, input).await
    }
    async fn delete_cache_security_group(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCacheSecurityGroupMessage,
    ) -> Result<(), ServiceError> {
        subnets::delete_security_group(self, ctx, input).await
    }
    async fn delete_cache_subnet_group(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCacheSubnetGroupMessage,
    ) -> Result<(), ServiceError> {
        subnets::delete(self, ctx, input).await
    }
}

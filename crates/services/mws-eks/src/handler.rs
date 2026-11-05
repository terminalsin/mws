//! Wires the generated `Handler` trait to the operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::Eks;

#[async_trait::async_trait]
impl Handler for Eks {
    async fn activate_certificate_authority(
        &self,
        ctx: &RequestContext,
        input: types::ActivateCertificateAuthorityRequest,
    ) -> Result<types::ActivateCertificateAuthorityResponse, ServiceError> {
        Eks::activate_certificate_authority(self, ctx, input).await
    }
    async fn associate_access_policy(
        &self,
        ctx: &RequestContext,
        input: types::AssociateAccessPolicyRequest,
    ) -> Result<types::AssociateAccessPolicyResponse, ServiceError> {
        Eks::associate_access_policy(self, ctx, input).await
    }
    async fn associate_encryption_config(
        &self,
        ctx: &RequestContext,
        input: types::AssociateEncryptionConfigRequest,
    ) -> Result<types::AssociateEncryptionConfigResponse, ServiceError> {
        Eks::associate_encryption_config(self, ctx, input).await
    }
    async fn associate_identity_provider_config(
        &self,
        ctx: &RequestContext,
        input: types::AssociateIdentityProviderConfigRequest,
    ) -> Result<types::AssociateIdentityProviderConfigResponse, ServiceError> {
        Eks::associate_identity_provider_config(self, ctx, input).await
    }
    async fn cancel_update(
        &self,
        ctx: &RequestContext,
        input: types::CancelUpdateRequest,
    ) -> Result<types::CancelUpdateResponse, ServiceError> {
        Eks::cancel_update(self, ctx, input).await
    }
    async fn create_access_entry(
        &self,
        ctx: &RequestContext,
        input: types::CreateAccessEntryRequest,
    ) -> Result<types::CreateAccessEntryResponse, ServiceError> {
        Eks::create_access_entry(self, ctx, input).await
    }
    async fn create_addon(
        &self,
        ctx: &RequestContext,
        input: types::CreateAddonRequest,
    ) -> Result<types::CreateAddonResponse, ServiceError> {
        Eks::create_addon(self, ctx, input).await
    }
    async fn create_capability(
        &self,
        ctx: &RequestContext,
        input: types::CreateCapabilityRequest,
    ) -> Result<types::CreateCapabilityResponse, ServiceError> {
        Eks::create_capability(self, ctx, input).await
    }
    async fn create_certificate_authority(
        &self,
        ctx: &RequestContext,
        input: types::CreateCertificateAuthorityRequest,
    ) -> Result<types::CreateCertificateAuthorityResponse, ServiceError> {
        Eks::create_certificate_authority(self, ctx, input).await
    }
    async fn create_cluster(
        &self,
        ctx: &RequestContext,
        input: types::CreateClusterRequest,
    ) -> Result<types::CreateClusterResponse, ServiceError> {
        Eks::create_cluster(self, ctx, input).await
    }
    async fn create_eks_anywhere_subscription(
        &self,
        ctx: &RequestContext,
        input: types::CreateEksAnywhereSubscriptionRequest,
    ) -> Result<types::CreateEksAnywhereSubscriptionResponse, ServiceError> {
        Eks::create_eks_anywhere_subscription(self, ctx, input).await
    }
    async fn create_fargate_profile(
        &self,
        ctx: &RequestContext,
        input: types::CreateFargateProfileRequest,
    ) -> Result<types::CreateFargateProfileResponse, ServiceError> {
        Eks::create_fargate_profile(self, ctx, input).await
    }
    async fn create_nodegroup(
        &self,
        ctx: &RequestContext,
        input: types::CreateNodegroupRequest,
    ) -> Result<types::CreateNodegroupResponse, ServiceError> {
        Eks::create_nodegroup(self, ctx, input).await
    }
    async fn create_pod_identity_association(
        &self,
        ctx: &RequestContext,
        input: types::CreatePodIdentityAssociationRequest,
    ) -> Result<types::CreatePodIdentityAssociationResponse, ServiceError> {
        Eks::create_pod_identity_association(self, ctx, input).await
    }
    async fn delete_access_entry(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessEntryRequest,
    ) -> Result<types::DeleteAccessEntryResponse, ServiceError> {
        Eks::delete_access_entry(self, ctx, input).await
    }
    async fn delete_addon(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAddonRequest,
    ) -> Result<types::DeleteAddonResponse, ServiceError> {
        Eks::delete_addon(self, ctx, input).await
    }
    async fn delete_capability(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCapabilityRequest,
    ) -> Result<types::DeleteCapabilityResponse, ServiceError> {
        Eks::delete_capability(self, ctx, input).await
    }
    async fn delete_certificate_authority(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCertificateAuthorityRequest,
    ) -> Result<types::DeleteCertificateAuthorityResponse, ServiceError> {
        Eks::delete_certificate_authority(self, ctx, input).await
    }
    async fn delete_cluster(
        &self,
        ctx: &RequestContext,
        input: types::DeleteClusterRequest,
    ) -> Result<types::DeleteClusterResponse, ServiceError> {
        Eks::delete_cluster(self, ctx, input).await
    }
    async fn delete_eks_anywhere_subscription(
        &self,
        ctx: &RequestContext,
        input: types::DeleteEksAnywhereSubscriptionRequest,
    ) -> Result<types::DeleteEksAnywhereSubscriptionResponse, ServiceError> {
        Eks::delete_eks_anywhere_subscription(self, ctx, input).await
    }
    async fn delete_fargate_profile(
        &self,
        ctx: &RequestContext,
        input: types::DeleteFargateProfileRequest,
    ) -> Result<types::DeleteFargateProfileResponse, ServiceError> {
        Eks::delete_fargate_profile(self, ctx, input).await
    }
    async fn delete_nodegroup(
        &self,
        ctx: &RequestContext,
        input: types::DeleteNodegroupRequest,
    ) -> Result<types::DeleteNodegroupResponse, ServiceError> {
        Eks::delete_nodegroup(self, ctx, input).await
    }
    async fn delete_pod_identity_association(
        &self,
        ctx: &RequestContext,
        input: types::DeletePodIdentityAssociationRequest,
    ) -> Result<types::DeletePodIdentityAssociationResponse, ServiceError> {
        Eks::delete_pod_identity_association(self, ctx, input).await
    }
    async fn deregister_cluster(
        &self,
        ctx: &RequestContext,
        input: types::DeregisterClusterRequest,
    ) -> Result<types::DeregisterClusterResponse, ServiceError> {
        Eks::deregister_cluster(self, ctx, input).await
    }
    async fn describe_access_entry(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAccessEntryRequest,
    ) -> Result<types::DescribeAccessEntryResponse, ServiceError> {
        Eks::describe_access_entry(self, ctx, input).await
    }
    async fn describe_addon(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAddonRequest,
    ) -> Result<types::DescribeAddonResponse, ServiceError> {
        Eks::describe_addon(self, ctx, input).await
    }
    async fn describe_addon_configuration(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAddonConfigurationRequest,
    ) -> Result<types::DescribeAddonConfigurationResponse, ServiceError> {
        Eks::describe_addon_configuration(self, ctx, input).await
    }
    async fn describe_addon_versions(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAddonVersionsRequest,
    ) -> Result<types::DescribeAddonVersionsResponse, ServiceError> {
        Eks::describe_addon_versions(self, ctx, input).await
    }
    async fn describe_capability(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCapabilityRequest,
    ) -> Result<types::DescribeCapabilityResponse, ServiceError> {
        Eks::describe_capability(self, ctx, input).await
    }
    async fn describe_certificate_authority(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCertificateAuthorityRequest,
    ) -> Result<types::DescribeCertificateAuthorityResponse, ServiceError> {
        Eks::describe_certificate_authority(self, ctx, input).await
    }
    async fn describe_cluster(
        &self,
        ctx: &RequestContext,
        input: types::DescribeClusterRequest,
    ) -> Result<types::DescribeClusterResponse, ServiceError> {
        Eks::describe_cluster(self, ctx, input).await
    }
    async fn describe_cluster_versions(
        &self,
        ctx: &RequestContext,
        input: types::DescribeClusterVersionsRequest,
    ) -> Result<types::DescribeClusterVersionsResponse, ServiceError> {
        Eks::describe_cluster_versions(self, ctx, input).await
    }
    async fn describe_eks_anywhere_subscription(
        &self,
        ctx: &RequestContext,
        input: types::DescribeEksAnywhereSubscriptionRequest,
    ) -> Result<types::DescribeEksAnywhereSubscriptionResponse, ServiceError> {
        Eks::describe_eks_anywhere_subscription(self, ctx, input).await
    }
    async fn describe_fargate_profile(
        &self,
        ctx: &RequestContext,
        input: types::DescribeFargateProfileRequest,
    ) -> Result<types::DescribeFargateProfileResponse, ServiceError> {
        Eks::describe_fargate_profile(self, ctx, input).await
    }
    async fn describe_identity_provider_config(
        &self,
        ctx: &RequestContext,
        input: types::DescribeIdentityProviderConfigRequest,
    ) -> Result<types::DescribeIdentityProviderConfigResponse, ServiceError> {
        Eks::describe_identity_provider_config(self, ctx, input).await
    }
    async fn describe_insight(
        &self,
        ctx: &RequestContext,
        input: types::DescribeInsightRequest,
    ) -> Result<types::DescribeInsightResponse, ServiceError> {
        Eks::describe_insight(self, ctx, input).await
    }
    async fn describe_insights_refresh(
        &self,
        ctx: &RequestContext,
        input: types::DescribeInsightsRefreshRequest,
    ) -> Result<types::DescribeInsightsRefreshResponse, ServiceError> {
        Eks::describe_insights_refresh(self, ctx, input).await
    }
    async fn describe_nodegroup(
        &self,
        ctx: &RequestContext,
        input: types::DescribeNodegroupRequest,
    ) -> Result<types::DescribeNodegroupResponse, ServiceError> {
        Eks::describe_nodegroup(self, ctx, input).await
    }
    async fn describe_pod_identity_association(
        &self,
        ctx: &RequestContext,
        input: types::DescribePodIdentityAssociationRequest,
    ) -> Result<types::DescribePodIdentityAssociationResponse, ServiceError> {
        Eks::describe_pod_identity_association(self, ctx, input).await
    }
    async fn describe_update(
        &self,
        ctx: &RequestContext,
        input: types::DescribeUpdateRequest,
    ) -> Result<types::DescribeUpdateResponse, ServiceError> {
        Eks::describe_update(self, ctx, input).await
    }
    async fn disassociate_access_policy(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateAccessPolicyRequest,
    ) -> Result<types::DisassociateAccessPolicyResponse, ServiceError> {
        Eks::disassociate_access_policy(self, ctx, input).await
    }
    async fn disassociate_identity_provider_config(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateIdentityProviderConfigRequest,
    ) -> Result<types::DisassociateIdentityProviderConfigResponse, ServiceError> {
        Eks::disassociate_identity_provider_config(self, ctx, input).await
    }
    async fn list_access_entries(
        &self,
        ctx: &RequestContext,
        input: types::ListAccessEntriesRequest,
    ) -> Result<types::ListAccessEntriesResponse, ServiceError> {
        Eks::list_access_entries(self, ctx, input).await
    }
    async fn list_access_policies(
        &self,
        ctx: &RequestContext,
        input: types::ListAccessPoliciesRequest,
    ) -> Result<types::ListAccessPoliciesResponse, ServiceError> {
        Eks::list_access_policies(self, ctx, input).await
    }
    async fn list_addons(
        &self,
        ctx: &RequestContext,
        input: types::ListAddonsRequest,
    ) -> Result<types::ListAddonsResponse, ServiceError> {
        Eks::list_addons(self, ctx, input).await
    }
    async fn list_associated_access_policies(
        &self,
        ctx: &RequestContext,
        input: types::ListAssociatedAccessPoliciesRequest,
    ) -> Result<types::ListAssociatedAccessPoliciesResponse, ServiceError> {
        Eks::list_associated_access_policies(self, ctx, input).await
    }
    async fn list_capabilities(
        &self,
        ctx: &RequestContext,
        input: types::ListCapabilitiesRequest,
    ) -> Result<types::ListCapabilitiesResponse, ServiceError> {
        Eks::list_capabilities(self, ctx, input).await
    }
    async fn list_certificate_authorities(
        &self,
        ctx: &RequestContext,
        input: types::ListCertificateAuthoritiesRequest,
    ) -> Result<types::ListCertificateAuthoritiesResponse, ServiceError> {
        Eks::list_certificate_authorities(self, ctx, input).await
    }
    async fn list_clusters(
        &self,
        ctx: &RequestContext,
        input: types::ListClustersRequest,
    ) -> Result<types::ListClustersResponse, ServiceError> {
        Eks::list_clusters(self, ctx, input).await
    }
    async fn list_eks_anywhere_subscriptions(
        &self,
        ctx: &RequestContext,
        input: types::ListEksAnywhereSubscriptionsRequest,
    ) -> Result<types::ListEksAnywhereSubscriptionsResponse, ServiceError> {
        Eks::list_eks_anywhere_subscriptions(self, ctx, input).await
    }
    async fn list_fargate_profiles(
        &self,
        ctx: &RequestContext,
        input: types::ListFargateProfilesRequest,
    ) -> Result<types::ListFargateProfilesResponse, ServiceError> {
        Eks::list_fargate_profiles(self, ctx, input).await
    }
    async fn list_identity_provider_configs(
        &self,
        ctx: &RequestContext,
        input: types::ListIdentityProviderConfigsRequest,
    ) -> Result<types::ListIdentityProviderConfigsResponse, ServiceError> {
        Eks::list_identity_provider_configs(self, ctx, input).await
    }
    async fn list_insights(
        &self,
        ctx: &RequestContext,
        input: types::ListInsightsRequest,
    ) -> Result<types::ListInsightsResponse, ServiceError> {
        Eks::list_insights(self, ctx, input).await
    }
    async fn list_nodegroups(
        &self,
        ctx: &RequestContext,
        input: types::ListNodegroupsRequest,
    ) -> Result<types::ListNodegroupsResponse, ServiceError> {
        Eks::list_nodegroups(self, ctx, input).await
    }
    async fn list_pod_identity_associations(
        &self,
        ctx: &RequestContext,
        input: types::ListPodIdentityAssociationsRequest,
    ) -> Result<types::ListPodIdentityAssociationsResponse, ServiceError> {
        Eks::list_pod_identity_associations(self, ctx, input).await
    }
    async fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        Eks::list_tags_for_resource(self, ctx, input).await
    }
    async fn list_updates(
        &self,
        ctx: &RequestContext,
        input: types::ListUpdatesRequest,
    ) -> Result<types::ListUpdatesResponse, ServiceError> {
        Eks::list_updates(self, ctx, input).await
    }
    async fn register_cluster(
        &self,
        ctx: &RequestContext,
        input: types::RegisterClusterRequest,
    ) -> Result<types::RegisterClusterResponse, ServiceError> {
        Eks::register_cluster(self, ctx, input).await
    }
    async fn start_insights_refresh(
        &self,
        ctx: &RequestContext,
        input: types::StartInsightsRefreshRequest,
    ) -> Result<types::StartInsightsRefreshResponse, ServiceError> {
        Eks::start_insights_refresh(self, ctx, input).await
    }
    async fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<types::TagResourceResponse, ServiceError> {
        Eks::tag_resource(self, ctx, input).await
    }
    async fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<types::UntagResourceResponse, ServiceError> {
        Eks::untag_resource(self, ctx, input).await
    }
    async fn update_access_entry(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAccessEntryRequest,
    ) -> Result<types::UpdateAccessEntryResponse, ServiceError> {
        Eks::update_access_entry(self, ctx, input).await
    }
    async fn update_addon(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAddonRequest,
    ) -> Result<types::UpdateAddonResponse, ServiceError> {
        Eks::update_addon(self, ctx, input).await
    }
    async fn update_capability(
        &self,
        ctx: &RequestContext,
        input: types::UpdateCapabilityRequest,
    ) -> Result<types::UpdateCapabilityResponse, ServiceError> {
        Eks::update_capability(self, ctx, input).await
    }
    async fn update_cluster_config(
        &self,
        ctx: &RequestContext,
        input: types::UpdateClusterConfigRequest,
    ) -> Result<types::UpdateClusterConfigResponse, ServiceError> {
        Eks::update_cluster_config(self, ctx, input).await
    }
    async fn update_cluster_version(
        &self,
        ctx: &RequestContext,
        input: types::UpdateClusterVersionRequest,
    ) -> Result<types::UpdateClusterVersionResponse, ServiceError> {
        Eks::update_cluster_version(self, ctx, input).await
    }
    async fn update_eks_anywhere_subscription(
        &self,
        ctx: &RequestContext,
        input: types::UpdateEksAnywhereSubscriptionRequest,
    ) -> Result<types::UpdateEksAnywhereSubscriptionResponse, ServiceError> {
        Eks::update_eks_anywhere_subscription(self, ctx, input).await
    }
    async fn update_nodegroup_config(
        &self,
        ctx: &RequestContext,
        input: types::UpdateNodegroupConfigRequest,
    ) -> Result<types::UpdateNodegroupConfigResponse, ServiceError> {
        Eks::update_nodegroup_config(self, ctx, input).await
    }
    async fn update_nodegroup_version(
        &self,
        ctx: &RequestContext,
        input: types::UpdateNodegroupVersionRequest,
    ) -> Result<types::UpdateNodegroupVersionResponse, ServiceError> {
        Eks::update_nodegroup_version(self, ctx, input).await
    }
    async fn update_pod_identity_association(
        &self,
        ctx: &RequestContext,
        input: types::UpdatePodIdentityAssociationRequest,
    ) -> Result<types::UpdatePodIdentityAssociationResponse, ServiceError> {
        Eks::update_pod_identity_association(self, ctx, input).await
    }
}

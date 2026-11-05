//! Wires the generated `Handler` trait to the operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::CodeArtifact;

#[async_trait::async_trait]
impl Handler for CodeArtifact {
    async fn associate_external_connection(
        &self,
        ctx: &RequestContext,
        input: types::AssociateExternalConnectionRequest,
    ) -> Result<types::AssociateExternalConnectionResult, ServiceError> {
        CodeArtifact::associate_external_connection(self, ctx, input)
    }
    async fn copy_package_versions(
        &self,
        ctx: &RequestContext,
        input: types::CopyPackageVersionsRequest,
    ) -> Result<types::CopyPackageVersionsResult, ServiceError> {
        CodeArtifact::copy_package_versions(self, ctx, input)
    }
    async fn create_domain(
        &self,
        ctx: &RequestContext,
        input: types::CreateDomainRequest,
    ) -> Result<types::CreateDomainResult, ServiceError> {
        CodeArtifact::create_domain(self, ctx, input)
    }
    async fn create_package_group(
        &self,
        ctx: &RequestContext,
        input: types::CreatePackageGroupRequest,
    ) -> Result<types::CreatePackageGroupResult, ServiceError> {
        CodeArtifact::create_package_group(self, ctx, input)
    }
    async fn create_repository(
        &self,
        ctx: &RequestContext,
        input: types::CreateRepositoryRequest,
    ) -> Result<types::CreateRepositoryResult, ServiceError> {
        CodeArtifact::create_repository(self, ctx, input)
    }
    async fn delete_domain(
        &self,
        ctx: &RequestContext,
        input: types::DeleteDomainRequest,
    ) -> Result<types::DeleteDomainResult, ServiceError> {
        CodeArtifact::delete_domain(self, ctx, input)
    }
    async fn delete_domain_permissions_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteDomainPermissionsPolicyRequest,
    ) -> Result<types::DeleteDomainPermissionsPolicyResult, ServiceError> {
        CodeArtifact::delete_domain_permissions_policy(self, ctx, input)
    }
    async fn delete_package(
        &self,
        ctx: &RequestContext,
        input: types::DeletePackageRequest,
    ) -> Result<types::DeletePackageResult, ServiceError> {
        CodeArtifact::delete_package(self, ctx, input)
    }
    async fn delete_package_group(
        &self,
        ctx: &RequestContext,
        input: types::DeletePackageGroupRequest,
    ) -> Result<types::DeletePackageGroupResult, ServiceError> {
        CodeArtifact::delete_package_group(self, ctx, input)
    }
    async fn delete_package_versions(
        &self,
        ctx: &RequestContext,
        input: types::DeletePackageVersionsRequest,
    ) -> Result<types::DeletePackageVersionsResult, ServiceError> {
        CodeArtifact::delete_package_versions(self, ctx, input)
    }
    async fn delete_repository(
        &self,
        ctx: &RequestContext,
        input: types::DeleteRepositoryRequest,
    ) -> Result<types::DeleteRepositoryResult, ServiceError> {
        CodeArtifact::delete_repository(self, ctx, input)
    }
    async fn delete_repository_permissions_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteRepositoryPermissionsPolicyRequest,
    ) -> Result<types::DeleteRepositoryPermissionsPolicyResult, ServiceError> {
        CodeArtifact::delete_repository_permissions_policy(self, ctx, input)
    }
    async fn describe_domain(
        &self,
        ctx: &RequestContext,
        input: types::DescribeDomainRequest,
    ) -> Result<types::DescribeDomainResult, ServiceError> {
        CodeArtifact::describe_domain(self, ctx, input)
    }
    async fn describe_package(
        &self,
        ctx: &RequestContext,
        input: types::DescribePackageRequest,
    ) -> Result<types::DescribePackageResult, ServiceError> {
        CodeArtifact::describe_package(self, ctx, input)
    }
    async fn describe_package_group(
        &self,
        ctx: &RequestContext,
        input: types::DescribePackageGroupRequest,
    ) -> Result<types::DescribePackageGroupResult, ServiceError> {
        CodeArtifact::describe_package_group(self, ctx, input)
    }
    async fn describe_package_version(
        &self,
        ctx: &RequestContext,
        input: types::DescribePackageVersionRequest,
    ) -> Result<types::DescribePackageVersionResult, ServiceError> {
        CodeArtifact::describe_package_version(self, ctx, input)
    }
    async fn describe_repository(
        &self,
        ctx: &RequestContext,
        input: types::DescribeRepositoryRequest,
    ) -> Result<types::DescribeRepositoryResult, ServiceError> {
        CodeArtifact::describe_repository(self, ctx, input)
    }
    async fn disassociate_external_connection(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateExternalConnectionRequest,
    ) -> Result<types::DisassociateExternalConnectionResult, ServiceError> {
        CodeArtifact::disassociate_external_connection(self, ctx, input)
    }
    async fn dispose_package_versions(
        &self,
        ctx: &RequestContext,
        input: types::DisposePackageVersionsRequest,
    ) -> Result<types::DisposePackageVersionsResult, ServiceError> {
        CodeArtifact::dispose_package_versions(self, ctx, input)
    }
    async fn get_associated_package_group(
        &self,
        ctx: &RequestContext,
        input: types::GetAssociatedPackageGroupRequest,
    ) -> Result<types::GetAssociatedPackageGroupResult, ServiceError> {
        CodeArtifact::get_associated_package_group(self, ctx, input)
    }
    async fn get_authorization_token(
        &self,
        ctx: &RequestContext,
        input: types::GetAuthorizationTokenRequest,
    ) -> Result<types::GetAuthorizationTokenResult, ServiceError> {
        CodeArtifact::get_authorization_token(self, ctx, input)
    }
    async fn get_domain_permissions_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetDomainPermissionsPolicyRequest,
    ) -> Result<types::GetDomainPermissionsPolicyResult, ServiceError> {
        CodeArtifact::get_domain_permissions_policy(self, ctx, input)
    }
    async fn get_package_version_asset(
        &self,
        ctx: &RequestContext,
        input: types::GetPackageVersionAssetRequest,
    ) -> Result<types::GetPackageVersionAssetResult, ServiceError> {
        CodeArtifact::get_package_version_asset(self, ctx, input)
    }
    async fn get_package_version_readme(
        &self,
        ctx: &RequestContext,
        input: types::GetPackageVersionReadmeRequest,
    ) -> Result<types::GetPackageVersionReadmeResult, ServiceError> {
        CodeArtifact::get_package_version_readme(self, ctx, input)
    }
    async fn get_repository_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::GetRepositoryEndpointRequest,
    ) -> Result<types::GetRepositoryEndpointResult, ServiceError> {
        CodeArtifact::get_repository_endpoint(self, ctx, input)
    }
    async fn get_repository_permissions_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetRepositoryPermissionsPolicyRequest,
    ) -> Result<types::GetRepositoryPermissionsPolicyResult, ServiceError> {
        CodeArtifact::get_repository_permissions_policy(self, ctx, input)
    }
    async fn list_allowed_repositories_for_group(
        &self,
        ctx: &RequestContext,
        input: types::ListAllowedRepositoriesForGroupRequest,
    ) -> Result<types::ListAllowedRepositoriesForGroupResult, ServiceError> {
        CodeArtifact::list_allowed_repositories_for_group(self, ctx, input)
    }
    async fn list_associated_packages(
        &self,
        ctx: &RequestContext,
        input: types::ListAssociatedPackagesRequest,
    ) -> Result<types::ListAssociatedPackagesResult, ServiceError> {
        CodeArtifact::list_associated_packages(self, ctx, input)
    }
    async fn list_domains(
        &self,
        ctx: &RequestContext,
        input: types::ListDomainsRequest,
    ) -> Result<types::ListDomainsResult, ServiceError> {
        CodeArtifact::list_domains(self, ctx, input)
    }
    async fn list_package_groups(
        &self,
        ctx: &RequestContext,
        input: types::ListPackageGroupsRequest,
    ) -> Result<types::ListPackageGroupsResult, ServiceError> {
        CodeArtifact::list_package_groups(self, ctx, input)
    }
    async fn list_package_version_assets(
        &self,
        ctx: &RequestContext,
        input: types::ListPackageVersionAssetsRequest,
    ) -> Result<types::ListPackageVersionAssetsResult, ServiceError> {
        CodeArtifact::list_package_version_assets(self, ctx, input)
    }
    async fn list_package_version_dependencies(
        &self,
        ctx: &RequestContext,
        input: types::ListPackageVersionDependenciesRequest,
    ) -> Result<types::ListPackageVersionDependenciesResult, ServiceError> {
        CodeArtifact::list_package_version_dependencies(self, ctx, input)
    }
    async fn list_package_versions(
        &self,
        ctx: &RequestContext,
        input: types::ListPackageVersionsRequest,
    ) -> Result<types::ListPackageVersionsResult, ServiceError> {
        CodeArtifact::list_package_versions(self, ctx, input)
    }
    async fn list_packages(
        &self,
        ctx: &RequestContext,
        input: types::ListPackagesRequest,
    ) -> Result<types::ListPackagesResult, ServiceError> {
        CodeArtifact::list_packages(self, ctx, input)
    }
    async fn list_repositories(
        &self,
        ctx: &RequestContext,
        input: types::ListRepositoriesRequest,
    ) -> Result<types::ListRepositoriesResult, ServiceError> {
        CodeArtifact::list_repositories(self, ctx, input)
    }
    async fn list_repositories_in_domain(
        &self,
        ctx: &RequestContext,
        input: types::ListRepositoriesInDomainRequest,
    ) -> Result<types::ListRepositoriesInDomainResult, ServiceError> {
        CodeArtifact::list_repositories_in_domain(self, ctx, input)
    }
    async fn list_sub_package_groups(
        &self,
        ctx: &RequestContext,
        input: types::ListSubPackageGroupsRequest,
    ) -> Result<types::ListSubPackageGroupsResult, ServiceError> {
        CodeArtifact::list_sub_package_groups(self, ctx, input)
    }
    async fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResult, ServiceError> {
        CodeArtifact::list_tags_for_resource(self, ctx, input)
    }
    async fn publish_package_version(
        &self,
        ctx: &RequestContext,
        input: types::PublishPackageVersionRequest,
    ) -> Result<types::PublishPackageVersionResult, ServiceError> {
        CodeArtifact::publish_package_version(self, ctx, input)
    }
    async fn put_domain_permissions_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutDomainPermissionsPolicyRequest,
    ) -> Result<types::PutDomainPermissionsPolicyResult, ServiceError> {
        CodeArtifact::put_domain_permissions_policy(self, ctx, input)
    }
    async fn put_package_origin_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutPackageOriginConfigurationRequest,
    ) -> Result<types::PutPackageOriginConfigurationResult, ServiceError> {
        CodeArtifact::put_package_origin_configuration(self, ctx, input)
    }
    async fn put_repository_permissions_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutRepositoryPermissionsPolicyRequest,
    ) -> Result<types::PutRepositoryPermissionsPolicyResult, ServiceError> {
        CodeArtifact::put_repository_permissions_policy(self, ctx, input)
    }
    async fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<types::TagResourceResult, ServiceError> {
        CodeArtifact::tag_resource(self, ctx, input)
    }
    async fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<types::UntagResourceResult, ServiceError> {
        CodeArtifact::untag_resource(self, ctx, input)
    }
    async fn update_package_group(
        &self,
        ctx: &RequestContext,
        input: types::UpdatePackageGroupRequest,
    ) -> Result<types::UpdatePackageGroupResult, ServiceError> {
        CodeArtifact::update_package_group(self, ctx, input)
    }
    async fn update_package_group_origin_configuration(
        &self,
        ctx: &RequestContext,
        input: types::UpdatePackageGroupOriginConfigurationRequest,
    ) -> Result<types::UpdatePackageGroupOriginConfigurationResult, ServiceError> {
        CodeArtifact::update_package_group_origin_configuration(self, ctx, input)
    }
    async fn update_package_versions_status(
        &self,
        ctx: &RequestContext,
        input: types::UpdatePackageVersionsStatusRequest,
    ) -> Result<types::UpdatePackageVersionsStatusResult, ServiceError> {
        CodeArtifact::update_package_versions_status(self, ctx, input)
    }
    async fn update_repository(
        &self,
        ctx: &RequestContext,
        input: types::UpdateRepositoryRequest,
    ) -> Result<types::UpdateRepositoryResult, ServiceError> {
        CodeArtifact::update_repository(self, ctx, input)
    }
}

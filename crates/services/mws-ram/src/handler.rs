//! The generated `Handler`, forwarding to the operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::Ram;

#[async_trait::async_trait]
impl Handler for Ram {
    async fn accept_resource_share_invitation(
        &self,
        ctx: &RequestContext,
        input: types::AcceptResourceShareInvitationRequest,
    ) -> Result<types::AcceptResourceShareInvitationResponse, ServiceError> {
        self.accept_resource_share_invitation(ctx, input)
    }

    async fn associate_resource_share(
        &self,
        ctx: &RequestContext,
        input: types::AssociateResourceShareRequest,
    ) -> Result<types::AssociateResourceShareResponse, ServiceError> {
        self.associate_resource_share(ctx, input)
    }

    async fn associate_resource_share_permission(
        &self,
        ctx: &RequestContext,
        input: types::AssociateResourceSharePermissionRequest,
    ) -> Result<types::AssociateResourceSharePermissionResponse, ServiceError> {
        self.associate_resource_share_permission(ctx, input)
    }

    async fn create_permission(
        &self,
        ctx: &RequestContext,
        input: types::CreatePermissionRequest,
    ) -> Result<types::CreatePermissionResponse, ServiceError> {
        self.create_permission(ctx, input)
    }

    async fn create_permission_version(
        &self,
        ctx: &RequestContext,
        input: types::CreatePermissionVersionRequest,
    ) -> Result<types::CreatePermissionVersionResponse, ServiceError> {
        self.create_permission_version(ctx, input)
    }

    async fn create_resource_share(
        &self,
        ctx: &RequestContext,
        input: types::CreateResourceShareRequest,
    ) -> Result<types::CreateResourceShareResponse, ServiceError> {
        self.create_resource_share(ctx, input)
    }

    async fn delete_permission(
        &self,
        ctx: &RequestContext,
        input: types::DeletePermissionRequest,
    ) -> Result<types::DeletePermissionResponse, ServiceError> {
        self.delete_permission(ctx, input)
    }

    async fn delete_permission_version(
        &self,
        ctx: &RequestContext,
        input: types::DeletePermissionVersionRequest,
    ) -> Result<types::DeletePermissionVersionResponse, ServiceError> {
        self.delete_permission_version(ctx, input)
    }

    async fn delete_resource_share(
        &self,
        ctx: &RequestContext,
        input: types::DeleteResourceShareRequest,
    ) -> Result<types::DeleteResourceShareResponse, ServiceError> {
        self.delete_resource_share(ctx, input)
    }

    async fn disassociate_resource_share(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateResourceShareRequest,
    ) -> Result<types::DisassociateResourceShareResponse, ServiceError> {
        self.disassociate_resource_share(ctx, input)
    }

    async fn disassociate_resource_share_permission(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateResourceSharePermissionRequest,
    ) -> Result<types::DisassociateResourceSharePermissionResponse, ServiceError> {
        self.disassociate_resource_share_permission(ctx, input)
    }

    async fn enable_sharing_with_aws_organization(
        &self,
        ctx: &RequestContext,
        input: types::EnableSharingWithAwsOrganizationRequest,
    ) -> Result<types::EnableSharingWithAwsOrganizationResponse, ServiceError> {
        let _ = input;
        self.enable_sharing_with_aws_organization(ctx)
    }

    async fn get_permission(
        &self,
        ctx: &RequestContext,
        input: types::GetPermissionRequest,
    ) -> Result<types::GetPermissionResponse, ServiceError> {
        self.get_permission(ctx, input)
    }

    async fn get_resource_policies(
        &self,
        ctx: &RequestContext,
        input: types::GetResourcePoliciesRequest,
    ) -> Result<types::GetResourcePoliciesResponse, ServiceError> {
        self.get_resource_policies(ctx, input)
    }

    async fn get_resource_share_associations(
        &self,
        ctx: &RequestContext,
        input: types::GetResourceShareAssociationsRequest,
    ) -> Result<types::GetResourceShareAssociationsResponse, ServiceError> {
        self.get_resource_share_associations(ctx, input)
    }

    async fn get_resource_share_invitations(
        &self,
        ctx: &RequestContext,
        input: types::GetResourceShareInvitationsRequest,
    ) -> Result<types::GetResourceShareInvitationsResponse, ServiceError> {
        self.get_resource_share_invitations(ctx, input)
    }

    async fn get_resource_shares(
        &self,
        ctx: &RequestContext,
        input: types::GetResourceSharesRequest,
    ) -> Result<types::GetResourceSharesResponse, ServiceError> {
        self.get_resource_shares(ctx, input)
    }

    async fn list_pending_invitation_resources(
        &self,
        ctx: &RequestContext,
        input: types::ListPendingInvitationResourcesRequest,
    ) -> Result<types::ListPendingInvitationResourcesResponse, ServiceError> {
        self.list_pending_invitation_resources(ctx, input)
    }

    async fn list_permission_associations(
        &self,
        ctx: &RequestContext,
        input: types::ListPermissionAssociationsRequest,
    ) -> Result<types::ListPermissionAssociationsResponse, ServiceError> {
        self.list_permission_associations(ctx, input)
    }

    async fn list_permission_versions(
        &self,
        ctx: &RequestContext,
        input: types::ListPermissionVersionsRequest,
    ) -> Result<types::ListPermissionVersionsResponse, ServiceError> {
        self.list_permission_versions(ctx, input)
    }

    async fn list_permissions(
        &self,
        ctx: &RequestContext,
        input: types::ListPermissionsRequest,
    ) -> Result<types::ListPermissionsResponse, ServiceError> {
        self.list_permissions(ctx, input)
    }

    async fn list_principals(
        &self,
        ctx: &RequestContext,
        input: types::ListPrincipalsRequest,
    ) -> Result<types::ListPrincipalsResponse, ServiceError> {
        self.list_principals(ctx, input)
    }

    async fn list_replace_permission_associations_work(
        &self,
        ctx: &RequestContext,
        input: types::ListReplacePermissionAssociationsWorkRequest,
    ) -> Result<types::ListReplacePermissionAssociationsWorkResponse, ServiceError> {
        self.list_replace_permission_associations_work(ctx, input)
    }

    async fn list_resource_share_permissions(
        &self,
        ctx: &RequestContext,
        input: types::ListResourceSharePermissionsRequest,
    ) -> Result<types::ListResourceSharePermissionsResponse, ServiceError> {
        self.list_resource_share_permissions(ctx, input)
    }

    async fn list_resource_types(
        &self,
        ctx: &RequestContext,
        input: types::ListResourceTypesRequest,
    ) -> Result<types::ListResourceTypesResponse, ServiceError> {
        self.list_resource_types(ctx, input)
    }

    async fn list_resources(
        &self,
        ctx: &RequestContext,
        input: types::ListResourcesRequest,
    ) -> Result<types::ListResourcesResponse, ServiceError> {
        self.list_resources(ctx, input)
    }

    async fn list_source_associations(
        &self,
        ctx: &RequestContext,
        input: types::ListSourceAssociationsRequest,
    ) -> Result<types::ListSourceAssociationsResponse, ServiceError> {
        self.list_source_associations(ctx, input)
    }

    async fn promote_permission_created_from_policy(
        &self,
        ctx: &RequestContext,
        input: types::PromotePermissionCreatedFromPolicyRequest,
    ) -> Result<types::PromotePermissionCreatedFromPolicyResponse, ServiceError> {
        self.promote_permission_created_from_policy(ctx, input)
    }

    async fn promote_resource_share_created_from_policy(
        &self,
        ctx: &RequestContext,
        input: types::PromoteResourceShareCreatedFromPolicyRequest,
    ) -> Result<types::PromoteResourceShareCreatedFromPolicyResponse, ServiceError> {
        self.promote_resource_share_created_from_policy(ctx, input)
    }

    async fn reject_resource_share_invitation(
        &self,
        ctx: &RequestContext,
        input: types::RejectResourceShareInvitationRequest,
    ) -> Result<types::RejectResourceShareInvitationResponse, ServiceError> {
        self.reject_resource_share_invitation(ctx, input)
    }

    async fn replace_permission_associations(
        &self,
        ctx: &RequestContext,
        input: types::ReplacePermissionAssociationsRequest,
    ) -> Result<types::ReplacePermissionAssociationsResponse, ServiceError> {
        self.replace_permission_associations(ctx, input)
    }

    async fn set_default_permission_version(
        &self,
        ctx: &RequestContext,
        input: types::SetDefaultPermissionVersionRequest,
    ) -> Result<types::SetDefaultPermissionVersionResponse, ServiceError> {
        self.set_default_permission_version(ctx, input)
    }

    async fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<types::TagResourceResponse, ServiceError> {
        self.tag_resource(ctx, input)?;
        Ok(types::TagResourceResponse::default())
    }

    async fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<types::UntagResourceResponse, ServiceError> {
        self.untag_resource(ctx, input)?;
        Ok(types::UntagResourceResponse::default())
    }

    async fn update_resource_share(
        &self,
        ctx: &RequestContext,
        input: types::UpdateResourceShareRequest,
    ) -> Result<types::UpdateResourceShareResponse, ServiceError> {
        self.update_resource_share(ctx, input)
    }
}

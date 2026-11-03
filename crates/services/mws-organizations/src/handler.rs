//! Wires the generated `Handler` trait to the synchronous operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::Organizations;

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
                let result = Organizations::$name(self, ctx, input);
                Box::pin(async move { result })
            }
        )*
    };
}

impl Handler for Organizations {
    delegate! {
        delete_organization(()) -> ();
        delete_resource_policy(()) -> ();
        describe_organization(()) -> types::DescribeOrganizationResponse;
        describe_resource_policy(()) -> types::DescribeResourcePolicyResponse;
        leave_organization(()) -> ();
        accept_handshake(types::AcceptHandshakeRequest) -> types::AcceptHandshakeResponse;
        attach_policy(types::AttachPolicyRequest) -> ();
        cancel_handshake(types::CancelHandshakeRequest) -> types::CancelHandshakeResponse;
        close_account(types::CloseAccountRequest) -> ();
        create_account(types::CreateAccountRequest) -> types::CreateAccountResponse;
        create_gov_cloud_account(types::CreateGovCloudAccountRequest) -> types::CreateGovCloudAccountResponse;
        create_organization(types::CreateOrganizationRequest) -> types::CreateOrganizationResponse;
        create_organizational_unit(types::CreateOrganizationalUnitRequest) -> types::CreateOrganizationalUnitResponse;
        create_policy(types::CreatePolicyRequest) -> types::CreatePolicyResponse;
        decline_handshake(types::DeclineHandshakeRequest) -> types::DeclineHandshakeResponse;
        delete_organizational_unit(types::DeleteOrganizationalUnitRequest) -> ();
        delete_policy(types::DeletePolicyRequest) -> ();
        deregister_delegated_administrator(types::DeregisterDelegatedAdministratorRequest) -> ();
        describe_account(types::DescribeAccountRequest) -> types::DescribeAccountResponse;
        describe_create_account_status(types::DescribeCreateAccountStatusRequest) -> types::DescribeCreateAccountStatusResponse;
        describe_effective_policy(types::DescribeEffectivePolicyRequest) -> types::DescribeEffectivePolicyResponse;
        describe_handshake(types::DescribeHandshakeRequest) -> types::DescribeHandshakeResponse;
        describe_organizational_unit(types::DescribeOrganizationalUnitRequest) -> types::DescribeOrganizationalUnitResponse;
        describe_policy(types::DescribePolicyRequest) -> types::DescribePolicyResponse;
        describe_responsibility_transfer(types::DescribeResponsibilityTransferRequest) -> types::DescribeResponsibilityTransferResponse;
        detach_policy(types::DetachPolicyRequest) -> ();
        disable_aws_service_access(types::DisableAWSServiceAccessRequest) -> ();
        disable_policy_type(types::DisablePolicyTypeRequest) -> types::DisablePolicyTypeResponse;
        enable_aws_service_access(types::EnableAWSServiceAccessRequest) -> ();
        enable_all_features(types::EnableAllFeaturesRequest) -> types::EnableAllFeaturesResponse;
        enable_policy_type(types::EnablePolicyTypeRequest) -> types::EnablePolicyTypeResponse;
        invite_account_to_organization(types::InviteAccountToOrganizationRequest) -> types::InviteAccountToOrganizationResponse;
        invite_organization_to_transfer_responsibility(types::InviteOrganizationToTransferResponsibilityRequest) -> types::InviteOrganizationToTransferResponsibilityResponse;
        list_aws_service_access_for_organization(types::ListAWSServiceAccessForOrganizationRequest) -> types::ListAWSServiceAccessForOrganizationResponse;
        list_accounts(types::ListAccountsRequest) -> types::ListAccountsResponse;
        list_accounts_for_parent(types::ListAccountsForParentRequest) -> types::ListAccountsForParentResponse;
        list_accounts_with_invalid_effective_policy(types::ListAccountsWithInvalidEffectivePolicyRequest) -> types::ListAccountsWithInvalidEffectivePolicyResponse;
        list_children(types::ListChildrenRequest) -> types::ListChildrenResponse;
        list_create_account_status(types::ListCreateAccountStatusRequest) -> types::ListCreateAccountStatusResponse;
        list_delegated_administrators(types::ListDelegatedAdministratorsRequest) -> types::ListDelegatedAdministratorsResponse;
        list_delegated_services_for_account(types::ListDelegatedServicesForAccountRequest) -> types::ListDelegatedServicesForAccountResponse;
        list_effective_policy_validation_errors(types::ListEffectivePolicyValidationErrorsRequest) -> types::ListEffectivePolicyValidationErrorsResponse;
        list_handshakes_for_account(types::ListHandshakesForAccountRequest) -> types::ListHandshakesForAccountResponse;
        list_handshakes_for_organization(types::ListHandshakesForOrganizationRequest) -> types::ListHandshakesForOrganizationResponse;
        list_inbound_responsibility_transfers(types::ListInboundResponsibilityTransfersRequest) -> types::ListInboundResponsibilityTransfersResponse;
        list_organizational_units_for_parent(types::ListOrganizationalUnitsForParentRequest) -> types::ListOrganizationalUnitsForParentResponse;
        list_outbound_responsibility_transfers(types::ListOutboundResponsibilityTransfersRequest) -> types::ListOutboundResponsibilityTransfersResponse;
        list_parents(types::ListParentsRequest) -> types::ListParentsResponse;
        list_policies(types::ListPoliciesRequest) -> types::ListPoliciesResponse;
        list_policies_for_target(types::ListPoliciesForTargetRequest) -> types::ListPoliciesForTargetResponse;
        list_roots(types::ListRootsRequest) -> types::ListRootsResponse;
        list_tags_for_resource(types::ListTagsForResourceRequest) -> types::ListTagsForResourceResponse;
        list_targets_for_policy(types::ListTargetsForPolicyRequest) -> types::ListTargetsForPolicyResponse;
        move_account(types::MoveAccountRequest) -> ();
        put_resource_policy(types::PutResourcePolicyRequest) -> types::PutResourcePolicyResponse;
        register_delegated_administrator(types::RegisterDelegatedAdministratorRequest) -> ();
        remove_account_from_organization(types::RemoveAccountFromOrganizationRequest) -> ();
        tag_resource(types::TagResourceRequest) -> ();
        terminate_responsibility_transfer(types::TerminateResponsibilityTransferRequest) -> types::TerminateResponsibilityTransferResponse;
        untag_resource(types::UntagResourceRequest) -> ();
        update_organizational_unit(types::UpdateOrganizationalUnitRequest) -> types::UpdateOrganizationalUnitResponse;
        update_policy(types::UpdatePolicyRequest) -> types::UpdatePolicyResponse;
        update_responsibility_transfer(types::UpdateResponsibilityTransferRequest) -> types::UpdateResponsibilityTransferResponse;
    }
}

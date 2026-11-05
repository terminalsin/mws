//! Wires the generated `Handler` trait to the synchronous operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::SsoAdmin;

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
                let result = SsoAdmin::$name(self, ctx, input);
                Box::pin(async move { result })
            }
        )*
    };
}

impl Handler for SsoAdmin {
    delegate! {
        add_region(types::AddRegionRequest) -> types::AddRegionResponse;
        attach_customer_managed_policy_reference_to_permission_set(types::AttachCustomerManagedPolicyReferenceToPermissionSetRequest) -> types::AttachCustomerManagedPolicyReferenceToPermissionSetResponse;
        attach_managed_policy_to_permission_set(types::AttachManagedPolicyToPermissionSetRequest) -> types::AttachManagedPolicyToPermissionSetResponse;
        create_account_assignment(types::CreateAccountAssignmentRequest) -> types::CreateAccountAssignmentResponse;
        create_application(types::CreateApplicationRequest) -> types::CreateApplicationResponse;
        create_application_assignment(types::CreateApplicationAssignmentRequest) -> types::CreateApplicationAssignmentResponse;
        create_instance(types::CreateInstanceRequest) -> types::CreateInstanceResponse;
        create_instance_access_control_attribute_configuration(types::CreateInstanceAccessControlAttributeConfigurationRequest) -> types::CreateInstanceAccessControlAttributeConfigurationResponse;
        create_permission_set(types::CreatePermissionSetRequest) -> types::CreatePermissionSetResponse;
        create_trusted_token_issuer(types::CreateTrustedTokenIssuerRequest) -> types::CreateTrustedTokenIssuerResponse;
        delete_account_assignment(types::DeleteAccountAssignmentRequest) -> types::DeleteAccountAssignmentResponse;
        delete_application(types::DeleteApplicationRequest) -> types::DeleteApplicationResponse;
        delete_application_access_scope(types::DeleteApplicationAccessScopeRequest) -> ();
        delete_application_assignment(types::DeleteApplicationAssignmentRequest) -> types::DeleteApplicationAssignmentResponse;
        delete_application_authentication_method(types::DeleteApplicationAuthenticationMethodRequest) -> ();
        delete_application_grant(types::DeleteApplicationGrantRequest) -> ();
        delete_inline_policy_from_permission_set(types::DeleteInlinePolicyFromPermissionSetRequest) -> types::DeleteInlinePolicyFromPermissionSetResponse;
        delete_instance(types::DeleteInstanceRequest) -> types::DeleteInstanceResponse;
        delete_instance_access_control_attribute_configuration(types::DeleteInstanceAccessControlAttributeConfigurationRequest) -> types::DeleteInstanceAccessControlAttributeConfigurationResponse;
        delete_permission_set(types::DeletePermissionSetRequest) -> types::DeletePermissionSetResponse;
        delete_permissions_boundary_from_permission_set(types::DeletePermissionsBoundaryFromPermissionSetRequest) -> types::DeletePermissionsBoundaryFromPermissionSetResponse;
        delete_trusted_token_issuer(types::DeleteTrustedTokenIssuerRequest) -> types::DeleteTrustedTokenIssuerResponse;
        describe_account_assignment_creation_status(types::DescribeAccountAssignmentCreationStatusRequest) -> types::DescribeAccountAssignmentCreationStatusResponse;
        describe_account_assignment_deletion_status(types::DescribeAccountAssignmentDeletionStatusRequest) -> types::DescribeAccountAssignmentDeletionStatusResponse;
        describe_application(types::DescribeApplicationRequest) -> types::DescribeApplicationResponse;
        describe_application_assignment(types::DescribeApplicationAssignmentRequest) -> types::DescribeApplicationAssignmentResponse;
        describe_application_provider(types::DescribeApplicationProviderRequest) -> types::DescribeApplicationProviderResponse;
        describe_instance(types::DescribeInstanceRequest) -> types::DescribeInstanceResponse;
        describe_instance_access_control_attribute_configuration(types::DescribeInstanceAccessControlAttributeConfigurationRequest) -> types::DescribeInstanceAccessControlAttributeConfigurationResponse;
        describe_permission_set(types::DescribePermissionSetRequest) -> types::DescribePermissionSetResponse;
        describe_permission_set_provisioning_status(types::DescribePermissionSetProvisioningStatusRequest) -> types::DescribePermissionSetProvisioningStatusResponse;
        describe_region(types::DescribeRegionRequest) -> types::DescribeRegionResponse;
        describe_trusted_token_issuer(types::DescribeTrustedTokenIssuerRequest) -> types::DescribeTrustedTokenIssuerResponse;
        detach_customer_managed_policy_reference_from_permission_set(types::DetachCustomerManagedPolicyReferenceFromPermissionSetRequest) -> types::DetachCustomerManagedPolicyReferenceFromPermissionSetResponse;
        detach_managed_policy_from_permission_set(types::DetachManagedPolicyFromPermissionSetRequest) -> types::DetachManagedPolicyFromPermissionSetResponse;
        get_application_access_scope(types::GetApplicationAccessScopeRequest) -> types::GetApplicationAccessScopeResponse;
        get_application_assignment_configuration(types::GetApplicationAssignmentConfigurationRequest) -> types::GetApplicationAssignmentConfigurationResponse;
        get_application_authentication_method(types::GetApplicationAuthenticationMethodRequest) -> types::GetApplicationAuthenticationMethodResponse;
        get_application_grant(types::GetApplicationGrantRequest) -> types::GetApplicationGrantResponse;
        get_application_session_configuration(types::GetApplicationSessionConfigurationRequest) -> types::GetApplicationSessionConfigurationResponse;
        get_inline_policy_for_permission_set(types::GetInlinePolicyForPermissionSetRequest) -> types::GetInlinePolicyForPermissionSetResponse;
        get_permissions_boundary_for_permission_set(types::GetPermissionsBoundaryForPermissionSetRequest) -> types::GetPermissionsBoundaryForPermissionSetResponse;
        list_account_assignment_creation_status(types::ListAccountAssignmentCreationStatusRequest) -> types::ListAccountAssignmentCreationStatusResponse;
        list_account_assignment_deletion_status(types::ListAccountAssignmentDeletionStatusRequest) -> types::ListAccountAssignmentDeletionStatusResponse;
        list_account_assignments(types::ListAccountAssignmentsRequest) -> types::ListAccountAssignmentsResponse;
        list_account_assignments_for_principal(types::ListAccountAssignmentsForPrincipalRequest) -> types::ListAccountAssignmentsForPrincipalResponse;
        list_accounts_for_provisioned_permission_set(types::ListAccountsForProvisionedPermissionSetRequest) -> types::ListAccountsForProvisionedPermissionSetResponse;
        list_application_access_scopes(types::ListApplicationAccessScopesRequest) -> types::ListApplicationAccessScopesResponse;
        list_application_assignments(types::ListApplicationAssignmentsRequest) -> types::ListApplicationAssignmentsResponse;
        list_application_assignments_for_principal(types::ListApplicationAssignmentsForPrincipalRequest) -> types::ListApplicationAssignmentsForPrincipalResponse;
        list_application_authentication_methods(types::ListApplicationAuthenticationMethodsRequest) -> types::ListApplicationAuthenticationMethodsResponse;
        list_application_grants(types::ListApplicationGrantsRequest) -> types::ListApplicationGrantsResponse;
        list_application_providers(types::ListApplicationProvidersRequest) -> types::ListApplicationProvidersResponse;
        list_applications(types::ListApplicationsRequest) -> types::ListApplicationsResponse;
        list_customer_managed_policy_references_in_permission_set(types::ListCustomerManagedPolicyReferencesInPermissionSetRequest) -> types::ListCustomerManagedPolicyReferencesInPermissionSetResponse;
        list_instances(types::ListInstancesRequest) -> types::ListInstancesResponse;
        list_managed_policies_in_permission_set(types::ListManagedPoliciesInPermissionSetRequest) -> types::ListManagedPoliciesInPermissionSetResponse;
        list_permission_set_provisioning_status(types::ListPermissionSetProvisioningStatusRequest) -> types::ListPermissionSetProvisioningStatusResponse;
        list_permission_sets(types::ListPermissionSetsRequest) -> types::ListPermissionSetsResponse;
        list_permission_sets_provisioned_to_account(types::ListPermissionSetsProvisionedToAccountRequest) -> types::ListPermissionSetsProvisionedToAccountResponse;
        list_regions(types::ListRegionsRequest) -> types::ListRegionsResponse;
        list_tags_for_resource(types::ListTagsForResourceRequest) -> types::ListTagsForResourceResponse;
        list_trusted_token_issuers(types::ListTrustedTokenIssuersRequest) -> types::ListTrustedTokenIssuersResponse;
        provision_permission_set(types::ProvisionPermissionSetRequest) -> types::ProvisionPermissionSetResponse;
        put_application_access_scope(types::PutApplicationAccessScopeRequest) -> ();
        put_application_assignment_configuration(types::PutApplicationAssignmentConfigurationRequest) -> types::PutApplicationAssignmentConfigurationResponse;
        put_application_authentication_method(types::PutApplicationAuthenticationMethodRequest) -> ();
        put_application_grant(types::PutApplicationGrantRequest) -> ();
        put_application_session_configuration(types::PutApplicationSessionConfigurationRequest) -> types::PutApplicationSessionConfigurationResponse;
        put_inline_policy_to_permission_set(types::PutInlinePolicyToPermissionSetRequest) -> types::PutInlinePolicyToPermissionSetResponse;
        put_permissions_boundary_to_permission_set(types::PutPermissionsBoundaryToPermissionSetRequest) -> types::PutPermissionsBoundaryToPermissionSetResponse;
        remove_region(types::RemoveRegionRequest) -> types::RemoveRegionResponse;
        tag_resource(types::TagResourceRequest) -> types::TagResourceResponse;
        untag_resource(types::UntagResourceRequest) -> types::UntagResourceResponse;
        update_application(types::UpdateApplicationRequest) -> types::UpdateApplicationResponse;
        update_instance(types::UpdateInstanceRequest) -> types::UpdateInstanceResponse;
        update_instance_access_control_attribute_configuration(types::UpdateInstanceAccessControlAttributeConfigurationRequest) -> types::UpdateInstanceAccessControlAttributeConfigurationResponse;
        update_permission_set(types::UpdatePermissionSetRequest) -> types::UpdatePermissionSetResponse;
        update_trusted_token_issuer(types::UpdateTrustedTokenIssuerRequest) -> types::UpdateTrustedTokenIssuerResponse;
    }
}

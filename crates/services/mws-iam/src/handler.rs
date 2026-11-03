//! Wires the generated `Handler` trait to the operation implementations in
//! `ops/`. Operations are synchronous; this adapts them to the async trait.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::Iam;

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
                let result = Iam::$name(self, ctx, input);
                Box::pin(async move { result })
            }
        )*
    };
}

impl Handler for Iam {
    delegate! {
        accept_delegation_request(types::AcceptDelegationRequestRequest) -> ();
        acquire_role(types::AcquireRoleRequest) -> types::AcquireRoleResponse;
        associate_delegation_request(types::AssociateDelegationRequestRequest) -> ();
        create_delegation_request(types::CreateDelegationRequestRequest) -> types::CreateDelegationRequestResponse;
        create_service_linked_role(types::CreateServiceLinkedRoleRequest) -> types::CreateServiceLinkedRoleResponse;
        delete_service_linked_role(types::DeleteServiceLinkedRoleRequest) -> types::DeleteServiceLinkedRoleResponse;
        generate_organizations_access_report(types::GenerateOrganizationsAccessReportRequest) -> types::GenerateOrganizationsAccessReportResponse;
        generate_service_last_accessed_details(types::GenerateServiceLastAccessedDetailsRequest) -> types::GenerateServiceLastAccessedDetailsResponse;
        get_delegation_request(types::GetDelegationRequestRequest) -> types::GetDelegationRequestResponse;
        get_human_readable_summary(types::GetHumanReadableSummaryRequest) -> types::GetHumanReadableSummaryResponse;
        get_organizations_access_report(types::GetOrganizationsAccessReportRequest) -> types::GetOrganizationsAccessReportResponse;
        get_role_template_version(types::GetRoleTemplateVersionRequest) -> types::GetRoleTemplateVersionResponse;
        get_service_last_accessed_details(types::GetServiceLastAccessedDetailsRequest) -> types::GetServiceLastAccessedDetailsResponse;
        get_service_last_accessed_details_with_entities(types::GetServiceLastAccessedDetailsWithEntitiesRequest) -> types::GetServiceLastAccessedDetailsWithEntitiesResponse;
        get_service_linked_role_deletion_status(types::GetServiceLinkedRoleDeletionStatusRequest) -> types::GetServiceLinkedRoleDeletionStatusResponse;
        list_delegation_requests(types::ListDelegationRequestsRequest) -> types::ListDelegationRequestsResponse;
        list_policies_granting_service_access(types::ListPoliciesGrantingServiceAccessRequest) -> types::ListPoliciesGrantingServiceAccessResponse;
        reject_delegation_request(types::RejectDelegationRequestRequest) -> ();
        send_delegation_token(types::SendDelegationTokenRequest) -> ();
        update_delegation_request(types::UpdateDelegationRequestRequest) -> ();
        create_saml_provider(types::CreateSAMLProviderRequest) -> types::CreateSAMLProviderResponse;
        delete_saml_provider(types::DeleteSAMLProviderRequest) -> ();
        disable_organizations_root_credentials_management(types::DisableOrganizationsRootCredentialsManagementRequest) -> types::DisableOrganizationsRootCredentialsManagementResponse;
        disable_organizations_root_sessions(types::DisableOrganizationsRootSessionsRequest) -> types::DisableOrganizationsRootSessionsResponse;
        enable_organizations_root_credentials_management(types::EnableOrganizationsRootCredentialsManagementRequest) -> types::EnableOrganizationsRootCredentialsManagementResponse;
        enable_organizations_root_sessions(types::EnableOrganizationsRootSessionsRequest) -> types::EnableOrganizationsRootSessionsResponse;
        get_account_properties(types::GetAccountPropertiesRequest) -> types::GetAccountPropertiesResponse;
        get_saml_provider(types::GetSAMLProviderRequest) -> types::GetSAMLProviderResponse;
        list_organizations_features(types::ListOrganizationsFeaturesRequest) -> types::ListOrganizationsFeaturesResponse;
        list_saml_provider_tags(types::ListSAMLProviderTagsRequest) -> types::ListSAMLProviderTagsResponse;
        list_saml_providers(types::ListSAMLProvidersRequest) -> types::ListSAMLProvidersResponse;
        put_account_properties(types::PutAccountPropertiesRequest) -> types::PutAccountPropertiesResponse;
        set_security_token_service_preferences(types::SetSecurityTokenServicePreferencesRequest) -> ();
        tag_saml_provider(types::TagSAMLProviderRequest) -> ();
        untag_saml_provider(types::UntagSAMLProviderRequest) -> ();
        update_account_password_policy(types::UpdateAccountPasswordPolicyRequest) -> ();
        update_saml_provider(types::UpdateSAMLProviderRequest) -> types::UpdateSAMLProviderResponse;
        delete_account_password_policy(()) -> ();
        get_account_password_policy(()) -> types::GetAccountPasswordPolicyResponse;
        get_account_summary(()) -> types::GetAccountSummaryResponse;
        generate_credential_report(()) -> types::GenerateCredentialReportResponse;
        get_credential_report(()) -> types::GetCredentialReportResponse;
        enable_outbound_web_identity_federation(()) -> types::EnableOutboundWebIdentityFederationResponse;
        disable_outbound_web_identity_federation(()) -> ();
        get_outbound_web_identity_federation_info(()) -> types::GetOutboundWebIdentityFederationInfoResponse;
        change_password(types::ChangePasswordRequest) -> ();

        create_service_specific_credential(types::CreateServiceSpecificCredentialRequest) -> types::CreateServiceSpecificCredentialResponse;
        create_virtual_mfa_device(types::CreateVirtualMFADeviceRequest) -> types::CreateVirtualMFADeviceResponse;
        deactivate_mfa_device(types::DeactivateMFADeviceRequest) -> ();
        delete_ssh_public_key(types::DeleteSSHPublicKeyRequest) -> ();
        delete_server_certificate(types::DeleteServerCertificateRequest) -> ();
        delete_service_specific_credential(types::DeleteServiceSpecificCredentialRequest) -> ();
        delete_signing_certificate(types::DeleteSigningCertificateRequest) -> ();
        delete_virtual_mfa_device(types::DeleteVirtualMFADeviceRequest) -> ();
        enable_mfa_device(types::EnableMFADeviceRequest) -> ();
        get_mfa_device(types::GetMFADeviceRequest) -> types::GetMFADeviceResponse;
        get_ssh_public_key(types::GetSSHPublicKeyRequest) -> types::GetSSHPublicKeyResponse;
        get_server_certificate(types::GetServerCertificateRequest) -> types::GetServerCertificateResponse;
        list_mfa_device_tags(types::ListMFADeviceTagsRequest) -> types::ListMFADeviceTagsResponse;
        list_mfa_devices(types::ListMFADevicesRequest) -> types::ListMFADevicesResponse;
        list_ssh_public_keys(types::ListSSHPublicKeysRequest) -> types::ListSSHPublicKeysResponse;
        list_server_certificate_tags(types::ListServerCertificateTagsRequest) -> types::ListServerCertificateTagsResponse;
        list_server_certificates(types::ListServerCertificatesRequest) -> types::ListServerCertificatesResponse;
        list_service_specific_credentials(types::ListServiceSpecificCredentialsRequest) -> types::ListServiceSpecificCredentialsResponse;
        list_signing_certificates(types::ListSigningCertificatesRequest) -> types::ListSigningCertificatesResponse;
        list_virtual_mfa_devices(types::ListVirtualMFADevicesRequest) -> types::ListVirtualMFADevicesResponse;
        reset_service_specific_credential(types::ResetServiceSpecificCredentialRequest) -> types::ResetServiceSpecificCredentialResponse;
        resync_mfa_device(types::ResyncMFADeviceRequest) -> ();
        tag_mfa_device(types::TagMFADeviceRequest) -> ();
        tag_server_certificate(types::TagServerCertificateRequest) -> ();
        untag_mfa_device(types::UntagMFADeviceRequest) -> ();
        untag_server_certificate(types::UntagServerCertificateRequest) -> ();
        update_ssh_public_key(types::UpdateSSHPublicKeyRequest) -> ();
        update_server_certificate(types::UpdateServerCertificateRequest) -> ();
        update_service_specific_credential(types::UpdateServiceSpecificCredentialRequest) -> ();
        update_signing_certificate(types::UpdateSigningCertificateRequest) -> ();
        upload_ssh_public_key(types::UploadSSHPublicKeyRequest) -> types::UploadSSHPublicKeyResponse;
        upload_server_certificate(types::UploadServerCertificateRequest) -> types::UploadServerCertificateResponse;
        upload_signing_certificate(types::UploadSigningCertificateRequest) -> types::UploadSigningCertificateResponse;

        create_open_id_connect_provider(types::CreateOpenIDConnectProviderRequest) -> types::CreateOpenIDConnectProviderResponse;
        get_open_id_connect_provider(types::GetOpenIDConnectProviderRequest) -> types::GetOpenIDConnectProviderResponse;
        list_open_id_connect_providers(types::ListOpenIDConnectProvidersRequest) -> types::ListOpenIDConnectProvidersResponse;
        delete_open_id_connect_provider(types::DeleteOpenIDConnectProviderRequest) -> ();
        add_client_id_to_open_id_connect_provider(types::AddClientIDToOpenIDConnectProviderRequest) -> ();
        remove_client_id_from_open_id_connect_provider(types::RemoveClientIDFromOpenIDConnectProviderRequest) -> ();
        update_open_id_connect_provider_thumbprint(types::UpdateOpenIDConnectProviderThumbprintRequest) -> ();
        tag_open_id_connect_provider(types::TagOpenIDConnectProviderRequest) -> ();
        untag_open_id_connect_provider(types::UntagOpenIDConnectProviderRequest) -> ();
        list_open_id_connect_provider_tags(types::ListOpenIDConnectProviderTagsRequest) -> types::ListOpenIDConnectProviderTagsResponse;
        create_account_alias(types::CreateAccountAliasRequest) -> ();
        delete_account_alias(types::DeleteAccountAliasRequest) -> ();
        list_account_aliases(types::ListAccountAliasesRequest) -> types::ListAccountAliasesResponse;
        get_account_authorization_details(types::GetAccountAuthorizationDetailsRequest) -> types::GetAccountAuthorizationDetailsResponse;
        create_group(types::CreateGroupRequest) -> types::CreateGroupResponse;
        get_group(types::GetGroupRequest) -> types::GetGroupResponse;
        list_groups(types::ListGroupsRequest) -> types::ListGroupsResponse;
        list_groups_for_user(types::ListGroupsForUserRequest) -> types::ListGroupsForUserResponse;
        update_group(types::UpdateGroupRequest) -> ();
        delete_group(types::DeleteGroupRequest) -> ();
        add_user_to_group(types::AddUserToGroupRequest) -> ();
        remove_user_from_group(types::RemoveUserFromGroupRequest) -> ();
        create_policy(types::CreatePolicyRequest) -> types::CreatePolicyResponse;
        get_policy(types::GetPolicyRequest) -> types::GetPolicyResponse;
        list_policies(types::ListPoliciesRequest) -> types::ListPoliciesResponse;
        delete_policy(types::DeletePolicyRequest) -> ();
        create_policy_version(types::CreatePolicyVersionRequest) -> types::CreatePolicyVersionResponse;
        get_policy_version(types::GetPolicyVersionRequest) -> types::GetPolicyVersionResponse;
        list_policy_versions(types::ListPolicyVersionsRequest) -> types::ListPolicyVersionsResponse;
        delete_policy_version(types::DeletePolicyVersionRequest) -> ();
        set_default_policy_version(types::SetDefaultPolicyVersionRequest) -> ();
        tag_policy(types::TagPolicyRequest) -> ();
        untag_policy(types::UntagPolicyRequest) -> ();
        list_policy_tags(types::ListPolicyTagsRequest) -> types::ListPolicyTagsResponse;
        list_entities_for_policy(types::ListEntitiesForPolicyRequest) -> types::ListEntitiesForPolicyResponse;
        attach_user_policy(types::AttachUserPolicyRequest) -> ();
        attach_group_policy(types::AttachGroupPolicyRequest) -> ();
        attach_role_policy(types::AttachRolePolicyRequest) -> ();
        detach_user_policy(types::DetachUserPolicyRequest) -> ();
        detach_group_policy(types::DetachGroupPolicyRequest) -> ();
        detach_role_policy(types::DetachRolePolicyRequest) -> ();
        list_attached_user_policies(types::ListAttachedUserPoliciesRequest) -> types::ListAttachedUserPoliciesResponse;
        list_attached_group_policies(types::ListAttachedGroupPoliciesRequest) -> types::ListAttachedGroupPoliciesResponse;
        list_attached_role_policies(types::ListAttachedRolePoliciesRequest) -> types::ListAttachedRolePoliciesResponse;
        put_user_policy(types::PutUserPolicyRequest) -> ();
        put_group_policy(types::PutGroupPolicyRequest) -> ();
        put_role_policy(types::PutRolePolicyRequest) -> ();
        get_user_policy(types::GetUserPolicyRequest) -> types::GetUserPolicyResponse;
        get_group_policy(types::GetGroupPolicyRequest) -> types::GetGroupPolicyResponse;
        get_role_policy(types::GetRolePolicyRequest) -> types::GetRolePolicyResponse;
        delete_user_policy(types::DeleteUserPolicyRequest) -> ();
        delete_group_policy(types::DeleteGroupPolicyRequest) -> ();
        delete_role_policy(types::DeleteRolePolicyRequest) -> ();
        list_user_policies(types::ListUserPoliciesRequest) -> types::ListUserPoliciesResponse;
        list_group_policies(types::ListGroupPoliciesRequest) -> types::ListGroupPoliciesResponse;
        list_role_policies(types::ListRolePoliciesRequest) -> types::ListRolePoliciesResponse;
        create_role(types::CreateRoleRequest) -> types::CreateRoleResponse;
        get_role(types::GetRoleRequest) -> types::GetRoleResponse;
        list_roles(types::ListRolesRequest) -> types::ListRolesResponse;
        update_role(types::UpdateRoleRequest) -> types::UpdateRoleResponse;
        update_role_description(types::UpdateRoleDescriptionRequest) -> types::UpdateRoleDescriptionResponse;
        update_assume_role_policy(types::UpdateAssumeRolePolicyRequest) -> ();
        delete_role(types::DeleteRoleRequest) -> ();
        tag_role(types::TagRoleRequest) -> ();
        untag_role(types::UntagRoleRequest) -> ();
        list_role_tags(types::ListRoleTagsRequest) -> types::ListRoleTagsResponse;
        put_role_permissions_boundary(types::PutRolePermissionsBoundaryRequest) -> ();
        delete_role_permissions_boundary(types::DeleteRolePermissionsBoundaryRequest) -> ();
        create_instance_profile(types::CreateInstanceProfileRequest) -> types::CreateInstanceProfileResponse;
        get_instance_profile(types::GetInstanceProfileRequest) -> types::GetInstanceProfileResponse;
        list_instance_profiles(types::ListInstanceProfilesRequest) -> types::ListInstanceProfilesResponse;
        list_instance_profiles_for_role(types::ListInstanceProfilesForRoleRequest) -> types::ListInstanceProfilesForRoleResponse;
        add_role_to_instance_profile(types::AddRoleToInstanceProfileRequest) -> ();
        remove_role_from_instance_profile(types::RemoveRoleFromInstanceProfileRequest) -> ();
        delete_instance_profile(types::DeleteInstanceProfileRequest) -> ();
        tag_instance_profile(types::TagInstanceProfileRequest) -> ();
        untag_instance_profile(types::UntagInstanceProfileRequest) -> ();
        list_instance_profile_tags(types::ListInstanceProfileTagsRequest) -> types::ListInstanceProfileTagsResponse;
        simulate_principal_policy(types::SimulatePrincipalPolicyRequest) -> types::SimulatePolicyResponse;
        simulate_custom_policy(types::SimulateCustomPolicyRequest) -> types::SimulatePolicyResponse;
        get_context_keys_for_custom_policy(types::GetContextKeysForCustomPolicyRequest) -> types::GetContextKeysForPolicyResponse;
        get_context_keys_for_principal_policy(types::GetContextKeysForPrincipalPolicyRequest) -> types::GetContextKeysForPolicyResponse;
        create_user(types::CreateUserRequest) -> types::CreateUserResponse;
        get_user(types::GetUserRequest) -> types::GetUserResponse;
        list_users(types::ListUsersRequest) -> types::ListUsersResponse;
        update_user(types::UpdateUserRequest) -> ();
        delete_user(types::DeleteUserRequest) -> ();
        tag_user(types::TagUserRequest) -> ();
        untag_user(types::UntagUserRequest) -> ();
        list_user_tags(types::ListUserTagsRequest) -> types::ListUserTagsResponse;
        put_user_permissions_boundary(types::PutUserPermissionsBoundaryRequest) -> ();
        delete_user_permissions_boundary(types::DeleteUserPermissionsBoundaryRequest) -> ();
        create_login_profile(types::CreateLoginProfileRequest) -> types::CreateLoginProfileResponse;
        get_login_profile(types::GetLoginProfileRequest) -> types::GetLoginProfileResponse;
        update_login_profile(types::UpdateLoginProfileRequest) -> ();
        delete_login_profile(types::DeleteLoginProfileRequest) -> ();
        create_access_key(types::CreateAccessKeyRequest) -> types::CreateAccessKeyResponse;
        list_access_keys(types::ListAccessKeysRequest) -> types::ListAccessKeysResponse;
        delete_access_key(types::DeleteAccessKeyRequest) -> ();
        update_access_key(types::UpdateAccessKeyRequest) -> ();
        get_access_key_last_used(types::GetAccessKeyLastUsedRequest) -> types::GetAccessKeyLastUsedResponse;
    }
}

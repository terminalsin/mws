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

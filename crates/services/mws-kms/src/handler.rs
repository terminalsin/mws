//! Wires the generated `Handler` trait to the synchronous operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::Kms;

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
                let result = Kms::$name(self, ctx, input);
                Box::pin(async move { result })
            }
        )*
    };
}

impl Handler for Kms {
    delegate! {
        cancel_key_deletion(types::CancelKeyDeletionRequest) -> types::CancelKeyDeletionResponse;
        connect_custom_key_store(types::ConnectCustomKeyStoreRequest) -> types::ConnectCustomKeyStoreResponse;
        create_alias(types::CreateAliasRequest) -> ();
        create_custom_key_store(types::CreateCustomKeyStoreRequest) -> types::CreateCustomKeyStoreResponse;
        create_grant(types::CreateGrantRequest) -> types::CreateGrantResponse;
        create_key(types::CreateKeyRequest) -> types::CreateKeyResponse;
        decapsulate(types::DecapsulateRequest) -> types::DecapsulateResponse;
        decrypt(types::DecryptRequest) -> types::DecryptResponse;
        delete_alias(types::DeleteAliasRequest) -> ();
        delete_custom_key_store(types::DeleteCustomKeyStoreRequest) -> types::DeleteCustomKeyStoreResponse;
        delete_imported_key_material(types::DeleteImportedKeyMaterialRequest) -> types::DeleteImportedKeyMaterialResponse;
        derive_shared_secret(types::DeriveSharedSecretRequest) -> types::DeriveSharedSecretResponse;
        describe_custom_key_stores(types::DescribeCustomKeyStoresRequest) -> types::DescribeCustomKeyStoresResponse;
        describe_key(types::DescribeKeyRequest) -> types::DescribeKeyResponse;
        disable_key(types::DisableKeyRequest) -> ();
        disable_key_rotation(types::DisableKeyRotationRequest) -> ();
        disconnect_custom_key_store(types::DisconnectCustomKeyStoreRequest) -> types::DisconnectCustomKeyStoreResponse;
        enable_key(types::EnableKeyRequest) -> ();
        enable_key_rotation(types::EnableKeyRotationRequest) -> ();
        encapsulate(types::EncapsulateRequest) -> types::EncapsulateResponse;
        encrypt(types::EncryptRequest) -> types::EncryptResponse;
        generate_data_key(types::GenerateDataKeyRequest) -> types::GenerateDataKeyResponse;
        generate_data_key_pair(types::GenerateDataKeyPairRequest) -> types::GenerateDataKeyPairResponse;
        generate_data_key_pair_without_plaintext(types::GenerateDataKeyPairWithoutPlaintextRequest) -> types::GenerateDataKeyPairWithoutPlaintextResponse;
        generate_data_key_without_plaintext(types::GenerateDataKeyWithoutPlaintextRequest) -> types::GenerateDataKeyWithoutPlaintextResponse;
        generate_mac(types::GenerateMacRequest) -> types::GenerateMacResponse;
        generate_random(types::GenerateRandomRequest) -> types::GenerateRandomResponse;
        get_key_last_usage(types::GetKeyLastUsageRequest) -> types::GetKeyLastUsageResponse;
        get_key_policy(types::GetKeyPolicyRequest) -> types::GetKeyPolicyResponse;
        get_key_rotation_status(types::GetKeyRotationStatusRequest) -> types::GetKeyRotationStatusResponse;
        get_parameters_for_import(types::GetParametersForImportRequest) -> types::GetParametersForImportResponse;
        get_public_key(types::GetPublicKeyRequest) -> types::GetPublicKeyResponse;
        import_key_material(types::ImportKeyMaterialRequest) -> types::ImportKeyMaterialResponse;
        list_aliases(types::ListAliasesRequest) -> types::ListAliasesResponse;
        list_grants(types::ListGrantsRequest) -> types::ListGrantsResponse;
        list_key_policies(types::ListKeyPoliciesRequest) -> types::ListKeyPoliciesResponse;
        list_key_rotations(types::ListKeyRotationsRequest) -> types::ListKeyRotationsResponse;
        list_keys(types::ListKeysRequest) -> types::ListKeysResponse;
        list_resource_tags(types::ListResourceTagsRequest) -> types::ListResourceTagsResponse;
        list_retirable_grants(types::ListRetirableGrantsRequest) -> types::ListGrantsResponse;
        put_key_policy(types::PutKeyPolicyRequest) -> ();
        re_encrypt(types::ReEncryptRequest) -> types::ReEncryptResponse;
        replicate_key(types::ReplicateKeyRequest) -> types::ReplicateKeyResponse;
        retire_grant(types::RetireGrantRequest) -> ();
        revoke_grant(types::RevokeGrantRequest) -> ();
        rotate_key_on_demand(types::RotateKeyOnDemandRequest) -> types::RotateKeyOnDemandResponse;
        schedule_key_deletion(types::ScheduleKeyDeletionRequest) -> types::ScheduleKeyDeletionResponse;
        sign(types::SignRequest) -> types::SignResponse;
        tag_resource(types::TagResourceRequest) -> ();
        untag_resource(types::UntagResourceRequest) -> ();
        update_alias(types::UpdateAliasRequest) -> ();
        update_custom_key_store(types::UpdateCustomKeyStoreRequest) -> types::UpdateCustomKeyStoreResponse;
        update_key_description(types::UpdateKeyDescriptionRequest) -> ();
        update_primary_region(types::UpdatePrimaryRegionRequest) -> ();
        verify(types::VerifyRequest) -> types::VerifyResponse;
        verify_mac(types::VerifyMacRequest) -> types::VerifyMacResponse;
    }
}

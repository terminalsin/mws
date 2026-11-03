//! Wires the generated `Handler` trait to the operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::SecretsManager;

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
                let result = SecretsManager::$name(self, ctx, input);
                Box::pin(async move { result })
            }
        )*
    };
}

impl Handler for SecretsManager {
    delegate! {
        batch_get_secret_value(types::BatchGetSecretValueRequest) -> types::BatchGetSecretValueResponse;
        cancel_rotate_secret(types::CancelRotateSecretRequest) -> types::CancelRotateSecretResponse;
        create_secret(types::CreateSecretRequest) -> types::CreateSecretResponse;
        delete_resource_policy(types::DeleteResourcePolicyRequest) -> types::DeleteResourcePolicyResponse;
        delete_secret(types::DeleteSecretRequest) -> types::DeleteSecretResponse;
        describe_secret(types::DescribeSecretRequest) -> types::DescribeSecretResponse;
        get_random_password(types::GetRandomPasswordRequest) -> types::GetRandomPasswordResponse;
        get_resource_policy(types::GetResourcePolicyRequest) -> types::GetResourcePolicyResponse;
        get_secret_value(types::GetSecretValueRequest) -> types::GetSecretValueResponse;
        list_secret_version_ids(types::ListSecretVersionIdsRequest) -> types::ListSecretVersionIdsResponse;
        list_secrets(types::ListSecretsRequest) -> types::ListSecretsResponse;
        put_resource_policy(types::PutResourcePolicyRequest) -> types::PutResourcePolicyResponse;
        put_secret_value(types::PutSecretValueRequest) -> types::PutSecretValueResponse;
        remove_regions_from_replication(types::RemoveRegionsFromReplicationRequest) -> types::RemoveRegionsFromReplicationResponse;
        replicate_secret_to_regions(types::ReplicateSecretToRegionsRequest) -> types::ReplicateSecretToRegionsResponse;
        restore_secret(types::RestoreSecretRequest) -> types::RestoreSecretResponse;
        rotate_secret(types::RotateSecretRequest) -> types::RotateSecretResponse;
        stop_replication_to_replica(types::StopReplicationToReplicaRequest) -> types::StopReplicationToReplicaResponse;
        tag_resource(types::TagResourceRequest) -> ();
        untag_resource(types::UntagResourceRequest) -> ();
        update_secret(types::UpdateSecretRequest) -> types::UpdateSecretResponse;
        update_secret_version_stage(types::UpdateSecretVersionStageRequest) -> types::UpdateSecretVersionStageResponse;
        validate_resource_policy(types::ValidateResourcePolicyRequest) -> types::ValidateResourcePolicyResponse;
    }
}

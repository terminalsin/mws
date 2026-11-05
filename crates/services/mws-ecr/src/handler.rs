//! Wires the generated `Handler` trait to the synchronous operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::Ecr;

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
                let result = Ecr::$name(self, ctx, input);
                Box::pin(async move { result })
            }
        )*
    };
}

impl Handler for Ecr {
    delegate! {
        batch_check_layer_availability(types::BatchCheckLayerAvailabilityRequest) -> types::BatchCheckLayerAvailabilityResponse;
        batch_delete_image(types::BatchDeleteImageRequest) -> types::BatchDeleteImageResponse;
        batch_get_image(types::BatchGetImageRequest) -> types::BatchGetImageResponse;
        batch_get_repository_scanning_configuration(types::BatchGetRepositoryScanningConfigurationRequest) -> types::BatchGetRepositoryScanningConfigurationResponse;
        complete_layer_upload(types::CompleteLayerUploadRequest) -> types::CompleteLayerUploadResponse;
        create_pull_through_cache_rule(types::CreatePullThroughCacheRuleRequest) -> types::CreatePullThroughCacheRuleResponse;
        create_repository(types::CreateRepositoryRequest) -> types::CreateRepositoryResponse;
        create_repository_creation_template(types::CreateRepositoryCreationTemplateRequest) -> types::CreateRepositoryCreationTemplateResponse;
        delete_lifecycle_policy(types::DeleteLifecyclePolicyRequest) -> types::DeleteLifecyclePolicyResponse;
        delete_pull_through_cache_rule(types::DeletePullThroughCacheRuleRequest) -> types::DeletePullThroughCacheRuleResponse;
        delete_registry_policy(types::DeleteRegistryPolicyRequest) -> types::DeleteRegistryPolicyResponse;
        delete_repository(types::DeleteRepositoryRequest) -> types::DeleteRepositoryResponse;
        delete_repository_creation_template(types::DeleteRepositoryCreationTemplateRequest) -> types::DeleteRepositoryCreationTemplateResponse;
        delete_repository_policy(types::DeleteRepositoryPolicyRequest) -> types::DeleteRepositoryPolicyResponse;
        delete_signing_configuration(types::DeleteSigningConfigurationRequest) -> types::DeleteSigningConfigurationResponse;
        deregister_pull_time_update_exclusion(types::DeregisterPullTimeUpdateExclusionRequest) -> types::DeregisterPullTimeUpdateExclusionResponse;
        describe_image_replication_status(types::DescribeImageReplicationStatusRequest) -> types::DescribeImageReplicationStatusResponse;
        describe_image_scan_findings(types::DescribeImageScanFindingsRequest) -> types::DescribeImageScanFindingsResponse;
        describe_image_signing_status(types::DescribeImageSigningStatusRequest) -> types::DescribeImageSigningStatusResponse;
        describe_images(types::DescribeImagesRequest) -> types::DescribeImagesResponse;
        describe_pull_through_cache_rules(types::DescribePullThroughCacheRulesRequest) -> types::DescribePullThroughCacheRulesResponse;
        describe_registry(types::DescribeRegistryRequest) -> types::DescribeRegistryResponse;
        describe_replication_backfill_results(types::DescribeReplicationBackfillResultsRequest) -> types::DescribeReplicationBackfillResultsResponse;
        describe_repositories(types::DescribeRepositoriesRequest) -> types::DescribeRepositoriesResponse;
        describe_repository_creation_templates(types::DescribeRepositoryCreationTemplatesRequest) -> types::DescribeRepositoryCreationTemplatesResponse;
        get_account_setting(types::GetAccountSettingRequest) -> types::GetAccountSettingResponse;
        get_authorization_token(types::GetAuthorizationTokenRequest) -> types::GetAuthorizationTokenResponse;
        get_download_url_for_layer(types::GetDownloadUrlForLayerRequest) -> types::GetDownloadUrlForLayerResponse;
        get_lifecycle_policy(types::GetLifecyclePolicyRequest) -> types::GetLifecyclePolicyResponse;
        get_lifecycle_policy_preview(types::GetLifecyclePolicyPreviewRequest) -> types::GetLifecyclePolicyPreviewResponse;
        get_registry_policy(types::GetRegistryPolicyRequest) -> types::GetRegistryPolicyResponse;
        get_registry_scanning_configuration(types::GetRegistryScanningConfigurationRequest) -> types::GetRegistryScanningConfigurationResponse;
        get_repository_policy(types::GetRepositoryPolicyRequest) -> types::GetRepositoryPolicyResponse;
        get_signing_configuration(types::GetSigningConfigurationRequest) -> types::GetSigningConfigurationResponse;
        initiate_layer_upload(types::InitiateLayerUploadRequest) -> types::InitiateLayerUploadResponse;
        list_image_referrers(types::ListImageReferrersRequest) -> types::ListImageReferrersResponse;
        list_images(types::ListImagesRequest) -> types::ListImagesResponse;
        list_pull_time_update_exclusions(types::ListPullTimeUpdateExclusionsRequest) -> types::ListPullTimeUpdateExclusionsResponse;
        list_replication_backfills(types::ListReplicationBackfillsRequest) -> types::ListReplicationBackfillsResponse;
        list_tags_for_resource(types::ListTagsForResourceRequest) -> types::ListTagsForResourceResponse;
        put_account_setting(types::PutAccountSettingRequest) -> types::PutAccountSettingResponse;
        put_image(types::PutImageRequest) -> types::PutImageResponse;
        put_image_scanning_configuration(types::PutImageScanningConfigurationRequest) -> types::PutImageScanningConfigurationResponse;
        put_image_tag_mutability(types::PutImageTagMutabilityRequest) -> types::PutImageTagMutabilityResponse;
        put_lifecycle_policy(types::PutLifecyclePolicyRequest) -> types::PutLifecyclePolicyResponse;
        put_registry_policy(types::PutRegistryPolicyRequest) -> types::PutRegistryPolicyResponse;
        put_registry_scanning_configuration(types::PutRegistryScanningConfigurationRequest) -> types::PutRegistryScanningConfigurationResponse;
        put_replication_configuration(types::PutReplicationConfigurationRequest) -> types::PutReplicationConfigurationResponse;
        put_signing_configuration(types::PutSigningConfigurationRequest) -> types::PutSigningConfigurationResponse;
        register_pull_time_update_exclusion(types::RegisterPullTimeUpdateExclusionRequest) -> types::RegisterPullTimeUpdateExclusionResponse;
        set_repository_policy(types::SetRepositoryPolicyRequest) -> types::SetRepositoryPolicyResponse;
        start_image_scan(types::StartImageScanRequest) -> types::StartImageScanResponse;
        start_lifecycle_policy_preview(types::StartLifecyclePolicyPreviewRequest) -> types::StartLifecyclePolicyPreviewResponse;
        start_replication_backfill(types::StartReplicationBackfillRequest) -> types::StartReplicationBackfillResponse;
        stop_replication_backfill(types::StopReplicationBackfillRequest) -> types::StopReplicationBackfillResponse;
        tag_resource(types::TagResourceRequest) -> types::TagResourceResponse;
        untag_resource(types::UntagResourceRequest) -> types::UntagResourceResponse;
        update_image_storage_class(types::UpdateImageStorageClassRequest) -> types::UpdateImageStorageClassResponse;
        update_pull_through_cache_rule(types::UpdatePullThroughCacheRuleRequest) -> types::UpdatePullThroughCacheRuleResponse;
        update_repository_creation_template(types::UpdateRepositoryCreationTemplateRequest) -> types::UpdateRepositoryCreationTemplateResponse;
        upload_layer_part(types::UploadLayerPartRequest) -> types::UploadLayerPartResponse;
        validate_pull_through_cache_rule(types::ValidatePullThroughCacheRuleRequest) -> types::ValidatePullThroughCacheRuleResponse;
    }
}

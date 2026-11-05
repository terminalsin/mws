//! Wires the generated `Handler` trait to the synchronous operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::EcrPublic;

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
                let result = EcrPublic::$name(self, ctx, input);
                Box::pin(async move { result })
            }
        )*
    };
}

impl Handler for EcrPublic {
    delegate! {
        batch_check_layer_availability(types::BatchCheckLayerAvailabilityRequest) -> types::BatchCheckLayerAvailabilityResponse;
        batch_delete_image(types::BatchDeleteImageRequest) -> types::BatchDeleteImageResponse;
        complete_layer_upload(types::CompleteLayerUploadRequest) -> types::CompleteLayerUploadResponse;
        create_repository(types::CreateRepositoryRequest) -> types::CreateRepositoryResponse;
        delete_repository(types::DeleteRepositoryRequest) -> types::DeleteRepositoryResponse;
        delete_repository_policy(types::DeleteRepositoryPolicyRequest) -> types::DeleteRepositoryPolicyResponse;
        describe_image_tags(types::DescribeImageTagsRequest) -> types::DescribeImageTagsResponse;
        describe_images(types::DescribeImagesRequest) -> types::DescribeImagesResponse;
        describe_registries(types::DescribeRegistriesRequest) -> types::DescribeRegistriesResponse;
        describe_repositories(types::DescribeRepositoriesRequest) -> types::DescribeRepositoriesResponse;
        get_authorization_token(types::GetAuthorizationTokenRequest) -> types::GetAuthorizationTokenResponse;
        get_registry_catalog_data(types::GetRegistryCatalogDataRequest) -> types::GetRegistryCatalogDataResponse;
        get_repository_catalog_data(types::GetRepositoryCatalogDataRequest) -> types::GetRepositoryCatalogDataResponse;
        get_repository_policy(types::GetRepositoryPolicyRequest) -> types::GetRepositoryPolicyResponse;
        initiate_layer_upload(types::InitiateLayerUploadRequest) -> types::InitiateLayerUploadResponse;
        list_tags_for_resource(types::ListTagsForResourceRequest) -> types::ListTagsForResourceResponse;
        put_image(types::PutImageRequest) -> types::PutImageResponse;
        put_registry_catalog_data(types::PutRegistryCatalogDataRequest) -> types::PutRegistryCatalogDataResponse;
        put_repository_catalog_data(types::PutRepositoryCatalogDataRequest) -> types::PutRepositoryCatalogDataResponse;
        set_repository_policy(types::SetRepositoryPolicyRequest) -> types::SetRepositoryPolicyResponse;
        tag_resource(types::TagResourceRequest) -> types::TagResourceResponse;
        untag_resource(types::UntagResourceRequest) -> types::UntagResourceResponse;
        upload_layer_part(types::UploadLayerPartRequest) -> types::UploadLayerPartResponse;
    }
}

//! Wires the generated `Handler` trait to the operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::S3Control;

#[async_trait::async_trait]
impl Handler for S3Control {
    async fn create_access_point(
        &self,
        ctx: &RequestContext,
        input: types::CreateAccessPointRequest,
    ) -> Result<types::CreateAccessPointResult, ServiceError> {
        S3Control::create_access_point(self, ctx, input)
    }
    async fn create_access_point_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::CreateAccessPointForObjectLambdaRequest,
    ) -> Result<types::CreateAccessPointForObjectLambdaResult, ServiceError> {
        S3Control::create_access_point_for_object_lambda(self, ctx, input)
    }
    async fn delete_access_point(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessPointRequest,
    ) -> Result<(), ServiceError> {
        S3Control::delete_access_point(self, ctx, input)
    }
    async fn delete_access_point_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessPointForObjectLambdaRequest,
    ) -> Result<(), ServiceError> {
        S3Control::delete_access_point_for_object_lambda(self, ctx, input)
    }
    async fn delete_access_point_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessPointPolicyRequest,
    ) -> Result<(), ServiceError> {
        S3Control::delete_access_point_policy(self, ctx, input)
    }
    async fn delete_access_point_policy_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAccessPointPolicyForObjectLambdaRequest,
    ) -> Result<(), ServiceError> {
        S3Control::delete_access_point_policy_for_object_lambda(self, ctx, input)
    }
    async fn delete_public_access_block(
        &self,
        ctx: &RequestContext,
        input: types::DeletePublicAccessBlockRequest,
    ) -> Result<(), ServiceError> {
        S3Control::delete_public_access_block(self, ctx, input)
    }
    async fn get_access_point(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessPointRequest,
    ) -> Result<types::GetAccessPointResult, ServiceError> {
        S3Control::get_access_point(self, ctx, input)
    }
    async fn get_access_point_configuration_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessPointConfigurationForObjectLambdaRequest,
    ) -> Result<types::GetAccessPointConfigurationForObjectLambdaResult, ServiceError> {
        S3Control::get_access_point_configuration_for_object_lambda(self, ctx, input)
    }
    async fn get_access_point_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessPointForObjectLambdaRequest,
    ) -> Result<types::GetAccessPointForObjectLambdaResult, ServiceError> {
        S3Control::get_access_point_for_object_lambda(self, ctx, input)
    }
    async fn get_access_point_policy(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessPointPolicyRequest,
    ) -> Result<types::GetAccessPointPolicyResult, ServiceError> {
        S3Control::get_access_point_policy(self, ctx, input)
    }
    async fn get_access_point_policy_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessPointPolicyForObjectLambdaRequest,
    ) -> Result<types::GetAccessPointPolicyForObjectLambdaResult, ServiceError> {
        S3Control::get_access_point_policy_for_object_lambda(self, ctx, input)
    }
    async fn get_access_point_policy_status(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessPointPolicyStatusRequest,
    ) -> Result<types::GetAccessPointPolicyStatusResult, ServiceError> {
        S3Control::get_access_point_policy_status(self, ctx, input)
    }
    async fn get_access_point_policy_status_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::GetAccessPointPolicyStatusForObjectLambdaRequest,
    ) -> Result<types::GetAccessPointPolicyStatusForObjectLambdaResult, ServiceError> {
        S3Control::get_access_point_policy_status_for_object_lambda(self, ctx, input)
    }
    async fn get_public_access_block(
        &self,
        ctx: &RequestContext,
        input: types::GetPublicAccessBlockRequest,
    ) -> Result<types::GetPublicAccessBlockOutput, ServiceError> {
        S3Control::get_public_access_block(self, ctx, input)
    }
    async fn list_access_points(
        &self,
        ctx: &RequestContext,
        input: types::ListAccessPointsRequest,
    ) -> Result<types::ListAccessPointsResult, ServiceError> {
        S3Control::list_access_points(self, ctx, input)
    }
    async fn list_access_points_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::ListAccessPointsForObjectLambdaRequest,
    ) -> Result<types::ListAccessPointsForObjectLambdaResult, ServiceError> {
        S3Control::list_access_points_for_object_lambda(self, ctx, input)
    }
    async fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResult, ServiceError> {
        S3Control::list_tags_for_resource(self, ctx, input)
    }
    async fn put_access_point_configuration_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::PutAccessPointConfigurationForObjectLambdaRequest,
    ) -> Result<(), ServiceError> {
        S3Control::put_access_point_configuration_for_object_lambda(self, ctx, input)
    }
    async fn put_access_point_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutAccessPointPolicyRequest,
    ) -> Result<(), ServiceError> {
        S3Control::put_access_point_policy(self, ctx, input)
    }
    async fn put_access_point_policy_for_object_lambda(
        &self,
        ctx: &RequestContext,
        input: types::PutAccessPointPolicyForObjectLambdaRequest,
    ) -> Result<(), ServiceError> {
        S3Control::put_access_point_policy_for_object_lambda(self, ctx, input)
    }
    async fn put_public_access_block(
        &self,
        ctx: &RequestContext,
        input: types::PutPublicAccessBlockRequest,
    ) -> Result<(), ServiceError> {
        S3Control::put_public_access_block(self, ctx, input)
    }
    async fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<types::TagResourceResult, ServiceError> {
        S3Control::tag_resource(self, ctx, input)
    }
    async fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<types::UntagResourceResult, ServiceError> {
        S3Control::untag_resource(self, ctx, input)
    }
}

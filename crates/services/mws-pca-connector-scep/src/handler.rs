//! The generated `Handler`, forwarding to the operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::ScepConnector;

#[async_trait::async_trait]
impl Handler for ScepConnector {
    async fn create_challenge(&self, ctx: &RequestContext, input: types::CreateChallengeRequest) -> Result<types::CreateChallengeResponse, ServiceError> {
        self.create_challenge(ctx, input)
    }

    async fn create_connector(&self, ctx: &RequestContext, input: types::CreateConnectorRequest) -> Result<types::CreateConnectorResponse, ServiceError> {
        self.create_connector(ctx, input)
    }

    async fn delete_challenge(&self, ctx: &RequestContext, input: types::DeleteChallengeRequest) -> Result<(), ServiceError> {
        self.delete_challenge(ctx, input)
    }

    async fn delete_connector(&self, ctx: &RequestContext, input: types::DeleteConnectorRequest) -> Result<(), ServiceError> {
        self.delete_connector(ctx, input)
    }

    async fn get_challenge_metadata(&self, ctx: &RequestContext, input: types::GetChallengeMetadataRequest) -> Result<types::GetChallengeMetadataResponse, ServiceError> {
        self.get_challenge_metadata(ctx, input)
    }

    async fn get_challenge_password(&self, ctx: &RequestContext, input: types::GetChallengePasswordRequest) -> Result<types::GetChallengePasswordResponse, ServiceError> {
        self.get_challenge_password(ctx, input)
    }

    async fn get_connector(&self, ctx: &RequestContext, input: types::GetConnectorRequest) -> Result<types::GetConnectorResponse, ServiceError> {
        self.get_connector(ctx, input)
    }

    async fn list_challenge_metadata(&self, ctx: &RequestContext, input: types::ListChallengeMetadataRequest) -> Result<types::ListChallengeMetadataResponse, ServiceError> {
        self.list_challenge_metadata(ctx, input)
    }

    async fn list_connectors(&self, ctx: &RequestContext, input: types::ListConnectorsRequest) -> Result<types::ListConnectorsResponse, ServiceError> {
        self.list_connectors(ctx, input)
    }

    async fn list_tags_for_resource(&self, ctx: &RequestContext, input: types::ListTagsForResourceRequest) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        self.list_tags_for_resource(ctx, input)
    }

    async fn tag_resource(&self, ctx: &RequestContext, input: types::TagResourceRequest) -> Result<(), ServiceError> {
        self.tag_resource(ctx, input)
    }

    async fn untag_resource(&self, ctx: &RequestContext, input: types::UntagResourceRequest) -> Result<(), ServiceError> {
        self.untag_resource(ctx, input)
    }

}

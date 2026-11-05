//! Wires the generated `Handler` trait to the operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::Amplify;

#[async_trait::async_trait]
impl Handler for Amplify {
    async fn create_app(
        &self,
        ctx: &RequestContext,
        input: types::CreateAppRequest,
    ) -> Result<types::CreateAppResult, ServiceError> {
        Amplify::create_app(self, ctx, input).await
    }
    async fn create_backend_environment(
        &self,
        ctx: &RequestContext,
        input: types::CreateBackendEnvironmentRequest,
    ) -> Result<types::CreateBackendEnvironmentResult, ServiceError> {
        Amplify::create_backend_environment(self, ctx, input).await
    }
    async fn create_branch(
        &self,
        ctx: &RequestContext,
        input: types::CreateBranchRequest,
    ) -> Result<types::CreateBranchResult, ServiceError> {
        Amplify::create_branch(self, ctx, input).await
    }
    async fn create_deployment(
        &self,
        ctx: &RequestContext,
        input: types::CreateDeploymentRequest,
    ) -> Result<types::CreateDeploymentResult, ServiceError> {
        Amplify::create_deployment(self, ctx, input).await
    }
    async fn create_domain_association(
        &self,
        ctx: &RequestContext,
        input: types::CreateDomainAssociationRequest,
    ) -> Result<types::CreateDomainAssociationResult, ServiceError> {
        Amplify::create_domain_association(self, ctx, input).await
    }
    async fn create_webhook(
        &self,
        ctx: &RequestContext,
        input: types::CreateWebhookRequest,
    ) -> Result<types::CreateWebhookResult, ServiceError> {
        Amplify::create_webhook(self, ctx, input).await
    }
    async fn delete_app(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAppRequest,
    ) -> Result<types::DeleteAppResult, ServiceError> {
        Amplify::delete_app(self, ctx, input).await
    }
    async fn delete_backend_environment(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBackendEnvironmentRequest,
    ) -> Result<types::DeleteBackendEnvironmentResult, ServiceError> {
        Amplify::delete_backend_environment(self, ctx, input).await
    }
    async fn delete_branch(
        &self,
        ctx: &RequestContext,
        input: types::DeleteBranchRequest,
    ) -> Result<types::DeleteBranchResult, ServiceError> {
        Amplify::delete_branch(self, ctx, input).await
    }
    async fn delete_domain_association(
        &self,
        ctx: &RequestContext,
        input: types::DeleteDomainAssociationRequest,
    ) -> Result<types::DeleteDomainAssociationResult, ServiceError> {
        Amplify::delete_domain_association(self, ctx, input).await
    }
    async fn delete_job(
        &self,
        ctx: &RequestContext,
        input: types::DeleteJobRequest,
    ) -> Result<types::DeleteJobResult, ServiceError> {
        Amplify::delete_job(self, ctx, input).await
    }
    async fn delete_webhook(
        &self,
        ctx: &RequestContext,
        input: types::DeleteWebhookRequest,
    ) -> Result<types::DeleteWebhookResult, ServiceError> {
        Amplify::delete_webhook(self, ctx, input).await
    }
    async fn generate_access_logs(
        &self,
        ctx: &RequestContext,
        input: types::GenerateAccessLogsRequest,
    ) -> Result<types::GenerateAccessLogsResult, ServiceError> {
        Amplify::generate_access_logs(self, ctx, input).await
    }
    async fn get_app(
        &self,
        ctx: &RequestContext,
        input: types::GetAppRequest,
    ) -> Result<types::GetAppResult, ServiceError> {
        Amplify::get_app(self, ctx, input).await
    }
    async fn get_artifact_url(
        &self,
        ctx: &RequestContext,
        input: types::GetArtifactUrlRequest,
    ) -> Result<types::GetArtifactUrlResult, ServiceError> {
        Amplify::get_artifact_url(self, ctx, input).await
    }
    async fn get_backend_environment(
        &self,
        ctx: &RequestContext,
        input: types::GetBackendEnvironmentRequest,
    ) -> Result<types::GetBackendEnvironmentResult, ServiceError> {
        Amplify::get_backend_environment(self, ctx, input).await
    }
    async fn get_branch(
        &self,
        ctx: &RequestContext,
        input: types::GetBranchRequest,
    ) -> Result<types::GetBranchResult, ServiceError> {
        Amplify::get_branch(self, ctx, input).await
    }
    async fn get_domain_association(
        &self,
        ctx: &RequestContext,
        input: types::GetDomainAssociationRequest,
    ) -> Result<types::GetDomainAssociationResult, ServiceError> {
        Amplify::get_domain_association(self, ctx, input).await
    }
    async fn get_job(
        &self,
        ctx: &RequestContext,
        input: types::GetJobRequest,
    ) -> Result<types::GetJobResult, ServiceError> {
        Amplify::get_job(self, ctx, input).await
    }
    async fn get_webhook(
        &self,
        ctx: &RequestContext,
        input: types::GetWebhookRequest,
    ) -> Result<types::GetWebhookResult, ServiceError> {
        Amplify::get_webhook(self, ctx, input).await
    }
    async fn list_apps(
        &self,
        ctx: &RequestContext,
        input: types::ListAppsRequest,
    ) -> Result<types::ListAppsResult, ServiceError> {
        Amplify::list_apps(self, ctx, input).await
    }
    async fn list_artifacts(
        &self,
        ctx: &RequestContext,
        input: types::ListArtifactsRequest,
    ) -> Result<types::ListArtifactsResult, ServiceError> {
        Amplify::list_artifacts(self, ctx, input).await
    }
    async fn list_backend_environments(
        &self,
        ctx: &RequestContext,
        input: types::ListBackendEnvironmentsRequest,
    ) -> Result<types::ListBackendEnvironmentsResult, ServiceError> {
        Amplify::list_backend_environments(self, ctx, input).await
    }
    async fn list_branches(
        &self,
        ctx: &RequestContext,
        input: types::ListBranchesRequest,
    ) -> Result<types::ListBranchesResult, ServiceError> {
        Amplify::list_branches(self, ctx, input).await
    }
    async fn list_domain_associations(
        &self,
        ctx: &RequestContext,
        input: types::ListDomainAssociationsRequest,
    ) -> Result<types::ListDomainAssociationsResult, ServiceError> {
        Amplify::list_domain_associations(self, ctx, input).await
    }
    async fn list_jobs(
        &self,
        ctx: &RequestContext,
        input: types::ListJobsRequest,
    ) -> Result<types::ListJobsResult, ServiceError> {
        Amplify::list_jobs(self, ctx, input).await
    }
    async fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        Amplify::list_tags_for_resource(self, ctx, input).await
    }
    async fn list_webhooks(
        &self,
        ctx: &RequestContext,
        input: types::ListWebhooksRequest,
    ) -> Result<types::ListWebhooksResult, ServiceError> {
        Amplify::list_webhooks(self, ctx, input).await
    }
    async fn start_deployment(
        &self,
        ctx: &RequestContext,
        input: types::StartDeploymentRequest,
    ) -> Result<types::StartDeploymentResult, ServiceError> {
        Amplify::start_deployment(self, ctx, input).await
    }
    async fn start_job(
        &self,
        ctx: &RequestContext,
        input: types::StartJobRequest,
    ) -> Result<types::StartJobResult, ServiceError> {
        Amplify::start_job(self, ctx, input).await
    }
    async fn stop_job(
        &self,
        ctx: &RequestContext,
        input: types::StopJobRequest,
    ) -> Result<types::StopJobResult, ServiceError> {
        Amplify::stop_job(self, ctx, input).await
    }
    async fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<types::TagResourceResponse, ServiceError> {
        Amplify::tag_resource(self, ctx, input).await
    }
    async fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<types::UntagResourceResponse, ServiceError> {
        Amplify::untag_resource(self, ctx, input).await
    }
    async fn update_app(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAppRequest,
    ) -> Result<types::UpdateAppResult, ServiceError> {
        Amplify::update_app(self, ctx, input).await
    }
    async fn update_branch(
        &self,
        ctx: &RequestContext,
        input: types::UpdateBranchRequest,
    ) -> Result<types::UpdateBranchResult, ServiceError> {
        Amplify::update_branch(self, ctx, input).await
    }
    async fn update_domain_association(
        &self,
        ctx: &RequestContext,
        input: types::UpdateDomainAssociationRequest,
    ) -> Result<types::UpdateDomainAssociationResult, ServiceError> {
        Amplify::update_domain_association(self, ctx, input).await
    }
    async fn update_webhook(
        &self,
        ctx: &RequestContext,
        input: types::UpdateWebhookRequest,
    ) -> Result<types::UpdateWebhookResult, ServiceError> {
        Amplify::update_webhook(self, ctx, input).await
    }
}

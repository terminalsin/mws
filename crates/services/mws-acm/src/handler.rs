//! Wires the generated `Handler` trait to the operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::Acm;

#[async_trait::async_trait]
impl Handler for Acm {
    async fn add_tags_to_certificate(
        &self,
        ctx: &RequestContext,
        input: types::AddTagsToCertificateRequest,
    ) -> Result<(), ServiceError> {
        Acm::add_tags_to_certificate(self, ctx, input)
    }
    async fn create_acme_domain_validation(
        &self,
        ctx: &RequestContext,
        input: types::CreateAcmeDomainValidationRequest,
    ) -> Result<types::CreateAcmeDomainValidationResponse, ServiceError> {
        Acm::create_acme_domain_validation(self, ctx, input).await
    }
    async fn create_acme_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::CreateAcmeEndpointRequest,
    ) -> Result<types::CreateAcmeEndpointResponse, ServiceError> {
        Acm::create_acme_endpoint(self, ctx, input)
    }
    async fn create_acme_external_account_binding(
        &self,
        ctx: &RequestContext,
        input: types::CreateAcmeExternalAccountBindingRequest,
    ) -> Result<types::CreateAcmeExternalAccountBindingResponse, ServiceError> {
        Acm::create_acme_external_account_binding(self, ctx, input)
    }
    async fn delete_acme_domain_validation(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAcmeDomainValidationRequest,
    ) -> Result<(), ServiceError> {
        Acm::delete_acme_domain_validation(self, ctx, input)
    }
    async fn delete_acme_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAcmeEndpointRequest,
    ) -> Result<(), ServiceError> {
        Acm::delete_acme_endpoint(self, ctx, input)
    }
    async fn delete_acme_external_account_binding(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAcmeExternalAccountBindingRequest,
    ) -> Result<(), ServiceError> {
        Acm::delete_acme_external_account_binding(self, ctx, input)
    }
    async fn delete_certificate(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCertificateRequest,
    ) -> Result<(), ServiceError> {
        Acm::delete_certificate(self, ctx, input)
    }
    async fn describe_acme_account(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAcmeAccountRequest,
    ) -> Result<types::DescribeAcmeAccountResponse, ServiceError> {
        Acm::describe_acme_account(self, ctx, input)
    }
    async fn describe_acme_domain_validation(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAcmeDomainValidationRequest,
    ) -> Result<types::DescribeAcmeDomainValidationResponse, ServiceError> {
        Acm::describe_acme_domain_validation(self, ctx, input)
    }
    async fn describe_acme_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAcmeEndpointRequest,
    ) -> Result<types::DescribeAcmeEndpointResponse, ServiceError> {
        Acm::describe_acme_endpoint(self, ctx, input)
    }
    async fn describe_acme_external_account_binding(
        &self,
        ctx: &RequestContext,
        input: types::DescribeAcmeExternalAccountBindingRequest,
    ) -> Result<types::DescribeAcmeExternalAccountBindingResponse, ServiceError> {
        Acm::describe_acme_external_account_binding(self, ctx, input)
    }
    async fn describe_certificate(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCertificateRequest,
    ) -> Result<types::DescribeCertificateResponse, ServiceError> {
        Acm::describe_certificate(self, ctx, input)
    }
    async fn export_certificate(
        &self,
        ctx: &RequestContext,
        input: types::ExportCertificateRequest,
    ) -> Result<types::ExportCertificateResponse, ServiceError> {
        Acm::export_certificate(self, ctx, input)
    }
    async fn get_account_configuration(
        &self,
        ctx: &RequestContext,
        _input: (),
    ) -> Result<types::GetAccountConfigurationResponse, ServiceError> {
        Acm::get_account_configuration(self, ctx)
    }
    async fn get_acme_external_account_binding_credentials(
        &self,
        ctx: &RequestContext,
        input: types::GetAcmeExternalAccountBindingCredentialsRequest,
    ) -> Result<types::GetAcmeExternalAccountBindingCredentialsResponse, ServiceError> {
        Acm::get_acme_external_account_binding_credentials(self, ctx, input)
    }
    async fn get_certificate(
        &self,
        ctx: &RequestContext,
        input: types::GetCertificateRequest,
    ) -> Result<types::GetCertificateResponse, ServiceError> {
        Acm::get_certificate(self, ctx, input)
    }
    async fn import_certificate(
        &self,
        ctx: &RequestContext,
        input: types::ImportCertificateRequest,
    ) -> Result<types::ImportCertificateResponse, ServiceError> {
        Acm::import_certificate(self, ctx, input)
    }
    async fn list_acme_accounts(
        &self,
        ctx: &RequestContext,
        input: types::ListAcmeAccountsRequest,
    ) -> Result<types::ListAcmeAccountsResponse, ServiceError> {
        Acm::list_acme_accounts(self, ctx, input)
    }
    async fn list_acme_domain_validations(
        &self,
        ctx: &RequestContext,
        input: types::ListAcmeDomainValidationsRequest,
    ) -> Result<types::ListAcmeDomainValidationsResponse, ServiceError> {
        Acm::list_acme_domain_validations(self, ctx, input)
    }
    async fn list_acme_endpoints(
        &self,
        ctx: &RequestContext,
        input: types::ListAcmeEndpointsRequest,
    ) -> Result<types::ListAcmeEndpointsResponse, ServiceError> {
        Acm::list_acme_endpoints(self, ctx, input)
    }
    async fn list_acme_external_account_bindings(
        &self,
        ctx: &RequestContext,
        input: types::ListAcmeExternalAccountBindingsRequest,
    ) -> Result<types::ListAcmeExternalAccountBindingsResponse, ServiceError> {
        Acm::list_acme_external_account_bindings(self, ctx, input)
    }
    async fn list_certificate_domain_validations(
        &self,
        ctx: &RequestContext,
        input: types::ListCertificateDomainValidationsRequest,
    ) -> Result<types::ListCertificateDomainValidationsResponse, ServiceError> {
        Acm::list_certificate_domain_validations(self, ctx, input)
    }
    async fn list_certificates(
        &self,
        ctx: &RequestContext,
        input: types::ListCertificatesRequest,
    ) -> Result<types::ListCertificatesResponse, ServiceError> {
        Acm::list_certificates(self, ctx, input)
    }
    async fn list_tags_for_certificate(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForCertificateRequest,
    ) -> Result<types::ListTagsForCertificateResponse, ServiceError> {
        Acm::list_tags_for_certificate(self, ctx, input)
    }
    async fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        Acm::list_tags_for_resource(self, ctx, input)
    }
    async fn put_account_configuration(
        &self,
        ctx: &RequestContext,
        input: types::PutAccountConfigurationRequest,
    ) -> Result<(), ServiceError> {
        Acm::put_account_configuration(self, ctx, input)
    }
    async fn remove_tags_from_certificate(
        &self,
        ctx: &RequestContext,
        input: types::RemoveTagsFromCertificateRequest,
    ) -> Result<(), ServiceError> {
        Acm::remove_tags_from_certificate(self, ctx, input)
    }
    async fn renew_certificate(
        &self,
        ctx: &RequestContext,
        input: types::RenewCertificateRequest,
    ) -> Result<(), ServiceError> {
        Acm::renew_certificate(self, ctx, input)
    }
    async fn request_certificate(
        &self,
        ctx: &RequestContext,
        input: types::RequestCertificateRequest,
    ) -> Result<types::RequestCertificateResponse, ServiceError> {
        Acm::request_certificate(self, ctx, input).await
    }
    async fn resend_validation_email(
        &self,
        ctx: &RequestContext,
        input: types::ResendValidationEmailRequest,
    ) -> Result<(), ServiceError> {
        Acm::resend_validation_email(self, ctx, input)
    }
    async fn revoke_acme_account(
        &self,
        ctx: &RequestContext,
        input: types::RevokeAcmeAccountRequest,
    ) -> Result<(), ServiceError> {
        Acm::revoke_acme_account(self, ctx, input)
    }
    async fn revoke_acme_external_account_binding(
        &self,
        ctx: &RequestContext,
        input: types::RevokeAcmeExternalAccountBindingRequest,
    ) -> Result<(), ServiceError> {
        Acm::revoke_acme_external_account_binding(self, ctx, input)
    }
    async fn revoke_certificate(
        &self,
        ctx: &RequestContext,
        input: types::RevokeCertificateRequest,
    ) -> Result<types::RevokeCertificateResponse, ServiceError> {
        Acm::revoke_certificate(self, ctx, input)
    }
    async fn search_certificates(
        &self,
        ctx: &RequestContext,
        input: types::SearchCertificatesRequest,
    ) -> Result<types::SearchCertificatesResponse, ServiceError> {
        Acm::search_certificates(self, ctx, input)
    }
    async fn tag_resource(&self, ctx: &RequestContext, input: types::TagResourceRequest) -> Result<(), ServiceError> {
        Acm::tag_resource(self, ctx, input)
    }
    async fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<(), ServiceError> {
        Acm::untag_resource(self, ctx, input)
    }
    async fn update_acme_domain_validation(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAcmeDomainValidationRequest,
    ) -> Result<(), ServiceError> {
        Acm::update_acme_domain_validation(self, ctx, input).await
    }
    async fn update_acme_endpoint(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAcmeEndpointRequest,
    ) -> Result<(), ServiceError> {
        Acm::update_acme_endpoint(self, ctx, input)
    }
    async fn update_certificate_options(
        &self,
        ctx: &RequestContext,
        input: types::UpdateCertificateOptionsRequest,
    ) -> Result<(), ServiceError> {
        Acm::update_certificate_options(self, ctx, input)
    }
}

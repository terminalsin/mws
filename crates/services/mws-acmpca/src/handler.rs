//! Wires the generated `Handler` trait to the synchronous operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::PrivateCa;

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
                let result = PrivateCa::$name(self, ctx, input);
                Box::pin(async move { result })
            }
        )*
    };
}

impl Handler for PrivateCa {
    delegate! {
        create_certificate_authority(types::CreateCertificateAuthorityRequest) -> types::CreateCertificateAuthorityResponse;
        describe_certificate_authority(types::DescribeCertificateAuthorityRequest) -> types::DescribeCertificateAuthorityResponse;
        list_certificate_authorities(types::ListCertificateAuthoritiesRequest) -> types::ListCertificateAuthoritiesResponse;
        get_certificate_authority_csr(types::GetCertificateAuthorityCsrRequest) -> types::GetCertificateAuthorityCsrResponse;
        get_certificate_authority_certificate(types::GetCertificateAuthorityCertificateRequest) -> types::GetCertificateAuthorityCertificateResponse;
        import_certificate_authority_certificate(types::ImportCertificateAuthorityCertificateRequest) -> ();
        issue_certificate(types::IssueCertificateRequest) -> types::IssueCertificateResponse;
        get_certificate(types::GetCertificateRequest) -> types::GetCertificateResponse;
        revoke_certificate(types::RevokeCertificateRequest) -> ();
        update_certificate_authority(types::UpdateCertificateAuthorityRequest) -> ();
        delete_certificate_authority(types::DeleteCertificateAuthorityRequest) -> ();
        restore_certificate_authority(types::RestoreCertificateAuthorityRequest) -> ();
        tag_certificate_authority(types::TagCertificateAuthorityRequest) -> ();
        untag_certificate_authority(types::UntagCertificateAuthorityRequest) -> ();
        list_tags(types::ListTagsRequest) -> types::ListTagsResponse;
        create_permission(types::CreatePermissionRequest) -> ();
        delete_permission(types::DeletePermissionRequest) -> ();
        list_permissions(types::ListPermissionsRequest) -> types::ListPermissionsResponse;
        put_policy(types::PutPolicyRequest) -> ();
        get_policy(types::GetPolicyRequest) -> types::GetPolicyResponse;
        delete_policy(types::DeletePolicyRequest) -> ();
        create_certificate_authority_audit_report(types::CreateCertificateAuthorityAuditReportRequest) -> types::CreateCertificateAuthorityAuditReportResponse;
        describe_certificate_authority_audit_report(types::DescribeCertificateAuthorityAuditReportRequest) -> types::DescribeCertificateAuthorityAuditReportResponse;
    }
}

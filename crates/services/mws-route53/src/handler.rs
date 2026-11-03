//! Wires the generated `Handler` trait to the synchronous operation
//! implementations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::Route53;

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
                let result = Route53::$name(self, ctx, input);
                Box::pin(async move { result })
            }
        )*
    };
}

impl Handler for Route53 {
    delegate! {
        create_hosted_zone(types::CreateHostedZoneRequest) -> types::CreateHostedZoneResponse;
        get_hosted_zone(types::GetHostedZoneRequest) -> types::GetHostedZoneResponse;
        get_hosted_zone_count(types::GetHostedZoneCountRequest) -> types::GetHostedZoneCountResponse;
        list_hosted_zones(types::ListHostedZonesRequest) -> types::ListHostedZonesResponse;
        list_hosted_zones_by_name(types::ListHostedZonesByNameRequest) -> types::ListHostedZonesByNameResponse;
        list_hosted_zones_by_vpc(types::ListHostedZonesByVPCRequest) -> types::ListHostedZonesByVPCResponse;
        update_hosted_zone_comment(types::UpdateHostedZoneCommentRequest) -> types::UpdateHostedZoneCommentResponse;
        delete_hosted_zone(types::DeleteHostedZoneRequest) -> types::DeleteHostedZoneResponse;
        associate_vpc_with_hosted_zone(types::AssociateVPCWithHostedZoneRequest) -> types::AssociateVPCWithHostedZoneResponse;
        disassociate_vpc_from_hosted_zone(types::DisassociateVPCFromHostedZoneRequest) -> types::DisassociateVPCFromHostedZoneResponse;
        get_change(types::GetChangeRequest) -> types::GetChangeResponse;
        change_resource_record_sets(types::ChangeResourceRecordSetsRequest) -> types::ChangeResourceRecordSetsResponse;
        list_resource_record_sets(types::ListResourceRecordSetsRequest) -> types::ListResourceRecordSetsResponse;
        create_health_check(types::CreateHealthCheckRequest) -> types::CreateHealthCheckResponse;
        get_health_check(types::GetHealthCheckRequest) -> types::GetHealthCheckResponse;
        get_health_check_count(types::GetHealthCheckCountRequest) -> types::GetHealthCheckCountResponse;
        list_health_checks(types::ListHealthChecksRequest) -> types::ListHealthChecksResponse;
        update_health_check(types::UpdateHealthCheckRequest) -> types::UpdateHealthCheckResponse;
        delete_health_check(types::DeleteHealthCheckRequest) -> types::DeleteHealthCheckResponse;
        change_tags_for_resource(types::ChangeTagsForResourceRequest) -> types::ChangeTagsForResourceResponse;
        list_tags_for_resource(types::ListTagsForResourceRequest) -> types::ListTagsForResourceResponse;
        list_tags_for_resources(types::ListTagsForResourcesRequest) -> types::ListTagsForResourcesResponse;
    }
}

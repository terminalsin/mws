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
        activate_key_signing_key(types::ActivateKeySigningKeyRequest) -> types::ActivateKeySigningKeyResponse;
        change_cidr_collection(types::ChangeCidrCollectionRequest) -> types::ChangeCidrCollectionResponse;
        create_cidr_collection(types::CreateCidrCollectionRequest) -> types::CreateCidrCollectionResponse;
        create_key_signing_key(types::CreateKeySigningKeyRequest) -> types::CreateKeySigningKeyResponse;
        create_query_logging_config(types::CreateQueryLoggingConfigRequest) -> types::CreateQueryLoggingConfigResponse;
        create_reusable_delegation_set(types::CreateReusableDelegationSetRequest) -> types::CreateReusableDelegationSetResponse;
        create_traffic_policy(types::CreateTrafficPolicyRequest) -> types::CreateTrafficPolicyResponse;
        create_traffic_policy_instance(types::CreateTrafficPolicyInstanceRequest) -> types::CreateTrafficPolicyInstanceResponse;
        create_traffic_policy_version(types::CreateTrafficPolicyVersionRequest) -> types::CreateTrafficPolicyVersionResponse;
        create_vpc_association_authorization(types::CreateVPCAssociationAuthorizationRequest) -> types::CreateVPCAssociationAuthorizationResponse;
        deactivate_key_signing_key(types::DeactivateKeySigningKeyRequest) -> types::DeactivateKeySigningKeyResponse;
        delete_cidr_collection(types::DeleteCidrCollectionRequest) -> types::DeleteCidrCollectionResponse;
        delete_key_signing_key(types::DeleteKeySigningKeyRequest) -> types::DeleteKeySigningKeyResponse;
        delete_query_logging_config(types::DeleteQueryLoggingConfigRequest) -> types::DeleteQueryLoggingConfigResponse;
        delete_reusable_delegation_set(types::DeleteReusableDelegationSetRequest) -> types::DeleteReusableDelegationSetResponse;
        delete_traffic_policy(types::DeleteTrafficPolicyRequest) -> types::DeleteTrafficPolicyResponse;
        delete_traffic_policy_instance(types::DeleteTrafficPolicyInstanceRequest) -> types::DeleteTrafficPolicyInstanceResponse;
        delete_vpc_association_authorization(types::DeleteVPCAssociationAuthorizationRequest) -> types::DeleteVPCAssociationAuthorizationResponse;
        disable_hosted_zone_dnssec(types::DisableHostedZoneDNSSECRequest) -> types::DisableHostedZoneDNSSECResponse;
        enable_hosted_zone_dnssec(types::EnableHostedZoneDNSSECRequest) -> types::EnableHostedZoneDNSSECResponse;
        get_account_limit(types::GetAccountLimitRequest) -> types::GetAccountLimitResponse;
        get_checker_ip_ranges(types::GetCheckerIpRangesRequest) -> types::GetCheckerIpRangesResponse;
        get_dnssec(types::GetDNSSECRequest) -> types::GetDNSSECResponse;
        get_geo_location(types::GetGeoLocationRequest) -> types::GetGeoLocationResponse;
        get_health_check_last_failure_reason(types::GetHealthCheckLastFailureReasonRequest) -> types::GetHealthCheckLastFailureReasonResponse;
        get_health_check_status(types::GetHealthCheckStatusRequest) -> types::GetHealthCheckStatusResponse;
        get_hosted_zone_limit(types::GetHostedZoneLimitRequest) -> types::GetHostedZoneLimitResponse;
        get_query_logging_config(types::GetQueryLoggingConfigRequest) -> types::GetQueryLoggingConfigResponse;
        get_reusable_delegation_set(types::GetReusableDelegationSetRequest) -> types::GetReusableDelegationSetResponse;
        get_reusable_delegation_set_limit(types::GetReusableDelegationSetLimitRequest) -> types::GetReusableDelegationSetLimitResponse;
        get_traffic_policy(types::GetTrafficPolicyRequest) -> types::GetTrafficPolicyResponse;
        get_traffic_policy_instance(types::GetTrafficPolicyInstanceRequest) -> types::GetTrafficPolicyInstanceResponse;
        get_traffic_policy_instance_count(types::GetTrafficPolicyInstanceCountRequest) -> types::GetTrafficPolicyInstanceCountResponse;
        list_cidr_blocks(types::ListCidrBlocksRequest) -> types::ListCidrBlocksResponse;
        list_cidr_collections(types::ListCidrCollectionsRequest) -> types::ListCidrCollectionsResponse;
        list_cidr_locations(types::ListCidrLocationsRequest) -> types::ListCidrLocationsResponse;
        list_geo_locations(types::ListGeoLocationsRequest) -> types::ListGeoLocationsResponse;
        list_query_logging_configs(types::ListQueryLoggingConfigsRequest) -> types::ListQueryLoggingConfigsResponse;
        list_reusable_delegation_sets(types::ListReusableDelegationSetsRequest) -> types::ListReusableDelegationSetsResponse;
        list_traffic_policies(types::ListTrafficPoliciesRequest) -> types::ListTrafficPoliciesResponse;
        list_traffic_policy_instances(types::ListTrafficPolicyInstancesRequest) -> types::ListTrafficPolicyInstancesResponse;
        list_traffic_policy_instances_by_hosted_zone(types::ListTrafficPolicyInstancesByHostedZoneRequest) -> types::ListTrafficPolicyInstancesByHostedZoneResponse;
        list_traffic_policy_instances_by_policy(types::ListTrafficPolicyInstancesByPolicyRequest) -> types::ListTrafficPolicyInstancesByPolicyResponse;
        list_traffic_policy_versions(types::ListTrafficPolicyVersionsRequest) -> types::ListTrafficPolicyVersionsResponse;
        list_vpc_association_authorizations(types::ListVPCAssociationAuthorizationsRequest) -> types::ListVPCAssociationAuthorizationsResponse;
        test_dns_answer(types::TestDNSAnswerRequest) -> types::TestDNSAnswerResponse;
        update_hosted_zone_features(types::UpdateHostedZoneFeaturesRequest) -> types::UpdateHostedZoneFeaturesResponse;
        update_traffic_policy_comment(types::UpdateTrafficPolicyCommentRequest) -> types::UpdateTrafficPolicyCommentResponse;
        update_traffic_policy_instance(types::UpdateTrafficPolicyInstanceRequest) -> types::UpdateTrafficPolicyInstanceResponse;
    }
}

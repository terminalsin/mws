//! Wires the generated `Handler` trait to the operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::GlobalAccelerator;

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
                let result = GlobalAccelerator::$name(self, ctx, input);
                Box::pin(async move { result })
            }
        )*
    };
}

impl Handler for GlobalAccelerator {
    delegate! {
        add_custom_routing_endpoints(types::AddCustomRoutingEndpointsRequest) -> types::AddCustomRoutingEndpointsResponse;
        add_endpoints(types::AddEndpointsRequest) -> types::AddEndpointsResponse;
        advertise_byoip_cidr(types::AdvertiseByoipCidrRequest) -> types::AdvertiseByoipCidrResponse;
        allow_custom_routing_traffic(types::AllowCustomRoutingTrafficRequest) -> ();
        create_accelerator(types::CreateAcceleratorRequest) -> types::CreateAcceleratorResponse;
        create_cross_account_attachment(types::CreateCrossAccountAttachmentRequest) -> types::CreateCrossAccountAttachmentResponse;
        create_custom_routing_accelerator(types::CreateCustomRoutingAcceleratorRequest) -> types::CreateCustomRoutingAcceleratorResponse;
        create_custom_routing_endpoint_group(types::CreateCustomRoutingEndpointGroupRequest) -> types::CreateCustomRoutingEndpointGroupResponse;
        create_custom_routing_listener(types::CreateCustomRoutingListenerRequest) -> types::CreateCustomRoutingListenerResponse;
        create_endpoint_group(types::CreateEndpointGroupRequest) -> types::CreateEndpointGroupResponse;
        create_listener(types::CreateListenerRequest) -> types::CreateListenerResponse;
        delete_accelerator(types::DeleteAcceleratorRequest) -> ();
        delete_cross_account_attachment(types::DeleteCrossAccountAttachmentRequest) -> ();
        delete_custom_routing_accelerator(types::DeleteCustomRoutingAcceleratorRequest) -> ();
        delete_custom_routing_endpoint_group(types::DeleteCustomRoutingEndpointGroupRequest) -> ();
        delete_custom_routing_listener(types::DeleteCustomRoutingListenerRequest) -> ();
        delete_endpoint_group(types::DeleteEndpointGroupRequest) -> ();
        delete_listener(types::DeleteListenerRequest) -> ();
        deny_custom_routing_traffic(types::DenyCustomRoutingTrafficRequest) -> ();
        deprovision_byoip_cidr(types::DeprovisionByoipCidrRequest) -> types::DeprovisionByoipCidrResponse;
        describe_accelerator(types::DescribeAcceleratorRequest) -> types::DescribeAcceleratorResponse;
        describe_accelerator_attributes(types::DescribeAcceleratorAttributesRequest) -> types::DescribeAcceleratorAttributesResponse;
        describe_cross_account_attachment(types::DescribeCrossAccountAttachmentRequest) -> types::DescribeCrossAccountAttachmentResponse;
        describe_custom_routing_accelerator(types::DescribeCustomRoutingAcceleratorRequest) -> types::DescribeCustomRoutingAcceleratorResponse;
        describe_custom_routing_accelerator_attributes(types::DescribeCustomRoutingAcceleratorAttributesRequest) -> types::DescribeCustomRoutingAcceleratorAttributesResponse;
        describe_custom_routing_endpoint_group(types::DescribeCustomRoutingEndpointGroupRequest) -> types::DescribeCustomRoutingEndpointGroupResponse;
        describe_custom_routing_listener(types::DescribeCustomRoutingListenerRequest) -> types::DescribeCustomRoutingListenerResponse;
        describe_endpoint_group(types::DescribeEndpointGroupRequest) -> types::DescribeEndpointGroupResponse;
        describe_listener(types::DescribeListenerRequest) -> types::DescribeListenerResponse;
        list_accelerators(types::ListAcceleratorsRequest) -> types::ListAcceleratorsResponse;
        list_byoip_cidrs(types::ListByoipCidrsRequest) -> types::ListByoipCidrsResponse;
        list_cross_account_attachments(types::ListCrossAccountAttachmentsRequest) -> types::ListCrossAccountAttachmentsResponse;
        list_cross_account_resource_accounts(types::ListCrossAccountResourceAccountsRequest) -> types::ListCrossAccountResourceAccountsResponse;
        list_cross_account_resources(types::ListCrossAccountResourcesRequest) -> types::ListCrossAccountResourcesResponse;
        list_custom_routing_accelerators(types::ListCustomRoutingAcceleratorsRequest) -> types::ListCustomRoutingAcceleratorsResponse;
        list_custom_routing_endpoint_groups(types::ListCustomRoutingEndpointGroupsRequest) -> types::ListCustomRoutingEndpointGroupsResponse;
        list_custom_routing_listeners(types::ListCustomRoutingListenersRequest) -> types::ListCustomRoutingListenersResponse;
        list_custom_routing_port_mappings(types::ListCustomRoutingPortMappingsRequest) -> types::ListCustomRoutingPortMappingsResponse;
        list_custom_routing_port_mappings_by_destination(types::ListCustomRoutingPortMappingsByDestinationRequest) -> types::ListCustomRoutingPortMappingsByDestinationResponse;
        list_endpoint_groups(types::ListEndpointGroupsRequest) -> types::ListEndpointGroupsResponse;
        list_listeners(types::ListListenersRequest) -> types::ListListenersResponse;
        list_tags_for_resource(types::ListTagsForResourceRequest) -> types::ListTagsForResourceResponse;
        provision_byoip_cidr(types::ProvisionByoipCidrRequest) -> types::ProvisionByoipCidrResponse;
        remove_custom_routing_endpoints(types::RemoveCustomRoutingEndpointsRequest) -> ();
        remove_endpoints(types::RemoveEndpointsRequest) -> ();
        tag_resource(types::TagResourceRequest) -> types::TagResourceResponse;
        untag_resource(types::UntagResourceRequest) -> types::UntagResourceResponse;
        update_accelerator(types::UpdateAcceleratorRequest) -> types::UpdateAcceleratorResponse;
        update_accelerator_attributes(types::UpdateAcceleratorAttributesRequest) -> types::UpdateAcceleratorAttributesResponse;
        update_cross_account_attachment(types::UpdateCrossAccountAttachmentRequest) -> types::UpdateCrossAccountAttachmentResponse;
        update_custom_routing_accelerator(types::UpdateCustomRoutingAcceleratorRequest) -> types::UpdateCustomRoutingAcceleratorResponse;
        update_custom_routing_accelerator_attributes(types::UpdateCustomRoutingAcceleratorAttributesRequest) -> types::UpdateCustomRoutingAcceleratorAttributesResponse;
        update_custom_routing_listener(types::UpdateCustomRoutingListenerRequest) -> types::UpdateCustomRoutingListenerResponse;
        update_endpoint_group(types::UpdateEndpointGroupRequest) -> types::UpdateEndpointGroupResponse;
        update_listener(types::UpdateListenerRequest) -> types::UpdateListenerResponse;
        withdraw_byoip_cidr(types::WithdrawByoipCidrRequest) -> types::WithdrawByoipCidrResponse;
    }
}

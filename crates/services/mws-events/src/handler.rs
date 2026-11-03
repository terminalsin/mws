//! Wires the generated `Handler` trait to the synchronous operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::Events;

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
                let result = Events::$name(self, ctx, input);
                Box::pin(async move { result })
            }
        )*
    };
}

impl Handler for Events {
    delegate! {
        activate_event_source(types::ActivateEventSourceRequest) -> ();
        cancel_replay(types::CancelReplayRequest) -> types::CancelReplayResponse;
        create_api_destination(types::CreateApiDestinationRequest) -> types::CreateApiDestinationResponse;
        create_archive(types::CreateArchiveRequest) -> types::CreateArchiveResponse;
        create_connection(types::CreateConnectionRequest) -> types::CreateConnectionResponse;
        create_endpoint(types::CreateEndpointRequest) -> types::CreateEndpointResponse;
        create_event_bus(types::CreateEventBusRequest) -> types::CreateEventBusResponse;
        create_partner_event_source(types::CreatePartnerEventSourceRequest) -> types::CreatePartnerEventSourceResponse;
        deactivate_event_source(types::DeactivateEventSourceRequest) -> ();
        deauthorize_connection(types::DeauthorizeConnectionRequest) -> types::DeauthorizeConnectionResponse;
        delete_api_destination(types::DeleteApiDestinationRequest) -> types::DeleteApiDestinationResponse;
        delete_archive(types::DeleteArchiveRequest) -> types::DeleteArchiveResponse;
        delete_connection(types::DeleteConnectionRequest) -> types::DeleteConnectionResponse;
        delete_endpoint(types::DeleteEndpointRequest) -> types::DeleteEndpointResponse;
        delete_event_bus(types::DeleteEventBusRequest) -> ();
        delete_partner_event_source(types::DeletePartnerEventSourceRequest) -> ();
        delete_rule(types::DeleteRuleRequest) -> ();
        describe_api_destination(types::DescribeApiDestinationRequest) -> types::DescribeApiDestinationResponse;
        describe_archive(types::DescribeArchiveRequest) -> types::DescribeArchiveResponse;
        describe_connection(types::DescribeConnectionRequest) -> types::DescribeConnectionResponse;
        describe_endpoint(types::DescribeEndpointRequest) -> types::DescribeEndpointResponse;
        describe_event_bus(types::DescribeEventBusRequest) -> types::DescribeEventBusResponse;
        describe_event_source(types::DescribeEventSourceRequest) -> types::DescribeEventSourceResponse;
        describe_partner_event_source(types::DescribePartnerEventSourceRequest) -> types::DescribePartnerEventSourceResponse;
        describe_replay(types::DescribeReplayRequest) -> types::DescribeReplayResponse;
        describe_rule(types::DescribeRuleRequest) -> types::DescribeRuleResponse;
        disable_rule(types::DisableRuleRequest) -> ();
        enable_rule(types::EnableRuleRequest) -> ();
        list_api_destinations(types::ListApiDestinationsRequest) -> types::ListApiDestinationsResponse;
        list_archives(types::ListArchivesRequest) -> types::ListArchivesResponse;
        list_connections(types::ListConnectionsRequest) -> types::ListConnectionsResponse;
        list_endpoints(types::ListEndpointsRequest) -> types::ListEndpointsResponse;
        list_event_buses(types::ListEventBusesRequest) -> types::ListEventBusesResponse;
        list_event_sources(types::ListEventSourcesRequest) -> types::ListEventSourcesResponse;
        list_partner_event_source_accounts(types::ListPartnerEventSourceAccountsRequest) -> types::ListPartnerEventSourceAccountsResponse;
        list_partner_event_sources(types::ListPartnerEventSourcesRequest) -> types::ListPartnerEventSourcesResponse;
        list_replays(types::ListReplaysRequest) -> types::ListReplaysResponse;
        list_rule_names_by_target(types::ListRuleNamesByTargetRequest) -> types::ListRuleNamesByTargetResponse;
        list_rules(types::ListRulesRequest) -> types::ListRulesResponse;
        list_tags_for_resource(types::ListTagsForResourceRequest) -> types::ListTagsForResourceResponse;
        list_targets_by_rule(types::ListTargetsByRuleRequest) -> types::ListTargetsByRuleResponse;
        put_events(types::PutEventsRequest) -> types::PutEventsResponse;
        put_partner_events(types::PutPartnerEventsRequest) -> types::PutPartnerEventsResponse;
        put_permission(types::PutPermissionRequest) -> ();
        put_rule(types::PutRuleRequest) -> types::PutRuleResponse;
        put_targets(types::PutTargetsRequest) -> types::PutTargetsResponse;
        remove_permission(types::RemovePermissionRequest) -> ();
        remove_targets(types::RemoveTargetsRequest) -> types::RemoveTargetsResponse;
        start_replay(types::StartReplayRequest) -> types::StartReplayResponse;
        tag_resource(types::TagResourceRequest) -> types::TagResourceResponse;
        test_event_pattern(types::TestEventPatternRequest) -> types::TestEventPatternResponse;
        untag_resource(types::UntagResourceRequest) -> types::UntagResourceResponse;
        update_api_destination(types::UpdateApiDestinationRequest) -> types::UpdateApiDestinationResponse;
        update_archive(types::UpdateArchiveRequest) -> types::UpdateArchiveResponse;
        update_connection(types::UpdateConnectionRequest) -> types::UpdateConnectionResponse;
        update_endpoint(types::UpdateEndpointRequest) -> types::UpdateEndpointResponse;
        update_event_bus(types::UpdateEventBusRequest) -> types::UpdateEventBusResponse;
    }
}

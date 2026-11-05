//! Wires the generated `Handler` trait to the synchronous operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::CloudTrail;

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
                let result = CloudTrail::$name(self, ctx, input);
                Box::pin(async move { result })
            }
        )*
    };
}

impl Handler for CloudTrail {
    delegate! {
        add_tags(types::AddTagsRequest) -> types::AddTagsResponse;
        cancel_query(types::CancelQueryRequest) -> types::CancelQueryResponse;
        create_channel(types::CreateChannelRequest) -> types::CreateChannelResponse;
        create_dashboard(types::CreateDashboardRequest) -> types::CreateDashboardResponse;
        create_event_data_store(types::CreateEventDataStoreRequest) -> types::CreateEventDataStoreResponse;
        create_trail(types::CreateTrailRequest) -> types::CreateTrailResponse;
        delete_channel(types::DeleteChannelRequest) -> types::DeleteChannelResponse;
        delete_dashboard(types::DeleteDashboardRequest) -> types::DeleteDashboardResponse;
        delete_event_data_store(types::DeleteEventDataStoreRequest) -> types::DeleteEventDataStoreResponse;
        delete_resource_policy(types::DeleteResourcePolicyRequest) -> types::DeleteResourcePolicyResponse;
        delete_trail(types::DeleteTrailRequest) -> types::DeleteTrailResponse;
        deregister_organization_delegated_admin(types::DeregisterOrganizationDelegatedAdminRequest) -> types::DeregisterOrganizationDelegatedAdminResponse;
        describe_query(types::DescribeQueryRequest) -> types::DescribeQueryResponse;
        describe_trails(types::DescribeTrailsRequest) -> types::DescribeTrailsResponse;
        disable_federation(types::DisableFederationRequest) -> types::DisableFederationResponse;
        enable_federation(types::EnableFederationRequest) -> types::EnableFederationResponse;
        generate_query(types::GenerateQueryRequest) -> types::GenerateQueryResponse;
        get_channel(types::GetChannelRequest) -> types::GetChannelResponse;
        get_dashboard(types::GetDashboardRequest) -> types::GetDashboardResponse;
        get_event_configuration(types::GetEventConfigurationRequest) -> types::GetEventConfigurationResponse;
        get_event_data_store(types::GetEventDataStoreRequest) -> types::GetEventDataStoreResponse;
        get_event_selectors(types::GetEventSelectorsRequest) -> types::GetEventSelectorsResponse;
        get_import(types::GetImportRequest) -> types::GetImportResponse;
        get_insight_selectors(types::GetInsightSelectorsRequest) -> types::GetInsightSelectorsResponse;
        get_query_results(types::GetQueryResultsRequest) -> types::GetQueryResultsResponse;
        get_resource_policy(types::GetResourcePolicyRequest) -> types::GetResourcePolicyResponse;
        get_trail(types::GetTrailRequest) -> types::GetTrailResponse;
        get_trail_status(types::GetTrailStatusRequest) -> types::GetTrailStatusResponse;
        list_channels(types::ListChannelsRequest) -> types::ListChannelsResponse;
        list_dashboards(types::ListDashboardsRequest) -> types::ListDashboardsResponse;
        list_event_data_stores(types::ListEventDataStoresRequest) -> types::ListEventDataStoresResponse;
        list_import_failures(types::ListImportFailuresRequest) -> types::ListImportFailuresResponse;
        list_imports(types::ListImportsRequest) -> types::ListImportsResponse;
        list_insights_data(types::ListInsightsDataRequest) -> types::ListInsightsDataResponse;
        list_insights_metric_data(types::ListInsightsMetricDataRequest) -> types::ListInsightsMetricDataResponse;
        list_public_keys(types::ListPublicKeysRequest) -> types::ListPublicKeysResponse;
        list_queries(types::ListQueriesRequest) -> types::ListQueriesResponse;
        list_tags(types::ListTagsRequest) -> types::ListTagsResponse;
        list_trails(types::ListTrailsRequest) -> types::ListTrailsResponse;
        lookup_events(types::LookupEventsRequest) -> types::LookupEventsResponse;
        put_event_configuration(types::PutEventConfigurationRequest) -> types::PutEventConfigurationResponse;
        put_event_selectors(types::PutEventSelectorsRequest) -> types::PutEventSelectorsResponse;
        put_insight_selectors(types::PutInsightSelectorsRequest) -> types::PutInsightSelectorsResponse;
        put_resource_policy(types::PutResourcePolicyRequest) -> types::PutResourcePolicyResponse;
        register_organization_delegated_admin(types::RegisterOrganizationDelegatedAdminRequest) -> types::RegisterOrganizationDelegatedAdminResponse;
        remove_tags(types::RemoveTagsRequest) -> types::RemoveTagsResponse;
        restore_event_data_store(types::RestoreEventDataStoreRequest) -> types::RestoreEventDataStoreResponse;
        search_sample_queries(types::SearchSampleQueriesRequest) -> types::SearchSampleQueriesResponse;
        start_dashboard_refresh(types::StartDashboardRefreshRequest) -> types::StartDashboardRefreshResponse;
        start_event_data_store_ingestion(types::StartEventDataStoreIngestionRequest) -> types::StartEventDataStoreIngestionResponse;
        start_import(types::StartImportRequest) -> types::StartImportResponse;
        start_logging(types::StartLoggingRequest) -> types::StartLoggingResponse;
        start_query(types::StartQueryRequest) -> types::StartQueryResponse;
        stop_event_data_store_ingestion(types::StopEventDataStoreIngestionRequest) -> types::StopEventDataStoreIngestionResponse;
        stop_import(types::StopImportRequest) -> types::StopImportResponse;
        stop_logging(types::StopLoggingRequest) -> types::StopLoggingResponse;
        update_channel(types::UpdateChannelRequest) -> types::UpdateChannelResponse;
        update_dashboard(types::UpdateDashboardRequest) -> types::UpdateDashboardResponse;
        update_event_data_store(types::UpdateEventDataStoreRequest) -> types::UpdateEventDataStoreResponse;
        update_trail(types::UpdateTrailRequest) -> types::UpdateTrailResponse;
    }
}

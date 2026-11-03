//! Wires the generated `Handler` trait to the synchronous operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::Logs;

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
                let result = Logs::$name(self, ctx, input);
                Box::pin(async move { result })
            }
        )*
    };
}

impl Handler for Logs {
    delegate! {
        associate_kms_key(types::AssociateKmsKeyRequest) -> ();
        associate_source_to_s3_table_integration(types::AssociateSourceToS3TableIntegrationRequest) -> types::AssociateSourceToS3TableIntegrationResponse;
        cancel_export_task(types::CancelExportTaskRequest) -> ();
        cancel_import_task(types::CancelImportTaskRequest) -> types::CancelImportTaskResponse;
        create_delivery(types::CreateDeliveryRequest) -> types::CreateDeliveryResponse;
        create_export_task(types::CreateExportTaskRequest) -> types::CreateExportTaskResponse;
        create_import_task(types::CreateImportTaskRequest) -> types::CreateImportTaskResponse;
        create_log_anomaly_detector(types::CreateLogAnomalyDetectorRequest) -> types::CreateLogAnomalyDetectorResponse;
        create_log_group(types::CreateLogGroupRequest) -> ();
        create_log_stream(types::CreateLogStreamRequest) -> ();
        create_lookup_table(types::CreateLookupTableRequest) -> types::CreateLookupTableResponse;
        create_scheduled_query(types::CreateScheduledQueryRequest) -> types::CreateScheduledQueryResponse;
        delete_account_policy(types::DeleteAccountPolicyRequest) -> types::DeleteAccountPolicyResponse;
        delete_data_protection_policy(types::DeleteDataProtectionPolicyRequest) -> ();
        delete_delivery(types::DeleteDeliveryRequest) -> ();
        delete_delivery_destination(types::DeleteDeliveryDestinationRequest) -> ();
        delete_delivery_destination_policy(types::DeleteDeliveryDestinationPolicyRequest) -> ();
        delete_delivery_source(types::DeleteDeliverySourceRequest) -> ();
        delete_destination(types::DeleteDestinationRequest) -> ();
        delete_index_policy(types::DeleteIndexPolicyRequest) -> types::DeleteIndexPolicyResponse;
        delete_integration(types::DeleteIntegrationRequest) -> types::DeleteIntegrationResponse;
        delete_log_anomaly_detector(types::DeleteLogAnomalyDetectorRequest) -> ();
        delete_log_group(types::DeleteLogGroupRequest) -> ();
        delete_log_stream(types::DeleteLogStreamRequest) -> ();
        delete_lookup_table(types::DeleteLookupTableRequest) -> ();
        delete_metric_filter(types::DeleteMetricFilterRequest) -> ();
        delete_query_definition(types::DeleteQueryDefinitionRequest) -> types::DeleteQueryDefinitionResponse;
        delete_resource_policy(types::DeleteResourcePolicyRequest) -> ();
        delete_retention_policy(types::DeleteRetentionPolicyRequest) -> ();
        delete_scheduled_query(types::DeleteScheduledQueryRequest) -> types::DeleteScheduledQueryResponse;
        delete_subscription_filter(types::DeleteSubscriptionFilterRequest) -> ();
        delete_syslog_configuration(types::DeleteSyslogConfigurationRequest) -> ();
        delete_transformer(types::DeleteTransformerRequest) -> ();
        describe_account_policies(types::DescribeAccountPoliciesRequest) -> types::DescribeAccountPoliciesResponse;
        describe_configuration_templates(types::DescribeConfigurationTemplatesRequest) -> types::DescribeConfigurationTemplatesResponse;
        describe_deliveries(types::DescribeDeliveriesRequest) -> types::DescribeDeliveriesResponse;
        describe_delivery_destinations(types::DescribeDeliveryDestinationsRequest) -> types::DescribeDeliveryDestinationsResponse;
        describe_delivery_sources(types::DescribeDeliverySourcesRequest) -> types::DescribeDeliverySourcesResponse;
        describe_destinations(types::DescribeDestinationsRequest) -> types::DescribeDestinationsResponse;
        describe_export_tasks(types::DescribeExportTasksRequest) -> types::DescribeExportTasksResponse;
        describe_field_indexes(types::DescribeFieldIndexesRequest) -> types::DescribeFieldIndexesResponse;
        describe_import_task_batches(types::DescribeImportTaskBatchesRequest) -> types::DescribeImportTaskBatchesResponse;
        describe_import_tasks(types::DescribeImportTasksRequest) -> types::DescribeImportTasksResponse;
        describe_index_policies(types::DescribeIndexPoliciesRequest) -> types::DescribeIndexPoliciesResponse;
        describe_log_groups(types::DescribeLogGroupsRequest) -> types::DescribeLogGroupsResponse;
        describe_log_streams(types::DescribeLogStreamsRequest) -> types::DescribeLogStreamsResponse;
        describe_lookup_tables(types::DescribeLookupTablesRequest) -> types::DescribeLookupTablesResponse;
        describe_metric_filters(types::DescribeMetricFiltersRequest) -> types::DescribeMetricFiltersResponse;
        describe_queries(types::DescribeQueriesRequest) -> types::DescribeQueriesResponse;
        describe_query_definitions(types::DescribeQueryDefinitionsRequest) -> types::DescribeQueryDefinitionsResponse;
        describe_resource_policies(types::DescribeResourcePoliciesRequest) -> types::DescribeResourcePoliciesResponse;
        describe_subscription_filters(types::DescribeSubscriptionFiltersRequest) -> types::DescribeSubscriptionFiltersResponse;
        disassociate_kms_key(types::DisassociateKmsKeyRequest) -> ();
        disassociate_source_from_s3_table_integration(types::DisassociateSourceFromS3TableIntegrationRequest) -> types::DisassociateSourceFromS3TableIntegrationResponse;
        filter_log_events(types::FilterLogEventsRequest) -> types::FilterLogEventsResponse;
        get_data_protection_policy(types::GetDataProtectionPolicyRequest) -> types::GetDataProtectionPolicyResponse;
        get_delivery(types::GetDeliveryRequest) -> types::GetDeliveryResponse;
        get_delivery_destination(types::GetDeliveryDestinationRequest) -> types::GetDeliveryDestinationResponse;
        get_delivery_destination_policy(types::GetDeliveryDestinationPolicyRequest) -> types::GetDeliveryDestinationPolicyResponse;
        get_delivery_source(types::GetDeliverySourceRequest) -> types::GetDeliverySourceResponse;
        get_integration(types::GetIntegrationRequest) -> types::GetIntegrationResponse;
        get_log_anomaly_detector(types::GetLogAnomalyDetectorRequest) -> types::GetLogAnomalyDetectorResponse;
        get_log_events(types::GetLogEventsRequest) -> types::GetLogEventsResponse;
        get_log_fields(types::GetLogFieldsRequest) -> types::GetLogFieldsResponse;
        get_log_group_fields(types::GetLogGroupFieldsRequest) -> types::GetLogGroupFieldsResponse;
        get_log_object(types::GetLogObjectRequest) -> types::GetLogObjectResponse;
        get_log_record(types::GetLogRecordRequest) -> types::GetLogRecordResponse;
        get_lookup_table(types::GetLookupTableRequest) -> types::GetLookupTableResponse;
        get_query_results(types::GetQueryResultsRequest) -> types::GetQueryResultsResponse;
        get_scheduled_query(types::GetScheduledQueryRequest) -> types::GetScheduledQueryResponse;
        get_scheduled_query_history(types::GetScheduledQueryHistoryRequest) -> types::GetScheduledQueryHistoryResponse;
        get_storage_tier_policy(types::GetStorageTierPolicyRequest) -> types::GetStorageTierPolicyResponse;
        get_transformer(types::GetTransformerRequest) -> types::GetTransformerResponse;
        list_aggregate_log_group_summaries(types::ListAggregateLogGroupSummariesRequest) -> types::ListAggregateLogGroupSummariesResponse;
        list_anomalies(types::ListAnomaliesRequest) -> types::ListAnomaliesResponse;
        list_integrations(types::ListIntegrationsRequest) -> types::ListIntegrationsResponse;
        list_log_anomaly_detectors(types::ListLogAnomalyDetectorsRequest) -> types::ListLogAnomalyDetectorsResponse;
        list_log_groups(types::ListLogGroupsRequest) -> types::ListLogGroupsResponse;
        list_log_groups_for_query(types::ListLogGroupsForQueryRequest) -> types::ListLogGroupsForQueryResponse;
        list_scheduled_queries(types::ListScheduledQueriesRequest) -> types::ListScheduledQueriesResponse;
        list_sources_for_s3_table_integration(types::ListSourcesForS3TableIntegrationRequest) -> types::ListSourcesForS3TableIntegrationResponse;
        list_syslog_configurations(types::ListSyslogConfigurationsRequest) -> types::ListSyslogConfigurationsResponse;
        list_tags_for_resource(types::ListTagsForResourceRequest) -> types::ListTagsForResourceResponse;
        list_tags_log_group(types::ListTagsLogGroupRequest) -> types::ListTagsLogGroupResponse;
        put_account_policy(types::PutAccountPolicyRequest) -> types::PutAccountPolicyResponse;
        put_bearer_token_authentication(types::PutBearerTokenAuthenticationRequest) -> ();
        put_data_protection_policy(types::PutDataProtectionPolicyRequest) -> types::PutDataProtectionPolicyResponse;
        put_delivery_destination(types::PutDeliveryDestinationRequest) -> types::PutDeliveryDestinationResponse;
        put_delivery_destination_policy(types::PutDeliveryDestinationPolicyRequest) -> types::PutDeliveryDestinationPolicyResponse;
        put_delivery_source(types::PutDeliverySourceRequest) -> types::PutDeliverySourceResponse;
        put_destination(types::PutDestinationRequest) -> types::PutDestinationResponse;
        put_destination_policy(types::PutDestinationPolicyRequest) -> ();
        put_index_policy(types::PutIndexPolicyRequest) -> types::PutIndexPolicyResponse;
        put_integration(types::PutIntegrationRequest) -> types::PutIntegrationResponse;
        put_log_events(types::PutLogEventsRequest) -> types::PutLogEventsResponse;
        put_log_group_deletion_protection(types::PutLogGroupDeletionProtectionRequest) -> ();
        put_metric_filter(types::PutMetricFilterRequest) -> ();
        put_query_definition(types::PutQueryDefinitionRequest) -> types::PutQueryDefinitionResponse;
        put_resource_policy(types::PutResourcePolicyRequest) -> types::PutResourcePolicyResponse;
        put_retention_policy(types::PutRetentionPolicyRequest) -> ();
        put_storage_tier_policy(types::PutStorageTierPolicyRequest) -> types::PutStorageTierPolicyResponse;
        put_subscription_filter(types::PutSubscriptionFilterRequest) -> ();
        put_syslog_configuration(types::PutSyslogConfigurationRequest) -> ();
        put_transformer(types::PutTransformerRequest) -> ();
        start_live_tail(types::StartLiveTailRequest) -> types::StartLiveTailResponse;
        start_query(types::StartQueryRequest) -> types::StartQueryResponse;
        stop_query(types::StopQueryRequest) -> types::StopQueryResponse;
        tag_log_group(types::TagLogGroupRequest) -> ();
        tag_resource(types::TagResourceRequest) -> ();
        test_metric_filter(types::TestMetricFilterRequest) -> types::TestMetricFilterResponse;
        test_transformer(types::TestTransformerRequest) -> types::TestTransformerResponse;
        untag_log_group(types::UntagLogGroupRequest) -> ();
        untag_resource(types::UntagResourceRequest) -> ();
        update_anomaly(types::UpdateAnomalyRequest) -> ();
        update_delivery_configuration(types::UpdateDeliveryConfigurationRequest) -> types::UpdateDeliveryConfigurationResponse;
        update_log_anomaly_detector(types::UpdateLogAnomalyDetectorRequest) -> ();
        update_lookup_table(types::UpdateLookupTableRequest) -> types::UpdateLookupTableResponse;
        update_scheduled_query(types::UpdateScheduledQueryRequest) -> types::UpdateScheduledQueryResponse;
    }
}

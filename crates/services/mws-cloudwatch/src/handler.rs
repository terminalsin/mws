//! Wires the generated `Handler` trait to the operations.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::CloudWatch;

macro_rules! delegate {
    ($($name:ident($input:ident) -> $output:ty;)*) => {
        #[async_trait::async_trait]
        impl Handler for CloudWatch {
            $(
                async fn $name(&self, ctx: &RequestContext, input: types::$input) -> Result<$output, ServiceError> {
                    self.observe(ctx);
                    CloudWatch::$name(self, ctx, input)
                }
            )*
        }
    };
}

delegate! {
    associate_dataset_kms_key(AssociateDatasetKmsKeyInput) -> types::AssociateDatasetKmsKeyOutput;
    create_resource_metrics_configuration(CreateResourceMetricsConfigurationInput) -> types::CreateResourceMetricsConfigurationOutput;
    delete_alarm_mute_rule(DeleteAlarmMuteRuleInput) -> ();
    delete_alarms(DeleteAlarmsInput) -> ();
    delete_anomaly_detector(DeleteAnomalyDetectorInput) -> types::DeleteAnomalyDetectorOutput;
    delete_dashboards(DeleteDashboardsInput) -> types::DeleteDashboardsOutput;
    delete_insight_rules(DeleteInsightRulesInput) -> types::DeleteInsightRulesOutput;
    delete_metric_stream(DeleteMetricStreamInput) -> types::DeleteMetricStreamOutput;
    delete_resource_metrics_configuration(DeleteResourceMetricsConfigurationInput) -> types::DeleteResourceMetricsConfigurationOutput;
    describe_alarm_contributors(DescribeAlarmContributorsInput) -> types::DescribeAlarmContributorsOutput;
    describe_alarm_history(DescribeAlarmHistoryInput) -> types::DescribeAlarmHistoryOutput;
    describe_alarms(DescribeAlarmsInput) -> types::DescribeAlarmsOutput;
    describe_alarms_for_metric(DescribeAlarmsForMetricInput) -> types::DescribeAlarmsForMetricOutput;
    describe_anomaly_detectors(DescribeAnomalyDetectorsInput) -> types::DescribeAnomalyDetectorsOutput;
    describe_insight_rules(DescribeInsightRulesInput) -> types::DescribeInsightRulesOutput;
    disable_alarm_actions(DisableAlarmActionsInput) -> ();
    disable_insight_rules(DisableInsightRulesInput) -> types::DisableInsightRulesOutput;
    disassociate_dataset_kms_key(DisassociateDatasetKmsKeyInput) -> types::DisassociateDatasetKmsKeyOutput;
    enable_alarm_actions(EnableAlarmActionsInput) -> ();
    enable_insight_rules(EnableInsightRulesInput) -> types::EnableInsightRulesOutput;
    get_alarm_mute_rule(GetAlarmMuteRuleInput) -> types::GetAlarmMuteRuleOutput;
    get_dashboard(GetDashboardInput) -> types::GetDashboardOutput;
    get_dataset(GetDatasetInput) -> types::GetDatasetOutput;
    get_insight_rule_report(GetInsightRuleReportInput) -> types::GetInsightRuleReportOutput;
    get_metric_data(GetMetricDataInput) -> types::GetMetricDataOutput;
    get_metric_statistics(GetMetricStatisticsInput) -> types::GetMetricStatisticsOutput;
    get_metric_stream(GetMetricStreamInput) -> types::GetMetricStreamOutput;
    get_metric_widget_image(GetMetricWidgetImageInput) -> types::GetMetricWidgetImageOutput;
    get_o_tel_enrichment(GetOTelEnrichmentInput) -> types::GetOTelEnrichmentOutput;
    get_resource_metrics_configuration(GetResourceMetricsConfigurationInput) -> types::GetResourceMetricsConfigurationOutput;
    list_alarm_mute_rules(ListAlarmMuteRulesInput) -> types::ListAlarmMuteRulesOutput;
    list_dashboards(ListDashboardsInput) -> types::ListDashboardsOutput;
    list_managed_insight_rules(ListManagedInsightRulesInput) -> types::ListManagedInsightRulesOutput;
    list_metric_streams(ListMetricStreamsInput) -> types::ListMetricStreamsOutput;
    list_metrics(ListMetricsInput) -> types::ListMetricsOutput;
    list_tags_for_resource(ListTagsForResourceInput) -> types::ListTagsForResourceOutput;
    put_alarm_mute_rule(PutAlarmMuteRuleInput) -> ();
    put_anomaly_detector(PutAnomalyDetectorInput) -> types::PutAnomalyDetectorOutput;
    put_composite_alarm(PutCompositeAlarmInput) -> ();
    put_dashboard(PutDashboardInput) -> types::PutDashboardOutput;
    put_insight_rule(PutInsightRuleInput) -> types::PutInsightRuleOutput;
    put_log_alarm(PutLogAlarmInput) -> ();
    put_managed_insight_rules(PutManagedInsightRulesInput) -> types::PutManagedInsightRulesOutput;
    put_metric_alarm(PutMetricAlarmInput) -> ();
    put_metric_data(PutMetricDataInput) -> ();
    put_metric_stream(PutMetricStreamInput) -> types::PutMetricStreamOutput;
    set_alarm_state(SetAlarmStateInput) -> ();
    start_metric_streams(StartMetricStreamsInput) -> types::StartMetricStreamsOutput;
    start_o_tel_enrichment(StartOTelEnrichmentInput) -> types::StartOTelEnrichmentOutput;
    stop_metric_streams(StopMetricStreamsInput) -> types::StopMetricStreamsOutput;
    stop_o_tel_enrichment(StopOTelEnrichmentInput) -> types::StopOTelEnrichmentOutput;
    tag_resource(TagResourceInput) -> types::TagResourceOutput;
    untag_resource(UntagResourceInput) -> types::UntagResourceOutput;
    update_o_tel_enrichment(UpdateOTelEnrichmentInput) -> types::UpdateOTelEnrichmentOutput;
    update_resource_metrics_configuration(UpdateResourceMetricsConfigurationInput) -> types::UpdateResourceMetricsConfigurationOutput;
}

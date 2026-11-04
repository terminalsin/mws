//! awsQuery for CloudWatch. The model moved CloudWatch to Smithy RPC v2
//! CBOR (with awsJson 1.0 too), but CloudWatch still answers the
//! form-encoded awsQuery requests older SDKs send. Requests decode with
//! the awsQuery codec generated from the same model, run through the same
//! handlers (the generated types are identical), and answer in XML with
//! the awsQuery error codes.

use mws_core::{HttpRequest, HttpResponse, RequestContext, ServiceError};

use crate::generated as j;
use crate::query_generated as q;
use crate::CloudWatch;

pub async fn handle(cw: &CloudWatch, ctx: &RequestContext, request: &HttpRequest) -> HttpResponse {
    let params = mws_proto_query::read_params(request);
    q::dispatch(&Bridge(cw), ctx, &params).await
}

/// The awsQuery code of a modeled error.
pub fn wire_code(e: &ServiceError) -> String {
    j::SERVICE_INFO
        .query_compatible
        .and_then(|q| q.codes.iter().find(|(shape, _)| *shape == e.code).map(|(_, code)| code.to_string()))
        .unwrap_or_else(|| e.code.to_string())
}

pub fn to_query_error(e: ServiceError) -> ServiceError {
    to_query(e)
}

fn to_query(mut e: ServiceError) -> ServiceError {
    e.code = wire_code(&e).into();
    e
}

fn convert<A: serde::Serialize, B: serde::de::DeserializeOwned>(a: A) -> Result<B, ServiceError> {
    serde_json::from_value(serde_json::to_value(a).map_err(|e| ServiceError::internal(e.to_string()))?)
        .map_err(|e| ServiceError::internal(e.to_string()))
}

struct Bridge<'a>(&'a CloudWatch);

macro_rules! bridge {
    ($($name:ident($input:ident) -> $output:ty;)*) => {
        #[async_trait::async_trait]
        impl q::Handler for Bridge<'_> {
            $(
                async fn $name(&self, ctx: &RequestContext, input: q::types::$input) -> Result<$output, ServiceError> {
                    let input: j::types::$input = convert(input)?;
                    let out = <CloudWatch as j::Handler>::$name(self.0, ctx, input).await.map_err(to_query)?;
                    convert(out)
                }
            )*
        }
    };
}

bridge! {
        associate_dataset_kms_key(AssociateDatasetKmsKeyInput) -> q::types::AssociateDatasetKmsKeyOutput;
        create_resource_metrics_configuration(CreateResourceMetricsConfigurationInput) -> q::types::CreateResourceMetricsConfigurationOutput;
        delete_alarm_mute_rule(DeleteAlarmMuteRuleInput) -> ();
        delete_alarms(DeleteAlarmsInput) -> ();
        delete_anomaly_detector(DeleteAnomalyDetectorInput) -> q::types::DeleteAnomalyDetectorOutput;
        delete_dashboards(DeleteDashboardsInput) -> q::types::DeleteDashboardsOutput;
        delete_insight_rules(DeleteInsightRulesInput) -> q::types::DeleteInsightRulesOutput;
        delete_metric_stream(DeleteMetricStreamInput) -> q::types::DeleteMetricStreamOutput;
        delete_resource_metrics_configuration(DeleteResourceMetricsConfigurationInput) -> q::types::DeleteResourceMetricsConfigurationOutput;
        describe_alarm_contributors(DescribeAlarmContributorsInput) -> q::types::DescribeAlarmContributorsOutput;
        describe_alarm_history(DescribeAlarmHistoryInput) -> q::types::DescribeAlarmHistoryOutput;
        describe_alarms(DescribeAlarmsInput) -> q::types::DescribeAlarmsOutput;
        describe_alarms_for_metric(DescribeAlarmsForMetricInput) -> q::types::DescribeAlarmsForMetricOutput;
        describe_anomaly_detectors(DescribeAnomalyDetectorsInput) -> q::types::DescribeAnomalyDetectorsOutput;
        describe_insight_rules(DescribeInsightRulesInput) -> q::types::DescribeInsightRulesOutput;
        disable_alarm_actions(DisableAlarmActionsInput) -> ();
        disable_insight_rules(DisableInsightRulesInput) -> q::types::DisableInsightRulesOutput;
        disassociate_dataset_kms_key(DisassociateDatasetKmsKeyInput) -> q::types::DisassociateDatasetKmsKeyOutput;
        enable_alarm_actions(EnableAlarmActionsInput) -> ();
        enable_insight_rules(EnableInsightRulesInput) -> q::types::EnableInsightRulesOutput;
        get_alarm_mute_rule(GetAlarmMuteRuleInput) -> q::types::GetAlarmMuteRuleOutput;
        get_dashboard(GetDashboardInput) -> q::types::GetDashboardOutput;
        get_dataset(GetDatasetInput) -> q::types::GetDatasetOutput;
        get_insight_rule_report(GetInsightRuleReportInput) -> q::types::GetInsightRuleReportOutput;
        get_metric_data(GetMetricDataInput) -> q::types::GetMetricDataOutput;
        get_metric_statistics(GetMetricStatisticsInput) -> q::types::GetMetricStatisticsOutput;
        get_metric_stream(GetMetricStreamInput) -> q::types::GetMetricStreamOutput;
        get_metric_widget_image(GetMetricWidgetImageInput) -> q::types::GetMetricWidgetImageOutput;
        get_o_tel_enrichment(GetOTelEnrichmentInput) -> q::types::GetOTelEnrichmentOutput;
        get_resource_metrics_configuration(GetResourceMetricsConfigurationInput) -> q::types::GetResourceMetricsConfigurationOutput;
        list_alarm_mute_rules(ListAlarmMuteRulesInput) -> q::types::ListAlarmMuteRulesOutput;
        list_dashboards(ListDashboardsInput) -> q::types::ListDashboardsOutput;
        list_managed_insight_rules(ListManagedInsightRulesInput) -> q::types::ListManagedInsightRulesOutput;
        list_metric_streams(ListMetricStreamsInput) -> q::types::ListMetricStreamsOutput;
        list_metrics(ListMetricsInput) -> q::types::ListMetricsOutput;
        list_tags_for_resource(ListTagsForResourceInput) -> q::types::ListTagsForResourceOutput;
        put_alarm_mute_rule(PutAlarmMuteRuleInput) -> ();
        put_anomaly_detector(PutAnomalyDetectorInput) -> q::types::PutAnomalyDetectorOutput;
        put_composite_alarm(PutCompositeAlarmInput) -> ();
        put_dashboard(PutDashboardInput) -> q::types::PutDashboardOutput;
        put_insight_rule(PutInsightRuleInput) -> q::types::PutInsightRuleOutput;
        put_log_alarm(PutLogAlarmInput) -> ();
        put_managed_insight_rules(PutManagedInsightRulesInput) -> q::types::PutManagedInsightRulesOutput;
        put_metric_alarm(PutMetricAlarmInput) -> ();
        put_metric_data(PutMetricDataInput) -> ();
        put_metric_stream(PutMetricStreamInput) -> q::types::PutMetricStreamOutput;
        set_alarm_state(SetAlarmStateInput) -> ();
        start_metric_streams(StartMetricStreamsInput) -> q::types::StartMetricStreamsOutput;
        start_o_tel_enrichment(StartOTelEnrichmentInput) -> q::types::StartOTelEnrichmentOutput;
        stop_metric_streams(StopMetricStreamsInput) -> q::types::StopMetricStreamsOutput;
        stop_o_tel_enrichment(StopOTelEnrichmentInput) -> q::types::StopOTelEnrichmentOutput;
        tag_resource(TagResourceInput) -> q::types::TagResourceOutput;
        untag_resource(UntagResourceInput) -> q::types::UntagResourceOutput;
        update_o_tel_enrichment(UpdateOTelEnrichmentInput) -> q::types::UpdateOTelEnrichmentOutput;
        update_resource_metrics_configuration(UpdateResourceMetricsConfigurationInput) -> q::types::UpdateResourceMetricsConfigurationOutput;
}

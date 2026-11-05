//! The generated `Handler`, forwarding each operation to its implementation.

use mws_core::{RequestContext, ServiceError};

use crate::generated::{types, Handler};
use crate::CostExplorer;

#[async_trait::async_trait]
impl Handler for CostExplorer {
    async fn create_anomaly_monitor(
        &self,
        ctx: &RequestContext,
        input: types::CreateAnomalyMonitorRequest,
    ) -> Result<types::CreateAnomalyMonitorResponse, ServiceError> {
        self.create_anomaly_monitor_op(ctx, input)
    }

    async fn create_anomaly_subscription(
        &self,
        ctx: &RequestContext,
        input: types::CreateAnomalySubscriptionRequest,
    ) -> Result<types::CreateAnomalySubscriptionResponse, ServiceError> {
        self.create_anomaly_subscription_op(ctx, input)
    }

    async fn create_cost_category_definition(
        &self,
        ctx: &RequestContext,
        input: types::CreateCostCategoryDefinitionRequest,
    ) -> Result<types::CreateCostCategoryDefinitionResponse, ServiceError> {
        self.create_cost_category_definition_op(ctx, input)
    }

    async fn delete_anomaly_monitor(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAnomalyMonitorRequest,
    ) -> Result<types::DeleteAnomalyMonitorResponse, ServiceError> {
        self.delete_anomaly_monitor_op(ctx, input)
    }

    async fn delete_anomaly_subscription(
        &self,
        ctx: &RequestContext,
        input: types::DeleteAnomalySubscriptionRequest,
    ) -> Result<types::DeleteAnomalySubscriptionResponse, ServiceError> {
        self.delete_anomaly_subscription_op(ctx, input)
    }

    async fn delete_cost_category_definition(
        &self,
        ctx: &RequestContext,
        input: types::DeleteCostCategoryDefinitionRequest,
    ) -> Result<types::DeleteCostCategoryDefinitionResponse, ServiceError> {
        self.delete_cost_category_definition_op(ctx, input)
    }

    async fn describe_cost_category_definition(
        &self,
        ctx: &RequestContext,
        input: types::DescribeCostCategoryDefinitionRequest,
    ) -> Result<types::DescribeCostCategoryDefinitionResponse, ServiceError> {
        self.describe_cost_category_definition_op(ctx, input)
    }

    async fn get_anomalies(
        &self,
        ctx: &RequestContext,
        input: types::GetAnomaliesRequest,
    ) -> Result<types::GetAnomaliesResponse, ServiceError> {
        self.get_anomalies_op(ctx, input)
    }

    async fn get_anomaly_monitors(
        &self,
        ctx: &RequestContext,
        input: types::GetAnomalyMonitorsRequest,
    ) -> Result<types::GetAnomalyMonitorsResponse, ServiceError> {
        self.get_anomaly_monitors_op(ctx, input)
    }

    async fn get_anomaly_subscriptions(
        &self,
        ctx: &RequestContext,
        input: types::GetAnomalySubscriptionsRequest,
    ) -> Result<types::GetAnomalySubscriptionsResponse, ServiceError> {
        self.get_anomaly_subscriptions_op(ctx, input)
    }

    async fn get_approximate_usage_records(
        &self,
        ctx: &RequestContext,
        input: types::GetApproximateUsageRecordsRequest,
    ) -> Result<types::GetApproximateUsageRecordsResponse, ServiceError> {
        self.get_approximate_usage_records_op(ctx, input)
    }

    async fn get_commitment_purchase_analysis(
        &self,
        ctx: &RequestContext,
        input: types::GetCommitmentPurchaseAnalysisRequest,
    ) -> Result<types::GetCommitmentPurchaseAnalysisResponse, ServiceError> {
        self.get_commitment_purchase_analysis_op(ctx, input)
    }

    async fn get_cost_and_usage(
        &self,
        ctx: &RequestContext,
        input: types::GetCostAndUsageRequest,
    ) -> Result<types::GetCostAndUsageResponse, ServiceError> {
        self.get_cost_and_usage_op(ctx, input)
    }

    async fn get_cost_and_usage_comparisons(
        &self,
        ctx: &RequestContext,
        input: types::GetCostAndUsageComparisonsRequest,
    ) -> Result<types::GetCostAndUsageComparisonsResponse, ServiceError> {
        self.get_cost_and_usage_comparisons_op(ctx, input)
    }

    async fn get_cost_and_usage_with_resources(
        &self,
        ctx: &RequestContext,
        input: types::GetCostAndUsageWithResourcesRequest,
    ) -> Result<types::GetCostAndUsageWithResourcesResponse, ServiceError> {
        self.get_cost_and_usage_with_resources_op(ctx, input)
    }

    async fn get_cost_categories(
        &self,
        ctx: &RequestContext,
        input: types::GetCostCategoriesRequest,
    ) -> Result<types::GetCostCategoriesResponse, ServiceError> {
        self.get_cost_categories_op(ctx, input)
    }

    async fn get_cost_comparison_drivers(
        &self,
        ctx: &RequestContext,
        input: types::GetCostComparisonDriversRequest,
    ) -> Result<types::GetCostComparisonDriversResponse, ServiceError> {
        self.get_cost_comparison_drivers_op(ctx, input)
    }

    async fn get_cost_forecast(
        &self,
        ctx: &RequestContext,
        input: types::GetCostForecastRequest,
    ) -> Result<types::GetCostForecastResponse, ServiceError> {
        self.get_cost_forecast_op(ctx, input)
    }

    async fn get_dimension_values(
        &self,
        ctx: &RequestContext,
        input: types::GetDimensionValuesRequest,
    ) -> Result<types::GetDimensionValuesResponse, ServiceError> {
        self.get_dimension_values_op(ctx, input)
    }

    async fn get_reservation_coverage(
        &self,
        ctx: &RequestContext,
        input: types::GetReservationCoverageRequest,
    ) -> Result<types::GetReservationCoverageResponse, ServiceError> {
        self.get_reservation_coverage_op(ctx, input)
    }

    async fn get_reservation_purchase_recommendation(
        &self,
        ctx: &RequestContext,
        input: types::GetReservationPurchaseRecommendationRequest,
    ) -> Result<types::GetReservationPurchaseRecommendationResponse, ServiceError> {
        self.get_reservation_purchase_recommendation_op(ctx, input)
    }

    async fn get_reservation_utilization(
        &self,
        ctx: &RequestContext,
        input: types::GetReservationUtilizationRequest,
    ) -> Result<types::GetReservationUtilizationResponse, ServiceError> {
        self.get_reservation_utilization_op(ctx, input)
    }

    async fn get_rightsizing_recommendation(
        &self,
        ctx: &RequestContext,
        input: types::GetRightsizingRecommendationRequest,
    ) -> Result<types::GetRightsizingRecommendationResponse, ServiceError> {
        self.get_rightsizing_recommendation_op(ctx, input)
    }

    async fn get_savings_plan_purchase_recommendation_details(
        &self,
        ctx: &RequestContext,
        input: types::GetSavingsPlanPurchaseRecommendationDetailsRequest,
    ) -> Result<types::GetSavingsPlanPurchaseRecommendationDetailsResponse, ServiceError> {
        self.get_savings_plan_purchase_recommendation_details_op(ctx, input)
    }

    async fn get_savings_plans_coverage(
        &self,
        ctx: &RequestContext,
        input: types::GetSavingsPlansCoverageRequest,
    ) -> Result<types::GetSavingsPlansCoverageResponse, ServiceError> {
        self.get_savings_plans_coverage_op(ctx, input)
    }

    async fn get_savings_plans_purchase_recommendation(
        &self,
        ctx: &RequestContext,
        input: types::GetSavingsPlansPurchaseRecommendationRequest,
    ) -> Result<types::GetSavingsPlansPurchaseRecommendationResponse, ServiceError> {
        self.get_savings_plans_purchase_recommendation_op(ctx, input)
    }

    async fn get_savings_plans_utilization(
        &self,
        ctx: &RequestContext,
        input: types::GetSavingsPlansUtilizationRequest,
    ) -> Result<types::GetSavingsPlansUtilizationResponse, ServiceError> {
        self.get_savings_plans_utilization_op(ctx, input)
    }

    async fn get_savings_plans_utilization_details(
        &self,
        ctx: &RequestContext,
        input: types::GetSavingsPlansUtilizationDetailsRequest,
    ) -> Result<types::GetSavingsPlansUtilizationDetailsResponse, ServiceError> {
        self.get_savings_plans_utilization_details_op(ctx, input)
    }

    async fn get_tags(
        &self,
        ctx: &RequestContext,
        input: types::GetTagsRequest,
    ) -> Result<types::GetTagsResponse, ServiceError> {
        self.get_tags_op(ctx, input)
    }

    async fn get_usage_forecast(
        &self,
        ctx: &RequestContext,
        input: types::GetUsageForecastRequest,
    ) -> Result<types::GetUsageForecastResponse, ServiceError> {
        self.get_usage_forecast_op(ctx, input)
    }

    async fn list_commitment_purchase_analyses(
        &self,
        ctx: &RequestContext,
        input: types::ListCommitmentPurchaseAnalysesRequest,
    ) -> Result<types::ListCommitmentPurchaseAnalysesResponse, ServiceError> {
        self.list_commitment_purchase_analyses_op(ctx, input)
    }

    async fn list_cost_allocation_tag_backfill_history(
        &self,
        ctx: &RequestContext,
        input: types::ListCostAllocationTagBackfillHistoryRequest,
    ) -> Result<types::ListCostAllocationTagBackfillHistoryResponse, ServiceError> {
        self.list_cost_allocation_tag_backfill_history_op(ctx, input)
    }

    async fn list_cost_allocation_tags(
        &self,
        ctx: &RequestContext,
        input: types::ListCostAllocationTagsRequest,
    ) -> Result<types::ListCostAllocationTagsResponse, ServiceError> {
        self.list_cost_allocation_tags_op(ctx, input)
    }

    async fn list_cost_category_definitions(
        &self,
        ctx: &RequestContext,
        input: types::ListCostCategoryDefinitionsRequest,
    ) -> Result<types::ListCostCategoryDefinitionsResponse, ServiceError> {
        self.list_cost_category_definitions_op(ctx, input)
    }

    async fn list_cost_category_resource_associations(
        &self,
        ctx: &RequestContext,
        input: types::ListCostCategoryResourceAssociationsRequest,
    ) -> Result<types::ListCostCategoryResourceAssociationsResponse, ServiceError> {
        self.list_cost_category_resource_associations_op(ctx, input)
    }

    async fn list_savings_plans_purchase_recommendation_generation(
        &self,
        ctx: &RequestContext,
        input: types::ListSavingsPlansPurchaseRecommendationGenerationRequest,
    ) -> Result<types::ListSavingsPlansPurchaseRecommendationGenerationResponse, ServiceError> {
        self.list_savings_plans_purchase_recommendation_generation_op(ctx, input)
    }

    async fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        self.list_tags_for_resource_op(ctx, input)
    }

    async fn provide_anomaly_feedback(
        &self,
        ctx: &RequestContext,
        input: types::ProvideAnomalyFeedbackRequest,
    ) -> Result<types::ProvideAnomalyFeedbackResponse, ServiceError> {
        self.provide_anomaly_feedback_op(ctx, input)
    }

    async fn start_commitment_purchase_analysis(
        &self,
        ctx: &RequestContext,
        input: types::StartCommitmentPurchaseAnalysisRequest,
    ) -> Result<types::StartCommitmentPurchaseAnalysisResponse, ServiceError> {
        self.start_commitment_purchase_analysis_op(ctx, input)
    }

    async fn start_cost_allocation_tag_backfill(
        &self,
        ctx: &RequestContext,
        input: types::StartCostAllocationTagBackfillRequest,
    ) -> Result<types::StartCostAllocationTagBackfillResponse, ServiceError> {
        self.start_cost_allocation_tag_backfill_op(ctx, input)
    }

    async fn start_savings_plans_purchase_recommendation_generation(
        &self,
        ctx: &RequestContext,
        input: types::StartSavingsPlansPurchaseRecommendationGenerationRequest,
    ) -> Result<types::StartSavingsPlansPurchaseRecommendationGenerationResponse, ServiceError> {
        self.start_savings_plans_purchase_recommendation_generation_op(ctx, input)
    }

    async fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<types::TagResourceResponse, ServiceError> {
        self.tag_resource_op(ctx, input)
    }

    async fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<types::UntagResourceResponse, ServiceError> {
        self.untag_resource_op(ctx, input)
    }

    async fn update_anomaly_monitor(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAnomalyMonitorRequest,
    ) -> Result<types::UpdateAnomalyMonitorResponse, ServiceError> {
        self.update_anomaly_monitor_op(ctx, input)
    }

    async fn update_anomaly_subscription(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAnomalySubscriptionRequest,
    ) -> Result<types::UpdateAnomalySubscriptionResponse, ServiceError> {
        self.update_anomaly_subscription_op(ctx, input)
    }

    async fn update_cost_allocation_tags_status(
        &self,
        ctx: &RequestContext,
        input: types::UpdateCostAllocationTagsStatusRequest,
    ) -> Result<types::UpdateCostAllocationTagsStatusResponse, ServiceError> {
        self.update_cost_allocation_tags_status_op(ctx, input)
    }

    async fn update_cost_category_definition(
        &self,
        ctx: &RequestContext,
        input: types::UpdateCostCategoryDefinitionRequest,
    ) -> Result<types::UpdateCostCategoryDefinitionResponse, ServiceError> {
        self.update_cost_category_definition_op(ctx, input)
    }
}

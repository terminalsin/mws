//! Cost Explorer through the official Rust SDK: a ledger seeded through
//! `/_aws/ce/records` plus request charges derived from real API calls,
//! grouped and filtered by dimensions, cost allocation tags (activation and
//! backfill) and cost categories; forecasts, comparisons, anomaly
//! detection with SNS alerts, and Savings Plans coverage and analyses.

use std::time::Duration;

use aws_sdk_costexplorer::error::ProvideErrorMetadata;
use aws_sdk_costexplorer::types::{
    AnalysisStatus, AnalysisType, AnomalyDateInterval, AnomalyMonitor, AnomalySubscription,
    AnomalySubscriptionFrequency, CommitmentPurchaseAnalysisConfiguration, CostAllocationTagStatus,
    CostAllocationTagStatusEntry, CostCategoryRule, CostCategoryRuleVersion, DateInterval, Dimension, DimensionValues,
    Expression, Granularity, GroupDefinition, GroupDefinitionType, Metric, MonitorDimension, MonitorType, SavingsPlans,
    SavingsPlansPurchaseAnalysisConfiguration, Subscriber, SubscriberType,
};
use aws_sdk_costexplorer::Client;
use chrono::{Datelike, NaiveDate, Utc};
use mws_e2e::Mws;
use serde_json::json;

const ACCOUNT: &str = "123456789012";
const EC2: &str = "Amazon Elastic Compute Cloud - Compute";
const S3: &str = "Amazon Simple Storage Service";

fn day(offset: i64) -> NaiveDate {
    Utc::now().date_naive() + chrono::Duration::days(offset)
}

fn interval(start: NaiveDate, end: NaiveDate) -> DateInterval {
    DateInterval::builder().start(start.to_string()).end(end.to_string()).build().unwrap()
}

fn group(kind: GroupDefinitionType, key: &str) -> GroupDefinition {
    GroupDefinition::builder().r#type(kind).key(key).build()
}

fn dims(key: Dimension, values: &[&str]) -> Expression {
    Expression::builder()
        .dimensions(
            DimensionValues::builder()
                .key(key)
                .set_values(Some(values.iter().map(|v| v.to_string()).collect()))
                .build(),
        )
        .build()
}

async fn seed(mws: &Mws, records: serde_json::Value) {
    let body = json!({ "records": records }).to_string();
    let (status, _, out) =
        mws.raw("POST", "/_aws/ce/records", &[("content-type", "application/json")], body.as_bytes()).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&out));
}

fn amount(m: Option<&aws_sdk_costexplorer::types::MetricValue>) -> f64 {
    m.and_then(|m| m.amount()).unwrap().parse().unwrap()
}

/// Ten days of EC2 ($24/day, team web) and S3 ($2.40/day, team data).
async fn seed_month(mws: &Mws) {
    let mut records = Vec::new();
    for d in -10..0 {
        let date = day(d);
        records.push(json!({
            "account": ACCOUNT, "start": date.to_string(), "end": (date + chrono::Duration::days(1)).to_string(),
            "service": EC2, "usageType": "BoxUsage:t3.large", "instanceType": "t3.large", "unit": "Hrs",
            "usageQuantity": 24.0, "cost": 24.0, "tags": {"team": "web"}
        }));
        records.push(json!({
            "account": ACCOUNT, "start": date.to_string(), "end": (date + chrono::Duration::days(1)).to_string(),
            "service": S3, "region": "eu-west-1", "usageType": "EUW1-TimedStorage-ByteHrs", "unit": "GB-Mo",
            "usageQuantity": 100.0, "cost": 2.4, "tags": {"team": "data"}
        }));
    }
    seed(mws, json!(records)).await;
}

#[tokio::test]
async fn costs_grouped_filtered_and_tagged() {
    let mws = Mws::start().await;
    let ce = Client::new(&mws.root_sdk_config().await);
    seed_month(&mws).await;

    // Daily costs by service.
    let out = ce
        .get_cost_and_usage()
        .time_period(interval(day(-10), day(0)))
        .granularity(Granularity::Daily)
        .metrics("UnblendedCost")
        .metrics("UsageQuantity")
        .group_by(group(GroupDefinitionType::Dimension, "SERVICE"))
        .send()
        .await
        .unwrap();
    let days = out.results_by_time();
    assert_eq!(days.len(), 10);
    let first = &days[0];
    assert_eq!(first.time_period().unwrap().start(), day(-10).to_string());
    let ec2 = first.groups().iter().find(|g| g.keys() == [EC2]).unwrap();
    assert_eq!(amount(ec2.metrics().unwrap().get("UnblendedCost")), 24.0);
    assert_eq!(ec2.metrics().unwrap()["UnblendedCost"].unit(), Some("USD"));
    assert_eq!(amount(ec2.metrics().unwrap().get("UsageQuantity")), 24.0);

    // A filter on region keeps S3 only.
    let out = ce
        .get_cost_and_usage()
        .time_period(interval(day(-10), day(0)))
        .granularity(Granularity::Monthly)
        .metrics("BlendedCost")
        .filter(dims(Dimension::Region, &["eu-west-1"]))
        .send()
        .await
        .unwrap();
    let total: f64 = out.results_by_time().iter().map(|r| amount(r.total().unwrap().get("BlendedCost"))).sum();
    assert!((total - 24.0).abs() < 1e-6, "{total}");

    // Dimension values.
    let values = ce
        .get_dimension_values()
        .time_period(interval(day(-10), day(0)))
        .dimension(Dimension::Service)
        .send()
        .await
        .unwrap();
    let names: Vec<_> = values.dimension_values().iter().filter_map(|v| v.value()).collect();
    assert!(names.contains(&EC2) && names.contains(&S3), "{names:?}");

    // Validation follows AWS.
    let err = ce
        .get_cost_and_usage()
        .time_period(interval(day(0), day(-1)))
        .granularity(Granularity::Daily)
        .metrics("UnblendedCost")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("ValidationException"));

    // The tag is known but inactive, so costs carry no tag value.
    let tags = ce.list_cost_allocation_tags().send().await.unwrap();
    let team = tags.cost_allocation_tags().iter().find(|t| t.tag_key() == "team").unwrap();
    assert_eq!(team.status(), &CostAllocationTagStatus::Inactive);
    let by_team = |ce: Client| async move {
        let out = ce
            .get_cost_and_usage()
            .time_period(interval(day(-10), day(0)))
            .granularity(Granularity::Monthly)
            .metrics("UnblendedCost")
            .group_by(group(GroupDefinitionType::Tag, "team"))
            .send()
            .await
            .unwrap();
        let mut keys: Vec<String> =
            out.results_by_time().iter().flat_map(|r| r.groups()).flat_map(|g| g.keys().to_vec()).collect();
        keys.sort();
        keys.dedup();
        keys
    };
    assert_eq!(by_team(ce.clone()).await, vec!["team$"]);

    // Activating applies from now on; a backfill brings older records in.
    ce.update_cost_allocation_tags_status()
        .cost_allocation_tags_status(
            CostAllocationTagStatusEntry::builder()
                .tag_key("team")
                .status(CostAllocationTagStatus::Active)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(by_team(ce.clone()).await, vec!["team$"]);
    let from = format!("{}-{:02}-01T00:00:00Z", day(-40).year(), day(-40).month());
    ce.start_cost_allocation_tag_backfill().backfill_from(&from).send().await.unwrap();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert_eq!(by_team(ce.clone()).await, vec!["team$data", "team$web"]);
    let history = ce.list_cost_allocation_tag_backfill_history().send().await.unwrap();
    assert_eq!(history.backfill_requests()[0].backfill_status().map(|s| s.as_str()), Some("SUCCEEDED"));
    let values = ce.get_tags().time_period(interval(day(-10), day(0))).tag_key("team").send().await.unwrap();
    assert_eq!(values.tags(), ["data", "web"]);

    // Comparisons need whole calendar months.
    let err = ce
        .get_cost_and_usage_comparisons()
        .baseline_time_period(interval(day(-10), day(-5)))
        .comparison_time_period(interval(day(-5), day(0)))
        .metric_for_comparison("UnblendedCost")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("ValidationException"));

    // Two months ago EC2 cost $100, last month $150 and S3 appeared.
    let this_month = day(0).with_day(1).unwrap();
    let last = (this_month - chrono::Duration::days(1)).with_day(1).unwrap();
    let before = (last - chrono::Duration::days(1)).with_day(1).unwrap();
    seed(
        &mws,
        json!([
            {"account": ACCOUNT, "start": before.to_string(), "service": EC2, "usageType": "BoxUsage:m5.large", "cost": 100.0},
            {"account": ACCOUNT, "start": last.to_string(), "service": EC2, "usageType": "BoxUsage:m5.large", "cost": 150.0},
            {"account": ACCOUNT, "start": last.to_string(), "service": S3, "usageType": "Requests-Tier1", "cost": 5.0},
        ]),
    )
    .await;
    let cmp = ce
        .get_cost_and_usage_comparisons()
        .baseline_time_period(interval(before, last))
        .comparison_time_period(interval(last, this_month))
        .metric_for_comparison("UnblendedCost")
        .filter(dims(Dimension::UsageType, &["BoxUsage:m5.large", "Requests-Tier1"]))
        .group_by(group(GroupDefinitionType::Dimension, "SERVICE"))
        .send()
        .await
        .unwrap();
    let total = &cmp.total_cost_and_usage().unwrap()["UnblendedCost"];
    assert_eq!(total.baseline_time_period_amount(), Some("100"));
    assert_eq!(total.comparison_time_period_amount(), Some("155"));
    assert_eq!(total.difference(), Some("55"));
    let drivers = ce
        .get_cost_comparison_drivers()
        .baseline_time_period(interval(before, last))
        .comparison_time_period(interval(last, this_month))
        .metric_for_comparison("UnblendedCost")
        .filter(dims(Dimension::UsageType, &["BoxUsage:m5.large", "Requests-Tier1"]))
        .send()
        .await
        .unwrap();
    let kinds: Vec<_> = drivers
        .cost_comparison_drivers()
        .iter()
        .flat_map(|d| d.cost_drivers())
        .filter_map(|d| d.r#type().map(|t| t.to_string()))
        .collect();
    assert!(kinds.iter().any(|k| k == "NEW_USAGE") && kinds.iter().any(|k| k == "USAGE_CHANGE"), "{kinds:?}");
}

#[tokio::test]
async fn cost_categories_and_forecasts() {
    let mws = Mws::start().await;
    let ce = Client::new(&mws.root_sdk_config().await);
    seed_month(&mws).await;

    let rule = |value: &str, service: &str| {
        CostCategoryRule::builder().value(value).rule(dims(Dimension::Service, &[service])).build()
    };
    let created = ce
        .create_cost_category_definition()
        .name("Platform")
        .rule_version(CostCategoryRuleVersion::CostCategoryExpressionV1)
        .rules(rule("Compute", EC2))
        .rules(rule("Storage", S3))
        .default_value("Other")
        // Categories apply from the start of the current month unless told otherwise.
        .effective_start(format!("{}-{:02}-01T00:00:00Z", day(-40).year(), day(-40).month()))
        .send()
        .await
        .unwrap();
    let arn = created.cost_category_arn().unwrap().to_string();
    let described = ce.describe_cost_category_definition().cost_category_arn(&arn).send().await.unwrap();
    assert_eq!(described.cost_category().unwrap().rules().len(), 2);
    let listed = ce.list_cost_category_definitions().send().await.unwrap();
    assert_eq!(listed.cost_category_references()[0].name(), Some("Platform"));

    let values = ce
        .get_cost_categories()
        .time_period(interval(day(-10), day(0)))
        .cost_category_name("Platform")
        .send()
        .await
        .unwrap();
    let mut vals = values.cost_category_values().to_vec();
    vals.sort();
    assert_eq!(vals, ["Compute", "Storage"]);

    let out = ce
        .get_cost_and_usage()
        .time_period(interval(day(-10), day(0)))
        .granularity(Granularity::Monthly)
        .metrics("UnblendedCost")
        .group_by(group(GroupDefinitionType::CostCategory, "Platform"))
        .send()
        .await
        .unwrap();
    let mut compute = 0.0;
    for g in out.results_by_time().iter().flat_map(|r| r.groups()) {
        if g.keys() == ["Platform$Compute"] {
            compute += amount(g.metrics().unwrap().get("UnblendedCost"));
        }
    }
    assert!((compute - 240.0).abs() < 1e-6, "{compute}");

    // Tags on the category.
    ce.tag_resource()
        .resource_arn(&arn)
        .resource_tags(
            aws_sdk_costexplorer::types::ResourceTag::builder().key("owner").value("finops").build().unwrap(),
        )
        .send()
        .await
        .unwrap();
    let tags = ce.list_tags_for_resource().resource_arn(&arn).send().await.unwrap();
    assert_eq!(tags.resource_tags()[0].value(), "finops");
    ce.delete_cost_category_definition().cost_category_arn(&arn).send().await.unwrap();
    let err = ce.describe_cost_category_definition().cost_category_arn(&arn).send().await.unwrap_err();
    assert_eq!(err.code(), Some("ResourceNotFoundException"));

    // A steady $26.40 a day forecasts about $184.80 a week.
    let forecast = ce
        .get_cost_forecast()
        .time_period(interval(day(0), day(7)))
        .metric(Metric::UnblendedCost)
        .granularity(Granularity::Daily)
        .prediction_interval_level(80)
        .send()
        .await
        .unwrap();
    let total: f64 = forecast.total().unwrap().amount().unwrap().parse().unwrap();
    assert!((total - 184.8).abs() < 1.0, "{total}");
    assert_eq!(forecast.forecast_results_by_time().len(), 7);

    let usage = ce
        .get_usage_forecast()
        .time_period(interval(day(0), day(7)))
        .metric(Metric::UsageQuantity)
        .granularity(Granularity::Daily)
        .send()
        .await
        .unwrap_err();
    assert_eq!(usage.code(), Some("UnresolvableUsageUnitException"));
}

#[tokio::test]
async fn anomalies_are_detected_and_alerted() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let ce = Client::new(&config);
    let sns = aws_sdk_sns::Client::new(&config);
    let sqs = aws_sdk_sqs::Client::new(&config);

    // An SNS topic that lets Cost Anomaly Detection publish, feeding a queue.
    let topic = sns.create_topic().name("cost-alerts").send().await.unwrap().topic_arn().unwrap().to_string();
    let policy = json!({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "costalerts.amazonaws.com"}, "Action": "SNS:Publish", "Resource": topic
    }]});
    sns.set_topic_attributes()
        .topic_arn(&topic)
        .attribute_name("Policy")
        .attribute_value(policy.to_string())
        .send()
        .await
        .unwrap();
    let queue = sqs.create_queue().queue_name("cost-alerts").send().await.unwrap().queue_url().unwrap().to_string();
    let attrs = sqs
        .get_queue_attributes()
        .queue_url(&queue)
        .attribute_names(aws_sdk_sqs::types::QueueAttributeName::QueueArn)
        .send()
        .await
        .unwrap();
    let queue_arn = attrs.attributes().unwrap()[&aws_sdk_sqs::types::QueueAttributeName::QueueArn].clone();
    let qpolicy = json!({"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": "sns.amazonaws.com"}, "Action": "sqs:SendMessage", "Resource": queue_arn,
        "Condition": {"ArnEquals": {"aws:SourceArn": topic}}
    }]});
    sqs.set_queue_attributes()
        .queue_url(&queue)
        .attributes(aws_sdk_sqs::types::QueueAttributeName::Policy, qpolicy.to_string())
        .send()
        .await
        .unwrap();
    sns.subscribe()
        .topic_arn(&topic)
        .protocol("sqs")
        .endpoint(&queue_arn)
        .attributes("RawMessageDelivery", "true")
        .send()
        .await
        .unwrap();

    let monitor = ce
        .create_anomaly_monitor()
        .anomaly_monitor(
            AnomalyMonitor::builder()
                .monitor_name("services")
                .monitor_type(MonitorType::Dimensional)
                .monitor_dimension(MonitorDimension::Service)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap()
        .monitor_arn()
        .to_string();
    let err = ce
        .create_anomaly_subscription()
        .anomaly_subscription(
            AnomalySubscription::builder()
                .monitor_arn_list(&monitor)
                .subscribers(Subscriber::builder().r#type(SubscriberType::Sns).address(&topic).build())
                .frequency(AnomalySubscriptionFrequency::Daily)
                .subscription_name("bad")
                .threshold(10.0)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("ValidationException"));
    ce.create_anomaly_subscription()
        .anomaly_subscription(
            AnomalySubscription::builder()
                .monitor_arn_list(&monitor)
                .subscribers(Subscriber::builder().r#type(SubscriberType::Sns).address(&topic).build())
                .frequency(AnomalySubscriptionFrequency::Immediate)
                .subscription_name("immediate")
                .threshold(50.0)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    // Twenty quiet days of Lambda, then a $300 spike yesterday.
    let mut records = Vec::new();
    for d in -21..0 {
        let cost = if d == -1 { 310.0 } else { 10.0 + (d % 3) as f64 };
        records.push(json!({"account": ACCOUNT, "start": day(d).to_string(), "end": day(d + 1).to_string(),
            "service": "AWS Lambda", "usageType": "Lambda-GB-Second", "cost": cost}));
    }
    seed(&mws, json!(records)).await;

    let anomalies = ce
        .get_anomalies()
        .monitor_arn(&monitor)
        .date_interval(AnomalyDateInterval::builder().start_date(day(-30).to_string()).build().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(anomalies.anomalies().len(), 1, "{anomalies:?}");
    let a = &anomalies.anomalies()[0];
    assert_eq!(a.dimension_value(), Some("AWS Lambda"));
    assert_eq!(a.anomaly_start_date(), Some(day(-1).to_string().as_str()));
    assert!(a.impact().unwrap().total_impact() > 290.0);
    assert_eq!(a.root_causes()[0].usage_type(), Some("Lambda-GB-Second"));

    // The immediate subscription got the alert.
    let msgs = sqs.receive_message().queue_url(&queue).wait_time_seconds(2).send().await.unwrap();
    let body: serde_json::Value = serde_json::from_str(msgs.messages()[0].body().unwrap()).unwrap();
    assert_eq!(body["anomalyId"], a.anomaly_id());
    assert_eq!(body["dimensionalValue"], "AWS Lambda");

    ce.provide_anomaly_feedback()
        .anomaly_id(a.anomaly_id())
        .feedback(aws_sdk_costexplorer::types::AnomalyFeedbackType::Yes)
        .send()
        .await
        .unwrap();
    let again = ce
        .get_anomalies()
        .date_interval(AnomalyDateInterval::builder().start_date(day(-30).to_string()).build().unwrap())
        .feedback(aws_sdk_costexplorer::types::AnomalyFeedbackType::Yes)
        .send()
        .await
        .unwrap();
    assert_eq!(again.anomalies().len(), 1);

    let monitors = ce.get_anomaly_monitors().send().await.unwrap();
    // Lambda, plus the request charges of this test's SQS and Cost Explorer calls.
    assert_eq!(monitors.anomaly_monitors()[0].dimensional_value_count(), 3);
    ce.delete_anomaly_monitor().monitor_arn(&monitor).send().await.unwrap();
    let err = ce.get_anomaly_monitors().monitor_arn_list(&monitor).send().await.unwrap_err();
    assert_eq!(err.code(), Some("UnknownMonitorException"));
}

#[tokio::test]
async fn request_charges_are_derived_from_api_calls() {
    let mws = Mws::start().await;
    let config = mws.root_sdk_config().await;
    let ce = Client::new(&config);
    let kms = aws_sdk_kms::Client::new(&config);
    let key = kms.create_key().send().await.unwrap().key_metadata().unwrap().key_id().to_string();
    for _ in 0..4 {
        kms.encrypt().key_id(&key).plaintext(aws_sdk_kms::primitives::Blob::new("x")).send().await.unwrap();
    }
    let out = ce
        .get_cost_and_usage()
        .time_period(interval(day(0), day(1)))
        .granularity(Granularity::Daily)
        .metrics("UnblendedCost")
        .metrics("UsageQuantity")
        .group_by(group(GroupDefinitionType::Dimension, "SERVICE"))
        .send()
        .await
        .unwrap();
    let groups = out.results_by_time()[0].groups();
    let kms_group = groups.iter().find(|g| g.keys() == ["AWS Key Management Service"]).expect("KMS charges");
    let requests = amount(kms_group.metrics().unwrap().get("UsageQuantity"));
    assert_eq!(requests, 5.0);
    let cost = amount(kms_group.metrics().unwrap().get("UnblendedCost"));
    assert!((cost - 5.0 * 0.03 / 10_000.0).abs() < 1e-9, "{cost}");
}

#[tokio::test]
async fn savings_plans_and_reservations() {
    let mws = Mws::start().await;
    let ce = Client::new(&mws.root_sdk_config().await);
    seed_month(&mws).await;

    let coverage = ce
        .get_savings_plans_coverage()
        .time_period(interval(day(-10), day(0)))
        .granularity(Granularity::Monthly)
        .send()
        .await
        .unwrap();
    let od: f64 = coverage
        .savings_plans_coverages()
        .iter()
        .map(|c| c.coverage().unwrap().on_demand_cost().unwrap().parse::<f64>().unwrap())
        .sum();
    assert!((od - 240.0).abs() < 1e-6, "{od}");

    let ri = ce.get_reservation_coverage().time_period(interval(day(-10), day(0))).send().await.unwrap();
    let hours: f64 = ri.total().unwrap().coverage_hours().unwrap().on_demand_hours().unwrap().parse().unwrap();
    assert_eq!(hours, 240.0);

    let err = ce.get_savings_plans_utilization().time_period(interval(day(-10), day(0))).send().await.unwrap_err();
    assert_eq!(err.code(), Some("DataUnavailableException"));
    let util = ce.get_reservation_utilization().time_period(interval(day(-10), day(0))).send().await.unwrap();
    assert!(util.utilizations_by_time().is_empty());

    let rec = ce
        .get_savings_plans_purchase_recommendation()
        .savings_plans_type(aws_sdk_costexplorer::types::SupportedSavingsPlansType::ComputeSp)
        .term_in_years(aws_sdk_costexplorer::types::TermInYears::OneYear)
        .payment_option(aws_sdk_costexplorer::types::PaymentOption::NoUpfront)
        .lookback_period_in_days(aws_sdk_costexplorer::types::LookbackPeriodInDays::SevenDays)
        .send()
        .await
        .unwrap();
    assert!(rec.metadata().unwrap().recommendation_id().is_some());

    let generation = ce.start_savings_plans_purchase_recommendation_generation().send().await.unwrap();
    let err = ce.start_savings_plans_purchase_recommendation_generation().send().await.unwrap_err();
    assert_eq!(err.code(), Some("GenerationExistsException"));
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let list = ce.list_savings_plans_purchase_recommendation_generation().send().await.unwrap();
    assert_eq!(list.generation_summary_list()[0].recommendation_id(), generation.recommendation_id());

    let started = ce
        .start_commitment_purchase_analysis()
        .commitment_purchase_analysis_configuration(
            CommitmentPurchaseAnalysisConfiguration::builder()
                .savings_plans_purchase_analysis_configuration(
                    SavingsPlansPurchaseAnalysisConfiguration::builder()
                        .analysis_type(AnalysisType::CustomCommitment)
                        .look_back_time_period(interval(day(-7), day(0)))
                        .savings_plans_to_add(
                            SavingsPlans::builder()
                                .savings_plans_type(aws_sdk_costexplorer::types::SupportedSavingsPlansType::ComputeSp)
                                .term_in_years(aws_sdk_costexplorer::types::TermInYears::OneYear)
                                .payment_option(aws_sdk_costexplorer::types::PaymentOption::NoUpfront)
                                .savings_plans_commitment(0.5)
                                .build(),
                        )
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let analysis = ce.get_commitment_purchase_analysis().analysis_id(started.analysis_id()).send().await.unwrap();
    assert_eq!(analysis.analysis_status(), &AnalysisStatus::Succeeded);
    let details = analysis.analysis_details().unwrap().savings_plans_purchase_analysis_details().unwrap();
    assert_eq!(details.current_average_hourly_on_demand_spend(), Some("1"));
    let saved: f64 = details.estimated_savings_amount().unwrap().parse().unwrap();
    assert!(saved > 0.0, "{details:?}");
    let err = ce
        .get_commitment_purchase_analysis()
        .analysis_id("00000000-0000-0000-0000-000000000000")
        .send()
        .await
        .unwrap_err();
    assert_eq!(err.code(), Some("AnalysisNotFoundException"));
}

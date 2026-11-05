//! CloudWatch resource types.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde_json::{json, Map, Value};

use super::{bools, copy, document, gone_ok, numbers, s, Created, Cx, HResult, Props, Provider};

pub fn register(m: &mut BTreeMap<&'static str, Arc<dyn Provider>>) {
    m.insert("AWS::CloudWatch::Alarm", Arc::new(Alarm));
    m.insert("AWS::CloudWatch::CompositeAlarm", Arc::new(CompositeAlarm));
    m.insert("AWS::CloudWatch::Dashboard", Arc::new(Dashboard));
}

const ALARM_FIELDS: &[&str] = &[
    "AlarmDescription",
    "ActionsEnabled",
    "OKActions",
    "AlarmActions",
    "InsufficientDataActions",
    "MetricName",
    "Namespace",
    "Statistic",
    "ExtendedStatistic",
    "Dimensions",
    "Period",
    "Unit",
    "EvaluationPeriods",
    "DatapointsToAlarm",
    "Threshold",
    "ComparisonOperator",
    "TreatMissingData",
    "EvaluateLowSampleCountPercentile",
    "Metrics",
    "ThresholdMetricId",
];

struct Alarm;

impl Alarm {
    async fn put(&self, cx: &Cx<'_>, name: &str, props: &Props) -> HResult<()> {
        let mut input = Map::new();
        input.insert("AlarmName".into(), json!(name));
        copy(props, &mut input, ALARM_FIELDS);
        numbers(&mut input, &["Period", "EvaluationPeriods", "DatapointsToAlarm", "Threshold"]);
        bools(&mut input, &["ActionsEnabled"]);
        if let Some(Value::Array(metrics)) = input.get_mut("Metrics") {
            for m in metrics.iter_mut() {
                if let Some(o) = m.as_object_mut() {
                    numbers(o, &["Period"]);
                    bools(o, &["ReturnData"]);
                    if let Some(Value::Object(stat)) = o.get_mut("MetricStat") {
                        numbers(stat, &["Period"]);
                    }
                }
            }
        }
        let tags = cx.tags(props);
        if !tags.is_empty() {
            input.insert("Tags".into(), json!(tags));
        }
        cx.call("monitoring", "PutMetricAlarm", Value::Object(input)).await.map(|_| ())
    }
}

#[async_trait::async_trait]
impl Provider for Alarm {
    fn create_only(&self) -> &'static [&'static str] {
        &["AlarmName"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["ComparisonOperator", "EvaluationPeriods"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "AlarmName").unwrap_or_else(|| cx.physical_name(255));
        self.put(cx, &name, props).await?;
        Ok(Created::new(&name).attr("Arn", cx.arn("cloudwatch", &format!("alarm:{name}"))))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        self.put(cx, name, new).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("monitoring", "DeleteAlarms", json!({"AlarmNames": [name]})).await)
    }
}

struct CompositeAlarm;

#[async_trait::async_trait]
impl Provider for CompositeAlarm {
    fn create_only(&self) -> &'static [&'static str] {
        &["AlarmName"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["AlarmRule"]
    }
    fn attributes(&self) -> &'static [&'static str] {
        &["Arn"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "AlarmName").unwrap_or_else(|| cx.physical_name(255));
        self.update(cx, &name, &Props::new(), props, &Props::new()).await?;
        Ok(Created::new(&name).attr("Arn", cx.arn("cloudwatch", &format!("alarm:{name}"))))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        let mut input = Map::new();
        input.insert("AlarmName".into(), json!(name));
        copy(
            new,
            &mut input,
            &[
                "AlarmRule",
                "AlarmDescription",
                "ActionsEnabled",
                "AlarmActions",
                "OKActions",
                "InsufficientDataActions",
                "ActionsSuppressor",
                "ActionsSuppressorWaitPeriod",
                "ActionsSuppressorExtensionPeriod",
            ],
        );
        numbers(&mut input, &["ActionsSuppressorWaitPeriod", "ActionsSuppressorExtensionPeriod"]);
        bools(&mut input, &["ActionsEnabled"]);
        cx.call("monitoring", "PutCompositeAlarm", Value::Object(input)).await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("monitoring", "DeleteAlarms", json!({"AlarmNames": [name]})).await)
    }
}

struct Dashboard;

#[async_trait::async_trait]
impl Provider for Dashboard {
    fn create_only(&self) -> &'static [&'static str] {
        &["DashboardName"]
    }
    fn required(&self) -> &'static [&'static str] {
        &["DashboardBody"]
    }

    async fn create(&self, cx: &Cx<'_>, props: &Props) -> HResult<Created> {
        let name = s(props, "DashboardName").unwrap_or_else(|| cx.physical_name(255));
        cx.call(
            "monitoring",
            "PutDashboard",
            json!({"DashboardName": name, "DashboardBody": document(props, "DashboardBody").unwrap_or_default()}),
        )
        .await?;
        Ok(Created::new(name))
    }

    async fn update(&self, cx: &Cx<'_>, name: &str, _old: &Props, new: &Props, attrs: &Props) -> HResult<Props> {
        cx.call(
            "monitoring",
            "PutDashboard",
            json!({"DashboardName": name, "DashboardBody": document(new, "DashboardBody").unwrap_or_default()}),
        )
        .await?;
        Ok(attrs.clone())
    }

    async fn delete(&self, cx: &Cx<'_>, name: &str, _props: &Props, _attrs: &Props) -> HResult<()> {
        gone_ok(cx.call("monitoring", "DeleteDashboards", json!({"DashboardNames": [name]})).await)
    }
}

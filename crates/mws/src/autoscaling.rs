//! EC2 Auto Scaling's links to other services: notifications to SNS and
//! SQS, events to EventBridge, group metrics and target tracking alarms in
//! CloudWatch, alarm actions back into Auto Scaling, and load balancer
//! registrations, attachment checks, deregistration delays and health
//! checks from Elastic Load Balancing.

use std::sync::Arc;

use mws_autoscaling::{
    AlarmManager, AlarmTrigger, AutoScaling, AutoScalingEvent, EventSink, GroupMetric, ManagedAlarm, MetricSink,
    NotificationSink, TrafficSink, TrafficSourceInfo, TrafficTarget,
};
use mws_cloudwatch::CloudWatch;
use mws_core::{RequestContext, Service};
use mws_elb::Elb;
use mws_events::{Events, ServiceEvent};
use mws_sns::Sns;
use mws_sqs::Sqs;
use serde_json::json;

/// Wire Auto Scaling to the services it calls.
pub(crate) fn wire(
    autoscaling: &AutoScaling,
    sns: &Sns,
    sqs: &Sqs,
    events: &Events,
    cloudwatch: &CloudWatch,
    elb: &Elb,
) {
    autoscaling.set_notification_sink(Arc::new(Notifications { sns: sns.clone(), sqs: sqs.clone() }));
    autoscaling.set_event_sink(Arc::new(EventsSink(events.clone())));
    autoscaling.set_metric_sink(Arc::new(Metrics(cloudwatch.clone())));
    autoscaling.set_alarm_manager(Arc::new(Alarms(cloudwatch.clone())));
    autoscaling.set_traffic_sink(Arc::new(Traffic(elb.clone())));
    cloudwatch.register_action_target("autoscaling", Arc::new(AlarmActions(autoscaling.clone())));
}

fn spawn<F>(what: &'static str, f: F)
where
    F: std::future::Future<Output = Result<serde_json::Value, mws_core::ServiceError>> + Send + 'static,
{
    if tokio::runtime::Handle::try_current().is_ok() {
        tokio::spawn(async move {
            if let Err(e) = f.await {
                tracing::warn!("Auto Scaling {what} failed: {} {}", e.code, e.message);
            }
        });
    }
}

/// Notification configurations and lifecycle hook targets: SNS topics and
/// SQS queues. Auto Scaling sends with its service-linked role (or the
/// hook's role), so the target's policy is not consulted.
struct Notifications {
    sns: Sns,
    sqs: Sqs,
}

impl NotificationSink for Notifications {
    fn send(
        &self,
        ctx: &RequestContext,
        target_arn: &str,
        _role_arn: Option<&str>,
        subject: Option<&str>,
        message: &str,
        _source_arn: &str,
    ) -> Result<(), String> {
        let service = target_arn.split(':').nth(2).unwrap_or_default();
        let region = target_arn.split(':').nth(3).unwrap_or_default().to_string();
        let ctx = RequestContext { region: if region.is_empty() { ctx.region.clone() } else { region }, ..ctx.clone() };
        match service {
            "sns" => {
                let mut request = json!({ "TopicArn": target_arn, "Message": message });
                if let Some(s) = subject {
                    request["Subject"] = json!(s);
                }
                let sns = self.sns.clone();
                spawn("SNS notification", async move { sns.invoke(ctx, "Publish", request).await });
                Ok(())
            }
            "sqs" => {
                let url = Sqs::queue_url_for(&ctx, target_arn).ok_or("The specified queue does not exist.")?;
                let request = json!({ "QueueUrl": url, "MessageBody": message });
                let sqs = self.sqs.clone();
                spawn("SQS notification", async move { sqs.invoke(ctx, "SendMessage", request).await });
                Ok(())
            }
            other => Err(format!("Notification targets of type {other} are not supported")),
        }
    }
}

struct EventsSink(Events);

impl EventSink for EventsSink {
    fn put(&self, ctx: &RequestContext, e: AutoScalingEvent) {
        let ctx = RequestContext { region: e.region.clone(), ..ctx.clone() };
        self.0.put_service_event(
            &ctx,
            ServiceEvent {
                partition: ctx.partition.clone(),
                account: e.account,
                region: e.region,
                source: "aws.autoscaling".into(),
                detail_type: e.detail_type,
                resources: e.resources,
                detail: e.detail,
                time: e.time,
            },
        );
    }
}

/// `AWS/AutoScaling` group metrics.
struct Metrics(CloudWatch);

impl MetricSink for Metrics {
    fn publish(&self, metrics: Vec<GroupMetric>) {
        for m in metrics {
            self.0.put_metric_as_service(mws_cloudwatch::ServiceMetric {
                account: m.account,
                region: m.region,
                namespace: "AWS/AutoScaling".into(),
                metric_name: m.metric_name,
                dimensions: vec![("AutoScalingGroupName".into(), m.group)],
                unit: Some("None".into()),
                timestamp: m.timestamp,
                values: vec![(m.value, 1.0)],
            });
        }
    }
}

/// Target tracking alarms, created in CloudWatch as the service-linked
/// role.
struct Alarms(CloudWatch);

#[async_trait::async_trait]
impl AlarmManager for Alarms {
    async fn put_alarm(&self, ctx: &RequestContext, a: &ManagedAlarm) -> Result<String, String> {
        let mut request = json!({
            "AlarmName": a.name,
            "AlarmDescription": a.description,
            "Namespace": a.namespace,
            "MetricName": a.metric_name,
            "Dimensions": a.dimensions.iter().map(|(n, v)| json!({"Name": n, "Value": v})).collect::<Vec<_>>(),
            "Statistic": a.statistic,
            "Period": a.period,
            "EvaluationPeriods": a.evaluation_periods,
            "DatapointsToAlarm": a.datapoints_to_alarm,
            "Threshold": a.threshold,
            "ComparisonOperator": a.comparison_operator,
            "AlarmActions": a.alarm_actions,
        });
        if let Some(u) = &a.unit {
            request["Unit"] = json!(u);
        }
        if !a.metrics.is_empty() {
            // A metric math alarm: the queries replace the single metric.
            let queries: Vec<serde_json::Value> = a
                .metrics
                .iter()
                .map(|q| {
                    let mut v = json!({ "Id": q.id });
                    if let Some(e) = &q.expression {
                        v["Expression"] = json!(e);
                    }
                    if let Some(l) = &q.label {
                        v["Label"] = json!(l);
                    }
                    if let Some(r) = q.return_data {
                        v["ReturnData"] = json!(r);
                    }
                    if let Some(m) = &q.metric {
                        let mut stat = json!({
                            "Metric": {
                                "Namespace": m.namespace,
                                "MetricName": m.metric_name,
                                "Dimensions": m.dimensions.iter().map(|(n, v)| json!({"Name": n, "Value": v})).collect::<Vec<_>>(),
                            },
                            "Stat": m.stat,
                            "Period": m.period,
                        });
                        if let Some(u) = &m.unit {
                            stat["Unit"] = json!(u);
                        }
                        v["MetricStat"] = stat;
                    } else {
                        v["Period"] = json!(a.period);
                    }
                    v
                })
                .collect();
            if let Some(o) = request.as_object_mut() {
                for k in ["Namespace", "MetricName", "Dimensions", "Statistic", "Period", "Unit"] {
                    o.remove(k);
                }
            }
            request["Metrics"] = json!(queries);
        }
        self.0.invoke(ctx.clone(), "PutMetricAlarm", request).await.map_err(|e| e.message)?;
        Ok(format!("arn:{}:cloudwatch:{}:{}:alarm:{}", ctx.partition, ctx.region, ctx.caller.account_id, a.name))
    }

    async fn delete_alarms(&self, ctx: &RequestContext, names: &[String]) {
        for chunk in names.chunks(100) {
            if let Err(e) = self.0.invoke(ctx.clone(), "DeleteAlarms", json!({ "AlarmNames": chunk })).await {
                tracing::warn!("Auto Scaling could not delete its alarms: {}", e.message);
            }
        }
    }
}

/// CloudWatch alarm actions naming scaling policies.
struct AlarmActions(AutoScaling);

impl mws_cloudwatch::AlarmActionTarget for AlarmActions {
    fn run(&self, _ctx: &RequestContext, a: mws_cloudwatch::AlarmAction) -> Result<(), String> {
        if a.state != "ALARM" {
            return Ok(());
        }
        if !a.action_arn.contains(":scalingPolicy:") {
            return Err(format!("{} is not a scaling policy", a.action_arn));
        }
        let trigger = AlarmTrigger {
            policy_arn: a.action_arn,
            alarm_name: a.alarm_name,
            alarm_arn: a.alarm_arn,
            account: a.account,
            region: a.region,
            threshold: a.threshold,
            metric_value: a.metric_value,
        };
        let me = self.0.clone();
        if tokio::runtime::Handle::try_current().is_ok() {
            tokio::spawn(async move {
                if let Err(e) = me.alarm_triggered(trigger).await {
                    tracing::warn!("Auto Scaling alarm action failed: {e}");
                }
            });
        }
        Ok(())
    }
}

/// Load balancer registrations, as Elastic Load Balancing API calls.
struct Traffic(Elb);

impl Traffic {
    fn call(&self, ctx: &RequestContext, target: &TrafficTarget, ids: &[String], register: bool) -> Result<(), String> {
        let ctx = ctx.clone();
        match target {
            TrafficTarget::TargetGroup(arn) => {
                let request = json!({
                    "TargetGroupArn": arn,
                    "Targets": ids.iter().map(|i| json!({"Id": i})).collect::<Vec<_>>(),
                });
                let op = if register { "RegisterTargets" } else { "DeregisterTargets" };
                let elb = self.0.clone();
                spawn("target registration", async move { elb.invoke(ctx, op, request).await });
                Ok(())
            }
            TrafficTarget::ClassicLoadBalancer(name) => {
                let request = json!({
                    "LoadBalancerName": name,
                    "Instances": ids.iter().map(|i| json!({"InstanceId": i})).collect::<Vec<_>>(),
                });
                let op =
                    if register { "RegisterInstancesWithLoadBalancer" } else { "DeregisterInstancesFromLoadBalancer" };
                let classic = self.0.classic();
                spawn("load balancer registration", async move { classic.invoke(ctx, op, request).await });
                Ok(())
            }
            TrafficTarget::LatticeTargetGroup(arn) => {
                Err(format!("VPC Lattice is not emulated; {arn} gets no targets"))
            }
        }
    }
}

impl TrafficSink for Traffic {
    fn register(&self, ctx: &RequestContext, target: &TrafficTarget, ids: &[String]) -> Result<(), String> {
        self.call(ctx, target, ids, true)
    }

    fn deregister(&self, ctx: &RequestContext, target: &TrafficTarget, ids: &[String]) -> Result<(), String> {
        self.call(ctx, target, ids, false)
    }

    /// Target groups and Classic Load Balancers with their health, read
    /// from ELB's state.
    fn describe(&self, account: &str, region: &str, target: &TrafficTarget) -> Option<TrafficSourceInfo> {
        match target {
            TrafficTarget::TargetGroup(arn) => {
                let tg = self.0.target_group(account, region, arn)?;
                Some(TrafficSourceInfo {
                    vpc_id: tg.vpc_id,
                    instance_targets: tg.target_type == "instance",
                    in_use: !tg.load_balancer_arns.is_empty(),
                    drain_seconds: tg.deregistration_delay_seconds,
                    unhealthy: tg.targets.into_iter().filter(|t| t.state == "unhealthy").map(|t| t.id).collect(),
                })
            }
            TrafficTarget::ClassicLoadBalancer(name) => {
                let lb = self.0.classic_load_balancer(account, region, name)?;
                Some(TrafficSourceInfo {
                    vpc_id: lb.vpc_id,
                    instance_targets: true,
                    in_use: true,
                    drain_seconds: lb.connection_draining_seconds.unwrap_or(0),
                    // Still registering is not a failure.
                    unhealthy: lb
                        .instances
                        .into_iter()
                        .filter(|i| i.state == "OutOfService" && i.reason_code == "Instance")
                        .map(|i| i.instance_id)
                        .collect(),
                })
            }
            TrafficTarget::LatticeTargetGroup(_) => None,
        }
    }
}

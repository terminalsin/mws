//! What EC2 reports on its own: `EC2 Instance State-change Notification`
//! events to EventBridge, `AWS/EC2` metrics to CloudWatch, and how long
//! instances on the metadata backend take to change state.

use std::sync::Arc;

use mws_cloudwatch::CloudWatch;
use mws_core::{ApiCall, RequestContext, RequestObserver};
use mws_ec2::{Ec2, InstanceMetric, InstanceStateChange, MetricSink, StateChangeSink};
use mws_events::{Events, ServiceEvent};
use serde_json::json;

/// How long a metadata-backend instance takes to finish a transition
/// (`MWS_EC2_TRANSITION_MS`, milliseconds; `0` settles at once, as does
/// `MWS_ASYNC_DELAY_MS=0` when this is unset).
const DEFAULT_TRANSITION_MS: u64 = 1000;

/// Wire EC2's events and metrics. The returned observer tells EC2 the
/// emulated time of every request, so metric periods close when the clock
/// moves even if nothing calls EC2.
pub(crate) fn wire(ec2: &Ec2, events: &Events, cloudwatch: &CloudWatch) -> Arc<dyn RequestObserver> {
    let ms = std::env::var("MWS_EC2_TRANSITION_MS")
        .ok()
        .and_then(|v| {
            v.trim().parse::<u64>().ok().or_else(|| {
                tracing::warn!("MWS_EC2_TRANSITION_MS {v:?} is not a number of milliseconds; using the default");
                None
            })
        })
        .map(std::time::Duration::from_millis)
        .unwrap_or_else(|| mws_core::settle::window(std::time::Duration::from_millis(DEFAULT_TRANSITION_MS)));
    ec2.set_transition_delay(ms);
    ec2.set_state_change_sink(Arc::new(StateChanges(events.clone())));
    ec2.set_metric_sink(Arc::new(Metrics(cloudwatch.clone())));
    Arc::new(Clock(ec2.clone()))
}

struct StateChanges(Events);

impl StateChangeSink for StateChanges {
    fn put(&self, ctx: &RequestContext, e: InstanceStateChange) {
        self.0.put_service_event(
            ctx,
            ServiceEvent {
                partition: e.partition,
                account: e.account,
                region: e.region,
                source: "aws.ec2".into(),
                detail_type: "EC2 Instance State-change Notification".into(),
                resources: vec![e.instance_arn],
                detail: json!({ "instance-id": e.instance_id, "state": e.state }),
                time: e.time,
            },
        );
    }
}

/// `AWS/EC2` metrics.
struct Metrics(CloudWatch);

impl MetricSink for Metrics {
    fn publish(&self, metrics: Vec<InstanceMetric>) {
        for m in metrics {
            self.0.put_metric_as_service(mws_cloudwatch::ServiceMetric {
                account: m.account,
                region: m.region,
                namespace: "AWS/EC2".into(),
                metric_name: m.metric_name.into(),
                dimensions: m.dimensions,
                unit: Some(m.unit.into()),
                timestamp: m.timestamp,
                values: vec![(m.value, 1.0)],
            });
        }
    }
}

struct Clock(Ec2);

impl RequestObserver for Clock {
    fn observe(&self, call: &ApiCall) {
        self.0.observe_time(call.at);
    }
}

//! What other MWS services do to EventBridge directly, where AWS couples
//! them: AWS services (S3 with EventBridge notifications, ...) sending
//! their events to an account's default event bus, and the scheduler that
//! fires scheduled rules.

use std::time::Duration;

use mws_core::RequestContext;
use serde_json::Value;

use crate::ingest::envelope;
use crate::names::BusRef;
use crate::schedule::Schedule;
use crate::Events;

/// An event an AWS service sends to an account's default event bus.
#[derive(Debug, Clone)]
pub struct ServiceEvent {
    pub partition: String,
    pub account: String,
    pub region: String,
    /// e.g. `aws.s3`.
    pub source: String,
    pub detail_type: String,
    pub resources: Vec<String>,
    pub detail: Value,
    pub time: chrono::DateTime<chrono::Utc>,
}

/// Another service whose events come due with the emulated clock rather
/// than a request (SSM parameter policies, ...). The scheduler asks it every
/// second.
pub trait ClockSource: Send + Sync {
    /// The events due by `now`, each returned once.
    fn due_events(&self, now: chrono::DateTime<chrono::Utc>) -> Vec<ServiceEvent>;
}

impl Events {
    /// Put an AWS service's event on the account's default bus, where it
    /// matches rules and reaches their targets like any other. Returns the
    /// event id. `ctx` is the request that caused the event.
    pub fn put_service_event(&self, ctx: &RequestContext, e: ServiceEvent) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let event = envelope(&id, &e.detail_type, &e.source, &e.account, e.time, &e.region, &e.resources, e.detail);
        let bus = BusRef { partition: e.partition, account: e.account, region: e.region, name: "default".into() };
        self.ingest(ctx, &bus, &event, None);
        id
    }

    /// Fire scheduled rules as their schedules come due, checking every
    /// second against the emulated clock.
    pub(crate) async fn run_scheduler(&self) {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            self.fire_schedules();
            self.poll_clock_sources();
        }
    }

    fn poll_clock_sources(&self) {
        let Some(template) = self.template() else { return };
        let now = self.now();
        let sources = self.inner.clock_sources.read().expect("clock source lock poisoned").clone();
        for source in sources {
            for e in source.due_events(now) {
                let ctx = RequestContext { region: e.region.clone(), ..self.delivery_ctx(&template) };
                self.put_service_event(&ctx, e);
            }
        }
    }

    fn fire_schedules(&self) {
        let Some(template) = self.template() else { return };
        let now = self.now();
        let mut due = Vec::new();
        {
            let mut st = self.lock();
            for (key, region) in st.regions.iter_mut() {
                let Some((account, region_name)) = key.split_once('/') else { continue };
                let Some(bus) = region.buses.get_mut("default") else { continue };
                let partition = bus.arn.split(':').nth(1).unwrap_or("aws").to_string();
                for rule in bus.rules.values_mut() {
                    let Some(schedule) = rule.schedule_expression.as_deref().and_then(Schedule::parse) else {
                        continue;
                    };
                    let after = rule.schedule_checked.unwrap_or(rule.created_at);
                    rule.schedule_checked = Some(now);
                    if !rule.enabled() || rule.targets.is_empty() {
                        continue;
                    }
                    for t in schedule.fires_between(rule.created_at, after, now, 100) {
                        due.push((partition.clone(), account.to_string(), region_name.to_string(), rule.clone(), t));
                    }
                }
            }
        }
        for (partition, account, region, rule, time) in due {
            let bus = BusRef { partition, account: account.clone(), region: region.clone(), name: "default".into() };
            let id = uuid::Uuid::new_v4().to_string();
            let event = envelope(
                &id,
                "Scheduled Event",
                "aws.events",
                &account,
                time,
                &region,
                std::slice::from_ref(&rule.arn),
                Value::Object(Default::default()),
            );
            let ctx = RequestContext { region: region.clone(), ..self.delivery_ctx(&template) };
            for target in &rule.targets {
                self.spawn_delivery(&ctx, &bus, &rule, target.clone(), event.clone(), now, 0);
            }
        }
    }
}

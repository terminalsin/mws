//! Systems Manager's EventBridge events for Run Command, Automation, State
//! Manager, compliance and change calendars. Systems Manager queues them
//! as they happen; the composition root drains the queue with
//! [`Ssm::take_events`] (every second, as an EventBridge clock source) and
//! puts each on the account's default bus with source `aws.ssm`.

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::Ssm;

/// At most this many events wait for the composition root; older ones are
/// dropped first (nothing drains the queue when EventBridge is absent).
const MAX_QUEUED: usize = 10_000;

/// One event for the default bus.
#[derive(Debug, Clone, PartialEq)]
pub struct SsmEvent {
    pub partition: String,
    pub account: String,
    pub region: String,
    /// For example `EC2 Command Status-change Notification`.
    pub detail_type: String,
    pub resources: Vec<String>,
    pub detail: Value,
    pub time: DateTime<Utc>,
}

/// Times as SSM writes them in Run Command and State Manager events.
pub(crate) fn iso(t: DateTime<Utc>) -> String {
    t.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Times as Automation writes them (`Nov 29, 2016 6:16:59 PM`).
pub(crate) fn automation_time(t: DateTime<Utc>) -> String {
    t.format("%b %-d, %Y %-I:%M:%S %p").to_string()
}

impl Ssm {
    /// The partition events are reported in: the most recent request's.
    pub(crate) fn partition(&self) -> String {
        self.template().map(|t| t.partition).unwrap_or_else(|| "aws".into())
    }

    pub(crate) fn emit(&self, account: &str, region: &str, detail_type: &str, resources: Vec<String>, detail: Value) {
        let time = Utc::now()
            + chrono::Duration::milliseconds(self.clock_offset_ms.load(std::sync::atomic::Ordering::Relaxed));
        let mut q = self.events.lock().expect("SSM event queue lock poisoned");
        if q.len() >= MAX_QUEUED {
            q.remove(0);
        }
        q.push(SsmEvent {
            partition: self.partition(),
            account: account.to_string(),
            region: region.to_string(),
            detail_type: detail_type.to_string(),
            resources,
            detail,
            time,
        });
    }

    /// The events that happened since the last call, oldest first.
    pub fn take_events(&self) -> Vec<SsmEvent> {
        std::mem::take(&mut *self.events.lock().expect("SSM event queue lock poisoned"))
    }

    /// Report "Calendar State Change" for every change calendar whose state
    /// changed since the last check (`now` is the emulated clock).
    pub(crate) fn check_calendars(&self, now: DateTime<Utc>) {
        let mut seen = Vec::new();
        {
            let st = self.lock();
            for (key, region) in &st.regions {
                let Some((account, region_name)) = key.split_once('/') else { continue };
                for doc in region.documents.values().filter(|d| d.document_type == "ChangeCalendar") {
                    let (open, next) = crate::nodes::calendar_state(&doc.default().content, now);
                    seen.push((account.to_string(), region_name.to_string(), doc.name.clone(), open, next));
                }
            }
        }
        let mut known = self.calendar_states.lock().expect("SSM calendar lock poisoned");
        let mut current = std::collections::HashMap::new();
        for (account, region, name, open, next) in seen {
            let key = format!("{account}/{region}/{name}");
            let before = known.get(&key).copied();
            current.insert(key, open);
            if before.is_none_or(|b| b == open) {
                continue;
            }
            let arn = crate::documents::arn(&self.partition(), &region, &account, &name);
            let mut detail = serde_json::json!({
                "state": if open { "OPEN" } else { "CLOSED" },
                "atTime": now.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            });
            if let Some(n) = next {
                detail["nextTransitionTime"] = Value::String(n.format("%Y-%m-%dT%H:%M:%SZ").to_string());
            }
            self.emit(&account, &region, "Calendar State Change", vec![arn], detail);
        }
        *known = current;
    }
}

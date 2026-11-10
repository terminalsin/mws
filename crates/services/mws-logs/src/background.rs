//! Work CloudWatch Logs does after the call that asked for it returns:
//! Logs Insights queries (`Scheduled` → `Running` → `Complete`), export
//! tasks (`PENDING` → `RUNNING` → `COMPLETED`) and import tasks
//! (`IN_PROGRESS` → `COMPLETED`). Each runs in its own task, taking a
//! few seconds of real time in all (long enough that concurrency limits
//! hold while a client starts many), and times out against the emulated
//! clock.

use std::time::Duration;

use crate::Logs;

/// How long a query stays `Scheduled`, then `Running`.
const QUERY_SCHEDULED: Duration = Duration::from_millis(500);
const QUERY_RUNNING: Duration = Duration::from_millis(3000);
/// Logs Insights stops queries after 60 minutes.
const QUERY_TIMEOUT_MS: i64 = 60 * 60_000;
/// How long an export task stays `PENDING`, then `RUNNING`.
const EXPORT_PENDING: Duration = Duration::from_millis(1000);
const EXPORT_RUNNING: Duration = Duration::from_millis(1000);
/// How long an import waits before it copies events.
const IMPORT_DELAY: Duration = Duration::from_millis(200);

fn in_runtime() -> bool {
    tokio::runtime::Handle::try_current().is_ok()
}

impl Logs {
    /// The emulated clock now, in epoch ms: the wall clock shifted as the
    /// last request's clock was.
    pub(crate) fn emulated_now_ms(&self) -> i64 {
        let offset = self.template.lock().expect("Logs template lock poisoned").as_ref().map(|(_, o)| *o);
        (chrono::Utc::now() + offset.unwrap_or_default()).timestamp_millis()
    }

    pub(crate) fn spawn_query(&self, account: String, region: String, id: String) {
        let me = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(QUERY_SCHEDULED).await;
            me.advance_query(&account, &region, &id, false);
            tokio::time::sleep(QUERY_RUNNING).await;
            me.advance_query(&account, &region, &id, true);
        });
    }

    /// Move a query on: to `Running`, or (`finish`) to `Complete` with the
    /// results it computed when it started. One that ran past the
    /// timeout on the emulated clock ends `Timeout`; one whose results
    /// were lost (state reloaded) ends `Failed`. A cancelled query stays
    /// cancelled.
    pub(crate) fn advance_query(&self, account: &str, region: &str, id: &str, finish: bool) {
        let now = self.emulated_now_ms();
        let mut st = self.lock();
        let Some(q) = st.region(account, region).queries.get_mut(id) else { return };
        if !matches!(q.status.as_str(), "Scheduled" | "Running") {
            q.pending = None;
            return;
        }
        if now - q.create_time > QUERY_TIMEOUT_MS {
            q.status = "Timeout".into();
            q.pending = None;
            return;
        }
        if !finish {
            q.status = "Running".into();
            return;
        }
        match q.pending.take() {
            Some((results, statistics)) => {
                q.results = results;
                q.statistics = statistics;
                q.status = "Complete".into();
            }
            None => q.status = "Failed".into(),
        }
    }

    pub(crate) fn spawn_export(&self, account: String, region: String, id: String) {
        let me = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(EXPORT_PENDING).await;
            if !me.start_export(&account, &region, &id) {
                return;
            }
            tokio::time::sleep(EXPORT_RUNNING).await;
            me.finish_export(&account, &region, &id);
        });
    }

    pub(crate) fn spawn_import(&self, account: String, region: String, id: String) {
        let me = self.clone();
        tokio::spawn(async move {
            tokio::time::sleep(IMPORT_DELAY).await;
            me.run_import(&account, &region, &id);
        });
    }

    /// After state is loaded: finish the queries that were running, and
    /// restart the export and import tasks that had not finished.
    pub(crate) fn resume_background(&self) {
        let mut queries = Vec::new();
        let mut exports = Vec::new();
        let mut imports = Vec::new();
        {
            let st = self.lock();
            for (key, r) in &st.regions {
                let Some((account, region)) = key.split_once('/') else { continue };
                let k = |id: &String| (account.to_string(), region.to_string(), id.clone());
                queries.extend(
                    r.queries
                        .values()
                        .filter(|q| matches!(q.status.as_str(), "Scheduled" | "Running"))
                        .map(|q| k(&q.id)),
                );
                exports.extend(
                    r.export_tasks
                        .iter()
                        .filter(|(_, t)| {
                            matches!(t.status.as_ref().and_then(|s| s.code.as_deref()), Some("PENDING" | "RUNNING"))
                        })
                        .map(|(id, _)| k(id)),
                );
                imports.extend(
                    r.import_tasks
                        .iter()
                        .filter(|(_, t)| t.record.import_status.as_deref() == Some("IN_PROGRESS"))
                        .map(|(id, _)| k(id)),
                );
            }
        }
        for (account, region, id) in queries {
            self.advance_query(&account, &region, &id, true);
        }
        for (account, region, id) in exports {
            self.reset_export(&account, &region, &id);
            if in_runtime() {
                self.spawn_export(account, region, id);
            } else if self.start_export(&account, &region, &id) {
                self.finish_export(&account, &region, &id);
            }
        }
        for (account, region, id) in imports {
            if in_runtime() {
                self.spawn_import(account, region, id);
            } else {
                self.run_import(&account, &region, &id);
            }
        }
    }
}

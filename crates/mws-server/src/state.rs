//! Whole-emulator state: export/import across services, the baseline that
//! `reset` returns to, named snapshots, scenarios and optional persistence.
//!
//! Services expose their state as opaque JSON ([`Service::export_state`]);
//! nothing here looks inside it. A state document is
//! `{"mwsState": 1, "services": {"<signing name>": <state>, ...}}`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use mws_core::{Caller, Service};
use mws_store::Store;
use serde_json::{json, Map, Value};

use crate::scenario::{self, Outputs, Scenario};
use crate::Gateway;

/// Format version of state documents.
pub const STATE_FORMAT: u64 = 1;

const META_SCENARIO: &str = "scenario";
const META_BASELINE: &str = "baseline";

pub(crate) struct StateHub {
    pub store: Option<Arc<Store>>,
    /// Snapshots when there is no store.
    mem_snapshots: Mutex<BTreeMap<String, (DateTime<Utc>, String)>>,
    /// The state `reset` returns to.
    baseline: Mutex<Value>,
    /// Service documents as last written to the store.
    last_saved: Mutex<BTreeMap<String, String>>,
    dirty: AtomicBool,
    notify: tokio::sync::Notify,
    /// Requests hold it shared; whole-state operations hold it exclusively
    /// so they never interleave with a request.
    pub gate: tokio::sync::RwLock<()>,
    pub flush_interval: Duration,
    /// Access key whose identity runs scenario steps.
    pub scenario_access_key: Option<String>,
}

impl Default for StateHub {
    fn default() -> Self {
        Self {
            store: None,
            mem_snapshots: Mutex::default(),
            baseline: Mutex::new(Value::Null),
            last_saved: Mutex::default(),
            dirty: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
            gate: tokio::sync::RwLock::new(()),
            flush_interval: Duration::from_millis(250),
            scenario_access_key: None,
        }
    }
}

/// A named snapshot as listed by the admin API.
#[derive(Debug, Clone)]
pub struct SnapshotInfo {
    pub name: String,
    pub created_at: DateTime<Utc>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Why a scenario step failed.
#[derive(Debug, Clone)]
pub struct ScenarioError {
    /// Zero-based step index, if a step failed (not the file as a whole).
    pub step: Option<usize>,
    pub message: String,
    /// The service's error code, if the service rejected the call.
    pub code: Option<String>,
}

impl std::fmt::Display for ScenarioError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.step {
            Some(i) => write!(f, "scenario step {}: {}", i + 1, self.message),
            None => write!(f, "scenario: {}", self.message),
        }
    }
}

impl Gateway {
    fn stateful(&self) -> impl Iterator<Item = (&'static str, &Arc<dyn Service>)> {
        self.named.iter().map(|(k, v)| (*k, v))
    }

    /// Every service's state as one document.
    pub fn export_state(&self) -> Value {
        let mut services = Map::new();
        for (name, svc) in self.stateful() {
            if let Some(state) = svc.export_state() {
                services.insert(name.to_string(), state);
            }
        }
        json!({ "mwsState": STATE_FORMAT, "services": services })
    }

    /// Replace every service's state with `doc`'s. Services `doc` does not
    /// mention are reset. If any service rejects its part, every service is
    /// put back the way it was.
    pub fn import_state(&self, doc: &Value) -> Result<(), String> {
        let services = parse_state_doc(doc)?;
        for name in services.keys() {
            if !self.named.contains_key(name.as_str()) {
                return Err(format!("state names unknown service {name:?}"));
            }
        }
        let before = self.export_state();
        if let Err(e) = self.apply_services(&services) {
            let restore = parse_state_doc(&before).expect("own export is well formed");
            let _ = self.apply_services(&restore);
            return Err(e);
        }
        self.mark_dirty();
        Ok(())
    }

    fn apply_services(&self, services: &Map<String, Value>) -> Result<(), String> {
        for (name, svc) in self.stateful() {
            match services.get(name) {
                Some(state) => svc.import_state(state.clone())?,
                None => svc.reset_state(),
            }
        }
        Ok(())
    }

    /// Return every service to a freshly started state (no scenario).
    pub fn reset_all(&self) {
        for (_, svc) in self.stateful() {
            svc.reset_state();
        }
        self.mark_dirty();
    }

    /// Return to the baseline: the startup scenario's result, or empty.
    pub fn reset_to_baseline(&self) -> Result<(), String> {
        let baseline = lock(&self.state.baseline).clone();
        if baseline.is_null() {
            self.reset_all();
            Ok(())
        } else {
            self.import_state(&baseline)
        }
    }

    /// Make the current state what `reset` returns to.
    pub fn set_baseline_to_current(&self) -> Result<(), String> {
        let current = self.export_state();
        if let Some(store) = &self.state.store {
            store.set_meta(META_BASELINE, &current.to_string()).map_err(|e| e.to_string())?;
        }
        *lock(&self.state.baseline) = current;
        Ok(())
    }

    /// Run a scenario's steps against the current state. On failure the
    /// state is rolled back to what it was before the first step.
    pub async fn apply_scenario(&self, scenario: &Scenario) -> Result<Outputs, ScenarioError> {
        let before = self.export_state();
        let result = self.run_steps(scenario).await;
        if result.is_err() {
            let _ = self.import_state(&before);
        }
        self.mark_dirty();
        result
    }

    async fn run_steps(&self, scenario: &Scenario) -> Result<Outputs, ScenarioError> {
        let mut outputs = Outputs::new();
        for (i, step) in scenario.steps.iter().enumerate() {
            let fail = |message: String, code: Option<String>| ScenarioError { step: Some(i), message, code };
            let svc = self.named.get(step.service.as_str()).cloned().ok_or_else(|| {
                fail(
                    format!(
                        "unknown service {:?}; MWS emulates {}",
                        step.service,
                        self.named.keys().copied().collect::<Vec<_>>().join(", ")
                    ),
                    None,
                )
            })?;
            let input = scenario::interpolate(&step.input, &outputs).map_err(|e| fail(e, None))?;
            let caller = self.scenario_caller(step, &outputs).map_err(|e| fail(e, None))?;
            let region = step
                .region
                .clone()
                .or_else(|| scenario.region.clone())
                .unwrap_or_else(|| self.env.default_region.clone());
            let ctx = self.context(uuid::Uuid::new_v4().to_string(), region, caller, None, Utc::now());
            let output = svc.invoke(ctx, &step.action, input).await.map_err(|e| {
                fail(
                    format!("{}:{} failed: {}: {}", step.service, step.action, e.code, e.message),
                    Some(e.code.to_string()),
                )
            })?;
            if let Some(id) = &step.id {
                outputs.insert(id.clone(), output);
            }
        }
        Ok(outputs)
    }

    fn scenario_caller(&self, step: &scenario::Step, outputs: &Outputs) -> Result<Caller, String> {
        let akid = match &step.access_key_id {
            Some(k) => scenario::interpolate_string(k, outputs)?,
            None => self
                .state
                .scenario_access_key
                .clone()
                .ok_or("no accessKeyId given and the gateway has no scenario principal")?,
        };
        let token = step.session_token.as_deref().map(|t| scenario::interpolate_string(t, outputs)).transpose()?;
        self.resolve(&akid, token.as_deref(), Utc::now())
            .map(|r| r.caller)
            .map_err(|e| format!("cannot act as access key {akid}: {}", e.into_service_error().message))
    }

    /// Bring state up at startup.
    ///
    /// With a store that already holds state saved under the same scenario,
    /// that state comes back as it was. Otherwise every service starts
    /// fresh, the scenario (if any) runs, and the result becomes the
    /// baseline. Saved state from a different scenario is kept as a named
    /// snapshot before it is replaced.
    pub async fn initialize_state(&self, scenario: Option<&Scenario>, scenario_source: &str) -> Result<(), String> {
        let _gate = self.state.gate.write().await;
        if let Some(store) = self.state.store.clone() {
            let saved = store.service_states().map_err(|e| e.to_string())?;
            if !saved.is_empty() {
                let same_scenario =
                    store.meta(META_SCENARIO).map_err(|e| e.to_string())?.unwrap_or_default() == scenario_source;
                let doc = saved_doc(&saved)?;
                if same_scenario {
                    self.import_state(&doc)?;
                    let baseline = match store.meta(META_BASELINE).map_err(|e| e.to_string())? {
                        Some(b) => serde_json::from_str(&b).map_err(|e| format!("stored baseline: {e}"))?,
                        None => Value::Null,
                    };
                    *lock(&self.state.baseline) = baseline;
                    *lock(&self.state.last_saved) = saved;
                    tracing::info!("restored saved state");
                    return Ok(());
                }
                let name = format!("before-scenario-change-{}", Utc::now().format("%Y%m%dT%H%M%SZ"));
                store.put_snapshot(&name, &doc.to_string()).map_err(|e| e.to_string())?;
                tracing::warn!(snapshot = %name, "scenario changed; saved state replaced (previous state kept as a snapshot)");
            }
        }
        self.reset_all();
        if let Some(s) = scenario {
            self.apply_scenario(s).await.map_err(|e| e.to_string())?;
            tracing::info!(steps = s.steps.len(), "applied scenario");
        }
        self.set_baseline_to_current()?;
        if let Some(store) = &self.state.store {
            store.set_meta(META_SCENARIO, scenario_source).map_err(|e| e.to_string())?;
        }
        self.flush_locked();
        Ok(())
    }

    // ---- snapshots ---------------------------------------------------------

    pub fn save_snapshot(&self, name: &str) -> Result<SnapshotInfo, String> {
        let doc = self.export_state().to_string();
        match &self.state.store {
            Some(store) => store
                .put_snapshot(name, &doc)
                .map(|i| SnapshotInfo { name: i.name, created_at: i.created_at })
                .map_err(|e| e.to_string()),
            None => {
                let created_at = Utc::now();
                lock(&self.state.mem_snapshots).insert(name.to_string(), (created_at, doc));
                Ok(SnapshotInfo { name: name.to_string(), created_at })
            }
        }
    }

    pub fn snapshot(&self, name: &str) -> Result<Option<Value>, String> {
        let text = match &self.state.store {
            Some(store) => store.snapshot(name).map_err(|e| e.to_string())?,
            None => lock(&self.state.mem_snapshots).get(name).map(|(_, d)| d.clone()),
        };
        text.map(|t| serde_json::from_str(&t).map_err(|e| format!("snapshot {name}: {e}"))).transpose()
    }

    pub fn snapshots(&self) -> Result<Vec<SnapshotInfo>, String> {
        match &self.state.store {
            Some(store) => Ok(store
                .snapshots()
                .map_err(|e| e.to_string())?
                .into_iter()
                .map(|i| SnapshotInfo { name: i.name, created_at: i.created_at })
                .collect()),
            None => Ok(lock(&self.state.mem_snapshots)
                .iter()
                .map(|(name, (created_at, _))| SnapshotInfo { name: name.clone(), created_at: *created_at })
                .collect()),
        }
    }

    pub fn delete_snapshot(&self, name: &str) -> Result<bool, String> {
        match &self.state.store {
            Some(store) => store.delete_snapshot(name).map_err(|e| e.to_string()),
            None => Ok(lock(&self.state.mem_snapshots).remove(name).is_some()),
        }
    }

    // ---- persistence -------------------------------------------------------

    pub(crate) fn mark_dirty(&self) {
        if self.state.store.is_some() && !self.state.dirty.swap(true, Ordering::AcqRel) {
            self.state.notify.notify_one();
        }
    }

    /// Write changed service state to the store now. A no-op without one.
    pub async fn flush(&self) {
        if self.state.store.is_none() {
            return;
        }
        let _gate = self.state.gate.read().await;
        self.flush_locked();
    }

    /// Flush while the caller already holds the gate.
    pub(crate) fn flush_locked(&self) {
        let Some(store) = &self.state.store else { return };
        self.state.dirty.store(false, Ordering::Release);
        let current: BTreeMap<String, String> = self
            .stateful()
            .filter_map(|(name, svc)| svc.export_state().map(|s| (name.to_string(), s.to_string())))
            .collect();
        let mut last = lock(&self.state.last_saved);
        let changed: Vec<(&str, &str)> =
            current.iter().filter(|(k, v)| last.get(*k) != Some(*v)).map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let removed: Vec<&str> = last.keys().filter(|k| !current.contains_key(*k)).map(String::as_str).collect();
        if changed.is_empty() && removed.is_empty() {
            return;
        }
        match store.save_service_states(&changed, &removed) {
            Ok(()) => *last = current,
            Err(e) => {
                tracing::error!("saving state failed: {e}");
                self.state.dirty.store(true, Ordering::Release);
            }
        }
    }

    /// Flush whenever state may have changed, at most once per
    /// `flush_interval`. Runs until the task is dropped.
    pub(crate) async fn persist_loop(self: Arc<Self>) {
        loop {
            self.state.notify.notified().await;
            tokio::time::sleep(self.state.flush_interval).await;
            self.flush().await;
        }
    }
}

fn parse_state_doc(doc: &Value) -> Result<Map<String, Value>, String> {
    let obj = doc.as_object().ok_or("state must be a JSON object")?;
    match obj.get("mwsState").and_then(Value::as_u64) {
        Some(STATE_FORMAT) => {}
        Some(v) => return Err(format!("state format {v} is not supported (expected {STATE_FORMAT})")),
        None => return Err("not an MWS state document (missing \"mwsState\")".into()),
    }
    match obj.get("services") {
        Some(Value::Object(s)) => Ok(s.clone()),
        None => Ok(Map::new()),
        Some(_) => Err("\"services\" must be an object".into()),
    }
}

fn saved_doc(saved: &BTreeMap<String, String>) -> Result<Value, String> {
    let mut services = Map::new();
    for (name, text) in saved {
        let v: Value = serde_json::from_str(text).map_err(|e| format!("saved state of {name}: {e}"))?;
        services.insert(name.clone(), v);
    }
    Ok(json!({ "mwsState": STATE_FORMAT, "services": services }))
}

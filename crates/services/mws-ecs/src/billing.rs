//! What ECS bills by the hour, for Cost Explorer: the vCPU and memory of
//! Fargate tasks from when they start pulling their images until they
//! stop, across accounts and Regions.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::Ecs;

/// A Fargate task that runs or ran (still listed).
#[derive(Debug, Clone)]
pub struct BillableTask {
    pub account: String,
    pub region: String,
    pub task_arn: String,
    /// Fargate Spot capacity.
    pub spot: bool,
    pub vcpu: f64,
    pub memory_gb: f64,
    pub started: Option<DateTime<Utc>>,
    pub stopped: Option<DateTime<Utc>>,
    pub tags: BTreeMap<String, String>,
}

/// `1024`, `1 vCPU` or `0.5 vcpu` as vCPUs; `2048`, `2 GB` as GB.
fn units(s: &str, per: f64) -> f64 {
    let lower = s.trim().to_ascii_lowercase();
    let num: String = lower.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    let v: f64 = num.parse().unwrap_or(0.0);
    if lower.contains("vcpu") || lower.contains("gb") {
        v
    } else {
        v / per
    }
}

impl Ecs {
    pub fn billable_tasks(&self) -> Vec<BillableTask> {
        let state = self.lock();
        let mut out = Vec::new();
        for (key, r) in &state.regions {
            let Some((account, region)) = key.split_once('/') else { continue };
            for rec in r.tasks.values() {
                let t = &rec.task;
                let provider = t.capacity_provider_name.as_deref().unwrap_or_default();
                let fargate = t.launch_type.as_deref() == Some("FARGATE") || provider.starts_with("FARGATE");
                if !fargate {
                    continue;
                }
                let started = t.pull_started_at.or(t.started_at);
                if started.is_none() {
                    continue;
                }
                let cpu = t.cpu.clone().or_else(|| rec.definition.cpu.clone()).unwrap_or_else(|| "256".into());
                let memory = t.memory.clone().or_else(|| rec.definition.memory.clone()).unwrap_or_else(|| "512".into());
                out.push(BillableTask {
                    account: account.to_string(),
                    region: region.to_string(),
                    task_arn: t.task_arn.clone().unwrap_or_default(),
                    spot: provider == "FARGATE_SPOT",
                    vcpu: units(&cpu, 1024.0),
                    memory_gb: units(&memory, 1024.0),
                    started,
                    stopped: t.stopped_at.or(t.execution_stopped_at),
                    tags: t
                        .tags
                        .iter()
                        .flatten()
                        .filter_map(|x| Some((x.key.clone()?, x.value.clone().unwrap_or_default())))
                        .collect(),
                });
            }
        }
        out
    }
}

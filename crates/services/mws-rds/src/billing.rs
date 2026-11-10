//! What RDS bills by the hour, for Cost Explorer: DB instances while they
//! run and their allocated storage, across accounts and Regions.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::Rds;

/// A DB instance.
#[derive(Debug, Clone)]
pub struct BillableDbInstance {
    pub account: String,
    pub region: String,
    pub arn: String,
    pub instance_class: String,
    pub engine: String,
    pub multi_az: bool,
    /// Compute is billed (not stopped).
    pub running: bool,
    pub storage_type: String,
    pub allocated_gib: i32,
    pub created: Option<DateTime<Utc>>,
    pub tags: BTreeMap<String, String>,
}

impl Rds {
    /// Every DB instance that exists (not being deleted).
    pub fn billable_instances(&self) -> Vec<BillableDbInstance> {
        let state = self.lock();
        let mut out = Vec::new();
        for (key, r) in &state.regions {
            let Some((account, region)) = key.split_once('/') else { continue };
            for rec in r.instances.values() {
                let db = &rec.db;
                let status = db.db_instance_status.as_deref().unwrap_or_default();
                if matches!(status, "deleting" | "failed") {
                    continue;
                }
                out.push(BillableDbInstance {
                    account: account.to_string(),
                    region: region.to_string(),
                    arn: db.db_instance_arn.clone().unwrap_or_default(),
                    instance_class: db.db_instance_class.clone().unwrap_or_default(),
                    engine: db.engine.clone().unwrap_or_default(),
                    multi_az: db.multi_az.unwrap_or(false),
                    running: !matches!(status, "stopped" | "stopping"),
                    storage_type: db.storage_type.clone().unwrap_or_else(|| "gp2".into()),
                    allocated_gib: db.allocated_storage.unwrap_or(0),
                    created: db.instance_create_time,
                    tags: db
                        .tag_list
                        .iter()
                        .flatten()
                        .filter_map(|t| Some((t.key.clone()?, t.value.clone().unwrap_or_default())))
                        .collect(),
                });
            }
        }
        out
    }
}

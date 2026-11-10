//! What EFS bills for storage, for Cost Explorer: the metered size of
//! every file system, across accounts and Regions.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::Efs;

#[derive(Debug, Clone)]
pub struct FileSystemStorage {
    pub account: String,
    pub region: String,
    pub arn: String,
    pub created: DateTime<Utc>,
    /// Metered bytes (Standard storage class).
    pub bytes: i64,
    pub tags: BTreeMap<String, String>,
}

impl Efs {
    /// Never call with EFS's state lock held.
    pub fn file_system_storage(&self) -> Vec<FileSystemStorage> {
        let listed: Vec<(String, String, crate::generated::types::FileSystemDescription)> = {
            let state = self.lock();
            state
                .regions
                .iter()
                .filter_map(|(k, r)| k.split_once('/').map(|(a, g)| (a.to_string(), g.to_string(), r)))
                .flat_map(|(a, g, r)| {
                    r.file_systems
                        .values()
                        .filter(|f| {
                            matches!(f.description.life_cycle_state.as_str(), "available" | "creating" | "updating")
                        })
                        .map(move |f| (a.clone(), g.clone(), f.description.clone()))
                })
                .collect()
        };
        listed
            .into_iter()
            .map(|(account, region, d)| FileSystemStorage {
                bytes: self.storage().size(&d.file_system_id),
                arn: d.file_system_arn.clone().unwrap_or_else(|| d.file_system_id.clone()),
                created: d.creation_time,
                tags: d.tags.iter().map(|t| (t.key.clone(), t.value.clone())).collect(),
                account,
                region,
            })
            .collect()
    }
}

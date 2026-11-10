//! What S3 bills for storage, for Cost Explorer: the bytes every bucket
//! holds (all versions and delete markers excluded), by storage class.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::S3;

/// One bucket's storage.
#[derive(Debug, Clone)]
pub struct BucketStorage {
    pub account: String,
    pub region: String,
    pub bucket: String,
    pub created: DateTime<Utc>,
    /// Bytes stored by storage class (`STANDARD`, `STANDARD_IA`, ...).
    pub bytes: BTreeMap<String, i64>,
    pub tags: BTreeMap<String, String>,
}

impl S3 {
    pub fn bucket_storage(&self) -> Vec<BucketStorage> {
        let state = self.read();
        state
            .buckets
            .values()
            .map(|b| {
                let mut bytes: BTreeMap<String, i64> = BTreeMap::new();
                for v in b.objects.values().flatten().filter(|v| !v.delete_marker) {
                    let class = if v.storage_class.is_empty() { "STANDARD" } else { v.storage_class.as_str() };
                    *bytes.entry(class.to_string()).or_default() += v.size();
                }
                BucketStorage {
                    account: b.owner.clone(),
                    region: b.region.clone(),
                    bucket: b.name.clone(),
                    created: b.created,
                    bytes,
                    tags: b.tags.iter().flatten().map(|t| (t.key.clone(), t.value.clone())).collect(),
                }
            })
            .collect()
    }
}

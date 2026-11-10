//! What ElastiCache bills by the hour, for Cost Explorer: the nodes of
//! every node-based cluster (replication group members included), across
//! accounts and Regions.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::ElastiCache;

/// A node-based cache cluster.
#[derive(Debug, Clone)]
pub struct BillableCacheCluster {
    pub account: String,
    pub region: String,
    pub arn: String,
    pub node_type: String,
    pub nodes: i32,
    pub engine: String,
    pub created: Option<DateTime<Utc>>,
    pub tags: BTreeMap<String, String>,
}

impl ElastiCache {
    pub fn billable_clusters(&self) -> Vec<BillableCacheCluster> {
        let state = self.lock();
        let mut out = Vec::new();
        for (key, r) in &state.regions {
            let Some((account, region)) = key.split_once('/') else { continue };
            for c in r.clusters.values() {
                if matches!(c.status(), "deleting" | "deleted" | "create-failed") {
                    continue;
                }
                let arn = c.info.arn.clone().unwrap_or_default();
                let tags = r
                    .tags
                    .get(&arn)
                    .into_iter()
                    .flatten()
                    .filter_map(|t| Some((t.key.clone()?, t.value.clone().unwrap_or_default())))
                    .collect();
                out.push(BillableCacheCluster {
                    account: account.to_string(),
                    region: region.to_string(),
                    arn,
                    node_type: c.info.cache_node_type.clone().unwrap_or_default(),
                    nodes: c.info.num_cache_nodes.unwrap_or(1),
                    engine: c.info.engine.clone().unwrap_or_default(),
                    created: c.info.cache_cluster_create_time,
                    tags,
                });
            }
        }
        out
    }
}

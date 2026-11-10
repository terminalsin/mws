//! What EKS bills by the hour, for Cost Explorer: each cluster's control
//! plane, across accounts and Regions.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};

use crate::Eks;

/// A cluster EKS runs (registered clusters are not billed).
#[derive(Debug, Clone)]
pub struct BillableCluster {
    pub account: String,
    pub region: String,
    pub arn: String,
    pub created: Option<DateTime<Utc>>,
    pub tags: BTreeMap<String, String>,
}

impl Eks {
    pub fn billable_clusters(&self) -> Vec<BillableCluster> {
        let state = self.read();
        let mut out = Vec::new();
        for (key, r) in &state.regions {
            let Some((account, region)) = key.split_once('/') else { continue };
            for rec in r.clusters.values() {
                if rec.registered || matches!(rec.cluster.status.as_deref(), Some("DELETING" | "FAILED")) {
                    continue;
                }
                out.push(BillableCluster {
                    account: account.to_string(),
                    region: region.to_string(),
                    arn: rec.cluster.arn.clone().unwrap_or_default(),
                    created: rec.cluster.created_at,
                    tags: rec.cluster.tags.clone().unwrap_or_default(),
                });
            }
        }
        out
    }
}

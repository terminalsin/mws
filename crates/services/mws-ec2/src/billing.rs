//! What EC2 bills by the hour, for Cost Explorer: instances while they run
//! and EBS volumes while they exist, across accounts and Regions.

use std::collections::BTreeMap;

use chrono::{DateTime, NaiveDateTime, Utc};

use crate::Ec2;

/// An instance that runs or ran recently (still listed).
#[derive(Debug, Clone)]
pub struct BillableInstance {
    pub account: String,
    pub region: String,
    pub instance_id: String,
    pub instance_type: String,
    /// `Linux/UNIX`, `Windows`, ...
    pub platform: String,
    /// When it last started running.
    pub launched: Option<DateTime<Utc>>,
    /// When it stopped or was terminated, if it no longer runs.
    pub stopped: Option<DateTime<Utc>>,
    pub tags: BTreeMap<String, String>,
}

/// An EBS volume.
#[derive(Debug, Clone)]
pub struct BillableVolume {
    pub account: String,
    pub region: String,
    pub volume_id: String,
    pub volume_type: String,
    pub size_gib: i32,
    pub created: Option<DateTime<Utc>>,
    pub tags: BTreeMap<String, String>,
}

fn tag_map(tags: Option<&Vec<crate::generated::types::Tag>>) -> BTreeMap<String, String> {
    tags.into_iter().flatten().filter_map(|t| Some((t.key.clone()?, t.value.clone().unwrap_or_default()))).collect()
}

/// The time in a `User initiated (2026-11-10 12:00:00 GMT)` reason.
fn reason_time(reason: Option<&str>) -> Option<DateTime<Utc>> {
    let inner = reason?.split_once('(')?.1.trim_end_matches(')');
    NaiveDateTime::parse_from_str(inner, "%Y-%m-%d %H:%M:%S GMT").ok().map(|t| t.and_utc())
}

impl Ec2 {
    /// Every instance that is running, or stopped or terminated but still
    /// listed, with when it started and stopped.
    pub fn billable_instances(&self) -> Vec<BillableInstance> {
        let state = self.lock();
        let mut out = Vec::new();
        for (key, r) in &state.regions {
            let Some((account, region)) = key.split_once('/') else { continue };
            for (id, rec) in &r.instances {
                let i = &rec.instance;
                let st = i.state.as_ref().and_then(|s| s.name.as_deref()).unwrap_or_default();
                let stopped = match st {
                    "running" => None,
                    "stopping" | "stopped" | "shutting-down" | "terminated" => {
                        match rec.terminated_at.or_else(|| reason_time(i.state_transition_reason.as_deref())) {
                            Some(t) => Some(t),
                            None => continue,
                        }
                    }
                    _ => continue,
                };
                out.push(BillableInstance {
                    account: account.to_string(),
                    region: region.to_string(),
                    instance_id: id.clone(),
                    instance_type: i.instance_type.clone().unwrap_or_else(|| "m1.small".into()),
                    platform: i.platform_details.clone().unwrap_or_else(|| "Linux/UNIX".into()),
                    launched: i.launch_time,
                    stopped,
                    tags: tag_map(i.tags.as_ref()),
                });
            }
        }
        out
    }

    /// Every EBS volume that exists.
    pub fn billable_volumes(&self) -> Vec<BillableVolume> {
        let state = self.lock();
        let mut out = Vec::new();
        for (key, r) in &state.regions {
            let Some((account, region)) = key.split_once('/') else { continue };
            for (id, v) in &r.volumes {
                if matches!(v.state.as_deref(), Some("deleted" | "deleting" | "error")) {
                    continue;
                }
                out.push(BillableVolume {
                    account: account.to_string(),
                    region: region.to_string(),
                    volume_id: id.clone(),
                    volume_type: v.volume_type.clone().unwrap_or_else(|| "gp2".into()),
                    size_gib: v.size.unwrap_or(0),
                    created: v.create_time,
                    tags: tag_map(v.tags.as_ref()),
                });
            }
        }
        out
    }
}

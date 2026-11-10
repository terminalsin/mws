//! Auto Scaling state: one [`RegionState`] per account and Region. Groups
//! keep their API shape (the generated `AutoScalingGroup`) plus what the
//! API does not show: their members' lifecycle, pending lifecycle actions,
//! cooldowns and instance refreshes.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::generated::types as t;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// Keyed by `{account}/{region}`.
    pub regions: BTreeMap<String, RegionState>,
}

impl State {
    pub fn key(account: &str, region: &str) -> String {
        format!("{account}/{region}")
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RegionState {
    pub launch_configurations: BTreeMap<String, t::LaunchConfiguration>,
    pub groups: BTreeMap<String, Group>,
    /// Newest last; kept for deleted groups too (`IncludeDeletedGroups`).
    pub activities: Vec<t::Activity>,
    pub account_settings: BTreeMap<String, String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Group {
    /// The group as `DescribeAutoScalingGroups` shows it, without
    /// `Instances` (rendered from `members`).
    pub cfg: t::AutoScalingGroup,
    pub members: BTreeMap<String, Member>,
    pub hooks: BTreeMap<String, t::LifecycleHook>,
    pub policies: BTreeMap<String, t::ScalingPolicy>,
    pub scheduled: BTreeMap<String, t::ScheduledUpdateGroupAction>,
    /// The last time each scheduled action ran.
    pub scheduled_ran: BTreeMap<String, DateTime<Utc>>,
    /// Topic ARN to notification types.
    pub notifications: BTreeMap<String, Vec<String>>,
    /// Classic load balancer names, target group ARNs and other traffic
    /// sources, by identifier.
    pub traffic_sources: BTreeMap<String, t::TrafficSourceState>,
    pub refreshes: Vec<Refresh>,
    /// Simple scaling cooldown: no simple policy runs before this.
    pub cooldown_until: Option<DateTime<Utc>>,
    /// After a failed launch, wait until then before trying again.
    pub launch_backoff_until: Option<DateTime<Utc>>,
    pub deleting: bool,
    pub force_delete: bool,
    /// `LaunchInstances` client tokens and their results.
    pub launch_tokens: BTreeMap<String, t::LaunchInstancesResult>,
    /// Alarms target tracking policies made, by policy name.
    pub policy_alarms: BTreeMap<String, Vec<String>>,
    /// The group's subnets with their zones (`(zone, zone id)`).
    pub subnet_zones: BTreeMap<String, (String, String)>,
    /// What caused the latest capacity change, for the next activity.
    pub pending_cause: Option<String>,
    /// The minute metrics were last published.
    pub metrics_published: Option<DateTime<Utc>>,
}

/// An instance in a group (or its warm pool).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Member {
    pub instance_id: String,
    pub instance_type: String,
    pub availability_zone: String,
    pub availability_zone_id: Option<String>,
    pub subnet_id: Option<String>,
    pub lifecycle_state: String,
    pub health_status: String,
    pub launch_configuration_name: Option<String>,
    pub launch_template: Option<t::LaunchTemplateSpecification>,
    pub image_id: Option<String>,
    pub protected_from_scale_in: bool,
    pub weighted_capacity: Option<String>,
    /// Launched on the Spot market.
    pub spot: bool,
    pub launched_at: DateTime<Utc>,
    /// When it entered `InService` (the health check grace period counts
    /// from here).
    pub in_service_at: Option<DateTime<Utc>>,
    /// In the warm pool rather than the group.
    pub warm: bool,
    /// A lifecycle action waiting for `CompleteLifecycleAction`.
    pub action: Option<LifecycleAction>,
    /// Hooks of the current transition already completed.
    pub hooks_done: Vec<String>,
    /// The activity that launched or is terminating it.
    pub activity_id: Option<String>,
    /// Why it is being terminated (shown in its activity).
    pub terminate_cause: Option<String>,
    /// Set when terminating should lower the desired capacity.
    pub decrement_on_terminate: bool,
    /// When termination finishes, return to the warm pool instead.
    pub return_to_warm_pool: bool,
    /// When it was deregistered from the group's load balancers;
    /// termination waits for the deregistration delay.
    pub deregistered_at: Option<DateTime<Utc>>,
    /// `TerminateInstances` has been sent.
    pub terminate_sent: bool,
    /// Where to go after a launch hook (`InService`, `Standby` or a
    /// warm pool state).
    pub after_launch: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LifecycleAction {
    pub hook: String,
    pub token: String,
    pub transition: String,
    /// Heartbeat deadline.
    pub deadline: DateTime<Utc>,
    /// The latest a heartbeat can push the deadline to.
    pub global_deadline: DateTime<Utc>,
    pub result: Option<String>,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Refresh {
    pub info: t::InstanceRefresh,
    /// Instances still to replace.
    pub to_replace: Vec<String>,
    pub total: i32,
    /// The group's configuration before the refresh, for rollbacks.
    pub previous_launch_template: Option<t::LaunchTemplateSpecification>,
    pub previous_mixed_instances_policy: Option<t::MixedInstancesPolicy>,
    pub previous_launch_configuration: Option<String>,
    /// A checkpoint pause lasts until then.
    pub paused_until: Option<DateTime<Utc>>,
    pub checkpoints_done: Vec<i32>,
}

impl Group {
    pub fn name(&self) -> &str {
        &self.cfg.auto_scaling_group_name
    }

    pub fn arn(&self) -> String {
        self.cfg.auto_scaling_group_arn.clone().unwrap_or_default()
    }

    pub fn suspended(&self, process: &str) -> bool {
        self.cfg.suspended_processes.iter().flatten().any(|p| p.process_name.as_deref() == Some(process))
    }

    /// Members that count toward the desired capacity.
    pub fn counted(&self) -> impl Iterator<Item = &Member> {
        self.members
            .values()
            .filter(|m| !m.warm && (m.lifecycle_state.starts_with("Pending") || m.lifecycle_state == "InService"))
    }

    pub fn active_refresh(&self) -> Option<&Refresh> {
        self.refreshes.iter().rev().find(|r| {
            matches!(
                r.info.status.as_deref(),
                Some("Pending" | "InProgress" | "Cancelling" | "RollbackInProgress" | "Baking")
            )
        })
    }

    pub fn active_refresh_mut(&mut self) -> Option<&mut Refresh> {
        self.refreshes.iter_mut().rev().find(|r| {
            matches!(
                r.info.status.as_deref(),
                Some("Pending" | "InProgress" | "Cancelling" | "RollbackInProgress" | "Baking")
            )
        })
    }
}

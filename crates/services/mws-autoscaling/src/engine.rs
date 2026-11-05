//! The reconciliation loop: what Auto Scaling does between API calls.
//!
//! Every pass, for every group: follow each member's instance in EC2 and
//! move it through its lifecycle (`Pending`, `Pending:Wait`, `InService`,
//! `Terminating:Wait`, ...), check health, then launch or terminate to meet
//! the desired capacity, rebalance zones, keep the warm pool filled, run
//! due scheduled actions and advance instance refreshes. Decisions are made
//! under the state lock; EC2 calls and notifications happen after it.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use mws_core::RequestContext;
use mws_ec2::generated::types as et;
use rand::seq::SliceRandom;
use serde_json::{json, Value};

use crate::ec2::InstanceInfo;
use crate::generated::types as t;
use crate::state::{Group, LifecycleAction, Member, RegionState, State};
use crate::util::{at, iso, LAUNCHING, TERMINATING};
use crate::{AutoScaling, AutoScalingEvent, GroupMetric, TrafficTarget};

/// One launch the plan asks for.
#[derive(Debug, Clone)]
pub(crate) struct LaunchReq {
    pub activity_id: String,
    pub subnet_id: Option<String>,
    pub availability_zone: String,
    pub availability_zone_id: Option<String>,
    pub warm: bool,
    pub launch_template: Option<(String, i64)>,
    pub launch_configuration: Option<t::LaunchConfiguration>,
    pub instance_type: Option<String>,
    pub image_id: Option<String>,
    pub weighted_capacity: Option<String>,
    pub template_data: Option<et::ResponseLaunchTemplateData>,
}

#[derive(Debug, Clone)]
pub(crate) enum Op {
    Launch(Box<LaunchReq>),
    Terminate(String),
    Stop(String, bool),
    Start(String),
    Notify { target: String, role: Option<String>, subject: Option<String>, message: String },
    Event { detail_type: String, resources: Vec<String>, detail: Value },
    Traffic { register: bool, target: TrafficTarget, instance_ids: Vec<String> },
}

/// The group's launch source, resolved to concrete versions.
#[derive(Debug, Clone, Default)]
pub(crate) struct Source {
    /// `(template id, version)` of the template launches use.
    pub template: Option<(String, i64)>,
    pub template_data: Option<et::ResponseLaunchTemplateData>,
    /// The template the group names now (for "oldest launch template").
    pub current_template: Option<(String, i64)>,
    pub configuration: Option<t::LaunchConfiguration>,
    pub overrides: Vec<t::LaunchTemplateOverrides>,
}

fn instance_arn(partition: &str, region: &str, account: &str, id: &str) -> String {
    format!("arn:{partition}:ec2:{region}:{account}:instance/{id}")
}

pub(crate) fn new_activity(
    activities: &mut Vec<t::Activity>,
    g: &Group,
    description: String,
    cause: String,
    status: &str,
    now: DateTime<Utc>,
    details: Value,
) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    activities.push(t::Activity {
        activity_id: id.clone(),
        auto_scaling_group_name: g.name().to_string(),
        auto_scaling_group_arn: Some(g.arn()),
        description: Some(description),
        cause,
        start_time: now,
        end_time: None,
        status_code: status.to_string(),
        status_message: None,
        progress: Some(if status == "Successful" { 100 } else { 0 }),
        details: Some(details.to_string()),
        auto_scaling_group_state: None,
    });
    if activities.len() > 2000 {
        activities.remove(0);
    }
    id
}

fn finish_activity(
    activities: &mut [t::Activity],
    id: &Option<String>,
    status: &str,
    message: Option<String>,
    now: DateTime<Utc>,
) -> Option<t::Activity> {
    let a = activities.iter_mut().rev().find(|a| Some(&a.activity_id) == id.as_ref())?;
    a.status_code = status.to_string();
    if matches!(status, "Successful" | "Failed" | "Cancelled") {
        a.end_time = Some(now);
        a.progress = Some(100);
    } else {
        a.progress = Some(30);
    }
    if message.is_some() {
        a.status_message = message;
    }
    Some(a.clone())
}

/// The group-level notification for `event` (`autoscaling:EC2_INSTANCE_LAUNCH`, ...).
fn group_notifications(g: &Group, event: &str, account: &str, activity: &t::Activity, instance_id: &str) -> Vec<Op> {
    let subject = match event {
        "autoscaling:EC2_INSTANCE_LAUNCH" => format!("Auto Scaling: launch for group \"{}\"", g.name()),
        "autoscaling:EC2_INSTANCE_LAUNCH_ERROR" => format!("Auto Scaling: failed launch for group \"{}\"", g.name()),
        "autoscaling:EC2_INSTANCE_TERMINATE" => format!("Auto Scaling: termination for group \"{}\"", g.name()),
        _ => format!("Auto Scaling: failed termination for group \"{}\"", g.name()),
    };
    let message = json!({
        "Progress": activity.progress.unwrap_or(0),
        "AccountId": account,
        "Description": activity.description.clone().unwrap_or_default(),
        "RequestId": activity.activity_id,
        "EndTime": activity.end_time.map(iso),
        "AutoScalingGroupARN": g.arn(),
        "ActivityId": activity.activity_id,
        "StartTime": iso(activity.start_time),
        "Service": "AWS Auto Scaling",
        "Time": iso(activity.end_time.unwrap_or(activity.start_time)),
        "EC2InstanceId": instance_id,
        "StatusCode": activity.status_code,
        "StatusMessage": activity.status_message.clone().unwrap_or_default(),
        "Details": activity.details.as_deref().and_then(|d| serde_json::from_str::<Value>(d).ok()).unwrap_or(json!({})),
        "AutoScalingGroupName": g.name(),
        "Cause": activity.cause,
        "Event": event,
    })
    .to_string();
    g.notifications
        .iter()
        .filter(|(_, types)| types.iter().any(|t| t == event))
        .map(|(topic, _)| Op::Notify {
            target: topic.clone(),
            role: None,
            subject: Some(subject.clone()),
            message: message.clone(),
        })
        .collect()
}

/// The EventBridge event for an activity.
fn activity_event(detail_type: &str, g: &Group, activity: &t::Activity, instance_arn: String, instance_id: &str) -> Op {
    Op::Event {
        detail_type: detail_type.to_string(),
        resources: vec![g.arn(), instance_arn],
        detail: json!({
            "StatusCode": activity.status_code,
            "AutoScalingGroupName": g.name(),
            "ActivityId": activity.activity_id,
            "Details": activity.details.as_deref().and_then(|d| serde_json::from_str::<Value>(d).ok()).unwrap_or(json!({})),
            "RequestId": activity.activity_id,
            "StatusMessage": activity.status_message.clone().unwrap_or_default(),
            "EndTime": activity.end_time.map(iso),
            "EC2InstanceId": instance_id,
            "StartTime": iso(activity.start_time),
            "Cause": activity.cause,
            "Description": activity.description.clone().unwrap_or_default(),
        }),
    }
}

pub(crate) struct Planner<'a> {
    pub g: &'a mut Group,
    pub activities: &'a mut Vec<t::Activity>,
    pub info: &'a BTreeMap<String, InstanceInfo>,
    pub source: &'a Source,
    pub now: DateTime<Utc>,
    pub account: &'a str,
    pub region: &'a str,
    pub partition: &'a str,
    pub ops: Vec<Op>,
    pub changed: bool,
}

impl Planner<'_> {
    fn iarn(&self, id: &str) -> String {
        instance_arn(self.partition, self.region, self.account, id)
    }

    /// Start the next hook of `transition` for member `id`. `true` when one
    /// now waits.
    fn start_hook(&mut self, id: &str, transition: &str) -> bool {
        let hooks: Vec<t::LifecycleHook> =
            self.g.hooks.values().filter(|h| h.lifecycle_transition.as_deref() == Some(transition)).cloned().collect();
        let m = self.g.members.get_mut(id).expect("member");
        let Some(hook) = hooks.into_iter().find(|h| !m.hooks_done.contains(h.lifecycle_hook_name.as_ref().unwrap()))
        else {
            return false;
        };
        let hb = hook.heartbeat_timeout.unwrap_or(3600) as i64;
        let global = hook.global_timeout.map(|g| g as i64).unwrap_or((hb * 100).min(172800));
        let token = uuid::Uuid::new_v4().to_string();
        let name = hook.lifecycle_hook_name.clone().unwrap_or_default();
        m.action = Some(LifecycleAction {
            hook: name.clone(),
            token: token.clone(),
            transition: transition.to_string(),
            deadline: self.now + Duration::seconds(hb),
            global_deadline: self.now + Duration::seconds(global),
            result: None,
        });
        let launching = transition == LAUNCHING;
        m.lifecycle_state = if m.warm {
            "Warmed:Pending:Wait".into()
        } else if launching {
            "Pending:Wait".into()
        } else {
            "Terminating:Wait".into()
        };
        let activity_id = m.activity_id.clone();
        let warm = m.warm;
        if let Some(a) = self.activities.iter_mut().rev().find(|a| Some(&a.activity_id) == activity_id.as_ref()) {
            a.status_code = "MidLifecycleAction".into();
            a.progress = Some(30);
        }
        let origin_dest = match (launching, warm) {
            (true, false) => ("EC2", "AutoScalingGroup"),
            (true, true) => ("EC2", "WarmPool"),
            (false, _) => ("AutoScalingGroup", "EC2"),
        };
        let mut message = json!({
            "Origin": origin_dest.0,
            "Destination": origin_dest.1,
            "LifecycleHookName": name,
            "AccountId": self.account,
            "RequestId": uuid::Uuid::new_v4().to_string(),
            "LifecycleTransition": transition,
            "AutoScalingGroupName": self.g.name(),
            "Service": "AWS Auto Scaling",
            "Time": iso(self.now),
            "EC2InstanceId": id,
            "LifecycleActionToken": token,
        });
        if let Some(md) = &hook.notification_metadata {
            message["NotificationMetadata"] = json!(md);
        }
        if let Some(target) = &hook.notification_target_arn {
            self.ops.push(Op::Notify {
                target: target.clone(),
                role: hook.role_arn.clone(),
                subject: None,
                message: message.to_string(),
            });
        }
        let mut detail = message.clone();
        if let Value::Object(m) = &mut detail {
            m.remove("AccountId");
            m.remove("RequestId");
            m.remove("Service");
            m.remove("Time");
        }
        self.ops.push(Op::Event {
            detail_type: if launching {
                "EC2 Instance-launch Lifecycle Action"
            } else {
                "EC2 Instance-terminate Lifecycle Action"
            }
            .into(),
            resources: vec![self.g.arn()],
            detail,
        });
        self.changed = true;
        true
    }

    /// A launched member reaches its destination.
    fn launched(&mut self, id: &str) {
        let now = self.now;
        let m = self.g.members.get_mut(id).expect("member");
        m.action = None;
        m.hooks_done.clear();
        if m.warm {
            // Into the warm pool: running, stopped or hibernated.
            let pool = self.g.cfg.warm_pool_configuration.as_ref().and_then(|w| w.pool_state.clone());
            match pool.as_deref().unwrap_or("Stopped") {
                "Running" => m.lifecycle_state = "Warmed:Running".into(),
                other => {
                    m.lifecycle_state = "Warmed:Pending:Proceed".into();
                    self.ops.push(Op::Stop(id.to_string(), other == "Hibernated"));
                }
            }
            let a = finish_activity(self.activities, &m.activity_id, "Successful", None, now);
            let _ = a;
            self.changed = true;
            return;
        }
        let target = m.after_launch.take().unwrap_or_else(|| "InService".into());
        m.lifecycle_state = target;
        m.in_service_at = Some(now);
        m.health_status = "Healthy".into();
        let in_service = m.lifecycle_state == "InService";
        if let Some(a) = finish_activity(self.activities, &m.activity_id, "Successful", None, now) {
            let mut ops = group_notifications(self.g, "autoscaling:EC2_INSTANCE_LAUNCH", self.account, &a, id);
            ops.push(activity_event("EC2 Instance Launch Successful", self.g, &a, self.iarn(id), id));
            self.ops.extend(ops);
        }
        if in_service {
            let ops = crate::ops::traffic::member_ops(self.g, &[id.to_string()], true);
            self.ops.extend(ops);
        }
        self.changed = true;
    }

    /// Start terminating a member (it runs its terminate hooks first).
    pub fn mark_terminating(&mut self, id: &str, cause: String, return_to_warm_pool: bool) {
        let now = self.now;
        let Some(m) = self.g.members.get(id) else { return };
        if m.lifecycle_state.starts_with("Terminating") {
            return;
        }
        let description = if m.warm {
            format!("Terminating EC2 instance from warm pool: {id}")
        } else {
            format!("Terminating EC2 instance: {id}")
        };
        let details =
            json!({"Subnet ID": m.subnet_id.clone().unwrap_or_default(), "Availability Zone": m.availability_zone});
        if !m.warm && m.lifecycle_state == "InService" {
            let ops = crate::ops::traffic::member_ops(self.g, &[id.to_string()], false);
            self.ops.extend(ops);
        }
        let activity = new_activity(self.activities, self.g, description, cause.clone(), "InProgress", now, details);
        let m = self.g.members.get_mut(id).expect("member");
        m.lifecycle_state = "Terminating".into();
        m.activity_id = Some(activity);
        m.terminate_cause = Some(cause);
        m.return_to_warm_pool = return_to_warm_pool;
        m.action = None;
        m.hooks_done.clear();
        m.terminate_sent = false;
        self.changed = true;
    }

    fn removed(&mut self, id: &str, ok: bool) {
        let now = self.now;
        let Some(m) = self.g.members.remove(id) else { return };
        let status = if ok { "Successful" } else { "Failed" };
        if let Some(a) = finish_activity(self.activities, &m.activity_id, status, None, now) {
            if !m.warm {
                let kind =
                    if ok { "autoscaling:EC2_INSTANCE_TERMINATE" } else { "autoscaling:EC2_INSTANCE_TERMINATE_ERROR" };
                let mut ops = group_notifications(self.g, kind, self.account, &a, id);
                ops.push(activity_event(
                    if ok { "EC2 Instance Terminate Successful" } else { "EC2 Instance Terminate Unsuccessful" },
                    self.g,
                    &a,
                    self.iarn(id),
                    id,
                ));
                self.ops.extend(ops);
            }
        }
        self.changed = true;
    }

    /// Follow one member's instance.
    fn step_member(&mut self, id: &str) {
        let now = self.now;
        let Some(m) = self.g.members.get(id).cloned() else { return };
        let info = self.info.get(id);
        let ec2_state = info.map(|i| i.state.as_str()).unwrap_or("terminated");
        let gone = matches!(ec2_state, "terminated" | "shutting-down");
        let state = m.lifecycle_state.as_str();
        // Lifecycle actions time out to their hook's default result.
        if let Some(action) = &m.action {
            if action.result.is_none() && now >= action.deadline.min(action.global_deadline) {
                let default = self
                    .g
                    .hooks
                    .get(&action.hook)
                    .and_then(|h| h.default_result.clone())
                    .unwrap_or_else(|| "ABANDON".into());
                if let Some(a) = self.g.members.get_mut(id).and_then(|m| m.action.as_mut()) {
                    a.result = Some(default);
                }
                self.changed = true;
            }
        }
        let m = self.g.members.get(id).cloned().expect("member");
        match state {
            "Pending" | "Warmed:Pending" => {
                if gone {
                    self.launch_failed(id, "Instance failed to launch.");
                } else if ec2_state == "running" && !self.start_hook(id, LAUNCHING) {
                    self.launched(id);
                }
            }
            "Pending:Wait" | "Warmed:Pending:Wait" => {
                let Some(action) = &m.action else { return };
                match action.result.as_deref() {
                    Some("CONTINUE") => {
                        let mm = self.g.members.get_mut(id).expect("member");
                        mm.hooks_done.push(action.hook.clone());
                        mm.action = None;
                        mm.lifecycle_state =
                            if mm.warm { "Warmed:Pending:Proceed".into() } else { "Pending:Proceed".into() };
                        self.changed = true;
                        if !self.start_hook(id, LAUNCHING) {
                            self.launched(id);
                        }
                    }
                    Some(_) => {
                        // ABANDON: the instance goes.
                        let cause = format!(
                            "{} an instance was taken out of service in response to a lifecycle action being abandoned.",
                            at(now)
                        );
                        if let Some(a) = finish_activity(
                            self.activities,
                            &m.activity_id,
                            "Cancelled",
                            Some("Instance launch abandoned by lifecycle action.".into()),
                            now,
                        ) {
                            let _ = a;
                        }
                        let mm = self.g.members.get_mut(id).expect("member");
                        mm.lifecycle_state = "Terminating:Proceed".into();
                        mm.action = None;
                        mm.terminate_cause = Some(cause);
                        mm.terminate_sent = false;
                        self.changed = true;
                    }
                    None => {
                        if gone {
                            self.removed(id, true);
                        }
                    }
                }
            }
            "Pending:Proceed" => {
                if !self.start_hook(id, LAUNCHING) {
                    self.launched(id);
                }
            }
            "Warmed:Pending:Proceed" => {
                if matches!(ec2_state, "stopped") {
                    let pool = self.g.cfg.warm_pool_configuration.as_ref().and_then(|w| w.pool_state.clone());
                    let mm = self.g.members.get_mut(id).expect("member");
                    mm.lifecycle_state =
                        if pool.as_deref() == Some("Hibernated") { "Warmed:Hibernated" } else { "Warmed:Stopped" }
                            .into();
                    self.changed = true;
                } else if ec2_state == "running" && m.action.is_none() && m.hooks_done.is_empty() {
                    // Fresh from a launch hook: finish entering the pool.
                    self.launched(id);
                } else if gone {
                    self.removed(id, true);
                }
            }
            "InService" => {
                let unhealthy_instance = !matches!(ec2_state, "running" | "pending");
                if unhealthy_instance && !self.g.suspended("HealthCheck") && m.health_status == "Healthy" {
                    self.g.members.get_mut(id).expect("member").health_status = "Unhealthy".into();
                    self.changed = true;
                }
                let m = self.g.members.get(id).cloned().expect("member");
                if m.health_status == "Unhealthy" && !self.g.suspended("ReplaceUnhealthy") {
                    let cause = if unhealthy_instance {
                        format!(
                            "{} an instance was taken out of service in response to an EC2 health check indicating it has been terminated or stopped.",
                            at(now)
                        )
                    } else {
                        format!("{} an instance was taken out of service in response to a user health-check.", at(now))
                    };
                    self.mark_terminating(id, cause, false);
                    return;
                }
                if let Some(life) = self.g.cfg.max_instance_lifetime.filter(|l| *l > 0) {
                    if now - m.launched_at >= Duration::seconds(life as i64) {
                        let cause = format!(
                            "{} an instance was taken out of service in response to the maximum instance lifetime of {life} seconds being reached.",
                            at(now)
                        );
                        self.mark_terminating(id, cause, false);
                    }
                }
            }
            "Terminating" => {
                if !self.start_hook(id, TERMINATING) {
                    self.g.members.get_mut(id).expect("member").lifecycle_state = "Terminating:Proceed".into();
                    self.changed = true;
                    self.step_member(id);
                }
            }
            "Terminating:Wait" => {
                let Some(action) = &m.action else { return };
                if action.result.is_some() {
                    let mm = self.g.members.get_mut(id).expect("member");
                    mm.hooks_done.push(action.hook.clone());
                    mm.action = None;
                    mm.lifecycle_state = "Terminating".into();
                    self.changed = true;
                    if !self.start_hook(id, TERMINATING) {
                        self.g.members.get_mut(id).expect("member").lifecycle_state = "Terminating:Proceed".into();
                        self.step_member(id);
                    }
                } else if gone {
                    self.removed(id, true);
                }
            }
            "Terminating:Proceed" => {
                if m.return_to_warm_pool {
                    if ec2_state == "stopped" {
                        let pool = self.g.cfg.warm_pool_configuration.as_ref().and_then(|w| w.pool_state.clone());
                        let _ = finish_activity(self.activities, &m.activity_id, "Successful", None, now);
                        let mm = self.g.members.get_mut(id).expect("member");
                        mm.warm = true;
                        mm.lifecycle_state =
                            if pool.as_deref() == Some("Hibernated") { "Warmed:Hibernated" } else { "Warmed:Stopped" }
                                .into();
                        mm.return_to_warm_pool = false;
                        mm.terminate_sent = false;
                        mm.hooks_done.clear();
                        self.changed = true;
                    } else if gone {
                        self.removed(id, true);
                    } else if !m.terminate_sent {
                        self.ops.push(Op::Stop(id.to_string(), false));
                        self.g.members.get_mut(id).expect("member").terminate_sent = true;
                        self.changed = true;
                    }
                } else if gone {
                    self.removed(id, true);
                } else if !m.terminate_sent {
                    self.ops.push(Op::Terminate(id.to_string()));
                    self.g.members.get_mut(id).expect("member").terminate_sent = true;
                    self.changed = true;
                }
            }
            "Warmed:Running" | "Warmed:Stopped" | "Warmed:Hibernated" | "Standby" if gone => {
                self.removed(id, true);
            }
            _ => {}
        }
    }

    fn launch_failed(&mut self, id: &str, reason: &str) {
        let now = self.now;
        if let Some(m) = self.g.members.remove(id) {
            let message = format!("{reason} Launching EC2 instance failed.");
            if let Some(a) = finish_activity(self.activities, &m.activity_id, "Failed", Some(message), now) {
                let mut ops =
                    group_notifications(self.g, "autoscaling:EC2_INSTANCE_LAUNCH_ERROR", self.account, &a, id);
                ops.push(activity_event("EC2 Instance Launch Unsuccessful", self.g, &a, self.iarn(id), id));
                self.ops.extend(ops);
            }
            self.changed = true;
        }
    }

    /// Zones members count in, including planned launches.
    fn zone_counts(&self, planned: &[LaunchReq], warm: bool) -> BTreeMap<String, usize> {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for (zone, _) in self.g.subnet_zones.values() {
            counts.entry(zone.clone()).or_default();
        }
        for m in self.g.members.values() {
            if m.warm == warm && !m.lifecycle_state.starts_with("Terminating") && m.lifecycle_state != "Standby" {
                *counts.entry(m.availability_zone.clone()).or_default() += 1;
            }
        }
        for p in planned.iter().filter(|p| p.warm == warm) {
            *counts.entry(p.availability_zone.clone()).or_default() += 1;
        }
        counts
    }

    /// A launch in the zone with the fewest instances.
    pub(crate) fn plan_launch(
        &mut self,
        planned: &[LaunchReq],
        warm: bool,
        cause: String,
        zone: Option<String>,
    ) -> Option<LaunchReq> {
        let counts = self.zone_counts(planned, warm);
        let zone = match zone {
            Some(z) => z,
            None => counts.iter().min_by_key(|(z, c)| (**c, (*z).clone())).map(|(z, _)| z.clone())?,
        };
        let subnets: Vec<(&String, &(String, String))> =
            self.g.subnet_zones.iter().filter(|(_, (z, _))| *z == zone).collect();
        let (subnet, (_, zone_id)) = subnets.first().map(|(s, z)| ((*s).clone(), (*z).clone()))?;
        let n = self.g.members.len() + planned.len();
        let ov =
            (!self.source.overrides.is_empty()).then(|| self.source.overrides[n % self.source.overrides.len()].clone());
        let description =
            if warm { "Launching a new EC2 instance into warm pool" } else { "Launching a new EC2 instance" };
        let details = json!({"Subnet ID": subnet, "Availability Zone": zone});
        let activity =
            new_activity(self.activities, self.g, description.into(), cause, "PreInService", self.now, details);
        self.changed = true;
        Some(LaunchReq {
            activity_id: activity,
            subnet_id: Some(subnet),
            availability_zone: zone,
            availability_zone_id: Some(zone_id).filter(|z| !z.is_empty()),
            warm,
            launch_template: self.source.template.clone(),
            launch_configuration: self.source.configuration.clone(),
            instance_type: ov.as_ref().and_then(|o| o.instance_type.clone()),
            image_id: ov.as_ref().and_then(|o| o.image_id.clone()),
            weighted_capacity: ov.as_ref().and_then(|o| o.weighted_capacity.clone()),
            template_data: self.source.template_data.clone(),
        })
    }

    fn outdated(&self, m: &Member) -> bool {
        match (&self.source.current_template, &self.g.cfg.launch_configuration_name) {
            (Some((id, v)), _) => m.launch_template.as_ref().is_none_or(|lt| {
                lt.launch_template_id.as_deref() != Some(id.as_str())
                    || lt.version.as_deref() != Some(v.to_string().as_str())
            }),
            (None, Some(lc)) => m.launch_configuration_name.as_deref() != Some(lc.as_str()),
            _ => false,
        }
    }

    /// Pick `n` members to terminate: balance zones, then apply the
    /// group's termination policies.
    fn victims(&self, n: usize, warm: bool) -> Vec<String> {
        let mut pool: Vec<&Member> = self
            .g
            .members
            .values()
            .filter(|m| {
                m.warm == warm
                    && !m.protected_from_scale_in
                    && (m.lifecycle_state.starts_with("Pending")
                        || m.lifecycle_state == "InService"
                        || m.lifecycle_state.starts_with("Warmed"))
            })
            .collect();
        let policies: Vec<String> =
            self.g.cfg.termination_policies.clone().filter(|p| !p.is_empty()).unwrap_or_else(|| vec!["Default".into()]);
        let mut chosen: Vec<String> = Vec::new();
        let mut rng = rand::thread_rng();
        for _ in 0..n {
            if pool.is_empty() {
                break;
            }
            // The zone with the most instances that has a candidate.
            let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
            for m in self.g.members.values() {
                if m.warm == warm && !chosen.contains(&m.instance_id) && !m.lifecycle_state.starts_with("Terminating") {
                    *counts.entry(m.availability_zone.as_str()).or_default() += 1;
                }
            }
            let zone = pool
                .iter()
                .map(|m| m.availability_zone.as_str())
                .max_by_key(|z| (counts.get(z).copied().unwrap_or(0), std::cmp::Reverse(*z)))
                .unwrap_or_default()
                .to_string();
            let mut cands: Vec<&Member> = pool.iter().copied().filter(|m| m.availability_zone == zone).collect();
            for p in &policies {
                if cands.len() <= 1 {
                    break;
                }
                let narrowed: Vec<&Member> = match p.as_str() {
                    "OldestInstance" => {
                        let min = cands.iter().map(|m| m.launched_at).min().unwrap();
                        cands.iter().copied().filter(|m| m.launched_at == min).collect()
                    }
                    "NewestInstance" => {
                        let max = cands.iter().map(|m| m.launched_at).max().unwrap();
                        cands.iter().copied().filter(|m| m.launched_at == max).collect()
                    }
                    "OldestLaunchConfiguration" | "OldestLaunchTemplate" => {
                        let old: Vec<&Member> = cands.iter().copied().filter(|m| self.outdated(m)).collect();
                        if old.is_empty() {
                            cands.clone()
                        } else {
                            old
                        }
                    }
                    "ClosestToNextInstanceHour" => {
                        let key = |m: &Member| (self.now - m.launched_at).num_seconds().rem_euclid(3600);
                        let max = cands.iter().map(|m| key(m)).max().unwrap();
                        cands.iter().copied().filter(|m| key(m) == max).collect()
                    }
                    _ => {
                        // Default / AllocationStrategy: oldest template or
                        // configuration, then closest to the next hour.
                        let old: Vec<&Member> = cands.iter().copied().filter(|m| self.outdated(m)).collect();
                        let set = if old.is_empty() { cands.clone() } else { old };
                        let key = |m: &Member| (self.now - m.launched_at).num_seconds().rem_euclid(3600);
                        let max = set.iter().map(|m| key(m)).max().unwrap();
                        set.into_iter().filter(|m| key(m) == max).collect()
                    }
                };
                if !narrowed.is_empty() {
                    cands = narrowed;
                }
            }
            let Some(pick) = cands.choose(&mut rng).map(|m| m.instance_id.clone()) else { break };
            pool.retain(|m| m.instance_id != pick);
            chosen.push(pick);
        }
        chosen
    }

    pub fn plan(&mut self) {
        let now = self.now;
        let ids: Vec<String> = self.g.members.keys().cloned().collect();
        for id in &ids {
            self.step_member(id);
        }
        let desired = self.g.cfg.desired_capacity.max(0) as usize;
        let counted = self.g.counted().count();
        let mut planned: Vec<LaunchReq> = Vec::new();
        let backoff = self.g.launch_backoff_until.is_some_and(|b| now < b);
        if counted < desired && !self.g.suspended("Launch") && !backoff && !self.g.subnet_zones.is_empty() {
            let base = self.g.pending_cause.take().map(|c| format!("{c}  ")).unwrap_or_default();
            let cause = format!(
                "{base}{} an instance was started in response to a difference between desired and actual capacity, increasing the capacity from {counted} to {desired}.",
                at(now)
            );
            for _ in counted..desired {
                // Prefer a warmed instance.
                let warmed = self
                    .g
                    .members
                    .values()
                    .filter(|m| {
                        m.warm
                            && matches!(
                                m.lifecycle_state.as_str(),
                                "Warmed:Running" | "Warmed:Stopped" | "Warmed:Hibernated"
                            )
                    })
                    .min_by_key(|m| (m.lifecycle_state != "Warmed:Running", m.launched_at))
                    .map(|m| {
                        (
                            m.instance_id.clone(),
                            m.lifecycle_state.clone(),
                            m.subnet_id.clone(),
                            m.availability_zone.clone(),
                        )
                    });
                if let Some((wid, st, subnet, zone)) = warmed {
                    let details = json!({"Subnet ID": subnet.unwrap_or_default(), "Availability Zone": zone});
                    let activity = new_activity(
                        self.activities,
                        self.g,
                        format!("Launching a new EC2 instance from warm pool: {wid}"),
                        cause.clone(),
                        "PreInService",
                        now,
                        details,
                    );
                    let m = self.g.members.get_mut(&wid).expect("member");
                    m.warm = false;
                    m.lifecycle_state = "Pending".into();
                    m.activity_id = Some(activity);
                    m.hooks_done.clear();
                    if st != "Warmed:Running" {
                        self.ops.push(Op::Start(wid));
                    }
                    self.changed = true;
                    continue;
                }
                match self.plan_launch(&planned, false, cause.clone(), None) {
                    Some(l) => planned.push(l),
                    None => break,
                }
            }
        } else if counted > desired && !self.g.suspended("Terminate") {
            let base = self.g.pending_cause.take().map(|c| format!("{c}  ")).unwrap_or_default();
            let cause = format!(
                "{base}{} an instance was taken out of service in response to a difference between desired and actual capacity, shrinking the capacity from {counted} to {desired}.",
                at(now)
            );
            let reuse = self
                .g
                .cfg
                .warm_pool_configuration
                .as_ref()
                .and_then(|w| w.instance_reuse_policy.as_ref().and_then(|p| p.reuse_on_scale_in))
                .unwrap_or(false)
                && !self.g.deleting;
            for id in self.victims(counted - desired, false) {
                self.mark_terminating(&id, cause.clone(), reuse);
            }
        } else if counted == desired
            && desired > 0
            && !self.g.suspended("AZRebalance")
            && !self.g.suspended("Launch")
            && !self.g.suspended("Terminate")
            && self
                .g
                .members
                .values()
                .all(|m| m.warm || m.lifecycle_state == "InService" || m.lifecycle_state == "Standby")
        {
            // Zone rebalancing: launch in the emptiest zone first; the
            // surplus is then taken from the fullest.
            let counts = self.zone_counts(&[], false);
            let (min_z, min_c) = counts
                .iter()
                .min_by_key(|(z, c)| (**c, (*z).clone()))
                .map(|(z, c)| (z.clone(), *c))
                .unwrap_or_default();
            let max_c = counts.values().copied().max().unwrap_or(0);
            let movable = self.victims(1, false).len() == 1;
            if max_c > min_c + 1 && movable && !backoff {
                let cause = format!("{} an instance was launched to aid in balancing the group's zones.", at(now));
                if let Some(l) = self.plan_launch(&planned, false, cause, Some(min_z)) {
                    planned.push(l);
                }
            }
        }
        self.plan_warm_pool(&mut planned);
        if self.g.deleting && desired == 0 {
            // Deleting a group also empties its warm pool.
            let warm: Vec<String> = self
                .g
                .members
                .values()
                .filter(|m| m.warm && !m.lifecycle_state.starts_with("Terminating"))
                .map(|m| m.instance_id.clone())
                .collect();
            for id in warm {
                let cause = format!("{} an instance was taken out of service in response to a user request.", at(now));
                self.mark_terminating(&id, cause, false);
            }
        }
        self.ops.extend(planned.into_iter().map(|l| Op::Launch(Box::new(l))));
    }

    fn plan_warm_pool(&mut self, planned: &mut Vec<LaunchReq>) {
        let now = self.now;
        let Some(wp) = self.g.cfg.warm_pool_configuration.clone() else { return };
        let warm: Vec<String> = self
            .g
            .members
            .values()
            .filter(|m| m.warm && !m.lifecycle_state.starts_with("Terminating"))
            .map(|m| m.instance_id.clone())
            .collect();
        if wp.status.as_deref() == Some("PendingDelete") {
            for id in &warm {
                let cause = format!("{} an instance was taken out of service in response to a user request.", at(now));
                self.mark_terminating(id, cause, false);
            }
            if self.g.members.values().all(|m| !m.warm) {
                self.g.cfg.warm_pool_configuration = None;
                self.g.cfg.warm_pool_size = None;
                self.changed = true;
            }
            return;
        }
        let max_prepared = wp.max_group_prepared_capacity.filter(|m| *m >= 0).unwrap_or(self.g.cfg.max_size);
        let target = (max_prepared - self.g.cfg.desired_capacity).max(wp.min_size.unwrap_or(0)).max(0) as usize;
        self.g.cfg.warm_pool_size = Some(target as i32);
        if warm.len() < target && !self.g.suspended("Launch") && !self.g.launch_backoff_until.is_some_and(|b| now < b) {
            let cause = format!(
                "{} an instance was launched in response to a difference between desired and actual warm pool capacity, increasing the capacity from {} to {target}.",
                at(now),
                warm.len()
            );
            for _ in warm.len()..target {
                match self.plan_launch(planned, true, cause.clone(), None) {
                    Some(l) => planned.push(l),
                    None => break,
                }
            }
        } else if warm.len() > target {
            let cause = format!(
                "{} an instance was taken out of service in response to a difference between desired and actual warm pool capacity, shrinking the capacity from {} to {target}.",
                at(now),
                warm.len()
            );
            for id in self.victims(warm.len() - target, true) {
                self.mark_terminating(&id, cause.clone(), false);
            }
        }
    }
}

/// A 5-field Unix cron expression as an AWS 6-field schedule.
pub(crate) fn cron_schedule(expr: &str) -> Option<mws_schedule::Schedule> {
    let f: Vec<&str> = expr.split_whitespace().collect();
    if f.len() != 5 {
        return None;
    }
    // Unix day-of-week counts Sunday as 0 (or 7); AWS counts it as 1.
    let dow: String = f[4]
        .split(',')
        .map(|part| {
            part.split('-')
                .map(|n| match n.parse::<u32>() {
                    Ok(d) => ((d % 7) + 1).to_string(),
                    Err(_) => n.to_string(),
                })
                .collect::<Vec<_>>()
                .join("-")
        })
        .collect::<Vec<_>>()
        .join(",");
    let (dom, dow) = match (f[2], dow.as_str()) {
        (_, "*") => (f[2].to_string(), "?".to_string()),
        ("*", d) => ("?".to_string(), d.to_string()),
        (d, w) => (d.to_string(), if w == "?" { "?".into() } else { w.to_string() }),
    };
    let dow = if dom != "?" && dow != "?" { "?".to_string() } else { dow };
    mws_schedule::Schedule::parse(&format!("cron({} {} {dom} {} {dow} *)", f[0], f[1], f[3]))
}

impl AutoScaling {
    pub(crate) async fn reconcile_region(
        &self,
        template: &RequestContext,
        account: &str,
        region: &str,
        now: DateTime<Utc>,
    ) {
        let sctx = self.service_ctx(template, account, region);
        let names: Vec<String> = {
            let st = self.lock();
            st.regions.get(&State::key(account, region)).map(|r| r.groups.keys().cloned().collect()).unwrap_or_default()
        };
        for name in names {
            for _ in 0..6 {
                if !self.reconcile_group(&sctx, account, region, &name, now).await {
                    break;
                }
            }
            self.run_scheduled_actions(account, region, &name, now);
            self.publish_metrics(account, region, &name, now);
        }
    }

    /// Resolve the launch source a group's launches use now.
    pub(crate) fn resolve_source(
        &self,
        ctx: &RequestContext,
        g: &Group,
        lcs: &BTreeMap<String, t::LaunchConfiguration>,
    ) -> Source {
        let resolve = |spec: &t::LaunchTemplateSpecification| {
            self.ec2()
                .resolve_launch_template(
                    ctx,
                    &et::LaunchTemplateSpecification {
                        launch_template_id: spec.launch_template_id.clone(),
                        launch_template_name: spec.launch_template_name.clone(),
                        version: spec.version.clone(),
                    },
                )
                .ok()
        };
        let group_spec = g.cfg.launch_template.clone().or_else(|| {
            g.cfg
                .mixed_instances_policy
                .as_ref()
                .and_then(|m| m.launch_template.as_ref().and_then(|l| l.launch_template_specification.clone()))
        });
        let current = group_spec.as_ref().and_then(resolve);
        // A refresh launches its desired configuration; a rollback launches
        // the group's own (which only changes when a refresh succeeds).
        let refresh = g
            .active_refresh()
            .filter(|r| r.info.status.as_deref() != Some("RollbackInProgress"))
            .and_then(|r| r.info.desired_configuration.clone());
        let (spec, overrides) = match &refresh {
            Some(dc) if dc.launch_template.is_some() || dc.mixed_instances_policy.is_some() => (
                dc.launch_template.clone().or_else(|| {
                    dc.mixed_instances_policy
                        .as_ref()
                        .and_then(|m| m.launch_template.as_ref().and_then(|l| l.launch_template_specification.clone()))
                }),
                dc.mixed_instances_policy
                    .as_ref()
                    .and_then(|m| m.launch_template.as_ref().and_then(|l| l.overrides.clone()))
                    .unwrap_or_default(),
            ),
            _ => (
                group_spec.clone(),
                g.cfg
                    .mixed_instances_policy
                    .as_ref()
                    .and_then(|m| m.launch_template.as_ref().and_then(|l| l.overrides.clone()))
                    .unwrap_or_default(),
            ),
        };
        let used = spec.as_ref().and_then(resolve);
        Source {
            template: used.as_ref().map(|r| (r.id.clone(), r.version)),
            template_data: used.map(|r| r.data),
            current_template: current.map(|r| (r.id, r.version)),
            configuration: if spec.is_none() {
                g.cfg.launch_configuration_name.as_ref().and_then(|n| lcs.get(n).cloned())
            } else {
                None
            },
            overrides,
        }
    }

    /// One pass over a group. `true` when something changed (so another
    /// pass may make progress at once).
    async fn reconcile_group(
        &self,
        sctx: &RequestContext,
        account: &str,
        region: &str,
        name: &str,
        now: DateTime<Utc>,
    ) -> bool {
        let key = State::key(account, region);
        let (ids, g_snapshot, lcs) = {
            let st = self.lock();
            let Some(r) = st.regions.get(&key) else { return false };
            let Some(g) = r.groups.get(name) else { return false };
            (g.members.keys().cloned().collect::<Vec<_>>(), g.clone(), r.launch_configurations.clone())
        };
        let source = self.resolve_source(sctx, &g_snapshot, &lcs);
        let info = match self.ec2_instances(sctx, &ids).await {
            Ok(i) => i,
            Err(e) => {
                tracing::warn!(group = name, "Auto Scaling could not describe its instances: {}", e.message);
                return false;
            }
        };
        let (ops, changed, group_arn, group_tags, delete) = {
            let mut st = self.lock();
            let Some(r) = st.regions.get_mut(&key) else { return false };
            let RegionState { groups, activities, .. } = r;
            let Some(g) = groups.get_mut(name) else { return false };
            let mut p = Planner {
                g,
                activities,
                info: &info,
                source: &source,
                now,
                account,
                region,
                partition: &sctx.partition,
                ops: Vec::new(),
                changed: false,
            };
            p.plan();
            crate::ops::refresh::advance(&mut p);
            let ops = std::mem::take(&mut p.ops);
            let changed = p.changed;
            let delete = g.deleting && g.members.is_empty();
            let tags: Vec<t::TagDescription> = g.cfg.tags.clone().unwrap_or_default();
            let arn = g.arn();
            if delete {
                groups.remove(name);
            }
            (ops, changed, arn, tags, delete)
        };
        if delete {
            if let Some(alarms) = self.alarms() {
                let names: Vec<String> = g_snapshot.policy_alarms.values().flatten().cloned().collect();
                if !names.is_empty() {
                    alarms.delete_alarms(sctx, &names);
                }
            }
        }
        let had_ops = !ops.is_empty();
        self.execute(sctx, account, region, name, &group_arn, &group_tags, ops, now).await;
        changed || had_ops
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn execute(
        &self,
        sctx: &RequestContext,
        account: &str,
        region: &str,
        name: &str,
        group_arn: &str,
        tags: &[t::TagDescription],
        ops: Vec<Op>,
        now: DateTime<Utc>,
    ) {
        let key = State::key(account, region);
        for op in ops {
            match op {
                Op::Launch(req) => {
                    let result = self.launch(sctx, name, tags, &req).await;
                    let mut followups = Vec::new();
                    {
                        let mut st = self.lock();
                        let Some(r) = st.regions.get_mut(&key) else { continue };
                        let RegionState { groups, activities, .. } = r;
                        let Some(g) = groups.get_mut(name) else { continue };
                        match result {
                            Ok((id, itype, image)) => {
                                if let Some(a) = activities.iter_mut().rev().find(|a| a.activity_id == req.activity_id)
                                {
                                    a.description = Some(if req.warm {
                                        format!("Launching a new EC2 instance into warm pool: {id}")
                                    } else {
                                        format!("Launching a new EC2 instance: {id}")
                                    });
                                    a.progress = Some(20);
                                }
                                g.members.insert(
                                    id.clone(),
                                    Member {
                                        instance_id: id,
                                        instance_type: itype,
                                        availability_zone: req.availability_zone.clone(),
                                        availability_zone_id: req.availability_zone_id.clone(),
                                        subnet_id: req.subnet_id.clone(),
                                        lifecycle_state: if req.warm { "Warmed:Pending" } else { "Pending" }.into(),
                                        health_status: "Healthy".into(),
                                        launch_configuration_name: req
                                            .launch_configuration
                                            .as_ref()
                                            .map(|l| l.launch_configuration_name.clone()),
                                        launch_template: req.launch_template.as_ref().map(|(id, v)| {
                                            t::LaunchTemplateSpecification {
                                                launch_template_id: Some(id.clone()),
                                                launch_template_name: g
                                                    .cfg
                                                    .launch_template
                                                    .as_ref()
                                                    .and_then(|l| l.launch_template_name.clone())
                                                    .or_else(|| {
                                                        g.cfg.mixed_instances_policy.as_ref().and_then(|m| {
                                                            m.launch_template.as_ref().and_then(|l| {
                                                                l.launch_template_specification
                                                                    .as_ref()
                                                                    .and_then(|s| s.launch_template_name.clone())
                                                            })
                                                        })
                                                    }),
                                                version: Some(v.to_string()),
                                            }
                                        }),
                                        image_id: image,
                                        protected_from_scale_in: g.cfg.new_instances_protected_from_scale_in
                                            == Some(true)
                                            && !req.warm,
                                        weighted_capacity: req.weighted_capacity.clone(),
                                        launched_at: now,
                                        warm: req.warm,
                                        activity_id: Some(req.activity_id.clone()),
                                        ..Default::default()
                                    },
                                );
                            }
                            Err(message) => {
                                g.launch_backoff_until = Some(now + Duration::seconds(10));
                                if let Some(a) = activities.iter_mut().rev().find(|a| a.activity_id == req.activity_id)
                                {
                                    a.status_code = "Failed".into();
                                    a.end_time = Some(now);
                                    a.progress = Some(100);
                                    a.description = Some(format!(
                                        "Launching a new EC2 instance.  Status Reason: {message} Launching EC2 instance failed."
                                    ));
                                    a.status_message = Some(format!("{message} Launching EC2 instance failed."));
                                    let a = a.clone();
                                    followups.extend(group_notifications(
                                        g,
                                        "autoscaling:EC2_INSTANCE_LAUNCH_ERROR",
                                        account,
                                        &a,
                                        "",
                                    ));
                                    followups.push(activity_event(
                                        "EC2 Instance Launch Unsuccessful",
                                        g,
                                        &a,
                                        String::new(),
                                        "",
                                    ));
                                }
                            }
                        }
                    }
                    for f in followups {
                        self.deliver(sctx, account, region, group_arn, f, now);
                    }
                }
                Op::Terminate(id) => {
                    if let Err(e) = self.ec2_terminate(sctx, vec![id.clone()]).await {
                        let mut st = self.lock();
                        if let Some(g) = st.regions.get_mut(&key).and_then(|r| r.groups.get_mut(name)) {
                            if let Some(m) = g.members.get_mut(&id) {
                                // Try again on a later pass.
                                m.terminate_sent = false;
                            }
                            g.launch_backoff_until = Some(now + Duration::seconds(10));
                        }
                        tracing::warn!(instance = %id, "Auto Scaling could not terminate an instance: {}", e.message);
                    }
                }
                Op::Stop(id, hibernate) => {
                    if let Err(e) = self.ec2_stop(sctx, vec![id.clone()], hibernate).await {
                        tracing::warn!(instance = %id, "Auto Scaling could not stop an instance: {}", e.message);
                    }
                }
                Op::Start(id) => {
                    if let Err(e) = self.ec2_start(sctx, vec![id.clone()]).await {
                        tracing::warn!(instance = %id, "Auto Scaling could not start an instance: {}", e.message);
                    }
                }
                other => self.deliver(sctx, account, region, group_arn, other, now),
            }
        }
    }

    pub(crate) fn deliver(
        &self,
        sctx: &RequestContext,
        account: &str,
        region: &str,
        group_arn: &str,
        op: Op,
        now: DateTime<Utc>,
    ) {
        match op {
            Op::Notify { target, role, subject, message } => {
                if let Some(sink) = self.notifications() {
                    if let Err(e) = sink.send(sctx, &target, role.as_deref(), subject.as_deref(), &message, group_arn) {
                        tracing::warn!(target = %target, "Auto Scaling notification failed: {e}");
                    }
                }
            }
            Op::Event { detail_type, resources, detail } => {
                if let Some(sink) = self.events() {
                    sink.put(
                        sctx,
                        AutoScalingEvent {
                            account: account.to_string(),
                            region: region.to_string(),
                            detail_type,
                            resources,
                            detail,
                            time: now,
                        },
                    );
                }
            }
            Op::Traffic { register, target, instance_ids } => {
                self.deliver_traffic(sctx, Op::Traffic { register, target, instance_ids })
            }
            _ => {}
        }
    }

    pub(crate) fn deliver_traffic(&self, sctx: &RequestContext, op: Op) {
        let (Some(sink), Op::Traffic { register, target, instance_ids }) = (self.traffic(), op) else { return };
        let result = if register {
            sink.register(sctx, &target, &instance_ids)
        } else {
            sink.deregister(sctx, &target, &instance_ids)
        };
        if let Err(e) = result {
            tracing::warn!(target = ?target, "Auto Scaling could not update load balancer registrations: {e}");
        }
    }

    /// Launch one instance for a group. Returns its id, type and AMI, or
    /// EC2's error message.
    async fn launch(
        &self,
        sctx: &RequestContext,
        group: &str,
        tags: &[t::TagDescription],
        req: &LaunchReq,
    ) -> Result<(String, String, Option<String>), String> {
        let mut input = et::RunInstancesRequest { min_count: 1, max_count: 1, ..Default::default() };
        let instance_tags: Vec<et::Tag> = tags
            .iter()
            .filter(|t| t.propagate_at_launch == Some(true))
            .map(|t| et::Tag { key: t.key.clone(), value: Some(t.value.clone().unwrap_or_default()) })
            .collect();
        if !instance_tags.is_empty() {
            input.tag_specifications =
                Some(vec![et::TagSpecification { resource_type: Some("instance".into()), tags: Some(instance_tags) }]);
        }
        if let Some((id, version)) = &req.launch_template {
            input.launch_template = Some(et::LaunchTemplateSpecification {
                launch_template_id: Some(id.clone()),
                launch_template_name: None,
                version: Some(version.to_string()),
            });
            let nis = req.template_data.as_ref().and_then(|d| d.network_interfaces.clone()).unwrap_or_default();
            if nis.is_empty() {
                input.subnet_id = req.subnet_id.clone();
            } else {
                let mut converted: Vec<et::InstanceNetworkInterfaceSpecification> = nis
                    .iter()
                    .filter_map(|n| {
                        let v = strip_nulls(serde_json::to_value(n).ok()?);
                        serde_json::from_value(v).ok()
                    })
                    .collect();
                if let Some(primary) = converted.iter_mut().find(|n| n.device_index.unwrap_or(0) == 0) {
                    primary.subnet_id = req.subnet_id.clone();
                }
                input.network_interfaces = Some(converted);
            }
            if req.instance_type.is_some() {
                input.instance_type = req.instance_type.clone();
            }
            if req.image_id.is_some() {
                input.image_id = req.image_id.clone();
            }
        } else if let Some(lc) = &req.launch_configuration {
            input.image_id = Some(lc.image_id.clone());
            input.instance_type = Some(lc.instance_type.clone());
            input.key_name = lc.key_name.clone();
            input.user_data = lc.user_data.clone();
            input.ebs_optimized = lc.ebs_optimized;
            input.kernel_id = lc.kernel_id.clone();
            input.ramdisk_id = lc.ramdisk_id.clone();
            input.monitoring = lc
                .instance_monitoring
                .as_ref()
                .map(|m| et::RunInstancesMonitoringEnabled { enabled: m.enabled.unwrap_or(true) });
            input.iam_instance_profile = lc.iam_instance_profile.as_ref().map(|p| {
                if p.starts_with("arn:") {
                    et::IamInstanceProfileSpecification { arn: Some(p.clone()), name: None }
                } else {
                    et::IamInstanceProfileSpecification { arn: None, name: Some(p.clone()) }
                }
            });
            input.metadata_options = lc.metadata_options.as_ref().map(|m| et::InstanceMetadataOptionsRequest {
                http_tokens: m.http_tokens.clone(),
                http_put_response_hop_limit: m.http_put_response_hop_limit,
                http_endpoint: m.http_endpoint.clone(),
                ..Default::default()
            });
            input.placement =
                lc.placement_tenancy.as_ref().map(|t| et::Placement { tenancy: Some(t.clone()), ..Default::default() });
            input.block_device_mappings = lc.block_device_mappings.as_ref().map(|list| {
                list.iter()
                    .map(|b| et::BlockDeviceMapping {
                        device_name: Some(b.device_name.clone()),
                        virtual_name: b.virtual_name.clone(),
                        no_device: b.no_device.filter(|n| *n).map(|_| String::new()),
                        ebs: b.ebs.as_ref().map(|e| et::EbsBlockDevice {
                            snapshot_id: e.snapshot_id.clone(),
                            volume_size: e.volume_size,
                            volume_type: e.volume_type.clone(),
                            delete_on_termination: e.delete_on_termination,
                            iops: e.iops,
                            encrypted: e.encrypted,
                            throughput: e.throughput,
                            ..Default::default()
                        }),
                    })
                    .collect()
            });
            let (ids, names): (Vec<String>, Vec<String>) =
                lc.security_groups.clone().unwrap_or_default().into_iter().partition(|g| g.starts_with("sg-"));
            if let Some(public) = lc.associate_public_ip_address {
                input.network_interfaces = Some(vec![et::InstanceNetworkInterfaceSpecification {
                    device_index: Some(0),
                    subnet_id: req.subnet_id.clone(),
                    associate_public_ip_address: Some(public),
                    groups: (!ids.is_empty()).then_some(ids),
                    delete_on_termination: Some(true),
                    ..Default::default()
                }]);
            } else {
                input.subnet_id = req.subnet_id.clone();
                if !ids.is_empty() {
                    input.security_group_ids = Some(ids);
                }
                if !names.is_empty() {
                    input.security_groups = Some(names);
                }
            }
        } else {
            return Err("The group has no launch template or launch configuration.".into());
        }
        let system_tags =
            vec![et::Tag { key: Some("aws:autoscaling:groupName".into()), value: Some(group.to_string()) }];
        let reservation = self.ec2().run_instances_as_service(sctx, input, system_tags).await.map_err(|e| {
            let m = e.message.trim_end_matches('.').to_string();
            format!("{m}.")
        })?;
        let i = reservation.instances.unwrap_or_default().into_iter().next().ok_or("No instance was launched.")?;
        Ok((i.instance_id.unwrap_or_default(), i.instance_type.unwrap_or_default(), i.image_id))
    }

    fn run_scheduled_actions(&self, account: &str, region: &str, name: &str, now: DateTime<Utc>) {
        let mut st = self.lock();
        let Some(r) = st.regions.get_mut(&State::key(account, region)) else { return };
        let Some(g) = r.groups.get_mut(name) else { return };
        if g.suspended("ScheduledActions") || g.deleting {
            return;
        }
        let actions: Vec<t::ScheduledUpdateGroupAction> = g.scheduled.values().cloned().collect();
        for a in actions {
            let name = a.scheduled_action_name.clone().unwrap_or_default();
            let start = a.start_time.or(a.time);
            if a.end_time.is_some_and(|e| now > e) {
                g.scheduled.remove(&name);
                continue;
            }
            let due = match &a.recurrence {
                None => start.is_some_and(|s| s <= now),
                Some(expr) => {
                    if start.is_some_and(|s| s > now) {
                        false
                    } else {
                        let last = g.scheduled_ran.get(&name).copied().or(start).unwrap_or(now - Duration::seconds(1));
                        cron_schedule(expr).is_some_and(|s| !s.fires_between(last, last, now, 1).is_empty())
                    }
                }
            };
            if !due {
                continue;
            }
            g.scheduled_ran.insert(name.clone(), now);
            if a.recurrence.is_none() {
                g.scheduled.remove(&name);
            }
            let before = g.cfg.desired_capacity;
            if let Some(v) = a.min_size {
                g.cfg.min_size = v;
            }
            if let Some(v) = a.max_size {
                g.cfg.max_size = v;
            }
            if let Some(v) = a.desired_capacity {
                g.cfg.desired_capacity = v;
            }
            g.cfg.desired_capacity = g.cfg.desired_capacity.clamp(g.cfg.min_size, g.cfg.max_size.max(g.cfg.min_size));
            let fmt = |v: Option<i32>| v.map(|v| v.to_string()).unwrap_or_else(|| "-".into());
            let cause = format!(
                "{} a scheduled action update of AutoScalingGroup constraints to min: {}, max: {}, desired: {} changing the desired capacity from {before} to {}.",
                at(now),
                fmt(a.min_size),
                fmt(a.max_size),
                fmt(a.desired_capacity),
                g.cfg.desired_capacity
            );
            if g.cfg.desired_capacity != before {
                g.pending_cause = Some(cause);
            }
        }
    }

    fn publish_metrics(&self, account: &str, region: &str, name: &str, now: DateTime<Utc>) {
        let Some(sink) = self.metrics() else { return };
        let metrics = {
            let mut st = self.lock();
            let Some(g) = st.regions.get_mut(&State::key(account, region)).and_then(|r| r.groups.get_mut(name)) else {
                return;
            };
            let enabled: Vec<String> =
                g.cfg.enabled_metrics.iter().flatten().filter_map(|m| m.metric.clone()).collect();
            if enabled.is_empty() {
                return;
            }
            let minute = now.timestamp() / 60;
            if g.metrics_published.is_some_and(|p| p.timestamp() / 60 == minute) {
                return;
            }
            g.metrics_published = Some(now);
            let count = |f: &dyn Fn(&Member) -> bool| g.members.values().filter(|m| f(m)).count() as f64;
            let in_service = count(&|m| !m.warm && m.lifecycle_state == "InService");
            let pending = count(&|m| !m.warm && m.lifecycle_state.starts_with("Pending"));
            let standby = count(&|m| !m.warm && m.lifecycle_state == "Standby");
            let terminating = count(&|m| !m.warm && m.lifecycle_state.starts_with("Terminating"));
            let warm_total = count(&|m| m.warm);
            let warm_warmed = count(&|m| {
                m.warm
                    && matches!(m.lifecycle_state.as_str(), "Warmed:Running" | "Warmed:Stopped" | "Warmed:Hibernated")
            });
            let warm_pending = count(&|m| m.warm && m.lifecycle_state.starts_with("Warmed:Pending"));
            let warm_terminating = count(&|m| m.warm && m.lifecycle_state.starts_with("Terminating"));
            let total = in_service + pending + standby + terminating;
            let warm_desired = g.cfg.warm_pool_size.unwrap_or(0) as f64;
            let ts = DateTime::from_timestamp(minute * 60, 0).unwrap_or(now);
            enabled
                .into_iter()
                .filter_map(|m| {
                    let value = match m.as_str() {
                        "GroupMinSize" => g.cfg.min_size as f64,
                        "GroupMaxSize" => g.cfg.max_size as f64,
                        "GroupDesiredCapacity" => g.cfg.desired_capacity as f64,
                        "GroupInServiceInstances" | "GroupInServiceCapacity" => in_service,
                        "GroupPendingInstances" | "GroupPendingCapacity" => pending,
                        "GroupStandbyInstances" | "GroupStandbyCapacity" => standby,
                        "GroupTerminatingInstances" | "GroupTerminatingCapacity" => terminating,
                        "GroupTotalInstances" | "GroupTotalCapacity" => total,
                        "WarmPoolDesiredCapacity" => warm_desired,
                        "WarmPoolWarmedCapacity" => warm_warmed,
                        "WarmPoolPendingCapacity" => warm_pending,
                        "WarmPoolTerminatingCapacity" => warm_terminating,
                        "WarmPoolTotalCapacity" => warm_total,
                        "GroupAndWarmPoolDesiredCapacity" => g.cfg.desired_capacity as f64 + warm_desired,
                        "GroupAndWarmPoolTotalCapacity" => total + warm_total,
                        _ => return None,
                    };
                    Some(GroupMetric {
                        account: account.to_string(),
                        region: region.to_string(),
                        group: name.to_string(),
                        metric_name: m,
                        value,
                        timestamp: ts,
                    })
                })
                .collect::<Vec<_>>()
        };
        sink.publish(metrics);
    }
}

fn strip_nulls(v: Value) -> Value {
    match v {
        Value::Object(m) => {
            Value::Object(m.into_iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k, strip_nulls(v))).collect())
        }
        Value::Array(a) => Value::Array(a.into_iter().map(strip_nulls).collect()),
        other => other,
    }
}

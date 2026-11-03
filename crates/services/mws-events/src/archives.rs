//! Archives, which keep the events on a bus that match them, and replays,
//! which send archived events back through the bus.

use mws_core::{ConditionContext, RequestContext, ServiceError};
use serde_json::{json, Value};

use crate::generated::{errors, types};
use crate::ingest::ReplayInfo;
use crate::names::{self, arn, not_found, own_region, validation, BusRef};
use crate::pattern::Pattern;
use crate::rules::{invalid_pattern, managed_rule_name};
use crate::state::{Archive, Replay, Rule};
use crate::Events;

const MANAGER: &str = "events.amazonaws.com";

fn archive_missing(name: &str) -> ServiceError {
    not_found(format!("Archive {name} does not exist."))
}

fn replay_missing(name: &str) -> ServiceError {
    not_found(format!("Replay {name} does not exist."))
}

/// The pattern of the rule EventBridge manages for an archive: the
/// archive's pattern, never matching replayed events.
fn managed_pattern(pattern: Option<&str>) -> String {
    let mut v: Value = pattern.and_then(|p| serde_json::from_str(p).ok()).unwrap_or_else(|| json!({}));
    v["replay-name"] = json!([{ "exists": false }]);
    v.to_string()
}

impl Events {
    fn set_managed_rule(&self, ctx: &RequestContext, bus: &BusRef, archive: &str, pattern: Option<&str>) {
        let name = managed_rule_name(archive);
        let arn = bus.rule_arn(&name);
        let now = ctx.received_at;
        let _ = self.with_bus(ctx, bus, |b| {
            let rule = b.rules.entry(name.clone()).or_insert_with(|| Rule {
                name: name.clone(),
                arn,
                managed_by: Some(MANAGER.into()),
                created_at: now,
                created_by: Some(bus.account.clone()),
                description: Some(format!("Rule for archive {archive}")),
                ..Rule::default()
            });
            rule.event_pattern = Some(managed_pattern(pattern));
            Ok(())
        });
    }

    fn archive(&self, ctx: &RequestContext, name: &str) -> Result<Archive, ServiceError> {
        let mut st = self.lock();
        own_region(&mut st, ctx).archives.get(name).cloned().ok_or_else(|| archive_missing(name))
    }

    pub fn create_archive(
        &self,
        ctx: &RequestContext,
        input: types::CreateArchiveRequest,
    ) -> Result<types::CreateArchiveResponse, ServiceError> {
        let archive_arn = arn(ctx, &format!("archive/{}", input.archive_name));
        ctx.authorize("events:CreateArchive", &archive_arn, ConditionContext::new())?;
        let bus = BusRef::from_arn(&input.event_source_arn).ok_or_else(|| {
            validation(format!(
                "Parameter EventSourceArn is not valid. Reason: {} is not an event bus ARN.",
                input.event_source_arn
            ))
        })?;
        if bus.account != ctx.caller.account_id || bus.region != ctx.region {
            return Err(validation("Parameter EventSourceArn is not valid. Reason: Cross account or cross region archives are not supported."));
        }
        if let Some(p) = &input.event_pattern {
            Pattern::parse(p).map_err(invalid_pattern)?;
        }
        if !self.bus_exists(ctx, &bus) {
            return Err(bus.missing());
        }
        let now = ctx.received_at;
        {
            let mut st = self.lock();
            let region = own_region(&mut st, ctx);
            if region.archives.contains_key(&input.archive_name) {
                return Err(errors::resource_already_exists(format!("Archive {} already exists.", input.archive_name)));
            }
            region.archives.insert(
                input.archive_name.clone(),
                Archive {
                    name: input.archive_name.clone(),
                    arn: archive_arn.clone(),
                    event_source_arn: input.event_source_arn.clone(),
                    description: input.description,
                    event_pattern: input.event_pattern.clone(),
                    state: "ENABLED".into(),
                    state_reason: None,
                    retention_days: input.retention_days.unwrap_or(0),
                    kms_key_identifier: input.kms_key_identifier,
                    creation_time: Some(now),
                    events: Vec::new(),
                },
            );
        }
        self.set_managed_rule(ctx, &bus, &input.archive_name, input.event_pattern.as_deref());
        Ok(types::CreateArchiveResponse {
            archive_arn: Some(archive_arn),
            state: Some("ENABLED".into()),
            state_reason: None,
            creation_time: Some(now),
        })
    }

    pub fn describe_archive(
        &self,
        ctx: &RequestContext,
        input: types::DescribeArchiveRequest,
    ) -> Result<types::DescribeArchiveResponse, ServiceError> {
        let a = self.archive(ctx, &input.archive_name)?;
        ctx.authorize("events:DescribeArchive", &a.arn, ConditionContext::new())?;
        Ok(types::DescribeArchiveResponse {
            archive_arn: Some(a.arn.clone()),
            archive_name: Some(a.name.clone()),
            event_source_arn: Some(a.event_source_arn.clone()),
            description: a.description.clone(),
            event_pattern: a.event_pattern.clone(),
            state: Some(a.state.clone()),
            state_reason: a.state_reason.clone(),
            kms_key_identifier: a.kms_key_identifier.clone(),
            retention_days: Some(a.retention_days),
            size_bytes: a.size_bytes(),
            event_count: a.events.len() as i64,
            creation_time: a.creation_time,
        })
    }

    pub fn list_archives(
        &self,
        ctx: &RequestContext,
        input: types::ListArchivesRequest,
    ) -> Result<types::ListArchivesResponse, ServiceError> {
        ctx.authorize("events:ListArchives", "*", ConditionContext::new())?;
        let items: Vec<types::Archive> = {
            let mut st = self.lock();
            own_region(&mut st, ctx)
                .archives
                .values()
                .filter(|a| input.name_prefix.as_deref().is_none_or(|p| a.name.starts_with(p)))
                .filter(|a| input.event_source_arn.as_deref().is_none_or(|s| a.event_source_arn == s))
                .filter(|a| input.state.as_deref().is_none_or(|s| a.state == s))
                .map(|a| types::Archive {
                    archive_name: Some(a.name.clone()),
                    event_source_arn: Some(a.event_source_arn.clone()),
                    state: Some(a.state.clone()),
                    state_reason: a.state_reason.clone(),
                    retention_days: Some(a.retention_days),
                    size_bytes: a.size_bytes(),
                    event_count: a.events.len() as i64,
                    creation_time: a.creation_time,
                })
                .collect()
        };
        let (page, next_token) = names::paginate(items, input.next_token.as_deref(), input.limit, 100)?;
        Ok(types::ListArchivesResponse { archives: Some(page), next_token })
    }

    pub fn update_archive(
        &self,
        ctx: &RequestContext,
        input: types::UpdateArchiveRequest,
    ) -> Result<types::UpdateArchiveResponse, ServiceError> {
        let a = self.archive(ctx, &input.archive_name)?;
        ctx.authorize("events:UpdateArchive", &a.arn, ConditionContext::new())?;
        if let Some(p) = &input.event_pattern {
            Pattern::parse(p).map_err(invalid_pattern)?;
        }
        let out = {
            let mut st = self.lock();
            let a = own_region(&mut st, ctx)
                .archives
                .get_mut(&input.archive_name)
                .ok_or_else(|| archive_missing(&input.archive_name))?;
            if input.description.is_some() {
                a.description = input.description;
            }
            if input.event_pattern.is_some() {
                a.event_pattern = input.event_pattern.clone();
            }
            if let Some(r) = input.retention_days {
                a.retention_days = r;
            }
            if input.kms_key_identifier.is_some() {
                a.kms_key_identifier = input.kms_key_identifier.filter(|k| !k.is_empty());
            }
            (
                a.clone(),
                types::UpdateArchiveResponse {
                    archive_arn: Some(a.arn.clone()),
                    state: Some(a.state.clone()),
                    state_reason: a.state_reason.clone(),
                    creation_time: a.creation_time,
                },
            )
        };
        if let Some(bus) = BusRef::from_arn(&out.0.event_source_arn) {
            self.set_managed_rule(ctx, &bus, &out.0.name, out.0.event_pattern.as_deref());
        }
        Ok(out.1)
    }

    pub fn delete_archive(
        &self,
        ctx: &RequestContext,
        input: types::DeleteArchiveRequest,
    ) -> Result<types::DeleteArchiveResponse, ServiceError> {
        let a = self.archive(ctx, &input.archive_name)?;
        ctx.authorize("events:DeleteArchive", &a.arn, ConditionContext::new())?;
        {
            let mut st = self.lock();
            let region = own_region(&mut st, ctx);
            region.archives.remove(&input.archive_name);
            region.tags.remove(&a.arn);
        }
        if let Some(bus) = BusRef::from_arn(&a.event_source_arn) {
            let name = managed_rule_name(&a.name);
            let _ = self.with_bus(ctx, &bus, |b| {
                b.rules.remove(&name);
                Ok(())
            });
        }
        Ok(types::DeleteArchiveResponse {})
    }

    // ----- replays -----

    pub fn start_replay(
        &self,
        ctx: &RequestContext,
        input: types::StartReplayRequest,
    ) -> Result<types::StartReplayResponse, ServiceError> {
        let replay_arn = arn(ctx, &format!("replay/{}", input.replay_name));
        ctx.authorize("events:StartReplay", &replay_arn, ConditionContext::new())?;
        if input.event_start_time >= input.event_end_time {
            return Err(validation(
                "Parameter EventStartTime is not valid. Reason: EventStartTime must be before EventEndTime.",
            ));
        }
        let archive = {
            let mut st = self.lock();
            own_region(&mut st, ctx).archives.values().find(|a| a.arn == input.event_source_arn).cloned()
        }
        .ok_or_else(|| not_found(format!("Archive {} does not exist.", input.event_source_arn)))?;
        if input.destination.arn != archive.event_source_arn {
            return Err(validation(
                "Parameter Destination.Arn is not valid. Reason: Cross event bus replay is not permitted.",
            ));
        }
        let now = ctx.received_at;
        {
            let mut st = self.lock();
            let region = own_region(&mut st, ctx);
            if region.replays.contains_key(&input.replay_name) {
                return Err(errors::resource_already_exists(format!("Replay {} already exists.", input.replay_name)));
            }
            region.replays.insert(
                input.replay_name.clone(),
                Replay {
                    name: input.replay_name.clone(),
                    arn: replay_arn.clone(),
                    description: input.description,
                    state: "STARTING".into(),
                    state_reason: None,
                    event_source_arn: input.event_source_arn.clone(),
                    destination: input.destination.clone(),
                    event_start_time: Some(input.event_start_time),
                    event_end_time: Some(input.event_end_time),
                    event_last_replayed_time: None,
                    replay_start_time: Some(now),
                    replay_end_time: None,
                },
            );
        }
        if tokio::runtime::Handle::try_current().is_ok() {
            let me = self.clone();
            let ctx = ctx.clone();
            let name = input.replay_name.clone();
            tokio::spawn(async move { me.run_replay(ctx, name).await });
        }
        Ok(types::StartReplayResponse {
            replay_arn: Some(replay_arn),
            state: Some("STARTING".into()),
            state_reason: None,
            replay_start_time: Some(now),
        })
    }

    fn replay_state(&self, ctx: &RequestContext, name: &str, f: impl FnOnce(&mut Replay)) -> Option<Replay> {
        let mut st = self.lock();
        let r = st.regions.get_mut(&format!("{}/{}", ctx.caller.account_id, ctx.region))?.replays.get_mut(name)?;
        f(r);
        Some(r.clone())
    }

    async fn run_replay(&self, ctx: RequestContext, name: String) {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let Some(replay) = self.replay_state(&ctx, &name, |r| {
            if r.state == "STARTING" {
                r.state = "RUNNING".into();
            }
        }) else {
            return;
        };
        let events = {
            let st = self.lock();
            st.region(&ctx.caller.account_id, &ctx.region)
                .and_then(|r| r.archives.values().find(|a| a.arn == replay.event_source_arn))
                .map(|a| a.events.clone())
                .unwrap_or_default()
        };
        let mut events: Vec<_> = events
            .into_iter()
            .filter(|e| {
                let t = e.time.or(e.ingested);
                t.is_some_and(|t| Some(t) >= replay.event_start_time && Some(t) < replay.event_end_time)
            })
            .collect();
        events.sort_by_key(|e| e.time.or(e.ingested));
        let Some(bus) = BusRef::from_arn(&replay.destination.arn) else { return };
        let info =
            ReplayInfo { name: name.clone(), rules: replay.destination.filter_arns.clone().filter(|f| !f.is_empty()) };
        let ctx = self.delivery_ctx(&ctx);
        for e in events {
            let cancelled = self.replay_state(&ctx, &name, |_| {}).is_none_or(|r| r.state != "RUNNING");
            if cancelled {
                break;
            }
            if let Ok(event) = serde_json::from_str::<Value>(&e.event) {
                self.ingest(&ctx, &bus, &event, Some(&info));
            }
            self.replay_state(&ctx, &name, |r| r.event_last_replayed_time = e.time.or(e.ingested));
        }
        let now = self.now();
        self.replay_state(&ctx, &name, |r| {
            r.state = if r.state == "CANCELLING" { "CANCELLED" } else { "COMPLETED" }.into();
            r.replay_end_time = Some(now);
        });
    }

    pub fn describe_replay(
        &self,
        ctx: &RequestContext,
        input: types::DescribeReplayRequest,
    ) -> Result<types::DescribeReplayResponse, ServiceError> {
        let r = {
            let mut st = self.lock();
            own_region(&mut st, ctx).replays.get(&input.replay_name).cloned()
        }
        .ok_or_else(|| replay_missing(&input.replay_name))?;
        ctx.authorize("events:DescribeReplay", &r.arn, ConditionContext::new())?;
        Ok(types::DescribeReplayResponse {
            replay_name: Some(r.name),
            replay_arn: Some(r.arn),
            description: r.description,
            state: Some(r.state),
            state_reason: r.state_reason,
            event_source_arn: Some(r.event_source_arn),
            destination: Some(r.destination),
            event_start_time: r.event_start_time,
            event_end_time: r.event_end_time,
            event_last_replayed_time: r.event_last_replayed_time,
            replay_start_time: r.replay_start_time,
            replay_end_time: r.replay_end_time,
        })
    }

    pub fn list_replays(
        &self,
        ctx: &RequestContext,
        input: types::ListReplaysRequest,
    ) -> Result<types::ListReplaysResponse, ServiceError> {
        ctx.authorize("events:ListReplays", "*", ConditionContext::new())?;
        let items: Vec<types::Replay> = {
            let mut st = self.lock();
            own_region(&mut st, ctx)
                .replays
                .values()
                .filter(|r| input.name_prefix.as_deref().is_none_or(|p| r.name.starts_with(p)))
                .filter(|r| input.state.as_deref().is_none_or(|s| r.state == s))
                .filter(|r| input.event_source_arn.as_deref().is_none_or(|s| r.event_source_arn == s))
                .map(|r| types::Replay {
                    replay_name: Some(r.name.clone()),
                    event_source_arn: Some(r.event_source_arn.clone()),
                    state: Some(r.state.clone()),
                    state_reason: r.state_reason.clone(),
                    event_start_time: r.event_start_time,
                    event_end_time: r.event_end_time,
                    event_last_replayed_time: r.event_last_replayed_time,
                    replay_start_time: r.replay_start_time,
                    replay_end_time: r.replay_end_time,
                })
                .collect()
        };
        let (page, next_token) = names::paginate(items, input.next_token.as_deref(), input.limit, 100)?;
        Ok(types::ListReplaysResponse { replays: Some(page), next_token })
    }

    pub fn cancel_replay(
        &self,
        ctx: &RequestContext,
        input: types::CancelReplayRequest,
    ) -> Result<types::CancelReplayResponse, ServiceError> {
        let replay_arn = arn(ctx, &format!("replay/{}", input.replay_name));
        ctx.authorize("events:CancelReplay", &replay_arn, ConditionContext::new())?;
        let mut st = self.lock();
        let r = own_region(&mut st, ctx)
            .replays
            .get_mut(&input.replay_name)
            .ok_or_else(|| replay_missing(&input.replay_name))?;
        if !matches!(r.state.as_str(), "STARTING" | "RUNNING") {
            return Err(errors::illegal_status(format!(
                "Replay {} is in state {} and cannot be cancelled.",
                input.replay_name, r.state
            )));
        }
        r.state = "CANCELLING".into();
        Ok(types::CancelReplayResponse {
            replay_arn: Some(r.arn.clone()),
            state: Some(r.state.clone()),
            state_reason: None,
        })
    }
}

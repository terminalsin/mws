//! Stream lifecycle and configuration: create, delete, describe, list,
//! retention, capacity modes, resharding, encryption, monitoring and the
//! newer per-stream settings.

use std::collections::BTreeMap;

use base64::Engine;
use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::names::{
    authorize, authorize_account, authorize_stream, invalid_argument, not_active, now_ms, request_tag_context,
    stream_arn, valid_name, validate_tags, StreamRef,
};
use crate::shards::{new_shard, rescale, sequence_number, uniform_ranges};
use crate::state::{State, Stream, TRANSITION_MS};
use crate::Kinesis;

const MIN_RETENTION: i32 = 24;
const MAX_RETENTION: i32 = 8760;
const ON_DEMAND_SHARDS: i32 = 4;
const ON_DEMAND_STREAM_LIMIT: i32 = 50;
const DEFAULT_MAX_RECORD_KIB: i32 = 1024;
const DAY_MS: i64 = 86_400_000;
/// `UpdateShardCount` calls per stream per rolling 24 hours.
const MAX_SHARD_COUNT_UPDATES: usize = 10;
/// `UpdateShardCount` cannot scale a stream beyond this many shards.
const MAX_STREAM_SHARDS: i32 = 10_000;
/// Open `NextToken`s for `ListShards` and `ListStreams` last this long.
const TOKEN_TTL_MS: i64 = 300_000;

/// The account shard limit: 500 in the largest Regions, 200 elsewhere.
fn shard_limit(region: &str) -> i32 {
    if matches!(region, "us-east-1" | "us-west-2" | "eu-west-1") {
        500
    } else {
        200
    }
}

fn open_shard_count(st: &State, account: &str, region: &str) -> i32 {
    st.streams
        .values()
        .filter(|s| s.account == account && s.region == region)
        .map(|s| s.open_shards().count() as i32)
        .sum()
}

pub(crate) fn shard_wire(s: &Stream, sh: &crate::state::Shard) -> types::Shard {
    let id = |i: Option<u32>| i.map(crate::state::shard_id);
    types::Shard {
        shard_id: sh.id(),
        parent_shard_id: id(sh.parent),
        adjacent_parent_shard_id: id(sh.adjacent_parent),
        hash_key_range: types::HashKeyRange {
            starting_hash_key: sh.start_hash.to_string(),
            ending_hash_key: sh.end_hash.to_string(),
        },
        sequence_number_range: types::SequenceNumberRange {
            starting_sequence_number: sequence_number(s.created_at, sh.index, 0),
            ending_sequence_number: sh
                .closed_at
                .map(|_| sequence_number(s.created_at, sh.index, sh.next_counter.saturating_sub(1))),
        },
    }
}

fn mode_details(s: &Stream) -> types::StreamModeDetails {
    types::StreamModeDetails { stream_mode: s.mode.clone() }
}

fn monitoring(s: &Stream) -> Vec<types::EnhancedMetrics> {
    vec![types::EnhancedMetrics { shard_level_metrics: Some(s.shard_level_metrics.clone()) }]
}

fn time(ms: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp_millis(ms).unwrap_or_default()
}

fn warm(s: &Stream) -> Option<types::WarmThroughputObject> {
    (s.mode == "ON_DEMAND").then(|| types::WarmThroughputObject {
        target_mi_bps: Some(s.warm_throughput_mibps.unwrap_or(0)),
        current_mi_bps: Some(s.warm_throughput_mibps.unwrap_or(0)),
    })
}

fn encode_token(parts: &[&str]) -> String {
    base64::engine::general_purpose::STANDARD.encode(parts.join("|"))
}

fn decode_token(token: &str) -> Option<Vec<String>> {
    let raw = base64::engine::general_purpose::STANDARD.decode(token).ok()?;
    Some(String::from_utf8(raw).ok()?.split('|').map(str::to_string).collect())
}

fn transition(s: &mut Stream, status: &str, now: i64) {
    s.status = status.to_string();
    s.settles_at = now + TRANSITION_MS;
}

/// The stream must be in a state that accepts configuration changes.
fn updatable<'a>(st: &'a mut State, r: &StreamRef) -> Result<&'a mut Stream, ServiceError> {
    r.active_mut(st)
}

impl Kinesis {
    pub fn create_stream(&self, ctx: &RequestContext, input: types::CreateStreamInput) -> Result<(), ServiceError> {
        let name = input.stream_name;
        let account = ctx.caller.account_id.clone();
        let arn = stream_arn(&ctx.partition, &ctx.region, &account, &name);
        let tags = input.tags.unwrap_or_default();
        let mut context = request_tag_context(&tags);
        authorize(ctx, "kinesis:CreateStream", &arn, None, &BTreeMap::new(), context.clone())?;
        if !tags.is_empty() {
            context.retain(|k, _| k.starts_with("aws:"));
            authorize(ctx, "kinesis:AddTagsToStream", &arn, None, &BTreeMap::new(), context)?;
        }
        if !valid_name(&name) {
            return Err(invalid_argument(format!("Invalid stream name {name}.")));
        }
        validate_tags(&tags)?;
        let mode = input.stream_mode_details.map(|m| m.stream_mode).unwrap_or_else(|| {
            if input.shard_count.is_some() {
                "PROVISIONED".into()
            } else {
                "ON_DEMAND".into()
            }
        });
        let shard_count = match (mode.as_str(), input.shard_count) {
            ("ON_DEMAND", Some(_)) => {
                return Err(errors::validation("ShardCount is not supported for streams in ON_DEMAND mode."))
            }
            ("ON_DEMAND", None) => ON_DEMAND_SHARDS,
            (_, Some(n)) => n,
            (_, None) => return Err(errors::validation("ShardCount is required for streams in PROVISIONED mode.")),
        };
        if input.warm_throughput_mi_bps.is_some() && mode != "ON_DEMAND" {
            return Err(invalid_argument("Warm throughput is only supported for streams in ON_DEMAND mode."));
        }
        let distribution = input.record_distribution_strategy.unwrap_or_else(|| "USER_PARTITION_KEY".into());
        if distribution == "AUTO" && mode != "ON_DEMAND" {
            return Err(invalid_argument(
                "The AUTO record distribution strategy is only supported for streams in ON_DEMAND mode.",
            ));
        }
        let now = now_ms(ctx);
        let mut st = self.settled(ctx);
        if st.streams.contains_key(&arn) {
            return Err(errors::resource_in_use(format!("Stream {name} under account {account} already exists.")));
        }
        let open = open_shard_count(&st, &account, &ctx.region);
        let limit = shard_limit(&ctx.region);
        if open + shard_count > limit {
            return Err(errors::limit_exceeded(format!(
                "This request would exceed the shard limit for the account {account} in {}. Current shard count for the account: {open}. Limit: {limit}. Number of additional shards that would have resulted from this request: {shard_count}. Refer to the AWS Service Limits page (http://docs.aws.amazon.com/general/latest/gr/aws_service_limits.html#ksa_limits) for current limits and how to request higher limits.",
                ctx.region
            )));
        }
        if mode == "ON_DEMAND" {
            let on_demand = st
                .streams
                .values()
                .filter(|s| s.account == account && s.region == ctx.region && s.mode == "ON_DEMAND")
                .count() as i32;
            if on_demand >= ON_DEMAND_STREAM_LIMIT {
                return Err(errors::limit_exceeded(format!(
                    "This request would exceed the on-demand stream limit of {ON_DEMAND_STREAM_LIMIT} for the account {account} in {}.",
                    ctx.region
                )));
            }
        }
        let mut stream = Stream {
            name: name.clone(),
            arn: arn.clone(),
            id: uuid::Uuid::new_v4().simple().to_string(),
            account,
            region: ctx.region.clone(),
            created_at: now,
            status: "CREATING".into(),
            settles_at: now + TRANSITION_MS,
            mode,
            retention_hours: MIN_RETENTION,
            encryption_type: "NONE".into(),
            tags,
            warm_throughput_mibps: input.warm_throughput_mi_bps,
            max_record_size_kib: input.max_record_size_in_ki_b.unwrap_or(DEFAULT_MAX_RECORD_KIB),
            distribution,
            ..Default::default()
        };
        for (start, end) in uniform_ranges(shard_count as u32) {
            new_shard(&mut stream, start, end, now);
        }
        st.streams.insert(arn, stream);
        Ok(())
    }

    pub fn delete_stream(&self, ctx: &RequestContext, input: types::DeleteStreamInput) -> Result<(), ServiceError> {
        let r = StreamRef::resolve(ctx, input.stream_name.as_deref(), input.stream_arn.as_deref())?;
        let mut st = self.settled(ctx);
        authorize_stream(ctx, &st, "DeleteStream", &r, ConditionContext::new())?;
        let consumers = st.consumers.values().filter(|c| c.stream_arn == r.arn).count();
        let channels = st
            .channels
            .values()
            .filter(|c| c.description.stream_configuration_list.iter().any(|s| s.stream_arn == r.arn))
            .count();
        let s = r.get_mut(&mut st)?;
        if s.status == "DELETING" {
            return Err(errors::resource_not_found(format!(
                "Stream {} under account {} not found.",
                s.name, s.account
            )));
        }
        if consumers > 0 && !input.enforce_consumer_deletion.unwrap_or(false) {
            return Err(errors::resource_in_use(format!(
                "Stream {} under account {} has {consumers} registered consumers. Deregister all consumers or set EnforceConsumerDeletion to true.",
                s.name, s.account
            )));
        }
        if channels > 0 {
            return Err(errors::resource_in_use(format!(
                "Stream {} under account {} has active channels. Delete the channels before deleting the stream.",
                s.name, s.account
            )));
        }
        transition(s, "DELETING", now_ms(ctx));
        Ok(())
    }

    pub fn describe_stream(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStreamInput,
    ) -> Result<types::DescribeStreamOutput, ServiceError> {
        let r = StreamRef::resolve(ctx, input.stream_name.as_deref(), input.stream_arn.as_deref())?;
        let st = self.settled(ctx);
        authorize_stream(ctx, &st, "DescribeStream", &r, ConditionContext::new())?;
        let s = r.get(&st)?;
        let limit = input.limit.unwrap_or(100).clamp(1, 10_000) as usize;
        let after = input.exclusive_start_shard_id.as_ref().map(|id| {
            s.shards
                .iter()
                .find(|sh| &sh.id() == id)
                .map(|sh| sh.index)
                .or_else(|| id.strip_prefix("shardId-").and_then(|n| n.parse().ok()))
                .unwrap_or(u32::MAX)
        });
        let all: Vec<_> = s.shards.iter().filter(|sh| after.is_none_or(|a| sh.index > a)).collect();
        let shards: Vec<types::Shard> = all.iter().take(limit).map(|sh| shard_wire(s, sh)).collect();
        Ok(types::DescribeStreamOutput {
            stream_description: types::StreamDescription {
                stream_name: s.name.clone(),
                stream_arn: s.arn.clone(),
                stream_status: s.status.clone(),
                stream_mode_details: Some(mode_details(s)),
                has_more_shards: all.len() > shards.len(),
                shards,
                retention_period_hours: s.retention_hours,
                stream_creation_timestamp: time(s.created_at),
                enhanced_monitoring: monitoring(s),
                encryption_type: Some(s.encryption_type.clone()),
                key_id: s.key_id.clone(),
            },
        })
    }

    pub fn describe_stream_summary(
        &self,
        ctx: &RequestContext,
        input: types::DescribeStreamSummaryInput,
    ) -> Result<types::DescribeStreamSummaryOutput, ServiceError> {
        let r = StreamRef::resolve(ctx, input.stream_name.as_deref(), input.stream_arn.as_deref())?;
        let st = self.settled(ctx);
        authorize_stream(ctx, &st, "DescribeStreamSummary", &r, ConditionContext::new())?;
        let s = r.get(&st)?;
        let consumers = st.consumers.values().filter(|c| c.stream_arn == s.arn).count() as i32;
        let channels = st
            .channels
            .values()
            .filter(|c| c.description.stream_configuration_list.iter().any(|x| x.stream_arn == s.arn))
            .count() as i32;
        Ok(types::DescribeStreamSummaryOutput {
            stream_description_summary: types::StreamDescriptionSummary {
                stream_name: s.name.clone(),
                stream_arn: s.arn.clone(),
                stream_id: Some(s.id.clone()),
                stream_status: s.status.clone(),
                stream_mode_details: Some(mode_details(s)),
                retention_period_hours: s.retention_hours,
                stream_creation_timestamp: time(s.created_at),
                enhanced_monitoring: monitoring(s),
                encryption_type: Some(s.encryption_type.clone()),
                key_id: s.key_id.clone(),
                open_shard_count: s.open_shards().count() as i32,
                consumer_count: Some(consumers),
                warm_throughput: warm(s),
                max_record_size_in_ki_b: Some(s.max_record_size_kib),
                channel_count: Some(channels),
                record_distribution_strategy: (s.mode == "ON_DEMAND").then(|| s.distribution.clone()),
            },
        })
    }

    pub fn list_streams(
        &self,
        ctx: &RequestContext,
        input: types::ListStreamsInput,
    ) -> Result<types::ListStreamsOutput, ServiceError> {
        let account = ctx.caller.account_id.clone();
        authorize_account(ctx, "kinesis:ListStreams")?;
        if input.next_token.is_some() && input.exclusive_start_stream_name.is_some() {
            return Err(invalid_argument("NextToken and ExclusiveStartStreamName cannot be provided together."));
        }
        let now = now_ms(ctx);
        let after = match &input.next_token {
            Some(t) => {
                let parts = decode_token(t)
                    .filter(|p| p.len() == 2)
                    .ok_or_else(|| invalid_argument(format!("Invalid NextToken: {t}")))?;
                let issued: i64 = parts[1].parse().unwrap_or(0);
                if issued + TOKEN_TTL_MS < now {
                    return Err(errors::expired_next_token(format!("Expired NextToken: {t}")));
                }
                Some(parts[0].clone())
            }
            None => input.exclusive_start_stream_name.clone(),
        };
        let limit = input.limit.unwrap_or(100).clamp(1, 10_000) as usize;
        let st = self.settled(ctx);
        let streams: Vec<&Stream> = st
            .streams
            .values()
            .filter(|s| s.account == account && s.region == ctx.region)
            .filter(|s| after.as_ref().is_none_or(|a| &s.name > a))
            .collect();
        let mut streams = streams;
        streams.sort_by(|a, b| a.name.cmp(&b.name));
        let more = streams.len() > limit;
        streams.truncate(limit);
        let next_token = more.then(|| {
            let last = streams.last().map(|s| s.name.clone()).unwrap_or_default();
            encode_token(&[&last, &now.to_string()])
        });
        Ok(types::ListStreamsOutput {
            stream_names: streams.iter().map(|s| s.name.clone()).collect(),
            has_more_streams: more,
            next_token,
            stream_summaries: Some(
                streams
                    .iter()
                    .map(|s| types::StreamSummary {
                        stream_name: s.name.clone(),
                        stream_arn: s.arn.clone(),
                        stream_status: s.status.clone(),
                        stream_mode_details: Some(mode_details(s)),
                        stream_creation_timestamp: Some(time(s.created_at)),
                    })
                    .collect(),
            ),
        })
    }

    pub fn list_shards(
        &self,
        ctx: &RequestContext,
        input: types::ListShardsInput,
    ) -> Result<types::ListShardsOutput, ServiceError> {
        let now = now_ms(ctx);
        let (r, after_index) = match &input.next_token {
            Some(t) => {
                if input.stream_name.is_some() || input.stream_arn.is_some() {
                    return Err(invalid_argument("NextToken and StreamName or StreamARN cannot be provided together."));
                }
                if input.exclusive_start_shard_id.is_some() || input.shard_filter.is_some() {
                    return Err(invalid_argument(
                        "NextToken cannot be provided together with ExclusiveStartShardId or ShardFilter.",
                    ));
                }
                let parts = decode_token(t)
                    .filter(|p| p.len() == 4)
                    .ok_or_else(|| invalid_argument(format!("Invalid NextToken: {t}")))?;
                let issued: i64 = parts[3].parse().unwrap_or(0);
                if issued + TOKEN_TTL_MS < now {
                    return Err(errors::expired_next_token(format!(
                        "The timestamp of the last ListShard call was {} which is older than the tolerated limit",
                        time(issued).to_rfc3339()
                    )));
                }
                (StreamRef::from_arn(&parts[0])?, parts[2].parse::<i64>().ok())
            }
            None => (StreamRef::resolve(ctx, input.stream_name.as_deref(), input.stream_arn.as_deref())?, None),
        };
        let st = self.settled(ctx);
        authorize_stream(ctx, &st, "ListShards", &r, ConditionContext::new())?;
        let s = r.get(&st)?;
        let exclusive = input
            .exclusive_start_shard_id
            .as_deref()
            .and_then(|id| id.strip_prefix("shardId-"))
            .and_then(|n| n.parse::<i64>().ok());
        let filter = input.shard_filter.clone();
        let ts = |f: &types::ShardFilter| f.timestamp.map(|t| t.timestamp_millis());
        let mut shards: Vec<&crate::state::Shard> = Vec::new();
        for sh in &s.shards {
            let idx = i64::from(sh.index);
            if after_index.is_some_and(|a| idx <= a) || exclusive.is_some_and(|e| idx <= e) {
                continue;
            }
            let keep = match &filter {
                None => true,
                Some(f) => match f.r#type.as_str() {
                    "AFTER_SHARD_ID" => {
                        let Some(id) = f.shard_id.as_deref() else {
                            return Err(invalid_argument(
                                "ShardId must be provided when the ShardFilter type is AFTER_SHARD_ID.",
                            ));
                        };
                        let a = id.strip_prefix("shardId-").and_then(|n| n.parse::<i64>().ok()).unwrap_or(-1);
                        idx > a
                    }
                    // The shards open at the trim horizon, which closed
                    // shards past retention have already left.
                    "AT_TRIM_HORIZON" => {
                        let t = (now - i64::from(s.retention_hours) * 3_600_000).max(s.created_at);
                        sh.created_at <= t && sh.closed_at.is_none_or(|c| c > t)
                    }
                    "FROM_TRIM_HORIZON" => true,
                    "AT_LATEST" => sh.open(),
                    "AT_TIMESTAMP" | "FROM_TIMESTAMP" => {
                        let Some(t) = ts(f) else {
                            return Err(invalid_argument(format!(
                                "Timestamp must be provided when the ShardFilter type is {}.",
                                f.r#type
                            )));
                        };
                        let t = t.max(s.created_at);
                        let open_then = sh.created_at <= t && sh.closed_at.is_none_or(|c| c > t);
                        if f.r#type == "AT_TIMESTAMP" {
                            open_then
                        } else {
                            sh.closed_at.is_none_or(|c| c > t)
                        }
                    }
                    other => return Err(invalid_argument(format!("Invalid ShardFilter type {other}."))),
                },
            };
            if keep {
                shards.push(sh);
            }
        }
        let limit = input.max_results.unwrap_or(1000).clamp(1, 10_000) as usize;
        let more = shards.len() > limit;
        shards.truncate(limit);
        let next_token = more.then(|| {
            let last = shards.last().map(|sh| sh.index).unwrap_or_default();
            encode_token(&[&s.arn, &s.created_at.to_string(), &last.to_string(), &now.to_string()])
        });
        Ok(types::ListShardsOutput { shards: Some(shards.iter().map(|sh| shard_wire(s, sh)).collect()), next_token })
    }

    pub fn increase_stream_retention_period(
        &self,
        ctx: &RequestContext,
        input: types::IncreaseStreamRetentionPeriodInput,
    ) -> Result<(), ServiceError> {
        let r = StreamRef::resolve(ctx, input.stream_name.as_deref(), input.stream_arn.as_deref())?;
        let mut st = self.settled(ctx);
        authorize_stream(ctx, &st, "IncreaseStreamRetentionPeriod", &r, ConditionContext::new())?;
        let hours = input.retention_period_hours;
        check_retention(hours)?;
        let s = updatable(&mut st, &r)?;
        if hours < s.retention_hours {
            return Err(invalid_argument(format!(
                "Requested retention period ({hours} hours) for stream {} can not be shorter than existing retention period ({} hours). Use DecreaseRetentionPeriod API.",
                s.name, s.retention_hours
            )));
        }
        s.retention_hours = hours;
        Ok(())
    }

    pub fn decrease_stream_retention_period(
        &self,
        ctx: &RequestContext,
        input: types::DecreaseStreamRetentionPeriodInput,
    ) -> Result<(), ServiceError> {
        let r = StreamRef::resolve(ctx, input.stream_name.as_deref(), input.stream_arn.as_deref())?;
        let mut st = self.settled(ctx);
        authorize_stream(ctx, &st, "DecreaseStreamRetentionPeriod", &r, ConditionContext::new())?;
        let hours = input.retention_period_hours;
        check_retention(hours)?;
        let s = updatable(&mut st, &r)?;
        if hours > s.retention_hours {
            return Err(invalid_argument(format!(
                "Requested retention period ({hours} hours) for stream {} can not be longer than existing retention period ({} hours). Use IncreaseRetentionPeriod API.",
                s.name, s.retention_hours
            )));
        }
        s.retention_hours = hours;
        Ok(())
    }

    pub fn update_shard_count(
        &self,
        ctx: &RequestContext,
        input: types::UpdateShardCountInput,
    ) -> Result<types::UpdateShardCountOutput, ServiceError> {
        let r = StreamRef::resolve(ctx, input.stream_name.as_deref(), input.stream_arn.as_deref())?;
        let mut st = self.settled(ctx);
        authorize_stream(ctx, &st, "UpdateShardCount", &r, ConditionContext::new())?;
        if input.scaling_type != "UNIFORM_SCALING" {
            return Err(errors::validation(format!(
                "1 validation error detected: Value '{}' at 'scalingType' failed to satisfy constraint: Member must satisfy enum value set: [UNIFORM_SCALING]",
                input.scaling_type
            )));
        }
        let target = input.target_shard_count;
        let account_open = open_shard_count(&st, &r.account, &ctx.region);
        let limit = shard_limit(&ctx.region);
        let now = now_ms(ctx);
        let s = updatable(&mut st, &r)?;
        if s.mode == "ON_DEMAND" {
            return Err(errors::validation(format!(
                "UpdateShardCount is not supported for stream {} under account {} because it is in ON_DEMAND mode.",
                s.name, s.account
            )));
        }
        let current = s.open_shards().count() as i32;
        s.shard_count_updates.retain(|t| t + DAY_MS > now);
        if s.shard_count_updates.len() >= MAX_SHARD_COUNT_UPDATES {
            return Err(errors::limit_exceeded(format!(
                "UpdateShardCount cannot be called more than {MAX_SHARD_COUNT_UPDATES} times in a rolling 24-hour period for stream {} under account {}.",
                s.name, s.account
            )));
        }
        if target > MAX_STREAM_SHARDS {
            return Err(errors::limit_exceeded(format!(
                "UpdateShardCount cannot scale up to more than {MAX_STREAM_SHARDS} shards in a stream. Target shard count: {target}"
            )));
        }
        if target > current * 2 {
            return Err(errors::limit_exceeded(format!(
                "UpdateShardCount cannot scale up over double your current open shard count. Current open shard count: {current} Target shard count: {target}"
            )));
        }
        if target * 2 < current {
            return Err(errors::limit_exceeded(format!(
                "UpdateShardCount cannot scale down below half your current open shard count. Current open shard count: {current} Target shard count: {target}"
            )));
        }
        if account_open - current + target > limit {
            return Err(errors::limit_exceeded(format!(
                "This request would exceed the shard limit for the account {} in {}. Current shard count for the account: {account_open}. Limit: {limit}.",
                s.account, ctx.region
            )));
        }
        if target != current {
            rescale(s, target, now);
        }
        s.shard_count_updates.push(now);
        transition(s, "UPDATING", now);
        Ok(types::UpdateShardCountOutput {
            stream_name: Some(s.name.clone()),
            current_shard_count: Some(current),
            target_shard_count: Some(target),
            stream_arn: Some(s.arn.clone()),
        })
    }

    pub fn update_stream_mode(
        &self,
        ctx: &RequestContext,
        input: types::UpdateStreamModeInput,
    ) -> Result<(), ServiceError> {
        let r = StreamRef::from_arn(&input.stream_arn)?;
        let mut st = self.settled(ctx);
        authorize_stream(ctx, &st, "UpdateStreamMode", &r, ConditionContext::new())?;
        let mode = input.stream_mode_details.stream_mode;
        let now = now_ms(ctx);
        let s = updatable(&mut st, &r)?;
        if s.mode == mode {
            return Err(invalid_argument(format!("Stream {} is already in {mode} mode.", s.name)));
        }
        // Capacity mode can change twice per rolling 24 hours.
        s.mode_changes.retain(|t| t + DAY_MS > now);
        if s.mode_changes.len() >= 2 {
            return Err(errors::limit_exceeded(format!(
                "Stream {} under account {} has had its capacity mode changed too many times in the last 24 hours.",
                s.name, s.account
            )));
        }
        if input.warm_throughput_mi_bps.is_some() && mode != "ON_DEMAND" {
            return Err(invalid_argument("Warm throughput is only supported for streams in ON_DEMAND mode."));
        }
        s.mode = mode.clone();
        s.mode_changes.push(now);
        if mode == "ON_DEMAND" {
            s.warm_throughput_mibps = input.warm_throughput_mi_bps;
        } else {
            s.warm_throughput_mibps = None;
            s.distribution = "USER_PARTITION_KEY".into();
        }
        transition(s, "UPDATING", now);
        Ok(())
    }

    pub fn split_shard(&self, ctx: &RequestContext, input: types::SplitShardInput) -> Result<(), ServiceError> {
        let r = StreamRef::resolve(ctx, input.stream_name.as_deref(), input.stream_arn.as_deref())?;
        let mut st = self.settled(ctx);
        authorize_stream(ctx, &st, "SplitShard", &r, ConditionContext::new())?;
        let account_open = open_shard_count(&st, &r.account, &ctx.region);
        let limit = shard_limit(&ctx.region);
        let now = now_ms(ctx);
        let s = updatable(&mut st, &r)?;
        if s.mode == "ON_DEMAND" {
            return Err(errors::validation(format!(
                "SplitShard is not supported for stream {} under account {} because it is in ON_DEMAND mode.",
                s.name, s.account
            )));
        }
        let Ok(at) = input.new_starting_hash_key.parse::<u128>() else {
            return Err(invalid_argument(format!(
                "NewStartingHashKey {} used in SplitShard() on shard {} in stream {} under account {} is not a valid hash key.",
                input.new_starting_hash_key, input.shard_to_split, s.name, s.account
            )));
        };
        let (index, start, end) = match s.shard(&input.shard_to_split) {
            Some(sh) if sh.open() => (sh.index, sh.start_hash, sh.end_hash),
            Some(_) => {
                return Err(errors::resource_in_use(format!(
                    "Shard {} in stream {} under account {} has already been merged or split, and thus is not eligible for merging or splitting.",
                    input.shard_to_split, s.name, s.account
                )))
            }
            None => {
                return Err(errors::resource_not_found(format!(
                    "Could not find shard {} in stream {} under account {}.",
                    input.shard_to_split, s.name, s.account
                )))
            }
        };
        if at <= start || at > end {
            return Err(invalid_argument(format!(
                "NewStartingHashKey {at} used in SplitShard() on shard {} in stream {} under account {} is not both greater than one plus the shard's StartingHashKey {start} and less than the shard's EndingHashKey {end}.",
                input.shard_to_split, s.name, s.account
            )));
        }
        if account_open + 1 > limit {
            return Err(errors::limit_exceeded(format!(
                "This request would exceed the shard limit for the account {} in {}. Current shard count for the account: {account_open}. Limit: {limit}.",
                s.account, ctx.region
            )));
        }
        if let Some(parent) = s.shard_mut(&input.shard_to_split) {
            parent.closed_at = Some(now);
        }
        for (a, b) in [(start, at - 1), (at, end)] {
            let child = new_shard(s, a, b, now);
            if let Some(c) = s.shards.iter_mut().find(|x| x.index == child) {
                c.parent = Some(index);
            }
        }
        transition(s, "UPDATING", now);
        Ok(())
    }

    pub fn merge_shards(&self, ctx: &RequestContext, input: types::MergeShardsInput) -> Result<(), ServiceError> {
        let r = StreamRef::resolve(ctx, input.stream_name.as_deref(), input.stream_arn.as_deref())?;
        let mut st = self.settled(ctx);
        authorize_stream(ctx, &st, "MergeShards", &r, ConditionContext::new())?;
        let now = now_ms(ctx);
        let s = updatable(&mut st, &r)?;
        if s.mode == "ON_DEMAND" {
            return Err(errors::validation(format!(
                "MergeShards is not supported for stream {} under account {} because it is in ON_DEMAND mode.",
                s.name, s.account
            )));
        }
        let find = |id: &str| -> Result<(u32, u128, u128), ServiceError> {
            match s.shard(id) {
                Some(sh) if sh.open() => Ok((sh.index, sh.start_hash, sh.end_hash)),
                Some(_) => Err(errors::resource_in_use(format!(
                    "Shard {id} in stream {} under account {} has already been merged or split, and thus is not eligible for merging or splitting.",
                    s.name, s.account
                ))),
                None => Err(errors::resource_not_found(format!(
                    "Could not find shard {id} in stream {} under account {}.",
                    s.name, s.account
                ))),
            }
        };
        let a = find(&input.shard_to_merge)?;
        let b = find(&input.adjacent_shard_to_merge)?;
        let adjacent = a.2.checked_add(1) == Some(b.1) || b.2.checked_add(1) == Some(a.1);
        if !adjacent {
            return Err(invalid_argument(format!(
                "Shards {} and {} in stream {} under account {} are not an adjacent pair of shards eligible for merging",
                input.shard_to_merge, input.adjacent_shard_to_merge, s.name, s.account
            )));
        }
        for id in [&input.shard_to_merge, &input.adjacent_shard_to_merge] {
            if let Some(sh) = s.shard_mut(id) {
                sh.closed_at = Some(now);
            }
        }
        let child = new_shard(s, a.1.min(b.1), a.2.max(b.2), now);
        if let Some(c) = s.shards.iter_mut().find(|x| x.index == child) {
            c.parent = Some(a.0);
            c.adjacent_parent = Some(b.0);
        }
        transition(s, "UPDATING", now);
        Ok(())
    }

    pub fn enable_enhanced_monitoring(
        &self,
        ctx: &RequestContext,
        input: types::EnableEnhancedMonitoringInput,
    ) -> Result<types::EnhancedMonitoringOutput, ServiceError> {
        self.change_monitoring(
            ctx,
            "EnableEnhancedMonitoring",
            input.stream_name.as_deref(),
            input.stream_arn.as_deref(),
            &input.shard_level_metrics,
            true,
        )
    }

    pub fn disable_enhanced_monitoring(
        &self,
        ctx: &RequestContext,
        input: types::DisableEnhancedMonitoringInput,
    ) -> Result<types::EnhancedMonitoringOutput, ServiceError> {
        self.change_monitoring(
            ctx,
            "DisableEnhancedMonitoring",
            input.stream_name.as_deref(),
            input.stream_arn.as_deref(),
            &input.shard_level_metrics,
            false,
        )
    }

    fn change_monitoring(
        &self,
        ctx: &RequestContext,
        action: &str,
        name: Option<&str>,
        arn: Option<&str>,
        metrics: &[String],
        enable: bool,
    ) -> Result<types::EnhancedMonitoringOutput, ServiceError> {
        const ALL: [&str; 7] = [
            "IncomingBytes",
            "IncomingRecords",
            "OutgoingBytes",
            "OutgoingRecords",
            "WriteProvisionedThroughputExceeded",
            "ReadProvisionedThroughputExceeded",
            "IteratorAgeMilliseconds",
        ];
        let r = StreamRef::resolve(ctx, name, arn)?;
        let mut st = self.settled(ctx);
        authorize_stream(ctx, &st, action, &r, ConditionContext::new())?;
        let s = updatable(&mut st, &r)?;
        let current = s.shard_level_metrics.clone();
        let named: Vec<String> = if metrics.iter().any(|m| m == "ALL") {
            ALL.iter().map(|m| m.to_string()).collect()
        } else {
            metrics.to_vec()
        };
        let mut desired: Vec<String> = if enable {
            let mut d = current.clone();
            for m in named {
                if !d.contains(&m) {
                    d.push(m);
                }
            }
            d
        } else {
            current.iter().filter(|m| !named.contains(m)).cloned().collect()
        };
        desired.sort_by_key(|m| ALL.iter().position(|a| a == m));
        s.shard_level_metrics = desired.clone();
        Ok(types::EnhancedMonitoringOutput {
            stream_name: Some(s.name.clone()),
            current_shard_level_metrics: Some(current),
            desired_shard_level_metrics: Some(desired),
            stream_arn: Some(s.arn.clone()),
        })
    }

    pub fn start_stream_encryption(
        &self,
        ctx: &RequestContext,
        input: types::StartStreamEncryptionInput,
    ) -> Result<(), ServiceError> {
        let r = StreamRef::resolve(ctx, input.stream_name.as_deref(), input.stream_arn.as_deref())?;
        {
            let st = self.settled(ctx);
            authorize_stream(ctx, &st, "StartStreamEncryption", &r, ConditionContext::new())?;
            let s = r.get(&st)?;
            if s.status != "ACTIVE" {
                return Err(not_active(s));
            }
        }
        if input.encryption_type != "KMS" {
            return Err(invalid_argument(format!(
                "Encryption type {} is not supported. Supported encryption types: KMS.",
                input.encryption_type
            )));
        }
        let (key_arn, data_key) = self.new_data_key(ctx, &r.arn, &input.key_id)?;
        let mut st = self.settled(ctx);
        let s = updatable(&mut st, &r)?;
        s.encryption_type = "KMS".into();
        s.key_id = Some(input.key_id);
        s.data_key = data_key;
        let _ = key_arn;
        transition(s, "UPDATING", now_ms(ctx));
        Ok(())
    }

    pub fn stop_stream_encryption(
        &self,
        ctx: &RequestContext,
        input: types::StopStreamEncryptionInput,
    ) -> Result<(), ServiceError> {
        let r = StreamRef::resolve(ctx, input.stream_name.as_deref(), input.stream_arn.as_deref())?;
        let mut st = self.settled(ctx);
        authorize_stream(ctx, &st, "StopStreamEncryption", &r, ConditionContext::new())?;
        if input.encryption_type != "KMS" {
            return Err(invalid_argument(format!(
                "Encryption type {} is not supported. Supported encryption types: KMS.",
                input.encryption_type
            )));
        }
        let now = now_ms(ctx);
        let s = updatable(&mut st, &r)?;
        if !s.encrypted() {
            return Err(invalid_argument(format!("Stream {} under account {} is not encrypted.", s.name, s.account)));
        }
        if s.key_id.as_deref() != Some(input.key_id.as_str()) {
            return Err(invalid_argument(format!(
                "Stream {} under account {} is not encrypted with key {}.",
                s.name, s.account, input.key_id
            )));
        }
        s.encryption_type = "NONE".into();
        s.key_id = None;
        s.data_key.clear();
        transition(s, "UPDATING", now);
        Ok(())
    }

    /// A data key for the stream under `key_id`, generated with the
    /// caller's KMS permissions: `(key ARN, ciphertext)`.
    pub(crate) fn new_data_key(
        &self,
        ctx: &RequestContext,
        stream_arn: &str,
        key_id: &str,
    ) -> Result<(String, Vec<u8>), ServiceError> {
        let Some(kms) = &self.kms else { return Ok((key_id.to_string(), Vec::new())) };
        let key = if key_id == "alias/aws/kinesis" || key_id.ends_with(":alias/aws/kinesis") {
            kms.aws_managed_key(ctx, "kinesis")
        } else {
            key_id.to_string()
        };
        let context: BTreeMap<String, String> = [("aws:kinesis:arn".to_string(), stream_arn.to_string())].into();
        let dk = kms.generate_data_key_via(ctx, "kinesis", &key, &context, 32).map_err(kms_error)?;
        Ok((dk.key_arn, dk.ciphertext))
    }

    /// Check the caller may decrypt the stream's data.
    pub(crate) fn check_decrypt(
        &self,
        ctx: &RequestContext,
        stream_arn: &str,
        data_key: &[u8],
    ) -> Result<(), ServiceError> {
        let Some(kms) = &self.kms else { return Ok(()) };
        if data_key.is_empty() {
            return Ok(());
        }
        let context: BTreeMap<String, String> = [("aws:kinesis:arn".to_string(), stream_arn.to_string())].into();
        kms.decrypt_via(ctx, "kinesis", data_key, &context).map_err(kms_error)?;
        Ok(())
    }

    pub fn update_stream_warm_throughput(
        &self,
        ctx: &RequestContext,
        input: types::UpdateStreamWarmThroughputInput,
    ) -> Result<types::UpdateStreamWarmThroughputOutput, ServiceError> {
        let r = StreamRef::resolve(ctx, input.stream_name.as_deref(), input.stream_arn.as_deref())?;
        let mut st = self.settled(ctx);
        authorize_stream(ctx, &st, "UpdateStreamWarmThroughput", &r, ConditionContext::new())?;
        let now = now_ms(ctx);
        let s = updatable(&mut st, &r)?;
        if s.mode != "ON_DEMAND" {
            return Err(invalid_argument(format!(
                "Warm throughput is only supported for streams in ON_DEMAND mode. Stream {} under account {} is in {} mode.",
                s.name, s.account, s.mode
            )));
        }
        s.warm_throughput_mibps = Some(input.warm_throughput_mi_bps);
        transition(s, "UPDATING", now);
        Ok(types::UpdateStreamWarmThroughputOutput {
            stream_arn: Some(s.arn.clone()),
            stream_name: Some(s.name.clone()),
            warm_throughput: warm(s),
        })
    }

    pub fn update_max_record_size(
        &self,
        ctx: &RequestContext,
        input: types::UpdateMaxRecordSizeInput,
    ) -> Result<(), ServiceError> {
        let Some(arn) = input.stream_arn.as_deref() else {
            return Err(invalid_argument("StreamARN must be provided."));
        };
        let r = StreamRef::from_arn(arn)?;
        let mut st = self.settled(ctx);
        authorize_stream(ctx, &st, "UpdateMaxRecordSize", &r, ConditionContext::new())?;
        let now = now_ms(ctx);
        let s = updatable(&mut st, &r)?;
        s.max_record_size_kib = input.max_record_size_in_ki_b;
        transition(s, "UPDATING", now);
        Ok(())
    }

    pub fn update_stream_record_distribution_strategy(
        &self,
        ctx: &RequestContext,
        input: types::UpdateStreamRecordDistributionStrategyInput,
    ) -> Result<(), ServiceError> {
        let r = StreamRef::from_arn(&input.stream_arn)?;
        let mut st = self.settled(ctx);
        authorize_stream(ctx, &st, "UpdateStreamRecordDistributionStrategy", &r, ConditionContext::new())?;
        let s = updatable(&mut st, &r)?;
        if s.mode != "ON_DEMAND" {
            return Err(invalid_argument(format!(
                "The record distribution strategy can only be set on streams in ON_DEMAND mode. Stream {} under account {} is in {} mode.",
                s.name, s.account, s.mode
            )));
        }
        s.distribution = input.record_distribution_strategy;
        Ok(())
    }

    pub fn describe_limits(
        &self,
        ctx: &RequestContext,
        _input: types::DescribeLimitsInput,
    ) -> Result<types::DescribeLimitsOutput, ServiceError> {
        let account = ctx.caller.account_id.clone();
        authorize_account(ctx, "kinesis:DescribeLimits")?;
        let st = self.settled(ctx);
        let on_demand = st
            .streams
            .values()
            .filter(|s| s.account == account && s.region == ctx.region && s.mode == "ON_DEMAND")
            .count() as i32;
        let channels = st.channels.values().filter(|c| c.account == account && c.region == ctx.region).count() as i32;
        Ok(types::DescribeLimitsOutput {
            shard_limit: shard_limit(&ctx.region),
            open_shard_count: open_shard_count(&st, &account, &ctx.region),
            on_demand_stream_count: on_demand,
            on_demand_stream_count_limit: ON_DEMAND_STREAM_LIMIT,
            channel_count: Some(channels),
            channel_count_limit: Some(crate::channels::CHANNEL_LIMIT),
        })
    }
}

fn check_retention(hours: i32) -> Result<(), ServiceError> {
    if hours < MIN_RETENTION {
        return Err(invalid_argument(format!(
            "Minimum allowed retention period is {MIN_RETENTION} hours. Requested retention period ({hours} hours) is too short."
        )));
    }
    if hours > MAX_RETENTION {
        return Err(invalid_argument(format!(
            "Maximum allowed retention period is {MAX_RETENTION} hours. Requested retention period ({hours} hours) is too long."
        )));
    }
    Ok(())
}

/// KMS failures as Kinesis reports them.
pub(crate) fn kms_error(e: ServiceError) -> ServiceError {
    let code = e.code.as_ref();
    let message = e.message.clone();
    match code {
        "NotFoundException" => errors::kms_not_found(message),
        "DisabledException" => errors::kms_disabled(message),
        "KMSInvalidStateException" => errors::kms_invalid_state(message),
        "InvalidKeyUsageException" | "KMSInvalidStateException " => errors::kms_invalid_state(message),
        c if c.starts_with("AccessDenied") => errors::kms_access_denied(message),
        "ThrottlingException" => errors::kms_throttling(message),
        _ => errors::kms_not_found(message),
    }
}

//! Channels (stream-to-S3 delivery configurations) and account settings.
//!
//! Channels are stored, validated and move through their statuses; MWS
//! does not run their delivery.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::names::{authorize, invalid_argument, now_ms, request_tag_context, validate_tags, StreamRef};
use crate::state::{Channel, State, TRANSITION_MS};
use crate::Kinesis;

pub const CHANNEL_LIMIT: i32 = 50;
const DEFAULT_FRESHNESS: i32 = 300;
/// The minimum throughput billing commitment lasts at least this long.
const COMMITMENT_MS: i64 = 24 * 3_600_000;

fn time(ms: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp_millis(ms).unwrap_or_default()
}

fn channel_not_found(arn: &str) -> ServiceError {
    errors::resource_not_found(format!("Channel {arn} not found."))
}

fn description(c: &Channel) -> types::ChannelDescription {
    let mut d = c.description.clone();
    d.channel_status = c.status.clone();
    d
}

fn authorize_channel(
    ctx: &RequestContext,
    action: &str,
    arn: &str,
    tags: &BTreeMap<String, String>,
) -> Result<(), ServiceError> {
    authorize(ctx, &format!("kinesis:{action}"), arn, None, tags, ConditionContext::new())
}

fn get<'a>(st: &'a State, arn: &str) -> Result<&'a Channel, ServiceError> {
    st.channels.get(arn).filter(|c| c.status != "DELETING").ok_or_else(|| channel_not_found(arn))
}

impl Kinesis {
    pub fn create_channel(
        &self,
        ctx: &RequestContext,
        input: types::CreateChannelInput,
    ) -> Result<types::CreateChannelOutput, ServiceError> {
        let account = ctx.caller.account_id.clone();
        let arn = format!("arn:{}:kinesis:{}:{account}:channel/{}", ctx.partition, ctx.region, input.channel_name);
        let tags = input.tags.clone().unwrap_or_default();
        authorize(ctx, "kinesis:CreateChannel", &arn, None, &BTreeMap::new(), request_tag_context(&tags))?;
        validate_tags(&tags)?;
        match (&input.s3_destination_configuration, &input.s3_tables_destination_configuration) {
            (Some(_), Some(_)) | (None, None) => {
                return Err(invalid_argument(
                    "Exactly one of S3DestinationConfiguration and S3TablesDestinationConfiguration must be specified.",
                ))
            }
            _ => {}
        }
        for sc in &input.stream_configuration_list {
            let fmt = sc.record_configuration.record_format_type.as_str();
            let s3 = input.s3_destination_configuration.is_some();
            if (s3 && fmt == "GSR_JSON") || (!s3 && matches!(fmt, "STRING" | "BYTE_ARRAY")) {
                return Err(invalid_argument(format!(
                    "Record format {fmt} is not supported for this destination type."
                )));
            }
        }
        let now = now_ms(ctx);
        let mut st = self.settled(ctx);
        let mut streams = Vec::new();
        for sc in &input.stream_configuration_list {
            let r = StreamRef::from_arn(&sc.stream_arn)?;
            let s = r.get(&st)?;
            streams.push(types::ChannelStreamDescription {
                stream_arn: s.arn.clone(),
                stream_creation_timestamp: time(s.created_at),
                record_configuration: sc.record_configuration.clone(),
            });
        }
        if st.channels.values().any(|c| c.arn == arn && c.status != "DELETING") {
            return Err(errors::resource_in_use(format!("Channel {} already exists.", input.channel_name)));
        }
        let count = st.channels.values().filter(|c| c.account == account && c.region == ctx.region).count() as i32;
        if count >= CHANNEL_LIMIT {
            return Err(errors::limit_exceeded(format!(
                "This request would exceed the channel limit of {CHANNEL_LIMIT} for the account {account}."
            )));
        }
        let desc = types::ChannelDescription {
            channel_name: input.channel_name.clone(),
            channel_arn: arn.clone(),
            channel_id: uuid::Uuid::new_v4().simple().to_string(),
            channel_status: "CREATING".into(),
            channel_status_reason: None,
            channel_creation_timestamp: time(now),
            service_execution_role_arn: input.service_execution_role_arn,
            stream_configuration_list: streams,
            s3_destination_configuration: input.s3_destination_configuration.map(|d| types::S3DestinationDescription {
                data_freshness_in_seconds: d.data_freshness_in_seconds.unwrap_or(DEFAULT_FRESHNESS),
                dead_letter_queue_s3_configuration: d.dead_letter_queue_s3_configuration.unwrap_or_default(),
                storage_configuration: d.storage_configuration,
            }),
            s3_tables_destination_configuration: input.s3_tables_destination_configuration.map(|d| {
                types::S3TablesDestinationDescription {
                    data_freshness_in_seconds: d.data_freshness_in_seconds.unwrap_or(DEFAULT_FRESHNESS),
                    dead_letter_queue_s3_configuration: d.dead_letter_queue_s3_configuration,
                    s3_tables_configuration_list: d.s3_tables_configuration_list,
                }
            }),
            encryption_configuration: input.encryption_configuration,
            logging_configuration: input.logging_configuration.unwrap_or_default(),
        };
        let c = Channel {
            arn: arn.clone(),
            account,
            region: ctx.region.clone(),
            created_at: now,
            settles_at: now + TRANSITION_MS,
            status: "CREATING".into(),
            description: desc,
            tags,
        };
        let out = description(&c);
        st.channels.insert(arn, c);
        Ok(types::CreateChannelOutput { channel_description: out })
    }

    pub fn describe_channel(
        &self,
        ctx: &RequestContext,
        input: types::DescribeChannelInput,
    ) -> Result<types::DescribeChannelOutput, ServiceError> {
        let st = self.settled(ctx);
        let tags = st.channels.get(&input.channel_arn).map(|c| c.tags.clone()).unwrap_or_default();
        authorize_channel(ctx, "DescribeChannel", &input.channel_arn, &tags)?;
        let c = get(&st, &input.channel_arn)?;
        Ok(types::DescribeChannelOutput { channel_description: description(c) })
    }

    pub fn update_channel(
        &self,
        ctx: &RequestContext,
        input: types::UpdateChannelInput,
    ) -> Result<types::UpdateChannelOutput, ServiceError> {
        let mut st = self.settled(ctx);
        let tags = st.channels.get(&input.channel_arn).map(|c| c.tags.clone()).unwrap_or_default();
        authorize_channel(ctx, "UpdateChannel", &input.channel_arn, &tags)?;
        get(&st, &input.channel_arn)?;
        let c = st.channels.get_mut(&input.channel_arn).expect("checked above");
        if c.status != "ACTIVE" {
            return Err(errors::resource_in_use(format!(
                "Channel {} is not ACTIVE, instead in state {}",
                c.arn, c.status
            )));
        }
        let d = &mut c.description;
        match (input.s3_destination_configuration, input.s3_tables_destination_configuration) {
            (Some(u), _) => match &mut d.s3_destination_configuration {
                Some(s3) => s3.data_freshness_in_seconds = u.data_freshness_in_seconds,
                None => return Err(invalid_argument("The channel does not deliver to a general purpose S3 bucket.")),
            },
            (None, Some(u)) => match &mut d.s3_tables_destination_configuration {
                Some(t) => t.data_freshness_in_seconds = u.data_freshness_in_seconds,
                None => return Err(invalid_argument("The channel does not deliver to S3 Tables.")),
            },
            (None, None) => {}
        }
        if let Some(l) = input.logging_configuration {
            d.logging_configuration = types::ChannelLoggingConfiguration {
                cloud_watch_logs: types::CloudWatchLogs {
                    enabled: l.cloud_watch_logs.enabled,
                    log_group_name: l.cloud_watch_logs.log_group_name,
                    log_stream_name: l.cloud_watch_logs.log_stream_name,
                },
            };
        }
        c.status = "UPDATING".into();
        c.settles_at = now_ms(ctx) + TRANSITION_MS;
        Ok(types::UpdateChannelOutput { channel_description: description(c) })
    }

    pub fn delete_channel(&self, ctx: &RequestContext, input: types::DeleteChannelInput) -> Result<(), ServiceError> {
        let mut st = self.settled(ctx);
        let tags = st.channels.get(&input.channel_arn).map(|c| c.tags.clone()).unwrap_or_default();
        authorize_channel(ctx, "DeleteChannel", &input.channel_arn, &tags)?;
        get(&st, &input.channel_arn)?;
        let c = st.channels.get_mut(&input.channel_arn).expect("checked above");
        c.status = "DELETING".into();
        c.settles_at = now_ms(ctx) + TRANSITION_MS;
        Ok(())
    }

    pub fn list_channels(
        &self,
        ctx: &RequestContext,
        input: types::ListChannelsInput,
    ) -> Result<types::ListChannelsOutput, ServiceError> {
        let account = ctx.caller.account_id.clone();
        let any = format!("arn:{}:kinesis:{}:{account}:channel/*", ctx.partition, ctx.region);
        authorize(ctx, "kinesis:ListChannels", &any, None, &BTreeMap::new(), ConditionContext::new())?;
        let st = self.settled(ctx);
        let filters = input.stream_filter.unwrap_or_default();
        let after = input.next_token.as_deref().unwrap_or_default();
        let mut channels: Vec<&Channel> = st
            .channels
            .values()
            .filter(|c| c.account == account && c.region == ctx.region && c.arn.as_str() > after)
            .filter(|c| {
                filters.is_empty()
                    || c.description.stream_configuration_list.iter().any(|s| {
                        filters.iter().any(|f| {
                            f.stream_arn == s.stream_arn
                                && f.stream_creation_timestamp.is_none_or(|t| t == s.stream_creation_timestamp)
                        })
                    })
            })
            .collect();
        channels.sort_by(|a, b| a.arn.cmp(&b.arn));
        let limit = input.max_results.unwrap_or(100).clamp(1, 10_000) as usize;
        let more = channels.len() > limit;
        channels.truncate(limit);
        Ok(types::ListChannelsOutput {
            next_token: more.then(|| channels.last().map(|c| c.arn.clone()).unwrap_or_default()),
            channel_summaries: channels
                .into_iter()
                .map(|c| types::ChannelSummary {
                    channel_name: c.description.channel_name.clone(),
                    channel_arn: c.arn.clone(),
                    channel_id: c.description.channel_id.clone(),
                    channel_status: c.status.clone(),
                    channel_status_reason: None,
                    channel_creation_timestamp: time(c.created_at),
                    channel_destination_type: if c.description.s3_destination_configuration.is_some() {
                        "S3".into()
                    } else {
                        "S3_TABLES".into()
                    },
                    streams: c
                        .description
                        .stream_configuration_list
                        .iter()
                        .map(|s| types::ChannelStreamIdentifier {
                            stream_arn: s.stream_arn.clone(),
                            stream_creation_timestamp: s.stream_creation_timestamp,
                        })
                        .collect(),
                })
                .collect(),
        })
    }

    fn commitment(st: &mut State, account: &str, now: i64) -> types::MinimumThroughputBillingCommitmentOutput {
        let a = st.accounts.entry(account.to_string()).or_default();
        if a.commitment_status.as_deref() == Some("ENABLED_UNTIL_EARLIEST_ALLOWED_END")
            && a.earliest_allowed_end_at.is_some_and(|t| t <= now)
        {
            a.commitment_status = Some("DISABLED".into());
        }
        types::MinimumThroughputBillingCommitmentOutput {
            status: a.commitment_status.clone().unwrap_or_else(|| "DISABLED".into()),
            started_at: a.started_at.map(time),
            ended_at: a.ended_at.map(time),
            earliest_allowed_end_at: a.earliest_allowed_end_at.map(time),
        }
    }

    pub fn describe_account_settings(
        &self,
        ctx: &RequestContext,
        _input: types::DescribeAccountSettingsInput,
    ) -> Result<types::DescribeAccountSettingsOutput, ServiceError> {
        let account = ctx.caller.account_id.clone();
        crate::names::authorize_account(ctx, "kinesis:DescribeAccountSettings")?;
        let mut st = self.settled(ctx);
        Ok(types::DescribeAccountSettingsOutput {
            minimum_throughput_billing_commitment: Some(Self::commitment(&mut st, &account, now_ms(ctx))),
        })
    }

    pub fn update_account_settings(
        &self,
        ctx: &RequestContext,
        input: types::UpdateAccountSettingsInput,
    ) -> Result<types::UpdateAccountSettingsOutput, ServiceError> {
        let account = ctx.caller.account_id.clone();
        crate::names::authorize_account(ctx, "kinesis:UpdateAccountSettings")?;
        let now = now_ms(ctx);
        let mut st = self.settled(ctx);
        Self::commitment(&mut st, &account, now);
        let a = st.accounts.entry(account.clone()).or_default();
        let current = a.commitment_status.clone().unwrap_or_else(|| "DISABLED".into());
        match input.minimum_throughput_billing_commitment.status.as_str() {
            "ENABLED" => {
                if current == "DISABLED" {
                    a.commitment_status = Some("ENABLED".into());
                    a.started_at = Some(now);
                    a.ended_at = None;
                    a.earliest_allowed_end_at = Some(now + COMMITMENT_MS);
                } else {
                    a.commitment_status = Some("ENABLED".into());
                    a.ended_at = None;
                }
            }
            _ => {
                if current == "DISABLED" {
                    return Err(invalid_argument("The minimum throughput billing commitment is already disabled."));
                }
                let end = a.earliest_allowed_end_at.unwrap_or(now);
                if end > now {
                    a.commitment_status = Some("ENABLED_UNTIL_EARLIEST_ALLOWED_END".into());
                    a.ended_at = Some(end);
                } else {
                    a.commitment_status = Some("DISABLED".into());
                    a.ended_at = Some(now);
                }
            }
        }
        Ok(types::UpdateAccountSettingsOutput {
            minimum_throughput_billing_commitment: Some(Self::commitment(&mut st, &account, now)),
        })
    }
}

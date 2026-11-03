//! Log groups and log streams, retention, KMS association, tags and the
//! log group flags.

use std::collections::BTreeMap;

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::names::{arn, check_tags, now_ms, page, request_tag_conditions, stream_not_found, GroupRef};
use crate::state::{LogGroup, LogStream, Region};
use crate::Logs;

pub const RETENTION_DAYS: &[i32] =
    &[1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653];

/// `uploadSequenceToken` / `nextSequenceToken` for a stream's sequence.
pub fn sequence_token(seq: u64) -> String {
    format!("49{seq:054}")
}

/// Exactly one of `logGroupName` and `logGroupIdentifier`.
pub fn name_or_identifier(
    ctx: &RequestContext,
    name: Option<&str>,
    identifier: Option<&str>,
) -> Result<GroupRef, ServiceError> {
    match (name, identifier) {
        (Some(_), Some(_)) => {
            Err(errors::invalid_parameter("LogGroup name and LogGroup ARN are mutually exclusive parameters."))
        }
        (Some(n), None) => Ok(GroupRef::own(ctx, n)),
        (None, Some(i)) => GroupRef::parse(ctx, i),
        (None, None) => Err(errors::invalid_parameter("Either LogGroup name or LogGroup ARN must be provided.")),
    }
}

impl Logs {
    pub(crate) fn describe_group(&self, region: &Region, g: &GroupRef, group: &LogGroup) -> types::LogGroup {
        let inherited: Vec<String> = region
            .account_policies
            .values()
            .filter(|p| p.policy_type.as_deref() == Some("DATA_PROTECTION_POLICY"))
            .map(|_| "ACCOUNT_DATA_PROTECTION".to_string())
            .take(1)
            .collect();
        types::LogGroup {
            log_group_name: Some(group.name.clone()),
            creation_time: Some(group.creation_time),
            retention_in_days: group.retention_in_days,
            metric_filter_count: Some(group.metric_filters.len() as i32),
            arn: Some(format!("{}:*", g.arn())),
            stored_bytes: Some(group.streams.values().map(LogStream::stored_bytes).sum()),
            kms_key_id: group.kms_key_id.clone(),
            data_protection_status: group.data_protection_policy.as_ref().map(|_| "ACTIVATED".to_string()),
            inherited_properties: (!inherited.is_empty()).then_some(inherited),
            log_group_class: Some(group.class.clone()),
            log_group_arn: Some(g.arn()),
            deletion_protection_enabled: Some(group.deletion_protection),
            bearer_token_authentication_enabled: Some(group.bearer_token_authentication),
            retention_policy_name: None,
        }
    }

    /// Check that `key` is a KMS key CloudWatch Logs may use for `g`, as
    /// `logs.<region>.amazonaws.com` with the log group ARN as encryption
    /// context.
    pub(crate) fn check_kms_key(
        &self,
        key: &str,
        encryption_context_arn: &str,
        region: &str,
    ) -> Result<(), ServiceError> {
        let denied = || {
            errors::access_denied(format!(
                "The specified KMS key does not exist or is not allowed to be used with Arn '{encryption_context_arn}'"
            ))
        };
        if !key.starts_with("arn:") || !key.contains(":kms:") {
            return Err(denied());
        }
        let Some(kms) = &self.kms else { return Ok(()) };
        let mut cond = ConditionContext::new();
        cond.insert("kms:EncryptionContext:aws:logs:arn".into(), vec![encryption_context_arn.to_string()]);
        let principal = format!("logs.{region}.amazonaws.com");
        let k = kms
            .key_for_service(key, &principal, &["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey"], &cond)
            .map_err(|_| denied())?;
        if k.key_state != "Enabled" || k.key_spec != "SYMMETRIC_DEFAULT" {
            return Err(denied());
        }
        Ok(())
    }

    pub(crate) fn create_log_group(
        &self,
        ctx: &RequestContext,
        input: types::CreateLogGroupRequest,
    ) -> Result<(), ServiceError> {
        let g = GroupRef::own(ctx, &input.log_group_name);
        let tags = input.tags.clone().unwrap_or_default();
        self.authorize_group(ctx, "CreateLogGroup", &g, None, request_tag_conditions(&tags))?;
        if !tags.is_empty() {
            self.authorize_group(ctx, "TagResource", &g, None, request_tag_conditions(&tags))?;
            check_tags(0, &tags)?;
        }
        let class = input.log_group_class.unwrap_or_else(|| "STANDARD".into());
        if let Some(k) = &input.kms_key_id {
            self.check_kms_key(k, &g.arn(), &ctx.region)?;
        }
        let now = now_ms(ctx);
        let mut st = self.lock();
        let region = st.region(&g.account, &g.region);
        if region.log_groups.contains_key(&g.name) {
            return Err(errors::resource_already_exists("The specified log group already exists"));
        }
        region.log_groups.insert(
            g.name.clone(),
            LogGroup {
                name: g.name.clone(),
                creation_time: now,
                retention_in_days: (class == "DELIVERY").then_some(2),
                kms_key_id: input.kms_key_id,
                class,
                tags,
                deletion_protection: input.deletion_protection_enabled.unwrap_or(false),
                ..LogGroup::default()
            },
        );
        Ok(())
    }

    pub(crate) fn delete_log_group(
        &self,
        ctx: &RequestContext,
        input: types::DeleteLogGroupRequest,
    ) -> Result<(), ServiceError> {
        let g = GroupRef::own(ctx, &input.log_group_name);
        self.authorize_group(ctx, "DeleteLogGroup", &g, None, ConditionContext::new())?;
        let mut st = self.lock();
        let region = st.region(&g.account, &g.region);
        let group = region.group(&g.name)?;
        if group.deletion_protection {
            return Err(errors::validation(format!(
                "Log group {} has deletion protection enabled. Disable deletion protection before deleting the log group.",
                g.name
            )));
        }
        region.log_groups.remove(&g.name);
        Ok(())
    }

    pub(crate) fn describe_log_groups(
        &self,
        ctx: &RequestContext,
        input: types::DescribeLogGroupsRequest,
    ) -> Result<types::DescribeLogGroupsResponse, ServiceError> {
        self.authorize(ctx, "DescribeLogGroups", &arn(ctx, "log-group::log-stream:"), ConditionContext::new())?;
        if input.log_group_name_prefix.is_some() && input.log_group_name_pattern.is_some() {
            return Err(errors::invalid_parameter(
                "LogGroup name prefix and LogGroup name pattern are mutually exclusive parameters.",
            ));
        }
        if input.log_group_identifiers.is_some()
            && (input.log_group_name_prefix.is_some() || input.log_group_name_pattern.is_some())
        {
            return Err(errors::invalid_parameter(
                "logGroupIdentifiers is mutually exclusive with logGroupNamePrefix and logGroupNamePattern.",
            ));
        }
        let wanted: Option<Vec<GroupRef>> = input
            .log_group_identifiers
            .as_ref()
            .map(|ids| ids.iter().map(|i| GroupRef::parse(ctx, i)).collect::<Result<_, _>>())
            .transpose()?;
        let mut accounts = vec![ctx.caller.account_id.clone()];
        if input.include_linked_accounts == Some(true) {
            accounts.extend(input.account_identifiers.iter().flatten().cloned());
        }
        let st = self.lock();
        let mut out = Vec::new();
        for account in &accounts {
            let Some(region) = st.region_ref(account, &ctx.region) else { continue };
            for group in region.log_groups.values() {
                let g = GroupRef { account: account.clone(), ..GroupRef::own(ctx, &group.name) };
                if let Some(p) = &input.log_group_name_prefix {
                    if !group.name.starts_with(p.as_str()) {
                        continue;
                    }
                }
                if let Some(p) = &input.log_group_name_pattern {
                    if !group.name.to_lowercase().contains(&p.to_lowercase()) {
                        continue;
                    }
                }
                if let Some(c) = &input.log_group_class {
                    if &group.class != c {
                        continue;
                    }
                }
                if let Some(w) = &wanted {
                    if !w.contains(&g) {
                        continue;
                    }
                }
                out.push(self.describe_group(region, &g, group));
            }
        }
        let (log_groups, next_token) =
            page(out, input.next_token.as_deref(), input.limit.unwrap_or(50).clamp(1, 50) as usize)?;
        Ok(types::DescribeLogGroupsResponse { log_groups: Some(log_groups), next_token })
    }

    pub(crate) fn list_log_groups(
        &self,
        ctx: &RequestContext,
        input: types::ListLogGroupsRequest,
    ) -> Result<types::ListLogGroupsResponse, ServiceError> {
        self.authorize(ctx, "ListLogGroups", &arn(ctx, "log-group:*"), ConditionContext::new())?;
        let pattern = input
            .log_group_name_pattern
            .as_deref()
            .map(|p| regex::Regex::new(p).map_err(|_| errors::invalid_parameter("Invalid logGroupNamePattern.")))
            .transpose()?;
        let mut accounts = vec![ctx.caller.account_id.clone()];
        if input.include_linked_accounts == Some(true) {
            accounts.extend(input.account_identifiers.iter().flatten().cloned());
        }
        let st = self.lock();
        let mut out = Vec::new();
        for account in &accounts {
            let Some(region) = st.region_ref(account, &ctx.region) else { continue };
            for group in region.log_groups.values() {
                if pattern.as_ref().is_some_and(|p| !p.is_match(&group.name)) {
                    continue;
                }
                if input.log_group_class.as_ref().is_some_and(|c| c != &group.class) {
                    continue;
                }
                let tags_ok =
                    input.log_group_tags.iter().flatten().all(|f| {
                        group.tags.get(&f.key).is_some_and(|v| f.values.as_ref().is_none_or(|vs| vs.contains(v)))
                    });
                if !tags_ok {
                    continue;
                }
                if let Some(names) = &input.field_index_names {
                    let indexed = group
                        .index_policy
                        .as_ref()
                        .and_then(|p| p.policy_document.as_deref())
                        .map(crate::policies::indexed_fields)
                        .unwrap_or_default();
                    if !names.iter().any(|n| indexed.contains(n)) {
                        continue;
                    }
                }
                if let Some(ds) = &input.data_sources {
                    let (name, ty) = data_source(&group.name);
                    if !ds.iter().any(|d| d.name == name && d.r#type.as_ref().is_none_or(|t| t == ty)) {
                        continue;
                    }
                }
                let g = GroupRef { account: account.clone(), ..GroupRef::own(ctx, &group.name) };
                out.push(types::LogGroupSummary {
                    log_group_name: Some(group.name.clone()),
                    log_group_arn: Some(g.arn()),
                    log_group_class: Some(group.class.clone()),
                });
            }
        }
        let (log_groups, next_token) =
            page(out, input.next_token.as_deref(), input.limit.unwrap_or(50).clamp(1, 1000) as usize)?;
        Ok(types::ListLogGroupsResponse { log_groups: Some(log_groups), next_token })
    }

    pub(crate) fn list_aggregate_log_group_summaries(
        &self,
        ctx: &RequestContext,
        input: types::ListAggregateLogGroupSummariesRequest,
    ) -> Result<types::ListAggregateLogGroupSummariesResponse, ServiceError> {
        self.authorize(ctx, "ListAggregateLogGroupSummaries", &arn(ctx, "log-group:*"), ConditionContext::new())?;
        let pattern = input
            .log_group_name_pattern
            .as_deref()
            .map(|p| regex::Regex::new(p).map_err(|_| errors::invalid_parameter("Invalid logGroupNamePattern.")))
            .transpose()?;
        let with_format = input.group_by == "DATA_SOURCE_NAME_TYPE_AND_FORMAT";
        let st = self.lock();
        let mut counts: BTreeMap<(String, String), i32> = BTreeMap::new();
        if let Some(region) = st.region_ref(&ctx.caller.account_id, &ctx.region) {
            for group in region.log_groups.values() {
                if pattern.as_ref().is_some_and(|p| !p.is_match(&group.name)) {
                    continue;
                }
                if input.log_group_class.as_ref().is_some_and(|c| c != &group.class) {
                    continue;
                }
                let (name, ty) = data_source(&group.name);
                if let Some(ds) = &input.data_sources {
                    if !ds.iter().any(|d| d.name == name && d.r#type.as_ref().is_none_or(|t| t == ty)) {
                        continue;
                    }
                }
                *counts.entry((name.to_string(), ty.to_string())).or_default() += 1;
            }
        }
        let summaries: Vec<_> = counts
            .into_iter()
            .map(|((name, ty), n)| {
                let mut ids = vec![
                    types::GroupingIdentifier { key: Some("dataSource.name".into()), value: Some(name) },
                    types::GroupingIdentifier { key: Some("dataSource.type".into()), value: Some(ty) },
                ];
                if with_format {
                    ids.push(types::GroupingIdentifier {
                        key: Some("dataSource.format".into()),
                        value: Some("Unknown".into()),
                    });
                }
                types::AggregateLogGroupSummary { log_group_count: Some(n), grouping_identifiers: Some(ids) }
            })
            .collect();
        let (summaries, next_token) =
            page(summaries, input.next_token.as_deref(), input.limit.unwrap_or(50).clamp(1, 1000) as usize)?;
        Ok(types::ListAggregateLogGroupSummariesResponse { aggregate_log_group_summaries: Some(summaries), next_token })
    }

    pub(crate) fn create_log_stream(
        &self,
        ctx: &RequestContext,
        input: types::CreateLogStreamRequest,
    ) -> Result<(), ServiceError> {
        let g = GroupRef::own(ctx, &input.log_group_name);
        self.authorize_group(ctx, "CreateLogStream", &g, Some(&input.log_stream_name), ConditionContext::new())?;
        let now = now_ms(ctx);
        let mut st = self.lock();
        let group = st.group_mut(&g)?;
        if group.streams.contains_key(&input.log_stream_name) {
            return Err(errors::resource_already_exists("The specified log stream already exists"));
        }
        group.streams.insert(
            input.log_stream_name.clone(),
            LogStream { name: input.log_stream_name, creation_time: now, ..LogStream::default() },
        );
        Ok(())
    }

    pub(crate) fn delete_log_stream(
        &self,
        ctx: &RequestContext,
        input: types::DeleteLogStreamRequest,
    ) -> Result<(), ServiceError> {
        let g = GroupRef::own(ctx, &input.log_group_name);
        self.authorize_group(ctx, "DeleteLogStream", &g, Some(&input.log_stream_name), ConditionContext::new())?;
        let mut st = self.lock();
        let group = st.group_mut(&g)?;
        group.streams.remove(&input.log_stream_name).ok_or_else(stream_not_found)?;
        Ok(())
    }

    pub(crate) fn describe_log_streams(
        &self,
        ctx: &RequestContext,
        input: types::DescribeLogStreamsRequest,
    ) -> Result<types::DescribeLogStreamsResponse, ServiceError> {
        let g = name_or_identifier(ctx, input.log_group_name.as_deref(), input.log_group_identifier.as_deref())?;
        self.authorize_group(ctx, "DescribeLogStreams", &g, None, ConditionContext::new())?;
        let by_time = input.order_by.as_deref() == Some("LastEventTime");
        if by_time && input.log_stream_name_prefix.is_some() {
            return Err(errors::invalid_parameter("Cannot order by LastEventTime with a logStreamNamePrefix."));
        }
        let cutoff = self.retention_cutoff_of(&g, now_ms(ctx));
        let st = self.lock();
        let group = st.group(&g)?;
        let mut streams: Vec<&LogStream> = group
            .streams
            .values()
            .filter(|s| input.log_stream_name_prefix.as_ref().is_none_or(|p| s.name.starts_with(p.as_str())))
            .collect();
        if by_time {
            streams.sort_by_key(|s| (s.last_event_timestamp.unwrap_or(0), s.name.clone()));
        }
        if input.descending == Some(true) {
            streams.reverse();
        }
        let out: Vec<types::LogStream> = streams
            .into_iter()
            .map(|s| {
                let live: Vec<_> = s.events.iter().filter(|e| e.timestamp >= cutoff).collect();
                types::LogStream {
                    log_stream_name: Some(s.name.clone()),
                    creation_time: Some(s.creation_time),
                    first_event_timestamp: live.first().map(|e| e.timestamp).or(s.first_event_timestamp),
                    last_event_timestamp: s.last_event_timestamp,
                    last_ingestion_time: s.last_ingestion_time,
                    upload_sequence_token: Some(sequence_token(s.sequence)),
                    arn: Some(g.stream_arn(&s.name)),
                    stored_bytes: Some(0),
                }
            })
            .collect();
        let (log_streams, next_token) =
            page(out, input.next_token.as_deref(), input.limit.unwrap_or(50).clamp(1, 50) as usize)?;
        Ok(types::DescribeLogStreamsResponse { log_streams: Some(log_streams), next_token })
    }

    /// Events older than this are past the group's retention.
    pub(crate) fn retention_cutoff_of(&self, g: &GroupRef, now: i64) -> i64 {
        let st = self.lock();
        st.group(g)
            .ok()
            .and_then(|gr| gr.retention_in_days)
            .map(|d| now - i64::from(d) * 86_400_000)
            .unwrap_or(i64::MIN)
    }

    pub(crate) fn put_retention_policy(
        &self,
        ctx: &RequestContext,
        input: types::PutRetentionPolicyRequest,
    ) -> Result<(), ServiceError> {
        let g = GroupRef::own(ctx, &input.log_group_name);
        self.authorize_group(ctx, "PutRetentionPolicy", &g, None, ConditionContext::new())?;
        if !RETENTION_DAYS.contains(&input.retention_in_days) {
            let set = RETENTION_DAYS.iter().map(i32::to_string).collect::<Vec<_>>().join(", ");
            return Err(errors::invalid_parameter(format!(
                "1 validation error detected: Value '{}' at 'retentionInDays' failed to satisfy constraint: Member must satisfy enum value set: [{set}]",
                input.retention_in_days
            )));
        }
        let mut st = self.lock();
        let group = st.group_mut(&g)?;
        if group.class == "DELIVERY" {
            return Err(errors::invalid_parameter(
                "Retention policy cannot be changed for log groups of the DELIVERY class.",
            ));
        }
        group.retention_in_days = Some(input.retention_in_days);
        let cutoff = now_ms(ctx) - i64::from(input.retention_in_days) * 86_400_000;
        for s in group.streams.values_mut() {
            s.expire(cutoff);
        }
        Ok(())
    }

    pub(crate) fn delete_retention_policy(
        &self,
        ctx: &RequestContext,
        input: types::DeleteRetentionPolicyRequest,
    ) -> Result<(), ServiceError> {
        let g = GroupRef::own(ctx, &input.log_group_name);
        self.authorize_group(ctx, "DeleteRetentionPolicy", &g, None, ConditionContext::new())?;
        let mut st = self.lock();
        st.group_mut(&g)?.retention_in_days = None;
        Ok(())
    }

    pub(crate) fn associate_kms_key(
        &self,
        ctx: &RequestContext,
        input: types::AssociateKmsKeyRequest,
    ) -> Result<(), ServiceError> {
        match (input.log_group_name.as_deref(), input.resource_identifier.as_deref()) {
            (Some(name), None) => {
                let g = GroupRef::own(ctx, name);
                self.authorize_group(ctx, "AssociateKmsKey", &g, None, ConditionContext::new())?;
                self.lock().group(&g)?;
                self.check_kms_key(&input.kms_key_id, &g.arn(), &ctx.region)?;
                self.lock().group_mut(&g)?.kms_key_id = Some(input.kms_key_id);
                Ok(())
            }
            (None, Some(resource)) => {
                let expected = arn(ctx, "query-result:*");
                if resource != expected {
                    return Err(errors::invalid_parameter(format!("Invalid resourceIdentifier: {resource}")));
                }
                self.authorize(ctx, "AssociateKmsKey", resource, ConditionContext::new())?;
                self.check_kms_key(&input.kms_key_id, resource, &ctx.region)?;
                self.lock().region(&ctx.caller.account_id, &ctx.region).storage_tier_kms(Some(input.kms_key_id));
                Ok(())
            }
            _ => {
                Err(errors::invalid_parameter("Exactly one of logGroupName and resourceIdentifier must be specified."))
            }
        }
    }

    pub(crate) fn disassociate_kms_key(
        &self,
        ctx: &RequestContext,
        input: types::DisassociateKmsKeyRequest,
    ) -> Result<(), ServiceError> {
        match (input.log_group_name.as_deref(), input.resource_identifier.as_deref()) {
            (Some(name), None) => {
                let g = GroupRef::own(ctx, name);
                self.authorize_group(ctx, "DisassociateKmsKey", &g, None, ConditionContext::new())?;
                self.lock().group_mut(&g)?.kms_key_id = None;
                Ok(())
            }
            (None, Some(resource)) => {
                self.authorize(ctx, "DisassociateKmsKey", resource, ConditionContext::new())?;
                let mut st = self.lock();
                let region = st.region(&ctx.caller.account_id, &ctx.region);
                if region.query_result_kms_key.is_none() {
                    return Err(errors::resource_not_found("No KMS key is associated with the resource."));
                }
                region.storage_tier_kms(None);
                Ok(())
            }
            _ => {
                Err(errors::invalid_parameter("Exactly one of logGroupName and resourceIdentifier must be specified."))
            }
        }
    }

    pub(crate) fn put_log_group_deletion_protection(
        &self,
        ctx: &RequestContext,
        input: types::PutLogGroupDeletionProtectionRequest,
    ) -> Result<(), ServiceError> {
        let g = GroupRef::parse(ctx, &input.log_group_identifier)?;
        self.authorize_group(ctx, "PutLogGroupDeletionProtection", &g, None, ConditionContext::new())?;
        self.lock().group_mut(&g)?.deletion_protection = input.deletion_protection_enabled;
        Ok(())
    }

    pub(crate) fn put_bearer_token_authentication(
        &self,
        ctx: &RequestContext,
        input: types::PutBearerTokenAuthenticationRequest,
    ) -> Result<(), ServiceError> {
        let g = GroupRef::parse(ctx, &input.log_group_identifier)?;
        self.authorize_group(ctx, "PutBearerTokenAuthentication", &g, None, ConditionContext::new())?;
        self.lock().group_mut(&g)?.bearer_token_authentication = input.bearer_token_authentication_enabled;
        Ok(())
    }

    // ---- tags ---------------------------------------------------------------

    pub(crate) fn tag_log_group(
        &self,
        ctx: &RequestContext,
        input: types::TagLogGroupRequest,
    ) -> Result<(), ServiceError> {
        let g = GroupRef::own(ctx, &input.log_group_name);
        self.authorize_group(ctx, "TagLogGroup", &g, None, request_tag_conditions(&input.tags))?;
        let mut st = self.lock();
        let group = st.group_mut(&g)?;
        let new = input.tags.keys().filter(|k| !group.tags.contains_key(*k)).count();
        if group.tags.len() + new > 50 {
            return Err(errors::invalid_parameter("A resource can have no more than 50 tags."));
        }
        group.tags.extend(input.tags);
        Ok(())
    }

    pub(crate) fn untag_log_group(
        &self,
        ctx: &RequestContext,
        input: types::UntagLogGroupRequest,
    ) -> Result<(), ServiceError> {
        let g = GroupRef::own(ctx, &input.log_group_name);
        let mut cond = ConditionContext::new();
        cond.insert("aws:TagKeys".into(), input.tags.clone());
        self.authorize_group(ctx, "UntagLogGroup", &g, None, cond)?;
        let mut st = self.lock();
        let group = st.group_mut(&g)?;
        for k in &input.tags {
            group.tags.remove(k);
        }
        Ok(())
    }

    pub(crate) fn list_tags_log_group(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsLogGroupRequest,
    ) -> Result<types::ListTagsLogGroupResponse, ServiceError> {
        let g = GroupRef::own(ctx, &input.log_group_name);
        self.authorize_group(ctx, "ListTagsLogGroup", &g, None, ConditionContext::new())?;
        let st = self.lock();
        Ok(types::ListTagsLogGroupResponse { tags: Some(st.group(&g)?.tags.clone()) })
    }

    /// The tags of any taggable resource, by ARN.
    fn with_tags<R>(
        &self,
        resource_arn: &str,
        f: impl FnOnce(&mut BTreeMap<String, String>) -> Result<R, ServiceError>,
    ) -> Result<R, ServiceError> {
        let not_found = || errors::resource_not_found(format!("The specified resource does not exist: {resource_arn}"));
        let parts: Vec<&str> = resource_arn.splitn(6, ':').collect();
        if parts.len() != 6 || parts[0] != "arn" || parts[2] != "logs" {
            return Err(errors::invalid_parameter(format!("Invalid ARN: {resource_arn}")));
        }
        let (account, region_name, rest) = (parts[4], parts[3], parts[5]);
        let mut st = self.lock();
        let region = st.region(account, region_name);
        let (kind, name) = rest.split_once(':').ok_or_else(not_found)?;
        // Delivery resources keep their tags optional, the rest a plain map.
        enum Slot<'a> {
            Map(&'a mut BTreeMap<String, String>),
            Opt(&'a mut Option<BTreeMap<String, String>>),
        }
        let slot = match kind {
            "log-group" => {
                let name = name.strip_suffix(":*").unwrap_or(name);
                Slot::Map(&mut region.log_groups.get_mut(name).ok_or_else(not_found)?.tags)
            }
            "destination" => Slot::Map(&mut region.destinations.get_mut(name).ok_or_else(not_found)?.tags),
            "delivery-source" => Slot::Opt(&mut region.delivery_sources.get_mut(name).ok_or_else(not_found)?.tags),
            "delivery-destination" => {
                Slot::Opt(&mut region.delivery_destinations.get_mut(name).ok_or_else(not_found)?.tags)
            }
            "delivery" => Slot::Opt(&mut region.deliveries.get_mut(name).ok_or_else(not_found)?.tags),
            "anomaly-detector" => {
                Slot::Map(&mut region.anomaly_detectors.get_mut(resource_arn).ok_or_else(not_found)?.tags)
            }
            "lookup-table" => Slot::Map(&mut region.lookup_tables.get_mut(name).ok_or_else(not_found)?.tags),
            "scheduled-query" => {
                Slot::Map(&mut region.scheduled_queries.get_mut(resource_arn).ok_or_else(not_found)?.tags)
            }
            _ => return Err(not_found()),
        };
        match slot {
            Slot::Map(t) => f(t),
            Slot::Opt(t) => {
                let mut tags = t.take().unwrap_or_default();
                let r = f(&mut tags);
                *t = Some(tags);
                r
            }
        }
    }

    fn current_tags(&self, resource_arn: &str) -> Result<BTreeMap<String, String>, ServiceError> {
        self.with_tags(resource_arn, |t| Ok(t.clone()))
    }

    pub(crate) fn tag_resource(
        &self,
        ctx: &RequestContext,
        input: types::TagResourceRequest,
    ) -> Result<(), ServiceError> {
        let existing = self.current_tags(&input.resource_arn)?;
        let mut cond = crate::names::tag_conditions(&existing);
        cond.extend(request_tag_conditions(&input.tags));
        self.authorize(ctx, "TagResource", input.resource_arn.trim_end_matches(":*"), cond)?;
        self.with_tags(&input.resource_arn, |t| {
            let new = input.tags.keys().filter(|k| !t.contains_key(*k)).count();
            check_tags(t.len() + new - input.tags.len(), &input.tags)?;
            t.extend(input.tags);
            Ok(())
        })
    }

    pub(crate) fn untag_resource(
        &self,
        ctx: &RequestContext,
        input: types::UntagResourceRequest,
    ) -> Result<(), ServiceError> {
        let existing = self.current_tags(&input.resource_arn)?;
        let mut cond = crate::names::tag_conditions(&existing);
        cond.insert("aws:TagKeys".into(), input.tag_keys.clone());
        self.authorize(ctx, "UntagResource", input.resource_arn.trim_end_matches(":*"), cond)?;
        self.with_tags(&input.resource_arn, |t| {
            for k in &input.tag_keys {
                t.remove(k);
            }
            Ok(())
        })
    }

    pub(crate) fn list_tags_for_resource(
        &self,
        ctx: &RequestContext,
        input: types::ListTagsForResourceRequest,
    ) -> Result<types::ListTagsForResourceResponse, ServiceError> {
        let existing = self.current_tags(&input.resource_arn)?;
        self.authorize(
            ctx,
            "ListTagsForResource",
            input.resource_arn.trim_end_matches(":*"),
            crate::names::tag_conditions(&existing),
        )?;
        Ok(types::ListTagsForResourceResponse { tags: Some(existing) })
    }
}

/// The data source CloudWatch Logs infers for a log group from its name.
pub fn data_source(name: &str) -> (&'static str, &'static str) {
    if name.starts_with("/aws/lambda/") {
        ("aws_lambda", "AWS::Lambda::Function")
    } else if name.starts_with("/aws/route53/") {
        ("amazon_route53", "AWS::Route53::HostedZone")
    } else if name.starts_with("/aws/vendedlogs/") {
        ("aws_vended_logs", "Unknown")
    } else {
        ("Unknown", "Unknown")
    }
}

impl Region {
    pub fn storage_tier_kms(&mut self, key: Option<String>) {
        self.query_result_kms_key = key;
    }
}

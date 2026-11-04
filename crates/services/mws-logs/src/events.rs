//! Writing and reading log events: `PutLogEvents`, `GetLogEvents` and
//! `FilterLogEvents`.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::filter;
use crate::generated::{errors, types};
use crate::groups::{name_or_identifier, sequence_token};
use crate::names::{now_ms, page, stream_not_found, GroupRef};
use crate::state::{Event, LogGroup};
use crate::Logs;

const MAX_BATCH_BYTES: i64 = 1_048_576;
const DAY_MS: i64 = 86_400_000;
const MAX_EVENTS_PER_PAGE: usize = 10_000;

/// A `GetLogEvents` token: `f/<56 digits>/s` or `b/<56 digits>/s`.
fn token(dir: char, pos: usize) -> String {
    format!("{dir}/{pos:056}/s")
}

fn parse_token(t: &str) -> Option<(char, usize)> {
    let mut parts = t.split('/');
    let dir = parts.next()?.chars().next()?;
    let pos = parts.next()?.parse().ok()?;
    (matches!(dir, 'f' | 'b') && parts.next() == Some("s")).then_some((dir, pos))
}

pub fn event_id(seq: u64) -> String {
    format!("3{seq:055}")
}

/// Turn a filter pattern parse failure into the error AWS returns.
pub fn parse_pattern(p: Option<&str>) -> Result<filter::Pattern, ServiceError> {
    filter::parse(p.unwrap_or("")).map_err(|_| errors::invalid_parameter("Invalid character(s) in term"))
}

/// The oldest timestamp a group's retention still keeps.
pub fn cutoff(group: &LogGroup, now: i64) -> i64 {
    group.retention_in_days.map(|d| now - i64::from(d) * DAY_MS).unwrap_or(i64::MIN)
}

/// The transformer that applies to a log group at ingestion: its own, or
/// else an account-level `TRANSFORMER_POLICY` whose selection criteria
/// match it.
pub fn transformer_for(st: &crate::state::State, g: &GroupRef) -> Option<Vec<types::Processor>> {
    if let Some(t) = st.group(g).ok().and_then(|group| group.transformer.as_ref()) {
        return Some(t.processors.clone());
    }
    let region = st.region_ref(&g.account, &g.region)?;
    region
        .account_policies
        .values()
        .filter(|p| p.policy_type.as_deref() == Some("TRANSFORMER_POLICY"))
        .filter(|p| crate::policies::selection_matches(p.selection_criteria.as_deref(), &g.name))
        .find_map(|p| {
            let doc: serde_json::Value = serde_json::from_str(p.policy_document.as_deref()?).ok()?;
            let mut d = mws_proto_json::Decoder::new();
            let processors = crate::generated::de::de_processors(&mut d, doc.get("transformerConfig"), "")?;
            d.finish("InvalidParameterException").ok()?;
            Some(processors)
        })
}

pub struct Accepted {
    pub response: types::PutLogEventsResponse,
    pub stored: Vec<Event>,
}

impl Logs {
    /// Store a batch the way `PutLogEvents` does, after authorization.
    pub(crate) fn store_events(
        &self,
        g: &GroupRef,
        stream: &str,
        events: Vec<types::InputLogEvent>,
        now: i64,
    ) -> Result<Accepted, ServiceError> {
        if events.windows(2).any(|w| w[1].timestamp < w[0].timestamp) {
            return Err(errors::invalid_parameter(
                "Log events in a single PutLogEvents request must be in chronological order.",
            ));
        }
        if let (Some(first), Some(last)) = (events.first(), events.last()) {
            if last.timestamp - first.timestamp > DAY_MS {
                return Err(errors::invalid_parameter(
                    "The batch of log events in a single PutLogEvents request cannot span more than 24 hours.",
                ));
            }
        }
        let size: i64 = events.iter().map(|e| e.message.len() as i64 + 26).sum();
        if size > MAX_BATCH_BYTES {
            return Err(errors::invalid_parameter(format!(
                "Upload too large: {size} bytes exceeds limit of {MAX_BATCH_BYTES}"
            )));
        }
        let mut st = self.lock();
        let processors = transformer_for(&st, g);
        let mut seq = st.next_seq;
        let group = st.group_mut(g)?;
        let retention_cutoff = cutoff(group, now);
        let stream = group.streams.get_mut(stream).ok_or_else(stream_not_found)?;
        let mut info = types::RejectedLogEventsInfo::default();
        let mut stored = Vec::new();
        for (i, e) in events.into_iter().enumerate() {
            let i = i as i32;
            if e.timestamp > now + 2 * 3_600_000 {
                info.too_new_log_event_start_index.get_or_insert(i);
                continue;
            }
            if e.timestamp < now - 14 * DAY_MS {
                info.too_old_log_event_end_index = Some(i);
                continue;
            }
            if e.timestamp < retention_cutoff {
                info.expired_log_event_end_index = Some(i);
                continue;
            }
            // Transformation happens at ingestion; an event the
            // processors cannot handle keeps only its original form.
            let transformed = processors.as_deref().and_then(|p| crate::transform::run(p, &e.message).ok());
            let ev = Event { timestamp: e.timestamp, ingestion_time: now, message: e.message, seq, transformed };
            seq += 1;
            stream.first_event_timestamp =
                Some(stream.first_event_timestamp.map_or(ev.timestamp, |t| t.min(ev.timestamp)));
            stream.last_event_timestamp =
                Some(stream.last_event_timestamp.map_or(ev.timestamp, |t| t.max(ev.timestamp)));
            stream.last_ingestion_time = Some(now);
            stored.push(ev.clone());
            stream.insert(ev);
        }
        stream.sequence += 1;
        stream.expire(retention_cutoff);
        let next = sequence_token(stream.sequence);
        st.next_seq = seq;
        let rejected = info.too_new_log_event_start_index.is_some()
            || info.too_old_log_event_end_index.is_some()
            || info.expired_log_event_end_index.is_some();
        Ok(Accepted {
            response: types::PutLogEventsResponse {
                next_sequence_token: Some(next),
                rejected_log_events_info: rejected.then_some(info),
                rejected_entity_info: None,
            },
            stored,
        })
    }

    pub(crate) fn put_log_events(
        &self,
        ctx: &RequestContext,
        input: types::PutLogEventsRequest,
    ) -> Result<types::PutLogEventsResponse, ServiceError> {
        let g = GroupRef::own(ctx, &input.log_group_name);
        self.authorize_group(ctx, "PutLogEvents", &g, Some(&input.log_stream_name), ConditionContext::new())?;
        let accepted = self.store_events(&g, &input.log_stream_name, input.log_events, now_ms(ctx))?;
        self.tails.publish(&g, &input.log_stream_name, &accepted.stored);
        self.forward(Some(ctx), &g, &input.log_stream_name, &accepted.stored);
        let mut response = accepted.response;
        if let Some(entity) = &input.entity {
            let attrs = entity.key_attributes.as_ref().map_or(0, |a| a.len());
            if attrs == 0 || attrs > 4 {
                response.rejected_entity_info =
                    Some(types::RejectedEntityInfo { error_type: "InvalidKeyAttributes".into() });
            }
        }
        Ok(response)
    }

    /// Authorize `logs:Unmask` when the caller asks for unmasked events.
    /// The data protection policies to apply, or none when the caller
    /// asks to unmask (and may).
    fn masking(&self, ctx: &RequestContext, g: &GroupRef, unmask: bool) -> Result<Vec<(String, i64)>, ServiceError> {
        if unmask {
            self.authorize_group(ctx, "Unmask", g, None, ConditionContext::new())?;
            return Ok(Vec::new());
        }
        let st = self.lock();
        st.group(g)?;
        Ok(crate::policies::masks_for(&st, g))
    }

    pub(crate) fn get_log_events(
        &self,
        ctx: &RequestContext,
        input: types::GetLogEventsRequest,
    ) -> Result<types::GetLogEventsResponse, ServiceError> {
        let g = name_or_identifier(ctx, input.log_group_name.as_deref(), input.log_group_identifier.as_deref())?;
        self.authorize_group(ctx, "GetLogEvents", &g, Some(&input.log_stream_name), ConditionContext::new())?;
        let mask = self.masking(ctx, &g, input.unmask)?;
        let now = now_ms(ctx);
        let st = self.lock();
        let group = st.group(&g)?;
        let stream = group.streams.get(&input.log_stream_name).ok_or_else(stream_not_found)?;
        let floor = cutoff(group, now).max(input.start_time.unwrap_or(i64::MIN));
        let events = &stream.events;
        let lo = events.partition_point(|e| e.timestamp < floor);
        let hi = match input.end_time {
            Some(end) => events.partition_point(|e| e.timestamp < end),
            None => events.len(),
        }
        .max(lo);
        let limit = input.limit.map_or(MAX_EVENTS_PER_PAGE, |l| l.clamp(1, 10_000) as usize);
        let (dir, pos) = match input.next_token.as_deref() {
            Some(t) => {
                parse_token(t).ok_or_else(|| errors::invalid_parameter("The specified nextToken is invalid."))?
            }
            None if input.start_from_head == Some(true) => ('f', lo),
            None => ('b', hi),
        };
        let (start, end) = if dir == 'f' {
            let s = pos.clamp(lo, hi);
            (s, (s + limit).min(hi))
        } else {
            let e = pos.clamp(lo, hi);
            (e.saturating_sub(limit).max(lo), e)
        };
        // Stay within 1 MB, keeping the events nearest the token.
        let (mut start, mut end) = (start, end);
        let mut bytes = 0i64;
        let mut kept = 0;
        if dir == 'f' {
            for e in &events[start..end] {
                bytes += e.size();
                if bytes > MAX_BATCH_BYTES && kept > 0 {
                    break;
                }
                kept += 1;
            }
            end = start + kept;
        } else {
            for e in events[start..end].iter().rev() {
                bytes += e.size();
                if bytes > MAX_BATCH_BYTES && kept > 0 {
                    break;
                }
                kept += 1;
            }
            start = end - kept;
        }
        let out = events[start..end]
            .iter()
            .map(|e| types::OutputLogEvent {
                timestamp: Some(e.timestamp),
                message: Some(crate::policies::mask(&mask, e.ingestion_time, &e.message)),
                ingestion_time: Some(e.ingestion_time),
            })
            .collect();
        Ok(types::GetLogEventsResponse {
            events: Some(out),
            next_forward_token: Some(token('f', end)),
            next_backward_token: Some(token('b', start)),
        })
    }

    pub(crate) fn filter_log_events(
        &self,
        ctx: &RequestContext,
        input: types::FilterLogEventsRequest,
    ) -> Result<types::FilterLogEventsResponse, ServiceError> {
        let g = name_or_identifier(ctx, input.log_group_name.as_deref(), input.log_group_identifier.as_deref())?;
        self.authorize_group(ctx, "FilterLogEvents", &g, None, ConditionContext::new())?;
        if input.log_stream_names.is_some() && input.log_stream_name_prefix.is_some() {
            return Err(errors::invalid_parameter(
                "logStreamNames and logStreamNamePrefix are mutually exclusive parameters.",
            ));
        }
        let pattern = parse_pattern(input.filter_pattern.as_deref())?;
        let mask = self.masking(ctx, &g, input.unmask)?;
        let now = now_ms(ctx);
        let st = self.lock();
        let group = st.group(&g)?;
        if let Some(names) = &input.log_stream_names {
            if let Some(missing) = names.iter().find(|n| !group.streams.contains_key(*n)) {
                let _ = missing;
                return Err(stream_not_found());
            }
        }
        let floor = cutoff(group, now).max(input.start_time.unwrap_or(i64::MIN));
        let mut hits: Vec<(&str, &Event)> = Vec::new();
        for s in group.streams.values() {
            if let Some(names) = &input.log_stream_names {
                if !names.contains(&s.name) {
                    continue;
                }
            }
            if let Some(p) = &input.log_stream_name_prefix {
                if !s.name.starts_with(p.as_str()) {
                    continue;
                }
            }
            for e in &s.events {
                if e.timestamp < floor || input.end_time.is_some_and(|end| e.timestamp >= end) {
                    continue;
                }
                if pattern.matches(&e.message) {
                    hits.push((s.name.as_str(), e));
                }
            }
        }
        hits.sort_by_key(|(_, e)| (e.timestamp, e.seq));
        let events: Vec<types::FilteredLogEvent> = hits
            .into_iter()
            .map(|(stream, e)| types::FilteredLogEvent {
                log_stream_name: Some(stream.to_string()),
                timestamp: Some(e.timestamp),
                message: Some(crate::policies::mask(&mask, e.ingestion_time, &e.message)),
                ingestion_time: Some(e.ingestion_time),
                event_id: Some(event_id(e.seq)),
            })
            .collect();
        let limit = input.limit.map_or(MAX_EVENTS_PER_PAGE, |l| l.clamp(1, 10_000) as usize);
        let (events, next_token) = page(events, input.next_token.as_deref(), limit)?;
        Ok(types::FilterLogEventsResponse { events: Some(events), searched_log_streams: Some(Vec::new()), next_token })
    }
}

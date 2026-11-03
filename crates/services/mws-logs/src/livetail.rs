//! `StartLiveTail`: a session that stays open and streams the events that
//! arrive in its log groups, once a second, for up to three hours.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use mws_core::{ConditionContext, HttpResponse, RequestContext, ServiceError, StreamingBody};

use crate::events::parse_pattern;
use crate::filter::Pattern;
use crate::generated::{self, errors, types};
use crate::names::{uuid, GroupRef};
use crate::state::Event;
use crate::Logs;

/// Sessions last at most this long.
const SESSION_LIMIT: Duration = Duration::from_secs(3 * 3600);
/// Above this many events per update, AWS samples.
const MAX_EVENTS_PER_UPDATE: usize = 500;

struct Session {
    groups: Vec<(GroupRef, String)>,
    stream_names: Option<Vec<String>>,
    prefixes: Option<Vec<String>>,
    pattern: Pattern,
    buffer: Arc<Mutex<Vec<types::LiveTailSessionLogEvent>>>,
}

/// Open live tail sessions. Not part of the persisted state.
#[derive(Clone, Default)]
pub struct Sessions(Arc<Mutex<Vec<Session>>>);

impl Sessions {
    fn add(&self, s: Session) {
        self.0.lock().expect("live tail lock").push(s);
    }

    fn remove(&self, buffer: &Arc<Mutex<Vec<types::LiveTailSessionLogEvent>>>) {
        self.0.lock().expect("live tail lock").retain(|s| !Arc::ptr_eq(&s.buffer, buffer));
    }

    pub fn clear(&self) {
        self.0.lock().expect("live tail lock").clear();
    }

    /// Hand newly stored events to the sessions watching their stream.
    pub fn publish(&self, g: &GroupRef, stream: &str, events: &[Event]) {
        if events.is_empty() {
            return;
        }
        let sessions = self.0.lock().expect("live tail lock");
        for s in sessions.iter() {
            let Some((_, identifier)) = s.groups.iter().find(|(r, _)| r == g) else { continue };
            if s.stream_names.as_ref().is_some_and(|n| !n.iter().any(|n| n == stream)) {
                continue;
            }
            if s.prefixes.as_ref().is_some_and(|p| !p.iter().any(|p| stream.starts_with(p.as_str()))) {
                continue;
            }
            let mut buf = s.buffer.lock().expect("live tail buffer");
            for e in events.iter().filter(|e| s.pattern.matches(&e.message)) {
                buf.push(types::LiveTailSessionLogEvent {
                    log_stream_name: Some(stream.to_string()),
                    log_group_identifier: Some(identifier.clone()),
                    message: Some(e.message.clone()),
                    timestamp: Some(e.timestamp),
                    ingestion_time: Some(e.ingestion_time),
                });
            }
        }
    }
}

impl Logs {
    /// Validate and authorize a live tail request; the `sessionStart`
    /// event and the session to register.
    fn open_live_tail(
        &self,
        ctx: &RequestContext,
        input: types::StartLiveTailRequest,
    ) -> Result<(types::LiveTailSessionStart, Session), ServiceError> {
        if input.log_stream_names.is_some() && input.log_stream_name_prefixes.is_some() {
            return Err(errors::invalid_parameter(
                "logStreamNames and logStreamNamePrefixes are mutually exclusive parameters.",
            ));
        }
        if (input.log_stream_names.is_some() || input.log_stream_name_prefixes.is_some())
            && input.log_group_identifiers.len() != 1
        {
            return Err(errors::invalid_parameter(
                "logStreamNames and logStreamNamePrefixes can only be used with a single log group.",
            ));
        }
        let mut groups = Vec::new();
        for id in &input.log_group_identifiers {
            if id.ends_with('*') {
                return Err(errors::invalid_parameter(format!(
                    "Log group identifier {id} must not end with an asterisk (*)."
                )));
            }
            let g = GroupRef::parse(ctx, id)?;
            self.authorize_group(ctx, "StartLiveTail", &g, None, ConditionContext::new())?;
            self.lock().group(&g)?;
            groups.push((g, id.clone()));
        }
        let pattern = parse_pattern(input.log_event_filter_pattern.as_deref())?;
        let start = types::LiveTailSessionStart {
            request_id: Some(ctx.request_id.clone()),
            session_id: Some(uuid()),
            log_group_identifiers: Some(input.log_group_identifiers.clone()),
            log_stream_names: input.log_stream_names.clone(),
            log_stream_name_prefixes: input.log_stream_name_prefixes.clone(),
            log_event_filter_pattern: input.log_event_filter_pattern.clone(),
        };
        let session = Session {
            groups,
            stream_names: input.log_stream_names,
            prefixes: input.log_stream_name_prefixes,
            pattern,
            buffer: Arc::default(),
        };
        Ok((start, session))
    }

    /// The wire path: the response stays open and a background task sends
    /// a `sessionUpdate` every second until the client goes away or the
    /// session times out.
    pub(crate) fn start_live_tail_streaming(
        &self,
        ctx: &RequestContext,
        input: types::StartLiveTailRequest,
    ) -> Result<HttpResponse, ServiceError> {
        let (start, session) = self.open_live_tail(ctx, input)?;
        let head = generated::encode_event_start_live_tail_response_stream(
            &types::StartLiveTailResponseStream::SessionStart(start),
        );
        let buffer = session.buffer.clone();
        self.tails.add(session);
        let (tx, body) = StreamingBody::channel(16);
        let sessions = self.tails.clone();
        tokio::spawn(async move {
            let started = tokio::time::Instant::now();
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            tick.tick().await;
            loop {
                tick.tick().await;
                if started.elapsed() >= SESSION_LIMIT {
                    let timeout =
                        types::StartLiveTailResponseStream::SessionTimeoutException(types::SessionTimeoutException {
                            message: Some("Session timed out after 3 hours".into()),
                        });
                    let _ =
                        tx.send(Bytes::from(generated::encode_event_start_live_tail_response_stream(&timeout))).await;
                    break;
                }
                let mut events = std::mem::take(&mut *buffer.lock().expect("live tail buffer"));
                let sampled = events.len() > MAX_EVENTS_PER_UPDATE;
                if sampled {
                    let step = events.len().div_ceil(MAX_EVENTS_PER_UPDATE);
                    events = events.into_iter().step_by(step).collect();
                }
                let update = types::StartLiveTailResponseStream::SessionUpdate(types::LiveTailSessionUpdate {
                    session_metadata: Some(types::LiveTailSessionMetadata { sampled }),
                    session_results: Some(events),
                });
                let frame = generated::encode_event_start_live_tail_response_stream(&update);
                if tx.send(Bytes::from(frame)).await.is_err() {
                    break;
                }
            }
            sessions.remove(&buffer);
        });
        let mut resp = mws_proto_json::event_stream_response(&generated::SERVICE_INFO, &ctx.request_id, head);
        resp.extensions_mut().insert(body);
        Ok(resp)
    }

    /// The scenario/invoke path: just the `sessionStart` event.
    pub(crate) fn start_live_tail(
        &self,
        ctx: &RequestContext,
        input: types::StartLiveTailRequest,
    ) -> Result<types::StartLiveTailResponse, ServiceError> {
        let (start, _) = self.open_live_tail(ctx, input)?;
        Ok(types::StartLiveTailResponse {
            response_stream: vec![types::StartLiveTailResponseStream::SessionStart(start)],
        })
    }
}

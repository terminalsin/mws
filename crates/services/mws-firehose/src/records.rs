//! `PutRecord` and `PutRecordBatch`: records go into the destination's
//! buffer and are delivered later.

use mws_core::{ConditionContext, RequestContext, ServiceError};
use rand::Rng;

use crate::generated::{errors, types};
use crate::monitor::point;
use crate::names::{authorize, invalid_argument, not_found, now_ms, StreamRef};
use crate::state::{Buffered, DeliveryStream, State};
use crate::Firehose;

/// A batch may carry at most this many bytes.
const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024;

/// Record ids look like Firehose's: long and opaque.
pub(crate) fn record_id() -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut rng = rand::thread_rng();
    (0..112).map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char).collect()
}

fn writable<'a>(st: &'a mut State, r: &StreamRef) -> Result<&'a mut DeliveryStream, ServiceError> {
    let s = r.get_mut(st)?;
    if !s.active() {
        return Err(not_found(&s.name, &s.account));
    }
    if s.kind != "DirectPut" {
        return Err(invalid_argument(format!("This operation is not permitted on {} delivery stream type.", s.kind)));
    }
    Ok(s)
}

fn encrypted(s: &DeliveryStream) -> Option<bool> {
    s.encryption.as_ref().map(|e| e.status == "ENABLED")
}

/// Buffer records in every destination of the stream.
pub(crate) fn buffer(s: &mut DeliveryStream, records: Vec<Buffered>) {
    if let Some((last, rest)) = s.destinations.split_last_mut() {
        for d in rest {
            d.buffer.extend(records.iter().cloned());
        }
        last.buffer.extend(records);
    }
}

impl Firehose {
    pub fn put_record(
        &self,
        ctx: &RequestContext,
        input: types::PutRecordInput,
    ) -> Result<types::PutRecordOutput, ServiceError> {
        let r = StreamRef::new(ctx, &input.delivery_stream_name);
        let mut st = self.settled(ctx);
        authorize(ctx, &st, "PutRecord", &r, ConditionContext::new())?;
        let s = writable(&mut st, &r)?;
        let id = record_id();
        let bytes = input.record.data.len() as f64;
        let rec = Buffered { record_id: id.clone(), data: input.record.data, arrival: now_ms(ctx), kinesis: None };
        buffer(s, vec![rec]);
        let out = types::PutRecordOutput { record_id: id, encrypted: encrypted(s) };
        let (account, name) = (s.account.clone(), s.name.clone());
        drop(st);
        self.metrics(
            ctx,
            &account,
            &name,
            vec![
                point("IncomingBytes", "Bytes", bytes),
                point("IncomingRecords", "Count", 1.0),
                point("IncomingPutRequests", "Count", 1.0),
                point("PutRecord.Bytes", "Bytes", bytes),
                point("PutRecord.Requests", "Count", 1.0),
            ],
        );
        Ok(out)
    }

    pub fn put_record_batch(
        &self,
        ctx: &RequestContext,
        input: types::PutRecordBatchInput,
    ) -> Result<types::PutRecordBatchOutput, ServiceError> {
        let r = StreamRef::new(ctx, &input.delivery_stream_name);
        let total: usize = input.records.iter().map(|r| r.data.len()).sum();
        let mut st = self.settled(ctx);
        authorize(ctx, &st, "PutRecordBatch", &r, ConditionContext::new())?;
        let s = writable(&mut st, &r)?;
        if total > MAX_BATCH_BYTES {
            return Err(errors::invalid_argument(format!(
                "Records size exceeds 4 MB limit for Firehose {} under account {}.",
                s.name, s.account
            )));
        }
        let now = now_ms(ctx);
        let mut responses = Vec::new();
        let mut buffered = Vec::new();
        for rec in input.records {
            let id = record_id();
            responses.push(types::PutRecordBatchResponseEntry {
                record_id: Some(id.clone()),
                error_code: None,
                error_message: None,
            });
            buffered.push(Buffered { record_id: id, data: rec.data, arrival: now, kinesis: None });
        }
        let count = buffered.len() as f64;
        buffer(s, buffered);
        let out =
            types::PutRecordBatchOutput { failed_put_count: 0, encrypted: encrypted(s), request_responses: responses };
        let (account, name) = (s.account.clone(), s.name.clone());
        drop(st);
        self.metrics(
            ctx,
            &account,
            &name,
            vec![
                point("IncomingBytes", "Bytes", total as f64),
                point("IncomingRecords", "Count", count),
                point("IncomingPutRequests", "Count", 1.0),
                point("PutRecordBatch.Bytes", "Bytes", total as f64),
                point("PutRecordBatch.Records", "Count", count),
                point("PutRecordBatch.Requests", "Count", 1.0),
            ],
        );
        Ok(out)
    }
}

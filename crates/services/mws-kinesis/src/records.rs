//! Writing and reading records: `PutRecord`, `PutRecords`,
//! `GetShardIterator` and `GetRecords`.

use mws_core::{ConditionContext, RequestContext, ServiceError};

use crate::generated::{errors, types};
use crate::names::{authorize_stream, invalid_argument, now_ms, stream_not_found, StreamRef};
use crate::shards::{hash_partition_key, parse_sequence_number, sequence_number, Iterator, ITERATOR_TTL_MS};
use crate::state::{shard_id, Shard, StoredRecord, Stream};
use crate::Kinesis;

/// `GetRecords` returns at most this many bytes per call.
const MAX_GET_BYTES: usize = 10 * 1024 * 1024;

fn time(ms: i64) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::from_timestamp_millis(ms).unwrap_or_default()
}

fn dry_run() -> ServiceError {
    errors::dry_run_operation("The request would have succeeded, but the DryRun flag is set.")
}

/// Streams accept writes and reads while `ACTIVE` or `UPDATING`.
fn usable<'a>(st: &'a mut crate::state::State, r: &StreamRef) -> Result<&'a mut Stream, ServiceError> {
    let s = r.get_mut(st)?;
    if !matches!(s.status.as_str(), "ACTIVE" | "UPDATING") {
        return Err(stream_not_found(&s.name, &s.account));
    }
    Ok(s)
}

/// One record to write, already validated against the model.
struct Entry<'a> {
    data: &'a [u8],
    partition_key: Option<&'a str>,
    explicit_hash_key: Option<&'a str>,
}

fn check_entry(s: &Stream, e: &Entry<'_>) -> Result<(), ServiceError> {
    if s.distribution != "AUTO" && e.partition_key.is_none() {
        return Err(errors::validation(
            "1 validation error detected: Value null at 'partitionKey' failed to satisfy constraint: Member must not be null",
        ));
    }
    let size = e.data.len() + e.partition_key.map_or(0, str::len);
    let max = s.max_record_size_kib as usize * 1024;
    if size > max {
        return Err(errors::validation(format!(
            "1 validation error detected: Value at 'data' failed to satisfy constraint: Member must have length less than or equal to {max}"
        )));
    }
    if let Some(h) = e.explicit_hash_key {
        if h.parse::<u128>().is_err() {
            return Err(invalid_argument(format!(
                "Invalid ExplicitHashKey. ExplicitHashKey must be in the range: [0, 2^128-1]. Specified value was {h}"
            )));
        }
    }
    Ok(())
}

/// Append a record to the shard it maps to; `(shard id, sequence number)`.
fn append(s: &mut Stream, e: &Entry<'_>, now: i64) -> (String, String) {
    let created = s.created_at;
    let open: Vec<usize> = s.shards.iter().enumerate().filter(|(_, sh)| sh.open()).map(|(i, _)| i).collect();
    let pos = if s.distribution == "AUTO" {
        let i = open[(s.round_robin % open.len() as u64) as usize];
        s.round_robin += 1;
        i
    } else {
        let hash = match e.explicit_hash_key {
            Some(h) => h.parse::<u128>().unwrap_or_default(),
            None => hash_partition_key(e.partition_key.unwrap_or_default()),
        };
        open.iter().copied().find(|i| s.shards[*i].contains(hash)).unwrap_or(open[0])
    };
    let shard: &mut Shard = &mut s.shards[pos];
    let counter = shard.next_counter;
    shard.next_counter += 1;
    shard.records.push(StoredRecord {
        counter,
        data: e.data.to_vec(),
        partition_key: e.partition_key.unwrap_or_default().to_string(),
        arrival: now,
    });
    (shard.id(), sequence_number(created, shard.index, counter))
}

impl Kinesis {
    /// The KMS checks a put to an encrypted stream makes, with the
    /// caller's permissions. Returns the stream's encryption type.
    fn encryption_for_put(&self, ctx: &RequestContext, r: &StreamRef) -> Result<String, ServiceError> {
        let key = {
            let st = self.lock();
            let s = r.get(&st)?;
            if !s.encrypted() {
                return Ok("NONE".into());
            }
            s.key_id.clone().unwrap_or_default()
        };
        let (_, data_key) = self.new_data_key(ctx, &r.arn, &key)?;
        if !data_key.is_empty() {
            if let Some(s) = self.lock().streams.get_mut(&r.arn) {
                s.data_key = data_key;
            }
        }
        Ok("KMS".into())
    }

    pub fn put_record(
        &self,
        ctx: &RequestContext,
        input: types::PutRecordInput,
    ) -> Result<types::PutRecordOutput, ServiceError> {
        let r = StreamRef::resolve(ctx, input.stream_name.as_deref(), input.stream_arn.as_deref())?;
        let entry = Entry {
            data: &input.data,
            partition_key: input.partition_key.as_deref(),
            explicit_hash_key: input.explicit_hash_key.as_deref(),
        };
        {
            let mut st = self.settled(ctx);
            authorize_stream(ctx, &st, "PutRecord", &r, ConditionContext::new())?;
            let s = usable(&mut st, &r)?;
            check_entry(s, &entry)?;
            if let Some(seq) = &input.sequence_number_for_ordering {
                if parse_sequence_number(seq).is_none() {
                    return Err(invalid_argument(format!(
                        "ExclusiveMinimumSequenceNumber {seq} used in PutRecord on stream {} under account {} is invalid.",
                        s.name, s.account
                    )));
                }
            }
        }
        if input.dry_run == Some(true) {
            return Err(dry_run());
        }
        let encryption = self.encryption_for_put(ctx, &r)?;
        let now = now_ms(ctx);
        let (shard, seq) = {
            let mut st = self.lock();
            let s = usable(&mut st, &r)?;
            append(s, &entry, now)
        };
        self.arrivals.notify_waiters();
        Ok(types::PutRecordOutput { shard_id: shard, sequence_number: seq, encryption_type: Some(encryption) })
    }

    pub fn put_records(
        &self,
        ctx: &RequestContext,
        input: types::PutRecordsInput,
    ) -> Result<types::PutRecordsOutput, ServiceError> {
        let r = StreamRef::resolve(ctx, input.stream_name.as_deref(), input.stream_arn.as_deref())?;
        let entries: Vec<Entry<'_>> = input
            .records
            .iter()
            .map(|e| Entry {
                data: &e.data,
                partition_key: e.partition_key.as_deref(),
                explicit_hash_key: e.explicit_hash_key.as_deref(),
            })
            .collect();
        {
            let mut st = self.settled(ctx);
            authorize_stream(ctx, &st, "PutRecords", &r, ConditionContext::new())?;
            let s = usable(&mut st, &r)?;
            for e in &entries {
                check_entry(s, e)?;
            }
            let total: usize = entries.iter().map(|e| e.data.len() + e.partition_key.map_or(0, str::len)).sum();
            if total > 10 * 1024 * 1024 {
                return Err(invalid_argument(format!(
                    "Records size exceeds 10 MB limit for stream {} under account {}.",
                    s.name, s.account
                )));
            }
        }
        if input.dry_run == Some(true) {
            return Err(dry_run());
        }
        let encryption = self.encryption_for_put(ctx, &r)?;
        let now = now_ms(ctx);
        let results = {
            let mut st = self.lock();
            let s = usable(&mut st, &r)?;
            entries
                .iter()
                .map(|e| {
                    let (shard, seq) = append(s, e, now);
                    types::PutRecordsResultEntry {
                        sequence_number: Some(seq),
                        shard_id: Some(shard),
                        error_code: None,
                        error_message: None,
                    }
                })
                .collect()
        };
        self.arrivals.notify_waiters();
        Ok(types::PutRecordsOutput {
            failed_record_count: Some(0),
            records: results,
            encryption_type: Some(encryption),
        })
    }

    pub fn get_shard_iterator(
        &self,
        ctx: &RequestContext,
        input: types::GetShardIteratorInput,
    ) -> Result<types::GetShardIteratorOutput, ServiceError> {
        let r = StreamRef::resolve(ctx, input.stream_name.as_deref(), input.stream_arn.as_deref())?;
        let mut st = self.settled(ctx);
        authorize_stream(ctx, &st, "GetShardIterator", &r, ConditionContext::new())?;
        let now = now_ms(ctx);
        let s = usable(&mut st, &r)?;
        let Some(shard) = s.shard(&input.shard_id) else {
            return Err(errors::resource_not_found(format!(
                "Shard {} in stream {} under account {} does not exist",
                input.shard_id, s.name, s.account
            )));
        };
        let counter = position(
            s,
            shard,
            &input.shard_iterator_type,
            input.starting_sequence_number.as_deref(),
            input.timestamp.map(|t| t.timestamp_millis()),
        )?;
        if input.dry_run == Some(true) {
            return Err(dry_run());
        }
        let it = Iterator {
            stream_arn: s.arn.clone(),
            stream_created: s.created_at,
            shard: shard.index,
            counter,
            issued: now,
        };
        Ok(types::GetShardIteratorOutput { shard_iterator: Some(it.encode()) })
    }

    pub fn get_records(
        &self,
        ctx: &RequestContext,
        input: types::GetRecordsInput,
    ) -> Result<types::GetRecordsOutput, ServiceError> {
        let Some(it) = Iterator::decode(&input.shard_iterator) else {
            return Err(invalid_argument("Invalid ShardIterator."));
        };
        if let Some(arn) = &input.stream_arn {
            if arn != &it.stream_arn {
                return Err(invalid_argument(format!(
                    "StreamARN {arn} does not match the stream of the shard iterator."
                )));
            }
        }
        let r = StreamRef::from_arn(&it.stream_arn)?;
        let now = now_ms(ctx);
        let data_key = {
            let mut st = self.settled(ctx);
            authorize_stream(ctx, &st, "GetRecords", &r, ConditionContext::new())?;
            let s = usable(&mut st, &r)?;
            if s.created_at != it.stream_created {
                return Err(stream_not_found(&s.name, &s.account));
            }
            if it.issued + ITERATOR_TTL_MS < now {
                return Err(errors::expired_iterator(format!(
                    "Iterator expired. The iterator was created at time {} while right now it is {} which is further in the future than the tolerated delay of {ITERATOR_TTL_MS} milliseconds.",
                    time(it.issued).format("%a %b %d %H:%M:%S UTC %Y"),
                    time(now).format("%a %b %d %H:%M:%S UTC %Y"),
                )));
            }
            s.encrypted().then(|| s.data_key.clone())
        };
        if input.dry_run == Some(true) {
            return Err(dry_run());
        }
        if let Some(dk) = data_key {
            self.check_decrypt(ctx, &r.arn, &dk)?;
        }
        let st = self.lock();
        let s = r.get(&st)?;
        let Some(shard) = s.shards.iter().find(|sh| sh.index == it.shard) else {
            return Err(errors::resource_not_found(format!(
                "Shard {} in stream {} under account {} does not exist",
                shard_id(it.shard),
                s.name,
                s.account
            )));
        };
        let limit = input.limit.unwrap_or(10_000).clamp(1, 10_000) as usize;
        let read = read_from(s, shard, it.counter, limit, now);
        let next = match (read.end_of_closed_shard, shard.open()) {
            (true, false) => None,
            _ => Some(Iterator { counter: read.next_counter, issued: now, ..it.clone() }.encode()),
        };
        Ok(types::GetRecordsOutput {
            records: read.records,
            next_shard_iterator: next,
            millis_behind_latest: Some(read.millis_behind),
            child_shards: read.end_of_closed_shard.then(|| children(s, shard)),
        })
    }
}

/// What one read of a shard returned.
pub(crate) struct Read {
    pub records: Vec<types::Record>,
    pub next_counter: u64,
    pub millis_behind: i64,
    /// The read reached the end of a closed shard.
    pub end_of_closed_shard: bool,
}

pub(crate) fn wire_record(s: &Stream, sh: &Shard, r: &StoredRecord) -> types::Record {
    types::Record {
        sequence_number: sequence_number(s.created_at, sh.index, r.counter),
        approximate_arrival_timestamp: Some(time(r.arrival)),
        data: r.data.clone(),
        partition_key: Some(r.partition_key.clone()),
        encryption_type: s.encrypted().then(|| "KMS".to_string()),
    }
}

/// Read up to `limit` records of a shard from `counter` on.
pub(crate) fn read_from(s: &Stream, sh: &Shard, counter: u64, limit: usize, now: i64) -> Read {
    let start = sh.records.partition_point(|r| r.counter < counter);
    let mut out = Vec::new();
    let mut bytes = 0;
    let mut next = counter.max(sh.records.get(start).map_or(sh.next_counter, |r| r.counter));
    for r in &sh.records[start..] {
        if out.len() >= limit || (bytes > 0 && bytes + r.data.len() > MAX_GET_BYTES) {
            break;
        }
        bytes += r.data.len();
        out.push(wire_record(s, sh, r));
        next = r.counter + 1;
    }
    let rest = &sh.records[start + out.len()..];
    let millis_behind = rest.first().map_or(0, |r| (now - r.arrival).max(0));
    if rest.is_empty() {
        next = next.max(sh.next_counter);
    }
    Read { records: out, next_counter: next, millis_behind, end_of_closed_shard: !sh.open() && rest.is_empty() }
}

/// The shards a closed shard was split or merged into.
pub(crate) fn children(s: &Stream, sh: &Shard) -> Vec<types::ChildShard> {
    s.shards
        .iter()
        .filter(|c| c.parent == Some(sh.index) || c.adjacent_parent == Some(sh.index))
        .map(|c| types::ChildShard {
            shard_id: c.id(),
            parent_shards: c.parent.into_iter().chain(c.adjacent_parent).map(shard_id).collect(),
            hash_key_range: types::HashKeyRange {
                starting_hash_key: c.start_hash.to_string(),
                ending_hash_key: c.end_hash.to_string(),
            },
        })
        .collect()
}

/// The counter a reader starts at for an iterator type (or starting
/// position).
pub(crate) fn position(
    s: &Stream,
    sh: &Shard,
    kind: &str,
    sequence: Option<&str>,
    timestamp: Option<i64>,
) -> Result<u64, ServiceError> {
    let first = || sh.records.first().map_or(sh.next_counter, |r| r.counter);
    match kind {
        "TRIM_HORIZON" => Ok(first()),
        "LATEST" => Ok(sh.next_counter),
        "AT_TIMESTAMP" => {
            let Some(t) = timestamp else {
                return Err(invalid_argument(
                    "Must specify timestampInMillis parameter for iterator of type AT_TIMESTAMP. Current request has no timestamp parameter.",
                ));
            };
            Ok(sh.records.iter().find(|r| r.arrival >= t).map_or(sh.next_counter, |r| r.counter))
        }
        "AT_SEQUENCE_NUMBER" | "AFTER_SEQUENCE_NUMBER" => {
            let Some(seq) = sequence else {
                return Err(invalid_argument(format!(
                    "Must either specify (1) AT_SEQUENCE_NUMBER or AFTER_SEQUENCE_NUMBER and StartingSequenceNumber or (2) TRIM_HORIZON or LATEST and no StartingSequenceNumber. Request specified {kind} and no StartingSequenceNumber."
                )));
            };
            let Some((created, index, counter)) = parse_sequence_number(seq) else {
                return Err(invalid_argument(format!(
                    "StartingSequenceNumber {seq} used in GetShardIterator on shard {} in stream {} under account {} is invalid.",
                    sh.id(),
                    s.name,
                    s.account
                )));
            };
            if created != s.created_at || index != sh.index {
                return Err(invalid_argument(format!(
                    "Invalid StartingSequenceNumber. It encodes {}, while it was used in a call to a shard with {}",
                    shard_id(index),
                    sh.id()
                )));
            }
            if counter >= sh.next_counter {
                return Err(invalid_argument(format!(
                    "StartingSequenceNumber {seq} used in GetShardIterator on shard {} in stream {} under account {} is invalid because it did not come from this stream.",
                    sh.id(),
                    s.name,
                    s.account
                )));
            }
            Ok(if kind == "AT_SEQUENCE_NUMBER" { counter } else { counter + 1 })
        }
        other => Err(errors::validation(format!(
            "1 validation error detected: Value '{other}' at 'shardIteratorType' failed to satisfy constraint: Member must satisfy enum value set: [AFTER_SEQUENCE_NUMBER, AT_SEQUENCE_NUMBER, AT_TIMESTAMP, TRIM_HORIZON, LATEST]"
        ))),
    }
}

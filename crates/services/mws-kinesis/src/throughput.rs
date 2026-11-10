//! Per-shard throughput limits, as token buckets over wall time (AWS
//! measures them per real second, whatever the emulated clock says).
//!
//! Provisioned shards take 1 MiB/s or 1,000 records/s of writes and serve
//! 5 `GetRecords` calls/s and 2 MiB/s of shared-throughput reads. A bucket
//! holds one second of capacity. A record or read larger than what is left
//! is admitted only when the bucket is full, and puts it into debt, so a
//! 10 MiB `GetRecords` page holds the next reads of the shard off for about
//! five seconds, as on AWS.
//!
//! On-demand streams have a write capacity of the larger of 4 MiB/s
//! (4,000 records/s) and their warm throughput, shared equally by their
//! open shards; reads get twice the write capacity. That is an
//! approximation: AWS on-demand adds shards as traffic grows, MWS keeps the
//! shards and gives them that share.
//!
//! Enhanced fan-out (`SubscribeToShard`) is paced separately, at 2 MiB/s
//! per consumer and shard, and does not count against these limits.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::state::Stream;

const MIB: f64 = 1024.0 * 1024.0;
/// Writes per shard: bytes and records per second.
const WRITE_BYTES: f64 = MIB;
const WRITE_RECORDS: f64 = 1000.0;
/// Shared-throughput reads per shard: bytes and `GetRecords` calls per
/// second.
const READ_BYTES: f64 = 2.0 * MIB;
const READ_CALLS: f64 = 5.0;
/// An on-demand stream's write capacity before warm throughput, in MiB/s.
const ON_DEMAND_MIBPS: f64 = 4.0;
/// Enhanced fan-out: bytes per second per consumer and shard.
pub(crate) const FAN_OUT_BYTES: f64 = 2.0 * MIB;

#[derive(Debug, Clone)]
pub(crate) struct Bucket {
    level: f64,
    at: Instant,
}

impl Bucket {
    pub(crate) fn full(rate: f64) -> Self {
        Self { level: rate, at: Instant::now() }
    }

    /// Refill at `rate` per second, holding at most one second's worth.
    pub(crate) fn refill(&mut self, rate: f64) {
        let now = Instant::now();
        self.level = (self.level + now.duration_since(self.at).as_secs_f64() * rate).min(rate);
        self.at = now;
    }

    /// Whether `amount` fits now: what is left, or a full bucket for an
    /// amount larger than the bucket.
    fn fits(&self, amount: f64, rate: f64) -> bool {
        self.level >= amount.min(rate)
    }

    pub(crate) fn take(&mut self, amount: f64) {
        self.level -= amount;
    }

    /// How long until the bucket is out of debt.
    pub(crate) fn wait(&self, rate: f64) -> std::time::Duration {
        if self.level > 0.0 {
            std::time::Duration::ZERO
        } else {
            std::time::Duration::from_secs_f64(-self.level / rate + 0.001)
        }
    }

    pub(crate) fn level(&self) -> f64 {
        self.level
    }
}

/// The rates one shard of a stream gets.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    write_bytes: f64,
    write_records: f64,
    read_bytes: f64,
    read_calls: f64,
}

impl Limits {
    pub(crate) fn of(s: &Stream) -> Self {
        let base = Self {
            write_bytes: WRITE_BYTES,
            write_records: WRITE_RECORDS,
            read_bytes: READ_BYTES,
            read_calls: READ_CALLS,
        };
        if s.mode != "ON_DEMAND" {
            return base;
        }
        let open = s.open_shards().count().max(1) as f64;
        let mibps = ON_DEMAND_MIBPS.max(f64::from(s.warm_throughput_mibps.unwrap_or(0)));
        let factor = (mibps / open).max(1.0);
        Self {
            write_bytes: base.write_bytes * factor,
            write_records: base.write_records * factor,
            read_bytes: base.read_bytes * factor,
            read_calls: base.read_calls,
        }
    }
}

#[derive(Debug, Clone)]
struct ShardBuckets {
    write_bytes: Bucket,
    write_records: Bucket,
    read_bytes: Bucket,
    read_calls: Bucket,
}

impl ShardBuckets {
    fn new(l: &Limits) -> Self {
        Self {
            write_bytes: Bucket::full(l.write_bytes),
            write_records: Bucket::full(l.write_records),
            read_bytes: Bucket::full(l.read_bytes),
            read_calls: Bucket::full(l.read_calls),
        }
    }
}

/// A shard by stream ARN, stream creation time and shard index (a stream
/// created again under the same name starts afresh).
pub(crate) type ShardKey = (String, i64, u32);

pub(crate) fn key(s: &Stream, index: u32) -> ShardKey {
    (s.arn.clone(), s.created_at, index)
}

/// Every shard's buckets. Not persisted: they describe the last second.
#[derive(Clone, Default)]
pub(crate) struct Throughput(Arc<Mutex<HashMap<ShardKey, ShardBuckets>>>);

impl Throughput {
    fn with<T>(&self, k: &ShardKey, l: &Limits, f: impl FnOnce(&mut ShardBuckets) -> T) -> T {
        let mut map = self.0.lock().expect("Kinesis throughput lock poisoned");
        let b = map.entry(k.clone()).or_insert_with(|| ShardBuckets::new(l));
        b.write_bytes.refill(l.write_bytes);
        b.write_records.refill(l.write_records);
        b.read_bytes.refill(l.read_bytes);
        b.read_calls.refill(l.read_calls);
        f(b)
    }

    /// Admit one record of `bytes` (data and partition key) to a shard,
    /// taking its share of the shard's write capacity.
    pub(crate) fn admit_write(&self, k: &ShardKey, l: &Limits, bytes: usize) -> bool {
        let bytes = bytes as f64;
        self.with(k, l, |b| {
            let ok = b.write_records.fits(1.0, l.write_records) && b.write_bytes.fits(bytes, l.write_bytes);
            if ok {
                b.write_records.take(1.0);
                b.write_bytes.take(bytes);
            }
            ok
        })
    }

    /// Admit a `GetRecords` call: one of the shard's calls this second,
    /// and read bytes left.
    pub(crate) fn admit_read(&self, k: &ShardKey, l: &Limits) -> bool {
        self.with(k, l, |b| {
            let ok = b.read_calls.fits(1.0, l.read_calls) && b.read_bytes.level() > 0.0;
            if ok {
                b.read_calls.take(1.0);
            }
            ok
        })
    }

    /// Charge the bytes an admitted `GetRecords` call returned.
    pub(crate) fn charge_read(&self, k: &ShardKey, l: &Limits, bytes: usize) {
        self.with(k, l, |b| b.read_bytes.take(bytes as f64));
    }

    pub(crate) fn clear(&self) {
        self.0.lock().expect("Kinesis throughput lock poisoned").clear();
    }
}

/// AWS's message for a throttled shard.
pub(crate) fn rate_exceeded(s: &Stream, shard: &str) -> String {
    format!("Rate exceeded for shard {shard} in stream {} under account {}.", s.name, s.account)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stream(mode: &str) -> Stream {
        let mut s = Stream { arn: "arn".into(), mode: mode.into(), ..Default::default() };
        s.shards = (0..4).map(|i| crate::state::Shard { index: i, ..Default::default() }).collect();
        s
    }

    #[test]
    fn writes_stop_at_a_thousand_records() {
        let t = Throughput::default();
        let s = stream("PROVISIONED");
        let l = Limits::of(&s);
        let k = key(&s, 0);
        let admitted = (0..1500).filter(|_| t.admit_write(&k, &l, 10)).count();
        assert!((1000..1010).contains(&admitted), "{admitted}");
    }

    #[test]
    fn writes_stop_at_a_mebibyte() {
        let t = Throughput::default();
        let s = stream("PROVISIONED");
        let l = Limits::of(&s);
        let k = key(&s, 0);
        let admitted = (0..20).filter(|_| t.admit_write(&k, &l, 100 * 1024)).count();
        assert_eq!(admitted, 10);
    }

    #[test]
    fn a_large_read_holds_off_later_reads() {
        let t = Throughput::default();
        let s = stream("PROVISIONED");
        let l = Limits::of(&s);
        let k = key(&s, 0);
        assert!(t.admit_read(&k, &l));
        t.charge_read(&k, &l, 10 * 1024 * 1024);
        assert!(!t.admit_read(&k, &l));
    }

    #[test]
    fn five_reads_a_second() {
        let t = Throughput::default();
        let s = stream("PROVISIONED");
        let l = Limits::of(&s);
        let k = key(&s, 0);
        assert_eq!((0..8).filter(|_| t.admit_read(&k, &l)).count(), 5);
    }

    #[test]
    fn on_demand_shares_warm_throughput() {
        let mut s = stream("ON_DEMAND");
        assert_eq!(Limits::of(&s).write_bytes, MIB);
        s.warm_throughput_mibps = Some(40);
        assert_eq!(Limits::of(&s).write_bytes, 10.0 * MIB);
    }
}

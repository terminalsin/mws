//! Shards: hash key ranges, partition key hashing, sequence numbers,
//! shard iterators and resharding.

use base64::Engine;
use md5::{Digest, Md5};

use crate::state::{Shard, Stream};

/// The largest hash key, 2^128 - 1.
pub const MAX_HASH: u128 = u128::MAX;

/// The MD5 of a partition key as an unsigned 128-bit big-endian integer,
/// which decides the shard.
pub fn hash_partition_key(key: &str) -> u128 {
    let digest = Md5::digest(key.as_bytes());
    u128::from_be_bytes(digest.into())
}

/// `n` ranges that split the hash key space evenly, as Kinesis assigns
/// them to a new stream's shards.
pub fn uniform_ranges(n: u32) -> Vec<(u128, u128)> {
    let n = u128::from(n.max(1));
    if n == 1 {
        return vec![(0, MAX_HASH)];
    }
    // floor(2^128 / n), computed without overflowing.
    let step = MAX_HASH / n + u128::from(MAX_HASH % n == n - 1);
    (0..n)
        .map(|i| {
            let start = step * i;
            let end = if i == n - 1 { MAX_HASH } else { step * (i + 1) - 1 };
            (start, end)
        })
        .collect()
}

pub fn new_shard(stream: &mut Stream, start: u128, end: u128, now: i64) -> u32 {
    let index = stream.next_shard_index;
    stream.next_shard_index += 1;
    stream.shards.push(Shard {
        index,
        parent: None,
        adjacent_parent: None,
        start_hash: start,
        end_hash: end,
        created_at: now,
        closed_at: None,
        next_counter: 1,
        records: Vec::new(),
    });
    index
}

/// Replace the open shards with `target` evenly sized ones. Each new shard
/// names the open shards its range came from as parents.
pub fn rescale(stream: &mut Stream, target: i32, now: i64) {
    let old: Vec<(u32, u128, u128)> = stream.open_shards().map(|s| (s.index, s.start_hash, s.end_hash)).collect();
    for s in stream.shards.iter_mut().filter(|s| s.open()) {
        s.closed_at = Some(now);
    }
    for (start, end) in uniform_ranges(target.max(1) as u32) {
        let overlapping: Vec<u32> =
            old.iter().filter(|(_, s, e)| *s <= end && start <= *e).map(|(i, _, _)| *i).collect();
        let index = new_shard(stream, start, end, now);
        let shard = stream.shards.iter_mut().find(|s| s.index == index).expect("just added");
        shard.parent = overlapping.first().copied();
        shard.adjacent_parent = overlapping.get(1).copied();
    }
}

// Sequence numbers: 56 decimal digits, "49" + the stream's creation time
// in milliseconds (15 digits) + the shard index (6) + the record's counter
// within the shard (33). They increase within a shard, and name the shard
// and stream they belong to.

pub fn sequence_number(stream_created: i64, shard: u32, counter: u64) -> String {
    format!("49{stream_created:015}{shard:06}{counter:033}")
}

/// `(stream creation millis, shard index, counter)`.
pub fn parse_sequence_number(s: &str) -> Option<(i64, u32, u64)> {
    if s.len() != 56 || !s.bytes().all(|b| b.is_ascii_digit()) || !s.starts_with("49") {
        return None;
    }
    Some((s[2..17].parse().ok()?, s[17..23].parse().ok()?, s[23..].parse().ok()?))
}

/// A shard iterator: where to read next in which shard, and when it was
/// issued (iterators expire after five minutes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Iterator {
    pub stream_arn: String,
    pub stream_created: i64,
    pub shard: u32,
    pub counter: u64,
    pub issued: i64,
}

const ITERATOR_PREFIX: &str = "AAAAAAAAAAE";

impl Iterator {
    pub fn encode(&self) -> String {
        let raw =
            format!("{}|{}|{}|{}|{}", self.stream_arn, self.stream_created, self.shard, self.counter, self.issued);
        format!("{ITERATOR_PREFIX}{}", base64::engine::general_purpose::STANDARD.encode(raw))
    }

    pub fn decode(s: &str) -> Option<Self> {
        let raw = base64::engine::general_purpose::STANDARD.decode(s.strip_prefix(ITERATOR_PREFIX)?).ok()?;
        let raw = String::from_utf8(raw).ok()?;
        let mut parts = raw.rsplitn(5, '|');
        let issued = parts.next()?.parse().ok()?;
        let counter = parts.next()?.parse().ok()?;
        let shard = parts.next()?.parse().ok()?;
        let stream_created = parts.next()?.parse().ok()?;
        let stream_arn = parts.next()?.to_string();
        Some(Self { stream_arn, stream_created, shard, counter, issued })
    }
}

/// Iterators are valid this long, in milliseconds.
pub const ITERATOR_TTL_MS: i64 = 300_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_match_kinesis() {
        assert_eq!(uniform_ranges(1), vec![(0, MAX_HASH)]);
        let two = uniform_ranges(2);
        assert_eq!(two[0], (0, 170141183460469231731687303715884105727));
        assert_eq!(two[1], (170141183460469231731687303715884105728, MAX_HASH));
        let four = uniform_ranges(4);
        assert_eq!(four[1].0, 85070591730234615865843651857942052864);
        assert_eq!(four[3].1, MAX_HASH);
        let three = uniform_ranges(3);
        assert_eq!(three[0].1 + 1, three[1].0);
        assert_eq!(three[1].1 + 1, three[2].0);
    }

    #[test]
    fn partition_keys_hash_like_md5() {
        // md5("a") = 0cc175b9c0f1b6a831c399e269772661
        assert_eq!(hash_partition_key("a"), 0x0cc175b9c0f1b6a831c399e269772661);
    }

    #[test]
    fn sequence_numbers_round_trip_and_order() {
        let a = sequence_number(1_700_000_000_000, 3, 9);
        let b = sequence_number(1_700_000_000_000, 3, 10);
        assert_eq!(a.len(), 56);
        assert!(a < b);
        assert_eq!(parse_sequence_number(&a), Some((1_700_000_000_000, 3, 9)));
        assert_eq!(parse_sequence_number("123"), None);
    }

    #[test]
    fn iterators_round_trip() {
        let it = Iterator {
            stream_arn: "arn:aws:kinesis:us-east-1:123456789012:stream/a|b".into(),
            stream_created: 5,
            shard: 2,
            counter: 7,
            issued: 99,
        };
        assert_eq!(Iterator::decode(&it.encode()), Some(it));
        assert_eq!(Iterator::decode("garbage"), None);
    }
}

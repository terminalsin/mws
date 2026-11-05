# Amazon Kinesis Data Streams

> Crate: [`mws-kinesis`](../../crates/services/mws-kinesis) · Tests: [`tests/e2e-rust/tests/e2e/kinesis.rs`](../../tests/e2e-rust/tests/e2e/kinesis.rs)

All 45 operations are generated from the AWS model (awsJson1.1, event streams).

## Behaviour

Streams in provisioned or on-demand mode (4 shards by default) with real shards:
partition keys are MD5-hashed into hash key ranges (or `ExplicitHashKey`),
56-digit sequence numbers increase per shard, and `PutRecord`/`PutRecords` (with
`SequenceNumberForOrdering`, size and batch limits) store records that
`GetShardIterator` (`AT_SEQUENCE_NUMBER`, `AFTER_SEQUENCE_NUMBER`,
`TRIM_HORIZON`, `LATEST`, `AT_TIMESTAMP`; iterators expire after five minutes)
and `GetRecords` read back with `MillisBehindLatest`.

`CREATING`/`UPDATING`/`DELETING` transitions on the emulated clock, retention
(24 hours to 365 days) trims old records, resharding (`SplitShard`,
`MergeShards`, `UpdateShardCount`, mode changes) closes parents and reports
`ChildShards`, `ListShards` with every `ShardFilter` and pagination. Enhanced
fan-out consumers and `SubscribeToShard` push records over a real event stream.
Server-side encryption with KMS keys (data keys from MWS KMS, so producers need
`kms:GenerateDataKey` and consumers `kms:Decrypt`), resource policies on streams
and consumers evaluated by the IAM engine for cross-account access, tags with
`aws:ResourceTag` conditions, enhanced monitoring, warm throughput, maximum
record size, account limits and settings, and channels (stored).

Other services read and write streams as their role: Firehose sources, Lambda
event source mappings, CloudWatch Logs subscriptions and EventBridge targets.

See also: [all services](README.md) · [authentication and authorization](../security.md).

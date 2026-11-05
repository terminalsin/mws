# Amazon Kinesis Data Streams

> Crate: [`mws-kinesis`](../../crates/services/mws-kinesis) · Tests: [`tests/e2e-rust/tests/e2e/kinesis.rs`](../../tests/e2e-rust/tests/e2e/kinesis.rs)

All 45 operations are generated from the AWS model (awsJson1.1, event streams) and implemented. Shards hold real records.

✅ supported · 🟡 partial · ❌ not supported

| Feature | Status | Details |
| --- | :---: | --- |
| Streams | ✅ | Provisioned or on-demand mode (4 shards by default), `CREATING`/`UPDATING`/`DELETING` transitions on the emulated clock. |
| Records | ✅ | Partition keys MD5-hashed into hash key ranges (or `ExplicitHashKey`), 56-digit sequence numbers per shard, `PutRecord`/`PutRecords` with `SequenceNumberForOrdering`, size and batch limits. |
| Reading | ✅ | `GetShardIterator` (`AT_SEQUENCE_NUMBER`, `AFTER_SEQUENCE_NUMBER`, `TRIM_HORIZON`, `LATEST`, `AT_TIMESTAMP`; iterators expire after five minutes) and `GetRecords` with `MillisBehindLatest`. |
| Retention | ✅ | 24 hours to 365 days; old records are trimmed. |
| Resharding | ✅ | `SplitShard`, `MergeShards`, `UpdateShardCount` and mode changes close parents and report `ChildShards`; `ListShards` with every `ShardFilter`. |
| Enhanced fan-out | ✅ | Consumers and `SubscribeToShard` pushing records over a real event stream. |
| Encryption | ✅ | Server-side encryption with KMS keys: producers need `kms:GenerateDataKey`, consumers `kms:Decrypt`. |
| Resource policies | ✅ | On streams and consumers, evaluated by the IAM engine for cross-account access; tags with `aws:ResourceTag` conditions. |
| CloudWatch metrics | ✅ | Published in `AWS/Kinesis`; enhanced monitoring settings. |
| Other settings | ✅ | Warm throughput, maximum record size, account limits and settings. |
| Channels | 🟡 | Stored only. |
| Integrations | ✅ | Firehose sources, Lambda event source mappings, CloudWatch Logs subscriptions and EventBridge targets read and write streams as their role. |

See also: [all services](README.md) · [authentication and authorization](../security.md).

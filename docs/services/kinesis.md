# Amazon Kinesis Data Streams

> Crate: [`mws-kinesis`](../../crates/services/mws-kinesis) · Tests: [`tests/e2e-rust/tests/e2e/kinesis.rs`](../../tests/e2e-rust/tests/e2e/kinesis.rs)

All 45 operations are generated from the AWS model (awsJson1.1, event streams) and implemented. Shards hold real records.

✅ supported · 🟡 partial · ❌ not supported

| Feature | Status | Details |
| --- | :---: | --- |
| Streams | ✅ | Provisioned or on-demand mode (4 shards by default), `CREATING`/`UPDATING`/`DELETING` transitions on the emulated clock. |
| Records | ✅ | Partition keys MD5-hashed into hash key ranges (or `ExplicitHashKey`), 56-digit sequence numbers per shard, `PutRecord`/`PutRecords` with `SequenceNumberForOrdering`, size and batch limits. |
| Reading | ✅ | `GetShardIterator` (`AT_SEQUENCE_NUMBER`, `AFTER_SEQUENCE_NUMBER`, `TRIM_HORIZON`, `LATEST`, `AT_TIMESTAMP`; iterators expire after five minutes) and `GetRecords` with `MillisBehindLatest`. |
| Throughput limits | ✅ | Per shard, over wall time (AWS counts real seconds, so moving the emulated clock does not refill them): writes take 1 MiB/s or 1,000 records/s (data plus partition key); above that `PutRecord` fails with `ProvisionedThroughputExceededException` ("Rate exceeded for shard shardId-… in stream … under account …."), and `PutRecords` fails just those records with that `ErrorCode`/`ErrorMessage` and counts them in `FailedRecordCount`. Shared-throughput reads take 5 `GetRecords` calls/s and 2 MiB/s; a large page (up to 10 MiB) holds the shard's next reads off until the bytes are paid back, as on AWS. Enhanced fan-out is paced at 2 MiB/s per consumer and shard, apart from these. `WriteProvisionedThroughputExceeded`, `ReadProvisionedThroughputExceeded` and `PutRecords.ThrottledRecords` count the throttles. Firehose, Lambda event source mappings and the other integrations are throttled like any consumer and retry on their next poll. |
| On-demand capacity | 🟡 | An approximation: AWS adds shards as on-demand traffic grows; MWS keeps the 4 shards and gives each an equal share of a write capacity of the larger of 4 MiB/s (4,000 records/s) and the stream's warm throughput, with twice that for reads. |
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

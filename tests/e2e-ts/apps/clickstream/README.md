# clickstream

Click events from a website, streamed through Kinesis and archived in S3.

- [`src/producer.ts`](src/producer.ts) batches events with `PutRecords`,
  partitioned by session, retrying only the failed entries.
- [`src/consumer.ts`](src/consumer.ts) reads every shard from `TRIM_HORIZON`
  until it catches up.
- [`src/infrastructure.ts`](src/infrastructure.ts) creates a two-shard stream,
  the data lake bucket, the role Firehose works as, and a delivery stream that
  reads the Kinesis stream and writes GZIP batches under
  `clicks/year=.../month=.../day=.../`.

The tests check that each session's clicks stay on one shard in order, then
move MWS's emulated clock past Firehose's 60 second buffer interval
(`POST /_mws/clock`) and read the delivered objects back from S3.

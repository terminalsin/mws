# Amazon Data Firehose

> Crate: [`mws-firehose`](../../crates/services/mws-firehose) · Tests: [`tests/e2e-rust/tests/e2e/firehose.rs`](../../tests/e2e-rust/tests/e2e/firehose.rs)

All 12 operations are generated from the AWS model (awsJson1.1).

## Behaviour

Delivery streams (`DirectPut` or reading a Kinesis data stream with the source
role, which `CreateDeliveryStream` checks) go `CREATING` to `ACTIVE`, keep
versions (`UpdateDestination` needs the current one), encryption
(`AWS_OWNED_CMK` or `CUSTOMER_MANAGED_CMK` through KMS) and tags. Records are
buffered and delivered when the destination's buffering hints say so, on the
emulated clock, as the delivery role: Amazon S3 (objects named
`<stream>-<version>-<time>-<uuid>` under `YYYY/MM/DD/HH/` or a custom prefix
with `!{timestamp:..}`, `!{firehose:..}` and dynamic partitioning keys; GZIP,
ZIP, Snappy and Hadoop Snappy; SSE-KMS; source record backup; failures as JSON
lines under the error prefix), HTTPS endpoints (Firehose's request format,
access key and common attribute headers, GZIP content encoding) and Splunk HEC,
retried for the retry duration and then backed up to S3, OpenSearch and
Elasticsearch (and Serverless) clusters with an endpoint through `_bulk`, and
Redshift as its intermediate S3 objects.

Processors run in Firehose's order: Lambda (the function gets Firehose's
transformation event, with Kinesis metadata, and
`Ok`/`Dropped`/`ProcessingFailed` results apply), decompression and CloudWatch
Logs message extraction, record de-aggregation, JQ metadata extraction for
dynamic partitioning, and delimiters.

## Known gaps

Snowflake, Iceberg and OpenSearch domains named only by ARN (their records go to
the S3 backup), MSK and database sources (stored), and format conversion to
Parquet/ORC.

See also: [all services](README.md) · [authentication and authorization](../security.md).

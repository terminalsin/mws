# Amazon Data Firehose

> Crate: [`mws-firehose`](../../crates/services/mws-firehose) · Tests: [`tests/e2e-rust/tests/e2e/firehose.rs`](../../tests/e2e-rust/tests/e2e/firehose.rs)

All 12 operations are generated from the AWS model (awsJson1.1) and implemented. Records are buffered and delivered on the emulated clock, as the delivery role.

✅ supported · 🟡 partial · ❌ not supported

## Delivery streams

| Feature | Status | Details |
| --- | :---: | --- |
| Sources | ✅ | `DirectPut`, or reading a Kinesis data stream with the source role, which `CreateDeliveryStream` checks. |
| MSK and database sources | ❌ | Stored only. |
| Lifecycle | ✅ | `CREATING` to `ACTIVE`; versions (`UpdateDestination` needs the current one); encryption with `AWS_OWNED_CMK` or `CUSTOMER_MANAGED_CMK`; tags. |
| Buffering | ✅ | Delivered when the destination's buffering hints say so. |
| CloudWatch metrics | ✅ | Published in `AWS/Firehose`. |

## Destinations

| Feature | Status | Details |
| --- | :---: | --- |
| Amazon S3 | ✅ | Objects named `<stream>-<version>-<time>-<uuid>` under `YYYY/MM/DD/HH/` or a custom prefix with `!{timestamp:..}`, `!{firehose:..}` and dynamic partitioning keys; GZIP, ZIP, Snappy and Hadoop Snappy; SSE-KMS; source record backup; failures under the error prefix. |
| HTTP endpoints and Splunk | ✅ | Firehose's request format, access key and attribute headers, GZIP content encoding; retried for the retry duration, then backed up to S3. |
| OpenSearch and Elasticsearch | 🟡 | Clusters and Serverless collections with an endpoint, through `_bulk`; domains named only by ARN go to the S3 backup. |
| Redshift | 🟡 | Written as its intermediate S3 objects. |
| Snowflake and Iceberg | ❌ | Records go to the S3 backup. |
| Format conversion | ❌ | Conversion reads its schema from the AWS Glue Data Catalog, which MWS does not have, so records go to the `format-conversion-failed` error output with `DataFormatConversion.EntityNotFound`, as when the table is missing on AWS. |

## Processing

| Feature | Status | Details |
| --- | :---: | --- |
| Lambda | ✅ | The function gets Firehose's transformation event (with Kinesis metadata); `Ok`, `Dropped` and `ProcessingFailed` results apply. Each invocation carries at most the processor's `BufferSizeInMBs` of data (0.2 to 3 MB; 1 MB by default, 256 KB for Splunk) and stays within Lambda's 6 MB request limit. Failed invocations (invoke errors, function errors, malformed responses) are retried `NumberOfRetries` times (3 by default), then the records go to the `processing-failed` error output with `errorCode`, `errorMessage`, `attemptsMade` and `lambdaArn`. `ExecuteProcessing.Duration` (per invocation), `ExecuteProcessing.Success` (successful over all invocations) and `SucceedProcessing.Records`/`Bytes` are published. |
| Processor buffering | 🟡 | One buffer per destination: with a Lambda processor, the buffer is due after the longer of the destination's interval and the processor's `BufferIntervalInSeconds` (60 s by default), or when the destination's size is reached, and is then cut into invocations by the processor's size. AWS buffers for the processor first and then for the destination, so with large volumes its invocations start earlier. |
| Built-in processors | ✅ | Decompression, CloudWatch Logs message extraction, record de-aggregation, JQ metadata extraction for dynamic partitioning, and delimiters, in Firehose's order. |

See also: [all services](README.md) · [authentication and authorization](../security.md).

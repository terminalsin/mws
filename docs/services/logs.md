# Amazon CloudWatch Logs

> Crate: [`mws-logs`](../../crates/services/mws-logs) · Tests: [`tests/e2e-rust/tests/e2e/logs.rs`](../../tests/e2e-rust/tests/e2e/logs.rs)

All 118 operations are generated from the AWS model (awsJson1.1, event streams) and implemented.

✅ supported · 🟡 partial · ❌ not supported

## Log data

| Feature | Status | Details |
| --- | :---: | --- |
| Log groups and streams | ✅ | Classes, retention against event timestamps, deletion protection, bearer token setting, and KMS keys checked against their key policy. |
| `PutLogEvents` | ✅ | AWS's ordering, batch span and too-old, too-new and expired rules. |
| Reading | ✅ | `GetLogEvents` and `FilterLogEvents` with forward and backward tokens. |
| Filter patterns | ✅ | Terms, `?` alternatives, JSON `{ $.x > 1 }` and space-delimited `[a, b=5*]` patterns. |
| Live tail | ✅ | `StartLiveTail` keeps its event stream open and pushes matching events every second. |
| Transformers | ✅ | JSON, key-value, CSV, grok, date, string and key processors applied at ingestion; originals and transformed events are both kept; `TestTransformer`. |
| Data protection | ✅ | Policies mask events ingested after them at every way out: `GetLogEvents`, `FilterLogEvents`, Logs Insights, SQL and PPL results, live tail, subscription deliveries and export tasks. Unmasking (`unmask: true`, the Insights `unmask` command) needs `logs:Unmask`. Audit findings (`FindingsDestination`, `LogEventsWithFindings`) are not produced. |

## Queries

| Feature | Status | Details |
| --- | :---: | --- |
| Logs Insights | ✅ | `fields`, `filter`, `filterIndex`, `parse`, `stats` with `bin()`, `sort`, `limit`, `dedup`, `display`, `unmask`, `unnest`, `lookup`, `SOURCE logGroups(namePrefix, class, accountIdentifiers)`, `pattern`, `diff`, `anomaly`, `@ptr`, `GetLogRecord`, query definitions and field discovery. `now()` is the query's time on the emulated clock. |
| Query lifecycle | ✅ | `StartQuery` returns at once; the query is `Scheduled`, then `Running`, then `Complete` about 0.6 s of real time later, over the events as they were when it started. `StopQuery` cancels a scheduled or running query (`Cancelled`). 30 concurrent queries per account and Region (`LimitExceededException`), and a 60-minute timeout on the emulated clock (`Timeout`). Results are not streamed while running. |
| `pattern`, `diff`, `anomaly` | 🟡 | `pattern` clusters values by whitespace tokens, the varying ones (with digits, or long hex ids) as `<*>`, and returns `@pattern`, `@ratio`, `@sampleCount`, `@severityLabel` (from a level word: `ERROR`, `WARN`, `INFO`, `DEBUG`, `TRACE`, `FATAL`, else `UNKNOWN`) and `@visualization` (counts in ten slices of the window, as JSON). `diff [previousDay\|previousWeek\|previousMonth]` adds `@previousSampleCount`, `@changeInSampleCount` and `@diffType` (`NEW`, `EXISTING`, `REMOVED`). `anomaly` keeps patterns whose busiest slice is more than two standard deviations above their mean, with `@description` and `@priority`. AWS's machine-learned clustering and token names are not reproduced; MWS chose these output names where AWS's exact ones are not documented. |
| OpenSearch SQL | ✅ | `SELECT` from log groups with `WHERE`, `GROUP BY`, `HAVING`, `ORDER BY`, `LIMIT` and `DISTINCT`. |
| SQL joins and subqueries | ✅ | `[INNER] JOIN`, `LEFT`/`RIGHT [OUTER] JOIN`, `CROSS JOIN` and comma joins across log groups and subqueries, with aliases (`alias.field`); uncorrelated subqueries in `FROM`, `IN (...)`, `EXISTS (...)` and scalar positions. `FULL OUTER JOIN` and correlated subqueries are not supported. |
| OpenSearch PPL | ✅ | `fields`, `where`, `eval`, `stats ... by` with `span()`, `sort`, `head`, `rename`, `dedup`, `top`, `rare`, `parse`, `fillnull`. |
| Scheduled queries | ✅ | Run on the emulated clock as their execution role, write results to S3 and refresh lookup tables. |
| Field indexes | ✅ | Field index policies and `DescribeFieldIndexes`. |

## Delivery

| Feature | Status | Details |
| --- | :---: | --- |
| Subscriptions to Lambda | ✅ | Gzipped, base64 `awslogs` payloads; the function policy must let `logs.amazonaws.com` invoke it. |
| Subscriptions to Kinesis and Firehose | ✅ | Directly or through a destination in any account, as the filter's role, with a `CONTROL_MESSAGE` test record first. `PutSubscriptionFilter` and `PutDestination` need `iam:PassRole` on the role (`iam:PassedToService` = `logs.amazonaws.com`). |
| Metric filters | ✅ | Publish into MWS CloudWatch (`$.field` values, dimensions, units, `defaultValue`); `TestMetricFilter`. |
| `AWS/Logs` metrics | 🟡 | `IncomingBytes` and `IncomingLogEvents` per `LogGroupName` and for the account; `ForwardedBytes` (compressed) and `ForwardedLogEvents` per subscription filter (`LogGroupName`, `DestinationType`, `FilterName`). `DeliveryErrors` and `DeliveryThrottling` count failed and throttled deliveries to Lambda, Kinesis and Firehose (and deliveries to a Logs destination that is gone); failed deliveries are not retried. `LogEventsWithFindings` is not published. |
| Export tasks | ✅ | The bucket is checked when the task is created; the task is `PENDING`, then `RUNNING`, then `COMPLETED` (or `FAILED`) about half a second later, writing gzipped, masked events to S3 as `logs.<region>.amazonaws.com`. `CancelExportTask` works while pending or running; one active task per account and Region (`LimitExceededException: Resource limit exceeded.`). |
| Vended log deliveries | 🟡 | Sources, destinations and deliveries are managed, but no MWS service is a vended log source yet. |
| Imports | ✅ | `CreateImportTask` copies a CloudTrail Lake event data store (which must be `ENABLED`) into the managed log group `/aws/cloudtrail/<store id>`, streams `<account>_CloudTrail_<region>`, one batch per hour of `eventTime`, in the background. The caller needs `iam:PassRole` and `cloudtrail:GetEventDataStoreData`; the role must trust `cloudtrail.amazonaws.com` and allow `cloudtrail:GetEventDataStoreData`, `logs:CreateLogGroup` and `logs:CreateLogStream`. At most 3 imports in progress. KMS-encrypted stores are not decrypted through the role. |

## Access and other features

| Feature | Status | Details |
| --- | :---: | --- |
| Resource and account policies | ✅ | Account-wide and per log group, with revision ids, evaluated by the IAM engine. |
| Destinations | ✅ | With cross-account access policies. |
| Writers | ✅ | Lambda logs to `/aws/lambda/<name>` as its execution role; Route 53 query logging writes through the log group's resource policy. |
| Anomaly detectors, integrations, lookup tables | 🟡 | Anomaly detectors and integrations are stored and described only; lookup tables are read by the Insights `lookup` command. |

See also: [all services](README.md) · [authentication and authorization](../security.md).

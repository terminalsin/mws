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
| Data protection | ✅ | Policies mask events ingested after them unless the caller may `logs:Unmask`. |

## Queries

| Feature | Status | Details |
| --- | :---: | --- |
| Logs Insights | ✅ | `fields`, `filter`, `parse`, `stats` with `bin()`, `sort`, `limit`, `dedup`, `display`, `@ptr`, `GetLogRecord`, query definitions and field discovery. |
| OpenSearch SQL | ✅ | `SELECT` from log groups with `WHERE`, `GROUP BY`, `HAVING`, `ORDER BY`, `LIMIT` and `DISTINCT`. |
| SQL joins and subqueries | ❌ | Not yet. |
| OpenSearch PPL | ✅ | `fields`, `where`, `eval`, `stats ... by` with `span()`, `sort`, `head`, `rename`, `dedup`, `top`, `rare`, `parse`, `fillnull`. |
| Scheduled queries | ✅ | Run on the emulated clock as their execution role, write results to S3 and refresh lookup tables. |
| Field indexes | ✅ | Field index policies and `DescribeFieldIndexes`. |

## Delivery

| Feature | Status | Details |
| --- | :---: | --- |
| Subscriptions to Lambda | ✅ | Gzipped, base64 `awslogs` payloads; the function policy must let `logs.amazonaws.com` invoke it. |
| Subscriptions to Kinesis and Firehose | ✅ | Directly or through a destination in any account, as the filter's role, with a `CONTROL_MESSAGE` test record first. |
| Metric filters | ✅ | Publish into MWS CloudWatch (`$.field` values, dimensions, units, `defaultValue`); `TestMetricFilter`. |
| Export tasks | ✅ | Gzipped events written to S3, judged by the bucket policy. |
| Vended log deliveries | 🟡 | Sources, destinations and deliveries are managed, but no MWS service is a vended log source yet. |
| Imports | ❌ | No CloudTrail Lake. |

## Access and other features

| Feature | Status | Details |
| --- | :---: | --- |
| Resource and account policies | ✅ | Account-wide and per log group, with revision ids, evaluated by the IAM engine. |
| Destinations | ✅ | With cross-account access policies. |
| Writers | ✅ | Lambda logs to `/aws/lambda/<name>` as its execution role; Route 53 query logging writes through the log group's resource policy. |
| Anomaly detectors, integrations, lookup tables | 🟡 | Stored and described only. |

See also: [all services](README.md) · [authentication and authorization](../security.md).

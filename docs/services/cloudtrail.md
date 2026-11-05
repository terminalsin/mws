# AWS CloudTrail

> Crates: [`mws-cloudtrail`](../../crates/services/mws-cloudtrail), [`mws-cloudtrail-data`](../../crates/services/mws-cloudtrail-data) · Tests: [`cloudtrail.rs`](../../tests/e2e-rust/tests/e2e/cloudtrail.rs), [`cloudtrail_parity.rs`](../../tests/e2e-rust/tests/e2e/cloudtrail_parity.rs)

All 60 CloudTrail operations (awsJson1.1) and the CloudTrail Data service's `PutAuditEvents` (restJson1) are generated from the AWS models and implemented. CloudTrail sees every API call the gateway dispatches to every MWS service and records it the way AWS does.

✅ supported · 🟡 partial · ❌ not supported

## Recording

| Feature | Status | Details |
| --- | :---: | --- |
| Every API call | ✅ | Each service's generated dispatcher renders the call's request parameters and response elements as CloudTrail does: lowerCamelCase names, `@sensitive` members shown as `HIDDEN_DUE_TO_SECURITY_REASONS`, payloads left out. Failed calls carry `errorCode` and `errorMessage`. |
| Records | ✅ | `eventVersion` 1.11 with the caller's `userIdentity` (root, IAM user, assumed role with its session context, AWS service), source IP, user agent, `readOnly`, `managementEvent`, `eventCategory`, `resources` and `recipientAccountId`. |
| Management and data events | ✅ | S3 object operations, Lambda `Invoke`, SQS, SNS `Publish`, Kinesis records, Firehose, EventBridge `PutEvents`, CloudWatch Logs events and metrics are data events; the rest are management events. |
| Global services | ✅ | IAM, STS's global endpoint, Organizations, Route 53 and other global services are recorded in `us-east-1`. |
| Event history | ✅ | `LookupEvents` over 90 days of management events per account and Region: every lookup attribute, time range, newest first, paging. |
| Network activity and console sign-in events | ❌ | MWS has no console to sign in to and no VPC endpoint traffic to observe, so these events never occur. |

## Trails

| Feature | Status | Details |
| --- | :---: | --- |
| Trail operations | ✅ | Create, update, delete, describe, list, tags, start/stop logging and status; single- and multi-Region trails, global service events. |
| Organization trails | ✅ | Created by the management account (or a delegated administrator) and log every member account. |
| Event selectors | ✅ | Basic (read/write type, management events, excluded sources, data resources) and advanced field selectors with every operator, validated with AWS's messages. |
| S3 log files | ✅ | Gzipped JSON under `AWSLogs/<account>/CloudTrail/<region>/yyyy/mm/dd/`, written as `cloudtrail.amazonaws.com` so the bucket policy applies; SSE-KMS with the trail's key. |
| Log file validation | ✅ | Digest files chained by `previousDigestSignature` and signed with RSA-2048 SHA-256; `ListPublicKeys` returns the keys. |
| SNS notifications | ✅ | One per log file, published as CloudTrail, so the topic policy applies. |
| CloudWatch Logs | ✅ | Each record written to `<account>_CloudTrail_<region>` as the trail's role. |
| EventBridge | ✅ | "AWS API Call via CloudTrail" events for write management events while a trail is logging, and for the data events a trail logs. |
| Insights | ✅ | With `ApiCallRateInsight` or `ApiErrorRateInsight` selected, write management calls and failed management calls (per error code) are counted per minute. A minute above the baseline (mean of the earlier minutes since counting began, up to 7 days, plus three standard deviations) with at least 10 calls logs a `Start` Insights event, and the first normal minute logs its `End`. Events go to `CloudTrail-Insight` log files, `LookupEvents` (`EventCategory=insight`), `ListInsightsData`, event data stores' Insights destinations and EventBridge ("AWS Insight via CloudTrail"). `ListInsightsMetricData` counts from the event history. AWS's own baseline model is not public, and AWS waits up to 36 hours before the first Insights; MWS starts after one minute of baseline. |

## CloudTrail Lake

| Feature | Status | Details |
| --- | :---: | --- |
| Event data stores | ✅ | Create, update, delete (7 days pending deletion), restore, start/stop ingestion, retention, termination protection, organization stores, KMS keys, event configuration. |
| Queries | ✅ | `StartQuery` runs SQL over the stores' events: a Trino subset with projections, `WHERE`, `GROUP BY`, aggregates, `ORDER BY`, `LIMIT`, `element_at` and nested fields. Results, statistics, `ListQueries` and delivery to S3. Queries finish as they start, so `CancelQuery` always reports the query inactive. |
| Imports | ✅ | Trail log files read back from S3 as the import's role into event data stores. |
| Channels | ✅ | Kept and validated. CloudTrail Data's `PutAuditEvents` checks the caller (identity policy, or the channel's resource policy across accounts, with `cloudtrail:ExternalId`), each event's schema and SHA-256 checksum, and stores the events in the channel's event data stores as `ActivityAuditLog` events. |
| Dashboards | ✅ | Kept and validated; refreshes run the widgets' queries. |
| Federation | 🟡 | Enabled and disabled with `iam:PassRole` checks; MWS has no AWS Glue or Athena, so no Data Catalog tables are created. |
| Resource policies, delegated administrators | ✅ | Kept and validated. |
| `GenerateQuery`, `SearchSampleQueries` | 🟡 | SQL is written from keywords in the prompt, not by a model; samples come from a small built-in catalogue. |

See also: [all services](README.md) · [authentication and authorization](../security.md).

# Amazon CloudWatch Logs

> Crate: [`mws-logs`](../../crates/services/mws-logs) · Tests: [`tests/e2e-rust/tests/e2e/logs.rs`](../../tests/e2e-rust/tests/e2e/logs.rs)

All 118 operations are generated from the AWS model (awsJson1.1, event streams).

## Behaviour

Implemented: log groups (classes, retention against event timestamps, deletion
protection, bearer token setting, KMS keys checked against their key policy for
`logs.<region>.amazonaws.com`) and streams, `PutLogEvents` with AWS's ordering,
batch span and too-old/too-new/expired rules, `GetLogEvents` and
`FilterLogEvents` with forward/backward tokens and the full filter pattern
syntax (terms, `?` alternatives, JSON `{ $.x > 1 }` and space-delimited `[a,
b=5*]` patterns), live tail (`StartLiveTail` keeps its event stream open and
pushes matching events every second), CloudWatch Logs Insights queries
(`fields`, `filter`, `parse` glob and regex, `stats` with the aggregate
functions and `bin()`, `sort`, `limit`, `dedup`, `display`, `@ptr`,
`GetLogRecord`, `GetLogObject`, query definitions, field discovery), OpenSearch
SQL (`SELECT ... FROM \`log group\`` or `` `logGroups(logGroupIdentifier:
[...])` ``, `WHERE` with `LIKE`/`IN`/`BETWEEN`/`IS NULL`, `GROUP BY`, `HAVING`,
`ORDER BY`, `LIMIT`, `DISTINCT`) and OpenSearch PPL (`fields`, `where`, `eval`,
`stats ... by` with `span()`, `sort`, `head`, `rename`, `dedup`, `top`, `rare`,
`parse`, `fillnull`) queries on the same engine, scheduled queries that run on
the emulated clock as their execution role (assumed by `logs.amazonaws.com`),
write their results as JSON to S3 and refresh lookup tables, with the runs in
`GetScheduledQueryHistory`, resource policies (account-wide and per log group,
with revision ids) that the IAM engine evaluates with `aws:ResourceTag`
conditions, account policies, data protection policies that mask events ingested
after them unless the caller may `logs:Unmask`, field index policies and
`DescribeFieldIndexes`, metric filters and subscription filters (patterns
checked, `TestMetricFilter` really matches and extracts), destinations with
cross-account access policies, transformers (`TestTransformer` runs the
processors: JSON, key-value, CSV, grok, date conversion, string and key
operations) that apply at ingestion (log group transformers or account
`TRANSFORMER_POLICY` policies): the original and transformed events are both
kept, `GetLogEvents` and `FilterLogEvents` return originals, Logs Insights
queries the transformed events, and subscription filters use them with
`applyOnTransformedLogs`, vended log delivery sources, destinations, destination
policies and deliveries, and export tasks that write gzipped events into S3 as
`logs.<region>.amazonaws.com`, judged by the bucket policy.

Subscription filters to Lambda functions deliver matching events as gzipped,
base64 `awslogs` payloads (`PutSubscriptionFilter` checks the function policy
lets `logs.amazonaws.com` invoke it). Other services write here as AWS does:
Lambda functions log to `/aws/lambda/<name>` as their execution role, and Route
53 query logging checks the log group's resource policy and the DNS responder
writes query logs. Stored and described only: anomaly detectors (no anomalies
are found), OpenSearch and S3 Tables integrations, lookup tables, syslog
configurations and the storage tier.

Subscription filters to Kinesis data streams and Firehose streams (directly or
through a destination, possibly in another account, whose target and role are
used) write the gzipped `DATA_MESSAGE` as the record, as the filter's role
assumed by `logs.amazonaws.com` (partition key: the log stream, or random with
`Distribution: Random`); `PutSubscriptionFilter` first writes the
`CONTROL_MESSAGE` test record and fails as AWS does when it cannot.

Metric filters publish their metrics into MWS CloudWatch (values from `$.field`
or `$field` selectors, dimensions, units and `defaultValue` for batches with no
match).

## Known gaps

Deliveries delivering (no MWS service is a vended log source yet), SQL joins and
subqueries, and imports (no CloudTrail Lake).

See also: [all services](README.md) · [authentication and authorization](../security.md).

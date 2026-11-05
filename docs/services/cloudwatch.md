# Amazon CloudWatch

> Crate: [`mws-cloudwatch`](../../crates/services/mws-cloudwatch) · Tests: [`tests/e2e-rust/tests/e2e/cloudwatch.rs`](../../tests/e2e-rust/tests/e2e/cloudwatch.rs)

All 55 operations are generated from the AWS model, which answers Smithy RPC v2
CBOR (current SDKs), awsJson 1.0 and awsQuery (older SDKs; `awsQueryCompatible`
error codes).

## Behaviour

`PutMetricData` (gzip-compressed bodies too) stores real datapoints for 455 days
with AWS's validation: values, `Values`/`Counts`, statistic sets,
high-resolution storage, units, up to 30 dimensions, the two-week/two-hour
timestamp window and reserved `AWS/` namespaces. `GetMetricStatistics` computes
`SampleCount`, `Sum`, `Average`, `Minimum`, `Maximum` and extended statistics
(`pNN`, `tmNN`, `wmNN`, `tcNN`, `tsNN`, `PR(a:b)`, `IQM`) per period with the
1,440-datapoint limit, and `ListMetrics` filters by namespace, name, dimensions
and `RecentlyActive`.

`GetMetricData` runs the metric math language: arithmetic, comparisons and
logic, `SEARCH` with the search expression syntax, `METRICS()`, `FILL`, `IF`,
`RATE`, `DIFF`, `RUNNING_SUM`, `SORT`, `SLICE`, `FIRST`/`LAST`, `REMOVE_EMPTY`,
time functions, `ANOMALY_DETECTION_BAND`, `INSIGHT_RULE_METRIC` and label
templates, with `ScanBy`, `MaxDatapoints` pagination and `PartialData`. Alarms
evaluate every second against the emulated clock: metric alarms on one metric or
metric math (`EvaluationPeriods`, `DatapointsToAlarm`, `TreatMissingData`,
anomaly detection band thresholds), composite alarms over their children's
states (`ALARM()`, `OK()`, `INSUFFICIENT_DATA()`, `AT_LEAST`, `TRUE`/`FALSE`,
`AND`/`OR`/`NOT`, cycle checks, actions suppressors with wait and extension
periods) and log alarms that run their Logs Insights query on its schedule.

State changes are written to the alarm history with AWS's reason strings and
reason data, sent to EventBridge as `CloudWatch Alarm State Change` events, and
run the state's actions: SNS topics (published as `cloudwatch.amazonaws.com`,
judged by the topic policy, with AWS's alarm message) and Lambda functions
(invoked as `lambda.alarms.cloudwatch.amazonaws.com`, judged by the function
policy), unless actions are disabled or an alarm mute rule (one-time `at()` or
recurring `cron()`/`rate()` windows) is active.

Also: dashboards with body validation, Contributor Insights rules that analyse
CloudWatch Logs events for `GetInsightRuleReport` (JSON and CLF logs, filters,
`Count`/`Sum`, contributors and rule metrics), managed rules, anomaly detectors
(training state from the metric's history), metric streams (running `json`
streams put each minute's records into their Firehose stream, as their role
assumed by `streams.metrics.cloudwatch.amazonaws.com`), tags with
`aws:RequestTag`/`aws:ResourceTag`/`aws:TagKeys` conditions, OTel enrichment,
resource metrics configurations, the default dataset's KMS key (checked by
encrypting through `monitoring` as the caller), and `GetMetricWidgetImage`,
which draws a real PNG graph.

## Known gaps

AWS service metrics outside `AWS/SQS`, `AWS/Kinesis`, `AWS/Firehose` and
`AWS/CertificateManager` (other `AWS/*` namespaces stay empty), metric streams
in OpenTelemetry formats deliver nothing, cross-account observability, and
EC2/Auto Scaling/Systems Manager alarm actions. Alarm evaluation does not yet
look back over the evaluation range for `TreatMissingData`, and never reports
the `PARTIAL_DATA` or `EVALUATION_ERROR` evaluation states.

See also: [all services](README.md) · [authentication and authorization](../security.md).

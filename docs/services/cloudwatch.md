# Amazon CloudWatch

> Crate: [`mws-cloudwatch`](../../crates/services/mws-cloudwatch) · Tests: [`tests/e2e-rust/tests/e2e/cloudwatch.rs`](../../tests/e2e-rust/tests/e2e/cloudwatch.rs)

All 55 operations are generated from the AWS model and implemented. MWS answers Smithy RPC v2 CBOR (current SDKs), awsJson 1.0 and awsQuery (older SDKs, with `awsQueryCompatible` error codes).

✅ supported · 🟡 partial · ❌ not supported

## Metrics

| Feature | Status | Details |
| --- | :---: | --- |
| `PutMetricData` | ✅ | Real datapoints kept for 455 days (gzip bodies too), with AWS's validation: values, `Values`/`Counts`, statistic sets, high resolution, units, up to 30 dimensions, the timestamp window and reserved `AWS/` namespaces. |
| `GetMetricStatistics` | ✅ | `SampleCount`, `Sum`, `Average`, `Minimum`, `Maximum` and extended statistics (`pNN`, `tmNN`, `wmNN`, `tcNN`, `tsNN`, `PR(a:b)`, `IQM`) with the 1,440-datapoint limit. |
| `ListMetrics` | ✅ | By namespace, name, dimensions and `RecentlyActive`. |
| Metric math | ✅ | `GetMetricData` with arithmetic and logic, `SEARCH`, `METRICS()`, `FILL`, `IF`, `RATE`, `DIFF`, `RUNNING_SUM`, `SORT`, `SLICE`, time functions, `ANOMALY_DETECTION_BAND`, `INSIGHT_RULE_METRIC` and label templates, with pagination and `PartialData`. |
| AWS service metrics | 🟡 | Published by SQS, Kinesis, Firehose and ACM; other `AWS/*` namespaces stay empty. |

## Alarms

| Feature | Status | Details |
| --- | :---: | --- |
| Metric alarms | ✅ | On one metric or metric math, evaluated on the emulated clock with `EvaluationPeriods`, `DatapointsToAlarm`, `TreatMissingData` and anomaly detection band thresholds. |
| Evaluation details | 🟡 | No look-back over the evaluation range for `TreatMissingData`, and no `PARTIAL_DATA` or `EVALUATION_ERROR` states. |
| Composite alarms | ✅ | `ALARM()`, `OK()`, `INSUFFICIENT_DATA()`, `AT_LEAST`, `AND`/`OR`/`NOT`, cycle checks and actions suppressors. |
| Log alarms | ✅ | Run their Logs Insights query on its schedule. |
| Actions | ✅ | SNS (as `cloudwatch.amazonaws.com`, with AWS's alarm message) and Lambda (as `lambda.alarms.cloudwatch.amazonaws.com`), judged by their policies; mute rules and disabled actions apply. |
| EC2, Auto Scaling and Systems Manager actions | ❌ | Not yet. |
| History and events | ✅ | Alarm history with AWS's reason strings and data; `CloudWatch Alarm State Change` events to EventBridge. |

## Other features

| Feature | Status | Details |
| --- | :---: | --- |
| Dashboards | ✅ | With body validation; `GetMetricWidgetImage` draws a real PNG graph. |
| Contributor Insights | ✅ | Rules that analyse CloudWatch Logs events for `GetInsightRuleReport`; managed rules. |
| Anomaly detectors | ✅ | Training state from the metric's history. |
| Metric streams | 🟡 | `json` streams deliver each minute's records to Firehose as their role; OpenTelemetry formats deliver nothing. |
| Tags and settings | ✅ | Tag condition keys, OTel enrichment, resource metrics configurations and the default dataset's KMS key. |
| Cross-account observability | ❌ | Not yet. |

See also: [all services](README.md) · [authentication and authorization](../security.md).

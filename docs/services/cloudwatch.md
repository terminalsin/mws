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
| AWS service metrics | 🟡 | Published by Lambda (`Invocations`, `Errors`, `Duration`, `Throttles`, `ConcurrentExecutions`, `IteratorAge`), SNS (published, delivered, failed and filtered-out notifications, `PublishSize`), EventBridge (matched events, triggered rules, invocations and attempts), SQS, Kinesis, Firehose, Logs, Elastic Load Balancing, Auto Scaling, EC2 (`AWS/EC2` instance metrics, see [EC2](ec2.md)), ElastiCache, ACM and Service Quotas usage; other `AWS/*` namespaces stay empty. |

## Alarms

| Feature | Status | Details |
| --- | :---: | --- |
| Metric alarms | ✅ | On one metric or metric math, evaluated about once a minute on the emulated clock (each period for high-resolution alarms) over completed periods only, with `EvaluationPeriods`, `DatapointsToAlarm`, `TreatMissingData` and anomaly detection band thresholds. A datapoint put now is evaluated once its period ends: tests move `/_mws/clock` past it instead of waiting. |
| Evaluation details | 🟡 | Alarms look back over an evaluation range of `EvaluationPeriods` + 2 periods: with enough real datapoints the most recent ones decide and `TreatMissingData` is ignored, otherwise the missing ones are treated as it says. AWS does not publish the exact range length, and there is no late-data lag and no `PARTIAL_DATA` or `EVALUATION_ERROR` states. |
| Composite alarms | ✅ | `ALARM()`, `OK()`, `INSUFFICIENT_DATA()`, `AT_LEAST`, `AND`/`OR`/`NOT`, cycle checks and actions suppressors. |
| Log alarms | ✅ | Run their Logs Insights query on its schedule. |
| Actions | ✅ | SNS (as `cloudwatch.amazonaws.com`, with AWS's alarm message) and Lambda (as `lambda.alarms.cloudwatch.amazonaws.com`), judged by their policies; mute rules and disabled actions apply. |
| Auto Scaling actions | ✅ | Run the named scaling policy. |
| EC2 actions | ✅ | `arn:aws:automate:<region>:ec2:stop`, `terminate`, `reboot` and `recover` act on the instance named by the alarm's `InstanceId` dimension (`recover` reboots it). |
| Systems Manager actions | 🟡 | `arn:aws:ssm:<region>:<account>:opsitem:<severity>[#CATEGORY=<category>]` creates an OpsItem (one per alarm while it is open; title, source and operational data approximate AWS's). Incident Manager (`ssm-incidents`) is not emulated and those actions fail. |
| History and events | ✅ | Alarm history with AWS's reason strings and data; `CloudWatch Alarm State Change` events to EventBridge. |

## Other features

| Feature | Status | Details |
| --- | :---: | --- |
| Dashboards | ✅ | With body validation; `GetMetricWidgetImage` draws a real PNG graph. |
| Contributor Insights | ✅ | Rules that analyse CloudWatch Logs events for `GetInsightRuleReport`; managed rules. |
| Anomaly detectors | 🟡 | `ANOMALY_DETECTION_BAND` trains a model on up to two weeks of history before the queried window (honouring `ExcludedTimeRanges` and `MetricTimezone`), with hourly, daily or weekly seasonality when the history covers two cycles; it needs 10 datapoints of history, otherwise the band is empty. Bands create the metric's detector when none exists. `StateValue` is `PENDING_TRAINING`, `TRAINED_INSUFFICIENT_DATA` (under a day of history) or `TRAINED`. The model is a deterministic mean/standard-deviation model, not AWS's; `AdaptationSpeed` and `OutlierFilteringStrength` are ignored. |
| Metric streams | 🟡 | `json` streams deliver each minute's records to Firehose as their role; OpenTelemetry formats deliver nothing. |
| Tags and settings | ✅ | Tag condition keys, OTel enrichment, resource metrics configurations and the default dataset's KMS key. |
| Cross-account observability | ❌ | Not yet. |

See also: [all services](README.md) · [authentication and authorization](../security.md).

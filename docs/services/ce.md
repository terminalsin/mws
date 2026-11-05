# AWS Cost Explorer

> Crate: [`mws-ce`](../../crates/services/mws-ce) · Tests: [`tests/e2e-rust/tests/e2e/costexplorer.rs`](../../tests/e2e-rust/tests/e2e/costexplorer.rs)

All 47 operations are generated from the AWS model (awsJson1.1) and implemented over a ledger of seeded records and request charges derived from real API calls.

✅ supported · 🟡 partial · ❌ not supported

| Feature | Status | Details |
| --- | :---: | --- |
| Seeded cost data | ✅ | `POST /_aws/ce/records` (unsigned) with `{"records": [...]}`: each record has `account`, `start` (date or time), optional `end` (an hour later by default), `service` (Cost Explorer's name, e.g. `Amazon Elastic Compute Cloud - Compute`), a `cost`, and optionally `region`, `usageType`, `operation`, `recordType`, `instanceType`, `availabilityZone`, `resourceId`, `purchaseType`, `unit`, `usageQuantity`, the other cost metrics, `tags` and any other `dimensions`. `GET /_aws/ce/records[?account=]` lists the ledger, `DELETE` clears the seeded part; scenario files call `MwsPutCostRecords`. |
| Derived request charges | 🟡 | Successful calls to services AWS bills per request (KMS, Secrets Manager, SQS, SNS publishes, Lambda invocations, S3 requests, CloudWatch, EventBridge, Kinesis puts, Cost Explorer) are charged at us-east-1 on-demand prices, per hour, account, Region, usage type and operation. No storage, compute hours or data transfer. |
| Consolidated billing | ✅ | Follows Organizations: a management account sees its members' costs (with their names for `LINKED_ACCOUNT`), a member its own. |
| `GetCostAndUsage` | ✅ | Hourly, daily and monthly granularity, all cost and usage metrics, two group bys over dimensions, tags and cost categories, the full filter expression language with match options; records split across periods. `WithResources` for the last 14 days. |
| Values | ✅ | `GetDimensionValues` (search, context), `GetTags`, `GetCostCategories`. |
| Forecasts | ✅ | `GetCostForecast` and `GetUsageForecast` by linear regression on daily history, with prediction intervals. |
| Comparisons | ✅ | `GetCostAndUsageComparisons` and `GetCostComparisonDrivers` (by usage type). |
| Cost categories | 🟡 | Rules over dimensions, tags and other categories, inherited values, default value, effective dates. Split charge rules are stored but not applied. |
| Cost allocation tags | ✅ | Tags found in the data, activation (applies from the activation hour), backfills that complete on the emulated clock. |
| Anomaly detection | 🟡 | Monitors (by service, by account, custom), anomalies found in the ledger with root causes and impact, feedback, subscriptions with thresholds; immediate SNS subscribers get AWS's alert JSON from `costalerts.amazonaws.com`. Detection is a heuristic (a day above the previous 14 days' mean by three standard deviations, 20% and $1), not AWS's model. Daily and weekly emails are not sent. |
| Coverage | ✅ | Reservation coverage from on-demand instance hours, Savings Plans coverage from eligible on-demand spend (EC2, Fargate, Lambda). |
| Utilization | 🟡 | MWS sells no Reserved Instances or Savings Plans: reservation utilization is empty and Savings Plans utilization answers `DataUnavailableException`, as AWS does for accounts without them. |
| Recommendations | 🟡 | Reservation, rightsizing and Savings Plans recommendations return metadata and no recommendations; generations complete on the emulated clock. |
| Commitment purchase analyses | ✅ | Savings Plans analyses estimate coverage, utilization and savings from the ledger's hourly on-demand spend. |
| Tags | ✅ | On cost categories, anomaly monitors and subscriptions. |

See also: [all services](README.md) · [Organizations](organizations.md).

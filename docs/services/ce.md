# AWS Cost Explorer

> Crate: [`mws-ce`](../../crates/services/mws-ce) · Tests: [`tests/e2e-rust/tests/e2e/costexplorer.rs`](../../tests/e2e-rust/tests/e2e/costexplorer.rs)

All 47 operations are generated from the AWS model (awsJson1.1) and implemented over a ledger of seeded records, request charges derived from real API calls, resource-hours and storage of the resources MWS runs, and usage other services charge (Marketplace metering).

✅ supported · 🟡 partial · ❌ not supported

| Feature | Status | Details |
| --- | :---: | --- |
| Seeded cost data | ✅ | `POST /_aws/ce/records` (unsigned) with `{"records": [...]}`: each record has `account`, `start` (date or time), optional `end` (an hour later by default), `service` (Cost Explorer's name, e.g. `Amazon Elastic Compute Cloud - Compute`), a `cost`, and optionally `region`, `usageType`, `operation`, `recordType`, `instanceType`, `availabilityZone`, `resourceId`, `purchaseType`, `unit`, `usageQuantity`, the other cost metrics, `tags` and any other `dimensions`. `GET /_aws/ce/records[?account=]` lists the ledger, `DELETE` clears the seeded part; scenario files call `MwsPutCostRecords`. |
| Derived request charges | 🟡 | Successful calls to services AWS bills per request (KMS, Secrets Manager, SQS, SNS publishes, Lambda invocations, S3 requests, CloudWatch, EventBridge, Kinesis puts, Cost Explorer) are charged at us-east-1 on-demand prices, per hour, account, Region, usage type and operation. Request charges carry no `RESOURCE_ID`. |
| Derived resource usage | 🟡 | Running resources are billed hour by hour on the emulated clock at public us-east-1 on-demand prices, with `RESOURCE_ID`, `INSTANCE_TYPE` and the resource's tags (so cost allocation tags, cost categories over tags and `GetCostAndUsageWithResources` see them): EC2 instances while running (`BoxUsage:<type>`, Linux or Windows), EBS volumes (`EBS:VolumeUsage.<type>`, GB-Mo), RDS instances (`InstanceUsage`/`Multi-AZUsage:<class>`, stopped instances accrue no compute) and their storage, EKS clusters (`AmazonEKS-Hours:perCluster`), ElastiCache nodes (`NodeUsage:<type>`), Fargate task vCPU and memory (On-Demand and Spot), S3 storage by storage class (`TimedStorage-*ByteHrs`, GB-Mo) and EFS storage. Resources are sampled on every Cost Explorer query and at most once a minute on other calls; a resource deleted between samples loses the time since the last one. No data transfer, Aurora, serverless caches, NAT gateways, load balancers or Elastic IPs. |
| Charged usage | 🟡 | Accepted Marketplace metering records (`MeterUsage`, `BatchMeterUsage`) are charged to the buyer under the product's title with `BILLING_ENTITY` `AWS Marketplace`, at the dimension's `price` in the catalogue (none: usage without cost), split by usage allocation tags. Other services charge through `CostExplorer::record_usage` (Bedrock tokens). |
| Consolidated billing | ✅ | Follows Organizations: a management account sees its members' costs (with their names for `LINKED_ACCOUNT`), a member its own. |
| `GetCostAndUsage` | ✅ | Hourly, daily and monthly granularity, all cost and usage metrics, two group bys over dimensions, tags and cost categories, the full filter expression language with match options; records split across periods. `WithResources` for the last 14 days. Hourly data covers the last 14 days (`ValidationException` before that; the hourly-granularity preference has no API and counts as enabled) and history 13 months (`DataUnavailableException`; multi-year data is not modeled). Results come in pages of at most 100 periods or 1,000 groups, with `NextPageToken`. |
| Values | ✅ | `GetDimensionValues` (search, context), `GetTags`, `GetCostCategories`. |
| Forecasts | ✅ | `GetCostForecast` and `GetUsageForecast` by linear regression on daily history, with prediction intervals. |
| Comparisons | ✅ | `GetCostAndUsageComparisons` and `GetCostComparisonDrivers` (by usage type). |
| Cost categories | ✅ | Rules over dimensions, tags and other categories, inherited values, default value, effective dates, and split charge rules (`FIXED`, `PROPORTIONAL`, `EVEN`) that share a source value's costs out to its targets when grouping by the category. |
| Cost allocation tags | ✅ | Tags found in the data, activation (applies from the activation hour), backfills that complete on the emulated clock. |
| Anomaly detection | 🟡 | Monitors (by service, by account, custom), anomalies found in the ledger with root causes and impact, feedback, subscriptions with thresholds; immediate SNS subscribers get AWS's alert JSON from `costalerts.amazonaws.com`. Detection is a heuristic (a day above the previous 14 days' mean by three standard deviations, 20% and $1), not AWS's model. Daily and weekly emails are not sent. |
| Coverage | ✅ | Reservation coverage from on-demand instance hours, Savings Plans coverage from eligible on-demand spend (EC2, Fargate, Lambda). |
| Utilization | 🟡 | MWS sells no Reserved Instances or Savings Plans: reservation utilization is empty and Savings Plans utilization answers `DataUnavailableException`, as AWS does for accounts without them. |
| Recommendations | 🟡 | Reservation, rightsizing and Savings Plans recommendations return metadata and no recommendations; generations complete on the emulated clock. |
| Commitment purchase analyses | ✅ | Savings Plans analyses estimate coverage, utilization and savings from the ledger's hourly on-demand spend. |
| Tags | ✅ | On cost categories, anomaly monitors and subscriptions. |
| Authorization | ✅ | Cost category, anomaly monitor and subscription operations authorize on the resource's ARN with `aws:ResourceTag/*`; create and tag operations pass `aws:RequestTag/*` and `aws:TagKeys`, untag `aws:TagKeys`. |
| Data latency | 🟡 | Costs are visible as soon as they accrue; AWS refreshes cost data up to three times a day. |

See also: [all services](README.md) · [Organizations](organizations.md).

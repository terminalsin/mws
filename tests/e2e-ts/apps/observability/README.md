# observability

Logs, metrics and alerting for a "checkout" service.

- [`src/logger.ts`](src/logger.ts) buffers JSON log lines and ships them with
  `PutLogEvents`.
- [`src/metrics.ts`](src/metrics.ts) publishes timings with `PutMetricData`.
- [`src/monitoring.ts`](src/monitoring.ts) creates the log group, a metric
  filter turning `{ $.level = "ERROR" }` lines into an `Errors` metric, and an
  alarm on that metric that notifies an SNS topic, which feeds a "pager" SQS
  queue.

The tests search logs with a JSON filter pattern, read statistics and metric
math back, and log enough errors to move the alarm to `ALARM` and receive the
notification CloudWatch sends.

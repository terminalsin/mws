# Amazon EventBridge

> Crate: [`mws-events`](../../crates/services/mws-events) · Tests: [`tests/e2e-rust/tests/e2e/events.rs`](../../tests/e2e-rust/tests/e2e/events.rs)

All 57 operations are generated from the AWS model (awsJson1.1) and implemented. Events really reach their targets.

✅ supported · 🟡 partial · ❌ not supported

## Buses and rules

| Feature | Status | Details |
| --- | :---: | --- |
| Event buses | ✅ | The default bus of every account and Region, custom buses and partner event buses. |
| Bus policies | ✅ | `PutPermission`/`RemovePermission` or whole documents, evaluated by the IAM engine for cross-account `PutEvents` and rule management. |
| Event patterns | ✅ | The full pattern language (exact values, `prefix`, `suffix`, `equals-ignore-case`, `wildcard`, `anything-but`, `numeric`, `exists`, `cidr`, `$or`, arrays) with EventBridge's validation messages; `TestEventPattern`. |
| Scheduled rules | ✅ | `rate()` and six-field `cron()` on the emulated clock. |
| Input shaping | ✅ | `Input`, `InputPath` and `InputTransformer`. |
| Retries and dead-letter queues | ✅ | Retry policies; dead-letter queues get EventBridge's error attributes. |
| Archives and replays | ✅ | Archives keep matching events through EventBridge's managed rule; replays send them back with `replay-name`. |
| Global endpoints, partner sources, tags | ✅ | `PutEvents` with `EndpointId` goes to the primary bus; `PutPartnerEvents`. |
| `iam:PassRole` | ✅ | Checked for rule and target roles. |
| Bus logging and KMS encryption | 🟡 | Stored only. |

## Targets

| Feature | Status | Details |
| --- | :---: | --- |
| SNS topics | ✅ | Allowed by the topic policy. |
| SQS queues | ✅ | Sent as `events.amazonaws.com`, allowed by the queue policy, with `MessageGroupId` for FIFO queues. |
| Lambda functions | ✅ | Invoked asynchronously as `events.amazonaws.com`, allowed by the function policy. |
| CloudWatch Logs | ✅ | One stream per event, allowed by the Logs resource policy. |
| Other event buses | ✅ | In any account or Region, through a target role or the receiving bus policy. |
| Kinesis and Firehose | ✅ | Written as the target's role; the partition key comes from `KinesisParameters.PartitionKeyPath`, else the event id. |
| API destinations | ✅ | Real HTTP requests with basic, API key or OAuth client credentials auth from the connection, and path, header and query parameters. |
| Other targets | ❌ | Step Functions, ECS and the rest are accepted but not delivered. |

## Events from other services

| Feature | Status | Details |
| --- | :---: | --- |
| S3 | ✅ | Buckets with EventBridge notifications put `aws.s3` events (object created and deleted, restores, tags, ACLs, storage class changes) on the owner's default bus. |
| SSM, ACM, CloudWatch | ✅ | Parameter Store policy actions and changes, certificate expiry warnings, and alarm state changes. |

See also: [all services](README.md) · [authentication and authorization](../security.md).

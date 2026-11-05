# Amazon EventBridge

> Crate: [`mws-events`](../../crates/services/mws-events) · Tests: [`tests/e2e-rust/tests/e2e/events.rs`](../../tests/e2e-rust/tests/e2e/events.rs)

All 57 operations are generated from the AWS model (awsJson1.1).

## Behaviour

Implemented: the default event bus of every account and Region, custom buses and
partner event buses, bus policies (`PutPermission`/`RemovePermission` or whole
documents) that the IAM engine evaluates for cross-account `PutEvents` and rule
management, rules with EventBridge's full event pattern language (exact values,
`prefix`, `suffix`, `equals-ignore-case`, `wildcard`, `anything-but`, `numeric`,
`exists`, `cidr`, `$or`, arrays) and its validation messages,
`TestEventPattern`, scheduled rules (`rate()` and six-field `cron()` against the
emulated clock), targets with `Input`, `InputPath` and `InputTransformer`, retry
policies and dead-letter queues.

Events really reach targets: SNS topics (allowed by the topic policy), SQS
queues (sent as `events.amazonaws.com`, allowed by the queue policy, with
`MessageGroupId` for FIFO queues; dead-letter queues get EventBridge's error
attributes), Lambda functions (invoked asynchronously as `events.amazonaws.com`,
allowed by the function policy), CloudWatch Logs groups (one stream per event,
allowed by the Logs resource policy), other buses in any account or Region
(through a target role, or the receiving bus policy), and API destinations (real
HTTP requests with basic, API key or OAuth client credentials auth from the
connection, path, header and query parameters).

S3 buckets with EventBridge notifications turned on put `aws.s3` events (`Object
Created`, `Object Deleted`, restores, tags, ACLs, storage class changes) on the
owner's default bus, SSM parameter policies send "Parameter Store Policy Action"
events, and ACM sends "ACM Certificate Approaching Expiration" events. Archives
keep matching events (with EventBridge's managed rule) and replays send them
back with `replay-name`.

Connections, API destinations, global endpoints (`PutEvents` with `EndpointId`
goes to the primary bus), partner event sources (`PutPartnerEvents`), and tags.
`iam:PassRole` is checked for rule and target roles. Kinesis data streams
(partition key from `KinesisParameters.PartitionKeyPath`, else the event id) and
Firehose streams get events written as the target's role (`RoleArn` is
required).

## Known gaps

Other target types (Step Functions, ECS, ...) are accepted but not delivered;
event bus logging and KMS encryption are stored only.

See also: [all services](README.md) · [authentication and authorization](../security.md).

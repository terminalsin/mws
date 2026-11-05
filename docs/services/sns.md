# Amazon SNS

> Crate: [`mws-sns`](../../crates/services/mws-sns) · Tests: [`tests/e2e-rust/tests/e2e/sns.rs`](../../tests/e2e-rust/tests/e2e/sns.rs)

All 42 operations are generated from the AWS model (awsQuery).

## Behaviour

Implemented: standard and FIFO topics (name rules, idempotent `CreateTopic`,
attributes with AWS's defaults and `EffectiveDeliveryPolicy`, the default access
policy, `AddPermission`/`RemovePermission`, access policies the IAM engine
evaluates with `aws:ResourceTag` conditions, tags, data protection policies),
subscriptions for every protocol with endpoint checks, confirmation tokens,
`ReturnSubscriptionArn`, `AuthenticateOnUnsubscribe` and attributes, filter
policies on message attributes or the message body (exact, prefix, suffix,
`anything-but`, `numeric`, `exists`, `cidr`, `equals-ignore-case`, `$or`) with
AWS's limits, `Publish` and `PublishBatch` with message attribute and size
checks, `MessageStructure` JSON, FIFO group ids, sequence numbers and
five-minute deduplication (content based or explicit), mobile push platform
applications and endpoints, SMS settings, opt-outs and the SMS sandbox.

Messages are really delivered and signed (`SignatureVersion` 1 or 2) with a
certificate served at `SigningCertURL`: Lambda functions get the SNS event
asynchronously as `sns.amazonaws.com` when the function policy allows it, SQS
queues get the envelope or the raw message (with its attributes, FIFO group and
deduplication ids) when the queue policy allows it, as do dead-letter queues,
HTTP/HTTPS endpoints get signed `SubscriptionConfirmation`, `Notification` (raw
or enveloped, retried per the delivery policy) and `UnsubscribeConfirmation`
POSTs, and the unsigned `SubscribeURL`/`UnsubscribeURL` links work.

Email, SMS and push messages land in an outbox at `/_aws/sns/email-messages`,
`/sms-messages` and `/platform-endpoint-messages` (with
`/_aws/sns/subscription-tokens/<arn>` and `POST
/_aws/sns/sms-opt-out?phoneNumber=` for tests). Other services publish as AWS
does: S3 event notifications and CloudWatch alarm actions, judged by the topic
policy (the default policy's `AWS:SourceOwner` condition admits the owner's own
alarms).

Delivery status logging works for Lambda, SQS, HTTP/S and application endpoints:
with `<Protocol>SuccessFeedbackRoleArn`/`FailureFeedbackRoleArn` set, SNS
assumes the role and writes AWS's status records to
`sns/<region>/<account>/<topic>` (successes sampled by
`SuccessFeedbackSampleRate`) and `.../Failure`. Server-side encryption: topics
with `KmsMasterKeyId` get a data key from KMS for every publish, so publishers
need `kms:GenerateDataKey*` and `kms:Decrypt` on the key (`KMSAccessDenied`,
`KMSDisabled`, `KMSInvalidState`, `KMSNotFound` otherwise); the AWS managed key
`alias/aws/sns` works through SNS for the whole account, and AWS services
publishing for a resource (S3 events, EventBridge) need the key policy to allow
their service principal.

FIFO topics with an `ArchivePolicy` archive messages for the retention period
(`BeginningArchiveTime`), and a subscription's `ReplayPolicy` redelivers the
archived messages in its time window through its filter policy (original message
id and timestamp, `"Replayed": true`; an `EndingPoint` pauses the subscription;
`ReplayStatus` reads `Completed`).

## Known gaps

Firehose delivery and data protection policies acting on messages.

See also: [all services](README.md) · [authentication and authorization](../security.md).

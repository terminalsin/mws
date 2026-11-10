# Amazon SNS

> Crate: [`mws-sns`](../../crates/services/mws-sns) · Tests: [`tests/e2e-rust/tests/e2e/sns.rs`](../../tests/e2e-rust/tests/e2e/sns.rs)

All 42 operations are generated from the AWS model (awsQuery) and implemented. Messages are really delivered and signed.

As in SNS, delivery is asynchronous: `Publish` returns once the message is accepted, and each subscription receives it shortly after, so consumers must poll or wait (for SQS, long-poll). Each topic delivers its messages in the order they were published, which keeps FIFO message groups in order; data protection, filter policies and KMS run per subscription at delivery time.

✅ supported · 🟡 partial · ❌ not supported

## Topics and subscriptions

| Feature | Status | Details |
| --- | :---: | --- |
| Standard and FIFO topics | ✅ | Name rules, idempotent `CreateTopic`, attributes with AWS's defaults and `EffectiveDeliveryPolicy`, tags. |
| Access policies | ✅ | The default access policy, `AddPermission`/`RemovePermission`, and policies evaluated by the IAM engine with `aws:ResourceTag` conditions. |
| Subscriptions | ✅ | Every protocol, with endpoint checks, confirmation tokens, `ReturnSubscriptionArn`, `AuthenticateOnUnsubscribe` and attributes. |
| Filter policies | ✅ | On message attributes or the body (exact, prefix, suffix, `anything-but`, `numeric`, `exists`, `cidr`, `equals-ignore-case`, `$or`) with AWS's limits. |
| Publishing | ✅ | `Publish` and `PublishBatch` with attribute and size checks, `MessageStructure` JSON, FIFO group ids, sequence numbers and five-minute deduplication. |
| Mobile push and SMS | ✅ | Platform applications and endpoints, SMS settings, opt-outs and the SMS sandbox. |
| Data protection policies | 🟡 | `Deny`, `Deidentify` (mask or redact) and `Audit` (to Logs, Firehose or S3) act on published messages and deliveries. Managed identifiers detected: email and IP addresses, US SSNs and phone numbers, credit card numbers, AWS secret keys and private keys, plus custom identifiers; other managed identifiers find nothing. |

## Delivery

| Feature | Status | Details |
| --- | :---: | --- |
| Signatures | ✅ | `SignatureVersion` 1 or 2, with a certificate served at `SigningCertURL`. |
| Lambda | ✅ | The SNS event, invoked asynchronously as `sns.amazonaws.com` when the function policy allows it. |
| SQS | ✅ | The envelope or the raw message (with attributes, FIFO group and deduplication ids) when the queue policy allows it; also for dead-letter queues. |
| HTTP and HTTPS | ✅ | Signed `SubscriptionConfirmation`, `Notification` (raw or enveloped, retried per the delivery policy) and `UnsubscribeConfirmation` POSTs; `SubscribeURL` and `UnsubscribeURL` work. |
| Email, SMS and push | ✅ | Land in an outbox at `/_aws/sns/email-messages`, `/sms-messages` and `/platform-endpoint-messages` for tests to read. |
| Firehose | ✅ | Written as the subscription's `SubscriptionRoleArn` (raw or enveloped). |
| Delivery status logging | ✅ | For Lambda, SQS, HTTP/S and application endpoints, written to CloudWatch Logs as the feedback role, sampled by `SuccessFeedbackSampleRate`. |

## Metrics

`AWS/SNS` metrics go to [CloudWatch](cloudwatch.md) by `TopicName`: `NumberOfMessagesPublished`, `PublishSize`, `NumberOfNotificationsDelivered`, `NumberOfNotificationsFailed` and `NumberOfNotificationsFilteredOut` (with the `-MessageAttributes` and `-MessageBody` variants).

## Encryption and archiving

| Feature | Status | Details |
| --- | :---: | --- |
| Server-side encryption | ✅ | Topics with `KmsMasterKeyId` get a data key from KMS for every publish (`KMSAccessDenied`, `KMSDisabled` and friends otherwise); `alias/aws/sns` works; AWS services need the key policy to allow them. |
| FIFO archive and replay | ✅ | `ArchivePolicy` keeps messages for the retention period; a subscription's `ReplayPolicy` redelivers them through its filter policy with `"Replayed": true`. |

## Publishers

| Feature | Status | Details |
| --- | :---: | --- |
| Other services | ✅ | S3 event notifications, CloudWatch alarm actions, EventBridge and Lambda destinations publish as AWS does, judged by the topic policy. |

See also: [all services](README.md) · [authentication and authorization](../security.md).

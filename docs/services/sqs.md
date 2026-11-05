# Amazon SQS

> Crate: [`mws-sqs`](../../crates/services/mws-sqs) · Tests: [`tests/e2e-rust/tests/e2e/sqs.rs`](../../tests/e2e-rust/tests/e2e/sqs.rs)

All 23 operations are generated from the AWS model (awsJson1.0, `awsQueryCompatible`) and implemented. Errors carry the awsQuery code in `x-amzn-query-error`, so SDKs report `AWS.SimpleQueueService.NonExistentQueue` and friends.

✅ supported · 🟡 partial · ❌ not supported

## Protocols

| Feature | Status | Details |
| --- | :---: | --- |
| awsJson 1.0 | ✅ | What current SDKs send. |
| Legacy awsQuery | ✅ | Requests from older SDKs, generated from the same model, with awsQuery validation codes. |

## Messages

| Feature | Status | Details |
| --- | :---: | --- |
| Standard queues | ✅ | Real messages, queue and per-message delays, retention on the emulated clock, message attribute and size validation. |
| Visibility timeouts | ✅ | Fresh receipt handles per receive; stale handles stop acting, with SQS's error wording. |
| Long polling | ✅ | Wakes as soon as a message arrives. |
| MD5 digests | ✅ | Of bodies and message attributes, computed as SQS does. |
| FIFO queues | ✅ | Message groups (a group with a message in flight yields nothing further), deduplication (explicit or content-based, per queue or per group, five minutes), sequence numbers and `ReceiveRequestAttemptId` retries. |
| Batch operations | ✅ | With SQS's entry rules. |

## Queues

| Feature | Status | Details |
| --- | :---: | --- |
| Dead-letter queues | ✅ | Messages move after `maxReceiveCount` receives, with redrive allow policies and `ListDeadLetterSourceQueues`. |
| Message move tasks | ✅ | Redrive back or to another queue at `MaxNumberOfMessagesPerSecond`, cancellable while running. |
| Queue lifecycle | ✅ | `PurgeQueue` once a minute; names blocked for 60 seconds after deletion; tags and `ListQueues` pagination. |
| CloudWatch metrics | ✅ | `AWS/SQS` metrics for active queues. |

## Security

| Feature | Status | Details |
| --- | :---: | --- |
| Queue policies | ✅ | Evaluated by the IAM engine with `aws:ResourceTag` conditions; `AddPermission`/`RemovePermission` edit them. |
| SSE-KMS | ✅ | Data keys from MWS KMS with the caller's permissions (`kms:GenerateDataKey` to send, `kms:Decrypt` to receive); `alias/aws/sqs` works. |
| Service principals | ✅ | SNS, S3, EventBridge and others deliver as their service principal, judged by the queue policy. |

See also: [all services](README.md) · [authentication and authorization](../security.md).

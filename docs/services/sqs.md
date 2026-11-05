# Amazon SQS

> Crate: [`mws-sqs`](../../crates/services/mws-sqs) · Tests: [`tests/e2e-rust/tests/e2e/sqs.rs`](../../tests/e2e-rust/tests/e2e/sqs.rs)

All 23 operations are generated from the AWS model (awsJson1.0,
`awsQueryCompatible`: errors carry the awsQuery code in `x-amzn-query-error`, so
SDKs report `AWS.SimpleQueueService.NonExistentQueue` and friends).

## Behaviour

Legacy awsQuery requests from older SDKs are answered too, generated from the
same model. Standard and FIFO queues hold real messages: queue and per-message
delays, visibility timeouts with fresh receipt handles per receive (stale
handles stop acting), long polling that wakes when a message arrives, retention
against the emulated clock, MD5 digests of bodies and message attributes as SQS
computes them, message attribute and size validation, FIFO message groups (a
group with a message in flight yields nothing further), deduplication (explicit
or content-based, per queue or per group, five minutes), sequence numbers and
`ReceiveRequestAttemptId` retries.

Dead-letter queues receive messages after `maxReceiveCount` receives
(`DeadLetterQueueSourceArn`), with redrive allow policies, and message move
tasks redrive them back or to another queue at `MaxNumberOfMessagesPerSecond`
(cancellable while running). `PurgeQueue` once a minute, queue names blocked for
60 s after deletion, batch operations with SQS's entry rules,
`AddPermission`/`RemovePermission` editing the queue policy, tags, and
`ListQueues`/`ListDeadLetterSourceQueues` pagination.

Queue policies are evaluated by the IAM engine with `aws:ResourceTag`
conditions; SSE-KMS queues get data keys from MWS KMS with the caller's
permissions (`kms:GenerateDataKey` to send, `kms:Decrypt` to receive), and
`alias/aws/sqs` works. Other services deliver as AWS service principals judged
by the queue policy (`Sqs::send_message_as_service`).

See also: [all services](README.md) · [authentication and authorization](../security.md).

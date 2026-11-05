# AWS Lambda

> Crate: [`mws-lambda`](../../crates/services/mws-lambda) · Tests: [`tests/e2e-rust/tests/e2e/lambda.rs`](../../tests/e2e-rust/tests/e2e/lambda.rs)

68 of 88 operations are generated from the AWS model (restJson1) and
implemented; functions really run.

## Behaviour

`Invoke` (`RequestResponse`, `Event` with retries, maximum event age and Lambda
destinations, `DryRun`), `InvokeAsync` and `InvokeWithResponseStream` start an
execution environment speaking the Lambda Runtime API: Python and Node.js
functions run on the local `python3`/`node`
(`MWS_LAMBDA_PYTHON`/`MWS_LAMBDA_NODE` pick the interpreter) with a runtime
client that loads handlers and reports errors as Lambda does, and `provided.*`
functions run their own `bootstrap`.

Environments stay warm, honour timeouts and reserved concurrency (throttling
with `TooManyRequestsException`), capture logs (`START`/`END`/`REPORT`,
`LogType: Tail`, and CloudWatch Logs groups written as the execution role), and
get the execution role's STS credentials and `AWS_ENDPOINT_URL` pointing back at
MWS, so SDKs inside functions use the emulator. Also: zips direct or from S3,
code downloads, versions, aliases with weighted routing, resource policies
(`AddPermission`), layers (on `PYTHONPATH`/`NODE_PATH`/`PATH`) and their
permissions, `iam:PassRole` and trust policy checks, environment variables,
tags, function URLs that serve HTTP (by `Host: <id>.lambda-url.<region>.on.aws`
or at `/_aws/lambda-url/<id>/`, payload format 2.0 events and responses, CORS,
`AWS_IAM` SigV4 or `NONE` with the resource policy granting
`lambda:InvokeFunctionUrl` and `lambda:InvokeFunction` with
`lambda:InvokedViaFunctionUrl`; `RESPONSE_STREAM` responses are buffered), event
invoke configs, provisioned concurrency, recursion and runtime management
settings, code signing configs, and event source mappings.

SQS mappings really poll: `CreateEventSourceMapping` checks the execution role
may receive, delete and read attributes (and that the queue's visibility timeout
covers the function's timeout), batches arrive as `aws:sqs` records with
`BatchSize` and `MaximumBatchingWindowInSeconds` honoured, processed messages
are deleted, failed batches return after their visibility timeout (so the
queue's redrive policy applies), and `ReportBatchItemFailures` keeps only the
reported messages.

Kinesis mappings really poll too: `CreateEventSourceMapping` needs a
`StartingPosition` and checks the role may read the stream; every shard is read
as the execution role from `TRIM_HORIZON`, `LATEST` or `AT_TIMESTAMP` (child
shards after their parents), batches arrive as `aws:kinesis` records, each shard
is checkpointed, failed batches are retried in order until
`MaximumRetryAttempts` or `MaximumRecordAgeInSeconds` (with
`BisectBatchOnFunctionError`), and `ReportBatchItemFailures` resumes at the
first reported sequence number.

Mappings for other sources (DynamoDB, Kafka, MQ, DocumentDB) are stored only.
`FilterCriteria` on SQS and Kinesis mappings (Kinesis `data` filtered as JSON
when it is JSON) is applied with the EventBridge pattern language (records that
match no filter are deleted without invoking the function, as Lambda does).
Container images are stored but cannot run.

## Known gaps

Durable executions, capacity providers, scaling configs and account resource
policies. Also not yet: S3 on-failure destinations, permission checks on
dead-letter queues and destinations when they are configured,
`ScalingConfig.MaximumConcurrency` on mappings, recursive loop detection, and
the six-hour retry window for throttled asynchronous events (asynchronous retry
delays follow the wall clock).

See also: [all services](README.md) · [authentication and authorization](../security.md).

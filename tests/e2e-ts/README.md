# TypeScript example apps

Small but realistic applications written against the
[AWS SDK for JavaScript v3](https://github.com/aws/aws-sdk-js-v3), each with a
[Vitest](https://vitest.dev) suite that runs it end to end against MWS. They
are the TypeScript end-to-end tests for MWS and, at the same time, examples of
how to test your own code with it.

| App | Services | What it shows |
| --- | --- | --- |
| [`upload-pipeline`](apps/upload-pipeline) | S3, SNS, SQS | Presigned uploads from a browser, S3 event notifications fanned out through SNS to SQS, a long-polling worker, a dead-letter queue |
| [`order-events`](apps/order-events) | EventBridge, Lambda, IAM, SQS, CloudWatch Logs | A custom event bus, rules with numeric patterns and input transformers, a TypeScript Lambda function bundled with esbuild that publishes events back to the bus |
| [`app-config`](apps/app-config) | SSM Parameter Store, Secrets Manager, KMS, IAM | Loading typed config from a parameter hierarchy, database credentials and their rotation, KMS envelope encryption with an encryption context |
| [`tenant-isolation`](apps/tenant-isolation) | IAM, STS, S3 | One role for every tenant with ABAC (`${aws:PrincipalTag/tenant}`), session tags through `fromTemporaryCredentials`, IAM denying cross-tenant reads |
| [`observability`](apps/observability) | CloudWatch Logs, CloudWatch, SNS, SQS | A structured logger, filter patterns, a metric filter, custom metrics and metric math, an alarm that pages through SNS |
| [`clickstream`](apps/clickstream) | Kinesis, Firehose, S3, IAM | Partitioned producers with `PutRecords` retries, a shard consumer, Firehose delivering gzipped, date-partitioned batches to S3 |

The application code (`src/`) never mentions MWS. It creates SDK clients with
no endpoint, and the SDK reads `AWS_ENDPOINT_URL`, `AWS_REGION` and the
credentials from the environment, as it would in a deployed environment.
Only the tests know they are talking to MWS.

## Running

Start MWS, then run every app's tests:

```sh
cargo run -p mws                 # in one terminal; listens on port 4566

cd tests/e2e-ts
npm ci
npm test                         # or: npm test -w apps/order-events
```

`npm run typecheck` type-checks every app. Lambda functions run on the `node`
that MWS finds on its `PATH` (or `MWS_LAMBDA_NODE`).

Each app's `vitest.config.ts` points the SDK at MWS and its root user:

| Variable | Default |
| --- | --- |
| `MWS_ENDPOINT` | `http://127.0.0.1:4566` |
| `MWS_REGION` | `us-east-1` |
| `MWS_ROOT_ACCESS_KEY_ID` | `AKIAMWSROOTEXAMPLE00` |
| `MWS_ROOT_SECRET_ACCESS_KEY` | `mwsRootSecretAccessKeyEXAMPLEKEY00000000` |

These replace any `AWS_*` credentials, profile or endpoint in your shell, so
a test run cannot reach a real AWS account by accident. `127.0.0.1` rather
than `localhost` matches the queue URLs MWS hands out, so the SQS client
doesn't warn that they differ from its endpoint.

## Testing your own code this way

- **Don't configure endpoints in application code.** Set `AWS_ENDPOINT_URL`
  for the test run instead (see `vitest.config.ts`). The one setting worth
  passing is `forcePathStyle: true` on S3 clients, which keeps bucket names
  out of the host name of a local endpoint.
- **Use unique names instead of resetting.** Every test file provisions its
  own resources with a random suffix, so apps can share one MWS and run in
  any order. If you'd rather start from a clean emulator, call
  `POST /_mws/reset` in a `beforeAll`, or save a snapshot with
  `PUT /_mws/snapshots/{name}` and restore it before each test.
- **Provision like production.** The apps create IAM roles, resource policies
  and trust policies the way an IaC template would, and MWS enforces them: a
  missing queue policy or `iam:PassRole` permission fails here as it would in
  AWS.
- **Move time instead of sleeping.** Firehose buffers, alarms, S3 lifecycle
  and other timers follow MWS's emulated clock, which `POST /_mws/clock`
  moves forward (see `clickstream`).
- **Take apps apart freely.** Each app is a standalone npm package with its
  own `package.json`, `tsconfig.json` and `vitest.config.ts`; copy one out of
  the workspace and it still works.

# AWS Lambda

> Crate: [`mws-lambda`](../../crates/services/mws-lambda) · Tests: [`tests/e2e-rust/tests/e2e/lambda.rs`](../../tests/e2e-rust/tests/e2e/lambda.rs), [`lambda_images.rs`](../../tests/e2e-rust/tests/e2e/lambda_images.rs), [`lambda_runtimes_docker.rs`](../../tests/e2e-rust/tests/e2e/lambda_runtimes_docker.rs)

68 of 88 operations are generated from the AWS model (restJson1) and implemented; the rest answer `NotImplemented`. Functions really run.

✅ supported · 🟡 partial · ❌ not supported

## Execution

| Feature | Status | Details |
| --- | :---: | --- |
| Managed runtimes | ✅ | With Docker, every managed runtime (`nodejs*`, `python*`, `java*`, `dotnet*`, `ruby*`, `provided*`) runs in AWS's own Lambda base image for it (`public.ecr.aws/lambda/nodejs:22`, `python:3.13`, `java:21`, ...), pulled on first use or when the function is created. See [base images](#base-images). |
| Local runtimes | 🟡 | Without Docker (or with `MWS_LAMBDA_RUNTIME_EXECUTOR=local`), Python and Node.js functions run on the local `python3`/`node` (`MWS_LAMBDA_PYTHON`/`MWS_LAMBDA_NODE` choose the interpreter) with MWS's runtime client, which loads handlers and reports errors as Lambda does, and `provided.*` functions run their own `bootstrap`. The interpreter's version is whatever is installed, and the AWS SDK is only there if installed. Java, .NET and Ruby need Docker. |
| Custom runtimes | ✅ | `provided.*` functions run their own `bootstrap` (from the package, or a layer's `/opt/bootstrap`) against the Lambda Runtime API. |
| Container images | ✅ | `PackageType: Image` functions pull `ImageUri` from MWS's [ECR](ecr.md) and run in Docker (`MWS_LAMBDA_DOCKER`) against the Lambda Runtime API, as Lambda's base images and custom runtimes expect. See [container images](#container-images). |
| `Invoke` | ✅ | `RequestResponse`, `DryRun`, and `Event` with retries, maximum event age and destinations; also `InvokeAsync`. |
| `InvokeWithResponseStream` | 🟡 | Supported; function URL `RESPONSE_STREAM` responses are buffered. |
| Function states | ✅ | A new function is `Pending` (`StateReasonCode: Creating`) and an update leaves `LastUpdateStatus: InProgress` until it is applied, then `Active` / `Successful`. Meanwhile `Invoke` of a `Pending` function fails with `ResourceConflictException` ("The operation cannot be performed at this time. The function is currently in the following state: Pending"), and `UpdateFunctionCode`, `UpdateFunctionConfiguration` and `PublishVersion` fail with "The operation cannot be performed at this time. An update is in progress for resource: <arn>", so use the `function_active_v2` / `function_updated_v2` waiters as on AWS. Invocations during an update run the code and configuration from before it; service-initiated invocations (SNS, EventBridge, S3, event source mappings, ...) wait for `Active`. The transition takes `MWS_LAMBDA_STATE_TRANSITION_MS` milliseconds (default 1000; `0` completes it at once) on the emulated clock, so moving `/_mws/clock` ahead ends it. CloudFormation waits for it before a function is `CREATE_COMPLETE`. |
| Execution environments | ✅ | Stay warm, honour timeouts and reserved concurrency (every invocation beyond it, warm environment or not, is throttled with `TooManyRequestsException`, `Reason: ReservedFunctionConcurrentInvocationLimitExceeded`; `0` throttles all at once), and get the execution role's STS credentials and an `AWS_ENDPOINT_URL` pointing back at MWS. |
| ABAC | ✅ | Actions on a function carry its tags as `aws:ResourceTag/<key>` (tagging actions and event source mapping actions too, the latter with `lambda:FunctionArn`), for identity and resource policies, Allow and Deny. |
| Logs | ✅ | `START`/`END`/`REPORT` lines, `LogType: Tail`, and CloudWatch Logs groups written as the execution role. |
| Metrics | ✅ | `AWS/Lambda` `Invocations`, `Errors`, `Duration`, `Throttles` and `ConcurrentExecutions` per invocation (by `FunctionName`, `Resource`, `ExecutedVersion` and across functions), and `IteratorAge` for stream mappings, in [CloudWatch](cloudwatch.md). |

## Container images

| Feature | Status | Details |
| --- | :---: | --- |
| `ImageUri` | ✅ | Resolved in ECR by `CreateFunction` and `UpdateFunctionCode`, by tag or digest, in AWS's form (`<account>.dkr.ecr.<region>.amazonaws.com/<repo>:<tag>`) or the host `MWS_ECR_REGISTRY_HOST` names. Missing or invalid images fail with Lambda's `InvalidParameterValueException` wording. `CodeSha256` is the image digest, and `GetFunction` returns `ResolvedImageUri` (`<repo>@sha256:...`). |
| Permissions | ✅ | Setting the code is a pull by the caller: `ecr:BatchGetImage` and `ecr:GetDownloadUrlForLayer` from identity or repository policies, or `AccessDeniedException`. The pull is recorded as `lastRecordedPullTime`. |
| Multi-platform images | ✅ | An index resolves to the manifest for the function's architecture (`x86_64` is `amd64`); without one, the image is not supported. |
| `ImageConfig` | ✅ | `EntryPoint`, `Command` and `WorkingDirectory` each replace only the image's own value. |
| Execution | ✅ | MWS loads the image from ECR's storage into Docker once (`docker load`, tagged `mws-lambda:<digest>`, so no registry login is needed), and runs each execution environment as a container on the host network. The image's `ENV` applies, under Lambda's variables and the function's; the root file system is read-only and `/tmp` is a tmpfs sized by `EphemeralStorage`; memory is limited to `MemorySize`. An entry point that cannot start fails with `Runtime.InvalidEntrypoint`. |
| Networking | ✅ | As for [base images](#base-images): the host's network on Linux, `host.docker.internal` elsewhere, MWS's own network namespace when it runs in a container. |
| Architectures | 🟡 | The image runs on the host's architecture; `arm64` functions on an x86 host need Docker's emulation. |
| Image deletion | 🟡 | A function whose image is deleted from ECR keeps running from Docker's copy; AWS marks it `Failed` (`ImageDeleted`). |

## Base images

| Feature | Status | Details |
| --- | :---: | --- |
| Selection | ✅ | `MWS_LAMBDA_RUNTIME_EXECUTOR`: `auto` (the default) uses the base images when a Docker daemon answers and falls back to local interpreters when it does not or when an image cannot be pulled; `docker` uses only the base images; `local` only local processes. `MWS_LAMBDA_IMAGE_REPOSITORY` points at a mirror. |
| Execution | ✅ | Each execution environment is a container of the base image with the deployment package at `/var/task` and the layers (merged in order) at `/opt`, both read-only. The image's own runtime interface client and entry point start the handler, so the language version, the bundled AWS SDK, error shapes and log format are AWS's. As for container images, the root file system is read-only, `/tmp` is a tmpfs sized by `EphemeralStorage` and memory is limited to `MemorySize`. |
| Architectures | ✅ | An `arm64` function on an x86 host (or the reverse) pulls and runs the image for its own architecture, which needs Docker's emulation. |
| Networking | ✅ | On Linux containers use the host's network. Elsewhere (`MWS_LAMBDA_DOCKER_NETWORK=bridge`) the Runtime API and `AWS_ENDPOINT_URL` go through `host.docker.internal`, which Docker Desktop provides. When MWS itself runs in a container (with the host's Docker socket), function containers join MWS's network namespace and their code and layers are copied into an image per package (`mws-lambda-package:<hash>`) rather than bind-mounted; see [running MWS in a container](../getting-started.md#running-mws-in-a-container). |

## Configuration

| Feature | Status | Details |
| --- | :---: | --- |
| Code | ✅ | Zips uploaded directly or from S3, code downloads, versions, and aliases with weighted routing. |
| Layers | ✅ | Mounted on `PYTHONPATH`/`NODE_PATH`/`PATH`, with layer permissions. |
| Permissions | ✅ | Resource policies (`AddPermission`), `iam:PassRole` and trust policy checks. |
| Other settings | ✅ | Environment variables, tags, event invoke configs, provisioned concurrency, recursion and runtime management settings, code signing configs. |
| Function URLs | ✅ | Serve HTTP at `Host: <id>.lambda-url.<region>.on.aws` or `/_aws/lambda-url/<id>/`, payload format 2.0, CORS, and `AWS_IAM` or `NONE` auth (both `lambda:InvokeFunctionUrl` and `lambda:InvokeFunction` are required, as on AWS). |
| Durable executions | ✅ | Functions with a `DurableConfig` start durable executions (named, idempotent; `Event` or synchronous). MWS keeps the operations the SDK checkpoints, runs waits and step retries on the emulated clock, completes callbacks (with timeouts and heartbeats) and chained invokes, re-invokes the function when an operation it waits for is ready, and records the execution history. |
| Capacity providers | 🟡 | Capacity providers, function scaling configs and the functions using them are managed as in AWS; the functions still run in local execution environments, not on EC2 instances. |
| File systems | ✅ | `FileSystemConfigs` mount the EFS access point at `LocalMountPath` in the execution environment, as the execution role's session, when an invocation starts a container (base images or container images). The function's subnets need an available mount target in one of their zones and VPC whose security groups allow TCP 2049 from the function's groups (`EFSMountConnectivityException` otherwise); the file system policy must allow `elasticfilesystem:ClientMount` (and `ClientWrite`, or the mount is read-only), and the access point's root directory is created from its creation info. Functions running as local processes fail with `EFSMountFailureException`. The POSIX user is not enforced. |
| `PutResourcePolicy` | ✅ | Sets the whole policy of a function or version, shared with `AddPermission`/`GetPolicy`. |

## Asynchronous invocation

| Feature | Status | Details |
| --- | :---: | --- |
| Destinations | ✅ | On success and on failure to Lambda, SQS, SNS and EventBridge, sent as the execution role. |
| Dead-letter queues | ✅ | Events that exhaust their retries go to the function's dead-letter target with Lambda's `RequestID`, `ErrorCode` and `ErrorMessage` attributes. |
| S3 on-failure destinations | ✅ | Records are written as the execution role under `aws/lambda/async/<function>/YYYY/MM/DD/...` (asynchronous invocations) or `aws/lambda/<mapping>/<shard>/...` (stream mappings, with the batch payload). |
| Retries | 🟡 | Function errors are retried `MaximumRetryAttempts` times (after 1 and 2 minutes). Throttled events are retried separately, with backoff from 1 second up to 5 minutes, without using up retry attempts, until they are older than `MaximumEventAgeInSeconds` (6 hours by default, by the emulated clock); only then do they go to the on-failure destination and dead-letter queue (`EventAgeExceeded`). Delays follow the wall clock. |
| Permission checks | 🟡 | Destinations and dead-letter queues are not checked when configured. |
| Recursive loop detection | ✅ | Functions get an X-Ray header in `_X_AMZN_TRACE_ID`, which the SDKs send on; SQS keeps it as `AWSTraceHeader` (also on SNS and S3 deliveries to queues), and SNS subscriptions and S3 notifications carry it to the invocations they cause. Lambda counts each function's invocations in the header's `Lineage` and drops the 17th from an SQS mapping, SNS subscription or S3 notification, unless `RecursiveLoop` is `Allow`, publishing `RecursiveInvocationsDropped`. A dropped asynchronous event goes to the on-failure destination (`RetriesExhausted`, with a `RecursiveInvocationException` response) and dead-letter queue; a dropped SQS batch stays in the queue for its redrive policy. Direct `Invoke` calls pass the header through without counting. |

## Event source mappings

| Feature | Status | Details |
| --- | :---: | --- |
| Polling | ✅ | Mappings poll as soon as they are `Enabled`, however they were made: API calls, CloudFormation, scenario files, or state restored at startup. |
| SQS | ✅ | Polled for real: role permissions and visibility timeout checks, `BatchSize`, `MaximumBatchingWindowInSeconds`, deletes on success, redrive on failure, `ReportBatchItemFailures`. |
| Kinesis | ✅ | Polled for real from `TRIM_HORIZON`, `LATEST` or `AT_TIMESTAMP` (child shards after their parents), each shard read about once a second (at once again while it has a backlog), so other consumers keep their share of its five reads a second, per-shard checkpoints, ordered retries with `MaximumRetryAttempts`, `MaximumRecordAgeInSeconds`, `BisectBatchOnFunctionError`, `ReportBatchItemFailures` and on-failure destinations. `ParallelizationFactor` hashes partition keys into up to 10 lanes per shard that run concurrently, each in order with its own checkpoint and retries; the shard's checkpoint moves past what every lane is done with. |
| Tumbling windows | ✅ | `TumblingWindowInSeconds`: windows aligned to the epoch, by record arrival time; each batch holds one window's records and gets `window`, `state` (what the function returned last in that window, `{}` at first), `shardId`, `eventSourceARN`, `isFinalInvokeForWindow` and `isWindowTerminatedEarly`. Once the window has ended, a final invocation with no records gets the last state; a state over 1 MB ends the window early. With lanes, each lane keeps its own windows. |
| `FilterCriteria` | ✅ | Applied with the EventBridge pattern language; records that match no filter are dropped without invoking the function. |
| Scaling | 🟡 | An SQS mapping runs up to five batches at once to start with, adds one more each poll (every 250 ms) while whole batches keep coming back, and drops back towards five when receives come back empty; it never runs more than `ScalingConfig.MaximumConcurrency` (or 1,250) or the function's reserved concurrency. A FIFO queue returns nothing more from a message group with a batch in flight, so each group stays in order. AWS's scaling rate (up to 300 more per minute) is approximated. |
| Other sources | ❌ | DynamoDB, Kafka, MQ and DocumentDB mappings are stored only. |

See also: [all services](README.md) · [authentication and authorization](../security.md).

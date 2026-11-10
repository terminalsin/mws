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
| Execution environments | ✅ | Stay warm, honour timeouts and reserved concurrency (throttling with `TooManyRequestsException`), and get the execution role's STS credentials and an `AWS_ENDPOINT_URL` pointing back at MWS. |
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
| Networking | 🟡 | As for [base images](#base-images): the host's network on Linux, `host.docker.internal` elsewhere. |
| Architectures | 🟡 | The image runs on the host's architecture; `arm64` functions on an x86 host need Docker's emulation. |
| Image deletion | 🟡 | A function whose image is deleted from ECR keeps running from Docker's copy; AWS marks it `Failed` (`ImageDeleted`). |

## Base images

| Feature | Status | Details |
| --- | :---: | --- |
| Selection | ✅ | `MWS_LAMBDA_RUNTIME_EXECUTOR`: `auto` (the default) uses the base images when a Docker daemon answers and falls back to local interpreters when it does not or when an image cannot be pulled; `docker` uses only the base images; `local` only local processes. `MWS_LAMBDA_IMAGE_REPOSITORY` points at a mirror. |
| Execution | ✅ | Each execution environment is a container of the base image with the deployment package at `/var/task` and the layers (merged in order) at `/opt`, both read-only. The image's own runtime interface client and entry point start the handler, so the language version, the bundled AWS SDK, error shapes and log format are AWS's. As for container images, the root file system is read-only, `/tmp` is a tmpfs sized by `EphemeralStorage` and memory is limited to `MemorySize`. |
| Architectures | ✅ | An `arm64` function on an x86 host (or the reverse) pulls and runs the image for its own architecture, which needs Docker's emulation. |
| Networking | 🟡 | On Linux containers use the host's network. Elsewhere (`MWS_LAMBDA_DOCKER_NETWORK=bridge`) the Runtime API and `AWS_ENDPOINT_URL` go through `host.docker.internal`, which Docker Desktop provides. MWS must share a file system with the Docker daemon, so it cannot itself run in a container with only the Docker socket mounted. |

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
| `PutResourcePolicy` | ✅ | Sets the whole policy of a function or version, shared with `AddPermission`/`GetPolicy`. |

## Asynchronous invocation

| Feature | Status | Details |
| --- | :---: | --- |
| Destinations | ✅ | On success and on failure to Lambda, SQS, SNS and EventBridge, sent as the execution role. |
| Dead-letter queues | ✅ | Events that exhaust their retries go to the function's dead-letter target with Lambda's `RequestID`, `ErrorCode` and `ErrorMessage` attributes. |
| S3 on-failure destinations | ✅ | Records are written as the execution role under `aws/lambda/async/<function>/YYYY/MM/DD/...` (asynchronous invocations) or `aws/lambda/<mapping>/<shard>/...` (stream mappings, with the batch payload). |
| Retries | 🟡 | Retried as Lambda does, but delays follow the wall clock, and throttled events are not kept for six hours. |
| Permission checks | 🟡 | Destinations and dead-letter queues are not checked when configured. |
| Recursive loop detection | ❌ | Configurable, but inert. |

## Event source mappings

| Feature | Status | Details |
| --- | :---: | --- |
| SQS | ✅ | Polled for real: role permissions and visibility timeout checks, `BatchSize`, `MaximumBatchingWindowInSeconds`, deletes on success, redrive on failure, `ReportBatchItemFailures`. |
| Kinesis | ✅ | Polled for real from `TRIM_HORIZON`, `LATEST` or `AT_TIMESTAMP` (child shards after their parents), per-shard checkpoints, ordered retries with `MaximumRetryAttempts`, `MaximumRecordAgeInSeconds`, `BisectBatchOnFunctionError`, `ReportBatchItemFailures` and on-failure destinations. |
| `FilterCriteria` | ✅ | Applied with the EventBridge pattern language; records that match no filter are dropped without invoking the function. |
| Scaling | 🟡 | `ScalingConfig.MaximumConcurrency` is stored but inert. |
| Other sources | ❌ | DynamoDB, Kafka, MQ and DocumentDB mappings are stored only. |

See also: [all services](README.md) · [authentication and authorization](../security.md).

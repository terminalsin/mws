# Amazon Elastic Container Service (ECS)

> Crate: [`mws-ecs`](../../crates/services/mws-ecs) · Tests: [`tests/e2e-rust/tests/e2e/ecs.rs`](../../tests/e2e-rust/tests/e2e/ecs.rs), [`ecs_docker.rs`](../../tests/e2e-rust/tests/e2e/ecs_docker.rs), [`ecs_roles.rs`](../../tests/e2e-rust/tests/e2e/ecs_roles.rs)

All 88 operations of the model are generated (awsJson 1.1) and implemented.

✅ supported · 🟡 partial · ❌ not supported

## Clusters and task definitions

| Feature | Status | Details |
| --- | :---: | --- |
| Clusters | ✅ | Settings (Container Insights defaults from the account setting), configuration, capacity providers and default strategies, Service Connect defaults, counts and statistics, `INACTIVE` after delete, the `ClusterContains*` errors. |
| Task definitions | ✅ | Revisions per family, ECS's defaults (`essential`, host ports for `awsvpc`), validation with ECS's `ClientException` messages, Fargate CPU and memory combinations, `requiresAttributes`, compatibilities, deregistration and `DeleteTaskDefinitions`. |
| Capacity providers | ✅ | `FARGATE` and `FARGATE_SPOT`, Auto Scaling group providers backed by real EC2 Auto Scaling groups, Managed Instances providers (metadata), strategies with base and weight. |
| Account settings, attributes, tags | ✅ | Every setting with account and principal scope and defaults; custom attributes; tags with the `ecs:CreateAction` check. |

## Tasks

| Feature | Status | Details |
| --- | :---: | --- |
| Lifecycle | ✅ | `RunTask` and `StartTask` with launch types and capacity provider strategies; `PROVISIONING` → `PENDING` → `ACTIVATING` → `RUNNING` → `DEACTIVATING` → `STOPPING` → `DEPROVISIONING` → `STOPPED` with ECS's stop codes and reasons; stopped tasks stay visible for an hour on the emulated clock; overrides, tags and tag propagation; task protection. |
| Docker backend | ✅ | `MWS_ECS_BACKEND=docker` runs each container as a Docker container: `dependsOn` order and conditions, health checks, essential containers ending the task, exit codes, volumes, port mappings for `bridge`. Podman works too. |
| Metadata backend | ✅ | `MWS_ECS_BACKEND=metadata` runs nothing; tasks reach `RUNNING` at once and stop when asked. |
| awsvpc networking | ✅ | Each task gets a requester-managed EC2 network interface with a private IP from its subnet, visible in `DescribeNetworkInterfaces` and deleted when the task stops. With Docker its containers share a network namespace on the VPC's Docker network. |
| Task and execution roles | ✅ | Roles are assumed by `ecs-tasks.amazonaws.com` (trust policies enforced). The execution role is assumed whenever the task definition names one. Containers get the task role's session from the credentials endpoint (`AWS_CONTAINER_CREDENTIALS_FULL_URI`), never as keys in the environment; the endpoint hands out a new session when the current one is within 30 minutes of expiring. |
| Image pulls | ✅ | ECR images (`<account>.dkr.ecr.<region>.amazonaws.com/...` or MWS's registry host) come from MWS's own registry as the execution role: `ecr:GetAuthorizationToken`, then `ecr:BatchGetImage` and `ecr:GetDownloadUrlForLayer` under identity and repository policy. A denied login stops the task with `ResourceInitializationError: ... unable to retrieve ecr registry auth`, a denied or missing image with `CannotPullContainerError`. With Docker the image is `docker load`ed from the registry's content (tagged `mws-ecs:<digest>`), so deleted images no longer start. Fargate task definitions with ECR images need an execution role. Other images are pulled from their registry, logged in with the `repositoryCredentials` secret. |
| Secrets | ✅ | The execution role reads `secrets` from Secrets Manager (JSON keys, staging labels, version ids) and Parameter Store. |
| `awslogs` | ✅ | Container output lands in CloudWatch Logs as `prefix/container/task-id`, written as the execution role; `awslogs-create-group` is honoured. |
| Task metadata endpoint | ✅ | Version 4 (and the v3 path) at `/_aws/ecs/metadata/<task-id>/<container>`: container and task metadata and stats; `ECS_CONTAINER_METADATA_URI_V4` is set in every container. |
| ECS Exec | 🟡 | `ExecuteCommand` returns a session and runs the command through the backend when the task has `enableExecuteCommand` and its task role allows `ssmmessages:CreateControlChannel`, `CreateDataChannel`, `OpenControlChannel` and `OpenDataChannel` (otherwise `TargetNotConnectedException`, as when the SSM agent cannot connect); there is no interactive Session Manager stream. |
| Agent APIs | ✅ | `DiscoverPollEndpoint`, `SubmitTaskStateChange`, `SubmitContainerStateChange` and `SubmitAttachmentStateChanges` are accepted. |

## Services

| Feature | Status | Details |
| --- | :---: | --- |
| Scheduler | ✅ | Keeps `REPLICA` services at their desired count and `DAEMON` services on every active container instance; replaces stopped and unhealthy tasks; drains on delete. |
| Rolling deployments | ✅ | Within `minimumHealthyPercent` and `maximumPercent`, with ECS's service events ("has started 2 tasks", "has reached a steady state"). Behind a load balancer a task counts as healthy (for the minimum, steady state and completion) only once its targets are `healthy`; with the metadata backend nothing answers health checks, so registered targets count as healthy. |
| Circuit breaker | ✅ | Failed launches past ECS's threshold fail the rollout, with rollback when enabled. Tasks replaced for failing ELB health checks before they ever passed count as failed launches. |
| Service deployments and revisions | ✅ | `ListServiceDeployments`, `DescribeServiceDeployments`, `DescribeServiceRevisions`, `StopServiceDeployment` (rollback), `ContinueServiceDeployment`. |
| Task sets | ✅ | `EXTERNAL` and `CODE_DEPLOY` controllers, scale, primary task set, stability status. |
| Load balancers | ✅ | `CreateService` and `UpdateService` check `loadBalancers` with ECS's `InvalidParameterException` messages: the target group exists, a load balancer forwards to it, its target type suits the network mode (`ip` for `awsvpc`, `instance` otherwise), and the container and port are in the task definition. Running service tasks register with their Elastic Load Balancing target groups (the task ENI IP for `awsvpc`, the instance and host port otherwise) and deregister when they stop; after the health check grace period, tasks the target group reports unhealthy are stopped and replaced, with ECS's service event. |
| Service Connect, Cloud Map | 🟡 | Recorded on services and revisions; nothing is registered in Cloud Map and no proxy runs. |
| Service auto scaling | ❌ | Application Auto Scaling is not emulated. |

## Container instances

| Feature | Status | Details |
| --- | :---: | --- |
| Registration | ✅ | Registered resources (CPU, memory, ports) and attributes, draining, deregistration with `force`. |
| Placement | ✅ | binpack, spread and random strategies, `distinctInstance` and `memberOf` with the cluster query language, `RESOURCE:CPU`, `RESOURCE:MEMORY` and `RESOURCE:PORTS` failures. |
| Instances from capacity providers | ✅ | Instances an Auto Scaling group provider's group launches join the cluster, sized by their instance type, and leave it when they terminate. With managed scaling, ECS sets the group's desired capacity from its target capacity: it grows when tasks have no room and shrinks after fifteen minutes of lower need. |

## Daemons, gateways and Express services

| Feature | Status | Details |
| --- | :---: | --- |
| Daemons | 🟡 | Daemon task definitions, daemons, revisions and deployments; deployments complete at once and no daemon tasks run. |
| Gateways | 🟡 | Gateways, cluster associations and routes for services with gateway connectors; no load balancer receives traffic. |
| Express services | 🟡 | Creates the cluster when missing, registers the task definition and runs a real Fargate service; a real Application Load Balancer, target group (with the health check path) and HTTP listener are created and deleted with the service. No ACM certificate or HTTPS listener and no auto scaling policy is created. |

## Terminal and files

The console's task page has Terminal and Files tabs for each container, using `/_aws/ecs/tasks/<cluster>/<task-id>/<container>/...`. This endpoint is MWS's own, not an AWS API. As with ECS Exec, it needs `ecs:ExecuteCommand` on the task, and the task must have been run with `enableExecuteCommand`. Tasks and services the console starts turn that on. The Logs tab reads the container's `awslogs` stream from CloudWatch Logs.

Requests are SigV4 signed like any AWS call. Each one runs a short `sh` script in the container with `docker exec` as root; it is not an interactive PTY. The routes, relative to the resource:

| Request | Effect |
| --- | --- |
| `POST exec` `{"command", "cwd"?}` | Runs a command. Returns `{"stdout", "stderr", "exitCode", "cwd"}`; `cwd` is the directory after the command, so `cd` carries over. |
| `GET files?path=` | Lists a directory: name, `file`/`dir`/`link`, size, modified time, mode. |
| `GET file?path=` | Returns the file's bytes, up to 8 MiB. `x-mws-truncated` is set when the file is longer. |
| `PUT file?path=` | Writes the body to the file, creating its directory. |
| `DELETE file?path=` | Removes the file or directory. |
| `POST dir?path=` | Creates a directory. |

## Access control

| Feature | Status | Details |
| --- | :---: | --- |
| IAM | ✅ | Every call is authorized with ECS's resources and condition keys (`ecs:cluster`, `ecs:task-definition`, `ecs:container-instances`, tags). |
| `iam:PassRole` | ✅ | Checked by `RunTask`, `StartTask`, `CreateService` and `UpdateService` (task and execution roles, with `iam:PassedToService` `ecs-tasks.amazonaws.com`; a service's legacy `role` with `ecs.amazonaws.com`), gateways and Express services. |

## Known gaps

- With Docker, containers outside the host network reach the credentials endpoint at `169.254.170.2` through the internal Docker network `mws-ecs-credentials` (its gateway is the host), so MWS must listen on that address (all interfaces). ECS sets `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` (port 80); MWS sets `AWS_CONTAINER_CREDENTIALS_FULL_URI` with its own port instead.
- EC2 launch type tasks without an execution role pull ECR images without a permission check: the container instance role is not modelled.
- No `aws.ecs` events reach EventBridge (`ECS Task State Change`, `ECS Service Action`, `ECS Deployment State Change`) and no `AWS/ECS` metrics reach CloudWatch.
- Stopping tasks do not wait for target deregistration (`deregistration_delay`).

See also: [all services](README.md) · [EC2 and VPC](ec2.md) · [configuration](../configuration.md).

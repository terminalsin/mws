# Amazon Elastic Container Service (ECS)

> Crate: [`mws-ecs`](../../crates/services/mws-ecs) · Tests: [`tests/e2e-rust/tests/e2e/ecs.rs`](../../tests/e2e-rust/tests/e2e/ecs.rs), [`ecs_docker.rs`](../../tests/e2e-rust/tests/e2e/ecs_docker.rs)

All 88 operations of the model are generated (awsJson 1.1) and implemented.

## Behaviour

| Feature | Status | Details |
| --- | --- | --- |
| Clusters | Full | Settings (Container Insights defaults from the account setting), configuration, capacity providers and default strategies, Service Connect defaults, counts and statistics, `INACTIVE` after delete, the `ClusterContains*` errors |
| Task definitions | Full | Revisions per family, ECS's defaults (`essential`, host ports for `awsvpc`), validation with ECS's `ClientException` messages, Fargate CPU/memory combinations, `requiresAttributes`, compatibilities, deregistration and `DeleteTaskDefinitions` |
| Tasks | Full | `RunTask` and `StartTask` with launch types and capacity provider strategies, the lifecycle `PROVISIONING` → `PENDING` → `ACTIVATING` → `RUNNING` → `DEACTIVATING` → `STOPPING` → `DEPROVISIONING` → `STOPPED`, stop codes and reasons, stopped tasks visible for an hour on the emulated clock, overrides, tags and propagation, task protection |
| Running containers | Docker backend | `MWS_ECS_BACKEND=docker` runs each container as a Docker container (`dependsOn` order and conditions, health checks, essential containers ending the task, exit codes, volumes, port mappings for `bridge`); `metadata` runs nothing and tasks reach `RUNNING` at once |
| awsvpc networking | Full | Each task gets a requester-managed EC2 network interface with a private IP from its subnet (visible in `DescribeNetworkInterfaces`, deleted when the task stops); with Docker its containers share a network namespace on the VPC's network |
| Roles, secrets, logs | Full | The task role is assumed by `ecs-tasks.amazonaws.com` (trust policy enforced) and its session handed to containers; the execution role reads `secrets` from Secrets Manager (JSON keys, stages, versions) and Parameter Store, and `awslogs` output lands in CloudWatch Logs as `prefix/container/task-id` |
| Task metadata endpoint | Full | Version 4 (and the v3 path) at `/_aws/ecs/metadata/<task-id>/<container>`: container and task metadata, stats, and `ECS_CONTAINER_METADATA_URI_V4` in every container |
| Services | Full | The scheduler keeps `REPLICA` services at their desired count and `DAEMON` services on every instance; rolling deployments within `minimumHealthyPercent`/`maximumPercent`, events ("has reached a steady state", "has started 2 tasks"), the deployment circuit breaker with rollback, unhealthy task replacement, draining on delete |
| Service deployments and revisions | Full | `ListServiceDeployments`, `DescribeServiceDeployments`, `DescribeServiceRevisions`, `StopServiceDeployment` (rollback), `ContinueServiceDeployment` |
| Task sets | Full | `EXTERNAL` and `CODE_DEPLOY` controllers, scale, primary task set, stability status |
| Container instances | Full | Registration with resources and attributes, placement (binpack, spread, random, `distinctInstance`, `memberOf` with the cluster query language), `RESOURCE:CPU`/`MEMORY`/`PORTS` failures, draining, deregistration |
| Capacity providers | Full | `FARGATE` and `FARGATE_SPOT`, Auto Scaling group and Managed Instances providers (metadata) |
| Account settings, attributes, tags | Full | All settings with account and principal scope and defaults; custom attributes; tags with `ecs:CreateAction` checks |
| Daemons | Control plane | Daemon task definitions, daemons, revisions and deployments (deployments complete at once; no daemon tasks run) |
| Gateways | Control plane | Gateways, cluster associations and routes for services with gateway connectors; no load balancer receives traffic |
| Express services | Partial | Creates the cluster when missing, registers the task definition and runs a real Fargate service; the endpoint URL is reported but no load balancer, certificate or auto scaling is created |
| IAM | Full | Every call is authorized with ECS's resources and condition keys (`ecs:cluster`, `ecs:task-definition`, `ecs:container-instances`, tags); `RunTask`, `StartTask`, gateways and Express services check `iam:PassRole` |

The agent-facing APIs (`DiscoverPollEndpoint`, `Submit*StateChange`) are
accepted; `ExecuteCommand` returns a session and runs the command through the
backend when the task has `enableExecuteCommand`.

## Known gaps

Load balancers, Service Connect and Cloud Map registration are recorded but no
traffic is routed; service auto scaling is not applied; EC2 container
instances are not launched for Auto Scaling group capacity providers (register
them with `RegisterContainerInstance`); daemon tasks do not run; `bridge`
networking has no ECS agent features such as dynamic port reuse limits; Fargate
ephemeral storage, GPU and inference accelerator settings are not enforced.

See also: [all services](README.md) · [EC2 and VPC](ec2.md) · [configuration](../configuration.md).

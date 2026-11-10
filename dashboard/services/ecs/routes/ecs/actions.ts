"use server";

import { CreateLogGroupCommand } from "@aws-sdk/client-cloudwatch-logs";
import {
  CreateClusterCommand,
  DeleteTaskDefinitionsCommand,
  UpdateClusterSettingsCommand,
  CreateServiceCommand,
  DeleteClusterCommand,
  DeleteServiceCommand,
  DeregisterTaskDefinitionCommand,
  RegisterTaskDefinitionCommand,
  RunTaskCommand,
  StopServiceDeploymentCommand,
  StopTaskCommand,
  UpdateServiceCommand,
} from "@aws-sdk/client-ecs";
import { ensureRole, type RoleSpec } from "@mws-dashboard/aws/auto";
import { act, checkFailures, FieldError, region, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { ecs, logs } from "../../lib/clients";
import { taskDefHref } from "../../lib/ecs";
import { defaultNetwork } from "../../lib/network";

// ECS names the parameter it rejects only in prose, so its messages are
// matched to the form's fields here: the problem then shows on that field.
const send = async <T>(run: () => Promise<T>, fields: [RegExp, string, ("taken" | "missing")?][]): Promise<T> => {
  try {
    return await run();
  } catch (e) {
    if (e instanceof FieldError) throw e;
    const message = e instanceof Error ? e.message : "";
    const hit = fields.find(([re]) => re.test(message));
    if (hit) throw new FieldError(hit[1], hit[2] === "taken" ? "Already exists" : message, hit[2] ?? "server");
    throw e;
  }
};

const TASK_DEFINITION: [RegExp, string, "missing"] = [/task definition/i, "taskDefinition", "missing"];

/** What Fargate needs to pull images and send awslogs output (AWS's
 * ecsTaskExecutionRole, with AmazonECSTaskExecutionRolePolicy's permissions). */
const EXECUTION_ROLE: RoleSpec = {
  name: "ecsTaskExecutionRole",
  service: "ecs-tasks.amazonaws.com",
  statements: [{ Effect: "Allow", Action: ["ecr:GetAuthorizationToken", "ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer", "ecr:BatchGetImage", "logs:CreateLogStream", "logs:PutLogEvents"], Resource: "*" }],
};

const clusterHref = (name: string) => `/ecs/cluster?name=${encodeURIComponent(name)}`;

export async function createCluster(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Cluster name");
    const client = await ecs();
    await send(
      () => client.send(new CreateClusterCommand({ clusterName: name, settings: [{ name: "containerInsights", value: text(form, "insights") === "on" ? "enabled" : "disabled" }] })),
      [[/cluster name/i, "name"]],
    );
    redirect(clusterHref(name));
  });
}

export async function deleteCluster(name: string) {
  return act(async () => {
    await (await ecs()).send(new DeleteClusterCommand({ cluster: name }));
    redirect("/ecs");
  });
}

export async function registerTaskDefinition(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const family = required(form, "family", "Family");
    const port = text(form, "port");
    const image = required(form, "image", "Image");
    const environment = text(form, "env")
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .map((l) => ({ name: l.slice(0, l.indexOf("=")), value: l.slice(l.indexOf("=") + 1) }));
    const container = text(form, "container") || family;
    // awslogs into /ecs/<family>, so the task's Logs tab has something to show.
    const logGroup = `/ecs/${family}`;
    if (text(form, "logs") === "on") {
      await (await logs()).send(new CreateLogGroupCommand({ logGroupName: logGroup })).catch((e) => {
        if (!(e instanceof Error && e.name === "ResourceAlreadyExistsException")) throw e;
      });
    }
    const awsRegion = await region();
    const executionRoleArn = text(form, "logs") === "on" ? await ensureRole(EXECUTION_ROLE) : undefined;
    const client = await ecs();
    await send(
      () =>
        client.send(
          new RegisterTaskDefinitionCommand({
            family,
            executionRoleArn,
            requiresCompatibilities: ["FARGATE"],
            networkMode: "awsvpc",
            cpu: text(form, "cpu") || "256",
            memory: text(form, "memory") || "512",
            containerDefinitions: [
              {
                name: container,
                image,
                essential: true,
                environment: environment.length ? environment : undefined,
                logConfiguration:
                  text(form, "logs") === "on"
                    ? { logDriver: "awslogs", options: { "awslogs-group": logGroup, "awslogs-region": awsRegion, "awslogs-stream-prefix": "ecs" } }
                    : undefined,
                portMappings: port ? [{ containerPort: Number(port), protocol: "tcp" }] : undefined,
                command: text(form, "command") ? text(form, "command").split(" ") : undefined,
              },
            ],
          }),
        ),
      [
        [/family/i, "family"],
        [/Fargate configuration/i, "memory"],
        [/image/i, "image"],
      ],
    );
    return `Registered ${family}`;
  }, "/ecs");
}

export async function deregisterTaskDefinition(arn: string) {
  return act(async () => {
    await (await ecs()).send(new DeregisterTaskDefinitionCommand({ taskDefinition: arn }));
    return `Deregistered ${arn.split("/").pop()}`;
  }, "/ecs", "/ecs/taskdef");
}

/** Delete INACTIVE revisions for good (DeleteTaskDefinitions answers
 * per-revision failures). */
export async function deleteTaskDefinitions(arns: string[]) {
  return act(async () => {
    const out = await (await ecs()).send(new DeleteTaskDefinitionsCommand({ taskDefinitions: arns }));
    checkFailures(out.failures, (f) => `${f.arn?.split("/").pop()}: ${f.reason}`);
    return arns.length === 1 ? `Deleting ${arns[0].split("/").pop()}` : `Deleting ${arns.length} revisions`;
  }, "/ecs", "/ecs/taskdef");
}

// What DescribeTaskDefinition answers that RegisterTaskDefinition does not take.
const READ_ONLY = ["taskDefinitionArn", "revision", "status", "requiresAttributes", "compatibilities", "registeredAt", "registeredBy", "deregisteredAt", "deleteRequestedAt"];

/** A new revision from the JSON of the current one, edited (AWS: Create
 * new revision → JSON). */
export async function registerRevision(family: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    let input: Record<string, unknown>;
    try {
      input = JSON.parse(required(form, "json", "Task definition"));
    } catch (e) {
      throw new FieldError("json", e instanceof Error ? e.message : "Not JSON", "format");
    }
    if (!input || typeof input !== "object" || Array.isArray(input)) throw new FieldError("json", "A task definition is a JSON object", "format");
    for (const k of READ_ONLY) delete input[k];
    if (input.family && input.family !== family) throw new FieldError("json", `family must stay ${family}`);
    const client = await ecs();
    const out = await send(
      () => client.send(new RegisterTaskDefinitionCommand({ ...(input as object), family } as ConstructorParameters<typeof RegisterTaskDefinitionCommand>[0])),
      [[/./, "json"]],
    );
    redirect(taskDefHref(out.taskDefinition?.taskDefinitionArn));
  });
}

export async function updateClusterInsights(cluster: string, enabled: boolean) {
  return act(async () => {
    await (await ecs()).send(new UpdateClusterSettingsCommand({ cluster, settings: [{ name: "containerInsights", value: enabled ? "enabled" : "disabled" }] }));
    return enabled ? "Container Insights on" : "Container Insights off";
  }, "/ecs/cluster");
}

export async function createService(cluster: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Service name");
    const taskDefinition = required(form, "taskDefinition", "Task definition");
    const client = await ecs();
    const network = await defaultNetwork();
    await send(
      () =>
        client.send(
          new CreateServiceCommand({
            cluster,
            serviceName: name,
            taskDefinition,
            desiredCount: Number(text(form, "desired") || 1),
            launchType: (text(form, "launchType") || "FARGATE") as "FARGATE" | "EC2",
            networkConfiguration: network,
            enableExecuteCommand: true,
          }),
        ),
      [[/not idempotent/i, "name", "taken"], [/service name/i, "name"], [/desired ?count/i, "desired"], TASK_DEFINITION],
    );
    return `Created ${name}`;
  }, "/ecs/cluster");
}

export async function scaleService(cluster: string, service: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const desiredCount = Number(required(form, "desired", "Desired tasks"));
    const client = await ecs();
    await send(() => client.send(new UpdateServiceCommand({ cluster, service, desiredCount })), [[/desired ?count/i, "desired"]]);
    return `Desired tasks: ${desiredCount}`;
  }, "/ecs/cluster", "/ecs/service");
}

/** Deploy: a new task definition revision, a new desired count, or the same
 * definition again (force new deployment, e.g. to pull a moved image tag). */
export async function updateService(cluster: string, service: string, was: { taskDefinition?: string; desired?: number }, _: ActionResult | null, form: FormData) {
  return act(
    async () => {
      const taskDefinition = text(form, "taskDefinition") || undefined;
      const desiredCount = text(form, "desired") === "" ? undefined : Number(text(form, "desired"));
      const force = text(form, "force") === "on";
      const changedDef = taskDefinition && taskDefinition !== was.taskDefinition ? taskDefinition : undefined;
      const changedCount = desiredCount !== undefined && desiredCount !== was.desired ? desiredCount : undefined;
      if (!changedDef && changedCount === undefined && !force) throw new Error("Nothing changed: pick a revision, a count, or force a new deployment");
      const client = await ecs();
      await send(
        () => client.send(new UpdateServiceCommand({ cluster, service, taskDefinition: changedDef, desiredCount: changedCount, forceNewDeployment: force || undefined })),
        [[/desired ?count/i, "desired"], TASK_DEFINITION],
      );
      return changedDef ? `Deploying ${changedDef.split("/").pop()}` : force ? "New deployment started" : `Desired tasks: ${changedCount}`;
    },
    "/ecs/cluster",
    "/ecs/service",
  );
}

export async function deleteService(cluster: string, service: string, leave: boolean) {
  return act(async () => {
    await (await ecs()).send(new DeleteServiceCommand({ cluster, service, force: true }));
    if (leave) redirect(clusterHref(cluster));
    return "Service deleted";
  }, "/ecs/cluster");
}

export async function runTask(cluster: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const client = await ecs();
    const input = {
      cluster,
      taskDefinition: required(form, "taskDefinition", "Task definition"),
      count: Number(text(form, "count") || 1),
      launchType: (text(form, "launchType") || "FARGATE") as "FARGATE" | "EC2",
      networkConfiguration: await defaultNetwork(),
      enableExecuteCommand: true,
    };
    const out = await send(() => client.send(new RunTaskCommand(input)), [[/count/i, "count"], TASK_DEFINITION]);
    if (out.failures?.length) throw new Error(out.failures.map((f) => f.reason).join(", "));
    return `Started ${out.tasks?.length ?? 0} task(s)`;
  }, "/ecs/cluster");
}

export async function stopTask(cluster: string, task: string) {
  return act(async () => {
    await (await ecs()).send(new StopTaskCommand({ cluster, task, reason: "Stopped in the console" }));
    return "Stopping";
  }, "/ecs/cluster", "/ecs/task", "/ecs/service");
}

/** Roll a service deployment back (or abort it where it is). */
export async function stopDeployment(arn: string, stopType: "ROLLBACK" | "ABORT") {
  return act(async () => {
    await (await ecs()).send(new StopServiceDeploymentCommand({ serviceDeploymentArn: arn, stopType }));
    return stopType === "ROLLBACK" ? "Rolling back" : "Stopping the deployment";
  }, "/ecs/service");
}

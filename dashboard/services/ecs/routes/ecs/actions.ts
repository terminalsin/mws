"use server";

import {
  CreateClusterCommand,
  CreateServiceCommand,
  DeleteClusterCommand,
  DeleteServiceCommand,
  DeregisterTaskDefinitionCommand,
  RegisterTaskDefinitionCommand,
  RunTaskCommand,
  StopTaskCommand,
  UpdateServiceCommand,
} from "@aws-sdk/client-ecs";
import { act, FieldError, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { ecs } from "../../lib/clients";
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
    const client = await ecs();
    await send(
      () =>
        client.send(
          new RegisterTaskDefinitionCommand({
            family,
            requiresCompatibilities: ["FARGATE"],
            networkMode: "awsvpc",
            cpu: text(form, "cpu") || "256",
            memory: text(form, "memory") || "512",
            containerDefinitions: [
              {
                name: text(form, "container") || family,
                image,
                essential: true,
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
    return "Deregistered";
  }, "/ecs");
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
  }, "/ecs/cluster");
}

export async function deleteService(cluster: string, service: string) {
  return act(async () => {
    await (await ecs()).send(new DeleteServiceCommand({ cluster, service, force: true }));
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
  }, "/ecs/cluster");
}

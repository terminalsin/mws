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
import { act, required, text, type ActionResult } from "@mws-dashboard/aws";
import { redirect } from "next/navigation";

import { ecs } from "../../lib/clients";
import { defaultNetwork } from "../../lib/network";

const clusterHref = (name: string) => `/ecs/cluster?name=${encodeURIComponent(name)}`;

export async function createCluster(_: ActionResult | null, form: FormData) {
  return act(async () => {
    const name = required(form, "name", "Cluster name");
    await (await ecs()).send(new CreateClusterCommand({ clusterName: name, settings: [{ name: "containerInsights", value: text(form, "insights") === "on" ? "enabled" : "disabled" }] }));
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
    await (await ecs()).send(
      new RegisterTaskDefinitionCommand({
        family,
        requiresCompatibilities: ["FARGATE"],
        networkMode: "awsvpc",
        cpu: text(form, "cpu") || "256",
        memory: text(form, "memory") || "512",
        containerDefinitions: [
          {
            name: text(form, "container") || family,
            image: required(form, "image", "Image"),
            essential: true,
            portMappings: port ? [{ containerPort: Number(port), protocol: "tcp" }] : undefined,
            command: text(form, "command") ? text(form, "command").split(" ") : undefined,
          },
        ],
      }),
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
    await (await ecs()).send(
      new CreateServiceCommand({
        cluster,
        serviceName: name,
        taskDefinition: required(form, "taskDefinition", "Task definition"),
        desiredCount: Number(text(form, "desired") || 1),
        launchType: (text(form, "launchType") || "FARGATE") as "FARGATE" | "EC2",
        networkConfiguration: await defaultNetwork(),
        enableExecuteCommand: true,
      }),
    );
    return `Created ${name}`;
  }, "/ecs/cluster");
}

export async function scaleService(cluster: string, service: string, _: ActionResult | null, form: FormData) {
  return act(async () => {
    const desiredCount = Number(required(form, "desired", "Desired tasks"));
    await (await ecs()).send(new UpdateServiceCommand({ cluster, service, desiredCount }));
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
    const out = await (await ecs()).send(
      new RunTaskCommand({ cluster, taskDefinition: required(form, "taskDefinition", "Task definition"), count: Number(text(form, "count") || 1), launchType: (text(form, "launchType") || "FARGATE") as "FARGATE" | "EC2", networkConfiguration: await defaultNetwork(), enableExecuteCommand: true }),
    );
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

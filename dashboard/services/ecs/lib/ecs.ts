import "server-only";

import {
  DescribeClustersCommand,
  DescribeServicesCommand,
  DescribeTasksCommand,
  ListClustersCommand,
  ListServicesCommand,
  ListTaskDefinitionFamiliesCommand,
  ListTaskDefinitionsCommand,
  ListTasksCommand,
  type DesiredStatus,
  type Service,
  type Task,
} from "@aws-sdk/client-ecs";
import { all } from "@mws-dashboard/aws";

import { ecs } from "./clients";

const chunks = <T>(list: T[], size: number) => Array.from({ length: Math.ceil(list.length / size) }, (_, i) => list.slice(i * size, (i + 1) * size));

/** Every cluster, described (DescribeClusters takes 100 at a time). */
export async function clusters(include: ("SETTINGS" | "STATISTICS" | "TAGS" | "CONFIGURATIONS")[] = []) {
  const client = await ecs();
  const arns = await all((nextToken) => client.send(new ListClustersCommand({ nextToken })), (r) => r.clusterArns, (r) => r.nextToken);
  const pages = await Promise.all(chunks(arns, 100).map((c) => client.send(new DescribeClustersCommand({ clusters: c, include: include.length ? include : undefined }))));
  return pages.flatMap((p) => p.clusters ?? []);
}

/** Every service of a cluster, described (DescribeServices takes 10 at a time). */
export async function services(cluster: string): Promise<Service[]> {
  const client = await ecs();
  const arns = await all((nextToken) => client.send(new ListServicesCommand({ cluster, nextToken })), (r) => r.serviceArns, (r) => r.nextToken);
  const pages = await Promise.all(chunks(arns, 10).map((c) => client.send(new DescribeServicesCommand({ cluster, services: c, include: ["TAGS"] }))));
  return pages.flatMap((p) => p.services ?? []).sort((a, b) => (a.serviceName ?? "").localeCompare(b.serviceName ?? ""));
}

/** A cluster's tasks in one desired state (ListTasks lists only RUNNING
 * unless asked), described 100 at a time. */
export async function tasks(cluster: string, desiredStatus: DesiredStatus, serviceName?: string): Promise<Task[]> {
  const client = await ecs();
  const arns = await all((nextToken) => client.send(new ListTasksCommand({ cluster, desiredStatus, serviceName, nextToken })), (r) => r.taskArns, (r) => r.nextToken);
  const pages = await Promise.all(chunks(arns, 100).map((c) => client.send(new DescribeTasksCommand({ cluster, tasks: c }))));
  return pages.flatMap((p) => p.tasks ?? []).sort((a, b) => (b.createdAt?.getTime() ?? 0) - (a.createdAt?.getTime() ?? 0));
}

/** A family's revisions, newest first. `familyPrefix` is a prefix match,
 * so revisions of other families that start the same are dropped. */
export async function revisions(family: string, status: "ACTIVE" | "INACTIVE" | "DELETE_IN_PROGRESS" = "ACTIVE") {
  const client = await ecs();
  const arns = await all(
    (nextToken) => client.send(new ListTaskDefinitionsCommand({ familyPrefix: family, status, sort: "DESC", nextToken })),
    (r) => r.taskDefinitionArns,
    (r) => r.nextToken,
  );
  return arns.filter((a) => familyOf(a) === family);
}

export async function families(status: "ACTIVE" | "INACTIVE" | "ALL" = "ACTIVE") {
  const client = await ecs();
  return all((nextToken) => client.send(new ListTaskDefinitionFamiliesCommand({ status, nextToken })), (r) => r.families, (r) => r.nextToken);
}

/** Every ACTIVE revision, newest first (for the run/service pickers). */
export async function activeDefinitions() {
  const client = await ecs();
  return all(
    (nextToken) => client.send(new ListTaskDefinitionsCommand({ status: "ACTIVE", sort: "DESC", nextToken })),
    (r) => r.taskDefinitionArns,
    (r) => r.nextToken,
  );
}

/** "web:3" from a task definition ARN. */
export const revisionOf = (arn: string | undefined) => arn?.split("/").pop() ?? "";
export const familyOf = (arn: string | undefined) => revisionOf(arn).replace(/:\d+$/, "");
export const taskDefHref = (arn: string | undefined) => {
  const r = revisionOf(arn);
  const [family, rev] = r.split(":");
  return `/ecs/taskdef?family=${encodeURIComponent(family)}${rev ? `&revision=${rev}` : ""}`;
};
export const serviceHref = (cluster: string, service: string) => `/ecs/service?cluster=${encodeURIComponent(cluster)}&name=${encodeURIComponent(service)}`;
export const taskHref = (cluster: string, arn: string) => `/ecs/task?cluster=${encodeURIComponent(cluster)}&id=${arn.split("/").pop()}`;

/** How a service is doing: its own status, then the primary deployment's
 * rollout, then whether the counts match. */
export function serviceHealth(s: Service): { tone: "good" | "warn" | "bad" | "neutral"; text: string } {
  const primary = s.deployments?.find((d) => d.status === "PRIMARY");
  if (s.status && s.status !== "ACTIVE") return { tone: "neutral", text: s.status.toLowerCase() };
  if (primary?.rolloutState === "FAILED") return { tone: "bad", text: "rollout failed" };
  if (primary?.rolloutState === "IN_PROGRESS" || (s.deployments?.length ?? 0) > 1) return { tone: "warn", text: "deploying" };
  if (s.runningCount === s.desiredCount) return { tone: "good", text: `${s.runningCount}/${s.desiredCount} tasks` };
  return { tone: "warn", text: `${s.runningCount}/${s.desiredCount} tasks` };
}

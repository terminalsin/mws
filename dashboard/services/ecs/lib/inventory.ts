import "server-only";

import { tagMap, type InventoryItem } from "@mws-dashboard/aws";

import { clusters, serviceHealth, serviceHref, services } from "./ecs";

const tags = (list: { key?: string; value?: string }[] | undefined) => tagMap((list ?? []).map((t) => ({ Key: t.key, Value: t.value })));

export async function ecsClusters(): Promise<InventoryItem[]> {
  const list = await clusters(["TAGS"]);
  return list.map((c) => ({
    service: "ecs",
    type: "ECS cluster",
    id: c.clusterArn!,
    name: c.clusterName!,
    href: `/ecs/cluster?name=${encodeURIComponent(c.clusterName!)}`,
    detail: `${c.activeServicesCount ?? 0} services · ${c.runningTasksCount ?? 0} running`,
    tags: tags(c.tags),
    signal: c.status && c.status !== "ACTIVE" ? { tone: "warn" as const, text: c.status.toLowerCase() } : undefined,
  }));
}

export async function ecsServices(): Promise<InventoryItem[]> {
  const list = await clusters();
  const all = await Promise.all(list.map(async (c) => (await services(c.clusterName!)).map((s) => ({ s, cluster: c.clusterName! }))));
  return all.flat().map(({ s, cluster }) => {
    const health = serviceHealth(s);
    return {
      service: "ecs",
      type: "ECS service",
      id: s.serviceArn!,
      name: s.serviceName!,
      href: serviceHref(cluster, s.serviceName!),
      detail: `${cluster} · ${s.runningCount ?? 0}/${s.desiredCount ?? 0} tasks`,
      tags: tags(s.tags),
      signal: health.tone === "bad" ? { tone: "bad" as const, text: health.text } : undefined,
    };
  });
}

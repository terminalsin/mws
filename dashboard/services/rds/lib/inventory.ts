import "server-only";

import type { InventoryItem } from "@mws-dashboard/aws";

import { STATUS_TONE, tagsOf } from "./clients";
import { clusters as listClusters, instances as listInstances } from "./data";

const signal = (status: string | undefined) => (STATUS_TONE(status) === "bad" ? { tone: "bad" as const, text: status ?? "" } : undefined);

export async function databases(): Promise<InventoryItem[]> {
  const [instances, clusters] = await Promise.all([listInstances(), listClusters()]);
  return [
    ...clusters.map((c) => ({
      service: "rds",
      type: "DB cluster",
      id: c.DBClusterArn!,
      name: c.DBClusterIdentifier!,
      href: `/rds/db?cluster=${encodeURIComponent(c.DBClusterIdentifier!)}`,
      detail: `${c.Engine} ${c.EngineVersion}`,
      tags: tagsOf(c.TagList),
      signal: signal(c.Status),
    })),
    ...instances.map((i) => ({
      service: "rds",
      type: "DB instance",
      id: i.DBInstanceArn!,
      name: i.DBInstanceIdentifier!,
      href: `/rds/db?id=${encodeURIComponent(i.DBInstanceIdentifier!)}`,
      detail: i.DBClusterIdentifier ? `${i.DBInstanceClass} in ${i.DBClusterIdentifier}` : `${i.Engine} ${i.EngineVersion}`,
      tags: tagsOf(i.TagList),
      signal: signal(i.DBInstanceStatus),
    })),
  ];
}

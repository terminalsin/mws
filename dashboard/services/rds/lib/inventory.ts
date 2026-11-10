import "server-only";

import { DescribeDBClustersCommand, DescribeDBInstancesCommand } from "@aws-sdk/client-rds";
import type { InventoryItem } from "@mws-dashboard/aws";

import { STATUS_TONE, rds, tagsOf } from "./clients";

const signal = (status: string | undefined) => (STATUS_TONE(status) === "bad" ? { tone: "bad" as const, text: status ?? "" } : undefined);

export async function databases(): Promise<InventoryItem[]> {
  const client = await rds();
  const [instances, clusters] = await Promise.all([
    client.send(new DescribeDBInstancesCommand({})).then((r) => r.DBInstances ?? []),
    client.send(new DescribeDBClustersCommand({})).then((r) => r.DBClusters ?? []),
  ]);
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
    ...instances
      .filter((i) => !i.DBClusterIdentifier)
      .map((i) => ({
        service: "rds",
        type: "DB instance",
        id: i.DBInstanceArn!,
        name: i.DBInstanceIdentifier!,
        href: `/rds/db?id=${encodeURIComponent(i.DBInstanceIdentifier!)}`,
        detail: `${i.Engine} ${i.EngineVersion}`,
        tags: tagsOf(i.TagList),
        signal: signal(i.DBInstanceStatus),
      })),
  ];
}

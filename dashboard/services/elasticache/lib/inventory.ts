import "server-only";

import { DescribeReplicationGroupsCommand, DescribeServerlessCachesCommand } from "@aws-sdk/client-elasticache";
import type { InventoryItem } from "@mws-dashboard/aws";

import { STATUS_TONE, elasticache } from "./clients";

const signal = (status: string | undefined) => (STATUS_TONE(status) === "bad" ? { tone: "bad" as const, text: status ?? "" } : undefined);

export async function caches(): Promise<InventoryItem[]> {
  const client = await elasticache();
  const [groups, serverless] = await Promise.all([
    client.send(new DescribeReplicationGroupsCommand({})).then((r) => r.ReplicationGroups ?? []),
    client.send(new DescribeServerlessCachesCommand({})).then((r) => r.ServerlessCaches ?? [], () => []),
  ]);
  return [
    ...groups.map((g) => ({
      service: "elasticache",
      type: "Cache",
      id: g.ARN!,
      name: g.ReplicationGroupId!,
      href: `/elasticache/cache?id=${encodeURIComponent(g.ReplicationGroupId!)}`,
      detail: g.Engine,
      signal: signal(g.Status),
    })),
    ...serverless.map((s) => ({
      service: "elasticache",
      type: "Serverless cache",
      id: s.ARN!,
      name: s.ServerlessCacheName!,
      href: `/elasticache/cache?serverless=${encodeURIComponent(s.ServerlessCacheName!)}`,
      detail: s.Engine,
      signal: signal(s.Status),
    })),
  ];
}

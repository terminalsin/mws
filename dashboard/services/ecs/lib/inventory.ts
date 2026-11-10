import "server-only";

import { ListClustersCommand as ListEcsClustersCommand } from "@aws-sdk/client-ecs";
import type { InventoryItem } from "@mws-dashboard/aws";

import { ecs } from "./clients";

export async function ecsClusters(): Promise<InventoryItem[]> {
  const out = await (await ecs()).send(new ListEcsClustersCommand({}));
  return (out.clusterArns ?? []).map((arn) => {
    const name = arn.split("/").pop()!;
    return { service: "ecs", type: "ECS cluster", id: arn, name, href: `/ecs/cluster?name=${encodeURIComponent(name)}` };
  });
}

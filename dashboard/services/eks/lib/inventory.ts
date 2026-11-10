import "server-only";

import { ListClustersCommand } from "@aws-sdk/client-eks";
import type { InventoryItem } from "@mws-dashboard/aws";

import { eks } from "./clients";

export async function eksClusters(): Promise<InventoryItem[]> {
  const out = await (await eks()).send(new ListClustersCommand({}));
  return (out.clusters ?? []).map((name) => ({ service: "eks", type: "EKS cluster", id: `eks:${name}`, name, href: `/eks/cluster?name=${encodeURIComponent(name)}` }));
}

import "server-only";

import { GetResourceSharesCommand } from "@aws-sdk/client-ram";
import { type InventoryItem } from "@mws-dashboard/aws";

import { ram } from "./clients";

export async function shares(): Promise<InventoryItem[]> {
  const out = await (await ram()).send(new GetResourceSharesCommand({ resourceOwner: "SELF" }));
  return (out.resourceShares ?? [])
    .filter((s) => s.status !== "DELETED")
    .map((s) => ({ service: "ram", type: "Resource share", id: s.resourceShareArn!, name: s.name!, href: `/ram/share?arn=${encodeURIComponent(s.resourceShareArn!)}` }));
}

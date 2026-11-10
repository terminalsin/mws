import "server-only";

import { GetResourceSharesCommand } from "@aws-sdk/client-ram";
import { all, type InventoryItem } from "@mws-dashboard/aws";

import { ram, shareHref } from "./clients";

export async function shares(): Promise<InventoryItem[]> {
  const client = await ram();
  const list = await all(
    (nextToken) => client.send(new GetResourceSharesCommand({ resourceOwner: "SELF", nextToken })),
    (r) => r.resourceShares,
    (r) => r.nextToken,
  );
  return list
    .filter((s) => s.status !== "DELETED")
    .map((s) => ({
      service: "ram",
      type: "Resource share",
      id: s.resourceShareArn!,
      name: s.name!,
      href: shareHref(s.resourceShareArn),
      tags: Object.fromEntries((s.tags ?? []).filter((t) => t.key).map((t) => [t.key!, t.value ?? ""])),
    }));
}

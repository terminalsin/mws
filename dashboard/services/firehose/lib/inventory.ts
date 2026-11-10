import "server-only";

import type { InventoryItem } from "@mws-dashboard/aws";

import { allNames, streamHref } from "./clients";

export async function streams(): Promise<InventoryItem[]> {
  return (await allNames()).map((name) => ({
    service: "firehose",
    type: "Firehose stream",
    id: `firehose:${name}`,
    name,
    href: streamHref(name),
  }));
}

import "server-only";

import { type InventoryItem } from "@mws-dashboard/aws";

import { listParameters } from "./ssm";

export async function parameters(): Promise<InventoryItem[]> {
  return (await listParameters("", false, false)).map(({ meta }) => ({
    service: "ssm",
    type: "Parameter",
    id: meta.ARN ?? meta.Name!,
    name: meta.Name!,
    href: `/ssm?path=${encodeURIComponent(meta.Name!.slice(0, meta.Name!.lastIndexOf("/") + 1))}`,
    detail: meta.Type,
  }));
}

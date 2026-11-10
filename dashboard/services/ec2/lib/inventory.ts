import "server-only";

import type { InventoryItem } from "@mws-dashboard/aws";

import { nameTag } from "./clients";
import { listInstances } from "./ec2";

export async function instances(): Promise<InventoryItem[]> {
  return (await listInstances())
    .filter((i) => i.State?.Name !== "terminated")
    .map((i) => ({
      service: "ec2",
      type: "Instance",
      id: i.InstanceId!,
      name: nameTag(i) ?? i.InstanceId!,
      href: `/ec2/instance?id=${i.InstanceId}`,
      detail: `${i.InstanceType} · ${i.State?.Name}`,
      tags: Object.fromEntries((i.Tags ?? []).map((t) => [t.Key!, t.Value ?? ""])),
    }));
}

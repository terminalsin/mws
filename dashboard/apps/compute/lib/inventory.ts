import "server-only";

import type { InventoryItem } from "@mws-dashboard/aws";

import { nameTag } from "./clients";
import { listInstances } from "./ec2";
import { listFunctions } from "./lambda";

export async function functions(): Promise<InventoryItem[]> {
  return (await listFunctions()).map((f) => ({
    service: "lambda",
    type: "Function",
    id: f.FunctionArn!,
    name: f.FunctionName!,
    href: `/compute/lambda/${encodeURIComponent(f.FunctionName!)}`,
    detail: f.Runtime ?? f.PackageType,
    tags: f.tags,
    signal: f.State === "Failed" ? { tone: "bad" as const, text: f.StateReason ?? "Failed" } : undefined,
  }));
}

export async function instances(): Promise<InventoryItem[]> {
  return (await listInstances())
    .filter((i) => i.State?.Name !== "terminated")
    .map((i) => ({
      service: "ec2",
      type: "Instance",
      id: i.InstanceId!,
      name: nameTag(i) ?? i.InstanceId!,
      href: `/compute/ec2/instance?id=${i.InstanceId}`,
      detail: `${i.InstanceType} · ${i.State?.Name}`,
      tags: Object.fromEntries((i.Tags ?? []).map((t) => [t.Key!, t.Value ?? ""])),
    }));
}

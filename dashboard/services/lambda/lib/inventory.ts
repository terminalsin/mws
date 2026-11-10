import "server-only";

import type { InventoryItem } from "@mws-dashboard/aws";

import { listFunctions } from "./lambda";

export async function functions(): Promise<InventoryItem[]> {
  return (await listFunctions()).map((f) => ({
    service: "lambda",
    type: "Function",
    id: f.FunctionArn!,
    name: f.FunctionName!,
    href: `/lambda/${encodeURIComponent(f.FunctionName!)}`,
    detail: f.Runtime ?? f.PackageType,
    tags: f.tags,
    signal: f.State === "Failed" ? { tone: "bad" as const, text: f.StateReason ?? "Failed" } : undefined,
  }));
}

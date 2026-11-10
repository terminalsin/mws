import "server-only";

import { ago, type InventoryItem } from "@mws-dashboard/aws";

import { listSecrets } from "./secrets";

export async function secretItems(): Promise<InventoryItem[]> {
  return (await listSecrets()).map((s) => ({
    service: "secretsmanager",
    type: "Secret",
    id: s.ARN!,
    name: s.Name!,
    href: `/secrets/secret?id=${encodeURIComponent(s.ARN!)}`,
    detail: s.Description,
    tags: Object.fromEntries((s.Tags ?? []).map((t) => [t.Key!, t.Value ?? ""])),
    signal: s.DeletedDate ? { tone: "bad" as const, text: `Deletes ${ago(s.DeletedDate)}` } : undefined,
  }));
}

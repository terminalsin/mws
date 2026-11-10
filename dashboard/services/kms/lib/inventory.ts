import "server-only";

import { ago, type InventoryItem } from "@mws-dashboard/aws";

import { listKeys } from "./kms";

export async function keys(): Promise<InventoryItem[]> {
  return (await listKeys())
    .filter((k) => k.meta.KeyManager === "CUSTOMER")
    .map(({ meta, aliases }) => ({
      service: "kms",
      type: "Key",
      id: meta.Arn!,
      name: aliases[0]?.replace(/^alias\//, "") ?? meta.KeyId!,
      href: `/kms/key?id=${meta.KeyId}`,
      detail: meta.KeySpec,
      signal: meta.KeyState === "PendingDeletion" ? { tone: "bad" as const, text: `Deletes ${ago(meta.DeletionDate)}` } : undefined,
    }));
}

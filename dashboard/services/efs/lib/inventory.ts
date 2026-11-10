import "server-only";

import type { InventoryItem } from "@mws-dashboard/aws";

import { allFileSystems, fsHref, tagsOf } from "./clients";

export async function fileSystems(): Promise<InventoryItem[]> {
  return (await allFileSystems()).map((f) => ({
    service: "efs",
    type: "File system",
    id: f.FileSystemArn!,
    name: f.Name ?? f.FileSystemId!,
    href: fsHref(f.FileSystemId!),
    detail: f.FileSystemId,
    tags: tagsOf(f.Tags),
  }));
}

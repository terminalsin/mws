import "server-only";

import type { InventoryItem } from "@mws-dashboard/aws";

import { repoHref, repositories as all } from "./clients";

export async function repositories(): Promise<InventoryItem[]> {
  return (await all()).map((r) => ({
    service: "ecr",
    type: "Repository",
    id: r.repositoryArn!,
    name: r.repositoryName!,
    href: repoHref(r.repositoryName!),
    detail: r.repositoryUri,
  }));
}

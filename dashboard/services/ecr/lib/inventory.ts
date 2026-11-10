import "server-only";

import { DescribeRepositoriesCommand } from "@aws-sdk/client-ecr";
import type { InventoryItem } from "@mws-dashboard/aws";

import { ecr } from "./clients";

export async function repositories(): Promise<InventoryItem[]> {
  const out = await (await ecr()).send(new DescribeRepositoriesCommand({}));
  return (out.repositories ?? []).map((r) => ({
    service: "ecr",
    type: "Repository",
    id: r.repositoryArn!,
    name: r.repositoryName!,
    href: `/ecr/repo?name=${encodeURIComponent(r.repositoryName!)}`,
    detail: r.repositoryUri,
  }));
}

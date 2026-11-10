import "server-only";

import { ListRepositoriesCommand } from "@aws-sdk/client-codeartifact";
import { type InventoryItem } from "@mws-dashboard/aws";

import { codeartifact } from "./clients";

export async function repositories(): Promise<InventoryItem[]> {
  const out = await (await codeartifact()).send(new ListRepositoriesCommand({}));
  return (out.repositories ?? []).map((r) => ({
    service: "codeartifact",
    type: "Package repository",
    id: r.arn!,
    name: r.name!,
    href: `/codeartifact/repo?domain=${encodeURIComponent(r.domainName!)}&name=${encodeURIComponent(r.name!)}`,
    detail: r.domainName,
  }));
}

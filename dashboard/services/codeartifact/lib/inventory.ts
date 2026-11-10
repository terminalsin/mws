import "server-only";

import { ListRepositoriesCommand } from "@aws-sdk/client-codeartifact";
import { all, type InventoryItem } from "@mws-dashboard/aws";

import { codeartifact } from "./clients";
import { repoHref } from "./refs";

export async function repositories(): Promise<InventoryItem[]> {
  const client = await codeartifact();
  const repos = await all((nextToken) => client.send(new ListRepositoriesCommand({ nextToken })), (r) => r.repositories, (r) => r.nextToken);
  return repos.map((r) => ({
    service: "codeartifact",
    type: "Package repository",
    id: r.arn!,
    name: r.name!,
    href: repoHref(r.domainName!, r.name!, r.domainOwner),
    detail: r.domainName,
  }));
}

import "server-only";

import { ListAccountsCommand } from "@aws-sdk/client-organizations";
import { type InventoryItem } from "@mws-dashboard/aws";

import { organizations } from "./clients";

export async function accounts(): Promise<InventoryItem[]> {
  const out = await (await organizations()).send(new ListAccountsCommand({}));
  return (out.Accounts ?? []).map((a) => ({
    service: "organizations",
    type: "Account",
    id: a.Arn!,
    name: a.Name!,
    href: `/organizations?account=${a.Id}`,
    detail: a.Id,
    signal: a.Status === "SUSPENDED" ? { tone: "warn" as const, text: "Suspended" } : undefined,
  }));
}

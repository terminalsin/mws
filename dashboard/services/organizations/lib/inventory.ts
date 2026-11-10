import "server-only";

import { ListAccountsCommand } from "@aws-sdk/client-organizations";
import { all, type InventoryItem } from "@mws-dashboard/aws";

import { organizations } from "./clients";

export async function accounts(): Promise<InventoryItem[]> {
  const client = await organizations();
  const list = await all((NextToken) => client.send(new ListAccountsCommand({ NextToken })), (r) => r.Accounts, (r) => r.NextToken);
  return list.map((a) => ({
    service: "organizations",
    type: "Account",
    id: a.Arn!,
    name: a.Name!,
    href: `/organizations/accounts/${a.Id}`,
    detail: a.Id,
    signal:
      a.State === "PENDING_CLOSURE" || a.Status === "PENDING_CLOSURE"
        ? { tone: "warn" as const, text: "Closing" }
        : a.State === "SUSPENDED" || a.Status === "SUSPENDED"
          ? { tone: "warn" as const, text: "Suspended" }
          : undefined,
  }));
}

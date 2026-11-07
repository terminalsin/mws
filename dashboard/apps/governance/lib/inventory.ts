import "server-only";

import { ListStacksCommand } from "@aws-sdk/client-cloudformation";
import { ListAccountsCommand } from "@aws-sdk/client-organizations";
import { GetResourceSharesCommand } from "@aws-sdk/client-ram";
import { type InventoryItem } from "@mws-dashboard/aws";

import { cloudformation, organizations, ram, stackTone } from "./clients";

const base = "/governance";

export async function stacks(): Promise<InventoryItem[]> {
  const out = await (await cloudformation()).send(new ListStacksCommand({}));
  return (out.StackSummaries ?? [])
    .filter((s) => s.StackStatus !== "DELETE_COMPLETE")
    .map((s) => ({
      service: "cloudformation",
      type: "Stack",
      id: s.StackId!,
      name: s.StackName!,
      href: `${base}/cloudformation/stack?name=${encodeURIComponent(s.StackName!)}`,
      detail: s.StackStatus?.toLowerCase().replace(/_/g, " "),
      signal: stackTone(s.StackStatus) === "bad" ? { tone: "bad" as const, text: s.StackStatus!.toLowerCase().replace(/_/g, " ") } : undefined,
    }));
}

export async function accounts(): Promise<InventoryItem[]> {
  const out = await (await organizations()).send(new ListAccountsCommand({}));
  return (out.Accounts ?? []).map((a) => ({
    service: "organizations",
    type: "Account",
    id: a.Arn!,
    name: a.Name!,
    href: `${base}/organizations?account=${a.Id}`,
    detail: a.Id,
    signal: a.Status === "SUSPENDED" ? { tone: "warn" as const, text: "Suspended" } : undefined,
  }));
}

export async function shares(): Promise<InventoryItem[]> {
  const out = await (await ram()).send(new GetResourceSharesCommand({ resourceOwner: "SELF" }));
  return (out.resourceShares ?? [])
    .filter((s) => s.status !== "DELETED")
    .map((s) => ({ service: "ram", type: "Resource share", id: s.resourceShareArn!, name: s.name!, href: `${base}/ram/share?arn=${encodeURIComponent(s.resourceShareArn!)}` }));
}

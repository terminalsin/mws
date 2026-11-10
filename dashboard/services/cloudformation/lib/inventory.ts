import "server-only";

import { ListStacksCommand } from "@aws-sdk/client-cloudformation";
import { type InventoryItem } from "@mws-dashboard/aws";

import { cloudformation, stackTone } from "./clients";

export async function stacks(): Promise<InventoryItem[]> {
  const out = await (await cloudformation()).send(new ListStacksCommand({}));
  return (out.StackSummaries ?? [])
    .filter((s) => s.StackStatus !== "DELETE_COMPLETE")
    .map((s) => ({
      service: "cloudformation",
      type: "Stack",
      id: s.StackId!,
      name: s.StackName!,
      href: `/cloudformation/stack?name=${encodeURIComponent(s.StackName!)}`,
      detail: s.StackStatus?.toLowerCase().replace(/_/g, " "),
      signal: stackTone(s.StackStatus) === "bad" ? { tone: "bad" as const, text: s.StackStatus!.toLowerCase().replace(/_/g, " ") } : undefined,
    }));
}

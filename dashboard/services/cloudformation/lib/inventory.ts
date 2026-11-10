import "server-only";

import { ListStacksCommand } from "@aws-sdk/client-cloudformation";
import { all, type InventoryItem } from "@mws-dashboard/aws";

import { word } from "./cloudformation";
import { cloudformation, stackTone } from "./clients";

export async function stacks(): Promise<InventoryItem[]> {
  const client = await cloudformation();
  const list = await all(
    (NextToken) => client.send(new ListStacksCommand({ NextToken })),
    (r) => r.StackSummaries,
    (r) => r.NextToken,
  );
  return list
    .filter((s) => s.StackStatus !== "DELETE_COMPLETE")
    .map((s) => ({
      service: "cloudformation",
      type: "Stack",
      id: s.StackId!,
      name: s.StackName!,
      href: `/cloudformation/stack?name=${encodeURIComponent(s.StackName!)}`,
      detail: word(s.StackStatus),
      signal: stackTone(s.StackStatus) === "bad" ? { tone: "bad" as const, text: word(s.StackStatus) } : undefined,
    }));
}

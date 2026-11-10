import "server-only";

import { ListGuardrailsCommand } from "@aws-sdk/client-bedrock";
import { type InventoryItem } from "@mws-dashboard/aws";

import { bedrock } from "./clients";

export async function guardrails(): Promise<InventoryItem[]> {
  const out = await (await bedrock()).send(new ListGuardrailsCommand({}));
  return (out.guardrails ?? []).map((g) => ({ service: "bedrock", type: "Guardrail", id: g.arn!, name: g.name!, href: `/bedrock/guardrail?id=${g.id}` }));
}

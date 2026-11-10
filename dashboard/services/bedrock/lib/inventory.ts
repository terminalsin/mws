import "server-only";

import { ListCustomModelsCommand, ListGuardrailsCommand, ListProvisionedModelThroughputsCommand } from "@aws-sdk/client-bedrock";
import { all, type InventoryItem } from "@mws-dashboard/aws";

import { bedrock } from "./clients";

export async function guardrails(): Promise<InventoryItem[]> {
  const c = await bedrock();
  const list = await all((nextToken) => c.send(new ListGuardrailsCommand({ nextToken })), (r) => r.guardrails, (r) => r.nextToken);
  return list.map((g) => ({ service: "bedrock", type: "Guardrail", id: g.arn!, name: g.name!, href: `/bedrock/guardrail?id=${g.id}` }));
}

export async function customModels(): Promise<InventoryItem[]> {
  const c = await bedrock();
  const list = await all((nextToken) => c.send(new ListCustomModelsCommand({ nextToken })), (r) => r.modelSummaries, (r) => r.nextToken);
  return list.map((m) => ({
    service: "bedrock",
    type: "Custom model",
    id: m.modelArn!,
    name: m.modelName!,
    detail: m.baseModelName,
    href: `/bedrock/custom-model?arn=${encodeURIComponent(m.modelArn!)}`,
    ...(m.modelStatus === "Failed" ? { signal: { tone: "bad" as const, text: "Customization failed" } } : {}),
  }));
}

export async function provisioned(): Promise<InventoryItem[]> {
  const c = await bedrock();
  const list = await all((nextToken) => c.send(new ListProvisionedModelThroughputsCommand({ nextToken })), (r) => r.provisionedModelSummaries, (r) => r.nextToken);
  return list.map((p) => ({
    service: "bedrock",
    type: "Provisioned Throughput",
    id: p.provisionedModelArn!,
    name: p.provisionedModelName!,
    detail: `${p.modelUnits} MU`,
    href: `/bedrock/provisioned-model?arn=${encodeURIComponent(p.provisionedModelArn!)}`,
    ...(p.status === "Failed" ? { signal: { tone: "bad" as const, text: "Provisioning failed" } } : {}),
  }));
}

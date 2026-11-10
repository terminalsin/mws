import "server-only";

import { DescribeMaintenanceWindowsCommand, DescribeOpsItemsCommand } from "@aws-sdk/client-ssm";
import { all, type InventoryItem } from "@mws-dashboard/aws";

import { ssm } from "./clients";
import { listDocuments, listNodes, nodeName } from "./nodes";
import { listParameters } from "./ssm";

export async function parameters(): Promise<InventoryItem[]> {
  return (await listParameters("", false, false)).map(({ meta }) => ({
    service: "ssm",
    type: "Parameter",
    id: meta.ARN ?? meta.Name!,
    name: meta.Name!,
    href: `/ssm/parameter?name=${encodeURIComponent(meta.Name!)}`,
    detail: meta.Type,
  }));
}

export async function documents(): Promise<InventoryItem[]> {
  return (await listDocuments([{ Key: "Owner", Values: ["Self"] }])).map((d) => ({
    service: "ssm",
    type: "SSM document",
    id: `ssm-document:${d.Name}`,
    name: d.Name!,
    href: `/ssm/document?name=${encodeURIComponent(d.Name!)}`,
    detail: d.DocumentType,
  }));
}

export async function nodes(): Promise<InventoryItem[]> {
  return (await listNodes()).map((n) => ({
    service: "ssm",
    type: "Managed node",
    id: `ssm-node:${n.InstanceId}`,
    name: nodeName(n),
    href: `/ssm/node?id=${encodeURIComponent(n.InstanceId!)}`,
    detail: n.PingStatus,
    signal: n.PingStatus === "ConnectionLost" ? { tone: "warn" as const, text: "Connection lost" } : undefined,
  }));
}

export async function windows(): Promise<InventoryItem[]> {
  const c = await ssm();
  const list = await all((NextToken) => c.send(new DescribeMaintenanceWindowsCommand({ NextToken, MaxResults: 50 })), (r) => r.WindowIdentities, (r) => r.NextToken);
  return list.map((w) => ({ service: "ssm", type: "Maintenance window", id: `ssm-window:${w.WindowId}`, name: w.Name!, href: `/ssm/window?id=${w.WindowId}`, detail: w.Schedule }));
}

/** Open OpsItems; high-priority ones are signals. */
export async function opsItems(): Promise<InventoryItem[]> {
  const c = await ssm();
  const list = await all(
    (NextToken) => c.send(new DescribeOpsItemsCommand({ OpsItemFilters: [{ Key: "Status", Operator: "Equal", Values: ["Open", "InProgress"] }], NextToken, MaxResults: 50 })),
    (r) => r.OpsItemSummaries,
    (r) => r.NextToken,
  );
  return list.map((o) => ({
    service: "ssm",
    type: "OpsItem",
    id: `ssm-opsitem:${o.OpsItemId}`,
    name: o.Title!,
    href: `/ssm/opsitem?id=${o.OpsItemId}`,
    detail: o.Status,
    signal: (o.Priority ?? 5) <= 2 ? { tone: "bad" as const, text: `P${o.Priority} OpsItem open` } : undefined,
  }));
}

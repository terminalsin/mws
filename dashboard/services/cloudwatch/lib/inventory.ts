import "server-only";

import type { InventoryItem } from "@mws-dashboard/aws";

import { listAlarms, listGroups } from "./clients";

export async function logGroups(): Promise<InventoryItem[]> {
  return (await listGroups()).map((g) => ({
    service: "cloudwatch",
    type: "Log group",
    id: g.logGroupArn ?? g.logGroupName!,
    name: g.logGroupName!,
    href: `/logs/group?${new URLSearchParams({ name: g.logGroupName! })}`,
  }));
}

export async function alarms(): Promise<InventoryItem[]> {
  const { metric, composite } = await listAlarms();
  return [...metric, ...composite].map((a) => ({
    service: "cloudwatch",
    type: "Alarm",
    id: a.AlarmArn!,
    name: a.AlarmName!,
    href: "/alarms",
    detail: a.StateValue,
    signal: a.StateValue === "ALARM" ? { tone: "bad" as const, text: "In alarm" } : undefined,
  }));
}

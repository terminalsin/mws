import "server-only";

import { ListDashboardsCommand } from "@aws-sdk/client-cloudwatch";
import { all, type InventoryItem } from "@mws-dashboard/aws";

import {
  alarmHref,
  cloudwatch,
  groupHref,
  listAlarms,
  listGroups,
} from "./clients";

export async function logGroups(): Promise<InventoryItem[]> {
  return (await listGroups()).map((g) => ({
    service: "cloudwatch",
    type: "Log group",
    id: g.logGroupArn ?? g.logGroupName!,
    name: g.logGroupName!,
    href: groupHref(g.logGroupName!),
  }));
}

export async function alarms(): Promise<InventoryItem[]> {
  return (await listAlarms()).map((a) => ({
    service: "cloudwatch",
    type:
      a.kind === "composite"
        ? "Composite alarm"
        : a.kind === "log"
          ? "Log alarm"
          : "Alarm",
    id: a.AlarmArn!,
    name: a.AlarmName!,
    href: alarmHref(a.AlarmName!),
    detail: a.StateValue,
    signal:
      a.StateValue === "ALARM"
        ? { tone: "bad" as const, text: "In alarm" }
        : undefined,
  }));
}

export async function dashboards(): Promise<InventoryItem[]> {
  const c = await cloudwatch();
  const list = await all(
    (NextToken) => c.send(new ListDashboardsCommand({ NextToken })),
    (r) => r.DashboardEntries,
    (r) => r.NextToken,
  );
  return list.map((d) => ({
    service: "cloudwatch",
    type: "Dashboard",
    id: d.DashboardArn ?? `dashboard:${d.DashboardName}`,
    name: d.DashboardName!,
    href: `/dashboards/dashboard?${new URLSearchParams({ name: d.DashboardName! })}`,
  }));
}

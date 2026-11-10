import "server-only";

import { ListEventBusesCommand, ListRulesCommand } from "@aws-sdk/client-eventbridge";
import { type InventoryItem } from "@mws-dashboard/aws";

import { events } from "./clients";

export async function eventItems(): Promise<InventoryItem[]> {
  const client = await events();
  const buses = (await client.send(new ListEventBusesCommand({}))).EventBuses ?? [];
  const rules = (
    await Promise.all(
      buses.map(async (b) =>
        ((await client.send(new ListRulesCommand({ EventBusName: b.Name }))).Rules ?? []).map((r) => ({ bus: b.Name!, rule: r })),
      ),
    )
  ).flat();
  return [
    ...buses
      .filter((b) => b.Name !== "default")
      .map((b) => ({ service: "events", type: "Event bus", id: b.Arn!, name: b.Name!, href: `/events?bus=${encodeURIComponent(b.Name!)}` })),
    ...rules.map(({ bus, rule }) => ({
      service: "events",
      type: "Rule",
      id: rule.Arn!,
      name: rule.Name!,
      detail: rule.ScheduleExpression ?? bus,
      href: `/events?bus=${encodeURIComponent(bus)}`,
    })),
  ];
}

import "server-only";

import { ListRulesCommand } from "@aws-sdk/client-eventbridge";
import { all, type InventoryItem } from "@mws-dashboard/aws";

import { events } from "./clients";
import { buses as listBuses } from "./targets";

export async function eventItems(): Promise<InventoryItem[]> {
  const client = await events();
  const buses = await listBuses();
  const rules = (
    await Promise.all(
      buses.map(async (b) =>
        (await all((NextToken) => client.send(new ListRulesCommand({ EventBusName: b.Name, NextToken })), (r) => r.Rules, (r) => r.NextToken)).map((r) => ({ bus: b.Name!, rule: r })),
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
      href: `/events/rule?bus=${encodeURIComponent(bus)}&name=${encodeURIComponent(rule.Name!)}`,
    })),
  ];
}

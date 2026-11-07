import "server-only";

import { ListEventBusesCommand, ListRulesCommand } from "@aws-sdk/client-eventbridge";
import { ListEmailIdentitiesCommand } from "@aws-sdk/client-sesv2";
import { ListTopicsCommand } from "@aws-sdk/client-sns";
import { collect, shortName, type InventoryItem } from "@mws-dashboard/aws";

import { events, isDlq, queues, ses, sns } from "./clients";

export async function queueItems(): Promise<InventoryItem[]> {
  return (await queues()).map((q) => {
    const visible = Number(q.attrs.ApproximateNumberOfMessages ?? 0);
    const dlq = isDlq(q);
    return {
      service: "sqs",
      type: dlq ? "Dead-letter queue" : "Queue",
      id: q.arn,
      name: q.name,
      href: `/messaging/sqs/${encodeURIComponent(q.name)}`,
      detail: `${visible} available`,
      signal:
        dlq && visible > 0
          ? { tone: "bad" as const, text: `${visible} failed message${visible === 1 ? "" : "s"}` }
          : visible >= 1000
            ? { tone: "warn" as const, text: `${visible} waiting` }
            : undefined,
    };
  });
}

export async function topicItems(): Promise<InventoryItem[]> {
  const client = await sns();
  const topics = await collect(
    (NextToken) => client.send(new ListTopicsCommand({ NextToken })),
    (r) => r.Topics,
    (r) => r.NextToken,
  );
  return topics.map((t) => ({
    service: "sns",
    type: "Topic",
    id: t.TopicArn!,
    name: shortName(t.TopicArn),
    href: `/messaging/sns/topic?arn=${encodeURIComponent(t.TopicArn!)}`,
  }));
}

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
      .map((b) => ({ service: "events", type: "Event bus", id: b.Arn!, name: b.Name!, href: `/messaging/events?bus=${encodeURIComponent(b.Name!)}` })),
    ...rules.map(({ bus, rule }) => ({
      service: "events",
      type: "Rule",
      id: rule.Arn!,
      name: rule.Name!,
      detail: rule.ScheduleExpression ?? bus,
      href: `/messaging/events?bus=${encodeURIComponent(bus)}`,
    })),
  ];
}

export async function identityItems(): Promise<InventoryItem[]> {
  const out = await (await ses()).send(new ListEmailIdentitiesCommand({}));
  return (out.EmailIdentities ?? []).map((i) => ({
    service: "ses",
    type: i.IdentityType === "DOMAIN" ? "Domain identity" : "Email identity",
    id: `ses:${i.IdentityName}`,
    name: i.IdentityName!,
    href: "/messaging/ses",
    detail: i.VerificationStatus?.toLowerCase(),
  }));
}

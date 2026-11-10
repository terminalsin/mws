import "server-only";

import { type InventoryItem } from "@mws-dashboard/aws";

import { isDlq, queues } from "./clients";

export async function queueItems(): Promise<InventoryItem[]> {
  return (await queues()).map((q) => {
    const visible = Number(q.attrs.ApproximateNumberOfMessages ?? 0);
    const dlq = isDlq(q);
    return {
      service: "sqs",
      type: dlq ? "Dead-letter queue" : "Queue",
      id: q.arn,
      name: q.name,
      href: `/sqs/${encodeURIComponent(q.name)}`,
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

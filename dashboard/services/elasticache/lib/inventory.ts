import "server-only";

import { ListTagsForResourceCommand } from "@aws-sdk/client-elasticache";
import { tagMap, type InventoryItem } from "@mws-dashboard/aws";

import { STATUS_TONE, elasticache } from "./clients";
import { listCaches } from "./elasticache";

const signal = (status: string | undefined) => (STATUS_TONE(status) === "bad" ? { tone: "bad" as const, text: status ?? "" } : undefined);

const TYPE = { serverless: "Serverless cache", group: "Cache", cluster: "Memcached cluster" } as const;

export async function caches(): Promise<InventoryItem[]> {
  const client = await elasticache();
  const list = await listCaches();
  return Promise.all(
    list.map(async (c) => ({
      service: "elasticache",
      type: TYPE[c.kind],
      id: c.arn ?? `elasticache:${c.kind}:${c.name}`,
      name: c.name,
      href: c.href,
      detail: [c.engine, c.version].filter(Boolean).join(" "),
      tags: c.arn ? await client.send(new ListTagsForResourceCommand({ ResourceName: c.arn })).then((r) => tagMap(r.TagList), () => undefined) : undefined,
      signal: signal(c.status),
    })),
  );
}

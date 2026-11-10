import "server-only";

import { ListDeliveryStreamsCommand } from "@aws-sdk/client-firehose";
import type { InventoryItem } from "@mws-dashboard/aws";

import { firehose } from "./clients";

export async function streams(): Promise<InventoryItem[]> {
  const out = await (await firehose()).send(new ListDeliveryStreamsCommand({}));
  return (out.DeliveryStreamNames ?? []).map((name) => ({ service: "firehose", type: "Firehose stream", id: `firehose:${name}`, name, href: `/firehose/stream?name=${encodeURIComponent(name)}` }));
}

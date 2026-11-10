import "server-only";

import { ListStreamsCommand } from "@aws-sdk/client-kinesis";
import type { InventoryItem } from "@mws-dashboard/aws";

import { kinesis } from "./clients";

export async function streams(): Promise<InventoryItem[]> {
  const out = await (await kinesis()).send(new ListStreamsCommand({}));
  return (out.StreamSummaries ?? []).map((s) => ({
    service: "kinesis",
    type: "Data stream",
    id: s.StreamARN!,
    name: s.StreamName!,
    href: `/kinesis/stream?name=${encodeURIComponent(s.StreamName!)}`,
    detail: s.StreamModeDetails?.StreamMode === "ON_DEMAND" ? "On-demand" : "Provisioned",
  }));
}

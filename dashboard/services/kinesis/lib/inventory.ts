import "server-only";

import type { InventoryItem } from "@mws-dashboard/aws";

import { listStreams, streamHref } from "./clients";

export async function streams(): Promise<InventoryItem[]> {
  return (await listStreams()).map((s) => ({
    service: "kinesis",
    type: "Data stream",
    id: s.StreamARN!,
    name: s.StreamName!,
    href: streamHref(s.StreamName!),
    detail:
      s.StreamModeDetails?.StreamMode === "ON_DEMAND"
        ? "On-demand"
        : "Provisioned",
  }));
}

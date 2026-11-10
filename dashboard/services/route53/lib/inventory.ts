import "server-only";

import { ListHostedZonesCommand } from "@aws-sdk/client-route-53";
import { type InventoryItem } from "@mws-dashboard/aws";

import { route53 } from "./clients";

export async function hostedZones(): Promise<InventoryItem[]> {
  const out = await (await route53()).send(new ListHostedZonesCommand({}));
  return (out.HostedZones ?? []).map((z) => ({
    service: "route53",
    type: "Hosted zone",
    id: z.Id!,
    name: z.Name!.replace(/\.$/, ""),
    href: `/route53/zone?id=${encodeURIComponent(z.Id!.split("/").pop()!)}`,
    detail: z.Config?.PrivateZone ? "Private" : "Public",
  }));
}

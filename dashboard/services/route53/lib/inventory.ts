import "server-only";

import { ListHostedZonesCommand } from "@aws-sdk/client-route-53";
import { all, type InventoryItem } from "@mws-dashboard/aws";

import { route53, zoneHref } from "./clients";

export async function hostedZones(): Promise<InventoryItem[]> {
  const client = await route53();
  const zones = await all(
    (Marker) => client.send(new ListHostedZonesCommand({ Marker })),
    (r) => r.HostedZones,
    (r) => (r.IsTruncated ? r.NextMarker : undefined),
  );
  return zones.map((z) => ({
    service: "route53",
    type: "Hosted zone",
    id: z.Id!,
    name: z.Name!.replace(/\.$/, ""),
    href: zoneHref(z.Id),
    detail: z.Config?.PrivateZone ? "Private" : "Public",
  }));
}

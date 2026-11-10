import "server-only";

import { ListAcceleratorsCommand } from "@aws-sdk/client-global-accelerator";
import { all, type InventoryItem } from "@mws-dashboard/aws";

import { acceleratorHref, ga } from "./clients";

export async function accelerators(): Promise<InventoryItem[]> {
  const client = await ga();
  const list = await all(
    (NextToken) => client.send(new ListAcceleratorsCommand({ NextToken })),
    (r) => r.Accelerators,
    (r) => r.NextToken,
  );
  return list.map((a) => ({
    service: "globalaccelerator",
    type: "Accelerator",
    id: a.AcceleratorArn!,
    name: a.Name!,
    href: acceleratorHref(a.AcceleratorArn),
    detail: a.DnsName,
  }));
}

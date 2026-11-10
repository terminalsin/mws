import "server-only";

import { ListAcceleratorsCommand } from "@aws-sdk/client-global-accelerator";
import { type InventoryItem } from "@mws-dashboard/aws";

import { ga } from "./clients";

export async function accelerators(): Promise<InventoryItem[]> {
  const out = await (await ga()).send(new ListAcceleratorsCommand({}));
  return (out.Accelerators ?? []).map((a) => ({
    service: "globalaccelerator",
    type: "Accelerator",
    id: a.AcceleratorArn!,
    name: a.Name!,
    href: `/ga/accelerator?arn=${encodeURIComponent(a.AcceleratorArn!)}`,
    detail: a.DnsName,
  }));
}

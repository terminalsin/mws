import "server-only";

import { type InventoryItem, tagMap } from "@mws-dashboard/aws";

import { nameTag } from "./clients";
import { listAddresses, listPeerings, listVpcs } from "./vpc";

export async function vpcs(): Promise<InventoryItem[]> {
  return (await listVpcs()).map((v) => ({
    service: "vpc",
    type: "VPC",
    id: v.VpcId!,
    name: nameTag(v) ?? v.VpcId!,
    href: `/vpc/${v.VpcId}`,
    detail: v.CidrBlock,
    tags: tagMap(v.Tags),
  }));
}

/** Elastic IPs: an unassociated one is still charged, so it is a signal. */
export async function addresses(): Promise<InventoryItem[]> {
  return (await listAddresses()).map((a) => ({
    service: "vpc",
    type: "Elastic IP",
    id: a.AllocationId ?? a.PublicIp!,
    name: nameTag(a) ?? a.PublicIp!,
    href: "/vpc?tab=eips",
    detail: a.PublicIp,
    tags: tagMap(a.Tags),
    signal: a.AssociationId ? undefined : { tone: "warn" as const, text: "Unassociated" },
  }));
}

/** Peering requests waiting for this account to accept them. */
export async function peerings(): Promise<InventoryItem[]> {
  const [all, own] = await Promise.all([listPeerings(), listVpcs()]);
  const mine = new Set(own.map((v) => v.VpcId));
  return all
    .filter((p) => !["deleted", "rejected", "expired", "failed"].includes(p.Status?.Code ?? ""))
    .map((p) => ({
      service: "vpc",
      type: "Peering connection",
      id: p.VpcPeeringConnectionId!,
      name: nameTag(p) ?? p.VpcPeeringConnectionId!,
      href: `/vpc/peering?id=${p.VpcPeeringConnectionId}`,
      detail: `${p.RequesterVpcInfo?.CidrBlock ?? ""} ⇄ ${p.AccepterVpcInfo?.CidrBlock ?? ""}`,
      tags: tagMap(p.Tags),
      signal: p.Status?.Code === "pending-acceptance" && mine.has(p.AccepterVpcInfo?.VpcId) ? { tone: "warn" as const, text: "Pending acceptance" } : undefined,
    }));
}

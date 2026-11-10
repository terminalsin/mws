import "server-only";

import { DescribeVpcsCommand } from "@aws-sdk/client-ec2";
import { type InventoryItem, tagMap } from "@mws-dashboard/aws";

import { ec2, nameTag } from "./clients";

export async function vpcs(): Promise<InventoryItem[]> {
  const out = await (await ec2()).send(new DescribeVpcsCommand({}));
  return (out.Vpcs ?? []).map((v) => ({
    service: "vpc",
    type: "VPC",
    id: v.VpcId!,
    name: nameTag(v) ?? v.VpcId!,
    href: `/vpc/${v.VpcId}`,
    detail: v.CidrBlock,
    tags: tagMap(v.Tags),
  }));
}

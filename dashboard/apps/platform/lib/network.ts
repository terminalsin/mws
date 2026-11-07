import "server-only";

import { DescribeImagesCommand, DescribeLaunchTemplatesCommand, DescribeSubnetsCommand, DescribeVpcsCommand } from "@aws-sdk/client-ec2";

import { ec2 } from "./clients";

/** The default VPC's subnets, where groups launch unless told otherwise. */
export async function defaultSubnets(): Promise<string[]> {
  const client = await ec2();
  const vpcs = (await client.send(new DescribeVpcsCommand({}))).Vpcs ?? [];
  const vpc = vpcs.find((v) => v.IsDefault) ?? vpcs[0];
  if (!vpc) return [];
  const subnets = (await client.send(new DescribeSubnetsCommand({ Filters: [{ Name: "vpc-id", Values: [vpc.VpcId!] }] }))).Subnets ?? [];
  return subnets.map((s) => s.SubnetId!);
}

export async function launchTemplates() {
  return (await (await ec2()).send(new DescribeLaunchTemplatesCommand({}))).LaunchTemplates ?? [];
}

/** Images to launch from: the account's own first, then a few public ones. */
export async function images() {
  const all = (await (await ec2()).send(new DescribeImagesCommand({}))).Images ?? [];
  return all.filter((i) => i.State === "available").slice(0, 40);
}

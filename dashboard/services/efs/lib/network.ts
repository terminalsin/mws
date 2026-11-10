import "server-only";

import { DescribeSubnetsCommand, DescribeVpcsCommand } from "@aws-sdk/client-ec2";

import { ec2 } from "./clients";

export async function subnetsOf(vpc: string) {
  const subnets = (await (await ec2()).send(new DescribeSubnetsCommand({ Filters: [{ Name: "vpc-id", Values: [vpc] }] }))).Subnets ?? [];
  return subnets.map((s) => s.SubnetId!);
}

export async function vpcs() {
  return (await (await ec2()).send(new DescribeVpcsCommand({}))).Vpcs ?? [];
}

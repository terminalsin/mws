import "server-only";

import { DescribeSecurityGroupsCommand, DescribeSubnetsCommand, DescribeVpcsCommand } from "@aws-sdk/client-ec2";
import { all } from "@mws-dashboard/aws";

import { ec2 } from "./clients";

export async function subnetsOf(vpc: string) {
  const c = await ec2();
  return all(
    (NextToken) => c.send(new DescribeSubnetsCommand({ Filters: [{ Name: "vpc-id", Values: [vpc] }], NextToken })),
    (r) => r.Subnets,
    (r) => r.NextToken,
  );
}

export async function securityGroupsOf(vpc: string) {
  const c = await ec2();
  return all(
    (NextToken) => c.send(new DescribeSecurityGroupsCommand({ Filters: [{ Name: "vpc-id", Values: [vpc] }], NextToken })),
    (r) => r.SecurityGroups,
    (r) => r.NextToken,
  );
}

export async function vpcs() {
  const c = await ec2();
  return all(
    (NextToken) => c.send(new DescribeVpcsCommand({ NextToken })),
    (r) => r.Vpcs,
    (r) => r.NextToken,
  );
}

export const nameOf = (tags: { Key?: string; Value?: string }[] | undefined) => tags?.find((t) => t.Key === "Name")?.Value;

import "server-only";

import { DescribeSubnetsCommand, DescribeVpcsCommand } from "@aws-sdk/client-ec2";
import { ListRolesCommand } from "@aws-sdk/client-iam";
import { collect } from "@mws-dashboard/aws";

import { ec2, iam } from "./clients";

export async function subnetsOf(vpc: string) {
  const subnets = (await (await ec2()).send(new DescribeSubnetsCommand({ Filters: [{ Name: "vpc-id", Values: [vpc] }] }))).Subnets ?? [];
  return subnets.map((s) => s.SubnetId!);
}

export async function vpcs() {
  return (await (await ec2()).send(new DescribeVpcsCommand({}))).Vpcs ?? [];
}

/** Roles a service may assume, for the role pickers. */
export async function rolesTrusting(service: string) {
  const client = await iam();
  const roles = await collect(
    (Marker) => client.send(new ListRolesCommand({ Marker })),
    (r) => r.Roles,
    (r) => (r.IsTruncated ? r.Marker : undefined),
  );
  return roles.filter((r) => decodeURIComponent(r.AssumeRolePolicyDocument ?? "").includes(service));
}

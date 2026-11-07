import "server-only";

import { DescribeSecurityGroupsCommand, DescribeSubnetsCommand, DescribeVpcsCommand } from "@aws-sdk/client-ec2";
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

/** The network a console-launched task gets: the default VPC's subnets and
 * default security group (else the first VPC's). */
export async function defaultNetwork() {
  const all = await vpcs();
  const vpc = all.find((v) => v.IsDefault) ?? all[0];
  if (!vpc) return undefined;
  const client = await ec2();
  const [subnets, groups] = await Promise.all([
    subnetsOf(vpc.VpcId!),
    client.send(new DescribeSecurityGroupsCommand({ Filters: [{ Name: "vpc-id", Values: [vpc.VpcId!] }, { Name: "group-name", Values: ["default"] }] })).then((r) => r.SecurityGroups ?? []),
  ]);
  return { awsvpcConfiguration: { subnets, securityGroups: groups.map((g) => g.GroupId!), assignPublicIp: "ENABLED" as const } };
}

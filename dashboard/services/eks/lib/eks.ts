import "server-only";

import { DescribeInstanceTypesCommand, DescribeSubnetsCommand, DescribeVpcsCommand } from "@aws-sdk/client-ec2";
import { ListRolesCommand } from "@aws-sdk/client-iam";
import { FieldError, collect } from "@mws-dashboard/aws";

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

/** The VPCs a cluster can use: EKS needs subnets in two Availability Zones. */
export async function clusterNetworks() {
  const client = await ec2();
  const [list, subnets] = await Promise.all([vpcs(), client.send(new DescribeSubnetsCommand({})).then((r) => r.Subnets ?? [])]);
  return list.map((v) => {
    const own = subnets.filter((s) => s.VpcId === v.VpcId);
    return { vpc: v, subnets: own.map((s) => s.SubnetId!), zones: new Set(own.map((s) => s.AvailabilityZone)).size };
  });
}

/** Every instance type EC2 offers, for the node group's instance type. */
export async function instanceTypes() {
  const client = await ec2();
  const types = await collect(
    (NextToken) => client.send(new DescribeInstanceTypesCommand({ NextToken, MaxResults: 100 })),
    (r) => r.InstanceTypes,
    (r) => r.NextToken,
  );
  return types.map((t) => t.InstanceType!).sort();
}

/** EKS's messages for values the form can fix, as the field each names.
 * All of them come back as InvalidParameterException, so they are told
 * apart by their (AWS) wording. */
export function fieldError(e: unknown): unknown {
  if (!(e instanceof Error)) return e;
  const m = e.message;
  let x: RegExpMatchArray | null;
  if ((x = m.match(/unsupported Kubernetes version (\S+)/i))) return new FieldError("version", `${x[1]} is not offered`, "enum");
  if (/at least two different AZs/i.test(m)) return new FieldError("vpc", "Needs subnets in two Availability Zones");
  if ((x = m.match(/Desired capacity (\d+) can't be greater than max size (\d+)/))) return new FieldError("max", `At least the desired ${x[1]}`, "range", { min: Number(x[1]) });
  if ((x = m.match(/Minimum capacity (\d+) can't be greater than max size (\d+)/))) return new FieldError("min", `At most the max ${x[2]}`, "range", { max: Number(x[2]) });
  if ((x = m.match(/Minimum capacity (\d+) can't be greater than desired size (\d+)/))) return new FieldError("min", `At most the desired ${x[2]}`, "range", { max: Number(x[2]) });
  if ((x = m.match(/Maximum size of (\d+) exceeds the limit of (\d+)/))) return new FieldError("max", `At most ${x[2]} nodes per node group`, "range", { max: Number(x[2]) });
  if ((x = m.match(/^\[(.+)\] is not a valid instance type/))) return new FieldError("type", `${x[1]} doesn't run this AMI type`);
  return e;
}

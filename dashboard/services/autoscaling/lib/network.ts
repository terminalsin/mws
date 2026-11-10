import "server-only";

import { DescribeImagesCommand, DescribeLaunchTemplatesCommand, DescribeLaunchTemplateVersionsCommand, DescribeSubnetsCommand, DescribeVpcsCommand } from "@aws-sdk/client-ec2";
import { DescribeTargetGroupsCommand } from "@aws-sdk/client-elastic-load-balancing-v2";
import { all } from "@mws-dashboard/aws";

import { ec2, elbv2 } from "./clients";

const nameOf = (r: { Tags?: { Key?: string; Value?: string }[] }) => r.Tags?.find((t) => t.Key === "Name")?.Value;

/** The default VPC's subnets, where groups launch unless told otherwise. */
export async function defaultSubnets(): Promise<string[]> {
  const { vpcs, subnets } = await vpcNetwork();
  const vpc = vpcs.find((v) => v.default) ?? vpcs[0];
  return subnets.filter((s) => s.vpc === vpc?.id).map((s) => s.id);
}

/** VPCs and their subnets, for the network step of the create form. */
export async function vpcNetwork() {
  const client = await ec2();
  const [vpcs, subnets] = await Promise.all([
    all((NextToken) => client.send(new DescribeVpcsCommand({ NextToken })), (r) => r.Vpcs, (r) => r.NextToken),
    all((NextToken) => client.send(new DescribeSubnetsCommand({ NextToken })), (r) => r.Subnets, (r) => r.NextToken),
  ]);
  return {
    vpcs: vpcs.map((v) => ({ id: v.VpcId!, label: `${nameOf(v) ?? v.VpcId} · ${v.CidrBlock}`, default: !!v.IsDefault })),
    subnets: subnets.map((s) => ({ id: s.SubnetId!, vpc: s.VpcId!, label: `${nameOf(s) ?? s.SubnetId} · ${s.CidrBlock}`, az: s.AvailabilityZone ?? "" })),
  };
}

export async function launchTemplates() {
  const client = await ec2();
  return all((NextToken) => client.send(new DescribeLaunchTemplatesCommand({ NextToken })), (r) => r.LaunchTemplates, (r) => r.NextToken);
}

export async function templateVersions(name: string) {
  const client = await ec2();
  return all((NextToken) => client.send(new DescribeLaunchTemplateVersionsCommand({ LaunchTemplateName: name, NextToken })), (r) => r.LaunchTemplateVersions, (r) => r.NextToken, 200);
}

/** ELBv2 target groups, with the VPC each serves. */
export async function targetGroups() {
  const client = await elbv2();
  return all((Marker) => client.send(new DescribeTargetGroupsCommand({ Marker })), (r) => r.TargetGroups, (r) => r.NextMarker);
}

/** Images to launch from: the account's own first, then the rest. */
export async function images() {
  const client = await ec2();
  const [own, rest] = await Promise.all([
    client.send(new DescribeImagesCommand({ Owners: ["self"] })).then((r) => r.Images ?? [], () => []),
    client.send(new DescribeImagesCommand({})).then((r) => r.Images ?? []),
  ]);
  const seen = new Set<string>();
  return [...own, ...rest].filter((i) => i.State === "available" && !seen.has(i.ImageId!) && seen.add(i.ImageId!));
}

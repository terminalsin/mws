import "server-only";

import {
  DescribeAddressesCommand,
  DescribeInternetGatewaysCommand,
  DescribeNatGatewaysCommand,
  DescribeNetworkAclsCommand,
  DescribeRouteTablesCommand,
  DescribeSecurityGroupsCommand,
  DescribeSubnetsCommand,
  DescribeVpcEndpointsCommand,
  DescribeVpcPeeringConnectionsCommand,
  DescribeVpcsCommand,
  type Filter,
  type RouteTable,
  type Subnet,
  type Vpc,
} from "@aws-sdk/client-ec2";
import { all } from "@mws-dashboard/aws";

import { ec2, nameTag } from "./clients";
import type { VpcChoice } from "./forms";

export { destinationOf, ROUTE_TARGETS, targetKey, routeTarget } from "./routes";

/** The route table that governs a subnet: its explicit association, else
 * its VPC's main table. */
export function tableFor(subnet: Subnet, tables: RouteTable[]) {
  return (
    tables.find((t) => t.Associations?.some((a) => a.SubnetId === subnet.SubnetId)) ??
    tables.find((t) => t.VpcId === subnet.VpcId && t.Associations?.some((a) => a.Main))
  );
}

/** A subnet is public when its route table sends the internet to an
 * internet gateway, as the VPC console decides. */
export function isPublic(subnet: Subnet, tables: RouteTable[]) {
  return !!tableFor(subnet, tables)?.Routes?.some((r) => (r.DestinationCidrBlock === "0.0.0.0/0" || r.DestinationIpv6CidrBlock === "::/0") && r.GatewayId?.startsWith("igw-"));
}

const byVpc = (vpcId?: string): Filter[] | undefined => (vpcId ? [{ Name: "vpc-id", Values: [vpcId] }] : undefined);

// Every list follows NextToken: AWS pages these calls.
export async function listVpcs(VpcIds?: string[]) {
  const c = await ec2();
  return all((NextToken) => c.send(new DescribeVpcsCommand({ VpcIds, NextToken })), (r) => r.Vpcs, (r) => r.NextToken);
}
export async function listSubnets(vpcId?: string, SubnetIds?: string[]) {
  const c = await ec2();
  return all((NextToken) => c.send(new DescribeSubnetsCommand({ Filters: byVpc(vpcId), SubnetIds, NextToken })), (r) => r.Subnets, (r) => r.NextToken);
}
export async function listTables(vpcId?: string) {
  const c = await ec2();
  return all((NextToken) => c.send(new DescribeRouteTablesCommand({ Filters: byVpc(vpcId), NextToken })), (r) => r.RouteTables, (r) => r.NextToken);
}
export async function listIgws(vpcId?: string) {
  const c = await ec2();
  const Filters = vpcId ? [{ Name: "attachment.vpc-id", Values: [vpcId] }] : undefined;
  return all((NextToken) => c.send(new DescribeInternetGatewaysCommand({ Filters, NextToken })), (r) => r.InternetGateways, (r) => r.NextToken);
}
export async function listNats(vpcId?: string) {
  const c = await ec2();
  return all((NextToken) => c.send(new DescribeNatGatewaysCommand({ Filter: byVpc(vpcId), NextToken })), (r) => r.NatGateways, (r) => r.NextToken);
}
export async function listEndpoints(vpcId?: string) {
  const c = await ec2();
  return all((NextToken) => c.send(new DescribeVpcEndpointsCommand({ Filters: byVpc(vpcId), NextToken })), (r) => r.VpcEndpoints, (r) => r.NextToken);
}
export async function listPeerings() {
  const c = await ec2();
  return all((NextToken) => c.send(new DescribeVpcPeeringConnectionsCommand({ NextToken })), (r) => r.VpcPeeringConnections, (r) => r.NextToken);
}
export async function listAcls(vpcId?: string) {
  const c = await ec2();
  return all((NextToken) => c.send(new DescribeNetworkAclsCommand({ Filters: byVpc(vpcId), NextToken })), (r) => r.NetworkAcls, (r) => r.NextToken);
}
export async function listGroups(vpcId?: string) {
  const c = await ec2();
  return all((NextToken) => c.send(new DescribeSecurityGroupsCommand({ Filters: byVpc(vpcId), NextToken })), (r) => r.SecurityGroups, (r) => r.NextToken);
}
/** DescribeAddresses is not paginated. */
export async function listAddresses() {
  return (await (await ec2()).send(new DescribeAddressesCommand({}))).Addresses ?? [];
}

export async function network(vpcId?: string) {
  const [vpcs, subnets, tables] = await Promise.all([listVpcs(vpcId ? [vpcId] : undefined), listSubnets(vpcId), listTables(vpcId)]);
  return { vpcs, subnets, tables };
}

/** A VPC's associated IPv4 blocks. */
export function cidrsOf(v: Vpc): string[] {
  const associated = (v.CidrBlockAssociationSet ?? []).filter((a) => a.CidrBlockState?.State === "associated").map((a) => a.CidrBlock!);
  return associated.length ? associated : v.CidrBlock ? [v.CidrBlock] : [];
}

/** The VPCs a new subnet can go in, with the blocks it must fit and avoid. */
export function choices(vpcs: Vpc[], subnets: Subnet[]): VpcChoice[] {
  return vpcs.map((v) => ({
    id: v.VpcId!,
    label: nameTag(v) ?? v.VpcId!,
    cidrs: cidrsOf(v),
    subnets: subnets.filter((s) => s.VpcId === v.VpcId && s.CidrBlock).map((s) => s.CidrBlock!),
  }));
}

/** A resource's name, or its id. */
export const label = (r: { Tags?: { Key?: string; Value?: string }[] } | undefined, id: string | undefined) => (r && nameTag(r)) ?? id ?? "";

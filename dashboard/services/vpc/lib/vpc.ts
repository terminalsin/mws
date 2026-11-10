import "server-only";

import { DescribeRouteTablesCommand, DescribeSubnetsCommand, DescribeVpcsCommand, type RouteTable, type Subnet, type Vpc } from "@aws-sdk/client-ec2";

import { ec2, nameTag } from "./clients";
import type { VpcChoice } from "./forms";

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

export async function network(vpcId?: string) {
  const client = await ec2();
  const Filters = vpcId ? [{ Name: "vpc-id", Values: [vpcId] }] : undefined;
  const [vpcs, subnets, tables] = await Promise.all([
    client.send(new DescribeVpcsCommand(vpcId ? { VpcIds: [vpcId] } : {})).then((r) => r.Vpcs ?? []),
    client.send(new DescribeSubnetsCommand({ Filters })).then((r) => r.Subnets ?? []),
    client.send(new DescribeRouteTablesCommand({ Filters })).then((r) => r.RouteTables ?? []),
  ]);
  return { vpcs, subnets, tables };
}

/** Where a route sends traffic, as a short target id and its kind. */
export function routeTarget(r: NonNullable<RouteTable["Routes"]>[number]) {
  const id =
    r.GatewayId ?? r.NatGatewayId ?? r.TransitGatewayId ?? r.VpcPeeringConnectionId ?? r.NetworkInterfaceId ?? r.InstanceId ?? r.EgressOnlyInternetGatewayId ?? r.CarrierGatewayId ?? "";
  return id;
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

import "server-only";

import { DescribeRouteTablesCommand, DescribeSubnetsCommand, DescribeVpcsCommand, type RouteTable, type Subnet } from "@aws-sdk/client-ec2";

import { ec2 } from "./clients";

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

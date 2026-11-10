// Routes: where one goes (its destination) and what it sends traffic to (its
// target), by the id prefix EC2 gives each kind of target.

import type { Route } from "@aws-sdk/client-ec2";

/** Target id prefixes, and the CreateRoute/ReplaceRoute member each fills. */
export const ROUTE_TARGETS = {
  "igw-": "GatewayId",
  "vgw-": "GatewayId",
  "nat-": "NatGatewayId",
  "pcx-": "VpcPeeringConnectionId",
  "tgw-": "TransitGatewayId",
  "eni-": "NetworkInterfaceId",
  "i-": "InstanceId",
  "eigw-": "EgressOnlyInternetGatewayId",
  "cagw-": "CarrierGatewayId",
  "vpce-": "VpcEndpointId",
} as const;

export type TargetKey = (typeof ROUTE_TARGETS)[keyof typeof ROUTE_TARGETS];

export function targetKey(target: string): TargetKey | undefined {
  const prefix = (Object.keys(ROUTE_TARGETS) as (keyof typeof ROUTE_TARGETS)[]).find((p) => target.startsWith(p));
  return prefix ? ROUTE_TARGETS[prefix] : undefined;
}

/** Where a route sends traffic: the target's id ("local" for the VPC). */
export function routeTarget(r: Route) {
  return (
    r.GatewayId ??
    r.NatGatewayId ??
    r.TransitGatewayId ??
    r.VpcPeeringConnectionId ??
    r.NetworkInterfaceId ??
    r.InstanceId ??
    r.EgressOnlyInternetGatewayId ??
    r.CarrierGatewayId ??
    r.LocalGatewayId ??
    r.CoreNetworkArn ??
    ""
  );
}

export type DestinationKey = "DestinationCidrBlock" | "DestinationIpv6CidrBlock" | "DestinationPrefixListId";

/** The member a destination goes in: an IPv4 or IPv6 block, or a prefix list. */
export function destinationOf(destination: string): DestinationKey {
  if (destination.startsWith("pl-")) return "DestinationPrefixListId";
  return destination.includes(":") ? "DestinationIpv6CidrBlock" : "DestinationCidrBlock";
}

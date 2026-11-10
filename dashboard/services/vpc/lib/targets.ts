import "server-only";

import { DescribeEgressOnlyInternetGatewaysCommand, DescribeTransitGatewayVpcAttachmentsCommand, DescribeVpnGatewaysCommand } from "@aws-sdk/client-ec2";

import { ec2 } from "./clients";
import { listIgws, listNats, listPeerings } from "./vpc";

/** What a route in this VPC can send traffic to: its internet, egress-only
 * and virtual private gateways, NAT gateways, active peerings and transit
 * gateway attachments. Also returns the attached virtual private gateways,
 * whose routes a table can propagate. */
export async function routeTargets(vpcId: string) {
  const client = await ec2();
  const [igws, nats, peerings, eigws, vgws, tgws] = await Promise.all([
    listIgws(vpcId),
    listNats(vpcId),
    listPeerings(),
    client.send(new DescribeEgressOnlyInternetGatewaysCommand({})).then((r) => r.EgressOnlyInternetGateways ?? [], () => []),
    client.send(new DescribeVpnGatewaysCommand({ Filters: [{ Name: "attachment.vpc-id", Values: [vpcId] }] })).then((r) => r.VpnGateways ?? [], () => []),
    client.send(new DescribeTransitGatewayVpcAttachmentsCommand({ Filters: [{ Name: "vpc-id", Values: [vpcId] }] })).then((r) => r.TransitGatewayVpcAttachments ?? [], () => []),
  ]);
  const vgwIds = vgws.filter((g) => g.VpcAttachments?.some((a) => a.VpcId === vpcId && a.State === "attached")).map((g) => g.VpnGatewayId!);
  const targets = [
    ...igws.map((g) => g.InternetGatewayId!),
    ...nats.filter((n) => n.State === "available" || n.State === "pending").map((n) => n.NatGatewayId!),
    ...peerings
      .filter((p) => p.Status?.Code === "active" && (p.RequesterVpcInfo?.VpcId === vpcId || p.AccepterVpcInfo?.VpcId === vpcId))
      .map((p) => p.VpcPeeringConnectionId!),
    ...tgws.filter((a) => a.State === "available").map((a) => a.TransitGatewayId!),
    ...eigws.filter((g) => g.Attachments?.some((a) => a.VpcId === vpcId)).map((g) => g.EgressOnlyInternetGatewayId!),
    ...vgwIds,
  ];
  return { targets: [...new Set(targets)], vgws: vgwIds };
}

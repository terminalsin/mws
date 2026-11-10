import "server-only";

import { EC2Client, type ResourceType, type TagSpecification } from "@aws-sdk/client-ec2";
import { client } from "@mws-dashboard/aws";

export const ec2 = () => client(EC2Client);

export const ICONS = {
  vpc: "resource/AmazonVPCVirtualprivatecloudVPC",
  publicSubnet: "group/Publicsubnet",
  privateSubnet: "group/Privatesubnet",
  routeTable: "resource/AmazonVPCRouter",
  igw: "resource/AmazonVPCInternetGateway",
  nat: "resource/AmazonVPCNATGateway",
  endpoint: "resource/AmazonVPCEndpoints",
  peering: "resource/AmazonVPCPeeringConnection",
  nacl: "resource/AmazonVPCNetworkAccessControlList",
  internet: "resource/Internet",
  eip: "resource/AmazonEC2ElasticIPAddress",
  eni: "resource/AmazonVPCElasticNetworkInterface",
  vgw: "resource/AmazonVPCVPNGateway",
  tgw: "resource/AWSTransitGatewayAttachment",
  instance: "resource/AmazonEC2Instance",
  carrier: "resource/AmazonVPCCarrierGateway",
};

export const nameTag = (r: { Tags?: { Key?: string; Value?: string }[] }) => r.Tags?.find((t) => t.Key === "Name")?.Value;

/** A Name tag for a create call's TagSpecifications. */
export function nameSpec(type: ResourceType, name: string | undefined): TagSpecification[] | undefined {
  return name ? [{ ResourceType: type, Tags: [{ Key: "Name", Value: name }] }] : undefined;
}

/** The tone of an EC2 networking state word. */
export const STATE_TONE = (s: string | undefined) =>
  s === "available" || s === "active" || s === "attached" || s === "associated"
    ? ("good" as const)
    : s === "failed" || s === "rejected" || s === "deleted" || s === "expired" || s === "blackhole"
      ? ("bad" as const)
      : s === "pending-acceptance"
        ? ("info" as const)
        : ("warn" as const);

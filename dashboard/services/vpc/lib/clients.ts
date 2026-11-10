import "server-only";

import { EC2Client } from "@aws-sdk/client-ec2";
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
};

export const nameTag = (r: { Tags?: { Key?: string; Value?: string }[] }) => r.Tags?.find((t) => t.Key === "Name")?.Value;

import "server-only";

import { EC2Client } from "@aws-sdk/client-ec2";
import { Route53Client } from "@aws-sdk/client-route-53";
import { client } from "@mws-dashboard/aws";

export const ec2 = () => client(EC2Client);
export const route53 = () => client(Route53Client);

export const ICONS = {
  vpc: "resource/AmazonVPCVirtualprivatecloudVPC",
  zone: "resource/AmazonRoute53HostedZone",
  route53: "service/AmazonRoute53",
  internet: "resource/Internet",
};

export const nameTag = (r: { Tags?: { Key?: string; Value?: string }[] }) => r.Tags?.find((t) => t.Key === "Name")?.Value;

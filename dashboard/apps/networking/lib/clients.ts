import "server-only";

import { ACMClient } from "@aws-sdk/client-acm";
import { ACMPCAClient } from "@aws-sdk/client-acm-pca";
import { EC2Client } from "@aws-sdk/client-ec2";
import { ElasticLoadBalancingV2Client } from "@aws-sdk/client-elastic-load-balancing-v2";
import { GlobalAcceleratorClient } from "@aws-sdk/client-global-accelerator";
import { Route53Client } from "@aws-sdk/client-route-53";
import { client } from "@mws-dashboard/aws";

export const ec2 = () => client(EC2Client);
export const route53 = () => client(Route53Client);
export const elb = () => client(ElasticLoadBalancingV2Client);
export const ga = () => client(GlobalAcceleratorClient);
export const acm = () => client(ACMClient);
export const pca = () => client(ACMPCAClient);

export const ICONS = {
  vpc: "resource/AmazonVPCVirtualprivatecloudVPC",
  publicSubnet: "group/Publicsubnet",
  privateSubnet: "group/Privatesubnet",
  routeTable: "resource/AmazonVPCRouter",
  igw: "resource/AmazonVPCInternetGateway",
  nat: "resource/AmazonVPCNATGateway",
  endpoint: "resource/AmazonVPCEndpoints",
  peering: "resource/AmazonVPCPeeringConnection",
  eni: "resource/AmazonVPCElasticNetworkInterface",
  nacl: "resource/AmazonVPCNetworkAccessControlList",
  zone: "resource/AmazonRoute53HostedZone",
  route53: "service/AmazonRoute53",
  alb: "resource/ElasticLoadBalancingApplicationLoadBalancer",
  nlb: "resource/ElasticLoadBalancingNetworkLoadBalancer",
  gwlb: "resource/ElasticLoadBalancingGatewayLoadBalancer",
  clb: "resource/ElasticLoadBalancingClassicLoadBalancer",
  elb: "service/ElasticLoadBalancing",
  ga: "service/AWSGlobalAccelerator",
  acm: "service/AWSCertificateManager",
  ca: "resource/AWSCertificateManagerCertificateAuthority",
  pca: "service/AWSPrivateCertificateAuthority",
  internet: "resource/Internet",
};

export const LB_ICON: Record<string, string> = { application: ICONS.alb, network: ICONS.nlb, gateway: ICONS.gwlb };

export const nameTag = (r: { Tags?: { Key?: string; Value?: string }[] }) => r.Tags?.find((t) => t.Key === "Name")?.Value;

/** Days until a date, rounded down (negative once past). */
export function daysUntil(d: Date | undefined) {
  return d ? Math.floor((d.getTime() - Date.now()) / 86_400_000) : undefined;
}

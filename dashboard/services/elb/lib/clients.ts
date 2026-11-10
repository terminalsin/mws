import "server-only";

import { ACMClient } from "@aws-sdk/client-acm";
import { EC2Client } from "@aws-sdk/client-ec2";
import { ElasticLoadBalancingV2Client } from "@aws-sdk/client-elastic-load-balancing-v2";
import { client } from "@mws-dashboard/aws";

export const ec2 = () => client(EC2Client);
export const elb = () => client(ElasticLoadBalancingV2Client);
export const acm = () => client(ACMClient);

export const ICONS = {
  vpc: "resource/AmazonVPCVirtualprivatecloudVPC",
  publicSubnet: "group/Publicsubnet",
  eni: "resource/AmazonVPCElasticNetworkInterface",
  alb: "resource/ElasticLoadBalancingApplicationLoadBalancer",
  nlb: "resource/ElasticLoadBalancingNetworkLoadBalancer",
  gwlb: "resource/ElasticLoadBalancingGatewayLoadBalancer",
  elb: "service/ElasticLoadBalancing",
};

export const LB_ICON: Record<string, string> = { application: ICONS.alb, network: ICONS.nlb, gateway: ICONS.gwlb };

export const nameTag = (r: { Tags?: { Key?: string; Value?: string }[] }) => r.Tags?.find((t) => t.Key === "Name")?.Value;
